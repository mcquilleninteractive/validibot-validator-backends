"""Decode one untrusted PDF stream behind a killable resource boundary.

Pikepdf's public stream API returns a fully materialized qpdf buffer. Checking
the decoded length after that call is too late to stop a compressed stream from
allocating excessive memory in the long-lived PDF inspection process. This
module therefore reopens the source PDF in a short-lived subprocess, applies
OS resource limits before importing pikepdf, and writes the decoded bytes only
when they fit the caller's limit.

The parent process passes only a source path, an indirect object number, a
trusted destination, and numeric limits. The child receives a deliberately
minimal environment: attempt capabilities, callback nonces, cloud credentials,
and observability secrets are not inherited. On Linux, the secret-bearing
entrypoint and attempt process are also non-dumpable, closing same-UID procfs
and ptrace inspection from the decoder. A native parser compromise still has
the container's allowed filesystem and kernel boundary, so this is defense in
depth rather than a claim of parser immunity.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from validator_backends.core.process_hardening import (
    prevent_privilege_escalation,
    protect_current_process_secrets,
)


STREAM_DECODE_LIMIT_EXIT = 20
STREAM_DECODE_ERROR_EXIT = 21
STREAM_DECODE_RESOURCE_EXIT = 22
STREAM_DECODE_MIN_MEMORY_BYTES = 256 * 1024 * 1024
STREAM_DECODE_MAX_MEMORY_BYTES = 1024 * 1024 * 1024
STREAM_DECODE_MEMORY_OVERHEAD_BYTES = 96 * 1024 * 1024
STREAM_DECODE_CHUNK_BYTES = 1024 * 1024
STREAM_DECODE_MAX_OPEN_FILES = 64
STREAM_DECODE_MAX_PROCESSES = 1


class StreamDecodeError(RuntimeError):
    """The isolated qpdf child could not decode the requested stream."""


class StreamDecodeLimitExceeded(StreamDecodeError):
    """The decoded stream exceeded a byte or process-resource boundary."""


class StreamDecodeByteLimitExceeded(StreamDecodeLimitExceeded):
    """The child decoded more bytes than the caller permits."""


class StreamDecodeResourceLimitExceeded(StreamDecodeLimitExceeded):
    """The child crossed its memory, CPU, descriptor, or file-size boundary."""


class StreamDecodeTimeout(StreamDecodeError):
    """The isolated decoder exceeded its non-cooperative wall-clock boundary."""


@dataclass(frozen=True, slots=True)
class DecodedPdfStream:
    """Identity of one bounded decoded stream staged by the child process."""

    path: Path
    size_bytes: int
    sha256: str
    encoded_size_bytes: int


class BoundedPdfStreamDecoder:
    """Cache isolated decoded streams for one PDF inspection attempt.

    Reopening qpdf once per discovery route would itself create a denial-of-
    service multiplier because one stream can be referenced by the name tree,
    associated-file arrays, and annotations simultaneously. The
    cache is keyed by indirect object identity and byte limit, so each distinct
    bounded decode runs once while callers still receive immutable staged
    bytes.
    """

    def __init__(
        self,
        *,
        source_path: Path,
        source_size_bytes: int,
        workspace: Path,
        started: float,
        max_execution_seconds: int,
    ) -> None:
        self._source_path = source_path
        self._source_size_bytes = source_size_bytes
        self._workspace = workspace
        self._started = started
        self._max_execution_seconds = max_execution_seconds
        self._cache: dict[tuple[int, int, int], DecodedPdfStream] = {}
        self._workspace.mkdir(parents=True, exist_ok=True)

    def decode(self, stream, *, max_decoded_bytes: int) -> DecodedPdfStream:
        """Return one cached bounded decode for an indirect pikepdf stream."""
        object_number, generation = stream.objgen
        cache_key = (object_number, generation, max_decoded_bytes)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        remaining_seconds = self._max_execution_seconds - (time.monotonic() - self._started)
        destination = self._workspace / (
            f"object-{object_number}-{generation}-limit-{max_decoded_bytes}.bin"
        )
        decoded = decode_pdf_stream(
            source_path=self._source_path,
            object_number=object_number,
            generation=generation,
            destination=destination,
            max_decoded_bytes=max_decoded_bytes,
            max_seconds=remaining_seconds,
            source_size_bytes=self._source_size_bytes,
        )
        self._cache[cache_key] = decoded
        return decoded

    @staticmethod
    def copy(decoded: DecodedPdfStream, destination: Path) -> None:
        """Copy one verified cache entry to a trusted artifact location."""
        destination.unlink(missing_ok=True)
        with decoded.path.open("rb") as source, destination.open("xb") as target:
            shutil.copyfileobj(source, target, STREAM_DECODE_CHUNK_BYTES)


def decode_pdf_stream(
    *,
    source_path: Path,
    object_number: int,
    generation: int,
    destination: Path,
    max_decoded_bytes: int,
    max_seconds: float,
    source_size_bytes: int,
) -> DecodedPdfStream:
    """Decode one indirect stream with hard child-process resource limits.

    Raises:
        StreamDecodeLimitExceeded: The decoded stream or child allocation
            crossed its configured boundary.
        StreamDecodeTimeout: The child did not finish within ``max_seconds``.
        StreamDecodeError: The object was unavailable or qpdf could not decode
            it safely.
    """
    if object_number <= 0 or generation < 0:
        raise StreamDecodeError("PDF streams must have a stable indirect object identity.")
    if max_decoded_bytes < 1:
        raise StreamDecodeByteLimitExceeded("The decoded-stream byte limit is exhausted.")
    if max_seconds <= 0:
        raise StreamDecodeTimeout("The PDF inspection deadline is exhausted.")

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)
    encoded_size_evidence = destination.with_name(f"{destination.name}.encoded-size")
    encoded_size_evidence.unlink(missing_ok=True)
    memory_bytes = _decoder_memory_limit(
        source_size_bytes=source_size_bytes,
        max_decoded_bytes=max_decoded_bytes,
    )
    command = [
        sys.executable,
        "-m",
        "validator_backends.pdf.stream_decoder",
        "--child",
        "--source",
        str(source_path.resolve()),
        "--object-number",
        str(object_number),
        "--generation",
        str(generation),
        "--destination",
        str(destination.resolve()),
        "--max-decoded-bytes",
        str(max_decoded_bytes),
        "--memory-bytes",
        str(memory_bytes),
        "--cpu-seconds",
        str(max(1, math.ceil(max_seconds))),
    ]
    try:
        evidence_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            evidence_flags |= os.O_NOFOLLOW
        evidence_descriptor = os.open(encoded_size_evidence, evidence_flags, 0o600)
        with os.fdopen(evidence_descriptor, "wb") as evidence_stream:
            completed = subprocess.run(
                command,
                check=False,
                cwd=_module_root(),
                env=_minimal_child_environment(),
                stdin=subprocess.DEVNULL,
                stdout=evidence_stream,
                stderr=subprocess.DEVNULL,
                timeout=max_seconds,
                start_new_session=True,
            )
    except subprocess.TimeoutExpired as exc:
        destination.unlink(missing_ok=True)
        encoded_size_evidence.unlink(missing_ok=True)
        raise StreamDecodeTimeout("The isolated PDF stream decoder timed out.") from exc

    try:
        if completed.returncode == STREAM_DECODE_LIMIT_EXIT:
            destination.unlink(missing_ok=True)
            raise StreamDecodeByteLimitExceeded("The decoded PDF stream exceeds its byte limit.")
        if completed.returncode == STREAM_DECODE_RESOURCE_EXIT or completed.returncode < 0:
            destination.unlink(missing_ok=True)
            raise StreamDecodeResourceLimitExceeded(
                "The isolated PDF stream decoder exceeded its process-resource limit."
            )
        if completed.returncode != 0:
            destination.unlink(missing_ok=True)
            raise StreamDecodeError("The isolated PDF stream decoder rejected the stream.")

        try:
            if encoded_size_evidence.stat().st_size > 64:
                raise ValueError("Encoded-size evidence exceeds its fixed bound.")
            encoded_size_bytes = int(encoded_size_evidence.read_text(encoding="ascii").strip())
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            destination.unlink(missing_ok=True)
            raise StreamDecodeError(
                "The isolated decoder produced invalid encoded-size evidence."
            ) from exc
        if not 0 <= encoded_size_bytes <= source_size_bytes:
            destination.unlink(missing_ok=True)
            raise StreamDecodeError(
                "The isolated decoder's encoded-size evidence exceeds the source."
            )

        try:
            size_bytes, sha256 = _file_identity(
                destination,
                max_bytes=max_decoded_bytes,
            )
        except (OSError, ValueError) as exc:
            destination.unlink(missing_ok=True)
            raise StreamDecodeError(
                "The isolated decoder produced an invalid staged file."
            ) from exc
        return DecodedPdfStream(
            path=destination,
            size_bytes=size_bytes,
            sha256=sha256,
            encoded_size_bytes=encoded_size_bytes,
        )
    finally:
        encoded_size_evidence.unlink(missing_ok=True)


def _decoder_memory_limit(*, source_size_bytes: int, max_decoded_bytes: int) -> int:
    """Return a bounded address-space budget for one clean decoder process."""
    requested = source_size_bytes + (max_decoded_bytes * 2) + STREAM_DECODE_MEMORY_OVERHEAD_BYTES
    return min(
        STREAM_DECODE_MAX_MEMORY_BYTES,
        max(STREAM_DECODE_MIN_MEMORY_BYTES, requested),
    )


def _module_root() -> Path:
    """Return the import root used by both source trees and installed images."""
    return Path(__file__).resolve().parents[2]


def _minimal_child_environment() -> dict[str, str]:
    """Return an allowlist environment that excludes attempt authority."""
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(_module_root()),
    }
    for name in ("LANG", "LC_ALL"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _file_identity(path: Path, *, max_bytes: int) -> tuple[int, str]:
    """Verify the child output without loading it into parent-process memory."""
    digest = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as source:
        while chunk := source.read(STREAM_DECODE_CHUNK_BYTES):
            size_bytes += len(chunk)
            if size_bytes > max_bytes:
                raise ValueError("Decoded stream crossed the parent byte limit.")
            digest.update(chunk)
    return size_bytes, digest.hexdigest()


def _apply_child_resource_limits(
    *,
    max_decoded_bytes: int,
    memory_bytes: int,
    cpu_seconds: int,
) -> None:
    """Apply POSIX limits before the child imports the native PDF parser."""
    import resource

    protect_current_process_secrets()
    prevent_privilege_escalation()
    _lower_resource_limit(resource.RLIMIT_CORE, 0)
    _lower_resource_limit(resource.RLIMIT_FSIZE, max_decoded_bytes)
    _lower_resource_limit(resource.RLIMIT_NOFILE, STREAM_DECODE_MAX_OPEN_FILES)
    _lower_resource_limit(resource.RLIMIT_CPU, cpu_seconds)
    process_limit = getattr(resource, "RLIMIT_NPROC", None)
    if process_limit is not None:
        _lower_resource_limit(process_limit, STREAM_DECODE_MAX_PROCESSES)
    # Darwin reserves a very large virtual address space before this module can
    # run and refuses to lower RLIMIT_AS below that reservation. Production
    # images are Linux, where the address-space limit is the native allocation
    # boundary; macOS development still retains CPU, file, descriptor, wall
    # clock, and outer-container limits.
    address_space_limit = (
        getattr(resource, "RLIMIT_AS", None) if sys.platform.startswith("linux") else None
    )
    if address_space_limit is not None:
        _lower_resource_limit(address_space_limit, memory_bytes)


def _lower_resource_limit(resource_name: int, requested: int) -> None:
    """Lower a soft/hard limit without attempting to raise a constrained child."""
    import resource

    _soft, hard = resource.getrlimit(resource_name)
    target = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
    resource.setrlimit(resource_name, (target, target))


def _write_exclusive(destination: Path, buffer, *, max_decoded_bytes: int) -> None:
    """Write one already-bounded qpdf buffer without following a symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as target:
            view = memoryview(buffer)
            for offset in range(0, len(view), STREAM_DECODE_CHUNK_BYTES):
                target.write(view[offset : offset + STREAM_DECODE_CHUNK_BYTES])
                if target.tell() > max_decoded_bytes:
                    raise ValueError("Decoded stream crossed the child byte limit.")
    finally:
        os.close(descriptor)


def _run_child(args: argparse.Namespace) -> int:
    """Open qpdf only after process limits are active and decode one object."""
    try:
        _apply_child_resource_limits(
            max_decoded_bytes=args.max_decoded_bytes,
            memory_bytes=args.memory_bytes,
            cpu_seconds=args.cpu_seconds,
        )
        import pikepdf

        with pikepdf.Pdf.open(
            args.source,
            password="",
            suppress_warnings=True,
            attempt_recovery=False,
        ) as pdf:
            stream = pdf.get_object(args.object_number, args.generation)
            if not isinstance(stream, pikepdf.Stream):
                return STREAM_DECODE_ERROR_EXIT
            encoded_size_bytes = len(stream.get_raw_stream_buffer())
            data = stream.get_stream_buffer()
            if len(data) > args.max_decoded_bytes:
                return STREAM_DECODE_LIMIT_EXIT
            _write_exclusive(
                args.destination,
                data,
                max_decoded_bytes=args.max_decoded_bytes,
            )
            print(encoded_size_bytes, flush=True)
    except MemoryError:
        return STREAM_DECODE_RESOURCE_EXIT
    except (OSError, RuntimeError, ValueError):
        return STREAM_DECODE_ERROR_EXIT
    return 0


def _parser() -> argparse.ArgumentParser:
    """Build the private child-process command parser."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--child", action="store_true", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--object-number", type=int, required=True)
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--max-decoded-bytes", type=int, required=True)
    parser.add_argument("--memory-bytes", type=int, required=True)
    parser.add_argument("--cpu-seconds", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute the private resource-limited decoder child."""
    args = _parser().parse_args(argv)
    return _run_child(args)


if __name__ == "__main__":
    raise SystemExit(main())
