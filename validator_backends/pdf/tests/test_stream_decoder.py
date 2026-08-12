"""Prove decoded PDF streams cross a bounded subprocess boundary.

These tests protect the gap between qpdf's fully materialized stream API and
Validibot's decoded-byte policy. They verify exact-byte staging, child-side
byte refusal, non-cooperative wall-clock handling, resource-death mapping, and
the environment allowlist that keeps attempt authority out of the parser.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pikepdf
import pytest

from validator_backends.pdf import engine as pdf_engine
from validator_backends.pdf import stream_decoder
from validator_backends.pdf.stream_decoder import (
    StreamDecodeByteLimitExceeded,
    StreamDecodeError,
    StreamDecodeResourceLimitExceeded,
    StreamDecodeTimeout,
    decode_pdf_stream,
)


def _pdf_with_stream(tmp_path: Path, payload: bytes) -> tuple[Path, tuple[int, int]]:
    """Create one PDF stream and return its stable indirect identity."""
    source = tmp_path / "stream.pdf"
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(100, 100))
    stream = pdf.make_stream(payload)
    pdf.Root["/ValidibotTestStream"] = stream
    pdf.save(source)
    with pikepdf.Pdf.open(source, attempt_recovery=False) as reopened:
        object_identity = reopened.Root["/ValidibotTestStream"].objgen
    return source, object_identity


def test_isolated_decoder_stages_exact_bytes(tmp_path: Path) -> None:
    """Process isolation must not rewrite a legitimate selected payload."""
    payload = b"bounded payload\n" * 100
    source, (object_number, generation) = _pdf_with_stream(tmp_path, payload)

    decoded = decode_pdf_stream(
        source_path=source,
        object_number=object_number,
        generation=generation,
        destination=tmp_path / "decoded.bin",
        max_decoded_bytes=len(payload),
        max_seconds=10,
        source_size_bytes=source.stat().st_size,
    )

    assert decoded.path.read_bytes() == payload
    assert decoded.size_bytes == len(payload)
    assert 0 < decoded.encoded_size_bytes <= source.stat().st_size


def test_child_refuses_bytes_before_publishing_a_staged_file(tmp_path: Path) -> None:
    """An oversized decoded buffer must not become a parent-visible artifact."""
    payload = b"highly compressible payload\n" * 500
    source, (object_number, generation) = _pdf_with_stream(tmp_path, payload)
    destination = tmp_path / "must-not-exist.bin"

    with pytest.raises(StreamDecodeByteLimitExceeded):
        decode_pdf_stream(
            source_path=source,
            object_number=object_number,
            generation=generation,
            destination=destination,
            max_decoded_bytes=16,
            max_seconds=10,
            source_size_bytes=source.stat().st_size,
        )

    assert not destination.exists()


def test_parent_maps_native_process_death_to_a_resource_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """OOM or signal death must fail closed instead of resembling bad user data."""

    def terminate(*_args, **_kwargs):
        return SimpleNamespace(returncode=-9)

    monkeypatch.setattr(stream_decoder.subprocess, "run", terminate)

    with pytest.raises(StreamDecodeResourceLimitExceeded):
        decode_pdf_stream(
            source_path=tmp_path / "source.pdf",
            object_number=1,
            generation=0,
            destination=tmp_path / "decoded.bin",
            max_decoded_bytes=1024,
            max_seconds=10,
            source_size_bytes=1024,
        )


def test_parent_enforces_a_non_cooperative_wall_clock_timeout(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A stuck native decode must be killable outside qpdf's call stack."""

    def time_out(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="decoder", timeout=1)

    monkeypatch.setattr(stream_decoder.subprocess, "run", time_out)

    with pytest.raises(StreamDecodeTimeout):
        decode_pdf_stream(
            source_path=tmp_path / "source.pdf",
            object_number=1,
            generation=0,
            destination=tmp_path / "decoded.bin",
            max_decoded_bytes=1024,
            max_seconds=1,
            source_size_bytes=1024,
        )


def test_decoder_child_receives_no_attempt_authority(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A parser compromise must not inherit cloud tokens or callback nonces."""
    captured_environment = {}
    monkeypatch.setenv("VALIDIBOT_GCS_ACCESS_TOKEN", "secret-token")
    monkeypatch.setenv("VALIDIBOT_CALLBACK_NONCE", "secret-nonce")

    def complete(command, **kwargs):
        captured_environment.update(kwargs["env"])
        destination = Path(command[command.index("--destination") + 1])
        destination.write_bytes(b"ok")
        kwargs["stdout"].write(b"2\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(stream_decoder.subprocess, "run", complete)

    decoded = decode_pdf_stream(
        source_path=tmp_path / "source.pdf",
        object_number=1,
        generation=0,
        destination=tmp_path / "decoded.bin",
        max_decoded_bytes=1024,
        max_seconds=10,
        source_size_bytes=1024,
    )

    assert decoded.path.read_bytes() == b"ok"
    assert "VALIDIBOT_GCS_ACCESS_TOKEN" not in captured_environment
    assert "VALIDIBOT_CALLBACK_NONCE" not in captured_environment
    assert set(captured_environment) <= {
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
        "PYTHONPATH",
    }


def test_encoded_size_evidence_cannot_become_an_output_pipe_memory_sink(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A compromised child cannot make the parent collect unbounded stdout."""

    def emit_oversized_evidence(command, **kwargs):
        destination = Path(command[command.index("--destination") + 1])
        destination.write_bytes(b"ok")
        kwargs["stdout"].write(b"9" * 65)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(stream_decoder.subprocess, "run", emit_oversized_evidence)
    destination = tmp_path / "decoded.bin"

    with pytest.raises(StreamDecodeError, match="encoded-size evidence"):
        decode_pdf_stream(
            source_path=tmp_path / "source.pdf",
            object_number=1,
            generation=0,
            destination=destination,
            max_decoded_bytes=1024,
            max_seconds=10,
            source_size_bytes=1024,
        )

    assert not destination.exists()
    assert not (tmp_path / "decoded.bin.encoded-size").exists()


def test_long_lived_engine_never_calls_the_materializing_decode_api() -> None:
    """Future features must not bypass the resource-limited child by accident."""
    engine_source = Path(pdf_engine.__file__).read_text(encoding="utf-8")

    assert ".get_stream_buffer()" not in engine_source
    assert ".get_raw_stream_buffer()" not in engine_source
