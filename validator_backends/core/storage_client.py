"""
Storage client utilities for validator containers.

Provides helpers for downloading input envelopes and uploading output envelopes
to various storage backends. Supports:

- gs:// - Google Cloud Storage (for production Cloud Run Jobs)
- file:// - Local filesystem (for self-hosted Docker deployments)

This module abstracts storage operations so validators work identically
whether running on GCP Cloud Run or self-hosted Docker.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol, TypedDict

from pydantic import BaseModel

from validator_backends.core.gcs_capability import (
    assert_gcs_uri_allowed,
    build_gcs_credentials,
    configure_capability_refresh,
    refresh_attempt_capability,
)


class _IntegrityBoundFile(Protocol):
    """Structural subset shared by input and resource file envelope items.

    Input files and resource files are separate classes in ``validibot-shared``
    with different envelope semantics, but the four fields needed to fetch bytes
    safely are identical. A ``Protocol`` lets the download path accept either
    without importing both or forcing a shared base class into the shared
    package — the coupling stays at "has these four attributes".

    Every field is required. A file described without its digest or version
    cannot be verified, and this module has no path that downloads unverified
    bytes.
    """

    uri: str
    size_bytes: int
    sha256: str
    storage_version: str


class _UploadedFileManifestItem(TypedDict):
    """One integrity-bound output entry in a directory manifest.

    When a validator emits a whole directory, the manifest is what makes the
    result verifiable: without it, Django would know a prefix was written but not
    which objects belong to the run or whether any were missing. Each entry
    carries the same integrity fields as :class:`StoredFile` plus the member's
    name relative to the uploaded directory.

    A ``TypedDict`` rather than a dataclass because these are serialised straight
    into ``manifest.json`` — the dict *is* the wire format.
    """

    name: str
    uri: str
    size_bytes: int
    sha256: str
    storage_version: str


logger = logging.getLogger(__name__)

STREAM_CHUNK_SIZE = 1024 * 1024
LOCAL_STORAGE_VERSION_PREFIX = "sha256:"
LOCAL_PUBLISHED_FILE_MODE = 0o644


class FileVerificationError(ValueError):
    """Raised before execution when stored bytes violate their file contract."""


class StorageConflictError(RuntimeError):
    """Raised when a create-only input or output identity already exists."""


@dataclass(frozen=True, slots=True)
class VerifiedFile:
    """A local input file, committed only after its full contract was verified.

    Returned by :func:`download_verified_file`. Its existence is the proof: a
    ``VerifiedFile`` is only constructed once the downloaded bytes matched the
    declared size, SHA-256, and storage version exactly. Code holding one does
    not need to re-check anything, which is why verification is a constructor
    precondition rather than a method someone might forget to call.

    Verification happens *during* the stream, not after. The declared size acts
    as a hard ceiling on bytes accepted, so an object that grew since Django
    described it is rejected mid-download rather than after it has filled the
    container's disk.

    Fields:
        path: Where the verified bytes now live locally. Committed create-only —
            an existing destination is treated as a conflict even when it already
            holds the expected bytes, because reuse would mean trusting something
            this attempt did not verify itself.
        uri: The source URI the bytes came from.
        size_bytes: Observed size, equal by construction to the declared size.
        sha256: Observed digest, equal by construction to the declared digest.
        storage_version: The immutable version that was pinned during the read.
            For ``gs://`` this is the GCS object generation, so the read is bound
            to exact bytes even if the object is later overwritten. For
            ``file://`` it is ``sha256:<digest>``, since a local filesystem has no
            generation concept.
    """

    path: Path
    uri: str
    size_bytes: int
    sha256: str
    storage_version: str


@dataclass(frozen=True, slots=True)
class StoredFile:
    """Integrity and immutable-version metadata for one uploaded output file.

    The output-side counterpart to :class:`VerifiedFile`. The two hold nearly the
    same fields for opposite reasons, and the difference is worth keeping
    straight: a ``VerifiedFile`` records what this container *checked* about
    bytes it received, while a ``StoredFile`` records what it *produced* so that
    Django can check them in turn. Hence no ``path`` — by the time one exists the
    bytes are in remote storage, and the local copy is no longer the artifact of
    record.

    These values travel back in the output envelope and become the evidence
    Django stores against the run. Uploads are create-only, so a conflicting
    destination raises :class:`StorageConflictError` rather than overwriting
    something a previous attempt already published.

    Fields:
        uri: Where the file was written.
        size_bytes: Size computed locally before upload.
        sha256: Digest computed locally before upload.
        storage_version: GCS generation of the created object, or
            ``sha256:<digest>`` for local storage. Django uses this to re-open the
            exact bytes this attempt wrote.
    """

    uri: str
    size_bytes: int
    sha256: str
    storage_version: str


def create_attempt_work_dir(base_dir: Path, execution_attempt_id: str) -> Path:
    """Create one safe, exclusive scratch directory for an execution attempt.

    The attempt identifier comes from the input envelope, so it is hashed before
    becoming a path component. Re-entering the same attempt in one runtime is a
    conflict rather than permission to reuse stale verified inputs or outputs.
    """
    if not execution_attempt_id:
        msg = "Execution attempt ID is required for backend scratch storage"
        raise ValueError(msg)

    base_dir.mkdir(parents=True, exist_ok=True)
    safe_attempt_name = hashlib.sha256(execution_attempt_id.encode("utf-8")).hexdigest()
    work_dir = base_dir / safe_attempt_name
    try:
        work_dir.mkdir()
    except FileExistsError as exc:
        msg = f"Create-only attempt scratch directory already exists: {work_dir}"
        raise StorageConflictError(msg) from exc
    return work_dir


# =============================================================================
# URI Parsing
# =============================================================================


def parse_uri(uri: str) -> tuple[str, str]:
    """
    Parse a storage URI into scheme and path.

    Args:
        uri: Storage URI like 'gs://bucket/path' or 'file:///path/to/file'

    Returns:
        Tuple of (scheme, path). For gs://, path includes bucket.
        For file://, path is the absolute filesystem path.

    Raises:
        ValueError: If URI scheme is not supported

    Examples:
        >>> parse_uri("gs://my-bucket/path/to/file.json")
        ('gs', 'my-bucket/path/to/file.json')
        >>> parse_uri("file:///app/storage/data.json")
        ('file', '/app/storage/data.json')
    """
    if uri.startswith("gs://"):
        return "gs", uri[5:]  # Remove 'gs://'
    if uri.startswith("file://"):
        return "file", uri[7:]  # Remove 'file://'

    raise ValueError(
        f"Unsupported URI scheme: {uri}. "
        "Supported schemes: gs:// (Google Cloud Storage), file:// (local filesystem)"
    )


def parse_gcs_uri(uri: str) -> tuple[str, str]:
    """
    Parse a GCS URI into bucket and blob path.

    Args:
        uri: GCS URI like 'gs://bucket-name/path/to/file.json'

    Returns:
        Tuple of (bucket_name, blob_path)

    Raises:
        ValueError: If URI is not a valid GCS URI
    """
    if not uri.startswith("gs://"):
        raise ValueError(f"Invalid GCS URI (must start with gs://): {uri}")

    uri_without_scheme = uri[5:]  # Remove 'gs://'
    parts = uri_without_scheme.split("/", 1)

    expected_parts = 2
    if len(parts) != expected_parts:
        raise ValueError(f"Invalid GCS URI (missing path): {uri}")

    bucket_name, blob_path = parts
    # Reject empty components: ``gs:///path`` (no bucket) and ``gs://bucket/``
    # (no object) both pass the split above but fail later inside the GCS
    # client with an opaque error. Fail fast here with a clear message.
    if not bucket_name or not blob_path:
        raise ValueError(f"Invalid GCS URI (empty bucket or path): {uri}")
    return bucket_name, blob_path


# =============================================================================
# Envelope Operations
# =============================================================================


def download_envelope[T: BaseModel](
    uri: str,
    envelope_class: type[T],
    *,
    configure_refresh: bool = True,
) -> T:
    """
    Download and deserialize a Pydantic envelope from storage.

    Supports both gs:// (GCS) and file:// (local filesystem) URIs.

    Args:
        uri: Storage URI to the envelope JSON file
        envelope_class: Pydantic model class to deserialize to

    Returns:
        Deserialized envelope instance

    Raises:
        ValueError: If URI is invalid or file doesn't exist
        ValidationError: If JSON doesn't match envelope schema
    """
    logger.info("Downloading envelope from %s", uri)

    scheme, path = parse_uri(uri)

    if scheme == "gs":
        json_content = _download_gcs_text(uri)
    elif scheme == "file":
        json_content = _read_local_file(path)
    else:
        raise ValueError(f"Unsupported URI scheme: {scheme}")

    envelope = envelope_class.model_validate_json(json_content)
    if configure_refresh:
        configure_capability_refresh(envelope)
        if os.getenv("VALIDIBOT_VERIFY_ATTEMPT_ACTIVE", "").lower() == "true":
            refresh_attempt_capability()

    logger.info(
        "Successfully loaded %s envelope (run_id=%s)",
        envelope_class.__name__,
        getattr(envelope, "run_id", "unknown"),
    )

    return envelope


def upload_envelope(envelope: BaseModel, uri: str) -> None:
    """
    Serialize and upload a Pydantic envelope to storage.

    Supports both gs:// (GCS) and file:// (local filesystem) URIs.

    Args:
        envelope: Pydantic model instance to upload
        uri: Storage URI where the envelope should be uploaded

    Raises:
        ValueError: If URI is invalid.
        StorageConflictError: If the destination identity already exists.
    """
    logger.info("Uploading %s to %s", envelope.__class__.__name__, uri)

    # Serialize to JSON
    json_content = envelope.model_dump_json(indent=2, exclude_none=True)

    scheme, path = parse_uri(uri)

    if scheme == "gs":
        _upload_gcs_text(uri, json_content)
    elif scheme == "file":
        _write_local_file(path, json_content)
    else:
        raise ValueError(f"Unsupported URI scheme: {scheme}")

    logger.info("Successfully uploaded envelope to %s", uri)


def stored_object_exists(uri: str) -> bool:
    """Return whether the exact output identity already exists."""
    scheme, path = parse_uri(uri)
    if scheme == "file":
        return Path(path).is_file()
    if scheme == "gs":
        assert_gcs_uri_allowed(uri)
        bucket_name, blob_path = parse_gcs_uri(uri)
        client = _get_gcs_client()
        return bool(client.bucket(bucket_name).blob(blob_path).exists())
    raise ValueError(f"Unsupported URI scheme: {scheme}")


# =============================================================================
# File Operations
# =============================================================================


def download_verified_file(
    item: _IntegrityBoundFile,
    destination: Path,
) -> VerifiedFile:
    """Stream one exact immutable file into place after full verification.

    The expected size is a hard byte ceiling, not merely metadata checked after
    download. Bytes are written to a sibling temporary file, hashed during the
    stream, and exposed through an atomic create-only commit only after size,
    SHA-256, and storage version all match. An existing destination is a
    contract conflict, including when it already contains the expected bytes.

    GCS reads pin ``item.storage_version`` as the blob generation. Local
    attempt files use ``sha256:<digest>`` as their immutable version policy and
    are still hashed end to end before use.
    """
    uri = str(item.uri)
    logger.info("Streaming verified file from %s to %s", uri, destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _reject_existing_local_destination(destination)

    fd, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".part",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as target:
            scheme, path = parse_uri(uri)
            if scheme == "file":
                _verify_local_storage_version(item)
                source_path = Path(path)
                if not source_path.is_file():
                    msg = f"Input file does not exist or is not a file: {uri}"
                    raise FileVerificationError(msg)
                with source_path.open("rb") as source:
                    actual_size, actual_sha256 = _stream_and_verify(
                        source=source,
                        target=target,
                        item=item,
                    )
            elif scheme == "gs":
                with _open_exact_gcs_generation(item) as source:
                    actual_size, actual_sha256 = _stream_and_verify(
                        source=source,
                        target=target,
                        item=item,
                    )
            else:  # pragma: no cover - parse_uri rejects unsupported schemes
                msg = f"Unsupported URI scheme: {scheme}"
                raise FileVerificationError(msg)

        _commit_local_temp_create_only(temporary_path, destination)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise

    verified = VerifiedFile(
        path=destination,
        uri=uri,
        size_bytes=actual_size,
        sha256=actual_sha256,
        storage_version=str(item.storage_version),
    )
    logger.info(
        "Verified %s (%d bytes, sha256=%s, version=%s)",
        uri,
        verified.size_bytes,
        verified.sha256,
        verified.storage_version,
    )
    return verified


def _verify_local_storage_version(item: _IntegrityBoundFile) -> None:
    """Require the content-addressed version used by read-only local inputs."""
    expected = f"{LOCAL_STORAGE_VERSION_PREFIX}{item.sha256}"
    if item.storage_version != expected:
        msg = (
            "Local input storage_version must bind to its declared digest: "
            f"expected {expected!r}, got {item.storage_version!r}"
        )
        raise FileVerificationError(msg)


def _open_exact_gcs_generation(item: _IntegrityBoundFile):
    """Open the exact GCS generation named by an integrity-bound item."""
    assert_gcs_uri_allowed(str(item.uri))
    try:
        generation = int(item.storage_version)
    except (TypeError, ValueError) as exc:
        msg = f"GCS storage_version must be a numeric generation: {item.storage_version!r}"
        raise FileVerificationError(msg) from exc
    if generation <= 0:
        msg = f"GCS generation must be positive: {generation}"
        raise FileVerificationError(msg)

    bucket_name, blob_path = parse_gcs_uri(str(item.uri))
    client = _get_gcs_client()
    blob = client.bucket(bucket_name).blob(blob_path, generation=generation)
    try:
        blob.reload(if_generation_match=generation)
    except Exception as exc:
        msg = f"Could not open the committed GCS generation {generation} for {item.uri}: {exc}"
        raise FileVerificationError(msg) from exc

    if blob.generation is None or int(blob.generation) != generation:
        msg = (
            f"GCS generation mismatch for {item.uri}: expected {generation}, got {blob.generation}"
        )
        raise FileVerificationError(msg)
    if blob.size is not None and int(blob.size) != item.size_bytes:
        msg = (
            f"GCS object size mismatch for {item.uri}: expected {item.size_bytes}, got {blob.size}"
        )
        raise FileVerificationError(msg)

    return blob.open(
        "rb",
        chunk_size=STREAM_CHUNK_SIZE,
        if_generation_match=generation,
    )


def _stream_and_verify(
    *,
    source: BinaryIO,
    target: BinaryIO,
    item: _IntegrityBoundFile,
) -> tuple[int, str]:
    """Copy bounded chunks while calculating and enforcing exact identity."""
    digest = hashlib.sha256()
    total = 0

    while True:
        # Read at most one byte beyond the declared ceiling. That single byte
        # is enough to prove the stream is too long without accepting a whole
        # extra SDK chunk from a lying or stale object.
        remaining_with_sentinel = item.size_bytes - total + 1
        chunk = source.read(min(STREAM_CHUNK_SIZE, remaining_with_sentinel))
        if not chunk:
            break
        total += len(chunk)
        if total > item.size_bytes:
            msg = (
                f"Input file exceeds its declared size for {item.uri}: "
                f"expected {item.size_bytes} bytes, received more than that"
            )
            raise FileVerificationError(msg)
        digest.update(chunk)
        target.write(chunk)

    if total != item.size_bytes:
        msg = (
            f"Input file size mismatch for {item.uri}: expected "
            f"{item.size_bytes}, received {total}"
        )
        raise FileVerificationError(msg)

    actual_sha256 = digest.hexdigest()
    if actual_sha256 != item.sha256:
        msg = (
            f"Input file SHA-256 mismatch for {item.uri}: expected "
            f"{item.sha256}, got {actual_sha256}"
        )
        raise FileVerificationError(msg)
    return total, actual_sha256


def upload_file(source: Path, uri: str, content_type: str | None = None) -> StoredFile:
    """
    Upload a file from local filesystem to storage.

    Supports both gs:// (GCS) and file:// (local filesystem) URIs.

    Args:
        source: Local path to the file
        uri: Storage URI where file should be uploaded
        content_type: Optional MIME type for the file (used for GCS only)

    Raises:
        ValueError: If URI is invalid or source file doesn't exist.
        StorageConflictError: If the destination identity already exists.
    """
    if not source.exists():
        raise ValueError(f"Source file does not exist: {source}")

    logger.info("Uploading file from %s to %s", source, uri)

    scheme, path = parse_uri(uri)

    size_bytes, sha256 = _file_identity(source)
    if scheme == "gs":
        storage_version = _upload_gcs_file(source, uri, content_type)
    elif scheme == "file":
        _copy_local_file(source, Path(path))
        storage_version = f"{LOCAL_STORAGE_VERSION_PREFIX}{sha256}"
    else:
        raise ValueError(f"Unsupported URI scheme: {scheme}")

    logger.info("Successfully uploaded file to %s (%d bytes)", uri, source.stat().st_size)
    return StoredFile(
        uri=uri,
        size_bytes=size_bytes,
        sha256=sha256,
        storage_version=storage_version,
    )


def upload_directory(
    source_dir: Path, base_uri: str, manifest_path: str = "manifest.json"
) -> dict:
    """
    Upload an entire directory to storage and create a manifest.

    Supports both gs:// (GCS) and file:// (local filesystem) URIs.

    Args:
        source_dir: Local directory to upload
        base_uri: Storage URI prefix (e.g., 'gs://bucket/path/' or 'file:///app/storage/')
        manifest_path: Relative path for manifest file within base_uri

    Returns:
        Manifest dict with file listings

    Raises:
        ValueError: If source_dir doesn't exist or base_uri is invalid
    """
    if not source_dir.exists():
        raise ValueError(f"Source directory does not exist: {source_dir}")

    logger.info("Uploading directory %s to %s", source_dir, base_uri)

    # Ensure base_uri ends with /
    if not base_uri.endswith("/"):
        base_uri += "/"

    files_uploaded: list[_UploadedFileManifestItem] = []

    # Upload all files in directory
    for file_path in source_dir.rglob("*"):
        if file_path.is_file():
            # Calculate relative path from source_dir
            rel_path = file_path.relative_to(source_dir)
            file_uri = f"{base_uri}{rel_path.as_posix()}"

            # Upload file
            stored = upload_file(file_path, file_uri)

            files_uploaded.append(
                {
                    "name": rel_path.as_posix(),
                    "uri": file_uri,
                    "size_bytes": stored.size_bytes,
                    "sha256": stored.sha256,
                    "storage_version": stored.storage_version,
                }
            )

    # Create manifest
    manifest = {
        "format": "directory",
        "base_uri": base_uri,
        "files": files_uploaded,
        "total_files": len(files_uploaded),
        "total_bytes": sum(f["size_bytes"] for f in files_uploaded),
    }

    # Upload manifest
    manifest_uri = f"{base_uri}{manifest_path}"
    scheme, path = parse_uri(manifest_uri)

    manifest_json = json.dumps(manifest, indent=2)
    if scheme == "gs":
        _upload_gcs_text(manifest_uri, manifest_json)
    elif scheme == "file":
        _write_local_file(path, manifest_json)

    logger.info("Uploaded %d files, manifest at %s", len(files_uploaded), manifest_uri)

    manifest["manifest_uri"] = manifest_uri
    return manifest


# =============================================================================
# Local Filesystem Helpers
# =============================================================================


def _read_local_file(path: str) -> str:
    """Read text content from a local file."""
    file_path = Path(path)
    if not file_path.exists():
        raise ValueError(f"File not found: {path}")
    return file_path.read_text(encoding="utf-8")


def _write_local_file(path: str, content: str) -> None:
    """Create one local text file without replacing an existing identity."""
    file_path = Path(path)
    with tempfile.TemporaryFile() as source:
        source.write(content.encode("utf-8"))
        source.seek(0)
        _copy_stream_to_local_create_only(source, file_path)


def _copy_local_file(source: Path, destination: Path) -> None:
    """Create one local output file without replacing an existing identity."""
    if not source.exists():
        raise ValueError(f"Source file not found: {source}")
    with source.open("rb") as source_file:
        _copy_stream_to_local_create_only(source_file, destination)


def _copy_stream_to_local_create_only(source: BinaryIO, destination: Path) -> None:
    """Copy a stream to a temporary sibling, then publish it create-only."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    _reject_existing_local_destination(destination)

    fd, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".part",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as target:
            shutil.copyfileobj(source, target, length=STREAM_CHUNK_SIZE)
            os.fchmod(target.fileno(), LOCAL_PUBLISHED_FILE_MODE)
        _commit_local_temp_create_only(temporary_path, destination)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def _reject_existing_local_destination(destination: Path) -> None:
    """Reject regular files, directories, symlinks, and broken symlinks."""
    if os.path.lexists(destination):
        msg = f"Create-only storage identity already exists: file://{destination}"
        raise StorageConflictError(msg)


def _commit_local_temp_create_only(
    temporary_path: Path,
    destination: Path,
) -> None:
    """Atomically expose a sibling temporary file without replacement.

    The hard-link operation is atomic and fails when ``destination`` already
    names any filesystem entry. Both paths share a parent directory, so they
    are guaranteed to be on the same filesystem.
    """
    try:
        os.link(temporary_path, destination)
    except FileExistsError as exc:
        msg = f"Create-only storage identity already exists: file://{destination}"
        raise StorageConflictError(msg) from exc
    temporary_path.unlink()


def _file_identity(path: Path) -> tuple[int, str]:
    """Return exact size and SHA-256 without buffering a file in memory."""
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while chunk := source.read(STREAM_CHUNK_SIZE):
            total += len(chunk)
            digest.update(chunk)
    return total, digest.hexdigest()


# =============================================================================
# Google Cloud Storage Helpers
# =============================================================================


def _get_gcs_client():
    """Build a GCS client with explicit attempt credentials when provided."""
    from google.cloud import storage

    credentials, project_id = build_gcs_credentials()
    if credentials is None:
        return storage.Client()
    return storage.Client(project=project_id, credentials=credentials)


def _download_gcs_text(uri: str) -> str:
    """Download text content from GCS."""
    assert_gcs_uri_allowed(uri)
    bucket_name, blob_path = parse_gcs_uri(uri)
    client = _get_gcs_client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_path)

    if not blob.exists():
        raise ValueError(f"File not found at {uri}")

    return str(blob.download_as_text())


def _upload_gcs_text(uri: str, content: str) -> None:
    """Create one GCS text object without replacing an existing generation."""
    assert_gcs_uri_allowed(uri)
    bucket_name, blob_path = parse_gcs_uri(uri)
    client = _get_gcs_client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_path)
    try:
        blob.upload_from_string(
            content,
            content_type="application/json",
            if_generation_match=0,
        )
    except Exception as exc:
        _raise_if_gcs_create_conflict(uri, exc)
        raise


def _upload_gcs_file(source: Path, uri: str, content_type: str | None = None) -> str:
    """Create a GCS file object and return its immutable generation."""
    assert_gcs_uri_allowed(uri)
    bucket_name, blob_path = parse_gcs_uri(uri)
    client = _get_gcs_client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_path)
    try:
        blob.upload_from_filename(
            str(source),
            content_type=content_type,
            if_generation_match=0,
        )
    except Exception as exc:
        _raise_if_gcs_create_conflict(uri, exc)
        raise
    if blob.generation is None:
        blob.reload()
    if blob.generation is None:
        msg = f"GCS did not return an object generation after uploading {uri}"
        raise ValueError(msg)
    return str(blob.generation)


def _raise_if_gcs_create_conflict(uri: str, exc: Exception) -> None:
    """Translate GCS's generation-precondition failure into one typed error."""
    from google.api_core.exceptions import PreconditionFailed

    if isinstance(exc, PreconditionFailed):
        msg = f"Create-only storage identity already exists: {uri}"
        raise StorageConflictError(msg) from exc
