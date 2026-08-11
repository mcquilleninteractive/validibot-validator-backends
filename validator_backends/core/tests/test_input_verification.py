"""Tests for bounded, immutable validator input materialization.

The runtime must not parse or execute a file merely because its URI resolves.
These tests pin the execution boundary: exact size is enforced as a streaming
ceiling, SHA-256 is calculated over the received bytes, provider version
identity is checked before the read, and the destination appears only after all
checks pass. Both local attempt mounts and generation-pinned GCS reads use the
same public helper, and interrupted streams never leave partial committed data.
"""

from __future__ import annotations

import hashlib
import io

import pytest

from validator_backends.core import storage_client
from validator_backends.core.storage_client import FileVerificationError, download_verified_file
from validibot_shared.validations.envelopes import InputFileItem, SupportedMimeType


def _sha256(payload: bytes) -> str:
    """Return the lowercase digest format required by the shared contract."""
    return hashlib.sha256(payload).hexdigest()


def _local_item(path, payload: bytes, **overrides) -> InputFileItem:
    """Build a strict local item, with overrides for negative-path tests."""
    digest = overrides.pop("sha256", _sha256(payload))
    values = {
        "name": "input.bin",
        "mime_type": SupportedMimeType.FMU,
        "port_key": "test_input",
        "uri": f"file://{path}",
        "size_bytes": len(payload),
        "sha256": digest,
        "storage_version": f"sha256:{digest}",
    }
    values.update(overrides)
    return InputFileItem(**values)


def _gcs_item(payload: bytes, **overrides) -> InputFileItem:
    """Build a generation-pinned GCS item for fake-client tests."""
    values = {
        "name": "input.bin",
        "mime_type": SupportedMimeType.FMU,
        "port_key": "test_input",
        "uri": "gs://input-bucket/runs/attempt/input.bin",
        "size_bytes": len(payload),
        "sha256": _sha256(payload),
        "storage_version": "1700000000000000",
    }
    values.update(overrides)
    return InputFileItem(**values)


class _FakeBlob:
    """Small generation-aware Blob stand-in used to inspect API arguments."""

    def __init__(
        self,
        payload: bytes,
        generation: int,
        *,
        reload_error=None,
        stream=None,
    ):
        self.payload = payload
        self.generation = generation
        self.size = len(payload)
        self.reload_error = reload_error
        self.stream = stream
        self.reload_kwargs = None
        self.open_kwargs = None

    def reload(self, **kwargs):
        """Record the generation precondition or simulate provider failure."""
        self.reload_kwargs = kwargs
        if self.reload_error is not None:
            raise self.reload_error

    def open(self, mode, **kwargs):
        """Return a bounded in-memory stream while recording read options."""
        assert mode == "rb"
        self.open_kwargs = kwargs
        return self.stream or io.BytesIO(self.payload)


class _InterruptedStream(io.BytesIO):
    """Raise after yielding one chunk to model a broken provider response."""

    def read(self, size=-1):
        """Return initial bytes, then fail before end-of-stream confirmation."""
        if self.tell() > 0:
            raise OSError("connection interrupted")
        return super().read(size)


class _FakeBucket:
    """Capture the object name and generation used to create a blob handle."""

    def __init__(self, blob):
        self._blob = blob
        self.requested = None

    def blob(self, name, *, generation):
        """Return the configured blob for the requested immutable generation."""
        self.requested = (name, generation)
        return self._blob


class _FakeClient:
    """Capture the bucket selected by the storage helper."""

    def __init__(self, bucket):
        self._bucket = bucket
        self.requested_bucket = None

    def bucket(self, name):
        """Return the configured bucket and record its trusted URI component."""
        self.requested_bucket = name
        return self._bucket


def test_local_file_is_atomically_committed_after_full_verification(tmp_path):
    """Matching local bytes produce a typed verified record and final file."""
    payload = b"verified local bytes"
    source = tmp_path / "source.bin"
    source.write_bytes(payload)
    destination = tmp_path / "work" / "input.bin"

    verified = download_verified_file(_local_item(source, payload), destination)

    assert destination.read_bytes() == payload
    assert verified.path == destination
    assert verified.size_bytes == len(payload)
    assert verified.sha256 == _sha256(payload)
    assert not list(destination.parent.glob(".*.part"))


@pytest.mark.parametrize(
    ("item_overrides", "message"),
    [
        ({"size_bytes": 4}, "exceeds its declared size"),
        ({"size_bytes": 100}, "size mismatch"),
        (
            {
                "sha256": "0" * 64,
                "storage_version": f"sha256:{'0' * 64}",
            },
            "SHA-256 mismatch",
        ),
        ({"storage_version": "sha256:" + "f" * 64}, "must bind"),
    ],
)
def test_local_contract_mismatch_never_commits_destination(
    tmp_path,
    item_overrides,
    message,
):
    """Size, digest, or version failure leaves no executable final file."""
    payload = b"unexpected bytes"
    source = tmp_path / "source.bin"
    source.write_bytes(payload)
    destination = tmp_path / "input.bin"
    item = _local_item(source, payload, **item_overrides)

    with pytest.raises(FileVerificationError, match=message):
        download_verified_file(item, destination)

    assert not destination.exists()
    assert not list(tmp_path.glob(".*.part"))


def test_gcs_read_pins_generation_and_verifies_stream(monkeypatch, tmp_path):
    """GCS materialization selects and preconditions the exact generation."""
    payload = b"generation-pinned bytes"
    generation = 1_700_000_000_000_000
    blob = _FakeBlob(payload, generation)
    bucket = _FakeBucket(blob)
    client = _FakeClient(bucket)
    monkeypatch.setattr(storage_client, "_get_gcs_client", lambda: client)
    destination = tmp_path / "input.bin"

    verified = download_verified_file(_gcs_item(payload), destination)

    assert verified.storage_version == str(generation)
    assert destination.read_bytes() == payload
    assert client.requested_bucket == "input-bucket"
    assert bucket.requested == ("runs/attempt/input.bin", generation)
    assert blob.reload_kwargs == {"if_generation_match": generation}
    assert blob.open_kwargs["if_generation_match"] == generation
    assert blob.open_kwargs["chunk_size"] == storage_client.STREAM_CHUNK_SIZE


def test_gcs_metadata_size_mismatch_fails_before_open(monkeypatch, tmp_path):
    """Provider size metadata rejects a wrong contract before any byte read."""
    payload = b"provider bytes"
    generation = 1_700_000_000_000_000
    blob = _FakeBlob(payload, generation)
    bucket = _FakeBucket(blob)
    monkeypatch.setattr(
        storage_client,
        "_get_gcs_client",
        lambda: _FakeClient(bucket),
    )

    with pytest.raises(FileVerificationError, match="GCS object size mismatch"):
        download_verified_file(
            _gcs_item(payload, size_bytes=len(payload) + 1),
            tmp_path / "input.bin",
        )

    assert blob.open_kwargs is None
    assert not (tmp_path / "input.bin").exists()


def test_unavailable_gcs_generation_fails_closed(monkeypatch, tmp_path):
    """A stale/deleted generation is a contract error, never an empty input."""
    payload = b"provider bytes"
    generation = 1_700_000_000_000_000
    blob = _FakeBlob(payload, generation, reload_error=RuntimeError("not found"))
    monkeypatch.setattr(
        storage_client,
        "_get_gcs_client",
        lambda: _FakeClient(_FakeBucket(blob)),
    )

    with pytest.raises(FileVerificationError, match="committed GCS generation"):
        download_verified_file(_gcs_item(payload), tmp_path / "input.bin")

    assert not (tmp_path / "input.bin").exists()


def test_gcs_generation_mismatch_fails_before_open(monkeypatch, tmp_path):
    """Provider metadata cannot silently redirect a pinned generation read."""
    payload = b"provider bytes"
    declared_generation = 1_700_000_000_000_000
    blob = _FakeBlob(payload, declared_generation + 1)
    monkeypatch.setattr(
        storage_client,
        "_get_gcs_client",
        lambda: _FakeClient(_FakeBucket(blob)),
    )

    with pytest.raises(FileVerificationError, match="GCS generation mismatch"):
        download_verified_file(_gcs_item(payload), tmp_path / "input.bin")

    assert blob.open_kwargs is None
    assert not (tmp_path / "input.bin").exists()


def test_interrupted_gcs_stream_never_commits_destination(monkeypatch, tmp_path):
    """A partial provider response must leave no executable final file."""
    payload = b"provider bytes"
    generation = 1_700_000_000_000_000
    blob = _FakeBlob(payload, generation, stream=_InterruptedStream(payload))
    monkeypatch.setattr(
        storage_client,
        "_get_gcs_client",
        lambda: _FakeClient(_FakeBucket(blob)),
    )
    destination = tmp_path / "input.bin"

    with pytest.raises(OSError, match="connection interrupted"):
        download_verified_file(_gcs_item(payload), destination)

    assert not destination.exists()
    assert not list(tmp_path.glob(".*.part"))


def test_local_upload_returns_complete_immutable_identity(tmp_path):
    """Output envelopes need identity derived from the bytes actually stored."""
    payload = b"artifact bytes written by a validator"
    source = tmp_path / "report.json"
    destination = tmp_path / "bundle" / "report.json"
    source.write_bytes(payload)

    stored = storage_client.upload_file(source, f"file://{destination}")

    digest = _sha256(payload)
    assert destination.read_bytes() == payload
    assert stored.uri == f"file://{destination}"
    assert stored.size_bytes == len(payload)
    assert stored.sha256 == digest
    assert stored.storage_version == f"sha256:{digest}"
