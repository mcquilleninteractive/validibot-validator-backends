"""Tests for create-only validator input and output identities.

Attempt-specific paths prevent normal retries from selecting the same name,
but the storage layer must still reject stale files, duplicate delivery, and
concurrent writers atomically. These tests define that policy for both local
filesystems and Google Cloud Storage. A same-byte replay is intentionally a
conflict: lifecycle fencing creates a new attempt identity instead of treating
an existing object as permission to reuse prior execution state.
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

import pytest
from google.api_core.exceptions import PreconditionFailed
from pydantic import BaseModel

from validator_backends.core import storage_client
from validator_backends.core.storage_client import StorageConflictError
from validibot_shared.validations.envelopes import InputFileItem, SupportedMimeType


class _OutputEnvelope(BaseModel):
    """Small serializable model used to exercise the public envelope writer."""

    status: str


def _local_input_item(source, payload: bytes) -> InputFileItem:
    """Build a strict local file item for destination-conflict coverage."""
    digest = hashlib.sha256(payload).hexdigest()
    return InputFileItem(
        name="input.bin",
        mime_type=SupportedMimeType.FMU,
        port_key="test_input",
        uri=f"file://{source}",
        size_bytes=len(payload),
        sha256=digest,
        storage_version=f"sha256:{digest}",
    )


def _install_fake_gcs_client(monkeypatch, blob: MagicMock) -> MagicMock:
    """Install a small mocked client and return its bucket for assertions."""
    bucket = MagicMock()
    bucket.blob.return_value = blob
    client = MagicMock()
    client.bucket.return_value = bucket
    monkeypatch.setattr(storage_client, "_get_gcs_client", lambda: client)
    return bucket


def test_verified_input_refuses_an_existing_destination(tmp_path):
    """Verified bytes cannot replace stale materialization from an earlier run."""
    payload = b"expected bytes"
    source = tmp_path / "source.bin"
    source.write_bytes(payload)
    destination = tmp_path / "work" / "input.bin"
    destination.parent.mkdir()
    destination.write_bytes(b"stale bytes")

    with pytest.raises(StorageConflictError, match="already exists"):
        storage_client.download_verified_file(
            _local_input_item(source, payload),
            destination,
        )

    assert destination.read_bytes() == b"stale bytes"


def test_attempt_scratch_directory_is_safe_and_create_only(tmp_path):
    """Untrusted attempt text cannot escape the root or reuse scratch state."""
    base_dir = tmp_path / "backend-work"
    attempt_id = "../../another-run"

    work_dir = storage_client.create_attempt_work_dir(base_dir, attempt_id)

    assert work_dir.parent == base_dir
    assert work_dir.name == hashlib.sha256(attempt_id.encode()).hexdigest()
    with pytest.raises(StorageConflictError, match="scratch directory already exists"):
        storage_client.create_attempt_work_dir(base_dir, attempt_id)


def test_local_output_file_rejects_same_byte_replay(tmp_path):
    """Even an identical replay conflicts because output identities are one-shot."""
    source = tmp_path / "report.txt"
    source.write_bytes(b"report bytes")
    destination = tmp_path / "bundle" / "report.txt"
    uri = f"file://{destination}"

    storage_client.upload_file(source, uri)

    with pytest.raises(StorageConflictError, match="already exists"):
        storage_client.upload_file(source, uri)

    assert destination.read_bytes() == b"report bytes"
    assert not list(destination.parent.glob(".*.part"))


def test_local_output_envelope_rejects_same_identity_replay(tmp_path):
    """A second result envelope cannot replace the attempt's first publication."""
    destination = tmp_path / "output" / "output.json"
    uri = f"file://{destination}"

    storage_client.upload_envelope(_OutputEnvelope(status="success"), uri)

    with pytest.raises(StorageConflictError, match="already exists"):
        storage_client.upload_envelope(_OutputEnvelope(status="failure"), uri)

    assert '"success"' in destination.read_text(encoding="utf-8")
    assert '"failure"' not in destination.read_text(encoding="utf-8")


def test_gcs_output_file_uses_generation_zero_precondition(monkeypatch, tmp_path):
    """Artifact upload must ask GCS to create a new object generation only."""
    source = tmp_path / "artifact.bin"
    source.write_bytes(b"artifact bytes")
    blob = MagicMock(generation=1_700_000_000_000_123)
    bucket = _install_fake_gcs_client(monkeypatch, blob)

    stored = storage_client.upload_file(
        source,
        "gs://output-bucket/runs/attempt/outputs/artifact.bin",
        content_type="application/octet-stream",
    )

    bucket.blob.assert_called_once_with("runs/attempt/outputs/artifact.bin")
    blob.upload_from_filename.assert_called_once_with(
        str(source),
        content_type="application/octet-stream",
        if_generation_match=0,
    )
    assert stored.storage_version == "1700000000000123"


def test_gcs_output_envelope_uses_generation_zero_precondition(monkeypatch):
    """The trusted result identity is published with the same create-only rule."""
    blob = MagicMock()
    _install_fake_gcs_client(monkeypatch, blob)

    storage_client.upload_envelope(
        _OutputEnvelope(status="success"),
        "gs://output-bucket/runs/attempt/output.json",
    )

    _, kwargs = blob.upload_from_string.call_args
    assert kwargs == {
        "content_type": "application/json",
        "if_generation_match": 0,
    }


def test_gcs_precondition_failure_is_a_typed_storage_conflict(monkeypatch):
    """Callers can distinguish stale output identity from provider downtime."""
    blob = MagicMock()
    blob.upload_from_string.side_effect = PreconditionFailed("object exists")
    _install_fake_gcs_client(monkeypatch, blob)

    with pytest.raises(StorageConflictError, match="already exists"):
        storage_client.upload_envelope(
            _OutputEnvelope(status="success"),
            "gs://output-bucket/runs/attempt/output.json",
        )
