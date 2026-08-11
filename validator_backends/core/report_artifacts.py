"""Helpers for uploading single report artifacts from backend output text."""

from __future__ import annotations

import tempfile
from pathlib import Path

from validator_backends.core.storage_client import upload_file
from validibot_shared.validations.envelopes import ValidationArtifact


def upload_text_report_artifact(
    *,
    content: str,
    execution_bundle_uri: str,
    filename: str,
    artifact_type: str,
    mime_type: str,
) -> ValidationArtifact | None:
    """Upload report text as one backend ``ValidationArtifact``.

    Backends often produce a canonical report as text inside their typed output
    model. This helper materializes those bytes into storage so Django can
    index the report through the normal produced-artifact path.
    """

    if not content:
        return None

    base_uri = execution_bundle_uri.rstrip("/")
    artifact_uri = f"{base_uri}/outputs/{filename}"

    with tempfile.TemporaryDirectory(prefix="validibot-report-") as tmp:
        report_path = Path(tmp) / filename
        report_path.write_text(content, encoding="utf-8")
        stored = upload_file(report_path, artifact_uri, content_type=mime_type)

    return ValidationArtifact(
        name=filename,
        type=artifact_type,
        mime_type=mime_type,
        uri=artifact_uri,
        size_bytes=stored.size_bytes,
        sha256=stored.sha256,
        storage_version=stored.storage_version,
    )


def upload_bytes_artifact(
    *,
    content: bytes,
    execution_bundle_uri: str,
    filename: str,
    artifact_type: str,
    mime_type: str,
) -> ValidationArtifact:
    """Upload exact backend-produced bytes as one trusted output artifact."""
    base_uri = execution_bundle_uri.rstrip("/")
    artifact_uri = f"{base_uri}/outputs/{filename}"

    with tempfile.TemporaryDirectory(prefix="validibot-artifact-") as tmp:
        artifact_path = Path(tmp) / filename
        artifact_path.write_bytes(content)
        stored = upload_file(artifact_path, artifact_uri, content_type=mime_type)

    return ValidationArtifact(
        name=filename,
        type=artifact_type,
        mime_type=mime_type,
        uri=artifact_uri,
        size_bytes=stored.size_bytes,
        sha256=stored.sha256,
        storage_version=stored.storage_version,
    )


def upload_file_artifact(
    *,
    source_path: Path,
    execution_bundle_uri: str,
    filename: str,
    artifact_type: str,
    mime_type: str,
    expected_size_bytes: int,
    expected_sha256: str,
) -> ValidationArtifact:
    """Upload one already-staged artifact after verifying its local identity.

    Large backends stage bounded outputs directly on disk. Accepting that path
    avoids copying the artifact through a second in-memory ``bytes`` value or a
    second temporary file before the storage client streams it to its immutable
    destination. The engine-provided identity is checked against what the
    storage client actually read, so mutation between staging and upload fails
    the attempt instead of publishing misleading evidence.
    """
    base_uri = execution_bundle_uri.rstrip("/")
    artifact_uri = f"{base_uri}/outputs/{filename}"
    stored = upload_file(source_path, artifact_uri, content_type=mime_type)
    if stored.size_bytes != expected_size_bytes or stored.sha256 != expected_sha256:
        msg = f"Staged artifact identity changed before upload: {source_path}"
        raise ValueError(msg)

    return ValidationArtifact(
        name=filename,
        type=artifact_type,
        mime_type=mime_type,
        uri=artifact_uri,
        size_bytes=stored.size_bytes,
        sha256=stored.sha256,
        storage_version=stored.storage_version,
    )
