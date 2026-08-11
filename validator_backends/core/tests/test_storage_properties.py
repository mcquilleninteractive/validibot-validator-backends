"""Bounded properties for backend scratch and input-materialization security.

Execution attempt IDs and file bytes have crossed the envelope trust boundary.
For every non-empty attempt ID up to 256 Unicode code points, scratch creation
must produce one hashed direct child and reject reuse with
``StorageConflictError``. For every generated payload up to 4 KiB, exact size,
SHA-256, and local content-addressed storage identity must all agree before the
destination appears. Contract mismatches are legitimate
``FileVerificationError`` rejections and may never leave committed or partial
files behind.

These are deliberately small pull-request budgets. Production files are
streamed under the envelope's exact byte ceiling, and the surrounding runtime
owns its independent wall-clock, memory, disk, and container limits.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from hypothesis import given
from hypothesis import strategies as st

from validator_backends.core.storage_client import (
    FileVerificationError,
    StorageConflictError,
    create_attempt_work_dir,
    download_verified_file,
)
from validibot_shared.validations.envelopes import InputFileItem, SupportedMimeType


ATTEMPT_IDS = st.text(
    alphabet=st.characters(exclude_categories=("Cs",)),
    min_size=1,
    max_size=256,
)
FILE_PAYLOADS = st.binary(max_size=4_096)
NONEMPTY_FILE_PAYLOADS = st.binary(min_size=1, max_size=4_096)


def _local_item(
    source: Path,
    declared_payload: bytes,
    *,
    sha256: str | None = None,
) -> InputFileItem:
    """Build a local immutable-file contract from the declared byte identity."""
    digest = sha256 or hashlib.sha256(declared_payload).hexdigest()
    return InputFileItem(
        name="input.bin",
        mime_type=SupportedMimeType.FMU,
        port_key="test_input",
        uri=f"file://{source}",
        size_bytes=len(declared_payload),
        sha256=digest,
        storage_version=f"sha256:{digest}",
    )


# Attempt paths protect one execution from traversal and stale-state reuse.


@given(ATTEMPT_IDS)
def test_attempt_scratch_is_a_hashed_create_only_child(attempt_id: str) -> None:
    """Hostile attempt text must neither shape a path nor reopen old scratch."""
    with TemporaryDirectory(prefix="validibot-scratch-property-") as temporary:
        base_dir = Path(temporary) / "backend-work"

        work_dir = create_attempt_work_dir(base_dir, attempt_id)

        assert work_dir.parent == base_dir
        assert work_dir.name == hashlib.sha256(attempt_id.encode("utf-8")).hexdigest()
        with pytest.raises(StorageConflictError, match="already exists"):
            create_attempt_work_dir(base_dir, attempt_id)


# Stream properties protect the atomic exact-byte execution boundary.


@given(FILE_PAYLOADS)
def test_exact_local_bytes_are_atomically_materialized(payload: bytes) -> None:
    """Every exact bounded payload must commit with its verified byte identity."""
    with TemporaryDirectory(prefix="validibot-input-property-") as temporary:
        root = Path(temporary)
        source = root / "source.bin"
        destination = root / "work" / "input.bin"
        source.write_bytes(payload)

        verified = download_verified_file(
            _local_item(source, payload),
            destination,
        )

        assert destination.read_bytes() == payload
        assert verified.size_bytes == len(payload)
        assert verified.sha256 == hashlib.sha256(payload).hexdigest()
        assert not list(destination.parent.glob(".*.part"))


@given(
    NONEMPTY_FILE_PAYLOADS,
    st.sampled_from(["too_long", "too_short", "wrong_digest"]),
)
def test_generated_identity_mismatches_never_commit(
    declared_payload: bytes,
    mutation: str,
) -> None:
    """Any size or digest disagreement must fail before bytes become executable."""
    actual_payload = declared_payload
    digest_override: str | None = None
    if mutation == "too_long":
        actual_payload += b"\x00"
    elif mutation == "too_short":
        actual_payload = declared_payload[:-1]
    else:
        digest_override = "0" * 64

    with TemporaryDirectory(prefix="validibot-input-property-") as temporary:
        root = Path(temporary)
        source = root / "source.bin"
        destination = root / "work" / "input.bin"
        source.write_bytes(actual_payload)

        with pytest.raises(FileVerificationError):
            download_verified_file(
                _local_item(
                    source,
                    declared_payload,
                    sha256=digest_override,
                ),
                destination,
            )

        assert not destination.exists()
        assert not list(destination.parent.glob(".*.part"))
