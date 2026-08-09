"""
FMU validator container entrypoint for Cloud Run Jobs.

Loads FMUInputEnvelope, runs the FMU with fmpy, writes FMUOutputEnvelope to GCS,
and POSTs the callback to Django.
"""

from __future__ import annotations

import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

from validator_backends.core.callback_client import post_callback
from validator_backends.core.envelope_loader import get_output_uri, load_input_envelope
from validator_backends.core.error_reporting import report_fatal
from validator_backends.core.output_identity import output_identity_for
from validator_backends.core.replay import replay_existing_output
from validator_backends.core.storage_client import (
    StorageConflictError,
    upload_directory,
    upload_envelope,
)
from validibot_shared.fmu.envelopes import FMUInputEnvelope, FMUOutputEnvelope
from validibot_shared.validations.envelopes import (
    RawOutputs,
    Severity,
    ValidationArtifact,
    ValidationMessage,
    ValidationStatus,
    ValidatorType,
)

from .runner import run_fmu_simulation


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)


def main() -> int:
    """Execute one attempt, publish artifacts/envelope, and post its callback.

    Returns the process exit code: 0 whenever the attempt reached a reportable
    conclusion, including a simulation that found problems. A non-zero code means
    the *container* failed, which is what tells the runtime to retry.
    """
    started_at = datetime.now(UTC)

    try:
        input_envelope = load_input_envelope(FMUInputEnvelope)
        if replay_existing_output(input_envelope, FMUOutputEnvelope):
            logger.info("Replayed existing FMU output without recompute")
            return 0
        logger.info(
            "Loaded FMU input envelope for run_id=%s validator=%s",
            input_envelope.run_id,
            input_envelope.validator.type,
        )

        outputs, work_dir = run_fmu_simulation(input_envelope)

        status = ValidationStatus.SUCCESS
        finished_at = datetime.now(UTC)

        artifacts: list[ValidationArtifact] = []
        raw_outputs: RawOutputs | None = None
        try:
            execution_bundle_uri = str(input_envelope.context.execution_bundle_uri)
            artifacts, raw_outputs = _upload_outputs(work_dir, execution_bundle_uri)
        except StorageConflictError:
            logger.exception("FMU output identity already exists")
            raise
        except Exception:
            logger.exception("Failed to upload FMU outputs; continuing without artifacts")

        output_uri = get_output_uri(input_envelope)
        output_envelope = FMUOutputEnvelope(
            run_id=input_envelope.run_id,
            **output_identity_for(input_envelope, output_uri),
            validator=input_envelope.validator,
            status=status,
            timing={
                "started_at": started_at,
                "finished_at": finished_at,
            },
            messages=[],
            metrics=[],
            artifacts=artifacts,
            outputs=outputs,
            raw_outputs=raw_outputs,
        )

        logger.info("Uploading FMU output envelope to %s", output_uri)
        upload_envelope(output_envelope, output_uri)

        post_callback(
            callback_url=(
                str(input_envelope.context.callback_url)
                if input_envelope.context.callback_url
                else None
            ),
            run_id=input_envelope.run_id,
            status=status,
            result_uri=output_uri,
            callback_id=input_envelope.context.callback_id,
            callback_nonce=input_envelope.context.callback_nonce,
            skip_callback=input_envelope.context.skip_callback,
        )
        logger.info("FMU validation complete (status=%s)", status.value)
        _cleanup(work_dir)
        return 0

    except Exception as exc:
        logger.exception("FMU validation failed with unexpected error")
        report_fatal(
            exc,
            context={
                "run_id": getattr(locals().get("input_envelope", None), "run_id", None),
                "validator": ValidatorType.FMU,
            },
        )
        try:
            if "input_envelope" in locals():
                finished_at = datetime.now(UTC)
                output_uri = get_output_uri(input_envelope)
                failure_envelope = FMUOutputEnvelope(
                    run_id=input_envelope.run_id,
                    **output_identity_for(input_envelope, output_uri),
                    validator=input_envelope.validator,
                    status=ValidationStatus.FAILED_RUNTIME,
                    timing={
                        "started_at": started_at,
                        "finished_at": finished_at,
                    },
                    messages=[
                        ValidationMessage(
                            severity=Severity.ERROR,
                            text="FMU validator failed. Please retry or contact support.",
                        )
                    ],
                    outputs=None,
                )
                upload_envelope(failure_envelope, output_uri)
                post_callback(
                    callback_url=(
                        str(input_envelope.context.callback_url)
                        if input_envelope.context.callback_url
                        else None
                    ),
                    run_id=input_envelope.run_id,
                    status=ValidationStatus.FAILED_RUNTIME,
                    result_uri=output_uri,
                    callback_id=input_envelope.context.callback_id,
                    callback_nonce=input_envelope.context.callback_nonce,
                    skip_callback=input_envelope.context.skip_callback,
                )
        except Exception:
            logger.exception("Failed to send failure callback")
        return 1


def _cleanup(work_dir: Path) -> None:
    """Best-effort cleanup of the working directory."""
    try:
        if work_dir.exists():
            for child in work_dir.iterdir():
                if child.is_file():
                    child.unlink(missing_ok=True)
            work_dir.rmdir()
    except Exception:
        logger.debug("Cleanup failed for %s", work_dir, exc_info=True)


if __name__ == "__main__":
    sys.exit(main())


def _upload_outputs(
    work_dir: Path,
    execution_bundle_uri: str,
) -> tuple[list[ValidationArtifact], RawOutputs | None]:
    """Upload any generated files (if present) and return artifact metadata."""
    base_uri = execution_bundle_uri.rstrip("/")
    outputs_uri = f"{base_uri}/outputs"
    manifest = upload_directory(
        work_dir,
        outputs_uri,
        manifest_path="manifest.json",
    )

    artifacts: list[ValidationArtifact] = []
    for item in manifest.get("files", []):
        name = item.get("name", "")
        uri = item.get("uri", "")
        size_bytes = item.get("size_bytes")
        sha256 = item.get("sha256", "")
        storage_version = item.get("storage_version", "")
        artifacts.append(
            ValidationArtifact(
                name=Path(name).name,
                type="file",
                mime_type=_guess_mime_type(name),
                uri=uri,
                size_bytes=size_bytes,
                sha256=sha256,
                storage_version=storage_version,
            )
        )

    raw_outputs = RawOutputs(
        format=manifest.get("format", "directory"),
        manifest_uri=manifest.get("manifest_uri", f"{outputs_uri}/manifest.json"),
    )
    return artifacts, raw_outputs


def _guess_mime_type(name: str) -> str | None:
    """Return a content type for the few artifact kinds FMU runs actually emit.

    Deliberately not ``mimetypes.guess_type``: the stdlib consults system files
    that differ between the build image and the runtime image, so the same
    artifact could be labelled differently across environments. ``None`` means
    "let storage decide" and is the correct answer for everything else here.
    """
    lowered = name.lower()
    if lowered.endswith(".txt") or lowered.endswith(".log"):
        return "text/plain"
    if lowered.endswith(".json"):
        return "application/json"
    return None
