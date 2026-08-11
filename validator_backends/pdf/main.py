"""Cloud Run and local-container entrypoint for PDF package inspection."""

from __future__ import annotations

import logging
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from validator_backends.core.callback_client import post_callback
from validator_backends.core.envelope_loader import get_output_uri, load_input_envelope
from validator_backends.core.error_reporting import report_fatal
from validator_backends.core.output_identity import output_identity_for
from validator_backends.core.replay import replay_existing_output
from validator_backends.core.report_artifacts import upload_file_artifact
from validator_backends.core.storage_client import upload_envelope
from validator_backends.pdf.runner import run_pdf_validation
from validibot_shared.pdf import PdfInputEnvelope, PdfOutputEnvelope
from validibot_shared.validations.envelopes import (
    Severity,
    ValidationMessage,
    ValidationStatus,
    ValidatorType,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

_ARTIFACT_CONTRACT = {
    "pdf_inventory": ("pdf-inventory.json", "application/json"),
    "extracted_files_bundle": ("extracted-files.zip", "application/zip"),
    "xmp_metadata": ("xmp.xml", "application/xml"),
    "selected_xml": ("selected.xml", "application/xml"),
    "selected_json": ("selected.json", "application/json"),
    "selected_step_p21": ("selected.p21", "model/step"),
}


def main() -> int:
    """Execute one attempt, publish artifacts/envelope, and post its callback."""
    started_at = datetime.now(UTC)
    try:
        input_envelope = load_input_envelope(PdfInputEnvelope)
        if replay_existing_output(input_envelope, PdfOutputEnvelope):
            logger.info("Replayed existing PDF output without recompute")
            return 0

        with tempfile.TemporaryDirectory(prefix="validibot-pdf-attempt-") as tmp:
            result = run_pdf_validation(input_envelope, workspace=Path(tmp))
            artifacts = _upload_artifacts(input_envelope, result.artifact_payloads)
        finished_at = datetime.now(UTC)
        output_uri = get_output_uri(input_envelope)
        output_envelope = PdfOutputEnvelope(
            run_id=input_envelope.run_id,
            **output_identity_for(input_envelope, output_uri),
            validator=input_envelope.validator,
            status=result.status,
            timing={"started_at": started_at, "finished_at": finished_at},
            messages=result.messages,
            metrics=[],
            artifacts=artifacts,
            outputs=result.outputs,
        )
        upload_envelope(output_envelope, output_uri)
        _post_result_callback(input_envelope, result.status, output_uri)
        logger.info("PDF package inspection complete (status=%s)", result.status.value)
        return 0
    except Exception as exc:
        logger.exception("PDF package validator failed with an unexpected error")
        report_fatal(
            exc,
            context={
                "run_id": getattr(locals().get("input_envelope"), "run_id", None),
                "validator": ValidatorType.PDF,
            },
        )
        _try_publish_runtime_failure(locals().get("input_envelope"), started_at)
        return 1


def _upload_artifacts(input_envelope, payloads):
    """Upload verified staged files in stable fixed-contract order."""
    unknown = set(payloads) - set(_ARTIFACT_CONTRACT)
    if unknown:
        raise ValueError(f"PDF backend produced undeclared artifacts: {sorted(unknown)}")
    artifacts = []
    for contract_key in _ARTIFACT_CONTRACT:
        content = payloads.get(contract_key)
        if content is None:
            continue
        filename, mime_type = _ARTIFACT_CONTRACT[contract_key]
        artifacts.append(
            upload_file_artifact(
                source_path=content.path,
                execution_bundle_uri=str(input_envelope.context.execution_bundle_uri),
                filename=filename,
                artifact_type=contract_key,
                mime_type=mime_type,
                expected_size_bytes=content.size_bytes,
                expected_sha256=content.sha256,
            )
        )
    return artifacts


def _post_result_callback(input_envelope, status, output_uri: str) -> None:
    """Post the normal attempt-bound callback after durable output publication."""
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


def _try_publish_runtime_failure(input_envelope, started_at) -> None:
    """Best-effort generic failure envelope for unexpected engine failures."""
    if input_envelope is None:
        return
    try:
        output_uri = get_output_uri(input_envelope)
        failure = PdfOutputEnvelope(
            run_id=input_envelope.run_id,
            **output_identity_for(input_envelope, output_uri),
            validator=input_envelope.validator,
            status=ValidationStatus.FAILED_RUNTIME,
            timing={"started_at": started_at, "finished_at": datetime.now(UTC)},
            messages=[
                ValidationMessage(
                    severity=Severity.ERROR,
                    text="PDF package inspection failed. Please retry or contact support.",
                )
            ],
            outputs=None,
        )
        upload_envelope(failure, output_uri)
        _post_result_callback(input_envelope, ValidationStatus.FAILED_RUNTIME, output_uri)
    except Exception:
        logger.exception("Failed to publish PDF runtime-failure output")


if __name__ == "__main__":
    sys.exit(main())
