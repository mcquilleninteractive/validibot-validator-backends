"""SHACL validator container entrypoint for Cloud Run Jobs / Docker.

Loads a ``SHACLInputEnvelope``, runs SHACL validation (RDF parse + pyshacl +
SPARQL-ASK assertions) in this isolated process, writes a ``SHACLOutputEnvelope``
to storage, and POSTs the callback to Django.

The isolation is the whole point: untrusted RDF and author-supplied SPARQL only
ever execute in this container, which has no database, no secrets, and a
locked-down service account.
"""

from __future__ import annotations

import logging
import sys
from datetime import UTC, datetime

from validator_backends.core.callback_client import post_callback
from validator_backends.core.envelope_loader import get_output_uri, load_input_envelope
from validator_backends.core.error_reporting import report_fatal
from validator_backends.core.output_identity import output_identity_for
from validator_backends.core.replay import replay_existing_output
from validator_backends.core.report_artifacts import upload_text_report_artifact
from validator_backends.core.storage_client import StorageConflictError, upload_envelope
from validator_backends.shacl.runner import run_shacl_validation
from validibot_shared.shacl.envelopes import SHACLInputEnvelope, SHACLOutputEnvelope
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


def main() -> int:
    """Execute one attempt, publish artifacts/envelope, and post its callback.

    Returns the process exit code: 0 whenever the attempt reached a reportable
    conclusion, including a graph that violated its shapes. A non-zero code means
    the *container* failed, which is what tells the runtime to retry.
    """
    started_at = datetime.now(UTC)

    try:
        input_envelope = load_input_envelope(SHACLInputEnvelope)
        if replay_existing_output(input_envelope, SHACLOutputEnvelope):
            logger.info("Replayed existing SHACL output without recompute")
            return 0
        logger.info(
            "Loaded SHACL input envelope for run_id=%s validator=%s",
            input_envelope.run_id,
            input_envelope.validator.type,
        )

        result = run_shacl_validation(input_envelope)
        finished_at = datetime.now(UTC)
        artifacts = _upload_report_artifacts(input_envelope, result.outputs)

        output_uri = get_output_uri(input_envelope)
        output_envelope = SHACLOutputEnvelope(
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

        logger.info("Uploading SHACL output envelope to %s", output_uri)
        upload_envelope(output_envelope, output_uri)

        post_callback(
            callback_url=(
                str(input_envelope.context.callback_url)
                if input_envelope.context.callback_url
                else None
            ),
            run_id=input_envelope.run_id,
            status=result.status,
            result_uri=output_uri,
            callback_id=input_envelope.context.callback_id,
            callback_nonce=input_envelope.context.callback_nonce,
            skip_callback=input_envelope.context.skip_callback,
        )
        logger.info("SHACL validation complete (status=%s)", result.status.value)
        return 0

    except Exception as exc:
        logger.exception("SHACL validation failed with unexpected error")
        report_fatal(
            exc,
            context={
                "run_id": getattr(locals().get("input_envelope", None), "run_id", None),
                "validator": ValidatorType.SHACL,
            },
        )
        try:
            if "input_envelope" in locals():
                finished_at = datetime.now(UTC)
                output_uri = get_output_uri(input_envelope)
                failure_envelope = SHACLOutputEnvelope(
                    run_id=input_envelope.run_id,
                    **output_identity_for(input_envelope, output_uri),
                    validator=input_envelope.validator,
                    status=ValidationStatus.FAILED_RUNTIME,
                    timing={"started_at": started_at, "finished_at": finished_at},
                    messages=[
                        ValidationMessage(
                            severity=Severity.ERROR,
                            text=("SHACL validator failed. Please retry or contact support."),
                        ),
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
            logger.exception("Failed to send SHACL failure callback")
        return 1


def _upload_report_artifacts(input_envelope: SHACLInputEnvelope, outputs):
    """Upload SHACL report bytes for Django artifact indexing."""

    report = getattr(outputs, "results_graph_turtle", "") if outputs else ""
    if not report:
        return []

    try:
        artifact = upload_text_report_artifact(
            content=report,
            execution_bundle_uri=str(input_envelope.context.execution_bundle_uri),
            filename="shacl-report.ttl",
            artifact_type="shacl-report",
            mime_type="text/turtle",
        )
    except StorageConflictError:
        logger.exception("SHACL report output identity already exists")
        raise
    except Exception:
        logger.exception("Failed to upload SHACL report artifact; continuing without it")
        return []

    return [artifact] if artifact else []


if __name__ == "__main__":
    sys.exit(main())
