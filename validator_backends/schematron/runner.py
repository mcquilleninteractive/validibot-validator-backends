"""Schematron validation runner for the isolated container backend.

Orchestrates one run from the typed input envelope (ADR-2026-07-01 D3/D4b):

1. Resolve and download the declared ``xml_document``; write the author's
   rules — which arrived **inline** in ``inputs.schematron_text`` — to a
   working file.
2. Re-apply the hardened-XML guard to the submission (D8, defence in depth).
3. Compile the rules (SchXslt2 transpile) and run them under Saxon, all
   inside one hard wall-clock timeout.
4. Parse the SVRL with the canonical shared parser and assemble
   ``SchematronOutputs`` — counts, the ``finding_rule_ids_by_severity``
   map, capped findings with an explicit truncation marker, and the D5
   provenance (the rules' sha256 from the envelope, the detected query
   binding, and the engine that actually ran).

Every "couldn't run the rules" outcome maps to the D9 taxonomy
(``engine_status`` + ``engine_error_code``) with ``passed=None`` — never to
fabricated rule findings. In particular, rules that fail to COMPILE report
``rules_invalid``: an authoring problem, distinct from generic engine
errors. The CEL/Basic output assertions are intentionally NOT run here —
they operate on the extracted signals and stay in Django, evaluated by
``SchematronValidator.post_execute_validate``.
"""

from __future__ import annotations

import logging
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from validator_backends.core.storage_client import download_verified_file
from validator_backends.schematron import engine
from validibot_shared.schematron.envelopes import (
    ENGINE_STATUS_ERROR,
    ENGINE_STATUS_OK,
    ENGINE_STATUS_TIMEOUT,
    SchematronFinding,
    SchematronOutputs,
)
from validibot_shared.schematron.svrl import (
    SEVERITY_ERROR,
    SEVERITY_WARNING,
    SvrlParseError,
    parse_svrl,
)
from validibot_shared.validations.envelopes import (
    MessageLocation,
    Severity,
    ValidationMessage,
    ValidationStatus,
)
from validibot_shared.validations.file_ports import select_input_file


if TYPE_CHECKING:
    from validibot_shared.schematron.envelopes import SchematronInputEnvelope

logger = logging.getLogger(__name__)

XML_DOCUMENT_PORT_KEY = "xml_document"

# Findings-severity strings → the shared Severity enum for the generic
# ``messages`` list (Django rebuilds rich findings from outputs.findings;
# messages are the lowest-common-denominator view).
_SEVERITY_TO_ENUM = {
    SEVERITY_ERROR: Severity.ERROR,
    SEVERITY_WARNING: Severity.WARNING,
}


class SchematronRunResult(NamedTuple):
    """What ``main.py`` needs to assemble the output envelope."""

    status: ValidationStatus
    messages: list[ValidationMessage]
    outputs: SchematronOutputs
    svrl_text: str = ""


def _xml_document_item(input_envelope: SchematronInputEnvelope):
    """Return the Schematron XML document through the shared matcher."""
    return select_input_file(
        input_envelope.input_files,
        port_key=XML_DOCUMENT_PORT_KEY,
    )


def run_schematron_validation(
    input_envelope: SchematronInputEnvelope,
) -> SchematronRunResult:
    """Execute one Schematron run per the input envelope."""
    inputs = input_envelope.inputs
    started = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="schematron-") as tmp:
        tmpdir = Path(tmp)
        submission_path = tmpdir / "submission.xml"
        sch_path = tmpdir / "rules.sch"
        svrl_path = tmpdir / "report.svrl"

        try:
            submission_item = _xml_document_item(input_envelope)
            download_verified_file(submission_item, submission_path)
            sch_path.write_text(inputs.schematron_text, encoding="utf-8")

            # Both inputs are untrusted, and NOTHING must parse them before the
            # guards run. Guard the author's RULES (D8b — they may have reached
            # this container by a path Django's authoring guard never covered)
            # and the submitted XML (D8a) FIRST, so the size/depth caps and the
            # defusedxml posture apply before any parse — including the
            # provenance detection below and Saxon's compile. Defence in depth.
            engine.guard_rules(
                sch_path,
                max_bytes=inputs.max_input_bytes,
                max_depth=inputs.max_input_depth,
            )
            engine.guard_submission(
                submission_path,
                max_bytes=inputs.max_input_bytes,
                max_depth=inputs.max_input_depth,
            )

            # Provenance only AFTER the rules source has passed the hardening
            # check — detect_query_binding parses the .sch, so an oversize or
            # over-deep document must be rejected by guard_rules first.
            query_binding = engine.detect_query_binding(sch_path)
            # ``xslt_timeout_seconds`` is enforced per run (the worker
            # subprocess's wall-clock). ``inputs.max_memory_mb`` is deliberately
            # NOT enforced here: memory is bounded at the container level by the
            # Cloud Run Job's ``--memory`` allocation, so the per-run field is
            # advisory. An OOM surfaces as an engine error (D9), never a hang.
            svrl_text = engine.run_schematron(
                sch_path,
                submission_path,
                svrl_path,
                timeout_seconds=inputs.xslt_timeout_seconds,
            )
            summary = parse_svrl(
                svrl_text,
                max_findings=engine.clamp(
                    inputs.max_findings,
                    engine.HARD_MAX_FINDINGS,
                    default=engine.HARD_MAX_FINDINGS,
                ),
            )
        except engine.SchematronTransformTimeout as exc:
            return _engine_failure_result(
                inputs,
                engine_status=ENGINE_STATUS_TIMEOUT,
                engine_message=str(exc),
                execution_seconds=time.monotonic() - started,
            )
        except engine.SchematronEngineError as exc:
            return _engine_failure_result(
                inputs,
                engine_status=ENGINE_STATUS_ERROR,
                engine_message=str(exc),
                engine_error_code=exc.error_code,
                execution_seconds=time.monotonic() - started,
            )
        except (SvrlParseError, ValueError) as exc:
            # Unreadable SVRL or a bad storage URI is equally "the rules
            # were not run" — an engine error, never a rule failure.
            return _engine_failure_result(
                inputs,
                engine_status=ENGINE_STATUS_ERROR,
                engine_message=str(exc),
                execution_seconds=time.monotonic() - started,
            )

    execution_seconds = time.monotonic() - started

    outputs = SchematronOutputs(
        engine_status=ENGINE_STATUS_OK,
        passed=summary.passed,
        error_count=summary.error_count,
        warning_count=summary.warning_count,
        info_count=summary.info_count,
        fired_rule_count=summary.fired_rule_count,
        finding_rule_ids_by_severity=summary.finding_rule_ids_by_severity,
        findings=[
            SchematronFinding(
                rule_id=f.rule_id,
                message=f.message,
                severity=f.severity,
                location_xpath=f.location,
                flag=f.flag,
                role=f.role,
            )
            for f in summary.findings
        ],
        findings_truncated=summary.findings_truncated,
        findings_suppressed_count=summary.findings_suppressed_count,
        schematron_sha256=inputs.schematron_sha256,
        query_binding=query_binding,
        engine=engine.engine_version(),
        execution_seconds=execution_seconds,
    )

    status = ValidationStatus.SUCCESS if summary.passed else ValidationStatus.FAILED_VALIDATION
    return SchematronRunResult(
        status=status,
        messages=_messages_from_outputs(outputs),
        outputs=outputs,
        svrl_text=svrl_text,
    )


def _engine_failure_result(
    inputs,
    *,
    engine_status: str,
    engine_message: str,
    engine_error_code: str = "",
    execution_seconds: float,
) -> SchematronRunResult:
    """Assemble the D9 failure shape: rules NOT run, ``passed`` unknown.

    Counts stay at zero-but-meaningless (Django nulls them from
    ``engine_status``), the findings list stays empty, and the single
    user-facing message carries the engine detail.
    """
    logger.error("Schematron engine failure (%s): %s", engine_status, engine_message)
    outputs = SchematronOutputs(
        engine_status=engine_status,
        engine_message=engine_message,
        engine_error_code=engine_error_code,
        passed=None,
        schematron_sha256=inputs.schematron_sha256,
        engine=engine.engine_version(),
        execution_seconds=execution_seconds,
    )
    return SchematronRunResult(
        status=ValidationStatus.FAILED_RUNTIME,
        messages=[
            ValidationMessage(severity=Severity.ERROR, text=engine_message),
        ],
        outputs=outputs,
    )


def _messages_from_outputs(outputs: SchematronOutputs) -> list[ValidationMessage]:
    """Project findings into the generic envelope ``messages`` list.

    Django rebuilds its rich findings (rule ids, deep links, meta) from
    ``outputs.findings``; the messages list is the generic fallback other
    envelope consumers read.
    """
    messages: list[ValidationMessage] = []
    for finding in outputs.findings:
        messages.append(
            ValidationMessage(
                severity=_SEVERITY_TO_ENUM.get(finding.severity, Severity.INFO),
                code=finding.rule_id or None,
                text=finding.message,
                location=(
                    MessageLocation(path=finding.location_xpath)
                    if finding.location_xpath
                    else None
                ),
            ),
        )
    return messages
