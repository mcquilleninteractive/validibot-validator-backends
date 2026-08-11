"""SHACL validation runner for the isolated container backend.

Replicates the orchestration that used to live in
``SHACLValidator.validate`` (community repo) — but emits the typed envelope
structures (``SHACLOutputs`` / ``ValidationMessage``) instead of Django
``ValidationResult`` objects, and reads every setting from the input envelope
rather than from Django settings.

Flow (each step delegates to :mod:`engine`):

1. Download the RDF submission referenced in ``input_files``.
2. Load any opted-in bundled standards (Phase 1 emits warnings).
3. Parse the submission as RDF using the resolved ``rdf_format``.
4. Run pyshacl with the resolved inference mode + advanced/gate flags.
5. Map ``sh:ValidationResult`` nodes to findings; extract ``o.*`` output_values.
6. Apply SHACL result handling (fail_immediately / fail_after_assertions /
   report_only).
7. Evaluate author-defined SPARQL-ASK assertions (when result handling allows).
8. Assemble ``SHACLOutputs`` (output values + findings + report + assertion tallies)
   and the final status.

The CEL/Basic output assertions are intentionally NOT run here — they operate on
the extracted output_values (no graph access) and stay in Django, evaluated by
``AdvancedValidator.post_execute_validate``.
"""

from __future__ import annotations

import hashlib
import logging
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from validator_backends.core.storage_client import download_verified_file
from validator_backends.shacl import engine
from validibot_shared.shacl.envelopes import (
    SHACL_RESULT_FAIL_IMMEDIATELY,
    SHACL_RESULT_REPORT_ONLY,
    SHACLFinding,
    SHACLOutputs,
)
from validibot_shared.validations.envelopes import (
    MessageLocation,
    Severity,
    ValidationMessage,
    ValidationStatus,
)
from validibot_shared.validations.file_ports import select_input_file


if TYPE_CHECKING:
    from validibot_shared.shacl.envelopes import SHACLInputEnvelope

logger = logging.getLogger(__name__)

DATA_GRAPH_PORT_KEY = "data_graph"

# Map the container's finding-severity strings to the shared Severity enum for
# the generic ``messages`` list. SUCCESS has no Severity member, so success
# findings are carried only in SHACLOutputs.findings, not in messages.
_SEVERITY_TO_ENUM = {
    engine.SEV_ERROR: Severity.ERROR,
    engine.SEV_WARNING: Severity.WARNING,
    engine.SEV_INFO: Severity.INFO,
}

# pyshacl version, resolved once for the output metadata.
try:  # pragma: no cover - trivial import guard
    from importlib.metadata import version as _pkg_version

    _PYSHACL_VERSION: str | None = _pkg_version("pyshacl")
except Exception:  # pragma: no cover
    _PYSHACL_VERSION = None


class SHACLRunResult(NamedTuple):
    """What the runner hands back to ``main`` for envelope assembly."""

    outputs: SHACLOutputs
    messages: list[ValidationMessage]
    status: ValidationStatus


def run_shacl_validation(input_envelope: SHACLInputEnvelope) -> SHACLRunResult:
    """Execute the SHACL validation described by ``input_envelope``."""
    started = time.monotonic()
    inputs = input_envelope.inputs

    content = _download_submission(input_envelope)

    # 1. Bundled standards (Phase 1 stub → warnings only).
    bundle_shapes, bundle_ontology, bundle_warnings = engine.load_bundled_standards(
        list(inputs.bundled_standards),
    )
    merged_shapes = inputs.shapes_text
    merged_ontology = inputs.ontology_text
    if bundle_shapes:
        merged_shapes = merged_shapes + engine.FILE_SEPARATOR + bundle_shapes
    if bundle_ontology:
        merged_ontology = merged_ontology + engine.FILE_SEPARATOR + bundle_ontology

    shapes_sha = hashlib.sha256(merged_shapes.encode("utf-8")).hexdigest()
    ontology_sha = (
        hashlib.sha256(merged_ontology.encode("utf-8")).hexdigest() if merged_ontology else ""
    )

    # 2. Parse the submission.
    data_graph, parse_error = engine.parse_rdf(content, inputs.rdf_format)
    if data_graph is None:
        return _failure_result(
            findings=[
                *bundle_warnings,
                SHACLFinding(
                    message=parse_error or "Failed to parse submission.",
                    severity=engine.SEV_ERROR,
                    code="shacl.parse_failed",
                ),
            ],
            output_values=engine.extract_output_values(
                data_graph=None,
                results_graph=None,
                parse_ok=False,
                parse_serialization=inputs.rdf_format,
            ),
            inputs=inputs,
            shapes_sha=shapes_sha,
            ontology_sha=ontology_sha,
            started=started,
        )

    # 3. Run SHACL.
    results_graph, shacl_error = engine.run_shacl_validation(
        data_graph,
        merged_shapes,
        merged_ontology,
        inference_mode=inputs.inference_mode,
        advanced_shacl=inputs.advanced_shacl,
        enable_advanced_features=inputs.enable_advanced_features,
        max_data_triples=inputs.max_data_triples,
        max_shape_triples=inputs.max_shape_triples,
        max_ontology_triples=inputs.max_ontology_triples,
        max_validation_depth=inputs.max_validation_depth,
        timeout_seconds=inputs.pyshacl_timeout_seconds,
    )
    if results_graph is None:
        return _failure_result(
            findings=[
                *bundle_warnings,
                SHACLFinding(
                    message=shacl_error or "SHACL engine error.",
                    severity=engine.SEV_ERROR,
                    code="shacl.engine_error",
                ),
            ],
            output_values=engine.extract_output_values(
                data_graph=data_graph,
                results_graph=None,
                parse_ok=True,
                parse_serialization=inputs.rdf_format,
            ),
            inputs=inputs,
            shapes_sha=shapes_sha,
            ontology_sha=ontology_sha,
            started=started,
        )

    # 4. Map findings + output values + report.
    shacl_findings = engine.map_results_to_issues(results_graph)
    output_values = engine.extract_output_values(
        data_graph=data_graph,
        results_graph=results_graph,
        parse_ok=True,
        parse_serialization=inputs.rdf_format,
    )
    report_turtle = _serialize_report(results_graph)

    result_handling = inputs.shacl_result_handling

    # 5. fail_immediately short-circuit: blocking SHACL error → skip SPARQL asks.
    if result_handling == SHACL_RESULT_FAIL_IMMEDIATELY and any(
        f.severity == engine.SEV_ERROR for f in shacl_findings
    ):
        return _build_result(
            findings=[*bundle_warnings, *shacl_findings],
            output_values=output_values,
            assertion_total=0,
            assertion_failures=0,
            report_turtle=report_turtle,
            inputs=inputs,
            shapes_sha=shapes_sha,
            ontology_sha=ontology_sha,
            started=started,
        )

    # 6. SPARQL-ASK assertions (run against the graph here, in isolation).
    sparql_findings = engine.evaluate_sparql_assertions(
        assertions=list(inputs.sparql_ask_assertions),
        data_graph=data_graph,
        results_graph=results_graph,
        timeout_seconds=inputs.sparql_query_timeout_seconds,
    )
    assertion_total = len(inputs.sparql_ask_assertions)
    assertion_failures = sum(
        1 for f in sparql_findings if f.assertion_id is not None and f.severity == engine.SEV_ERROR
    )

    # 7. report_only drops SHACL findings from the surfaced set (counts/report
    # are still exposed via output values + results_graph_turtle).
    blocking_shacl = [] if result_handling == SHACL_RESULT_REPORT_ONLY else shacl_findings

    findings = [*bundle_warnings, *blocking_shacl, *sparql_findings]

    return _build_result(
        findings=findings,
        output_values=output_values,
        assertion_total=assertion_total,
        assertion_failures=assertion_failures,
        report_turtle=report_turtle,
        inputs=inputs,
        shapes_sha=shapes_sha,
        ontology_sha=ontology_sha,
        started=started,
    )


# =============================================================================
# Helpers
# =============================================================================


def _data_graph_item(input_envelope: SHACLInputEnvelope):
    """Return the SHACL data graph through the shared matcher."""
    return select_input_file(
        input_envelope.input_files,
        port_key=DATA_GRAPH_PORT_KEY,
    )


def _download_submission(input_envelope: SHACLInputEnvelope) -> str:
    """Download the RDF submission file and return its text content."""
    file_item = _data_graph_item(input_envelope)
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "submission.rdf"
        download_verified_file(file_item, dest)
        return dest.read_text(encoding="utf-8")


def _serialize_report(results_graph) -> str:
    """Serialise the SHACL ValidationReport as Turtle for evidence download."""
    try:
        return results_graph.serialize(format="turtle")
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to serialise SHACL report as Turtle: %s", exc)
        return ""


def _messages_from_findings(findings: list[SHACLFinding]) -> list[ValidationMessage]:
    """Map findings to generic ValidationMessages (skipping SUCCESS rows)."""
    messages: list[ValidationMessage] = []
    for f in findings:
        sev = _SEVERITY_TO_ENUM.get(f.severity)
        if sev is None:
            # SUCCESS (or any unknown) — carried only in outputs.findings.
            continue
        messages.append(
            ValidationMessage(
                severity=sev,
                code=f.code or None,
                text=f.message,
                location=MessageLocation(path=f.path) if f.path else None,
            ),
        )
    return messages


def _status_for(findings: list[SHACLFinding]) -> ValidationStatus:
    """SUCCESS unless any surfaced finding is a blocking ERROR."""
    if any(f.severity == engine.SEV_ERROR for f in findings):
        return ValidationStatus.FAILED_VALIDATION
    return ValidationStatus.SUCCESS


def _build_result(
    *,
    findings: list[SHACLFinding],
    output_values: dict,
    assertion_total: int,
    assertion_failures: int,
    report_turtle: str,
    inputs,
    shapes_sha: str,
    ontology_sha: str,
    started: float,
) -> SHACLRunResult:
    """Assemble the SHACLOutputs + messages + status from engine results."""
    outputs = SHACLOutputs(
        conforms=output_values.get("shacl_violation_count", 0) == 0,
        findings=findings,
        parse_ok=output_values["parse_ok"],
        parse_serialization=output_values["parse_serialization"],
        triple_count=output_values["triple_count"],
        namespaces_present=output_values["namespaces_present"],
        has_s223_namespace=output_values["has_s223_namespace"],
        has_g36_namespace=output_values["has_g36_namespace"],
        has_brick_namespace=output_values["has_brick_namespace"],
        shacl_violation_count=output_values["shacl_violation_count"],
        shacl_warning_count=output_values["shacl_warning_count"],
        shacl_info_count=output_values["shacl_info_count"],
        shacl_total_count=output_values["shacl_total_count"],
        results_graph_turtle=report_turtle,
        shacl_shapes_sha256=shapes_sha,
        shacl_ontology_sha256=ontology_sha,
        advanced_shacl_requested=bool(inputs.advanced_shacl),
        shacl_result_handling=inputs.shacl_result_handling,
        assertion_total=assertion_total,
        assertion_failures=assertion_failures,
        execution_seconds=max(0.0, time.monotonic() - started),
        pyshacl_version=_PYSHACL_VERSION,
    )
    return SHACLRunResult(
        outputs=outputs,
        messages=_messages_from_findings(findings),
        status=_status_for(findings),
    )


def _failure_result(
    *,
    findings: list[SHACLFinding],
    output_values: dict,
    inputs,
    shapes_sha: str,
    ontology_sha: str,
    started: float,
) -> SHACLRunResult:
    """Build a parse/engine-failure result (FAILED_VALIDATION, no assertions)."""
    return _build_result(
        findings=findings,
        output_values=output_values,
        assertion_total=0,
        assertion_failures=0,
        report_turtle="",
        inputs=inputs,
        shapes_sha=shapes_sha,
        ontology_sha=ontology_sha,
        started=started,
    )
