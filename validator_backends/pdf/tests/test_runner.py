"""Port resolution tests for the PDF runner's single declared input.

ADR-2026-07-06 declares a `port_key` on every envelope file item so a backend
can find the file belonging to a named Validibot file port without guessing
from list position. That field is **optional** in `validibot-shared`
(`InputFileItem.port_key` defaults to `None`), which means an envelope that
omits it is still schema-valid and must not be rejected outright.

These tests pin the runner to that contract. They exercise
`_pdf_document_item` directly rather than `run_pdf_validation`, because the
question under test is purely "which envelope item is the PDF document?" —
answering it requires no PDF bytes, no temporary workspace, and no download.
The engine behaviour that follows is covered by `test_engine.py`.
"""

from __future__ import annotations

import pytest

from validator_backends.pdf.runner import _pdf_document_item
from validibot_shared.pdf import PdfInputEnvelope, PdfInputs
from validibot_shared.validations.envelopes import (
    ATTEMPT_CONTRACT_VERSION,
    ExecutionContext,
    InputFileItem,
    SupportedMimeType,
    ValidatorType,
)


def _pdf_item(**overrides) -> InputFileItem:
    """Build one otherwise-valid PDF input item with the given identity fields.

    Every field except `port_key` and `role` is held constant so a failing test
    isolates the port-resolution behaviour rather than envelope validation.
    """
    fields = {
        "name": "document.pdf",
        "mime_type": SupportedMimeType.APPLICATION_PDF,
        "role": "pdf-document",
        "port_key": "pdf_document",
        "uri": "gs://bucket/runs/run-1/document.pdf",
        "size_bytes": 1024,
        "sha256": "a" * 64,
        "storage_version": "1700000000000000",
    }
    fields.update(overrides)
    return InputFileItem(**fields)


def _envelope(*input_files: InputFileItem) -> PdfInputEnvelope:
    """Wrap the given items in a minimal, schema-valid PDF input envelope."""
    return PdfInputEnvelope(
        run_id="run-1",
        validator={
            "id": "validator-1",
            "type": ValidatorType.PDF,
            "version": "1",
        },
        org={"id": "org-1", "name": "Test Org"},
        workflow={
            "id": "workflow-1",
            "step_id": "step-1",
            "step_name": "Inspect PDF",
        },
        input_files=list(input_files),
        inputs=PdfInputs(),
        context=ExecutionContext(
            execution_attempt_id="attempt-1",
            step_run_id="step-run-1",
            attempt_contract_version=ATTEMPT_CONTRACT_VERSION,
            expected_output_uri="gs://bucket/runs/run-1/output.json",
            execution_bundle_uri="gs://bucket/runs/run-1/",
            skip_callback=True,
        ),
    )


# ── Identification by either declared identifier ──────────────────────────
# The envelope carries two independent names for the same file: `port_key` is
# the Validibot-facing file-port name that bindings and the step editor use,
# and `role` is the backend-facing meaning. Django writes both, but only
# `role` is guaranteed present by the shared schema, so the runner has to
# accept a match on either one.


def test_resolves_the_document_when_django_sets_both_identifiers():
    """The normal production envelope carries port key and role together.

    This is what `envelope_builder._build_pdf_input_file_item` emits today; if
    this test ever fails, the live dispatch path is broken.
    """
    envelope = _envelope(_pdf_item())

    assert _pdf_document_item(envelope).name == "document.pdf"


def test_resolves_the_document_from_role_when_port_key_is_absent():
    """A schema-valid envelope may omit `port_key` entirely.

    `InputFileItem.port_key` is optional, and several shared envelope builders
    (SHACL, Schematron, FMU) construct items without it. Matching on
    `port_key` alone would reject input the shared contract permits, so `role`
    has to serve as the fallback identifier.
    """
    envelope = _envelope(_pdf_item(port_key=None))

    assert _pdf_document_item(envelope).name == "document.pdf"


def test_resolves_the_document_from_port_key_when_role_is_absent():
    """`role` is itself optional, so `port_key` must work on its own too.

    This is the mirror of the previous test and the case the runner already
    handled before the fallback was added. Neither identifier is mandatory
    on its own; the runner needs exactly one of them to match.
    """
    envelope = _envelope(_pdf_item(role=None))

    assert _pdf_document_item(envelope).name == "document.pdf"


# ── Cardinality enforcement ───────────────────────────────────────────────
# The `pdf_document` port is declared `1..1` (ADR-2026-08-07). Django validates
# cardinality before launch, but the backend treats its envelope as untrusted
# input and re-checks, so an ambiguous or empty envelope fails loudly instead
# of silently inspecting an arbitrary file.


def test_rejects_an_envelope_with_no_matching_input():
    """An item that matches neither identifier is not the PDF document.

    Falling back to `input_files[0]` here would let an unrelated file be
    inspected and reported as the submitted PDF — exactly the positional
    guessing the file-port design guide forbids.
    """
    envelope = _envelope(_pdf_item(port_key="some_other_port", role="primary-model"))

    with pytest.raises(ValueError, match="exactly one input file"):
        _pdf_document_item(envelope)


def test_rejects_an_envelope_with_two_matching_inputs():
    """Two candidate documents make the choice ambiguous, so refuse to guess.

    Picking either one would produce evidence attributing the inspection to a
    file the workflow author did not necessarily intend.
    """
    envelope = _envelope(
        _pdf_item(name="first.pdf"),
        _pdf_item(name="second.pdf"),
    )

    with pytest.raises(ValueError, match="exactly one input file"):
        _pdf_document_item(envelope)


def test_rejects_an_empty_envelope():
    """A required `1..1` port with nothing bound is a contract violation."""
    envelope = _envelope()

    with pytest.raises(ValueError, match="exactly one input file"):
        _pdf_document_item(envelope)
