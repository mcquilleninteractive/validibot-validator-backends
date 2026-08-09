"""Download, verify, and inspect one PDF package in an isolated workspace."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from validator_backends.core.storage_client import download_verified_file
from validator_backends.pdf.engine import PdfEngineResult, inspect_pdf


if TYPE_CHECKING:
    from validibot_shared.pdf import PdfInputEnvelope
    from validibot_shared.validations.envelopes import InputFileItem


# The Validibot-facing file-port name declared by the PDF validator config, and
# the backend-facing role Django writes alongside it. ``port_key`` is optional
# on the shared envelope, so an envelope may legitimately identify this item by
# role alone -- see ``_pdf_document_item``.
PDF_DOCUMENT_PORT_KEY = "pdf_document"
PDF_DOCUMENT_ROLE = "pdf-document"


def _pdf_document_item(input_envelope: PdfInputEnvelope) -> InputFileItem:
    """Return the one declared PDF document, matching on port key or role.

    ``InputFileItem.port_key`` is optional in ``validibot-shared`` (it defaults
    to ``None``), so an envelope carrying no port key is schema-valid. Matching
    on ``port_key`` alone would therefore reject input the shared contract
    permits. Accept either identifier -- the same fallback the Portfolio
    Manager runner uses -- while still refusing an envelope that does not carry
    exactly one PDF document, which is what the ``1..1`` port cardinality in
    ADR-2026-08-07 promises the engine.
    """
    matches = [
        item
        for item in input_envelope.input_files
        if item.port_key == PDF_DOCUMENT_PORT_KEY or item.role == PDF_DOCUMENT_ROLE
    ]
    if len(matches) != 1:
        msg = (
            "PDF validation requires exactly one input file on the "
            f"{PDF_DOCUMENT_PORT_KEY} port; found {len(matches)}."
        )
        raise ValueError(msg)
    return matches[0]


def run_pdf_validation(input_envelope: PdfInputEnvelope) -> PdfEngineResult:
    """Run the bounded PDF engine against the envelope's declared input port."""
    input_file = _pdf_document_item(input_envelope)

    with tempfile.TemporaryDirectory(prefix="validibot-pdf-") as tmp:
        pdf_path = Path(tmp) / "document.pdf"
        download_verified_file(input_file, pdf_path)
        return inspect_pdf(
            pdf_path,
            source_name=input_file.name,
            inputs=input_envelope.inputs,
        )
