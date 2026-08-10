"""Download, verify, and inspect one PDF package in an isolated workspace."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from validator_backends.core.storage_client import download_verified_file
from validator_backends.pdf.engine import PdfEngineResult, inspect_pdf
from validibot_shared.validations.file_ports import select_input_file


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
    """Return the one declared PDF document through the shared matcher."""
    return select_input_file(
        input_envelope.input_files,
        port_key=PDF_DOCUMENT_PORT_KEY,
        legacy_role=PDF_DOCUMENT_ROLE,
    )


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
