"""Download, verify, and inspect one PDF package in an isolated workspace."""

from __future__ import annotations

from typing import TYPE_CHECKING

from validator_backends.core.storage_client import download_verified_file
from validator_backends.pdf.engine import PdfEngineResult, inspect_pdf
from validibot_shared.validations.file_ports import select_input_file


if TYPE_CHECKING:
    from pathlib import Path

    from validibot_shared.pdf import PdfInputEnvelope
    from validibot_shared.validations.envelopes import InputFileItem


# The declared Validibot file-port key is the sole input identity.
PDF_DOCUMENT_PORT_KEY = "pdf_document"


def _pdf_document_item(input_envelope: PdfInputEnvelope) -> InputFileItem:
    """Return the one declared PDF document through the shared matcher."""
    return select_input_file(
        input_envelope.input_files,
        port_key=PDF_DOCUMENT_PORT_KEY,
    )


def run_pdf_validation(
    input_envelope: PdfInputEnvelope,
    *,
    workspace: Path,
) -> PdfEngineResult:
    """Run the bounded PDF engine against the envelope's declared input port."""
    input_file = _pdf_document_item(input_envelope)
    input_dir = workspace / "input"
    input_dir.mkdir(parents=True)
    pdf_path = input_dir / "document.pdf"
    download_verified_file(input_file, pdf_path)
    return inspect_pdf(
        pdf_path,
        source_name=input_file.name,
        inputs=input_envelope.inputs,
        workspace=workspace / "inspection",
    )
