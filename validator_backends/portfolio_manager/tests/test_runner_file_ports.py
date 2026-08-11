"""Prove Portfolio Manager dispatches its report through the shared matcher.

The runner accepts both single reports and ZIP collections, but their file
selection contract is identical: exactly one named report, independent of
envelope order. Parser and collection behavior remain covered elsewhere.
"""

from types import SimpleNamespace

import pytest

from validator_backends.portfolio_manager.runner import _primary_report_item
from validibot_shared.validations.envelopes import InputFileItem, SupportedMimeType
from validibot_shared.validations.file_ports import FilePortLookupError


def _item(*, name: str, port_key: str, role: str | None) -> InputFileItem:
    """Build one integrity-complete report item for dispatch tests."""
    return InputFileItem(
        name=name,
        mime_type=SupportedMimeType.MICROSOFT_EXCEL_XLSX,
        port_key=port_key,
        role=role,
        uri=f"gs://test/{name}",
        size_bytes=1,
        sha256="c" * 64,
        storage_version="1",
    )


def test_report_is_selected_by_port_key_instead_of_position() -> None:
    """An unrelated first file must not be interpreted as a building report."""
    side_file = _item(
        name="side.bin",
        port_key="other_file",
        role="portfolio-manager-report",
    )
    report = _item(
        name="report.xlsx",
        port_key="portfolio_manager_report",
        role=None,
    )
    envelope = SimpleNamespace(input_files=[side_file, report])

    assert _primary_report_item(envelope) is report


def test_report_role_cannot_override_a_conflicting_port_key() -> None:
    """A report-like role cannot redirect validation to another input port."""
    envelope = SimpleNamespace(
        input_files=[
            _item(
                name="wrong.xlsx",
                port_key="other_file",
                role="portfolio-manager-report",
            )
        ]
    )

    with pytest.raises(FilePortLookupError, match="was not found"):
        _primary_report_item(envelope)


def test_duplicate_report_ports_are_rejected_as_ambiguous() -> None:
    """Two exact reports must fail instead of selecting an arbitrary workbook."""
    envelope = SimpleNamespace(
        input_files=[
            _item(
                name="first.xlsx",
                port_key="portfolio_manager_report",
                role=None,
            ),
            _item(
                name="second.xlsx",
                port_key="portfolio_manager_report",
                role=None,
            ),
        ]
    )

    with pytest.raises(FilePortLookupError, match="ambiguous; found 2"):
        _primary_report_item(envelope)
