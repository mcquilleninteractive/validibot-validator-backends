"""Prove Portfolio Manager dispatches its report through the shared matcher.

The runner accepts both single reports and ZIP collections, but their file
selection contract is identical: exactly one named report, independent of
envelope order. Parser and collection behavior remain covered elsewhere.
"""

from types import SimpleNamespace

from validator_backends.portfolio_manager.runner import _primary_report_item
from validibot_shared.validations.envelopes import InputFileItem, SupportedMimeType


def _item(*, name: str, port_key: str | None, role: str | None) -> InputFileItem:
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


def test_keyless_report_uses_its_backend_role() -> None:
    """Role-only envelopes remain valid because the shared key is optional."""
    report = _item(
        name="report.xlsx",
        port_key=None,
        role="portfolio-manager-report",
    )

    assert _primary_report_item(SimpleNamespace(input_files=[report])) is report
