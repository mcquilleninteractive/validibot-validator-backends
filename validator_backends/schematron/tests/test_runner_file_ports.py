"""Prove the Schematron runner resolves its declared XML document by name.

Schematron rules must run against the exact bound document, even when future
envelopes carry additional files. These tests protect the shared file-port
dispatch independently of Saxon and the rules hardening suite.
"""

from types import SimpleNamespace

from validator_backends.schematron.runner import _xml_document_item
from validibot_shared.validations.envelopes import InputFileItem, SupportedMimeType


def _item(*, name: str, port_key: str, role: str | None) -> InputFileItem:
    """Build one integrity-complete XML item for dispatch tests."""
    return InputFileItem(
        name=name,
        mime_type=SupportedMimeType.APPLICATION_XML,
        port_key=port_key,
        role=role,
        uri=f"gs://test/{name}",
        size_bytes=1,
        sha256="b" * 64,
        storage_version="1",
    )


def test_xml_document_is_selected_by_port_key_instead_of_position() -> None:
    """A side file cannot become the document merely by appearing first."""
    side_file = _item(
        name="side.xml",
        port_key="schema_file",
        role="xml-document",
    )
    document = _item(name="document.xml", port_key="xml_document", role=None)
    envelope = SimpleNamespace(input_files=[side_file, document])

    assert _xml_document_item(envelope) is document
