"""Prove the Schematron runner resolves its declared XML document by name.

Schematron rules must run against the exact bound document, even when future
envelopes carry additional files. These tests protect the shared file-port
dispatch independently of Saxon and the rules hardening suite.
"""

from types import SimpleNamespace

import pytest

from validator_backends.schematron.runner import _xml_document_item
from validibot_shared.validations.envelopes import InputFileItem, SupportedMimeType
from validibot_shared.validations.file_ports import FilePortLookupError


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


def test_xml_document_role_cannot_override_a_conflicting_port_key() -> None:
    """A document-like role must not select a differently named file port."""
    envelope = SimpleNamespace(
        input_files=[
            _item(
                name="schema.xml",
                port_key="schema_file",
                role="xml-document",
            )
        ]
    )

    with pytest.raises(FilePortLookupError, match="was not found"):
        _xml_document_item(envelope)


def test_duplicate_xml_document_ports_are_rejected_as_ambiguous() -> None:
    """Two exact documents must fail rather than make evidence order-dependent."""
    envelope = SimpleNamespace(
        input_files=[
            _item(name="first.xml", port_key="xml_document", role=None),
            _item(name="second.xml", port_key="xml_document", role=None),
        ]
    )

    with pytest.raises(FilePortLookupError, match="ambiguous; found 2"):
        _xml_document_item(envelope)
