"""Prove the SHACL runner resolves its named RDF input without list guessing.

The RDF parser operates on untrusted bytes, so selecting the wrong envelope
item would make the result and its evidence describe a different graph. These
focused tests keep name dispatch separate from the heavier pySHACL suite.
"""

from types import SimpleNamespace

import pytest

from validator_backends.shacl.runner import _data_graph_item
from validibot_shared.validations.envelopes import InputFileItem, SupportedMimeType
from validibot_shared.validations.file_ports import FilePortLookupError


def _item(*, name: str, port_key: str, role: str | None) -> InputFileItem:
    """Build one integrity-complete RDF item for dispatch tests."""
    return InputFileItem(
        name=name,
        mime_type=SupportedMimeType.RDF_TURTLE,
        port_key=port_key,
        role=role,
        uri=f"gs://test/{name}",
        size_bytes=1,
        sha256="a" * 64,
        storage_version="1",
    )


def test_data_graph_is_selected_by_port_key_instead_of_position() -> None:
    """An unrelated first item must never be parsed as the SHACL data graph."""
    side_file = _item(
        name="side.ttl",
        port_key="shapes_graph",
        role="data-graph",
    )
    data_graph = _item(name="data.ttl", port_key="data_graph", role=None)
    envelope = SimpleNamespace(input_files=[side_file, data_graph])

    assert _data_graph_item(envelope) is data_graph


def test_data_graph_role_cannot_override_a_conflicting_port_key() -> None:
    """Descriptive RDF metadata must never replace the declared identity."""
    envelope = SimpleNamespace(
        input_files=[
            _item(
                name="wrong.ttl",
                port_key="shapes_graph",
                role="data-graph",
            )
        ]
    )

    with pytest.raises(FilePortLookupError, match="was not found"):
        _data_graph_item(envelope)


def test_duplicate_data_graph_ports_are_rejected_as_ambiguous() -> None:
    """Two exact RDF candidates must fail rather than choose by list order."""
    envelope = SimpleNamespace(
        input_files=[
            _item(name="first.ttl", port_key="data_graph", role=None),
            _item(name="second.ttl", port_key="data_graph", role=None),
        ]
    )

    with pytest.raises(FilePortLookupError, match="ambiguous; found 2"):
        _data_graph_item(envelope)
