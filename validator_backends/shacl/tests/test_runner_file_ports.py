"""Prove the SHACL runner resolves its named RDF input without list guessing.

The RDF parser operates on untrusted bytes, so selecting the wrong envelope
item would make the result and its evidence describe a different graph. These
focused tests keep name dispatch separate from the heavier pySHACL suite.
"""

from types import SimpleNamespace

from validator_backends.shacl.runner import _data_graph_item
from validibot_shared.validations.envelopes import InputFileItem, SupportedMimeType


def _item(*, name: str, port_key: str | None, role: str | None) -> InputFileItem:
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


def test_keyless_data_graph_uses_its_backend_role() -> None:
    """A schema-valid producer that omits the key can retain role compatibility."""
    data_graph = _item(name="data.ttl", port_key=None, role="data-graph")

    assert _data_graph_item(SimpleNamespace(input_files=[data_graph])) is data_graph
