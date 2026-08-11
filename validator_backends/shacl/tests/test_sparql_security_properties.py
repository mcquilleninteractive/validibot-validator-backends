"""Bounded properties for the container-side SHACL SPARQL security policy.

Author-supplied query text is untrusted even if Django scrubbed it before
dispatch. The legitimate outcomes are acceptance of a local read-only ASK or a
documented ``SparqlScrubError`` rejection. Across ASCII case and legal
whitespace variations, the runtime must continue to reject federation,
external dataset clauses, non-ASK forms, and update syntax. The separate
embedded-SHACL property protects the lightweight pre-pySHACL scan as well as
the ASK algebra scrubber.

Queries generated here stay below 256 characters and contain no graph data;
the tests therefore exercise policy recognition rather than query execution.
Subprocess timeouts and graph-size limits are covered by the fixed engine
regression suite.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from rdflib import BNode, Graph, Literal
from rdflib.namespace import SH

from validator_backends.shacl import engine
from validator_backends.shacl.sparql_security import (
    SparqlScrubError,
    scrub_sparql_ask,
)


SPARQL_WHITESPACE = st.sampled_from([" ", "\t", "\n", "\r\n", " \n\t"])


def _keyword_case(keyword: str) -> st.SearchStrategy[str]:
    """Generate every ASCII case combination for one SPARQL keyword."""
    return st.tuples(
        *(st.sampled_from([character.lower(), character.upper()]) for character in keyword)
    ).map("".join)


ASK_KEYWORDS = _keyword_case("ASK")
SERVICE_KEYWORDS = _keyword_case("SERVICE")
FROM_KEYWORDS = _keyword_case("FROM")
WHERE_KEYWORDS = _keyword_case("WHERE")


# ASK algebra properties protect the final execution-time scrub.


@given(ASK_KEYWORDS, SPARQL_WHITESPACE)
def test_local_read_only_ask_is_case_and_whitespace_tolerant(
    ask_keyword: str,
    whitespace: str,
) -> None:
    """Policy normalization must not reject harmless ASK spelling variations."""
    query = f"{ask_keyword}{whitespace}{{ ?subject ?predicate ?object }}"

    assert scrub_sparql_ask(query) is None


@given(ASK_KEYWORDS, SERVICE_KEYWORDS, SPARQL_WHITESPACE)
def test_service_federation_is_rejected_for_every_spelling(
    ask_keyword: str,
    service_keyword: str,
    whitespace: str,
) -> None:
    """Case or legal spacing must never bypass the federation/exfiltration ban."""
    query = (
        f"{ask_keyword} {{ {service_keyword}{whitespace}"
        "<https://invalid.example/sparql> { ?s ?p ?o } }"
    )

    with pytest.raises(SparqlScrubError, match="SERVICE"):
        scrub_sparql_ask(query)


@given(ASK_KEYWORDS, FROM_KEYWORDS, WHERE_KEYWORDS, SPARQL_WHITESPACE)
def test_external_dataset_clauses_are_rejected_for_every_spelling(
    ask_keyword: str,
    from_keyword: str,
    where_keyword: str,
    whitespace: str,
) -> None:
    """A query cannot select a remote graph by varying keyword presentation."""
    query = (
        f"{ask_keyword}{whitespace}{from_keyword}{whitespace}"
        f"<https://invalid.example/graph>{whitespace}{where_keyword} {{ ?s ?p ?o }}"
    )

    with pytest.raises(SparqlScrubError, match="FROM"):
        scrub_sparql_ask(query)


@given(
    st.sampled_from(
        [
            "SELECT * WHERE { ?s ?p ?o }",
            "CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p ?o }",
            "DESCRIBE ?s WHERE { ?s ?p ?o }",
            "INSERT DATA { <urn:s> <urn:p> <urn:o> }",
            "DELETE WHERE { ?s ?p ?o }",
            "LOAD <https://invalid.example/graph>",
        ],
    ),
)
def test_non_ask_and_update_forms_are_cleanly_rejected(query: str) -> None:
    """Unsupported and state-changing forms must reject without another error."""
    with pytest.raises(SparqlScrubError):
        scrub_sparql_ask(query)


# Embedded SHACL SPARQL uses a separate pre-execution text inspection path.


@given(SERVICE_KEYWORDS, SPARQL_WHITESPACE)
def test_embedded_service_is_rejected_before_advanced_feature_gates(
    service_keyword: str,
    whitespace: str,
) -> None:
    """Embedded federation must fail even when every advanced gate is enabled."""
    shapes = Graph()
    constraint = BNode()
    query = (
        f"SELECT $this WHERE {{ {service_keyword}{whitespace}"
        "<https://invalid.example/sparql> { $this ?p ?o } }"
    )
    shapes.add((constraint, SH.select, Literal(query)))

    error = engine.inspect_shapes_policy(
        shapes,
        advanced_shacl_requested=True,
        enable_advanced_features=True,
    )

    assert error is not None
    assert "forbidden construct" in error
