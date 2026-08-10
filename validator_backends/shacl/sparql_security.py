"""SPARQL ASK assertion security: parse-time AST scrubbing.

This is the **container copy** of the SHACL SPARQL scrubber. It is kept byte-for-byte
equivalent to ``validibot/validations/validators/shacl/sparql_security.py`` in the
community repo, with one difference: there is no Django here, so
:func:`resolve_limits` reads the module-level defaults instead of settings.

⚠️  Two copies of this module exist on purpose:

- The Django copy runs at **form save time** (``form_fields.clean``) so an author
  cannot persist a dangerous query in the first place.
- This container copy runs at **execution time** as belt-and-suspenders against
  queries that reach the engine without passing through the form (fixtures,
  admin imports, direct API writes).

If you tighten the rules here, mirror the change in the Django copy (and vice
versa). The scrub is the robust control behind the isolation boundary.

What we forbid :

- Top-level form ≠ ``ASK`` (SELECT/CONSTRUCT/DESCRIBE rejected; Update ops are
  refused by the parser itself, and we also list their algebra node names).
- ``ServiceGraphPattern`` (the ``SERVICE`` clause) — the federation/exfiltration
  vector.
- ``FROM`` / ``FROM NAMED`` with non-default IRIs — remote-graph loads.
- Property paths nested beyond a depth cap (cubic-blowup DoS).
- Queries over a total length cap.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rdflib.paths import (
    AlternativePath,
    InvPath,
    MulPath,
    NegatedPath,
    Path,
    SequencePath,
)
from rdflib.plugins.sparql.algebra import translateQuery
from rdflib.plugins.sparql.parser import parseQuery
from rdflib.plugins.sparql.parserutils import CompValue


DEFAULT_MAX_QUERY_LENGTH = 10_000
DEFAULT_MAX_PROPERTY_PATH_DEPTH = 8
HARD_MAX_QUERY_LENGTH = 50_000
HARD_MAX_PROPERTY_PATH_DEPTH = 32

# Algebra-tree node names that must not appear anywhere in the query.
_FORBIDDEN_ALGEBRA_NODES: frozenset[str] = frozenset(
    {
        "ServiceGraphPattern",  # SERVICE clause — federation / exfiltration
        # Update grammar nodes (defense in depth):
        "Load",
        "Clear",
        "Drop",
        "Create",
        "Add",
        "Move",
        "Copy",
        "InsertData",
        "DeleteData",
        "Modify",  # INSERT / DELETE / WHERE update form
    },
)

# Property-path operator classes from rdflib.
_PATH_OPERATOR_TYPES: tuple[type, ...] = (
    AlternativePath,
    SequencePath,
    InvPath,
    MulPath,
    NegatedPath,
)


class SparqlScrubError(ValueError):
    """Raised when a SPARQL ASK query violates one of the scrub rules.

    The message is user-facing — it appears in finding text without further
    sanitisation. Keep it descriptive enough that the author can fix the query.
    """


@dataclass(frozen=True)
class ScrubLimits:
    """Resolved limits for a single scrub invocation.

    Passed explicitly rather than read from module globals so tests can exercise
    boundary behaviour without mutating process state, and so a future caller
    could tighten limits per invocation.

    These are the container's own conservative caps. Django enforces its copy
    from settings (``SHACL_SPARQL_QUERY_LENGTH_MAX`` and
    ``SHACL_SPARQL_PROPERTY_PATH_DEPTH_MAX``) when the query is saved; there is
    no settings layer here, so :func:`resolve_limits` returns fixed module
    defaults. This is second-line defence, not the primary gate — the values are
    intentionally allowed to be stricter than Django's.

    Fields:
        max_query_length: Ceiling on raw query characters, applied before
            parsing. Cheap rejection of a query large enough to make parsing
            itself the attack.
        max_property_path_depth: Ceiling on nesting of property path operators
            (``/``, ``|``, ``*``, ``+``, ``^``, ``!``). Deeply nested paths are
            the compact way to express an expensive traversal — a short query can
            still cost enormous evaluation time — so depth is bounded
            independently of length.
    """

    max_query_length: int
    max_property_path_depth: int


def resolve_limits() -> ScrubLimits:
    """Return the scrub limits.

    In the container there is no settings layer, so we use the module defaults.
    Django's copy reads ``SHACL_SPARQL_QUERY_LENGTH_MAX`` /
    ``SHACL_SPARQL_PROPERTY_PATH_DEPTH_MAX`` from settings; the engine here is a
    second line of defence with conservative fixed caps.
    """
    return ScrubLimits(
        max_query_length=DEFAULT_MAX_QUERY_LENGTH,
        max_property_path_depth=DEFAULT_MAX_PROPERTY_PATH_DEPTH,
    )


def scrub_sparql_ask(
    query_text: str,
    *,
    limits: ScrubLimits | None = None,
) -> None:
    """Validate that ``query_text`` is a safe SPARQL ASK query.

    Returns ``None`` on success; raises :class:`SparqlScrubError` with a
    user-facing message on any policy violation.
    """
    effective_limits = limits if limits is not None else resolve_limits()

    if query_text is None or not query_text.strip():
        msg = "SPARQL query is empty."
        raise SparqlScrubError(msg)

    if len(query_text) > effective_limits.max_query_length:
        msg = (
            f"SPARQL query exceeds the maximum length of "
            f"{effective_limits.max_query_length:,} characters "
            f"(got {len(query_text):,}). Shorten the query or split it "
            "into multiple smaller assertions."
        )
        raise SparqlScrubError(msg)

    try:
        parsed = parseQuery(query_text)
    except Exception as exc:
        msg = (
            "SPARQL syntax error: "
            f"{type(exc).__name__}: {exc}. "
            "Only SPARQL 1.1 ASK queries are supported."
        )
        raise SparqlScrubError(msg) from exc

    body = parsed[1] if len(parsed) > 1 else None
    if not isinstance(body, CompValue) or body.name != "AskQuery":
        actual = getattr(body, "name", type(body).__name__)
        msg = (
            f"Only SPARQL ASK queries are supported; got {actual}. "
            "SELECT, CONSTRUCT, and DESCRIBE are reserved for a future "
            "release; Update operations (INSERT, DELETE, LOAD, ...) are "
            "never permitted."
        )
        raise SparqlScrubError(msg)

    # Reject FROM / FROM NAMED before translating to algebra. ``CompValue.get``
    # returns the key name (not None) on a miss, so use membership + indexing.
    dataset_clauses = body["datasetClause"] if "datasetClause" in body else None  # noqa: SIM401
    if isinstance(dataset_clauses, (list, tuple)) and len(dataset_clauses) > 0:
        msg = (
            "SPARQL FROM and FROM NAMED clauses are not permitted. "
            "Queries run against the data / results / union graphs "
            "provided by the validator; no external graphs may be "
            "referenced."
        )
        raise SparqlScrubError(msg)

    try:
        translated = translateQuery(parsed)
    except Exception as exc:
        msg = (
            "SPARQL algebra translation failed: "
            f"{type(exc).__name__}: {exc}. "
            "The query is syntactically valid but the engine could not "
            "build an execution plan for it."
        )
        raise SparqlScrubError(msg) from exc

    _walk_algebra(
        translated.algebra,
        max_path_depth=effective_limits.max_property_path_depth,
    )


# =============================================================================
# Internal helpers
# =============================================================================


def _walk_algebra(node: Any, *, max_path_depth: int) -> None:
    """Recursively inspect the algebra tree for forbidden constructs."""
    if isinstance(node, CompValue):
        name = node.name or ""
        if name in _FORBIDDEN_ALGEBRA_NODES:
            raise SparqlScrubError(_forbidden_node_message(name))
        for value in node.values():
            _walk_algebra(value, max_path_depth=max_path_depth)
        return

    if isinstance(node, _PATH_OPERATOR_TYPES):
        depth = _property_path_depth(node)
        if depth > max_path_depth:
            msg = (
                f"SPARQL property path nests {depth} levels deep, "
                f"over the limit of {max_path_depth}. Deeply nested "
                "paths can produce cubic-time evaluation on "
                "attacker-crafted graphs; rewrite the assertion "
                "with explicit triples or reduce path nesting."
            )
            raise SparqlScrubError(msg)
        return

    if isinstance(node, (list, tuple)):
        for item in node:
            _walk_algebra(item, max_path_depth=max_path_depth)


def _property_path_depth(path: Any, *, current: int = 0) -> int:
    """Return the maximum nesting depth of property-path operators."""
    if not isinstance(path, _PATH_OPERATOR_TYPES):
        return current

    deepest = current + 1

    inner = getattr(path, "path", None)
    if inner is not None and isinstance(inner, Path):
        deepest = max(deepest, _property_path_depth(inner, current=current + 1))

    args = getattr(path, "args", None)
    if isinstance(args, (list, tuple)):
        for arg in args:
            if isinstance(arg, Path):
                deepest = max(
                    deepest,
                    _property_path_depth(arg, current=current + 1),
                )

    return deepest


def _forbidden_node_message(name: str) -> str:
    """User-facing explanation of why a particular construct is banned."""
    if name == "ServiceGraphPattern":
        return (
            "SPARQL SERVICE clauses are not permitted. They federate "
            "queries to remote endpoints, which would let an assertion "
            "exfiltrate data from the validated graph to an external "
            "URL. Rewrite the assertion to query only the local graph."
        )
    if name in {"InsertData", "DeleteData", "Modify"}:
        return (
            f"SPARQL update operations are not permitted (got {name}). "
            "Only read-only ASK queries are supported."
        )
    if name == "Load":
        return (
            "SPARQL LOAD operations are not permitted. They fetch "
            "remote RDF documents over the network; the validator "
            "operates only on graphs provided by the pipeline."
        )
    return f"SPARQL construct '{name}' is not permitted in author-defined ASK assertions."
