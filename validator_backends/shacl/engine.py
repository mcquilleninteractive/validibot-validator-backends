"""Pure SHACL engine functions for the isolated container backend.

This is the relocated, Django-free descendant of
``validibot/validations/validators/shacl/engine.py``. The behaviour and security
posture are identical; the adaptations are mechanical:

- Resource limits arrive as function parameters (resolved by Django from settings
  and shipped in the input envelope) instead of being read from ``django.conf``.
- Findings are emitted as ``validibot_shared.shacl.envelopes.SHACLFinding`` rows
  (severity as a plain string) instead of Django ``ValidationIssue`` objects.
- The killable subprocess workers are addressed by their container module paths.

Everything that touches the untrusted graph or runs author-supplied SPARQL lives
here, and *only* here, behind the container isolation boundary.
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
from dataclasses import dataclass
from json import JSONDecodeError
from json import dumps as json_dumps
from json import loads as json_loads
from typing import Any

from rdflib import Graph, URIRef
from rdflib.exceptions import ParserError
from rdflib.namespace import RDF, SH

from validator_backends.shacl.sparql_security import SparqlScrubError, scrub_sparql_ask
from validibot_shared.shacl.envelopes import SHACLFinding


logger = logging.getLogger(__name__)

# ── Severity strings (mirror Django's Severity TextChoices values) ──
SEV_ERROR = "ERROR"
SEV_WARNING = "WARNING"
SEV_INFO = "INFO"
SEV_SUCCESS = "SUCCESS"

# ── Resource limits (defaults + hard caps; the envelope supplies resolved values) ──
DEFAULT_MAX_DATA_TRIPLES = 100_000
DEFAULT_MAX_SHAPE_TRIPLES = 50_000
DEFAULT_MAX_ONTOLOGY_TRIPLES = 100_000
DEFAULT_MAX_VALIDATION_DEPTH = 25

HARD_MAX_DATA_TRIPLES = 1_000_000
HARD_MAX_SHAPE_TRIPLES = 200_000
HARD_MAX_ONTOLOGY_TRIPLES = 500_000
HARD_MAX_VALIDATION_DEPTH = 50

# pySHACL wall-clock budget. This is a backstop against pathological
# shapes/SPARQL, NOT the size guard — input size is bounded separately by the
# triple-count caps above (data graph hard-capped at 1M triples). The budget is
# therefore generous: a real building model near the triple cap can legitimately
# take minutes (SHACL cost grows super-linearly in constraints x target nodes).
# The 1800s (30 min) hard cap sits below the container's outer timeout (3600s) so
# pySHACL times out cleanly with a useful message instead of an opaque container
# kill. Must mirror Django's _DEFAULT_PYSHACL_TIMEOUT / _HARD_MAX_PYSHACL_TIMEOUT
# (validibot/.../shacl/launch.py) and SHACL_VALIDATION_TIMEOUT_SECONDS (base.py).
DEFAULT_PYSHACL_TIMEOUT_SECONDS = 300
HARD_MAX_PYSHACL_TIMEOUT_SECONDS = 1800

DEFAULT_SPARQL_QUERY_TIMEOUT_SECONDS = 10
HARD_MAX_SPARQL_QUERY_TIMEOUT_SECONDS = 60

# SHACL-AF / SHACL-JS constructs. Core SHACL is always allowed; advanced
# constructs are gated because they evaluate author-supplied SPARQL/rules.
_SHACL_ADVANCED_PREDICATES: frozenset[URIRef] = frozenset(
    {SH.sparql, SH.select, SH.ask, SH.construct, SH.rule},
)
_SHACL_ADVANCED_CLASSES: frozenset[URIRef] = frozenset(
    {SH.SPARQLConstraint, SH.SPARQLRule, SH.TripleRule},
)
_SHACL_JS_PREDICATES: frozenset[URIRef] = frozenset(
    {SH.js, SH.jsFunctionName, SH.jsLibrary, SH.jsLibraryURL},
)
_SHACL_JS_CLASSES: frozenset[URIRef] = frozenset(
    {SH.JSConstraint, SH.JSRule, SH.JSTarget, SH.JSTargetType, SH.JSFunction},
)
_EMBEDDED_SPARQL_FORBIDDEN_PATTERN = re.compile(
    r"\b(SERVICE|LOAD|CLEAR|DROP|CREATE|ADD|MOVE|COPY|INSERT|DELETE)\b"
    r"|\bFROM\s+(?:NAMED\s+)?<",
    re.IGNORECASE,
)

# Well-known building-domain namespaces (coarse routing output_values for CEL).
NS_S223 = "http://data.ashrae.org/standard223#"
NS_G36 = "http://data.ashrae.org/standard223/1.0/extensions/g36#"
NS_BRICK = "https://brickschema.org/schema/Brick#"

# SHACL severity (rdflib URI) → Validibot severity string.
_SH_SEVERITY_TO_VALIDIBOT: dict[URIRef, str] = {
    SH.Violation: SEV_ERROR,
    SH.Warning: SEV_WARNING,
    SH.Info: SEV_INFO,
}

FILE_SEPARATOR = "\n# === File boundary ===\n"

# SPARQL-ASK target graphs.
SPARQL_ASK_TARGET_DATA = "data"
SPARQL_ASK_TARGET_RESULTS = "results"
SPARQL_ASK_TARGET_UNION = "union"
_VALID_TARGET_GRAPHS: frozenset[str] = frozenset(
    {SPARQL_ASK_TARGET_DATA, SPARQL_ASK_TARGET_RESULTS, SPARQL_ASK_TARGET_UNION},
)


def _clamp(value: int, default: int, hard_max: int) -> int:
    """Return a positive ``value`` clamped to ``hard_max``, else ``default``."""
    if not isinstance(value, int) or value <= 0:
        return default
    return min(value, hard_max)


# =============================================================================
# Pre-parse safety scanning
# =============================================================================

_XML_XXE_PATTERN = re.compile(
    r"<!DOCTYPE\b|<!ENTITY\b|<!ELEMENT\b|SYSTEM\s+['\"]|PUBLIC\s+['\"]",
    re.IGNORECASE,
)


def prevalidate_safety(content: str, rdf_format: str) -> str | None:
    """Reject RDF content containing known-dangerous constructs (XXE / remote ctx).

    Runs before rdflib parsing. Returns an error message if the content must be
    refused, otherwise ``None``. Fails closed.
    """
    if not content:
        return None

    if rdf_format == "xml":
        match = _XML_XXE_PATTERN.search(content)
        if match is not None:
            return (
                f"RDF/XML content contains '{match.group(0).strip()}', "
                "which the validator refuses as an XXE / external-entity "
                "vector. Remove the DTD / entity declaration and resubmit, "
                "or convert the file to Turtle, JSON-LD, or N-Triples."
            )

    if rdf_format == "json-ld":
        try:
            parsed_json = json_loads(content)
        except JSONDecodeError:
            return None
        except Exception as exc:
            logger.warning(
                "JSON-LD prevalidation raised unexpected exception",
                extra={"exc_type": type(exc).__name__},
            )
            return (
                "JSON-LD safety prevalidation failed unexpectedly. "
                "The validator refuses the submission rather than "
                "risking remote context loading."
            )
        context_error = _find_jsonld_context_document_reference(parsed_json)
        if context_error is not None:
            return context_error

    return None


def _find_jsonld_context_document_reference(value: Any) -> str | None:
    """Find any JSON-LD @context value that may trigger a document load."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "@context":
                error = _validate_jsonld_context_value(child)
            else:
                error = _find_jsonld_context_document_reference(child)
            if error is not None:
                return error
    elif isinstance(value, list):
        for child in value:
            error = _find_jsonld_context_document_reference(child)
            if error is not None:
                return error
    return None


def _validate_jsonld_context_value(context_value: Any) -> str | None:
    """Validate one JSON-LD @context value (string refs refused; inline allowed)."""
    if isinstance(context_value, str):
        if context_value.lower().startswith("data:"):
            return None
        return (
            f"JSON-LD content references @context document '{context_value}'. "
            "The validator refuses context documents to prevent SSRF, "
            "local-file reads, and context substitution. Inline the "
            "@context object in the JSON-LD, use a data: URI, or convert "
            "the file to Turtle."
        )
    if isinstance(context_value, dict):
        return _find_jsonld_context_document_reference(context_value)
    if isinstance(context_value, list):
        for item in context_value:
            error = _validate_jsonld_context_value(item)
            if error is not None:
                return error
    return None


# =============================================================================
# RDF parsing
# =============================================================================


def parse_rdf(content: str, rdf_format: str) -> tuple[Graph | None, str | None]:
    """Parse RDF content into an rdflib ``Graph``.

    Returns ``(graph, error_message)`` with exactly one not-None. Every call
    passes through :func:`prevalidate_safety` before rdflib touches the bytes.
    """
    if not content:
        return None, "Submission is empty."

    safety_error = prevalidate_safety(content, rdf_format)
    if safety_error is not None:
        return None, safety_error

    g = Graph()
    try:
        g.parse(data=content, format=rdf_format)
    except ParserError as exc:
        return None, f"RDF parse error ({rdf_format}): {exc}"
    except Exception as exc:
        logger.warning(
            "RDF parse raised unexpected exception",
            extra={"rdf_format": rdf_format, "exc_type": type(exc).__name__},
        )
        return None, f"Unexpected error parsing RDF as {rdf_format}: {exc}"

    return g, None


# =============================================================================
# Bundled standards (Phase 1 stub — mirrors the Django engine)
# =============================================================================

_KNOWN_BUNDLES = {"brick-1.4", "qudt-2.1"}


def load_bundled_standards(
    bundled_standards: list[str],
) -> tuple[str, str, list[SHACLFinding]]:
    """Return bundle shapes/ontology content + warnings for requested bundles.

    Phase 1 returns empty content and a WARNING finding per requested bundle.
    """
    warnings: list[SHACLFinding] = []
    for bundle in bundled_standards:
        if bundle in _KNOWN_BUNDLES:
            warnings.append(
                SHACLFinding(
                    message=(
                        f"Bundled standard '{bundle}' is recognised but the "
                        "shapes file ships in Phase 2 of the SHACL validator "
                        "rollout. The validation will proceed without these "
                        "shapes. Upload the file manually if you need it now."
                    ),
                    severity=SEV_WARNING,
                    code="shacl.bundle_not_yet_shipped",
                ),
            )
        else:
            warnings.append(
                SHACLFinding(
                    message=(
                        f"Unknown bundled standard '{bundle}'. The validator "
                        "does not recognise this identifier; check the step "
                        "config or upload the shapes manually."
                    ),
                    severity=SEV_WARNING,
                    code="shacl.bundle_unknown",
                ),
            )
    return "", "", warnings


# =============================================================================
# SHACL validation
# =============================================================================


def run_shacl_validation(
    data_graph: Graph,
    shapes_text: str,
    ontology_text: str,
    *,
    inference_mode: str,
    advanced_shacl: bool,
    enable_advanced_features: bool,
    max_data_triples: int = DEFAULT_MAX_DATA_TRIPLES,
    max_shape_triples: int = DEFAULT_MAX_SHAPE_TRIPLES,
    max_ontology_triples: int = DEFAULT_MAX_ONTOLOGY_TRIPLES,
    max_validation_depth: int = DEFAULT_MAX_VALIDATION_DEPTH,
    timeout_seconds: int = DEFAULT_PYSHACL_TIMEOUT_SECONDS,
) -> tuple[Graph | None, str | None]:
    """Run pyshacl against the data graph using the supplied shapes.

    Returns ``(results_graph, error_message)`` — exactly one is ``None``.
    All limits are clamped to their hard caps defensively even though Django
    already clamps them when building the envelope.
    """
    if not shapes_text.strip():
        return None, (
            "No SHACL shapes were supplied. Upload one or more shape "
            "files in the step config or attach a custom SHACL validator "
            "from the library."
        )

    data_limit = _clamp(max_data_triples, DEFAULT_MAX_DATA_TRIPLES, HARD_MAX_DATA_TRIPLES)
    if len(data_graph) > data_limit:
        return None, (
            f"Submitted RDF graph has {len(data_graph)} triples, over the "
            f"{data_limit} triple SHACL validation limit."
        )

    shapes_graph = Graph()
    try:
        shapes_graph.parse(data=shapes_text, format="turtle")
    except Exception as exc:
        return None, f"Shapes graph failed to parse as Turtle: {exc}"
    shape_limit = _clamp(
        max_shape_triples,
        DEFAULT_MAX_SHAPE_TRIPLES,
        HARD_MAX_SHAPE_TRIPLES,
    )
    if len(shapes_graph) > shape_limit:
        return None, (
            f"SHACL shapes graph has {len(shapes_graph)} triples, over the "
            f"{shape_limit} triple validation limit."
        )
    policy_error = inspect_shapes_policy(
        shapes_graph,
        advanced_shacl_requested=advanced_shacl,
        enable_advanced_features=enable_advanced_features,
    )
    if policy_error is not None:
        return None, policy_error

    ontology_graph: Graph | None = None
    if ontology_text.strip():
        ontology_graph = Graph()
        try:
            ontology_graph.parse(data=ontology_text, format="turtle")
        except Exception as exc:
            return None, f"Ontology graph failed to parse as Turtle: {exc}"
        ontology_limit = _clamp(
            max_ontology_triples,
            DEFAULT_MAX_ONTOLOGY_TRIPLES,
            HARD_MAX_ONTOLOGY_TRIPLES,
        )
        if len(ontology_graph) > ontology_limit:
            return None, (
                f"SHACL ontology graph has {len(ontology_graph)} triples, over "
                f"the {ontology_limit} triple validation limit."
            )

    pyshacl_result, pyshacl_error = _run_pyshacl_with_timeout(
        data_graph=data_graph,
        shapes_graph=shapes_graph,
        ontology_graph=ontology_graph,
        inference_mode=inference_mode,
        advanced_shacl=(advanced_shacl and enable_advanced_features),
        max_validation_depth=_clamp(
            max_validation_depth,
            DEFAULT_MAX_VALIDATION_DEPTH,
            HARD_MAX_VALIDATION_DEPTH,
        ),
        timeout_seconds=_clamp(
            timeout_seconds,
            DEFAULT_PYSHACL_TIMEOUT_SECONDS,
            HARD_MAX_PYSHACL_TIMEOUT_SECONDS,
        ),
    )
    if pyshacl_error is not None:
        return None, pyshacl_error
    return pyshacl_result, None


def inspect_shapes_policy(
    shapes_graph: Graph,
    *,
    advanced_shacl_requested: bool,
    enable_advanced_features: bool,
) -> str | None:
    """Reject SHACL constructs that are unsafe for the current deployment.

    Core SHACL is always allowed. SHACL-JS is never allowed. SHACL-AF SPARQL
    constraints/rules require both the per-step ``advanced_shacl`` request and
    the deployment-level ``enable_advanced_features`` flag.
    """
    js_hit = _first_shape_policy_hit(
        shapes_graph,
        predicates=_SHACL_JS_PREDICATES,
        classes=_SHACL_JS_CLASSES,
    )
    if js_hit is not None:
        return (
            f"SHACL-JS construct '{js_hit}' was found in the shapes graph. "
            "Validibot does not execute SHACL-JS because it would run "
            "author-supplied JavaScript."
        )

    embedded_sparql_error = _inspect_embedded_shacl_sparql(shapes_graph)
    if embedded_sparql_error is not None:
        return embedded_sparql_error

    advanced_hit = _first_shape_policy_hit(
        shapes_graph,
        predicates=_SHACL_ADVANCED_PREDICATES,
        classes=_SHACL_ADVANCED_CLASSES,
    )
    if advanced_hit is None:
        return None

    if not advanced_shacl_requested:
        return (
            f"Advanced SHACL construct '{advanced_hit}' was found in the "
            "shapes graph, but Advanced SHACL is disabled for this validator. "
            "Remove the construct or enable Advanced SHACL for the step."
        )
    if not enable_advanced_features:
        return (
            f"Advanced SHACL construct '{advanced_hit}' was found in the "
            "shapes graph. This deployment has SHACL_ENABLE_ADVANCED_FEATURES "
            "disabled, so embedded SHACL-AF/SPARQL execution is refused. "
            "Enable that setting only for trusted authors."
        )
    return None


def _first_shape_policy_hit(
    graph: Graph,
    *,
    predicates: frozenset[URIRef],
    classes: frozenset[URIRef],
) -> str | None:
    """Return a compact description of the first forbidden shape term."""
    for _subject, predicate, _object in graph:
        if predicate in predicates:
            return str(predicate)
    for class_uri in classes:
        if (None, RDF.type, class_uri) in graph:
            return str(class_uri)
    return None


def _inspect_embedded_shacl_sparql(shapes_graph: Graph) -> str | None:
    """Reject network/update features inside embedded SHACL SPARQL text."""
    for predicate in (SH.select, SH.ask, SH.construct):
        for sparql_text in shapes_graph.objects(predicate=predicate):
            text = str(sparql_text)
            match = _EMBEDDED_SPARQL_FORBIDDEN_PATTERN.search(text)
            if match is not None:
                return (
                    f"Embedded SHACL SPARQL contains forbidden construct "
                    f"'{match.group(0).strip()}'. SERVICE, FROM, LOAD, "
                    "SPARQL Update, and remote graph operations are not "
                    "permitted in shapes."
                )
    return None


def _run_pyshacl_with_timeout(
    *,
    data_graph: Graph,
    shapes_graph: Graph,
    ontology_graph: Graph | None,
    inference_mode: str,
    advanced_shacl: bool,
    max_validation_depth: int,
    timeout_seconds: int,
) -> tuple[Graph | None, str | None]:
    """Run pySHACL in a killable subprocess and terminate it on timeout."""
    try:
        payload = {
            "data_graph_ntriples": data_graph.serialize(format="nt"),
            "shapes_graph_turtle": shapes_graph.serialize(format="turtle"),
            "ontology_graph_turtle": (
                ontology_graph.serialize(format="turtle") if ontology_graph is not None else ""
            ),
            "inference_mode": inference_mode,
            "advanced_shacl": advanced_shacl,
            "max_validation_depth": max_validation_depth,
        }
    except Exception as exc:
        logger.exception("Failed to serialise SHACL subprocess payload")
        return None, f"SHACL engine error before subprocess launch: {exc}"

    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "validator_backends.shacl.pyshacl_worker",
            ],
            input=json_dumps(payload),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, (
            f"SHACL validation exceeded the {timeout_seconds}s wall-clock "
            "budget and was terminated. Reduce graph size, simplify shapes, "
            "or lower the inference/advanced SHACL settings."
        )
    except OSError as exc:
        logger.exception("Failed to launch SHACL subprocess")
        return None, f"SHACL engine error launching worker subprocess: {exc}"

    try:
        response = json_loads(completed.stdout or "{}")
    except JSONDecodeError:
        logger.exception("Failed to decode SHACL subprocess response")
        detail = completed.stderr.strip() or completed.stdout.strip() or "no output"
        return None, (
            "SHACL validation worker exited without a valid response "
            f"(exit code {completed.returncode}): {detail}"
        )

    if completed.returncode != 0:
        detail = completed.stderr.strip() or str(response.get("body", "")).strip()
        return None, (
            "SHACL validation worker failed "
            f"(exit code {completed.returncode}): {detail or 'no output'}"
        )

    status = response.get("status")
    body = response.get("body", "")
    if status == "error":
        return None, str(body)
    if status != "ok":
        return None, f"SHACL validation worker returned unknown status '{status}'."

    results_graph = Graph()
    try:
        results_graph.parse(data=str(body), format="turtle")
    except Exception as exc:
        logger.exception("Failed to parse SHACL subprocess result graph")
        return None, f"SHACL engine error parsing result graph: {exc}"
    return results_graph, None


# =============================================================================
# SPARQL ASK assertion execution
# =============================================================================


@dataclass(frozen=True)
class SparqlAskAssertion:
    """One author-defined SPARQL ASK assertion (engine-internal form).

    A SHACL run answers "does this data satisfy these shapes". SPARQL ASK
    assertions let an author additionally ask a yes/no question — either of the
    data itself or of the validation report SHACL just produced. An ASK returning
    ``false`` is the failure case, so assertions are written as statements that
    should hold.

    This is the engine-internal shape. ``run_sparql_ask_assertions`` accepts
    anything with these attributes, which is how the same code path serves both
    this class and the shared ``SHACLSparqlAssertionSpec`` from the envelope
    without either package depending on the other.

    Every query is re-scrubbed immediately before execution even though Django
    scrubbed it at save time — the standing defence-in-depth posture, since by
    the time a query reaches here it has crossed a process boundary as JSON.

    Fields:
        target_graph: Which graph to query. ``"data"`` is the submitted data,
            ``"results"`` is the SHACL validation report, and ``"union"`` is
            both. Querying ``results`` is what enables meta-assertions such as
            "no violation was reported for any node of this class". An unknown
            value produces an engine-error finding rather than an exception.
        query: The SPARQL ASK query text.
        severity: Severity for the finding raised when the ASK returns ``false``.
            Engine errors are always reported at error severity regardless of
            this value — a query that could not run is a different problem from
            a query whose answer was ``false``.
        description: Short label identifying this assertion in findings. Falls
            back to ``SPARQL ASK #<n>`` when empty, so ordering matters to the
            reader if descriptions are omitted.
        error_message_template: Message shown when the ASK returns ``false``.
            Defaults to a generic "assertion returned false" line.
        success_message: Optional message emitted when the ASK returns ``true``.
            Empty means silence on success, which is the usual choice — this
            exists for assertions where confirming the check ran is itself
            valuable evidence.
        assertion_id: Database identifier carried through into finding metadata
            so a finding can be traced back to the row that produced it.
            ``None`` for assertions not persisted in Django.
    """

    target_graph: str
    query: str
    severity: str
    description: str = ""
    error_message_template: str = ""
    success_message: str = ""
    assertion_id: int | None = None


def run_sparql_ask(
    *,
    query_text: str,
    target_graph_name: str,
    data_graph: Graph,
    results_graph: Graph | None,
    timeout_seconds: int,
) -> tuple[bool | None, str | None]:
    """Execute one SPARQL ASK against the requested target graph.

    Returns ``(answer, error_message)`` with exactly one not-None. Never raises.
    """
    if target_graph_name not in _VALID_TARGET_GRAPHS:
        return None, (
            f"Unknown SPARQL target graph '{target_graph_name}'. "
            f"Expected one of: {sorted(_VALID_TARGET_GRAPHS)}."
        )

    # Re-scrub at run time (belt-and-braces; the form already scrubbed at save).
    try:
        scrub_sparql_ask(query_text)
    except SparqlScrubError as exc:
        return None, f"SPARQL ASK rejected by security scrub: {exc}"

    target = _select_target_graph(
        target_graph_name=target_graph_name,
        data_graph=data_graph,
        results_graph=results_graph,
    )
    if target is None:
        return None, (
            f"SPARQL target '{target_graph_name}' is not available "
            "because no SHACL results graph was produced. Did SHACL "
            "fail to run, or did parsing fail earlier in the pipeline?"
        )

    effective_timeout = _clamp(
        timeout_seconds,
        DEFAULT_SPARQL_QUERY_TIMEOUT_SECONDS,
        HARD_MAX_SPARQL_QUERY_TIMEOUT_SECONDS,
    )
    return _execute_ask_with_timeout(
        query_text=query_text,
        graph=target,
        timeout_seconds=effective_timeout,
    )


def _select_target_graph(
    *,
    target_graph_name: str,
    data_graph: Graph,
    results_graph: Graph | None,
) -> Graph | None:
    """Resolve a ``target_graph`` name to an rdflib Graph instance."""
    if target_graph_name == SPARQL_ASK_TARGET_DATA:
        return data_graph
    if target_graph_name == SPARQL_ASK_TARGET_RESULTS:
        return results_graph
    if target_graph_name == SPARQL_ASK_TARGET_UNION:
        if results_graph is None:
            return data_graph
        union = Graph()
        for triple in data_graph:
            union.add(triple)
        for triple in results_graph:
            union.add(triple)
        return union
    return None


def _execute_ask_with_timeout(
    *,
    query_text: str,
    graph: Graph,
    timeout_seconds: int,
) -> tuple[bool | None, str | None]:
    """Run an ASK in a killable subprocess and terminate it on timeout."""
    payload = {
        "query": query_text,
        "graph_ntriples": graph.serialize(format="nt"),
    }
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "validator_backends.shacl.sparql_ask_worker",
            ],
            input=json_dumps(payload),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, (
            f"SPARQL ASK exceeded the {timeout_seconds}s wall-clock "
            "budget. Simplify the query or narrow the target graph."
        )

    stdout = completed.stdout.strip()
    if not stdout:
        stderr = completed.stderr.strip()
        return None, ("SPARQL ASK worker returned no result" + (f": {stderr}" if stderr else "."))
    try:
        response = json_loads(stdout)
    except JSONDecodeError as exc:
        stderr = completed.stderr.strip()
        return None, (
            "SPARQL ASK worker returned invalid JSON: "
            f"{exc}" + (f" stderr={stderr}" if stderr else "")
        )

    if response.get("status") == "ok":
        return bool(response.get("answer")), None
    return None, str(
        response.get("body") or f"SPARQL ASK worker failed with exit code {completed.returncode}.",
    )


def evaluate_sparql_assertions(
    *,
    assertions: list[Any],
    data_graph: Graph,
    results_graph: Graph | None,
    timeout_seconds: int = DEFAULT_SPARQL_QUERY_TIMEOUT_SECONDS,
) -> list[SHACLFinding]:
    """Run every assertion in order; return one finding per failing/erroring ASK.

    ``assertions`` items only need the attributes ``target_graph``, ``query``,
    ``severity``, ``description``, ``error_message_template``, ``success_message``,
    and ``assertion_id`` — both ``SparqlAskAssertion`` and the shared
    ``SHACLSparqlAssertionSpec`` satisfy that shape.
    """
    findings: list[SHACLFinding] = []
    for index, assertion in enumerate(assertions):
        label = assertion.description or f"SPARQL ASK #{index + 1}"
        answer, error = run_sparql_ask(
            query_text=assertion.query,
            target_graph_name=assertion.target_graph,
            data_graph=data_graph,
            results_graph=results_graph,
            timeout_seconds=timeout_seconds,
        )
        if error is not None:
            findings.append(
                SHACLFinding(
                    message=f"{label}: {error}",
                    severity=SEV_ERROR,
                    code="shacl.sparql_ask_engine_error",
                    meta={
                        "assertion_index": index,
                        "target_graph": assertion.target_graph,
                    },
                    assertion_id=assertion.assertion_id,
                ),
            )
            continue

        if answer is False:
            findings.append(
                SHACLFinding(
                    message=(
                        assertion.error_message_template or f"{label}: assertion returned false."
                    ),
                    severity=assertion.severity,
                    code="shacl.sparql_ask_failed",
                    meta={
                        "assertion_index": index,
                        "target_graph": assertion.target_graph,
                        "description": assertion.description,
                    },
                    assertion_id=assertion.assertion_id,
                ),
            )
        elif assertion.success_message:
            findings.append(
                SHACLFinding(
                    message=assertion.success_message,
                    severity=SEV_SUCCESS,
                    code="assertion_passed",
                    meta={
                        "assertion_index": index,
                        "target_graph": assertion.target_graph,
                        "description": assertion.description,
                    },
                    assertion_id=assertion.assertion_id,
                ),
            )
    return findings


# =============================================================================
# Result mapping
# =============================================================================


def map_results_to_issues(results_graph: Graph) -> list[SHACLFinding]:
    """Walk a SHACL ``sh:ValidationReport`` graph and emit findings."""
    findings: list[SHACLFinding] = []

    for result_node in results_graph.objects(predicate=SH.result):
        severity_uri = results_graph.value(result_node, SH.resultSeverity)
        severity = _SH_SEVERITY_TO_VALIDIBOT.get(severity_uri, SEV_ERROR)

        focus_node = results_graph.value(result_node, SH.focusNode)
        result_path = results_graph.value(result_node, SH.resultPath)
        source_shape = results_graph.value(result_node, SH.sourceShape)
        constraint = results_graph.value(result_node, SH.sourceConstraintComponent)
        value = results_graph.value(result_node, SH.value)

        messages = [str(m) for m in results_graph.objects(result_node, SH.resultMessage)]
        primary_message = messages[0] if messages else "SHACL constraint violated."

        meta: dict[str, Any] = {
            "shacl_focus_node": _node_repr(focus_node),
            "shacl_source_shape": _node_repr(source_shape),
            "shacl_constraint_component": _node_repr(constraint),
        }
        if value is not None:
            meta["shacl_value"] = _node_repr(value)
        if len(messages) > 1:
            meta["shacl_all_messages"] = messages

        findings.append(
            SHACLFinding(
                path=_node_repr(result_path) or "",
                message=primary_message,
                severity=severity,
                code=_shacl_code_from_constraint(constraint),
                meta=meta,
            ),
        )

    severity_order = {SEV_ERROR: 0, SEV_WARNING: 1, SEV_INFO: 2}
    findings.sort(
        key=lambda f: (
            severity_order.get(f.severity, 99),
            (f.meta or {}).get("shacl_source_shape", "") or "",
            f.message,
        ),
    )
    return findings


def _node_repr(node: Any) -> str:
    """Render an rdflib node as a stable string for finding paths/meta."""
    if node is None:
        return ""
    return str(node)


def _shacl_code_from_constraint(constraint_uri: Any) -> str:
    """Derive a short machine-readable code from a SHACL constraint URI."""
    if constraint_uri is None:
        return "shacl.unknown"
    text = str(constraint_uri)
    if text.startswith(str(SH)):
        return f"shacl.{text[len(str(SH)) :]}"
    return f"shacl.{text}"


# =============================================================================
# Output-value extraction
# =============================================================================


def extract_output_values(
    data_graph: Graph | None,
    results_graph: Graph | None,
    *,
    parse_ok: bool,
    parse_serialization: str,
) -> dict[str, Any]:
    """Compute the ``o.*`` output output-value dict for CEL assertions."""
    output_values: dict[str, Any] = {
        "parse_ok": parse_ok,
        "parse_serialization": parse_serialization,
        "triple_count": len(data_graph) if data_graph is not None else 0,
        "namespaces_present": [],
        "has_s223_namespace": False,
        "has_g36_namespace": False,
        "has_brick_namespace": False,
        "shacl_violation_count": 0,
        "shacl_warning_count": 0,
        "shacl_info_count": 0,
        "shacl_total_count": 0,
    }

    if data_graph is not None:
        namespaces = _collect_namespaces(data_graph)
        output_values["namespaces_present"] = sorted(namespaces)
        output_values["has_s223_namespace"] = NS_S223 in namespaces
        output_values["has_g36_namespace"] = NS_G36 in namespaces
        output_values["has_brick_namespace"] = NS_BRICK in namespaces

    if results_graph is not None:
        for result_node in results_graph.objects(predicate=SH.result):
            sev = results_graph.value(result_node, SH.resultSeverity)
            if sev == SH.Violation:
                output_values["shacl_violation_count"] += 1
            elif sev == SH.Warning:
                output_values["shacl_warning_count"] += 1
            elif sev == SH.Info:
                output_values["shacl_info_count"] += 1
        output_values["shacl_total_count"] = (
            output_values["shacl_violation_count"]
            + output_values["shacl_warning_count"]
            + output_values["shacl_info_count"]
        )

    return output_values


def _collect_namespaces(graph: Graph) -> set[str]:
    """Return the set of namespace URIs that appear in any triple position."""
    seen: set[str] = set()
    for triple in graph:
        for term in triple:
            if isinstance(term, URIRef):
                uri = str(term)
                cut = max(uri.rfind("#"), uri.rfind("/"))
                if cut > 0:
                    seen.add(uri[: cut + 1])
    return seen
