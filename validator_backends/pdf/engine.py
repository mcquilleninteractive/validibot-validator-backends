"""Bounded, non-rendering PDF package inventory and extraction engine.

The engine uses qpdf through pikepdf with recovery disabled. It walks the
reachable object graph with explicit depth and reference budgets, inventories
standard file-specification and interactive mechanisms, and extracts only
bounded member streams. It never renders pages, runs an action or script,
follows a URI, rewrites the source PDF, or uses an embedded name as a path.

PDF streams can expand while qpdf decodes their filter chains. The container's
memory limit remains the final native-code boundary; this module adds earlier
structural, encoded-byte, decoded-byte, filter-count, and expansion-ratio
guards so ordinary hostile inputs fail as domain results well before that
boundary wherever qpdf can expose the necessary facts.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import time
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pikepdf
from defusedxml import ElementTree as SafeElementTree

from validibot_shared.pdf import (
    PdfDocumentFacts,
    PdfInputs,
    PdfInventory,
    PdfInventorySource,
    PdfMember,
    PdfOutputs,
    PdfParserInfo,
    PdfPayloadSelector,
)
from validibot_shared.validations.envelopes import (
    Severity,
    ValidationMessage,
    ValidationStatus,
)


PDF_ENGINE_NAME = "qpdf/pikepdf"
PDF_HARD_MAX_INPUT_BYTES = 250_000_000
PDF_MAX_STREAM_FILTERS = 64
PDF_MAX_DECODE_RATIO = 200
PDF_DECODE_RATIO_MIN_BYTES = 4_096
PDF_MAX_NAME_TREE_DEPTH = 64
PDF_MAX_DISCOVERY_PATH_CHARS = 2_000


@dataclass(slots=True)
class _InspectionBudget:
    """Mutable counters for work that is not represented by unique members."""

    member_references: int = 0
    total_decoded_bytes: int = 0


@dataclass(frozen=True, slots=True)
class _GraphDictionary:
    """One reachable dictionary and its bounded diagnostic path."""

    value: Any
    location: str


@dataclass(slots=True)
class _MemberRecord:
    """Mutable internal record merged by extracted-byte SHA-256.

    One record per *distinct payload*, not per place a payload was found. A PDF
    can reach the same embedded bytes through several unrelated structures at
    once — the ``/EmbeddedFiles`` name tree, a bare file specification, a PDF/A-3
    ``/AF`` associated-files array, a page's file-attachment annotation — and
    naively treating those as four attachments would both mislead the author and
    inflate the output. Keying on the SHA-256 of the *extracted* bytes collapses
    them into one member.

    That merge is why nearly every field below is a ``set``. The payload is
    singular but the evidence about it is plural, and all of it is kept: how many
    ways a file was reachable, and whether those routes agreed with each other,
    is itself signal. Sets are sorted into stable lists when the output envelope
    is assembled.

    **Declared versus detected is the central distinction.** The PDF's own claims
    about a payload are untrusted input, so they are recorded (plural,
    ``declared_media_types``) alongside what sniffing actually found (singular,
    ``detected_media_type``). Disagreement raises the ``declared_type_mismatch``
    risk flag rather than being resolved in favour of either side. A single
    payload declared as two different types across two discovery sites is
    preserved as exactly that.

    Fields:
        data: The extracted bytes. Held in memory because members are small by
            policy and may be re-emitted as output artifacts.
        sha256: Digest of ``data``; the merge key for this record.
        discovery_kinds: How the payload was reached — ``embedded_files_name_tree``,
            ``file_specification``, ``associated_file``,
            ``file_attachment_annotation``. Multiple entries mean multiple routes.
        discovery_locations: Structural paths to each discovery site, for example
            ``…/AF[0]``, so a finding can point at where in the document a member
            actually lives.
        object_references: Underlying PDF object references, letting two
            discovery sites that share one object be told apart from two that
            merely share content.
        original_names: Every filename the document declared for these bytes.
            Retained only as quoted data and never used to build a path — see
            ``_filename_risks``, which flags traversal characters, drive-letter
            prefixes, control characters, and bidirectional-override characters
            that could disguise an extension in a UI.
        descriptions: Author-supplied descriptions, joined on output.
        declared_media_types: What the PDF claims these bytes are (see above).
        af_relationships: PDF/A-3 ``AFRelationship`` values — ``Source``,
            ``Data``, ``Alternative``, ``Supplement`` and similar. These say what
            role an attachment plays, and are what a workflow author selects on
            when picking, say, the ZUGFeRD invoice XML out of a PDF.
        rich_media_asset_names: Asset names when the payload came in through a
            rich-media annotation.
        encoded_size_bytes: The stream's declared ``/Length`` — the size *before*
            decompression, and a document's claim rather than an observation.
            Compare against ``len(data)`` to reason about compression ratio.
        detected_media_type: The single sniffed type (see above).
        xml_root_qname: Root element qualified name when the payload parses as
            XML. This is what identifies an attachment as a particular business
            document without trusting its filename or declared type.
        risk_flags: Accumulated hazards — filename risks above, plus
            ``declared_type_mismatch`` and ``executable_content``. Flags are
            reported; they do not by themselves suppress the member.
        selected_output_key: Set when a member matches an author's selector and
            is therefore promoted to a named output. Empty for members that were
            merely catalogued.
    """

    data: bytes
    sha256: str
    discovery_kinds: set[str] = field(default_factory=set)
    discovery_locations: set[str] = field(default_factory=set)
    object_references: set[str] = field(default_factory=set)
    original_names: set[str] = field(default_factory=set)
    descriptions: set[str] = field(default_factory=set)
    declared_media_types: set[str] = field(default_factory=set)
    af_relationships: set[str] = field(default_factory=set)
    rich_media_asset_names: set[str] = field(default_factory=set)
    encoded_size_bytes: int | None = None
    detected_media_type: str = ""
    xml_root_qname: str = ""
    risk_flags: set[str] = field(default_factory=set)
    selected_output_key: str = ""


@dataclass(frozen=True, slots=True)
class PdfEngineResult:
    """Complete domain result plus exact artifact bytes for the entrypoint.

    Unlike the other backends' result tuples, this one carries payload bytes.
    The engine decides *which* embedded members become outputs but does not
    upload them, leaving the entrypoint to own all storage I/O — so the engine
    stays testable without a storage backend, and every upload goes through one
    audited path.

    Fields:
        status: Overall validation status for the run.
        messages: Findings surfaced to the author.
        outputs: The typed PDF output envelope, including member metadata.
        artifact_payloads: Output key to exact bytes, for members the author's
            selectors promoted to artifacts. Keys match the
            ``selected_output_key`` values recorded on the corresponding members.
    """

    status: ValidationStatus
    messages: list[ValidationMessage]
    outputs: PdfOutputs
    artifact_payloads: dict[str, bytes]


def inspect_pdf(
    path: Path,
    *,
    source_name: str,
    inputs: PdfInputs,
) -> PdfEngineResult:
    """Inspect one PDF without recovery, rendering, execution, or rewriting."""
    started = time.monotonic()
    source_bytes = _read_bounded(path, PDF_HARD_MAX_INPUT_BYTES)
    source = PdfInventorySource(
        name=Path(source_name).name or "document.pdf",
        size_bytes=len(source_bytes),
        sha256=hashlib.sha256(source_bytes).hexdigest(),
    )
    findings: list[ValidationMessage] = []
    records: dict[str, _MemberRecord] = {}
    budget = _InspectionBudget()
    xmp_bytes = b""
    bundle_bytes = b""
    header_version = _header_version(source_bytes)

    if len(source_bytes) > inputs.limits.max_input_bytes:
        return _limit_failure(
            source=source,
            inputs=inputs,
            header_version=header_version,
            code="pdf.limit.input_bytes",
            text="The PDF exceeds the configured input-byte limit.",
            execution_seconds=time.monotonic() - started,
        )

    try:
        with pikepdf.Pdf.open(
            path,
            password="",
            suppress_warnings=False,
            attempt_recovery=False,
        ) as pdf:
            if len(pdf.pages) > inputs.limits.max_pages:
                return _limit_failure(
                    source=source,
                    inputs=inputs,
                    header_version=header_version,
                    code="pdf.limit.pages",
                    text="The PDF exceeds the configured page limit.",
                    execution_seconds=time.monotonic() - started,
                )
            if len(pdf.objects) > inputs.limits.max_objects:
                return _limit_failure(
                    source=source,
                    inputs=inputs,
                    header_version=header_version,
                    code="pdf.limit.objects",
                    text="The PDF exceeds the configured object limit.",
                    execution_seconds=time.monotonic() - started,
                )

            raw_parser_warnings = pdf.get_warnings()
            parser_warnings = [
                _bounded_text(warning, 500)
                for warning in raw_parser_warnings[: inputs.limits.max_findings]
            ]
            if len(raw_parser_warnings) > len(parser_warnings):
                findings.append(
                    _message(
                        Severity.ERROR,
                        "pdf.limit.parser_warnings",
                        "The PDF exceeds the configured parser-warning limit.",
                    )
                )
            findings.extend(
                _message(
                    Severity.WARNING,
                    "pdf.structure.parser_warning",
                    "The PDF parser reported a structural warning.",
                )
                for _warning in parser_warnings
            )

            root = pdf.Root
            xmp_bytes = _document_xmp(root, inputs=inputs, findings=findings)
            graph = _walk_reachable_dictionaries(
                root,
                max_depth=inputs.limits.max_object_depth,
                findings=findings,
            )
            extensions = _inventory_extensions(root)
            requirements = _inventory_requirements(root)
            interactive = _interactive_features(pdf, root)
            signatures = _inventory_signatures(pdf, inputs=inputs)

            _discover_name_tree_attachments(
                pdf,
                records=records,
                budget=budget,
                inputs=inputs,
                findings=findings,
            )
            _discover_file_spec_objects(
                pdf,
                records=records,
                budget=budget,
                inputs=inputs,
                findings=findings,
            )
            _discover_graph_associated_files(
                graph,
                records=records,
                budget=budget,
                inputs=inputs,
                findings=findings,
            )
            _discover_rich_media_assets(
                graph,
                records=records,
                budget=budget,
                inputs=inputs,
                findings=findings,
            )
            for page_number, page in enumerate(pdf.pages, start=1):
                _discover_page_annotations(
                    page.obj,
                    page_number=page_number,
                    records=records,
                    budget=budget,
                    inputs=inputs,
                    findings=findings,
                )

            _apply_package_risk_findings(records, findings=findings)
            if inputs.profile == "safe_static_package_v1":
                _apply_safe_static_profile(interactive, findings=findings)

            selected = _apply_selectors(
                records,
                inputs=inputs,
                findings=findings,
            )
            if inputs.emit_extracted_files_bundle and records:
                candidate_bundle = _build_bundle(records)
                if len(candidate_bundle) > inputs.limits.max_total_member_bytes:
                    findings.append(
                        _message(
                            Severity.ERROR,
                            "pdf.limit.output_bundle_bytes",
                            "The deterministic extraction bundle exceeds the "
                            "configured total-member output budget.",
                        )
                    )
                else:
                    bundle_bytes = candidate_bundle
            metadata = _xmp_inventory(xmp_bytes)
            metadata["object_metadata"] = _inventory_object_metadata(
                graph,
                document_xmp_sha256=metadata.get("sha256", ""),
                inputs=inputs,
                findings=findings,
            )
            metadata["incremental_revision_markers"] = max(
                0,
                source_bytes.count(b"startxref") - 1,
            )
            _enforce_finding_limit(findings, inputs.limits.max_findings)
            members = _public_members(records)
            finding_summary = _finding_summary(findings)
            passed = finding_summary.get("ERROR", 0) == 0
            inventory = PdfInventory(
                source=source,
                parser=PdfParserInfo(
                    engine=PDF_ENGINE_NAME,
                    versions={
                        "pikepdf": pikepdf.__version__,
                        "qpdf": pikepdf.__libqpdf_version__,
                    },
                    recovery_attempted=False,
                    warnings=parser_warnings,
                ),
                pdf=PdfDocumentFacts(
                    header_version=str(pdf.pdf_version or header_version),
                    catalog_version=_pdf_name(root.get("/Version")),
                    page_count=len(pdf.pages),
                    object_count=len(pdf.objects),
                    **_encryption_facts(pdf),
                    linearized=bool(pdf.is_linearized),
                ),
                extensions=extensions,
                requirements=requirements,
                declarations=_inventory_declarations(xmp_bytes),
                metadata=metadata,
                interactive_features=interactive,
                signatures=signatures,
                members=members,
                profile_results=[
                    {
                        "profile": inputs.profile,
                        "passed": passed,
                    }
                ],
                limits=inputs.limits.model_dump(mode="json"),
                finding_summary=finding_summary,
            )
    except pikepdf.PasswordError:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.encryption.password_required",
                "The PDF requires a user password and cannot be inspected.",
            )
        )
        inventory = _failure_inventory(
            source=source,
            inputs=inputs,
            header_version=header_version,
            encrypted=True,
            findings=findings,
        )
        selected = {}
        xmp_bytes = b""
        bundle_bytes = b""
    except pikepdf.PdfError:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.structure.invalid",
                "The file is not a readable PDF with recovery disabled.",
            )
        )
        inventory = _failure_inventory(
            source=source,
            inputs=inputs,
            header_version=header_version,
            encrypted=False,
            findings=findings,
        )
        selected = {}
        xmp_bytes = b""
        bundle_bytes = b""

    inventory_bytes = (
        inventory.model_dump_json(indent=2, exclude_none=True).encode("utf-8") + b"\n"
    )
    if len(inventory_bytes) > inputs.limits.max_inventory_bytes:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.inventory_bytes",
                "The canonical PDF inventory exceeds the configured output limit.",
            )
        )
        inventory = _failure_inventory(
            source=source,
            inputs=inputs,
            header_version=header_version,
            encrypted=inventory.pdf.encrypted,
            findings=findings,
        )
        selected = {}
        xmp_bytes = b""
        bundle_bytes = b""
        records = {}
        inventory_bytes = (
            inventory.model_dump_json(indent=2, exclude_none=True).encode("utf-8") + b"\n"
        )
    artifact_payloads = {"pdf_inventory": inventory_bytes, **selected}
    if xmp_bytes:
        artifact_payloads["xmp_metadata"] = xmp_bytes
    if bundle_bytes:
        artifact_payloads["extracted_files_bundle"] = bundle_bytes

    finding_summary = _finding_summary(findings)
    passed = finding_summary.get("ERROR", 0) == 0
    outputs = PdfOutputs(
        passed=passed,
        member_count=len(inventory.members),
        selected_output_keys=sorted(selected),
        finding_summary=finding_summary,
        inventory=inventory,
        engine=(
            f"{PDF_ENGINE_NAME} pikepdf/{pikepdf.__version__} qpdf/{pikepdf.__libqpdf_version__}"
        ),
        execution_seconds=time.monotonic() - started,
    )
    return PdfEngineResult(
        status=(ValidationStatus.SUCCESS if passed else ValidationStatus.FAILED_VALIDATION),
        messages=findings,
        outputs=outputs,
        artifact_payloads=artifact_payloads,
    )


def _read_bounded(path: Path, max_bytes: int) -> bytes:
    """Read the already identity-verified local file under a second hard cap."""
    with path.open("rb") as source:
        data = source.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("The PDF exceeds the configured input-byte limit.")
    return data


def _document_xmp(root, *, inputs: PdfInputs, findings) -> bytes:
    """Return a safe, bounded document XMP packet when present."""
    metadata = root.get("/Metadata")
    if metadata is None or not hasattr(metadata, "read_bytes"):
        return b""
    data = metadata.read_bytes()
    if len(data) > inputs.limits.max_xmp_bytes:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.xmp_bytes",
                "The document XMP packet exceeds the configured limit.",
            )
        )
        return b""
    try:
        SafeElementTree.fromstring(data)
    except Exception:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.metadata.xmp_invalid",
                "Document XMP is not safe, well-formed XML.",
            )
        )
        return b""
    return data


def _walk_reachable_dictionaries(
    root,
    *,
    max_depth: int,
    findings: list[ValidationMessage],
) -> list[_GraphDictionary]:
    """Walk dictionaries and arrays iteratively with cycle and depth guards."""
    discovered: list[_GraphDictionary] = []
    seen: set[tuple[Any, ...]] = set()
    # Direct pikepdf objects have no object number, so their fallback identity
    # is the Python wrapper id. Keep every traversed container alive for the
    # whole walk: otherwise a discarded direct-array wrapper can be collected
    # and its id reused by an unrelated later object, making discovery depend
    # on allocator timing.
    retained_containers: list[Any] = []
    stack: list[tuple[Any, str, int]] = [(root, "catalog", 0)]
    depth_exhausted = False

    while stack:
        value, location, depth = stack.pop()
        if not isinstance(value, (pikepdf.Dictionary, pikepdf.Array, pikepdf.Stream)):
            continue
        retained_containers.append(value)
        identity = _graph_object_identity(value)
        if identity in seen:
            continue
        seen.add(identity)
        if depth > max_depth:
            depth_exhausted = True
            continue
        if isinstance(value, (pikepdf.Dictionary, pikepdf.Stream)):
            discovered.append(
                _GraphDictionary(
                    value=value,
                    location=_bounded_text(location, PDF_MAX_DISCOVERY_PATH_CHARS),
                )
            )
            children = [
                (
                    child,
                    f"{location}/{_pdf_name(key)}",
                    depth + 1,
                )
                for key, child in value.items()
            ]
        else:
            children = [
                (child, f"{location}[{position}]", depth + 1)
                for position, child in enumerate(value)
            ]
        stack.extend(reversed(children))

    if depth_exhausted:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.object_depth",
                "The reachable PDF object graph exceeds the configured depth limit.",
            )
        )
    return discovered


def _graph_object_identity(value) -> tuple[Any, ...]:
    """Return a stable indirect identity or a process-local direct identity."""
    try:
        object_number, generation = value.objgen
    except (AttributeError, ValueError):
        object_number = generation = 0
    if object_number:
        return ("indirect", int(object_number), int(generation))
    return ("direct", id(value))


def _discover_graph_associated_files(
    graph: list[_GraphDictionary],
    *,
    records,
    budget,
    inputs,
    findings,
) -> None:
    """Discover `/AF` arrays on every reachable dictionary, including structure."""
    for item in graph:
        _discover_associated_files(
            item.value,
            location=item.location,
            records=records,
            budget=budget,
            inputs=inputs,
            findings=findings,
        )


def _discover_rich_media_assets(
    graph: list[_GraphDictionary],
    *,
    records,
    budget,
    inputs,
    findings,
) -> None:
    """Discover RichMedia asset name trees without activating configurations."""
    for item in graph:
        annotation = item.value
        if _pdf_name(annotation.get("/Subtype")) != "RichMedia":
            continue
        content = annotation.get("/RichMediaContent")
        if not isinstance(content, pikepdf.Dictionary):
            continue
        assets = content.get("/Assets")
        if not isinstance(assets, pikepdf.Dictionary):
            continue
        for asset_name, file_spec in _name_tree_pairs(assets):
            if not isinstance(file_spec, pikepdf.Dictionary):
                continue
            _add_file_spec(
                file_spec,
                original_name=_file_spec_name(file_spec),
                discovery_kind="rich_media_asset",
                location=f"{item.location}/RichMediaContent/Assets",
                records=records,
                budget=budget,
                inputs=inputs,
                findings=findings,
                rich_media_asset_name=asset_name,
            )


def _name_tree_pairs(tree) -> list[tuple[str, Any]]:
    """Return bounded RichMedia name-tree pairs without relying on traversal order."""
    result: list[tuple[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    retained_nodes: list[Any] = []
    stack: list[tuple[Any, int]] = [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        if not isinstance(node, pikepdf.Dictionary) or depth > PDF_MAX_NAME_TREE_DEPTH:
            continue
        retained_nodes.append(node)
        identity = _graph_object_identity(node)
        if identity in seen:
            continue
        seen.add(identity)
        names = node.get("/Names")
        if isinstance(names, pikepdf.Array):
            pair_count = len(names) // 2
            for pair_index in range(pair_count):
                name = _pdf_text(names[pair_index * 2])
                value = names[pair_index * 2 + 1]
                result.append((name, value))
        kids = node.get("/Kids")
        if isinstance(kids, pikepdf.Array):
            stack.extend((kid, depth + 1) for kid in reversed(kids))
    return sorted(result, key=lambda pair: pair[0])


def _discover_name_tree_attachments(pdf, *, records, budget, inputs, findings) -> None:
    """Discover the catalog EmbeddedFiles name tree through pikepdf's API."""
    for logical_name in sorted(pdf.attachments):
        spec = pdf.attachments[logical_name]
        _add_file_spec(
            spec.obj,
            original_name=logical_name,
            discovery_kind="embedded_files_name_tree",
            location="catalog/Names/EmbeddedFiles",
            records=records,
            budget=budget,
            inputs=inputs,
            findings=findings,
        )


def _discover_file_spec_objects(pdf, *, records, budget, inputs, findings) -> None:
    """Find indirect file specifications not reachable from the name tree."""
    for obj in pdf.objects:
        if not isinstance(obj, pikepdf.Dictionary):
            continue
        if _pdf_name(obj.get("/Type")) != "Filespec" and "/EF" not in obj:
            continue
        _add_file_spec(
            obj,
            original_name=_file_spec_name(obj),
            discovery_kind="file_specification",
            location=f"object:{_object_reference(obj)}",
            records=records,
            budget=budget,
            inputs=inputs,
            findings=findings,
        )


def _discover_associated_files(
    container,
    *,
    location,
    records,
    budget,
    inputs,
    findings,
) -> None:
    """Discover a direct `/AF` array on a catalog, page, or annotation."""
    if not isinstance(container, (pikepdf.Dictionary, pikepdf.Stream)):
        return
    associated = container.get("/AF")
    if not isinstance(associated, pikepdf.Array):
        return
    for position, spec in enumerate(associated):
        if not isinstance(spec, pikepdf.Dictionary):
            continue
        _add_file_spec(
            spec,
            original_name=_file_spec_name(spec),
            discovery_kind="associated_file",
            location=f"{location}/AF[{position}]",
            records=records,
            budget=budget,
            inputs=inputs,
            findings=findings,
        )


def _discover_page_annotations(
    page,
    *,
    page_number,
    records,
    budget,
    inputs,
    findings,
) -> None:
    """Discover file-bearing annotations without activating their actions."""
    annotations = page.get("/Annots")
    if not isinstance(annotations, pikepdf.Array):
        return
    for position, annotation in enumerate(annotations):
        if not isinstance(annotation, pikepdf.Dictionary):
            continue
        location = f"page:{page_number}/Annots[{position}]"
        _discover_associated_files(
            annotation,
            location=location,
            records=records,
            budget=budget,
            inputs=inputs,
            findings=findings,
        )
        subtype = _pdf_name(annotation.get("/Subtype"))
        file_spec = annotation.get("/FS")
        if subtype == "FileAttachment" and isinstance(
            file_spec,
            pikepdf.Dictionary,
        ):
            _add_file_spec(
                file_spec,
                original_name=_file_spec_name(file_spec),
                discovery_kind="file_attachment_annotation",
                location=location,
                records=records,
                budget=budget,
                inputs=inputs,
                findings=findings,
            )


def _add_file_spec(
    spec,
    *,
    original_name,
    discovery_kind,
    location,
    records,
    budget,
    inputs,
    findings,
    rich_media_asset_name="",
) -> None:
    """Extract one file specification under byte budgets and merge by SHA-256."""
    budget.member_references += 1
    if budget.member_references > inputs.limits.max_member_references:
        if not any(message.code == "pdf.limit.member_references" for message in findings):
            findings.append(
                _message(
                    Severity.ERROR,
                    "pdf.limit.member_references",
                    "The PDF exceeds the configured package-member limit.",
                )
            )
        return
    embedded = spec.get("/EF") if isinstance(spec, pikepdf.Dictionary) else None
    if not isinstance(embedded, pikepdf.Dictionary):
        return
    stream = embedded.get("/UF") or embedded.get("/F")
    if stream is None or not hasattr(stream, "read_bytes"):
        return
    filter_count = _stream_filter_count(stream)
    if filter_count > PDF_MAX_STREAM_FILTERS:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.stream_filters",
                "An embedded member declares an excessive stream-filter chain.",
            )
        )
        return
    encoded_size = len(stream.read_raw_bytes())
    data = stream.read_bytes()
    if len(data) > inputs.limits.max_member_bytes:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.member_bytes",
                "An embedded member exceeds the configured decoded-byte limit.",
            )
        )
        return
    if (
        len(data) >= PDF_DECODE_RATIO_MIN_BYTES
        and len(data) > max(1, encoded_size) * PDF_MAX_DECODE_RATIO
    ):
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.decode_ratio",
                "An embedded member exceeds the decoded-to-encoded ratio limit.",
            )
        )
        return
    budget.total_decoded_bytes += len(data)
    digest = hashlib.sha256(data).hexdigest()
    if budget.total_decoded_bytes > inputs.limits.max_total_member_bytes:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.total_member_bytes",
                "Embedded members exceed the configured total decoded-byte limit.",
            )
        )
        return

    record = records.setdefault(digest, _MemberRecord(data=data, sha256=digest))
    record.discovery_kinds.add(discovery_kind)
    record.discovery_locations.add(location)
    reference = _object_reference(spec)
    if reference:
        record.object_references.add(reference)
    if original_name or "/UF" in spec or "/F" in spec:
        normalized_name = str(original_name)
        record.original_names.add(normalized_name)
        record.risk_flags.update(_filename_risks(normalized_name))
    description = _pdf_text(spec.get("/Desc"))
    if description:
        record.descriptions.add(description)
    relationship = _pdf_name(spec.get("/AFRelationship"))
    if relationship:
        record.af_relationships.add(relationship)
    if rich_media_asset_name:
        record.rich_media_asset_names.add(str(rich_media_asset_name))
    declared_media_type = _stream_media_type(stream)
    if declared_media_type:
        record.declared_media_types.add(declared_media_type)
    record.encoded_size_bytes = encoded_size
    detected, root_qname = _detect_member_type(data)
    record.detected_media_type = detected
    record.xml_root_qname = root_qname
    if (
        declared_media_type
        and detected
        and not _media_types_equivalent(
            declared_media_type,
            detected,
        )
    ):
        record.risk_flags.add("declared_type_mismatch")


def _apply_selectors(records, *, inputs, findings) -> dict[str, bytes]:
    """Apply exact singleton selectors and preflight their carrier syntax."""
    selected: dict[str, bytes] = {}
    selector_specs = (
        ("selected_xml", inputs.selected_xml, "application/xml"),
        ("selected_json", inputs.selected_json, "application/json"),
        ("selected_step_p21", inputs.selected_step_p21, "model/step"),
    )
    for output_key, selector, expected_media_type in selector_specs:
        if selector is None:
            continue
        matches = [record for record in records.values() if _selector_matches(record, selector)]
        if not matches:
            findings.append(
                _message(
                    Severity.ERROR if selector.required else Severity.INFO,
                    "pdf.selector.not_found",
                    f"No embedded member matched the {output_key} selector.",
                )
            )
            continue
        if len(matches) > 1:
            findings.append(
                _message(
                    Severity.ERROR,
                    "pdf.selector.ambiguous",
                    f"More than one embedded member matched the {output_key} selector.",
                )
            )
            continue
        record = matches[0]
        if "declared_type_mismatch" in record.risk_flags:
            findings.append(
                _message(
                    Severity.ERROR,
                    "pdf.selector.type_mismatch",
                    "The selected member's declared and detected types conflict.",
                )
            )
            continue
        try:
            _preflight_payload(record.data, expected_media_type)
        except ValueError:
            findings.append(
                _message(
                    Severity.ERROR,
                    "pdf.selector.preflight_failed",
                    f"The selected {output_key} member failed carrier preflight.",
                )
            )
            continue
        record.selected_output_key = output_key
        selected[output_key] = record.data
    return selected


def _selector_matches(record: _MemberRecord, selector: PdfPayloadSelector) -> bool:
    """Return whether every configured exact field matches one record."""
    if selector.discovery_kinds and not set(selector.discovery_kinds).issubset(
        record.discovery_kinds
    ):
        return False
    if selector.original_filename and selector.original_filename not in (record.original_names):
        return False
    if selector.declared_media_type and selector.declared_media_type not in (
        record.declared_media_types
    ):
        return False
    if selector.detected_media_type and selector.detected_media_type != record.detected_media_type:
        return False
    if selector.af_relationship and selector.af_relationship not in (record.af_relationships):
        return False
    if selector.rich_media_asset_name and selector.rich_media_asset_name not in (
        record.rich_media_asset_names
    ):
        return False
    return not (selector.xml_root_qname and selector.xml_root_qname != record.xml_root_qname)


def _preflight_payload(data: bytes, media_type: str) -> None:
    """Check carrier syntax without claiming domain or schema conformance."""
    if media_type == "application/xml":
        SafeElementTree.fromstring(data)
        return
    if media_type == "application/json":
        json.loads(data, object_pairs_hook=_reject_duplicate_json_keys)
        return
    if media_type == "model/step":
        text = data.decode("ascii", errors="strict").strip()
        if not (
            text.startswith("ISO-10303-21;")
            and text.endswith("END-ISO-10303-21;")
            and re.search(r"FILE_SCHEMA\s*\(\s*\([^)]*\)\s*\)\s*;", text, re.I)
        ):
            raise ValueError("Invalid STEP Part 21 exchange-file envelope.")
        return
    raise ValueError("Unsupported typed payload preflight.")


def _reject_duplicate_json_keys(pairs):
    """Build a JSON object while rejecting ambiguous duplicate keys."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key.")
        result[key] = value
    return result


def _public_members(records: dict[str, _MemberRecord]) -> list[PdfMember]:
    """Freeze internal records into deterministic public inventory members."""
    members = []
    for index, record in enumerate(
        sorted(records.values(), key=lambda item: item.sha256),
        start=1,
    ):
        members.append(
            PdfMember(
                member_id=f"member-{index:04d}",
                discovery_kinds=sorted(record.discovery_kinds),
                discovery_locations=sorted(record.discovery_locations),
                object_references=sorted(record.object_references),
                original_names=sorted(record.original_names),
                description="; ".join(sorted(record.descriptions)),
                declared_media_type=(
                    sorted(record.declared_media_types)[0] if record.declared_media_types else ""
                ),
                detected_media_type=record.detected_media_type,
                af_relationships=sorted(record.af_relationships),
                rich_media_asset_names=sorted(record.rich_media_asset_names),
                xml_root_qname=record.xml_root_qname,
                encoded_size_bytes=record.encoded_size_bytes,
                decoded_size_bytes=len(record.data),
                sha256=record.sha256,
                extraction_eligible=True,
                risk_flags=sorted(record.risk_flags),
                selected_output_key=record.selected_output_key,
            )
        )
    return members


def _build_bundle(records: dict[str, _MemberRecord]) -> bytes:
    """Return a deterministic ZIP with hash-based paths and a manifest."""
    manifest = {
        "schema_version": "validibot.pdf_bundle_manifest.v1",
        "members": [
            {
                "sha256": record.sha256,
                "original_names": sorted(record.original_names),
                "path": f"files/{record.sha256}{_safe_extension(record)}",
                "size_bytes": len(record.data),
            }
            for record in sorted(records.values(), key=lambda item: item.sha256)
        ],
    }
    payload = io.BytesIO()
    with zipfile.ZipFile(
        payload,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        _write_deterministic_zip_entry(
            archive,
            "manifest.json",
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n",
        )
        for record in sorted(records.values(), key=lambda item: item.sha256):
            _write_deterministic_zip_entry(
                archive,
                f"files/{record.sha256}{_safe_extension(record)}",
                record.data,
            )
    return payload.getvalue()


def _write_deterministic_zip_entry(archive, name: str, data: bytes) -> None:
    """Write one normalized ZIP member without source timestamps or paths."""
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    info.flag_bits = 0
    archive.writestr(info, data, compresslevel=9)


def _inventory_extensions(root) -> list[dict[str, Any]]:
    """Return bounded catalog extension identities as plain JSON values."""
    extensions = root.get("/Extensions")
    if not isinstance(extensions, pikepdf.Dictionary):
        return []
    result = []
    for developer, value in sorted(extensions.items(), key=lambda item: str(item[0])):
        item = {"developer": _pdf_name(developer)}
        if isinstance(value, pikepdf.Dictionary):
            item.update(
                {
                    "base_version": _pdf_name(value.get("/BaseVersion")),
                    "extension_level": _safe_int(value.get("/ExtensionLevel")),
                    "url": _pdf_text(value.get("/URL")),
                }
            )
        result.append(item)
    return result


def _inventory_requirements(root) -> list[dict[str, Any]]:
    """Return catalog requirement types without interpreting domain payloads."""
    requirements = root.get("/Requirements")
    if not isinstance(requirements, pikepdf.Array):
        return []
    result = []
    for position, requirement in enumerate(requirements):
        if isinstance(requirement, pikepdf.Dictionary):
            result.append(
                {
                    "position": position,
                    "type": _pdf_name(requirement.get("/Type")),
                    "subtype": _pdf_name(requirement.get("/S")),
                }
            )
    return result


def _interactive_features(pdf, root) -> dict[str, Any]:
    """Inventory active feature presence without executing or dereferencing URLs."""
    counts = Counter()
    uri_targets: set[str] = set()
    if root.get("/OpenAction") is not None:
        counts["open_actions"] += 1
    if root.get("/AA") is not None:
        counts["additional_actions"] += 1
    acroform = root.get("/AcroForm")
    if acroform is not None:
        counts["acroforms"] += 1
    if isinstance(acroform, pikepdf.Dictionary) and acroform.get("/XFA") is not None:
        counts["xfa_entries"] += 1
    names = root.get("/Names")
    if isinstance(names, pikepdf.Dictionary) and names.get("/JavaScript") is not None:
        counts["javascript_name_trees"] += 1
    action_names = {
        "JavaScript": "javascript_actions",
        "Launch": "launch_actions",
        "GoToR": "remote_go_to_actions",
        "GoToE": "remote_go_to_actions",
        "SubmitForm": "submit_form_actions",
        "ImportData": "import_data_actions",
        "ResetForm": "reset_form_actions",
    }
    for obj in pdf.objects:
        if not isinstance(obj, pikepdf.Dictionary):
            continue
        subtype = _pdf_name(obj.get("/Subtype"))
        action = _pdf_name(obj.get("/S"))
        if subtype == "RichMedia":
            counts["rich_media_annotations"] += 1
            settings = obj.get("/RichMediaSettings")
            if (
                isinstance(settings, pikepdf.Dictionary)
                and settings.get("/Activation") is not None
            ):
                counts["rich_media_automatic_activation"] += 1
        if subtype == "3D":
            counts["three_d_annotations"] += 1
            if obj.get("/3DD") is not None:
                counts["three_d_streams"] += 1
        if action in action_names:
            counts[action_names[action]] += 1
        if action == "URI":
            counts["uri_actions"] += 1
            uri = _bounded_text(_pdf_text(obj.get("/URI")), 2_048)
            if uri and len(uri_targets) < 1_000:
                uri_targets.add(uri)
        if _pdf_name(obj.get("/Type")) == "Filespec" and _pdf_name(obj.get("/FS")) in {"URL", "F"}:
            counts["external_file_specifications"] += 1
    result: dict[str, Any] = dict(sorted(counts.items()))
    if uri_targets:
        result["uri_action_targets"] = sorted(uri_targets)
    return result


def _inventory_signatures(pdf, *, inputs: PdfInputs) -> list[dict[str, Any]]:
    """Inventory signature dictionary claims without asserting trust or validity."""
    signatures = []
    for obj in pdf.objects:
        if len(signatures) >= inputs.limits.max_findings:
            break
        if not isinstance(obj, pikepdf.Dictionary):
            continue
        if _pdf_name(obj.get("/Type")) != "Sig" and _pdf_name(obj.get("/FT")) != "Sig":
            continue
        byte_range = obj.get("/ByteRange")
        signatures.append(
            {
                "object_reference": _object_reference(obj),
                "subfilter": _pdf_name(obj.get("/SubFilter")),
                "byte_range_item_count": (
                    len(byte_range) if isinstance(byte_range, pikepdf.Array) else 0
                ),
                "claimed_name": _pdf_text(obj.get("/Name")),
            }
        )
    return signatures


def _apply_safe_static_profile(interactive, *, findings) -> None:
    """Turn active/external feature presence into explicit profile failures."""
    if interactive.get("uri_actions"):
        findings.append(
            _message(
                Severity.WARNING,
                "pdf.profile.safe_static.uri_actions",
                "The PDF contains ordinary URI links; targets were inventoried.",
            )
        )
    rejected_features = {
        "open_actions",
        "additional_actions",
        "javascript_name_trees",
        "javascript_actions",
        "launch_actions",
        "remote_go_to_actions",
        "submit_form_actions",
        "import_data_actions",
        "reset_form_actions",
        "external_file_specifications",
        "xfa_entries",
        "rich_media_automatic_activation",
    }
    for feature in sorted(rejected_features):
        count = interactive.get(feature, 0)
        if count:
            findings.append(
                _message(
                    Severity.ERROR,
                    f"pdf.profile.safe_static.{feature}",
                    f"Safe static package policy rejects {feature.replace('_', ' ')}.",
                )
            )


def _apply_package_risk_findings(records, *, findings) -> None:
    """Surface member type conflicts and executable payloads with stable codes."""
    executable_types = {
        "application/x-dosexec",
        "application/x-executable",
        "application/java-archive",
    }
    digests_by_name: dict[str, set[str]] = {}
    for record in records.values():
        for name in record.original_names:
            digests_by_name.setdefault(name, set()).add(record.sha256)
        if len(record.declared_media_types) > 1:
            record.risk_flags.add("conflicting_declared_media_types")
            findings.append(
                _message(
                    Severity.WARNING,
                    "pdf.member.conflicting_declared_types",
                    "One embedded byte sequence has conflicting declared media types.",
                )
            )
        if "declared_type_mismatch" in record.risk_flags:
            findings.append(
                _message(
                    Severity.WARNING,
                    "pdf.member.type_mismatch",
                    "An embedded member's declared and detected types conflict.",
                )
            )
        if record.detected_media_type in executable_types:
            record.risk_flags.add("executable_content")
            findings.append(
                _message(
                    Severity.WARNING,
                    "pdf.member.executable_content",
                    "An embedded member appears to contain executable content.",
                )
            )
    duplicate_names = {name for name, digests in digests_by_name.items() if len(digests) > 1}
    for record in records.values():
        if record.original_names & duplicate_names:
            record.risk_flags.add("duplicate_name")
    if duplicate_names:
        findings.append(
            _message(
                Severity.WARNING,
                "pdf.member.duplicate_name",
                "Different embedded byte sequences share a declared filename.",
            )
        )


def _failure_inventory(
    *,
    source,
    inputs,
    header_version,
    encrypted,
    findings,
) -> PdfInventory:
    """Build the canonical inventory even for intentional domain rejection."""
    return PdfInventory(
        source=source,
        parser=PdfParserInfo(
            engine=PDF_ENGINE_NAME,
            versions={
                "pikepdf": pikepdf.__version__,
                "qpdf": pikepdf.__libqpdf_version__,
            },
            recovery_attempted=False,
        ),
        pdf=PdfDocumentFacts(
            header_version=header_version,
            encrypted=encrypted,
        ),
        profile_results=[{"profile": inputs.profile, "passed": False}],
        limits=inputs.limits.model_dump(mode="json"),
        finding_summary=_finding_summary(findings),
    )


def _encryption_facts(pdf) -> dict[str, Any]:
    """Inventory encryption and permission flags after an empty-password open."""
    if not pdf.is_encrypted:
        return {"encrypted": False}
    permissions = {
        field_name: bool(getattr(pdf.allow, field_name)) for field_name in pdf.allow._fields
    }
    encryption = pdf.encryption
    methods = {
        key: str(getattr(encryption, key))
        for key in ("file_method", "stream_method", "string_method")
    }
    return {
        "encrypted": True,
        "opened_with_empty_password": True,
        "encryption_revision": int(encryption.R),
        "encryption_bits": int(encryption.bits),
        "encryption_methods": methods,
        "permissions": permissions,
    }


def _limit_failure(
    *,
    source,
    inputs,
    header_version,
    code,
    text,
    execution_seconds,
) -> PdfEngineResult:
    """Return one stable domain failure when a structural limit is exceeded."""
    findings = [_message(Severity.ERROR, code, text)]
    inventory = _failure_inventory(
        source=source,
        inputs=inputs,
        header_version=header_version,
        encrypted=False,
        findings=findings,
    )
    inventory_bytes = inventory.model_dump_json(indent=2).encode() + b"\n"
    outputs = PdfOutputs(
        passed=False,
        member_count=0,
        finding_summary=_finding_summary(findings),
        inventory=inventory,
        engine=PDF_ENGINE_NAME,
        execution_seconds=execution_seconds,
    )
    return PdfEngineResult(
        status=ValidationStatus.FAILED_VALIDATION,
        messages=findings,
        outputs=outputs,
        artifact_payloads={"pdf_inventory": inventory_bytes},
    )


def _detect_member_type(data: bytes) -> tuple[str, str]:
    """Return a conservative carrier MIME type and optional XML root QName."""
    prefix = data[:4096].lstrip()
    if prefix.startswith(b"<"):
        try:
            root = SafeElementTree.fromstring(data)
        except Exception:
            return "application/octet-stream", ""
        return "application/xml", str(root.tag)
    if prefix.startswith((b"{", b"[")):
        try:
            json.loads(data, object_pairs_hook=_reject_duplicate_json_keys)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return "application/octet-stream", ""
        return "application/json", ""
    if prefix.startswith(b"%PDF-"):
        return "application/pdf", ""
    if prefix.startswith(b"PK\x03\x04"):
        return "application/zip", ""
    if prefix.startswith(b"ISO-10303-21;"):
        return "model/step", ""
    if prefix.startswith(b"MZ"):
        return "application/x-dosexec", ""
    return "application/octet-stream", ""


def _xmp_inventory(data: bytes) -> dict[str, Any]:
    """Return non-sensitive XMP carrier facts, never the full packet content."""
    if not data:
        return {}
    root = SafeElementTree.fromstring(data)
    namespaces = sorted(
        {
            match.decode("utf-8", errors="replace")
            for match in re.findall(rb'xmlns(?::[A-Za-z_][\w.-]*)?="([^"]+)"', data)
        }
    )
    return {
        "present": True,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "root_qname": str(root.tag),
        "namespaces": namespaces[:1_000],
    }


def _inventory_object_metadata(
    graph: list[_GraphDictionary],
    *,
    document_xmp_sha256: str,
    inputs: PdfInputs,
    findings: list[ValidationMessage],
) -> list[dict[str, Any]]:
    """Inventory safe object-level metadata packets without exposing XML content."""
    packets: dict[str, dict[str, Any]] = {}
    for item in graph:
        stream = item.value.get("/Metadata")
        if stream is None or not hasattr(stream, "read_bytes"):
            continue
        data = stream.read_bytes()
        if len(data) > inputs.limits.max_xmp_bytes:
            findings.append(
                _message(
                    Severity.ERROR,
                    "pdf.limit.object_metadata_bytes",
                    "An object metadata packet exceeds the configured XMP limit.",
                )
            )
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest == document_xmp_sha256:
            continue
        try:
            root = SafeElementTree.fromstring(data)
        except Exception:
            findings.append(
                _message(
                    Severity.ERROR,
                    "pdf.metadata.object_xmp_invalid",
                    "An object metadata packet is not safe, well-formed XML.",
                )
            )
            continue
        packet = packets.setdefault(
            digest,
            {
                "sha256": digest,
                "size_bytes": len(data),
                "root_qname": str(root.tag),
                "object_reference": _object_reference(stream),
                "locations": [],
            },
        )
        packet["locations"].append(item.location)
    return [
        {
            **packet,
            "locations": sorted(set(packet["locations"])),
        }
        for packet in sorted(packets.values(), key=lambda value: value["sha256"])
    ]


def _inventory_declarations(data: bytes) -> list[dict[str, str]]:
    """Inventory PDF Declaration namespace properties as bounded claims."""
    if not data:
        return []
    root = SafeElementTree.fromstring(data)
    declarations = []
    for element in root.iter():
        qname = str(element.tag)
        namespace = qname[1:].partition("}")[0] if qname.startswith("{") else ""
        if "declaration" not in namespace.casefold():
            continue
        declarations.append(
            {
                "qname": _bounded_text(qname, 1_024),
                "value": _bounded_text(element.text or "", 2_000).strip(),
            }
        )
    return declarations[:1_000]


def _enforce_finding_limit(
    findings: list[ValidationMessage],
    max_findings: int,
) -> None:
    """Bound authored findings and fail closed when diagnostic output exhausts."""
    if len(findings) <= max_findings:
        return
    del findings[max(0, max_findings - 1) :]
    findings.append(
        _message(
            Severity.ERROR,
            "pdf.limit.findings",
            "The PDF exceeds the configured finding-output limit.",
        )
    )


def _filename_risks(name: str) -> set[str]:
    """Flag dangerous embedded names while retaining them only as quoted data."""
    risks = set()
    if not name:
        risks.add("filename_empty")
    path_segments = re.split(r"[/\\]", name)
    if name in {".", ".."} or any(segment in {".", ".."} for segment in path_segments):
        risks.add("filename_dot_segment")
    if "/" in name or "\\" in name:
        risks.add("filename_path_hazard")
    if name.startswith(("/", "\\")):
        risks.add("filename_absolute_path")
    if re.match(r"^[A-Za-z]:", name):
        risks.add("filename_drive_prefix")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        risks.add("filename_control_character")
    if any(char in name for char in "\u202a\u202b\u202d\u202e\u2066\u2067\u2068\u2069"):
        risks.add("filename_bidi_control")
    if any(ord(char) > 127 for char in name):
        risks.add("filename_unicode")
    return risks


def _stream_filter_count(stream) -> int:
    """Return the declared filter-chain length without decoding the stream."""
    filters = stream.get("/Filter")
    if filters is None:
        return 0
    if isinstance(filters, pikepdf.Array):
        return len(filters)
    return 1


def _stream_media_type(stream) -> str:
    """Decode an EmbeddedFile stream `/Subtype` name as a MIME type."""
    subtype = str(stream.get("/Subtype") or "")
    if subtype.startswith("/"):
        subtype = subtype[1:]
    return subtype.replace("#2F", "/").replace("#2f", "/")


def _file_spec_name(spec) -> str:
    """Return the Unicode or legacy file-specification name as evidence."""
    return _pdf_text(spec.get("/UF")) or _pdf_text(spec.get("/F"))


def _object_reference(obj) -> str:
    """Return a diagnostic indirect-object reference when one exists."""
    try:
        number, generation = obj.objgen
    except (AttributeError, ValueError):
        return ""
    return f"{number} {generation} R" if number else ""


def _pdf_name(value) -> str:
    """Normalize a PDF Name to its bare value without coercing containers."""
    if value is None:
        return ""
    text = str(value)
    return text[1:] if text.startswith("/") else text


def _pdf_text(value) -> str:
    """Return bounded text from a scalar PDF string/name."""
    if value is None or isinstance(value, (pikepdf.Dictionary, pikepdf.Array)):
        return ""
    return _bounded_text(value, 2_000)


def _bounded_text(value, limit: int) -> str:
    """Bound untrusted diagnostic text and replace embedded NULs."""
    return str(value).replace("\x00", "�")[:limit]


def _safe_int(value) -> int | None:
    """Convert a scalar PDF number without trusting it as an allocation bound."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return None


def _media_types_equivalent(declared: str, detected: str) -> bool:
    """Treat the conventional XML aliases as equivalent carrier declarations."""
    if declared == "application/octet-stream":
        return True
    if declared == detected:
        return True
    return {declared, detected} <= {"application/xml", "text/xml"}


def _safe_extension(record: _MemberRecord) -> str:
    """Choose an engine-owned extension from detected type, never source name."""
    return {
        "application/xml": ".xml",
        "application/json": ".json",
        "application/pdf": ".pdf",
        "application/zip": ".zip",
        "model/step": ".p21",
    }.get(record.detected_media_type, ".bin")


def _header_version(data: bytes) -> str:
    """Read only the bounded PDF header version for rejected-file inventory."""
    match = re.match(rb"%PDF-(\d\.\d)", data[:16])
    return match.group(1).decode("ascii") if match else ""


def _finding_summary(messages: list[ValidationMessage]) -> dict[str, int]:
    """Count findings by stable severity name."""
    counts = Counter(message.severity.value for message in messages)
    return dict(sorted(counts.items()))


def _message(severity: Severity, code: str, text: str) -> ValidationMessage:
    """Build one generic stable finding without untrusted content snippets."""
    return ValidationMessage(severity=severity, code=code, text=text)
