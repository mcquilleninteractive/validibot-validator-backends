"""Bounded, non-rendering static-text PDF package inspection engine.

The engine uses qpdf through pikepdf with recovery disabled. It walks the
reachable object graph with explicit depth and reference budgets so prohibited
features cannot hide outside the few package routes the product supports. It
decodes only document XMP and file streams reached through EmbeddedFiles,
catalog/page/annotation Associated Files, or FileAttachment annotations. A
decoded member is eligible only when it is safe, bounded XML, JSON, or STEP
Part 21 text. It never renders pages, runs an action or script, follows a URI,
rewrites the source PDF, or uses an embedded name as a path.

PDF streams can expand while qpdf decodes their filter chains. The container's
memory limit remains the final native-code boundary; this module adds earlier
structural, encoded-byte, decoded-byte, filter-count, and expansion-ratio
guards so ordinary hostile inputs fail as domain results well before that
boundary wherever qpdf can expose the necessary facts.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pikepdf
from defusedxml import ElementTree as SafeElementTree

from validator_backends.pdf.stream_decoder import (
    BoundedPdfStreamDecoder,
    StreamDecodeByteLimitExceeded,
    StreamDecodeError,
    StreamDecodeResourceLimitExceeded,
    StreamDecodeTimeout,
)
from validibot_shared.pdf import (
    PDF_STATIC_TEXT_PROFILE,
    PdfCollection,
    PdfDeclaration,
    PdfDocumentFacts,
    PdfExtension,
    PdfInputs,
    PdfInventory,
    PdfInventorySource,
    PdfLogicalStructureFacts,
    PdfMember,
    PdfOutputs,
    PdfParserInfo,
    PdfPayloadSelector,
    PdfRequirement,
    PdfRichMediaAnnotation,
    PdfThreeDAnnotation,
)
from validibot_shared.validations.envelopes import (
    Severity,
    ValidationMessage,
    ValidationStatus,
)


PDF_ENGINE_NAME = "qpdf/pikepdf"
PDF_HARD_MAX_INPUT_BYTES = 262_144_000
PDF_DECODE_RATIO_MIN_BYTES = 4_096
PDF_MAX_NAME_TREE_DEPTH = 64
PDF_MAX_DISCOVERY_PATH_CHARS = 2_000
PDF_STREAM_CHUNK_SIZE = 1024 * 1024
PDF_ALLOWED_MEMBER_MEDIA_TYPES = {
    "application/json",
    "application/xml",
    "model/step",
}
PDF_REJECTED_XML_ROOTS = {
    "{http://www.w3.org/1999/XSL/Transform}stylesheet",
    "{http://www.w3.org/1999/XSL/Transform}transform",
    "{http://www.w3.org/2000/svg}svg",
    "{http://www.w3.org/1999/xhtml}html",
}
PDF_XMPMETA_QNAME = "{adobe:ns:meta/}xmpmeta"
PDF_RDF_QNAME = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}RDF"
PDF_REJECTED_FILENAME_SUFFIXES = {
    ".bat",
    ".cmd",
    ".com",
    ".exe",
    ".hta",
    ".htm",
    ".html",
    ".jar",
    ".js",
    ".mjs",
    ".ps1",
    ".sh",
    ".svg",
    ".xhtml",
    ".xsl",
    ".xslt",
}
PDF_REJECTED_FILENAME_RISKS = {
    "filename_absolute_path",
    "filename_bidi_control",
    "filename_control_character",
    "filename_dot_segment",
    "filename_drive_prefix",
    "filename_empty",
    "filename_path_hazard",
}


@dataclass(slots=True)
class _InspectionBudget:
    """Mutable counters for work that is not represented by unique members."""

    member_references: int = 0
    total_decoded_bytes: int = 0


@dataclass(frozen=True, slots=True)
class StagedArtifact:
    """One bounded artifact staged in the attempt workspace.

    The path remains valid only while the caller-owned attempt workspace is
    alive. ``size_bytes`` and ``sha256`` are computed while the artifact is
    staged and are verified again by the upload path before publication.
    Keeping this as a file identity, rather than a ``bytes`` payload, prevents
    large selected members and ZIP bundles from being duplicated in memory.
    """

    path: Path
    size_bytes: int
    sha256: str

    @classmethod
    def from_path(cls, path: Path) -> StagedArtifact:
        """Hash a completed staged file and return its immutable local identity."""
        size_bytes, sha256 = _file_identity(path)
        return cls(path=path, size_bytes=size_bytes, sha256=sha256)

    def read_bytes(self) -> bytes:
        """Read a small artifact for focused tests or carrier parsing."""
        return self.path.read_bytes()


class _BoundedOutput:
    """Seekable file wrapper that rejects writes beyond one output-byte budget."""

    def __init__(self, path: Path, max_bytes: int):
        self._file = path.open("w+b")
        self._max_bytes = max_bytes
        self._high_water = 0

    def __enter__(self) -> _BoundedOutput:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._file.close()

    def write(self, data: bytes) -> int:
        """Write bytes unless doing so would exceed the configured high-water mark."""
        end = self._file.tell() + len(data)
        if max(self._high_water, end) > self._max_bytes:
            raise _OutputLimitExceeded
        written = self._file.write(data)
        self._high_water = max(self._high_water, self._file.tell())
        return written

    def tell(self) -> int:
        """Return the current underlying file offset for ``zipfile``."""
        return self._file.tell()

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Move the underlying file offset for ZIP header finalization."""
        return self._file.seek(offset, whence)

    def flush(self) -> None:
        """Flush staged bytes before they are hashed or uploaded."""
        self._file.flush()

    def writable(self) -> bool:
        """Tell ``zipfile`` that the bounded wrapper accepts writes."""
        return True

    def seekable(self) -> bool:
        """Tell ``zipfile`` that local-header rewrites are supported."""
        return True


class _OutputLimitExceeded(ValueError):
    """Raised internally when a staged ZIP crosses its byte budget."""


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
        path: Attempt-local staged decoded bytes. Embedded names never influence
            this path; the SHA-256 digest is the leaf name.
        decoded_size_bytes: Observed decoded size of ``path``.
        sha256: Digest of the staged bytes; the merge key for this record.
        discovery_kinds: Supported route by which the payload was reached —
            ``embedded_files_name_tree``, ``associated_file``, or
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
        encoded_size_bytes: The stream's declared ``/Length`` — the size *before*
            decompression, and a document's claim rather than an observation.
            Compare against ``decoded_size_bytes`` to reason about compression
            ratio without loading the staged payload into Python memory.
        detected_media_type: The single sniffed type (see above).
        xml_root_qname: Root element qualified name when the payload parses as
            XML. This is what identifies an attachment as a particular business
            document without trusting its filename or declared type.
        extraction_eligible: Whether the bytes satisfy the fixed static-text
            carrier policy. Ineligible bytes are evidence only and can never
            enter a bundle or selected output.
        refusal_reason: Stable reason an otherwise discovered member is not
            extraction eligible.
        risk_flags: Accumulated filename and type-identity hazards.
        selected_output_key: Set when a member matches an author's selector and
            is therefore promoted to a named output. Empty for members that were
            merely catalogued.
    """

    path: Path
    decoded_size_bytes: int
    sha256: str
    discovery_kinds: set[str] = field(default_factory=set)
    discovery_locations: set[str] = field(default_factory=set)
    object_references: set[str] = field(default_factory=set)
    original_names: set[str] = field(default_factory=set)
    descriptions: set[str] = field(default_factory=set)
    declared_media_types: set[str] = field(default_factory=set)
    af_relationships: set[str] = field(default_factory=set)
    encoded_size_bytes: int | None = None
    detected_media_type: str = ""
    xml_root_qname: str = ""
    step_file_schema: list[str] = field(default_factory=list)
    extraction_eligible: bool = True
    refusal_reason: str = ""
    risk_flags: set[str] = field(default_factory=set)
    selected_output_key: str = ""


@dataclass(frozen=True, slots=True)
class PdfEngineResult:
    """Complete domain result plus staged artifacts for the entrypoint.

    The engine decides *which* embedded members become outputs and stages those
    bytes in the caller-owned attempt workspace. It does not upload them. That
    leaves storage I/O in the entrypoint while avoiding a second in-memory copy
    of potentially large inventory, bundle, and selected-member outputs.

    Fields:
        status: Overall validation status for the run.
        messages: Findings surfaced to the author.
        outputs: The typed PDF output envelope, including member metadata.
        artifact_payloads: Output key to staged artifact identity, for members
            the author's selectors promoted to artifacts. Keys match the
            ``selected_output_key`` values recorded on the corresponding members.
    """

    status: ValidationStatus
    messages: list[ValidationMessage]
    outputs: PdfOutputs
    artifact_payloads: dict[str, StagedArtifact]


def inspect_pdf(
    path: Path,
    *,
    source_name: str,
    inputs: PdfInputs,
    workspace: Path,
) -> PdfEngineResult:
    """Inspect one PDF without recovery, rendering, execution, or rewriting."""
    started = time.monotonic()
    workspace.mkdir(parents=True, exist_ok=True)
    members_dir = workspace / "members"
    members_dir.mkdir()
    artifacts_dir = workspace / "artifacts"
    artifacts_dir.mkdir()
    source_size, source_sha256, header_version, incremental_markers = _source_facts(
        path,
        PDF_HARD_MAX_INPUT_BYTES,
    )
    source = PdfInventorySource(
        name=Path(source_name).name or "document.pdf",
        size_bytes=source_size,
        sha256=source_sha256,
    )
    findings: list[ValidationMessage] = []
    records: dict[str, _MemberRecord] = {}
    budget = _InspectionBudget()
    xmp_path: Path | None = None
    bundle_path: Path | None = None

    if source_size > inputs.limits.max_input_bytes:
        return _limit_failure(
            source=source,
            inputs=inputs,
            header_version=header_version,
            code="pdf.limit.input_bytes",
            text="The PDF exceeds the configured input-byte limit.",
            execution_seconds=time.monotonic() - started,
            inventory_path=artifacts_dir / "pdf-inventory.json",
        )

    try:
        with pikepdf.Pdf.open(
            path,
            password="",
            suppress_warnings=False,
            attempt_recovery=False,
        ) as pdf:
            if pdf.is_encrypted:
                return _encrypted_pdf_failure(
                    pdf=pdf,
                    source=source,
                    inputs=inputs,
                    header_version=header_version,
                    execution_seconds=time.monotonic() - started,
                    inventory_path=artifacts_dir / "pdf-inventory.json",
                )
            stream_decoder = BoundedPdfStreamDecoder(
                source_path=path,
                source_size_bytes=source_size,
                workspace=workspace / "decoded-stream-cache",
                started=started,
                max_execution_seconds=inputs.limits.max_execution_seconds,
            )
            if len(pdf.pages) > inputs.limits.max_pages:
                return _limit_failure(
                    source=source,
                    inputs=inputs,
                    header_version=header_version,
                    code="pdf.limit.pages",
                    text="The PDF exceeds the configured page limit.",
                    execution_seconds=time.monotonic() - started,
                    inventory_path=artifacts_dir / "pdf-inventory.json",
                )
            if len(pdf.objects) > inputs.limits.max_objects:
                return _limit_failure(
                    source=source,
                    inputs=inputs,
                    header_version=header_version,
                    code="pdf.limit.objects",
                    text="The PDF exceeds the configured object limit.",
                    execution_seconds=time.monotonic() - started,
                    inventory_path=artifacts_dir / "pdf-inventory.json",
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
            _check_deadline(started, inputs.limits.max_execution_seconds)
            xmp_path = _document_xmp(
                root,
                destination=artifacts_dir / "xmp.xml",
                stream_decoder=stream_decoder,
                inputs=inputs,
                findings=findings,
            )
            graph = _walk_reachable_dictionaries(
                root,
                max_depth=inputs.limits.max_object_depth,
                findings=findings,
            )
            _check_deadline(started, inputs.limits.max_execution_seconds)
            extensions = _inventory_extensions(root)
            requirements = _inventory_requirements(root)
            collections = _inventory_collections(root)
            rich_media = _inventory_rich_media(graph)
            three_d = _inventory_three_d(graph)
            logical_structure = _inventory_logical_structure(root, graph)
            interactive = _interactive_features(
                pdf,
                root,
                inputs=inputs,
                findings=findings,
            )
            _check_deadline(started, inputs.limits.max_execution_seconds)

            supported_file_specs: set[tuple[Any, ...]] = set()
            supported_af_containers: set[tuple[Any, ...]] = set()
            _discover_name_tree_attachments(
                pdf,
                stream_decoder=stream_decoder,
                records=records,
                budget=budget,
                inputs=inputs,
                findings=findings,
                members_dir=members_dir,
                supported_file_specs=supported_file_specs,
            )
            _discover_associated_files(
                root,
                location="catalog",
                stream_decoder=stream_decoder,
                records=records,
                budget=budget,
                inputs=inputs,
                findings=findings,
                members_dir=members_dir,
                supported_file_specs=supported_file_specs,
                supported_af_containers=supported_af_containers,
            )
            _check_deadline(started, inputs.limits.max_execution_seconds)
            for page_number, page in enumerate(pdf.pages, start=1):
                _discover_associated_files(
                    page.obj,
                    location=f"page:{page_number}",
                    stream_decoder=stream_decoder,
                    records=records,
                    budget=budget,
                    inputs=inputs,
                    findings=findings,
                    members_dir=members_dir,
                    supported_file_specs=supported_file_specs,
                    supported_af_containers=supported_af_containers,
                )
                _discover_page_annotations(
                    page.obj,
                    page_number=page_number,
                    stream_decoder=stream_decoder,
                    records=records,
                    budget=budget,
                    inputs=inputs,
                    findings=findings,
                    members_dir=members_dir,
                    supported_file_specs=supported_file_specs,
                    supported_af_containers=supported_af_containers,
                )
                _check_deadline(started, inputs.limits.max_execution_seconds)

            _reject_unsupported_package_routes(
                graph,
                supported_file_specs=supported_file_specs,
                supported_af_containers=supported_af_containers,
                findings=findings,
            )
            _apply_static_text_member_policy(records, findings=findings)
            _apply_static_text_profile(
                interactive,
                collection_count=len(collections),
                findings=findings,
            )

            selected: dict[str, StagedArtifact] = {}
            if not _has_errors(findings):
                selected = _apply_selectors(
                    records,
                    inputs=inputs,
                    findings=findings,
                )
            if _has_errors(findings):
                _clear_selected_outputs(records)
                selected = {}
            _check_deadline(started, inputs.limits.max_execution_seconds)
            eligible_records = {
                digest: record for digest, record in records.items() if record.extraction_eligible
            }
            if (
                inputs.emit_extracted_files_bundle
                and eligible_records
                and not _has_errors(findings)
            ):
                candidate_bundle_path = artifacts_dir / "extracted-files.zip"
                try:
                    _build_bundle(
                        eligible_records,
                        destination=candidate_bundle_path,
                        max_bytes=inputs.limits.max_output_bundle_bytes,
                    )
                except _OutputLimitExceeded:
                    candidate_bundle_path.unlink(missing_ok=True)
                    findings.append(
                        _message(
                            Severity.ERROR,
                            "pdf.limit.output_bundle_bytes",
                            "The deterministic extraction bundle exceeds the "
                            "configured output-bundle budget.",
                        )
                    )
                else:
                    bundle_path = candidate_bundle_path
            metadata = _xmp_inventory(xmp_path)
            metadata["incremental_revision_markers"] = incremental_markers
            _check_deadline(started, inputs.limits.max_execution_seconds)
            _enforce_finding_limit(findings, inputs.limits.max_findings)
            if _has_errors(findings):
                _clear_selected_outputs(records)
                selected = {}
                bundle_path = None
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
                declarations=_inventory_declarations(xmp_path),
                collections=collections,
                rich_media=rich_media,
                three_d=three_d,
                logical_structure=logical_structure,
                metadata=metadata,
                interactive_features=interactive,
                members=members,
                profile_results=[
                    {
                        "profile": PDF_STATIC_TEXT_PROFILE,
                        "passed": passed,
                    }
                ],
                limits=inputs.limits.model_dump(mode="json"),
                finding_summary=finding_summary,
            )
    except TimeoutError:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.execution_seconds",
                "PDF inspection exceeded the configured execution-time limit.",
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
        xmp_path = None
        bundle_path = None
    except pikepdf.PasswordError:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.policy.static_text.encryption",
                "Static text package policy rejects encrypted PDFs.",
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
        xmp_path = None
        bundle_path = None
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
        xmp_path = None
        bundle_path = None

    inventory_path = artifacts_dir / "pdf-inventory.json"
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
        xmp_path = None
        bundle_path = None
        records = {}
        inventory_bytes = (
            inventory.model_dump_json(indent=2, exclude_none=True).encode("utf-8") + b"\n"
        )
    inventory_path.write_bytes(inventory_bytes)
    artifact_payloads = {
        "pdf_inventory": StagedArtifact.from_path(inventory_path),
        **selected,
    }
    publish_supplementary_artifacts = not _has_errors(findings)
    if xmp_path is not None and publish_supplementary_artifacts:
        artifact_payloads["xmp_metadata"] = StagedArtifact.from_path(xmp_path)
    if bundle_path is not None and publish_supplementary_artifacts:
        artifact_payloads["extracted_files_bundle"] = StagedArtifact.from_path(bundle_path)

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


def _source_facts(path: Path, max_bytes: int) -> tuple[int, str, str, int]:
    """Hash the source and count revision markers without retaining PDF bytes."""
    digest = hashlib.sha256()
    size_bytes = 0
    marker_count = 0
    overlap = b""
    header = b""
    with path.open("rb") as source:
        while chunk := source.read(PDF_STREAM_CHUNK_SIZE):
            size_bytes += len(chunk)
            if size_bytes > max_bytes:
                raise ValueError("The PDF exceeds the backend hard input-byte limit.")
            digest.update(chunk)
            if not header:
                header = chunk[:16]
            scanned = overlap + chunk
            marker_count += scanned.count(b"startxref")
            overlap = scanned[-8:]
    return (
        size_bytes,
        digest.hexdigest(),
        _header_version(header),
        max(0, marker_count - 1),
    )


def _file_identity(path: Path) -> tuple[int, str]:
    """Return a staged file's size and SHA-256 through a bounded-memory read."""
    digest = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as source:
        while chunk := source.read(PDF_STREAM_CHUNK_SIZE):
            size_bytes += len(chunk)
            digest.update(chunk)
    return size_bytes, digest.hexdigest()


def _check_deadline(started: float, max_seconds: int) -> None:
    """Raise a runtime timeout before starting more PDF-domain work."""
    if time.monotonic() - started > max_seconds:
        raise TimeoutError("PDF inspection exceeded its execution budget.")


def _document_xmp(
    root,
    *,
    destination: Path,
    stream_decoder,
    inputs: PdfInputs,
    findings,
) -> Path | None:
    """Stage a safe, bounded document XMP packet when present."""
    metadata = root.get("/Metadata")
    if metadata is None or not hasattr(metadata, "get_stream_buffer"):
        return None
    if (
        _pdf_name(metadata.get("/Type")) != "Metadata"
        or _pdf_name(metadata.get("/Subtype")) != "XML"
    ):
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.policy.static_text.xmp_stream_identity",
                "Document XMP must be an explicit Metadata/XML stream.",
            )
        )
        return None
    if not _uses_static_text_stream_filter(metadata):
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.policy.static_text.xmp_stream_filter",
                "Document XMP uses a stream filter outside the static-text policy.",
            )
        )
        return None
    try:
        decoded = stream_decoder.decode(
            metadata,
            max_decoded_bytes=inputs.limits.max_xmp_bytes,
        )
    except StreamDecodeByteLimitExceeded:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.xmp_bytes",
                "The document XMP packet exceeds the configured limit.",
            )
        )
        return None
    except StreamDecodeResourceLimitExceeded:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.stream_decode_resources",
                "Document XMP exceeded the isolated decoder's resource limit.",
            )
        )
        return None
    except StreamDecodeTimeout as exc:
        raise TimeoutError("The isolated PDF stream decoder timed out.") from exc
    except StreamDecodeError:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.metadata.xmp_decode_failed",
                "Document XMP could not be decoded safely.",
            )
        )
        return None
    stream_decoder.copy(decoded, destination)
    try:
        root_element = SafeElementTree.parse(destination).getroot()
    except Exception:
        destination.unlink(missing_ok=True)
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.metadata.xmp_invalid",
                "Document XMP is not safe, well-formed XML.",
            )
        )
        return None
    if root_element.tag not in {PDF_XMPMETA_QNAME, PDF_RDF_QNAME} or (
        root_element.tag != PDF_RDF_QNAME and root_element.find(f".//{PDF_RDF_QNAME}") is None
    ):
        destination.unlink(missing_ok=True)
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.policy.static_text.xmp_structure",
                "Document metadata must contain an XMP RDF packet.",
            )
        )
        return None
    return destination


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


def _name_tree_pairs(
    tree,
    *,
    max_pairs: int,
) -> tuple[list[tuple[str, Any]], bool]:
    """Return a bounded stable name-tree prefix and whether it was truncated."""
    result: list[tuple[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    retained_nodes: list[Any] = []
    stack: list[tuple[Any, int]] = [(tree, 0)]
    truncated = False
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
                if len(result) >= max_pairs:
                    truncated = True
                    break
                name = _pdf_text(names[pair_index * 2])
                value = names[pair_index * 2 + 1]
                result.append((name, value))
        if truncated:
            break
        kids = node.get("/Kids")
        if isinstance(kids, pikepdf.Array):
            stack.extend((kid, depth + 1) for kid in reversed(kids))
    return sorted(result, key=lambda pair: pair[0]), truncated


def _discover_name_tree_attachments(
    pdf,
    *,
    stream_decoder,
    records,
    budget,
    inputs,
    findings,
    members_dir,
    supported_file_specs,
) -> None:
    """Discover a bounded catalog EmbeddedFiles name tree without attachments API."""
    names = pdf.Root.get("/Names")
    embedded_files = names.get("/EmbeddedFiles") if isinstance(names, pikepdf.Dictionary) else None
    if not isinstance(embedded_files, pikepdf.Dictionary):
        return
    pairs, truncated = _name_tree_pairs(
        embedded_files,
        max_pairs=inputs.limits.max_member_references,
    )
    if truncated:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.member_references",
                "The EmbeddedFiles name tree exceeds the package-member limit.",
            )
        )
    for logical_name, spec in pairs:
        if not isinstance(spec, pikepdf.Dictionary):
            continue
        _add_file_spec(
            spec,
            original_name=logical_name,
            discovery_kind="embedded_files_name_tree",
            location="catalog/Names/EmbeddedFiles",
            stream_decoder=stream_decoder,
            records=records,
            budget=budget,
            inputs=inputs,
            findings=findings,
            members_dir=members_dir,
            supported_file_specs=supported_file_specs,
        )


def _discover_associated_files(
    container,
    *,
    location,
    stream_decoder,
    records,
    budget,
    inputs,
    findings,
    members_dir,
    supported_file_specs,
    supported_af_containers,
) -> None:
    """Discover a direct `/AF` array on a catalog, page, or annotation."""
    if not isinstance(container, (pikepdf.Dictionary, pikepdf.Stream)):
        return
    associated = container.get("/AF")
    if not isinstance(associated, pikepdf.Array):
        return
    supported_af_containers.add(_graph_object_identity(container))
    for position, spec in enumerate(associated):
        if not isinstance(spec, pikepdf.Dictionary):
            continue
        _add_file_spec(
            spec,
            original_name=_file_spec_name(spec),
            discovery_kind="associated_file",
            location=f"{location}/AF[{position}]",
            stream_decoder=stream_decoder,
            records=records,
            budget=budget,
            inputs=inputs,
            findings=findings,
            members_dir=members_dir,
            supported_file_specs=supported_file_specs,
        )


def _discover_page_annotations(
    page,
    *,
    page_number,
    stream_decoder,
    records,
    budget,
    inputs,
    findings,
    members_dir,
    supported_file_specs,
    supported_af_containers,
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
            stream_decoder=stream_decoder,
            records=records,
            budget=budget,
            inputs=inputs,
            findings=findings,
            members_dir=members_dir,
            supported_file_specs=supported_file_specs,
            supported_af_containers=supported_af_containers,
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
                stream_decoder=stream_decoder,
                records=records,
                budget=budget,
                inputs=inputs,
                findings=findings,
                members_dir=members_dir,
                supported_file_specs=supported_file_specs,
            )


def _add_file_spec(
    spec,
    *,
    original_name,
    discovery_kind,
    location,
    stream_decoder,
    records,
    budget,
    inputs,
    findings,
    members_dir,
    supported_file_specs,
) -> None:
    """Extract one file specification under byte budgets and merge by SHA-256."""
    supported_file_specs.add(_graph_object_identity(spec))
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
    if _pdf_name(spec.get("/Type")) != "Filespec":
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.policy.static_text.file_specification_identity",
                "An allowed attachment route must reference an explicit Filespec.",
            )
        )
        return
    embedded = spec.get("/EF") if isinstance(spec, pikepdf.Dictionary) else None
    if not isinstance(embedded, pikepdf.Dictionary):
        return
    stream = embedded.get("/UF") or embedded.get("/F")
    if stream is None or not hasattr(stream, "get_stream_buffer"):
        return
    if _pdf_name(stream.get("/Type")) != "EmbeddedFile":
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.policy.static_text.member_stream_identity",
                "An attachment member must be an explicit EmbeddedFile stream.",
            )
        )
        return
    if not _uses_static_text_stream_filter(stream):
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.policy.static_text.member_stream_filter",
                "An embedded member uses a stream filter outside the static-text policy.",
            )
        )
        return
    try:
        decoded = stream_decoder.decode(
            stream,
            max_decoded_bytes=inputs.limits.max_member_bytes,
        )
    except StreamDecodeByteLimitExceeded:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.member_bytes",
                "An embedded member exceeds the configured decoded-byte limit.",
            )
        )
        return
    except StreamDecodeResourceLimitExceeded:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.stream_decode_resources",
                "An embedded member exceeded the isolated decoder's resource limit.",
            )
        )
        return
    except StreamDecodeTimeout as exc:
        raise TimeoutError("The isolated PDF stream decoder timed out.") from exc
    except StreamDecodeError:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.member.decode_failed",
                "An embedded member could not be decoded safely.",
            )
        )
        return
    decoded_size = decoded.size_bytes
    encoded_size = decoded.encoded_size_bytes
    if (
        decoded_size >= PDF_DECODE_RATIO_MIN_BYTES
        and decoded_size > max(1, encoded_size) * inputs.limits.max_decode_ratio
    ):
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.decode_ratio",
                "An embedded member exceeds the decoded-to-encoded ratio limit.",
            )
        )
        return
    budget.total_decoded_bytes += decoded_size
    if budget.total_decoded_bytes > inputs.limits.max_total_member_bytes:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.limit.total_member_bytes",
                "Embedded members exceed the configured total decoded-byte limit.",
            )
        )
        return

    candidate = members_dir / f".candidate-{budget.member_references:04d}"
    stream_decoder.copy(decoded, candidate)
    staged_size, digest = _file_identity(candidate)
    if staged_size != decoded_size:
        candidate.unlink(missing_ok=True)
        raise ValueError("qpdf stream size changed while staging an embedded member.")
    record = records.get(digest)
    is_new_record = record is None
    if record is None:
        staged_path = members_dir / digest
        candidate.replace(staged_path)
        record = _MemberRecord(
            path=staged_path,
            decoded_size_bytes=decoded_size,
            sha256=digest,
        )
        records[digest] = record
    else:
        candidate.unlink()
    record.discovery_kinds.add(discovery_kind)
    record.discovery_locations.add(location)
    reference = _object_reference(spec)
    if reference:
        record.object_references.add(reference)
    candidate_names: list[str] = []
    if original_name is not None:
        candidate_names.append(str(original_name))
    for name_key in ("/UF", "/F"):
        if name_key in spec:
            candidate_names.append(_pdf_text(spec.get(name_key)))
    for normalized_name in candidate_names:
        record.original_names.add(normalized_name)
        record.risk_flags.update(_filename_risks(normalized_name))
    description = _pdf_text(spec.get("/Desc"))
    if description:
        record.descriptions.add(description)
    relationship = _pdf_name(spec.get("/AFRelationship"))
    if relationship:
        record.af_relationships.add(relationship)
    declared_media_type = _stream_media_type(stream)
    if declared_media_type:
        record.declared_media_types.add(declared_media_type)
    record.encoded_size_bytes = encoded_size
    if is_new_record:
        detected, root_qname, step_file_schema = _detect_member_type(record.path)
        record.detected_media_type = detected
        record.xml_root_qname = root_qname
        record.step_file_schema = step_file_schema
    if (
        declared_media_type
        and record.detected_media_type
        and not _media_types_equivalent(
            declared_media_type,
            record.detected_media_type,
        )
    ):
        record.risk_flags.add("declared_type_mismatch")


def _apply_selectors(records, *, inputs, findings) -> dict[str, StagedArtifact]:
    """Apply exact singleton selectors and preflight their carrier syntax."""
    selected: dict[str, StagedArtifact] = {}
    selector_specs = (
        ("selected_xml", inputs.selected_xml, "application/xml"),
        ("selected_json", inputs.selected_json, "application/json"),
        ("selected_step_p21", inputs.selected_step_p21, "model/step"),
    )
    for output_key, selector, expected_media_type in selector_specs:
        if selector is None:
            continue
        matches = [
            record
            for record in records.values()
            if record.extraction_eligible and _selector_matches(record, selector)
        ]
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
            step_file_schema = _preflight_payload(record.path, expected_media_type)
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
        if step_file_schema:
            record.step_file_schema = step_file_schema
        selected[output_key] = StagedArtifact(
            path=record.path,
            size_bytes=record.decoded_size_bytes,
            sha256=record.sha256,
        )
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
    if selector.step_file_schema and not set(selector.step_file_schema).issubset(
        record.step_file_schema
    ):
        return False
    return not (selector.xml_root_qname and selector.xml_root_qname != record.xml_root_qname)


def _preflight_payload(path: Path, media_type: str) -> list[str]:
    """Check carrier syntax without claiming domain or schema conformance."""
    if media_type == "application/xml":
        SafeElementTree.parse(path)
        return []
    if media_type == "application/json":
        with path.open(encoding="utf-8") as source:
            json.load(source, object_pairs_hook=_reject_duplicate_json_keys)
        return []
    if media_type == "model/step":
        text = path.read_text(encoding="ascii", errors="strict").strip()
        file_schema = _step_file_schema(text)
        if not (
            text.startswith("ISO-10303-21;") and text.endswith("END-ISO-10303-21;") and file_schema
        ):
            raise ValueError("Invalid STEP Part 21 exchange-file envelope.")
        return file_schema
    raise ValueError("Unsupported typed payload preflight.")


def _step_file_schema(text: str) -> list[str]:
    """Return bounded schema identifiers from a Part 21 FILE_SCHEMA header."""
    match = re.search(
        r"FILE_SCHEMA\s*\(\s*\((.*?)\)\s*\)\s*;",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if match is None:
        return []
    return [
        value.replace("''", "'") for value in re.findall(r"'((?:''|[^'])*)'", match.group(1))[:128]
    ]


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
                xml_root_qname=record.xml_root_qname,
                step_file_schema=record.step_file_schema,
                encoded_size_bytes=record.encoded_size_bytes,
                decoded_size_bytes=record.decoded_size_bytes,
                sha256=record.sha256,
                extraction_eligible=record.extraction_eligible,
                refusal_reason=record.refusal_reason,
                risk_flags=sorted(record.risk_flags),
                selected_output_key=record.selected_output_key,
            )
        )
    return members


def _build_bundle(
    records: dict[str, _MemberRecord],
    *,
    destination: Path,
    max_bytes: int,
) -> None:
    """Stream a deterministic, byte-bounded ZIP to the attempt workspace."""
    manifest = {
        "schema_version": "validibot.pdf_bundle_manifest.v1",
        "members": [
            {
                "sha256": record.sha256,
                "original_names": sorted(record.original_names),
                "path": f"files/{record.sha256}{_safe_extension(record)}",
                "size_bytes": record.decoded_size_bytes,
            }
            for record in sorted(records.values(), key=lambda item: item.sha256)
            if record.extraction_eligible
        ],
    }
    with (
        _BoundedOutput(destination, max_bytes) as output,
        zipfile.ZipFile(
            output,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive,
    ):
        _write_deterministic_zip_entry(
            archive,
            "manifest.json",
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n",
        )
        for record in sorted(records.values(), key=lambda item: item.sha256):
            if not record.extraction_eligible:
                continue
            _write_deterministic_zip_file(
                archive,
                f"files/{record.sha256}{_safe_extension(record)}",
                record.path,
            )


def _write_deterministic_zip_entry(archive, name: str, data: bytes) -> None:
    """Write one normalized ZIP member without source timestamps or paths."""
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    info.flag_bits = 0
    archive.writestr(info, data, compresslevel=9)


def _write_deterministic_zip_file(archive, name: str, source_path: Path) -> None:
    """Stream one staged member into a normalized ZIP entry."""
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    info.flag_bits = 0
    with (
        source_path.open("rb") as source,
        archive.open(
            info,
            mode="w",
            force_zip64=True,
        ) as target,
    ):
        while chunk := source.read(PDF_STREAM_CHUNK_SIZE):
            target.write(chunk)


def _inventory_extensions(root) -> list[PdfExtension]:
    """Return bounded catalog extension identities, including unknown entries."""
    extensions = root.get("/Extensions")
    if not isinstance(extensions, pikepdf.Dictionary):
        return []
    result: list[PdfExtension] = []
    for developer, value in sorted(extensions.items(), key=lambda item: str(item[0])):
        if not isinstance(value, pikepdf.Dictionary):
            value = pikepdf.Dictionary()
        result.append(
            PdfExtension(
                developer=_pdf_name(developer),
                object_reference=_object_reference(value),
                base_version=_pdf_name(value.get("/BaseVersion")),
                extension_level=_safe_int(value.get("/ExtensionLevel")),
                extension_revision=_safe_int(value.get("/ExtensionRevision")),
                url=_bounded_text(_pdf_text(value.get("/URL")), 2_048),
            )
        )
    return result


def _inventory_requirements(root) -> list[PdfRequirement]:
    """Return catalog requirement types without interpreting domain payloads."""
    requirements = root.get("/Requirements")
    if not isinstance(requirements, pikepdf.Array):
        return []
    result: list[PdfRequirement] = []
    for position, requirement in enumerate(requirements):
        if isinstance(requirement, pikepdf.Dictionary):
            result.append(
                PdfRequirement(
                    position=position,
                    object_reference=_object_reference(requirement),
                    type=_pdf_name(requirement.get("/Type")),
                    subtype=_pdf_name(requirement.get("/S")),
                    keys=sorted(_pdf_name(key) for key in requirement)[:128],
                )
            )
    return result


def _inventory_collections(root) -> list[PdfCollection]:
    """Record only enough Collection structure to explain a policy rejection."""
    collection = root.get("/Collection")
    if not isinstance(collection, pikepdf.Dictionary):
        return []
    return [
        PdfCollection(
            object_reference=_object_reference(collection),
            view=_pdf_name(collection.get("/View")),
        )
    ]


def _inventory_rich_media(
    graph: list[_GraphDictionary],
) -> list[PdfRichMediaAnnotation]:
    """Record only enough RichMedia structure to explain a policy rejection."""
    result: list[PdfRichMediaAnnotation] = []
    for item in graph:
        annotation = item.value
        if _pdf_name(annotation.get("/Subtype")) != "RichMedia":
            continue
        result.append(
            PdfRichMediaAnnotation(
                object_reference=_object_reference(annotation),
                locations=[item.location],
            )
        )
    return result


def _inventory_three_d(
    graph: list[_GraphDictionary],
) -> list[PdfThreeDAnnotation]:
    """Record only enough 3D structure to explain a policy rejection."""
    result: list[PdfThreeDAnnotation] = []
    for item in graph:
        annotation = item.value
        if _pdf_name(annotation.get("/Subtype")) != "3D":
            continue
        stream = annotation.get("/3DD")
        stream_subtype = ""
        stream_reference = ""
        if isinstance(stream, pikepdf.Stream):
            stream_subtype = _pdf_name(stream.get("/Subtype"))
            stream_reference = _object_reference(stream)
        result.append(
            PdfThreeDAnnotation(
                object_reference=_object_reference(annotation),
                locations=[item.location],
                stream_object_reference=stream_reference,
                stream_subtype=stream_subtype,
            )
        )
    return result


def _inventory_logical_structure(
    root,
    graph: list[_GraphDictionary],
) -> PdfLogicalStructureFacts:
    """Count tagged, marked-content, object-reference, and optional-content facts."""
    structure_elements = 0
    marked_content_references = 0
    marked_content_ids: set[int] = set()
    object_references = 0
    associated_file_links = 0
    for item in graph:
        value = item.value
        object_type = _pdf_name(value.get("/Type"))
        if object_type == "StructElem":
            structure_elements += 1
        elif object_type == "MCR":
            marked_content_references += 1
        elif object_type == "OBJR":
            object_references += 1
        mcid = _safe_int(value.get("/MCID"))
        if mcid is not None:
            marked_content_ids.add(mcid)
        associated = value.get("/AF")
        if isinstance(associated, pikepdf.Array):
            associated_file_links += len(associated)
    optional_content_groups = 0
    properties = root.get("/OCProperties")
    if isinstance(properties, pikepdf.Dictionary):
        groups = properties.get("/OCGs")
        if isinstance(groups, pikepdf.Array):
            optional_content_groups = len(groups)
    return PdfLogicalStructureFacts(
        tagged=isinstance(root.get("/StructTreeRoot"), pikepdf.Dictionary),
        structure_element_count=structure_elements,
        marked_content_reference_count=marked_content_references,
        marked_content_id_count=len(marked_content_ids),
        object_reference_count=object_references,
        optional_content_group_count=optional_content_groups,
        associated_file_link_count=associated_file_links,
    )


def _interactive_features(
    pdf,
    root,
    *,
    inputs: PdfInputs,
    findings: list[ValidationMessage],
) -> dict[str, Any]:
    """Count prohibited active structures without reading URI or script payloads."""
    counts = Counter()
    action_entries = 0
    if root.get("/OpenAction") is not None:
        counts["open_actions"] += 1
        action_entries += 1
    if root.get("/AA") is not None:
        counts["additional_actions"] += 1
        action_entries += 1
    acroform = root.get("/AcroForm")
    if acroform is not None:
        counts["acroforms"] += 1
        fields = acroform.get("/Fields") if isinstance(acroform, pikepdf.Dictionary) else None
        action_entries += len(fields) if isinstance(fields, pikepdf.Array) else 1
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
        "GoTo": "internal_go_to_actions",
        "Hide": "hide_actions",
        "Movie": "media_actions",
        "Named": "named_actions",
        "Rendition": "media_actions",
        "SetOCGState": "optional_content_actions",
        "Sound": "media_actions",
        "Thread": "thread_actions",
    }
    for obj in pdf.objects:
        if not isinstance(obj, pikepdf.Dictionary):
            continue
        subtype = _pdf_name(obj.get("/Subtype"))
        action = _pdf_name(obj.get("/S"))
        if obj is not root and obj.get("/AA") is not None:
            counts["additional_actions"] += 1
            action_entries += 1
        if subtype == "RichMedia":
            counts["rich_media_annotations"] += 1
            action_entries += 1
        if subtype == "3D":
            counts["three_d_annotations"] += 1
            if obj.get("/3DD") is not None:
                counts["three_d_streams"] += 1
        if subtype == "Widget":
            counts["widget_annotations"] += 1
        if subtype in {"Movie", "Screen", "Sound"}:
            counts["media_annotations"] += 1
        if action in action_names:
            counts[action_names[action]] += 1
            action_entries += 1
        elif _pdf_name(obj.get("/Type")) == "Action" and action != "URI":
            counts["unknown_actions"] += 1
            action_entries += 1
        if _pdf_name(obj.get("/Type")) == "Filespec" and not isinstance(
            obj.get("/EF"),
            pikepdf.Dictionary,
        ):
            counts["external_file_specifications"] += 1
        if action_entries > inputs.limits.max_action_entries:
            findings.append(
                _message(
                    Severity.ERROR,
                    "pdf.limit.action_entries",
                    "Actions, scripts, or form entries exceed the configured limit.",
                )
            )
            break
    counts["inspected_action_entries"] = action_entries
    return dict(sorted(counts.items()))


def _apply_static_text_profile(
    interactive,
    *,
    collection_count: int,
    findings,
) -> None:
    """Reject every active or package mechanism outside the fixed policy."""
    rejected_features = {
        "acroforms",
        "open_actions",
        "additional_actions",
        "javascript_name_trees",
        "javascript_actions",
        "launch_actions",
        "remote_go_to_actions",
        "submit_form_actions",
        "import_data_actions",
        "reset_form_actions",
        "internal_go_to_actions",
        "hide_actions",
        "media_actions",
        "named_actions",
        "optional_content_actions",
        "thread_actions",
        "unknown_actions",
        "external_file_specifications",
        "xfa_entries",
        "rich_media_annotations",
        "three_d_annotations",
        "three_d_streams",
        "widget_annotations",
        "media_annotations",
    }
    for feature in sorted(rejected_features):
        count = interactive.get(feature, 0)
        if count:
            findings.append(
                _message(
                    Severity.ERROR,
                    f"pdf.policy.static_text.{feature}",
                    f"Static text package policy rejects {feature.replace('_', ' ')}.",
                )
            )
    if collection_count:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.policy.static_text.collections",
                "Static text package policy rejects PDF Collection navigation.",
            )
        )


def _apply_static_text_member_policy(records, *, findings) -> None:
    """Allow only unambiguous XML, JSON, and STEP Part 21 text members."""
    digests_by_name: dict[str, set[str]] = {}
    for record in records.values():
        for name in record.original_names:
            digests_by_name.setdefault(name, set()).add(record.sha256)
        if not record.original_names:
            record.risk_flags.add("filename_empty")
        if record.detected_media_type not in PDF_ALLOWED_MEMBER_MEDIA_TYPES:
            if record.detected_media_type in {
                "application/java-archive",
                "application/x-dosexec",
                "application/x-executable",
            }:
                record.risk_flags.add("executable_content")
            _refuse_member(record, "unsupported_member_type")
            findings.append(
                _message(
                    Severity.ERROR,
                    "pdf.policy.static_text.unsupported_member_type",
                    "An embedded member is not XML, JSON, or STEP Part 21 text.",
                )
            )
        elif (
            record.detected_media_type == "application/xml"
            and record.xml_root_qname in PDF_REJECTED_XML_ROOTS
        ):
            record.risk_flags.add("active_xml_vocabulary")
            _refuse_member(record, "active_xml_vocabulary")
            findings.append(
                _message(
                    Severity.ERROR,
                    "pdf.policy.static_text.active_xml_vocabulary",
                    "An embedded XML member uses an active document vocabulary.",
                )
            )
        else:
            try:
                schemas = _preflight_payload(
                    record.path,
                    record.detected_media_type,
                )
            except (OSError, UnicodeDecodeError, ValueError):
                _refuse_member(record, "carrier_preflight_failed")
                findings.append(
                    _message(
                        Severity.ERROR,
                        "pdf.policy.static_text.carrier_preflight_failed",
                        "An embedded text member failed its bounded carrier preflight.",
                    )
                )
            else:
                if schemas:
                    record.step_file_schema = schemas
        if len(record.declared_media_types) > 1:
            record.risk_flags.add("conflicting_declared_media_types")
            _refuse_member(record, "conflicting_declared_media_types")
            findings.append(
                _message(
                    Severity.ERROR,
                    "pdf.policy.static_text.conflicting_declared_types",
                    "One embedded byte sequence has conflicting declared media types.",
                )
            )
        if "declared_type_mismatch" in record.risk_flags:
            _refuse_member(record, "declared_type_mismatch")
            findings.append(
                _message(
                    Severity.ERROR,
                    "pdf.policy.static_text.declared_type_mismatch",
                    "An embedded member's declared and detected types conflict.",
                )
            )
        if record.risk_flags & PDF_REJECTED_FILENAME_RISKS:
            _refuse_member(record, "unsafe_filename")
            findings.append(
                _message(
                    Severity.ERROR,
                    "pdf.policy.static_text.unsafe_filename",
                    "An embedded member has a filename unsafe for reliable interchange.",
                )
            )
        if any(
            Path(name).suffix.casefold() in PDF_REJECTED_FILENAME_SUFFIXES
            for name in record.original_names
        ):
            record.risk_flags.add("active_filename_extension")
            _refuse_member(record, "active_filename_extension")
            findings.append(
                _message(
                    Severity.ERROR,
                    "pdf.policy.static_text.active_filename_extension",
                    "An embedded member uses an active or executable filename extension.",
                )
            )
    duplicate_names = {name for name, digests in digests_by_name.items() if len(digests) > 1}
    for record in records.values():
        if record.original_names & duplicate_names:
            record.risk_flags.add("duplicate_name")
            _refuse_member(record, "duplicate_name")
    if duplicate_names:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.policy.static_text.duplicate_name",
                "Different embedded byte sequences share a declared filename.",
            )
        )


def _reject_unsupported_package_routes(
    graph: list[_GraphDictionary],
    *,
    supported_file_specs: set[tuple[Any, ...]],
    supported_af_containers: set[tuple[Any, ...]],
    findings: list[ValidationMessage],
) -> None:
    """Reject file-bearing routes outside the deliberately small allowlist."""
    unsupported_af = False
    unsupported_file_spec = False
    unsupported_object_metadata = False
    for item in graph:
        value = item.value
        identity = _graph_object_identity(value)
        if isinstance(value.get("/AF"), pikepdf.Array) and identity not in (
            supported_af_containers
        ):
            unsupported_af = True
        if (
            isinstance(value.get("/EF"), pikepdf.Dictionary)
            and identity not in supported_file_specs
        ):
            unsupported_file_spec = True
        if item.location != "catalog" and isinstance(
            value.get("/Metadata"),
            pikepdf.Stream,
        ):
            unsupported_object_metadata = True
    if unsupported_af:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.policy.static_text.unsupported_associated_file_route",
                "An Associated Files array occurs outside the catalog, page, or annotation.",
            )
        )
    if unsupported_file_spec:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.policy.static_text.unsupported_file_specification_route",
                "An embedded file specification is not reachable through an allowed route.",
            )
        )
    if unsupported_object_metadata:
        findings.append(
            _message(
                Severity.ERROR,
                "pdf.policy.static_text.object_metadata",
                "Static text package policy permits document-level XMP only.",
            )
        )


def _refuse_member(record: _MemberRecord, reason: str) -> None:
    """Mark a discovered byte sequence as evidence-only without hiding hazards."""
    record.extraction_eligible = False
    if not record.refusal_reason:
        record.refusal_reason = reason


def _clear_selected_outputs(records: dict[str, _MemberRecord]) -> None:
    """Remove selection evidence when atomic artifact publication is refused."""
    for record in records.values():
        record.selected_output_key = ""


def _has_errors(findings: list[ValidationMessage]) -> bool:
    """Return whether any domain finding prevents supplementary publication."""
    return any(message.severity == Severity.ERROR for message in findings)


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
        profile_results=[{"profile": PDF_STATIC_TEXT_PROFILE, "passed": False}],
        limits=inputs.limits.model_dump(mode="json"),
        finding_summary=_finding_summary(findings),
    )


def _encryption_facts(pdf) -> dict[str, Any]:
    """Record bounded encryption facts for the rejected-file inventory."""
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


def _encrypted_pdf_failure(
    *,
    pdf,
    source,
    inputs,
    header_version,
    execution_seconds,
    inventory_path: Path,
) -> PdfEngineResult:
    """Reject encryption before decoding XMP, attachments, or page resources."""
    findings = [
        _message(
            Severity.ERROR,
            "pdf.policy.static_text.encryption",
            "Static text package policy rejects encrypted PDFs.",
        )
    ]
    inventory = PdfInventory(
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
            header_version=str(pdf.pdf_version or header_version),
            object_count=len(pdf.objects),
            **_encryption_facts(pdf),
            linearized=bool(pdf.is_linearized),
        ),
        profile_results=[{"profile": PDF_STATIC_TEXT_PROFILE, "passed": False}],
        limits=inputs.limits.model_dump(mode="json"),
        finding_summary=_finding_summary(findings),
    )
    inventory_path.write_bytes(inventory.model_dump_json(indent=2).encode() + b"\n")
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
        artifact_payloads={
            "pdf_inventory": StagedArtifact.from_path(inventory_path),
        },
    )


def _limit_failure(
    *,
    source,
    inputs,
    header_version,
    code,
    text,
    execution_seconds,
    inventory_path: Path,
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
    inventory_path.write_bytes(inventory_bytes)
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
        artifact_payloads={
            "pdf_inventory": StagedArtifact.from_path(inventory_path),
        },
    )


def _detect_member_type(path: Path) -> tuple[str, str, list[str]]:
    """Return conservative carrier, XML QName, and Part 21 schema identities."""
    with path.open("rb") as source:
        prefix = source.read(4096).lstrip()
    if prefix.startswith(b"<"):
        try:
            root = SafeElementTree.parse(path).getroot()
        except Exception:
            return "application/octet-stream", "", []
        return "application/xml", str(root.tag), []
    if prefix.startswith((b"{", b"[")):
        try:
            with path.open(encoding="utf-8") as source:
                json.load(source, object_pairs_hook=_reject_duplicate_json_keys)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return "application/octet-stream", "", []
        return "application/json", "", []
    if prefix.startswith(b"%PDF-"):
        return "application/pdf", "", []
    if prefix.startswith(b"PK\x03\x04"):
        return "application/zip", "", []
    if prefix.startswith(b"ISO-10303-21;"):
        try:
            text = path.read_text(encoding="ascii", errors="strict")
        except UnicodeDecodeError:
            return "application/octet-stream", "", []
        return "model/step", "", _step_file_schema(text)
    if prefix.startswith(b"MZ"):
        return "application/x-dosexec", "", []
    return "application/octet-stream", "", []


def _xmp_inventory(path: Path | None) -> dict[str, Any]:
    """Return non-sensitive XMP carrier facts, never the full packet content."""
    if path is None:
        return {}
    data = path.read_bytes()
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


def _inventory_declarations(path: Path | None) -> list[PdfDeclaration]:
    """Inventory declared profile identifiers from the bounded XMP packet."""
    if path is None:
        return []
    root = SafeElementTree.parse(path).getroot()
    declarations: list[PdfDeclaration] = []
    seen: set[tuple[str, str]] = set()
    for element in root.iter():
        qname = str(element.tag)
        namespace = qname[1:].partition("}")[0] if qname.startswith("{") else ""
        if "declaration" not in namespace.casefold():
            continue
        for descendant in element.iter():
            identifier = _bounded_text(descendant.text or "", 2_048).strip()
            identity = (qname, identifier)
            if not identifier or identity in seen:
                continue
            seen.add(identity)
            declarations.append(
                PdfDeclaration(
                    identifier=identifier,
                    source_qname=_bounded_text(qname, 1_024),
                )
            )
            if len(declarations) >= 1_000:
                return declarations
    return declarations


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


def _uses_static_text_stream_filter(stream) -> bool:
    """Allow only an unfiltered stream or one canonical FlateDecode filter."""
    if "/DecodeParms" in stream:
        return False
    filters = stream.get("/Filter")
    if filters is None:
        return True
    if isinstance(filters, pikepdf.Array):
        return len(filters) == 1 and _pdf_name(filters[0]) == "FlateDecode"
    return _pdf_name(filters) == "FlateDecode"


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
    """Treat registered aliases for the same carrier as equivalent."""
    if declared == "application/octet-stream":
        return True
    if declared == detected:
        return True
    return (
        {declared, detected} <= {"application/xml", "text/xml"}
        # ISO registered both names for STEP Part 21. Accepting the pair keeps
        # validation about the submitted bytes rather than the producer's MIME
        # database while still rejecting declarations for a different carrier.
        or {declared, detected} <= {"application/p21", "model/step"}
    )


def _safe_extension(record: _MemberRecord) -> str:
    """Choose an engine-owned extension from detected type, never source name."""
    return {
        "application/xml": ".xml",
        "application/json": ".json",
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
