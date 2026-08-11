"""Exercise the versioned golden and hostile PDF acceptance corpus.

The corpus is the release fence for dependency upgrades. These tests verify
lawful provenance and exact digests first, then run the same small files through
determinism, discovery, selector, no-execution, encryption, parser, and limit
assertions. No case relies on dangerous resource consumption; exhaustion paths
use deliberately low configured budgets.
"""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

from validator_backends.pdf.engine import inspect_pdf
from validibot_shared.pdf import PdfInputs, PdfPayloadSelector, PdfProcessingLimits
from validibot_shared.validations.envelopes import ValidationStatus


FIXTURE_ROOT = Path(__file__).parent / "fixtures"
MANIFEST_PATH = FIXTURE_ROOT / "manifest.json"
EXPECTED_SCHEMA_VERSION = "validibot.pdf_test_corpus.v1"
EXPECTED_CORPUS_VERSION = "1.0.0"
KNOWN_LICENSES = {"CC0-1.0"}
EXPECTED_TYPED_PAYLOADS = {
    "selected_xml": b'<handover xmlns="urn:validibot:fixture"><id>A-1</id></handover>',
    "selected_json": b'{"asset":"A-1"}',
    "selected_step_p21": (
        b"ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('AP242_FIXTURE'));\nENDSEC;\n"
        b"DATA;\nENDSEC;\nEND-ISO-10303-21;\n"
    ),
}


def _manifest() -> dict:
    """Load the reviewed manifest rather than infer fixture intent from names."""
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _fixture(name: str) -> Path:
    """Return one corpus path by stable manifest fixture ID."""
    entry = next(item for item in _manifest()["fixtures"] if item["fixture_id"] == name)
    return FIXTURE_ROOT / entry["path"]


def _codes(result) -> set[str]:
    """Return stable finding codes without coupling tests to message wording."""
    return {message.code for message in result.messages}


# ── Provenance and exact corpus identity ──────────────────────────────────
# A dependency release is accepted against reviewed bytes, not whatever files
# happen to be present in the checkout. The manifest is therefore checked as a
# strict allow-list with complete authorship and redistribution evidence.


def test_manifest_is_complete_digest_pinned_and_lawfully_redistributable() -> None:
    """Every distributed PDF must have exact identity and complete provenance."""
    manifest = _manifest()

    assert manifest["schema_version"] == EXPECTED_SCHEMA_VERSION
    assert manifest["corpus_version"] == EXPECTED_CORPUS_VERSION
    entries = manifest["fixtures"]
    assert entries
    assert len({entry["fixture_id"] for entry in entries}) == len(entries)
    assert len({entry["path"] for entry in entries}) == len(entries)

    listed_paths = set()
    for entry in entries:
        path = FIXTURE_ROOT / entry["path"]
        listed_paths.add(path.relative_to(FIXTURE_ROOT).as_posix())
        data = path.read_bytes()
        assert entry["size_bytes"] == len(data)
        assert entry["sha256"] == hashlib.sha256(data).hexdigest()
        assert entry["pdf_version"]
        assert entry["mechanisms"]
        assert isinstance(entry["hazards"], list)
        assert entry["expected_findings"]
        assert entry["expected_artifacts"]
        assert entry["provenance"]
        assert entry["author"]
        assert entry["license"] in KNOWN_LICENSES
        assert entry["synthetic"] is True
        assert entry["derived_from"] is None
        assert entry["redistributable"] is True
        assert entry["redistribution_restriction"] == ""
        assert entry["generator"]["script"] == "generate.py"
        assert entry["generator"]["version"]

    actual_paths = {
        path.relative_to(FIXTURE_ROOT).as_posix()
        for directory in (FIXTURE_ROOT / "golden", FIXTURE_ROOT / "hostile")
        for path in directory.rglob("*")
        if path.is_file()
    }
    assert actual_paths == listed_paths


# ── Stable wrapper and package discovery ──────────────────────────────────
# These assertions cover the standardized locations the backend promises, and
# pin deduplication to exact payload hashes while retaining every route.


@pytest.mark.parametrize(
    ("fixture_id", "expected_version"),
    [("minimal-pdf-1x", "1.7"), ("minimal-pdf-2", "2.0")],
)
def test_minimal_pdf_versions_are_inventoried(
    fixture_id: str,
    expected_version: str,
) -> None:
    """Both the established PDF 1.x carrier and PDF 2.0 remain accepted."""
    path = _fixture(fixture_id)

    result = inspect_pdf(path, source_name=path.name, inputs=PdfInputs())

    assert result.status == ValidationStatus.SUCCESS
    assert result.outputs.inventory.pdf.header_version == expected_version
    assert result.outputs.inventory.parser.recovery_attempted is False


def test_package_mechanisms_are_discovered_and_deduplicated() -> None:
    """One payload reached through many mechanisms remains one evidenced member."""
    path = _fixture("package-mechanisms")
    selector = PdfPayloadSelector(
        required=True,
        original_filename="handover.xml",
        declared_media_type="application/xml",
        af_relationship="Data",
        xml_root_qname="{urn:validibot:fixture}handover",
    )

    result = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(
            emit_extracted_files_bundle=True,
            selected_xml=selector,
        ),
    )

    assert result.status == ValidationStatus.SUCCESS, _codes(result)
    assert (
        result.artifact_payloads["selected_xml"].read_bytes()
        == EXPECTED_TYPED_PAYLOADS["selected_xml"]
    )
    members = {member.detected_media_type: member for member in result.outputs.inventory.members}
    xml_member = members["application/xml"]
    assert {
        "embedded_files_name_tree",
        "file_specification",
        "associated_file",
        "file_attachment_annotation",
    } <= set(xml_member.discovery_kinds)
    assert len(xml_member.discovery_locations) >= 6
    json_member = members["application/json"]
    assert "rich_media_asset" in json_member.discovery_kinds
    assert json_member.rich_media_asset_names == ["asset-index"]
    inventory = result.outputs.inventory
    assert inventory.metadata["object_metadata"]
    assert inventory.declarations
    assert inventory.extensions[0].developer == "ISO_"
    assert inventory.requirements[0].subtype == "FixtureRequirement"
    assert inventory.interactive_features["rich_media_annotations"] == 1
    assert inventory.interactive_features["three_d_streams"] == 1


def test_repeated_runs_emit_identical_inventory_and_zip_bytes() -> None:
    """The same source and configuration must produce reproducible evidence."""
    path = _fixture("package-mechanisms")
    inputs = PdfInputs(emit_extracted_files_bundle=True)

    first = inspect_pdf(path, source_name=path.name, inputs=inputs)
    second = inspect_pdf(path, source_name=path.name, inputs=inputs)

    assert first.outputs.inventory == second.outputs.inventory
    assert (
        first.artifact_payloads["pdf_inventory"].read_bytes()
        == second.artifact_payloads["pdf_inventory"].read_bytes()
    )
    assert (
        first.artifact_payloads["extracted_files_bundle"].read_bytes()
        == second.artifact_payloads["extracted_files_bundle"].read_bytes()
    )


# ── Exact selector outcomes and hazardous member evidence ─────────────────
# Every fixed typed output exercises its zero, one, and ambiguous match paths;
# this prevents traversal order from becoming an implicit selection rule.


@pytest.mark.parametrize(
    ("output_key", "selector"),
    [
        (
            "selected_xml",
            PdfPayloadSelector(
                original_filename="handover.xml",
                detected_media_type="application/xml",
            ),
        ),
        (
            "selected_json",
            PdfPayloadSelector(
                original_filename="asset-index.json",
                detected_media_type="application/json",
            ),
        ),
        (
            "selected_step_p21",
            PdfPayloadSelector(
                original_filename="assembly.p21",
                detected_media_type="model/step",
            ),
        ),
    ],
)
def test_each_typed_selector_emits_the_exact_unique_bytes(
    output_key: str,
    selector: PdfPayloadSelector,
) -> None:
    """A unique typed match is byte-preserving and independently digestable."""
    path = _fixture("typed-and-hazardous-members")

    result = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(**{output_key: selector}),
    )

    payload = EXPECTED_TYPED_PAYLOADS[output_key]
    assert result.status == ValidationStatus.SUCCESS, _codes(result)
    assert result.artifact_payloads[output_key].read_bytes() == payload
    selected_member = next(
        member
        for member in result.outputs.inventory.members
        if member.selected_output_key == output_key
    )
    assert selected_member.decoded_size_bytes == len(payload)
    assert selected_member.sha256 == hashlib.sha256(payload).hexdigest()


def test_step_file_schema_selects_the_exact_part_21_member() -> None:
    """Part 21 selection can use its bounded FILE_SCHEMA header identity."""
    path = _fixture("typed-and-hazardous-members")

    result = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(
            selected_step_p21=PdfPayloadSelector(
                required=True,
                step_file_schema=["AP242_FIXTURE"],
            )
        ),
    )

    assert result.status == ValidationStatus.SUCCESS, _codes(result)
    assert (
        result.artifact_payloads["selected_step_p21"].read_bytes()
        == EXPECTED_TYPED_PAYLOADS["selected_step_p21"]
    )


@pytest.mark.parametrize(
    "output_key",
    ["selected_xml", "selected_json", "selected_step_p21"],
)
def test_each_typed_selector_fails_closed_for_zero_and_multiple_matches(
    output_key: str,
) -> None:
    """Required absence and ambiguity emit no artifact and never choose first."""
    path = _fixture("typed-and-hazardous-members")

    missing = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(
            **{
                output_key: PdfPayloadSelector(
                    required=True,
                    original_filename="does-not-exist.fixture",
                )
            }
        ),
    )
    ambiguous = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(
            **{
                output_key: PdfPayloadSelector(
                    required=True,
                    discovery_kinds=["file_specification"],
                )
            }
        ),
    )

    assert missing.status == ValidationStatus.FAILED_VALIDATION
    assert output_key not in missing.artifact_payloads
    assert "pdf.selector.not_found" in _codes(missing)
    assert ambiguous.status == ValidationStatus.FAILED_VALIDATION
    assert output_key not in ambiguous.artifact_payloads
    assert "pdf.selector.ambiguous" in _codes(ambiguous)


def test_optional_zero_match_is_visible_without_minting_an_artifact() -> None:
    """An optional absent member is explicit evidence, never silent fallback."""
    path = _fixture("typed-and-hazardous-members")

    result = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(
            selected_xml=PdfPayloadSelector(
                required=False,
                original_filename="optional-missing.xml",
            )
        ),
    )

    assert result.status == ValidationStatus.SUCCESS
    assert "selected_xml" not in result.artifact_payloads
    assert "pdf.selector.not_found" in _codes(result)


def test_member_hazards_preserve_names_as_evidence_only() -> None:
    """Dangerous names and false claims are flagged without becoming paths."""
    path = _fixture("typed-and-hazardous-members")

    result = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(emit_extracted_files_bundle=True),
    )

    all_flags = {flag for member in result.outputs.inventory.members for flag in member.risk_flags}
    assert {
        "filename_path_hazard",
        "filename_dot_segment",
        "filename_absolute_path",
        "filename_drive_prefix",
        "filename_control_character",
        "filename_bidi_control",
        "filename_unicode",
        "filename_empty",
        "duplicate_name",
        "declared_type_mismatch",
        "conflicting_declared_media_types",
        "executable_content",
    } <= all_flags
    assert {
        "pdf.member.type_mismatch",
        "pdf.member.conflicting_declared_types",
        "pdf.member.duplicate_name",
        "pdf.member.executable_content",
    } <= _codes(result)


# ── No execution, no network, no rewrite, and honest signature evidence ───
# Active declarations are treated as inert PDF objects. Python-level process
# and network entry points are booby-trapped to make any accidental activation
# fail the test immediately.


def test_active_features_are_inventoried_without_execution_network_or_rewrite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hostile declarations remain inert and the submitted bytes stay immutable."""
    path = _fixture("interactive-signature-incremental")
    before = path.read_bytes()
    sibling_names = sorted(item.name for item in path.parent.iterdir())

    def forbidden(*_args, **_kwargs):
        raise AssertionError("PDF inspection attempted execution or network access")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)

    result = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(profile="safe_static_package_v1"),
    )

    assert result.status == ValidationStatus.FAILED_VALIDATION
    features = result.outputs.inventory.interactive_features
    for feature in (
        "javascript_actions",
        "xfa_entries",
        "uri_actions",
        "launch_actions",
        "submit_form_actions",
        "import_data_actions",
        "reset_form_actions",
        "remote_go_to_actions",
        "rich_media_automatic_activation",
        "external_file_specifications",
    ):
        assert features[feature] >= 1
    assert path.read_bytes() == before
    assert sorted(item.name for item in path.parent.iterdir()) == sibling_names
    assert result.outputs.inventory.parser.recovery_attempted is False
    assert result.outputs.inventory.metadata["incremental_revision_markers"] == 1
    assert result.outputs.inventory.signatures
    signature = result.outputs.inventory.signatures[0]
    assert signature.byte_range
    assert signature.apparent_signed_revision_bytes is not None
    assert signature.apparently_covers_current_file is False
    assert signature.claimed_name


# ── Encryption, malformed input, warnings, and bounded exhaustion ─────────
# User data that cannot be inspected remains a domain result with a canonical
# failure inventory; every exhausted budget is an error, never partial success.


def test_encryption_paths_distinguish_empty_and_required_user_passwords() -> None:
    """Inspectable permissions and secret-gated content have distinct outcomes."""
    empty_path = _fixture("empty-user-password")
    required_path = _fixture("password-required")

    empty = inspect_pdf(empty_path, source_name=empty_path.name, inputs=PdfInputs())
    required = inspect_pdf(
        required_path,
        source_name=required_path.name,
        inputs=PdfInputs(),
    )

    assert empty.status == ValidationStatus.SUCCESS
    assert empty.outputs.inventory.pdf.encrypted is True
    assert empty.outputs.inventory.pdf.opened_with_empty_password is True
    assert empty.outputs.inventory.pdf.permissions["extract"] is False
    assert required.status == ValidationStatus.FAILED_VALIDATION
    assert "pdf.encryption.password_required" in _codes(required)
    assert set(required.artifact_payloads) == {"pdf_inventory"}


@pytest.mark.parametrize(
    "fixture_id",
    ["malformed-xref", "malformed-object-stream"],
)
def test_malformed_structures_fail_as_domain_results(fixture_id: str) -> None:
    """Damaged xref, trailer, and object structures cannot mint a passing result."""
    path = _fixture(fixture_id)

    result = inspect_pdf(path, source_name=path.name, inputs=PdfInputs())

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert "pdf.structure.invalid" in _codes(result)
    assert set(result.artifact_payloads) == {"pdf_inventory"}


def test_parser_warnings_are_preserved_without_silent_repair() -> None:
    """A readable warning-bearing PDF reports diagnostics and no recovery claim."""
    path = _fixture("parser-warning")

    result = inspect_pdf(path, source_name=path.name, inputs=PdfInputs())

    assert result.status == ValidationStatus.SUCCESS
    assert "pdf.structure.parser_warning" in _codes(result)
    assert result.outputs.inventory.parser.warnings
    assert result.outputs.inventory.parser.recovery_attempted is False


@pytest.mark.parametrize(
    ("fixture_id", "limits", "expected_code"),
    [
        (
            "deep-cycle",
            PdfProcessingLimits(max_object_depth=8),
            "pdf.limit.object_depth",
        ),
        (
            "page-and-object-limits",
            PdfProcessingLimits(max_pages=1),
            "pdf.limit.pages",
        ),
        (
            "page-and-object-limits",
            PdfProcessingLimits(max_objects=1),
            "pdf.limit.objects",
        ),
        (
            "package-mechanisms",
            PdfProcessingLimits(max_member_references=1),
            "pdf.limit.member_references",
        ),
        (
            "typed-and-hazardous-members",
            PdfProcessingLimits(max_member_bytes=8),
            "pdf.limit.member_bytes",
        ),
        (
            "typed-and-hazardous-members",
            PdfProcessingLimits(max_total_member_bytes=24),
            "pdf.limit.total_member_bytes",
        ),
        (
            "high-decode-ratio",
            PdfProcessingLimits(),
            "pdf.limit.decode_ratio",
        ),
        (
            "excessive-filters",
            PdfProcessingLimits(),
            "pdf.limit.stream_filters",
        ),
        (
            "typed-and-hazardous-members",
            PdfProcessingLimits(max_findings=1),
            "pdf.limit.findings",
        ),
    ],
)
def test_structural_and_output_limits_fail_closed_with_small_inputs(
    fixture_id: str,
    limits: PdfProcessingLimits,
    expected_code: str,
) -> None:
    """Configured exhaustion always fails and retains a bounded inventory."""
    path = _fixture(fixture_id)
    started = time.monotonic()

    result = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(limits=limits),
    )

    assert time.monotonic() - started < 5
    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert expected_code in _codes(result)
    assert "pdf_inventory" in result.artifact_payloads
    assert result.outputs.passed is False


def test_bundle_output_exhaustion_emits_no_partial_zip() -> None:
    """ZIP overhead beyond the output budget fails instead of truncating bytes."""
    path = _fixture("empty-user-password")

    result = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(
            emit_extracted_files_bundle=True,
            limits=PdfProcessingLimits(max_output_bundle_bytes=50),
        ),
    )

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert "pdf.limit.output_bundle_bytes" in _codes(result)
    assert "extracted_files_bundle" not in result.artifact_payloads
