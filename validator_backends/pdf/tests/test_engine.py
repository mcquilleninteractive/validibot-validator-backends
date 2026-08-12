"""Exercise PDF inventory, exact selection, and no-execution policy.

The fixtures are generated from small synthetic PDFs so the suite can assert
the exact package mechanisms it creates without shipping opaque third-party
documents.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Literal, assert_never

import pikepdf
import pytest

from validator_backends.pdf import engine as pdf_engine
from validator_backends.pdf.engine import inspect_pdf
from validibot_shared.pdf import PdfInputs, PdfPayloadSelector, PdfProcessingLimits
from validibot_shared.validations.envelopes import ValidationStatus


_FIXTURE_MEDIA_TYPES_BY_SUFFIX = {
    ".json": "application/json",
    ".p21": "model/step",
    ".xml": "application/xml",
}
_VALID_XMP = (
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
    b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    b'<rdf:Description rdf:about=""/>'
    b"</rdf:RDF></x:xmpmeta>"
)
XmpFilterViolation = Literal["decode-parameters", "unsupported-filter"]


def _pdf_with_attachments(
    tmp_path: Path,
    attachments: dict[str, bytes],
    *,
    active_javascript: bool = False,
    declared_media_types: dict[str, str] | None = None,
) -> Path:
    """Create a PDF whose attachment declarations are host-independent.

    Operating systems maintain different filename-to-MIME registries. Tests
    must declare the intended fixture metadata explicitly so identical source
    bytes exercise identical validator paths everywhere.
    """
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    declared_media_types = declared_media_types or {}
    for name, content in attachments.items():
        extension = Path(name).suffix.lower()
        spec = pikepdf.AttachedFileSpec(
            pdf,
            content,
            description=f"fixture {name}",
            filename=name,
            mime_type=declared_media_types.get(
                name,
                _FIXTURE_MEDIA_TYPES_BY_SUFFIX.get(
                    extension,
                    "application/octet-stream",
                ),
            ),
            relationship=pikepdf.Name("/Data"),
        )
        spec.obj["/UF"] = pikepdf.String(name)
        spec.obj["/F"] = pikepdf.String(name)
        pdf.attachments[name] = spec
    if active_javascript:
        pdf.Root["/OpenAction"] = pikepdf.Dictionary(
            S=pikepdf.Name("/JavaScript"),
            JS=pikepdf.String("app.alert('never run')"),
        )
    path = tmp_path / "package.pdf"
    pdf.save(path)
    return path


def _pdf_with_uri_link(tmp_path: Path) -> Path:
    """Create a PDF containing one ordinary user-activated hyperlink."""
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(200, 200))
    action = pdf.make_indirect(
        pikepdf.Dictionary(
            S=pikepdf.Name("/URI"),
            URI=pikepdf.String("https://example.test/specification"),
        )
    )
    annotation = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"),
            Subtype=pikepdf.Name("/Link"),
            Rect=pikepdf.Array([10, 10, 100, 30]),
            A=action,
        )
    )
    page.obj["/Annots"] = pikepdf.Array([annotation])
    path = tmp_path / "linked.pdf"
    pdf.save(path)
    return path


def _pdf_with_signature_dictionary(tmp_path: Path) -> Path:
    """Create a certification-signature dictionary without adding a form."""
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    signature = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/Sig"),
            Filter=pikepdf.Name("/Adobe.PPKLite"),
            SubFilter=pikepdf.Name("/adbe.pkcs7.detached"),
            ByteRange=pikepdf.Array([0, 0, 0, 0]),
            Contents=pikepdf.String("deliberately-not-a-validated-signature"),
        )
    )
    pdf.Root["/Perms"] = pikepdf.Dictionary(DocMDP=signature)
    path = tmp_path / "signed.pdf"
    pdf.save(path)
    return path


def _pdf_with_xmp_filter_violation(
    tmp_path: Path,
    *,
    violation: XmpFilterViolation,
) -> Path:
    """Create valid document XMP whose stream dictionary violates the policy."""
    source = _pdf_with_attachments(tmp_path, {})
    path = tmp_path / f"xmp-{violation}.pdf"
    with pikepdf.Pdf.open(source) as pdf:
        metadata = pdf.make_stream(_VALID_XMP)
        if violation == "decode-parameters":
            placeholder = b"/FixtureDecodeParms"
            replacement = b"/DecodeParms       "
            metadata["/FixtureDecodeParms"] = pikepdf.Dictionary(Predictor=1)
        elif violation == "unsupported-filter":
            placeholder = b"/FixtureFilter"
            replacement = b"/Filter       "
            metadata["/FixtureFilter"] = pikepdf.Name("/ASCIIHexDecode")
        else:
            assert_never(violation)
        metadata["/Type"] = pikepdf.Name("/Metadata")
        metadata["/Subtype"] = pikepdf.Name("/XML")
        pdf.Root["/Metadata"] = metadata
        pdf.save(path, compress_streams=False, fix_metadata_version=False)
    serialized = path.read_bytes()
    assert serialized.count(placeholder) == 1
    assert len(placeholder) == len(replacement)
    path.write_bytes(serialized.replace(placeholder, replacement, 1))
    return path


def _pdf_with_rich_media_configurations(tmp_path: Path, count: int) -> Path:
    """Create inert RichMedia configuration dictionaries for limit testing."""
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(200, 200))
    configurations = pikepdf.Array(
        [pikepdf.Dictionary(Subtype=pikepdf.Name("/Video")) for _ in range(count)]
    )
    annotation = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"),
            Subtype=pikepdf.Name("/RichMedia"),
            Rect=pikepdf.Array([10, 10, 100, 100]),
            RichMediaContent=pikepdf.Dictionary(
                Assets=pikepdf.Dictionary(Names=pikepdf.Array()),
                Configurations=configurations,
            ),
        )
    )
    page.obj["/Annots"] = pikepdf.Array([annotation])
    path = tmp_path / "rich-media.pdf"
    pdf.save(path)
    return path


def test_exact_xml_selector_emits_original_verified_bytes(tmp_path: Path) -> None:
    """A unique exact member match should compose without rewriting XML bytes."""
    xml = b'<handover xmlns="urn:example:asset"><id>A-1</id></handover>'
    path = _pdf_with_attachments(tmp_path, {"asset-handover.xml": xml})

    result = inspect_pdf(
        path,
        source_name="drawing.pdf",
        inputs=PdfInputs(
            selected_xml=PdfPayloadSelector(
                required=True,
                original_filename="asset-handover.xml",
                xml_root_qname="{urn:example:asset}handover",
            )
        ),
    )

    assert result.status == ValidationStatus.SUCCESS, [
        (message.code, message.text) for message in result.messages
    ]
    assert result.artifact_payloads["selected_xml"].read_bytes() == xml
    assert result.outputs.inventory.members[0].sha256 == hashlib.sha256(xml).hexdigest()
    assert result.outputs.inventory.members[0].selected_output_key == "selected_xml"


def test_one_attempt_can_emit_all_six_fixed_artifacts(tmp_path: Path) -> None:
    """The first multi-output backend must preserve every declared typed result."""
    xml = b"<handover/>"
    json_payload = b'{"asset":"A-1"}'
    step = (
        b"ISO-10303-21;\nHEADER;\n"
        b"FILE_SCHEMA(('AP242_MANAGED_MODEL_BASED_3D_ENGINEERING_MIM_LF'));\n"
        b"ENDSEC;\nDATA;\nENDSEC;\nEND-ISO-10303-21;\n"
    )
    source = _pdf_with_attachments(
        tmp_path,
        {
            "handover.xml": xml,
            "asset-index.json": json_payload,
            "assembly.p21": step,
        },
    )
    path = tmp_path / "complete-package.pdf"
    with pikepdf.Pdf.open(source) as pdf:
        metadata = pdf.make_stream(
            b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
            b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            b'<rdf:Description rdf:about=""/>'
            b"</rdf:RDF></x:xmpmeta>"
        )
        metadata["/Type"] = pikepdf.Name("/Metadata")
        metadata["/Subtype"] = pikepdf.Name("/XML")
        pdf.Root["/Metadata"] = metadata
        pdf.save(path)

    result = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(
            emit_extracted_files_bundle=True,
            selected_xml=PdfPayloadSelector(original_filename="handover.xml"),
            selected_json=PdfPayloadSelector(original_filename="asset-index.json"),
            selected_step_p21=PdfPayloadSelector(original_filename="assembly.p21"),
        ),
    )

    assert result.status == ValidationStatus.SUCCESS, [
        (message.code, message.text) for message in result.messages
    ]
    assert set(result.artifact_payloads) == {
        "pdf_inventory",
        "extracted_files_bundle",
        "xmp_metadata",
        "selected_xml",
        "selected_json",
        "selected_step_p21",
    }
    assert result.artifact_payloads["selected_xml"].read_bytes() == xml
    assert result.artifact_payloads["selected_json"].read_bytes() == json_payload
    assert result.artifact_payloads["selected_step_p21"].read_bytes() == step


def test_step_selector_accepts_both_registered_part_21_media_types(
    tmp_path: Path,
) -> None:
    """A valid ISO media-type alias must not become a false conflict finding."""
    step = (
        b"ISO-10303-21;\nHEADER;\n"
        b"FILE_SCHEMA(('AP242_MANAGED_MODEL_BASED_3D_ENGINEERING_MIM_LF'));\n"
        b"ENDSEC;\nDATA;\nENDSEC;\nEND-ISO-10303-21;\n"
    )
    path = _pdf_with_attachments(
        tmp_path,
        {"assembly.p21": step},
        declared_media_types={"assembly.p21": "application/p21"},
    )

    result = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(
            selected_step_p21=PdfPayloadSelector(original_filename="assembly.p21"),
        ),
    )

    assert result.status == ValidationStatus.SUCCESS, [
        (message.code, message.text) for message in result.messages
    ]
    member = result.outputs.inventory.members[0]
    assert member.declared_media_type == "application/p21"
    assert member.detected_media_type == "model/step"
    assert "declared_type_mismatch" not in member.risk_flags
    assert result.artifact_payloads["selected_step_p21"].read_bytes() == step


def test_ambiguous_selector_fails_without_choosing_first(tmp_path: Path) -> None:
    """Traversal order must never decide between multiple matching XML members."""
    path = _pdf_with_attachments(
        tmp_path,
        {
            "a.xml": b"<a/>",
            "b.xml": b"<b/>",
        },
    )

    result = inspect_pdf(
        path,
        source_name="drawing.pdf",
        inputs=PdfInputs(
            selected_xml=PdfPayloadSelector(
                required=True,
                declared_media_type="application/xml",
            )
        ),
    )

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert "selected_xml" not in result.artifact_payloads
    assert any(message.code == "pdf.selector.ambiguous" for message in result.messages)


def test_active_xml_vocabulary_is_not_eligible_static_text(tmp_path: Path) -> None:
    """SVG must not pass merely because it is well-formed XML text."""
    path = _pdf_with_attachments(
        tmp_path,
        {
            "diagram.svg": (
                b'<svg xmlns="http://www.w3.org/2000/svg"><script>never_execute()</script></svg>'
            )
        },
        declared_media_types={"diagram.svg": "application/xml"},
    )

    result = inspect_pdf(path, source_name=path.name, inputs=PdfInputs())

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert set(result.artifact_payloads) == {"pdf_inventory"}
    assert any(
        message.code == "pdf.policy.static_text.active_xml_vocabulary"
        for message in result.messages
    )
    assert result.outputs.inventory.members[0].extraction_eligible is False


def test_member_decode_parameters_are_rejected_before_extraction(tmp_path: Path) -> None:
    """Even Flate predictor settings are outside the deliberately tiny codec set."""
    source = _pdf_with_attachments(tmp_path, {"data.xml": b"<data/>"})
    path = tmp_path / "decode-parameters.pdf"
    with pikepdf.Pdf.open(source) as pdf:
        names = pdf.Root["/Names"]["/EmbeddedFiles"]["/Names"]
        stream = names[1]["/EF"]["/F"]
        stream["/DecodeParms"] = pikepdf.Dictionary(Predictor=1)
        pdf.save(path)

    result = inspect_pdf(path, source_name=path.name, inputs=PdfInputs())

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert set(result.artifact_payloads) == {"pdf_inventory"}
    assert any(
        message.code == "pdf.policy.static_text.member_stream_filter"
        for message in result.messages
    )


@pytest.mark.parametrize("violation", ["decode-parameters", "unsupported-filter"])
def test_document_xmp_filter_violations_are_rejected_before_decode(
    tmp_path: Path,
    violation: XmpFilterViolation,
) -> None:
    """Document XMP has its own exact filter boundary and regression coverage."""
    path = _pdf_with_xmp_filter_violation(tmp_path, violation=violation)

    result = inspect_pdf(path, source_name=path.name, inputs=PdfInputs())

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert set(result.artifact_payloads) == {"pdf_inventory"}
    assert any(
        message.code == "pdf.policy.static_text.xmp_stream_filter" for message in result.messages
    )


def test_document_xmp_requires_explicit_metadata_xml_identity(tmp_path: Path) -> None:
    """An arbitrary catalog stream cannot become XMP solely by parsing as XML."""
    source = _pdf_with_attachments(tmp_path, {})
    path = tmp_path / "misidentified-xmp.pdf"
    with pikepdf.Pdf.open(source) as pdf:
        metadata = pdf.make_stream(b"<not-xmp/>")
        metadata["/Type"] = pikepdf.Name("/FixtureStream")
        metadata["/Subtype"] = pikepdf.Name("/FixtureXML")
        pdf.Root["/Metadata"] = metadata
        pdf.save(path)
    serialized = path.read_bytes()
    assert b"/Type /Metadata" in serialized
    path.write_bytes(serialized.replace(b"/Type /Metadata", b"/Type /Metadatz", 1))

    result = inspect_pdf(path, source_name=path.name, inputs=PdfInputs())

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert set(result.artifact_payloads) == {"pdf_inventory"}
    assert any(
        message.code == "pdf.policy.static_text.xmp_stream_identity" for message in result.messages
    )


def test_document_metadata_must_contain_an_xmp_rdf_packet(tmp_path: Path) -> None:
    """Metadata/XML identity alone must not promote arbitrary XML as XMP."""
    source = _pdf_with_attachments(tmp_path, {})
    path = tmp_path / "not-xmp.pdf"
    valid_xmp = (
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/>'
        b"</x:xmpmeta>"
    )
    with pikepdf.Pdf.open(source) as pdf:
        metadata = pdf.make_stream(valid_xmp)
        metadata["/Type"] = pikepdf.Name("/Metadata")
        metadata["/Subtype"] = pikepdf.Name("/XML")
        pdf.Root["/Metadata"] = metadata
        pdf.save(path, compress_streams=False)
    serialized = path.read_bytes()
    identity_offset = serialized.index(b"/Type /Metadata")
    stream_start = serialized.index(b"stream\n", identity_offset) + len(b"stream\n")
    stream_end = serialized.index(b"\nendstream", stream_start)
    ordinary_xml = b"<ordinary-metadata/>".ljust(stream_end - stream_start, b" ")
    path.write_bytes(serialized[:stream_start] + ordinary_xml + serialized[stream_end:])

    result = inspect_pdf(path, source_name=path.name, inputs=PdfInputs())

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert set(result.artifact_payloads) == {"pdf_inventory"}
    assert any(
        message.code == "pdf.policy.static_text.xmp_structure" for message in result.messages
    )


def test_static_text_policy_flags_javascript_without_executing_it(
    tmp_path: Path,
) -> None:
    """Active content must become inventory evidence and a policy failure."""
    path = _pdf_with_attachments(
        tmp_path,
        {"safe.xml": b"<safe/>"},
        active_javascript=True,
    )

    result = inspect_pdf(
        path,
        source_name="active.pdf",
        inputs=PdfInputs(),
    )

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert result.outputs.inventory.interactive_features["open_actions"] == 1
    assert any(
        message.code == "pdf.policy.static_text.open_actions" for message in result.messages
    )
    assert set(result.artifact_payloads) == {"pdf_inventory"}


def test_static_text_policy_ignores_ordinary_uri_links(tmp_path: Path) -> None:
    """Out-of-scope hyperlinks are neither followed, copied, nor policy findings."""
    path = _pdf_with_uri_link(tmp_path)

    result = inspect_pdf(
        path,
        source_name="linked.pdf",
        inputs=PdfInputs(),
    )

    assert result.status == ValidationStatus.SUCCESS
    assert result.outputs.inventory.interactive_features.get("uri_actions", 0) == 0
    assert "uri_action_targets" not in result.outputs.inventory.interactive_features
    assert all("uri" not in message.code for message in result.messages)


def test_static_text_policy_ignores_a_signature_dictionary(tmp_path: Path) -> None:
    """A signature dictionary alone is not interpreted or made a policy result."""
    path = _pdf_with_signature_dictionary(tmp_path)

    result = inspect_pdf(path, source_name=path.name, inputs=PdfInputs())

    assert result.status == ValidationStatus.SUCCESS
    inventory = result.outputs.inventory.model_dump(mode="json")
    assert "signatures" not in inventory
    assert all("signature" not in message.code for message in result.messages)
    assert set(result.artifact_payloads) == {"pdf_inventory"}


def test_extraction_bundle_is_deterministic_and_uses_hash_paths(
    tmp_path: Path,
) -> None:
    """Original embedded names must remain metadata rather than ZIP entry paths."""
    path = _pdf_with_attachments(
        tmp_path,
        {"safe.xml": b"<safe/>"},
    )
    inputs = PdfInputs(emit_extracted_files_bundle=True)

    first = inspect_pdf(path, source_name="drawing.pdf", inputs=inputs)
    second = inspect_pdf(path, source_name="drawing.pdf", inputs=inputs)
    first_zip = first.artifact_payloads["extracted_files_bundle"].read_bytes()
    second_zip = second.artifact_payloads["extracted_files_bundle"].read_bytes()

    assert first_zip == second_zip
    with zipfile.ZipFile(BytesIO(first_zip)) as archive:
        assert "safe.xml" not in archive.namelist()
        assert archive.namelist()[0] == "manifest.json"
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["members"][0]["original_names"] == ["safe.xml"]
        assert manifest["members"][0]["path"].startswith("files/")


def test_unsafe_member_name_suppresses_every_supplementary_artifact(
    tmp_path: Path,
) -> None:
    """One unsafe name must atomically withhold selectors, XMP, and ZIP output."""
    source = _pdf_with_attachments(tmp_path, {"../unsafe.xml": b"<safe/>"})
    path = tmp_path / "unsafe-with-xmp.pdf"
    with pikepdf.Pdf.open(source) as pdf:
        metadata = pdf.make_stream(b'<x:xmpmeta xmlns:x="adobe:ns:meta/"/>')
        metadata["/Type"] = pikepdf.Name("/Metadata")
        metadata["/Subtype"] = pikepdf.Name("/XML")
        pdf.Root["/Metadata"] = metadata
        pdf.save(path)

    result = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(
            emit_extracted_files_bundle=True,
            selected_xml=PdfPayloadSelector(original_filename="../unsafe.xml"),
        ),
    )

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert set(result.artifact_payloads) == {"pdf_inventory"}
    assert result.outputs.selected_output_keys == []
    assert any(
        message.code == "pdf.policy.static_text.unsafe_filename" for message in result.messages
    )


def test_malformed_pdf_is_a_domain_result_with_an_inventory(tmp_path: Path) -> None:
    """An intentionally rejected malformed carrier is not a backend crash."""
    path = tmp_path / "broken.pdf"
    path.write_bytes(b"%PDF-2.0\nnot a real object graph")

    result = inspect_pdf(path, source_name="broken.pdf", inputs=PdfInputs())

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert "pdf_inventory" in result.artifact_payloads
    inventory = json.loads(result.artifact_payloads["pdf_inventory"].read_bytes())
    assert inventory["schema_version"] == "validibot.pdf_inventory.v2"
    assert any(message.code == "pdf.structure.invalid" for message in result.messages)


def test_configured_input_limit_is_a_domain_failure(tmp_path: Path) -> None:
    """A policy byte limit should produce evidence rather than a runtime error."""
    path = _pdf_with_attachments(tmp_path, {})

    result = inspect_pdf(
        path,
        source_name="drawing.pdf",
        inputs=PdfInputs(limits=PdfProcessingLimits(max_input_bytes=10)),
    )

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert "pdf_inventory" in result.artifact_payloads
    assert any(message.code == "pdf.limit.input_bytes" for message in result.messages)


def test_execution_deadline_is_a_domain_failure_with_inventory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Cooperative deadline exhaustion must still publish bounded evidence."""
    path = _pdf_with_attachments(tmp_path, {})
    clock_calls = 0

    def elapsed_clock() -> float:
        nonlocal clock_calls
        clock_calls += 1
        return 0.0 if clock_calls == 1 else 2.0

    monkeypatch.setattr(pdf_engine.time, "monotonic", elapsed_clock)

    result = inspect_pdf(
        path,
        source_name="drawing.pdf",
        inputs=PdfInputs(limits=PdfProcessingLimits(max_execution_seconds=1)),
    )

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert "pdf_inventory" in result.artifact_payloads
    assert any(message.code == "pdf.limit.execution_seconds" for message in result.messages)


def test_rich_media_configuration_limit_stops_bounded_inspection(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """RichMedia is rejected shallowly without decoding its internal assets."""
    path = _pdf_with_rich_media_configurations(tmp_path, count=4)

    def forbidden_decode(*_args, **_kwargs):
        raise AssertionError("RichMedia rejection attempted to decode a stream")

    monkeypatch.setattr(pdf_engine.BoundedPdfStreamDecoder, "decode", forbidden_decode)

    result = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(limits=PdfProcessingLimits(max_action_entries=2)),
    )

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert result.outputs.inventory.interactive_features["rich_media_annotations"] == 1
    assert any(
        message.code == "pdf.policy.static_text.rich_media_annotations"
        for message in result.messages
    )
    assert set(result.artifact_payloads) == {"pdf_inventory"}


def test_empty_user_password_encryption_is_rejected_before_extraction(
    tmp_path: Path,
) -> None:
    """Even empty-user-password encryption is outside the fixed policy."""
    source = _pdf_with_attachments(tmp_path, {"data.xml": b"<data/>"})
    encrypted = tmp_path / "owner-protected.pdf"
    with pikepdf.Pdf.open(source) as pdf:
        pdf.save(
            encrypted,
            encryption=pikepdf.Encryption(
                owner="owner-secret",
                user="",
                R=6,
                allow=pikepdf.Permissions(extract=False, print_highres=False),
            ),
        )

    result = inspect_pdf(encrypted, source_name=encrypted.name, inputs=PdfInputs())

    assert result.status == ValidationStatus.FAILED_VALIDATION
    facts = result.outputs.inventory.pdf
    assert facts.encrypted is True
    assert set(result.artifact_payloads) == {"pdf_inventory"}
    assert any(message.code == "pdf.policy.static_text.encryption" for message in result.messages)


def test_user_password_encryption_reports_the_same_policy_failure(tmp_path: Path) -> None:
    """Password-gated encryption must not create a separate processing mode."""
    source = _pdf_with_attachments(tmp_path, {})
    encrypted = tmp_path / "password-required.pdf"
    with pikepdf.Pdf.open(source) as pdf:
        pdf.save(
            encrypted,
            encryption=pikepdf.Encryption(
                owner="owner-secret",
                user="reader-secret",
                R=6,
            ),
        )

    result = inspect_pdf(encrypted, source_name=encrypted.name, inputs=PdfInputs())

    assert result.status == ValidationStatus.FAILED_VALIDATION
    assert any(message.code == "pdf.policy.static_text.encryption" for message in result.messages)
    assert set(result.artifact_payloads) == {"pdf_inventory"}


def test_inventory_output_limit_emits_a_small_failure_inventory(tmp_path: Path) -> None:
    """Inventory metadata itself must remain bounded even with many long names."""
    attachments = {
        f"{index:03d}-{'x' * 180}.xml": f"<row>{index}</row>".encode() for index in range(60)
    }
    path = _pdf_with_attachments(tmp_path, attachments)

    result = inspect_pdf(
        path,
        source_name="large-inventory.pdf",
        inputs=PdfInputs(
            limits=PdfProcessingLimits(max_inventory_bytes=10_000),
        ),
    )

    assert result.status == ValidationStatus.FAILED_VALIDATION
    inventory_bytes = result.artifact_payloads["pdf_inventory"].read_bytes()
    assert len(inventory_bytes) <= 10_000
    assert any(message.code == "pdf.limit.inventory_bytes" for message in result.messages)
