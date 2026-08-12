"""Generate the repository-owned PDF validator acceptance corpus.

The script is deliberately standalone and writes only beneath its own fixture
directory. It builds semantic PDF structures directly rather than copying any
external document, then records the exact distributed bytes in ``manifest.json``.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pikepdf


GENERATOR_ID = "validibot-pdf-corpus-generator"
GENERATOR_VERSION = "2"
FIXTURE_ROOT = Path(__file__).resolve().parent
GOLDEN = FIXTURE_ROOT / "golden"
HOSTILE = FIXTURE_ROOT / "hostile"
CORPUS_AUTHOR = "McQuillen Interactive Pty. Ltd."
CORPUS_LICENSE = "CC0-1.0"


@dataclass(frozen=True, slots=True)
class FixtureDescription:
    """Reviewed provenance and acceptance intent for one generated fixture."""

    fixture_id: str
    relative_path: str
    pdf_version: str
    mechanisms: list[str]
    hazards: list[str]
    expected_findings: dict[str, list[str]]
    expected_artifacts: dict[str, list[str]]
    deterministic: bool = True


def _new_pdf() -> tuple[pikepdf.Pdf, Any]:
    """Return a one-page PDF with no timestamps or inherited metadata."""
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(200, 200))
    return pdf, page


def _save(
    pdf: pikepdf.Pdf,
    path: Path,
    *,
    version: str = "1.7",
    encryption: pikepdf.Encryption | None = None,
    compress_streams: bool = True,
) -> None:
    """Save ordinary fixtures with stable IDs and classic cross references."""
    path.parent.mkdir(parents=True, exist_ok=True)
    save_options = {
        "deterministic_id": encryption is None,
        "compress_streams": compress_streams,
        "object_stream_mode": pikepdf.ObjectStreamMode.disable,
        "encryption": encryption,
    }
    if encryption is None:
        save_options["force_version"] = version
    else:
        save_options["min_version"] = version
    pdf.save(path, **save_options)


def _embedded_stream(
    pdf: pikepdf.Pdf,
    data: bytes,
    *,
    media_type: str = "",
):
    """Create one embedded-file stream with optional untrusted MIME metadata."""
    stream = pdf.make_stream(data)
    stream["/Type"] = pikepdf.Name("/EmbeddedFile")
    if media_type:
        stream["/Subtype"] = pikepdf.Name(f"/{media_type}")
    stream["/Params"] = pikepdf.Dictionary(Size=len(data))
    return stream


def _file_spec(
    pdf: pikepdf.Pdf,
    *,
    name: str,
    data: bytes | None = None,
    media_type: str = "",
    stream=None,
    relationship: str = "Data",
    description: str = "Synthetic corpus member",
):
    """Create one indirect file specification for exact fixture bytes."""
    embedded = stream or _embedded_stream(pdf, data or b"", media_type=media_type)
    spec = pdf.make_indirect(pikepdf.Dictionary())
    spec["/Type"] = pikepdf.Name("/Filespec")
    spec["/F"] = pikepdf.String(name)
    spec["/UF"] = pikepdf.String(name)
    spec["/Desc"] = pikepdf.String(description)
    spec["/AFRelationship"] = pikepdf.Name(f"/{relationship}")
    spec["/EF"] = pikepdf.Dictionary(F=embedded, UF=embedded)
    return spec


def _set_embedded_name_tree(pdf: pikepdf.Pdf, pairs: list[tuple[str, Any]]) -> None:
    """Install a deterministic catalog EmbeddedFiles name tree."""
    names = pdf.Root.get("/Names")
    if not isinstance(names, pikepdf.Dictionary):
        names = pikepdf.Dictionary()
        pdf.Root["/Names"] = names
    flat = pikepdf.Array()
    for logical_name, spec in sorted(pairs, key=lambda pair: pair[0]):
        flat.append(pikepdf.String(logical_name))
        flat.append(spec)
    names["/EmbeddedFiles"] = pikepdf.Dictionary(Names=flat)


def _xmp_stream(pdf: pikepdf.Pdf, xml: bytes):
    """Create one XMP metadata stream."""
    stream = pdf.make_stream(xml)
    stream["/Type"] = pikepdf.Name("/Metadata")
    stream["/Subtype"] = pikepdf.Name("/XML")
    return stream


def _minimal(path: Path, *, version: str) -> None:
    """Write a minimal one-page PDF at the requested wrapper version."""
    pdf, _page = _new_pdf()
    _save(pdf, path, version=version)
    pdf.close()


def _package_mechanisms(path: Path) -> None:
    """Write metadata and every generic V1 package discovery mechanism."""
    pdf, page = _new_pdf()
    shared_xml = b'<handover xmlns="urn:validibot:fixture"><id>A-1</id></handover>'
    shared_spec = _file_spec(
        pdf,
        name="handover.xml",
        data=shared_xml,
        media_type="application/xml",
        relationship="Data",
    )
    rich_json_spec = _file_spec(
        pdf,
        name="asset-index.json",
        data=b'{"asset":"A-1"}',
        media_type="application/json",
        relationship="Supplement",
    )
    _set_embedded_name_tree(pdf, [("handover.xml", shared_spec)])

    pdf.Root["/AF"] = pikepdf.Array([shared_spec])
    page.obj["/AF"] = pikepdf.Array([shared_spec])
    file_annotation = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"),
            Subtype=pikepdf.Name("/FileAttachment"),
            Rect=pikepdf.Array([10, 10, 30, 30]),
            FS=shared_spec,
            AF=pikepdf.Array([shared_spec]),
        )
    )

    rich_media_content = pdf.make_indirect(
        pikepdf.Dictionary(
            Assets=pikepdf.Dictionary(
                Names=pikepdf.Array([pikepdf.String("asset-index"), rich_json_spec])
            ),
            Configurations=pikepdf.Array(),
        )
    )
    rich_annotation = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"),
            Subtype=pikepdf.Name("/RichMedia"),
            Rect=pikepdf.Array([40, 10, 80, 40]),
            RichMediaContent=rich_media_content,
        )
    )
    three_d_stream = pdf.make_stream(b"U3D synthetic inert fixture")
    three_d_stream["/Subtype"] = pikepdf.Name("/U3D")
    three_d_annotation = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"),
            Subtype=pikepdf.Name("/3D"),
            Rect=pikepdf.Array([90, 10, 130, 40]),
            **{"3DD": three_d_stream},
        )
    )
    page.obj["/Annots"] = pikepdf.Array([file_annotation, rich_annotation, three_d_annotation])

    structure_element = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/StructElem"),
            S=pikepdf.Name("/Div"),
            AF=pikepdf.Array([shared_spec]),
        )
    )
    pdf.Root["/StructTreeRoot"] = pikepdf.Dictionary(
        Type=pikepdf.Name("/StructTreeRoot"),
        K=pikepdf.Array([structure_element]),
    )
    form_xobject = pdf.make_stream(b"q Q")
    form_xobject["/Type"] = pikepdf.Name("/XObject")
    form_xobject["/Subtype"] = pikepdf.Name("/Form")
    form_xobject["/BBox"] = pikepdf.Array([0, 0, 10, 10])
    form_xobject["/AF"] = pikepdf.Array([shared_spec])
    page.obj["/Resources"] = pikepdf.Dictionary(
        XObject=pikepdf.Dictionary(FixtureForm=form_xobject),
        Properties=pikepdf.Dictionary(
            FixtureProperty=pikepdf.Dictionary(AF=pikepdf.Array([shared_spec]))
        ),
    )

    document_xmp = (
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
        b'xmlns:pdfd="http://pdfa.org/declarations/">'
        b'<rdf:Description rdf:about="">'
        b"<pdfd:declarations><rdf:Bag><rdf:li>urn:validibot:fixture:profile:v1"
        b"</rdf:li></rdf:Bag></pdfd:declarations>"
        b"</rdf:Description></rdf:RDF></x:xmpmeta>"
    )
    pdf.Root["/Metadata"] = _xmp_stream(pdf, document_xmp)
    page.obj["/Metadata"] = _xmp_stream(
        pdf,
        b'<m:metadata xmlns:m="urn:validibot:fixture:object"><m:id>page-1</m:id></m:metadata>',
    )
    pdf.Root["/Extensions"] = pikepdf.Dictionary(
        ISO_=pikepdf.Dictionary(
            BaseVersion=pikepdf.Name("/2.0"),
            ExtensionLevel=1,
            URL=pikepdf.String("https://example.invalid/never-fetched"),
        )
    )
    pdf.Root["/Requirements"] = pikepdf.Array(
        [
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Requirement"),
                S=pikepdf.Name("/FixtureRequirement"),
            )
        ]
    )
    pdf.Root["/Collection"] = pikepdf.Dictionary(
        Type=pikepdf.Name("/Collection"),
        View=pikepdf.Name("/D"),
    )
    _save(pdf, path, version="2.0")
    pdf.close()


def _static_text_package(path: Path) -> None:
    """Write the positive fixture for every allowed V1 carrier and route."""
    pdf, page = _new_pdf()
    xml_spec = _file_spec(
        pdf,
        name="handover.xml",
        data=b'<handover xmlns="urn:validibot:fixture"><id>A-1</id></handover>',
        media_type="application/xml",
        relationship="Data",
    )
    json_spec = _file_spec(
        pdf,
        name="asset-index.json",
        data=b'{"asset":"A-1"}',
        media_type="application/json",
        relationship="Supplement",
    )
    step_spec = _file_spec(
        pdf,
        name="assembly.p21",
        data=(
            b"ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('AP242_FIXTURE'));\nENDSEC;\n"
            b"DATA;\nENDSEC;\nEND-ISO-10303-21;\n"
        ),
        media_type="model/step",
        relationship="Data",
    )
    _set_embedded_name_tree(
        pdf,
        [
            ("asset-index.json", json_spec),
            ("assembly.p21", step_spec),
            ("handover.xml", xml_spec),
        ],
    )
    pdf.Root["/AF"] = pikepdf.Array([xml_spec])
    page.obj["/AF"] = pikepdf.Array([step_spec])
    file_annotation = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"),
            Subtype=pikepdf.Name("/FileAttachment"),
            Rect=pikepdf.Array([10, 10, 30, 30]),
            FS=json_spec,
            AF=pikepdf.Array([json_spec]),
        )
    )
    page.obj["/Annots"] = pikepdf.Array([file_annotation])
    pdf.Root["/Metadata"] = _xmp_stream(
        pdf,
        (
            b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
            b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            b'<rdf:Description rdf:about="" xmlns:vb="urn:validibot:fixture">'
            b"<vb:policy>static_text_package_v1</vb:policy>"
            b"</rdf:Description></rdf:RDF></x:xmpmeta>"
        ),
    )
    _save(pdf, path, version="2.0")
    pdf.close()


def _typed_and_hazardous_members(path: Path) -> None:
    """Write carrier, MIME, duplicate-name, and filename-hazard coverage."""
    pdf, _page = _new_pdf()
    nested_pdf = io.BytesIO()
    nested, _nested_page = _new_pdf()
    nested.save(
        nested_pdf,
        force_version="1.7",
        deterministic_id=True,
        object_stream_mode=pikepdf.ObjectStreamMode.disable,
    )
    nested.close()
    zip_payload = io.BytesIO()
    with zipfile.ZipFile(zip_payload, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo("readme.txt", date_time=(1980, 1, 1, 0, 0, 0))
        archive.writestr(info, b"synthetic fixture")

    specs: list[tuple[str, Any]] = []

    def add(logical_name: str, **kwargs) -> Any:
        spec = _file_spec(pdf, **kwargs)
        specs.append((logical_name, spec))
        return spec

    add(
        "xml-correct",
        name="handover.xml",
        data=b'<handover xmlns="urn:validibot:fixture"><id>A-1</id></handover>',
        media_type="application/xml",
    )
    add(
        "json-missing-mime",
        name="asset-index.json",
        data=b'{"asset":"A-1"}',
    )
    add(
        "step-correct",
        name="assembly.p21",
        data=(
            b"ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('AP242_FIXTURE'));\nENDSEC;\n"
            b"DATA;\nENDSEC;\nEND-ISO-10303-21;\n"
        ),
        media_type="model/step",
    )
    add(
        "nested-pdf",
        name="nested.pdf",
        data=nested_pdf.getvalue(),
        media_type="application/pdf",
    )
    add(
        "zip",
        name="archive.zip",
        data=zip_payload.getvalue(),
        media_type="application/zip",
    )
    add(
        "executable-looking",
        name="viewer.exe",
        data=b"MZ" + b"synthetic-not-executable" * 4,
        media_type="application/octet-stream",
    )
    add(
        "false-mime",
        name="unknown.bin",
        data=b"opaque fixture bytes",
        media_type="application/xml",
    )

    duplicate_a = add(
        "duplicate-name-a",
        name="duplicate.xml",
        data=b"<first/>",
        media_type="application/xml",
    )
    duplicate_b = add(
        "duplicate-name-b",
        name="duplicate.xml",
        data=b"<second/>",
        media_type="application/xml",
    )
    pdf.Root["/AF"] = pikepdf.Array([duplicate_a, duplicate_b])

    shared_stream = _embedded_stream(pdf, b"<conflict/>", media_type="application/xml")
    add(
        "conflicting-mime-a",
        name="conflicting.xml",
        stream=shared_stream,
        relationship="Data",
    )
    conflicting_stream = _embedded_stream(
        pdf,
        b"<conflict/>",
        media_type="text/plain",
    )
    conflicting_spec = _file_spec(
        pdf,
        name="conflicting.xml",
        stream=conflicting_stream,
        relationship="Alternative",
    )
    specs.append(("conflicting-mime-b", conflicting_spec))

    hazardous_names = [
        "../traversal.xml",
        "/absolute.xml",
        "C:\\drive.xml",
        "./dot.xml",
        "control\x01.xml",
        "bidi-\u202egnp.xml",
        "r\u00e9sum\u00e9.xml",
        "",
    ]
    for index, hazardous_name in enumerate(hazardous_names):
        add(
            f"hazard-{index:02d}",
            name=hazardous_name,
            data=f"hazard-{index}".encode(),
            media_type="application/octet-stream",
        )
    _set_embedded_name_tree(pdf, specs)
    _save(pdf, path, version="2.0")
    pdf.close()


def _interactive_and_signature(path: Path) -> None:
    """Write inert declarations for every V1 active-feature category."""
    pdf, page = _new_pdf()
    actions = []
    for action_name in [
        "JavaScript",
        "Launch",
        "SubmitForm",
        "ImportData",
        "ResetForm",
        "GoToR",
    ]:
        action = pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name(f"/{action_name}")))
        if action_name == "JavaScript":
            action["/JS"] = pikepdf.String("app.alert('must never execute')")
        else:
            action["/F"] = pikepdf.String("https://example.invalid/never-fetched")
        actions.append(action)
    uri_action = pdf.make_indirect(
        pikepdf.Dictionary(
            S=pikepdf.Name("/URI"),
            URI=pikepdf.String("https://example.invalid/never-fetched"),
        )
    )
    pdf.Root["/OpenAction"] = actions[0]
    pdf.Root["/AA"] = pikepdf.Dictionary(WC=actions[1])
    names = pikepdf.Dictionary(
        JavaScript=pikepdf.Dictionary(Names=pikepdf.Array([pikepdf.String("fixture"), actions[0]]))
    )
    pdf.Root["/Names"] = names
    xfa = pdf.make_stream(b"<xdp:xdp xmlns:xdp='http://ns.adobe.com/xdp/'/>")
    pdf.Root["/AcroForm"] = pikepdf.Dictionary(
        Fields=pikepdf.Array(),
        XFA=xfa,
    )
    annotations = []
    for position, action in enumerate([*actions[1:], uri_action]):
        annotations.append(
            pdf.make_indirect(
                pikepdf.Dictionary(
                    Type=pikepdf.Name("/Annot"),
                    Subtype=pikepdf.Name("/Link"),
                    Rect=pikepdf.Array([10, 10 + position * 5, 50, 14 + position * 5]),
                    A=action,
                )
            )
        )
    rich_annotation = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"),
            Subtype=pikepdf.Name("/RichMedia"),
            Rect=pikepdf.Array([60, 10, 100, 40]),
            RichMediaContent=pikepdf.Dictionary(
                Assets=pikepdf.Dictionary(Names=pikepdf.Array()),
            ),
            RichMediaSettings=pikepdf.Dictionary(
                Activation=pikepdf.Dictionary(Condition=pikepdf.Name("/PO"))
            ),
        )
    )
    annotations.append(rich_annotation)
    page.obj["/Annots"] = pikepdf.Array(annotations)
    external_spec = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/Filespec"),
            FS=pikepdf.Name("/URL"),
            F=pikepdf.String("https://example.invalid/external.bin"),
        )
    )
    pdf.Root["/FixtureExternalFile"] = external_spec
    signature = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/Sig"),
            Filter=pikepdf.Name("/Adobe.PPKLite"),
            SubFilter=pikepdf.Name("/adbe.pkcs7.detached"),
            ByteRange=pikepdf.Array([0, 100, 200, 300]),
            Name=pikepdf.String("Unverified fixture claim"),
        )
    )
    pdf.Root["/FixtureSignature"] = signature
    _save(pdf, path, version="2.0")
    pdf.close()
    _append_noop_incremental_revision(path)


def _append_noop_incremental_revision(path: Path) -> None:
    """Append a valid no-object incremental xref section for inventory coverage."""
    data = path.read_bytes()
    previous_match = re.search(rb"startxref\s+(\d+)\s+%%EOF\s*$", data)
    trailer_matches = list(re.finditer(rb"trailer\s*<<(.*?)>>", data, flags=re.DOTALL))
    if previous_match is None or not trailer_matches:
        raise RuntimeError("Classic xref trailer required for incremental fixture.")
    previous_xref = int(previous_match.group(1))
    trailer = trailer_matches[-1].group(1)
    root_match = re.search(rb"/Root\s+(\d+\s+\d+\s+R)", trailer)
    size_match = re.search(rb"/Size\s+(\d+)", trailer)
    if root_match is None or size_match is None:
        raise RuntimeError("Root and Size required for incremental fixture.")
    offset = len(data) + 1
    update = (
        b"\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size "
        + size_match.group(1)
        + b" /Root "
        + root_match.group(1)
        + b" /Prev "
        + str(previous_xref).encode()
        + b" >>\nstartxref\n"
        + str(offset).encode()
        + b"\n%%EOF\n"
    )
    path.write_bytes(data + update)


def _encrypted(path: Path, *, user_password: str) -> None:
    """Write one small encrypted PDF for empty and required password behavior."""
    pdf, _page = _new_pdf()
    spec = _file_spec(
        pdf,
        name="encrypted-data.xml",
        data=b"<encrypted-fixture/>",
        media_type="application/xml",
    )
    _set_embedded_name_tree(pdf, [("encrypted-data.xml", spec)])
    _save(
        pdf,
        path,
        version="1.7",
        encryption=pikepdf.Encryption(
            owner="owner-fixture-password",
            user=user_password,
            R=6,
            allow=pikepdf.Permissions(extract=False, print_highres=False),
        ),
    )
    pdf.close()


def _deep_cycle(path: Path) -> None:
    """Write a bounded indirect cycle behind a deliberately deep dictionary chain."""
    pdf, _page = _new_pdf()
    first = pdf.make_indirect(pikepdf.Dictionary(Level=0))
    current = first
    for level in range(1, 25):
        child = pdf.make_indirect(pikepdf.Dictionary(Level=level))
        current["/Next"] = child
        current = child
    current["/Back"] = first
    pdf.Root["/FixtureChain"] = first
    _save(pdf, path, version="2.0")
    pdf.close()


def _page_and_object_limits(path: Path) -> None:
    """Write a small multi-page document for low configured structural limits."""
    pdf, _page = _new_pdf()
    pdf.add_blank_page(page_size=(200, 200))
    pdf.Root["/FixtureObjects"] = pikepdf.Array(
        [pdf.make_indirect(pikepdf.Dictionary(Index=index)) for index in range(8)]
    )
    _save(pdf, path, version="2.0")
    pdf.close()


def _high_ratio_member(path: Path) -> None:
    """Write a safe-size member whose repetitive bytes compress beyond policy."""
    pdf, _page = _new_pdf()
    spec = _file_spec(
        pdf,
        name="high-ratio.txt",
        data=b"A" * 100_000,
        media_type="text/plain",
    )
    _set_embedded_name_tree(pdf, [("high-ratio.txt", spec)])
    _save(pdf, path, version="1.7", compress_streams=True)
    pdf.close()


def _excessive_filters(path: Path) -> None:
    """Write a short stream with an excessive declared filter chain."""
    pdf, _page = _new_pdf()
    stream = _embedded_stream(pdf, b"bounded filter fixture")
    stream["/Filter"] = pikepdf.Array([pikepdf.Name("/FlateDecode") for _index in range(65)])
    spec = _file_spec(pdf, name="filters.bin", stream=stream)
    _set_embedded_name_tree(pdf, [("filters.bin", spec)])
    _save(pdf, path, version="1.7", compress_streams=False)
    pdf.close()


def _parser_warning(path: Path) -> None:
    """Write a readable PDF whose stream length causes a bounded qpdf warning."""
    pdf, page = _new_pdf()
    content = pdf.make_stream(b"q 1 0 0 1 0 0 cm Q")
    page.obj["/Contents"] = content
    _save(pdf, path, version="1.7", compress_streams=False)
    pdf.close()
    data = path.read_bytes()
    match = re.search(rb"/Length\s+(\d+)", data)
    if match is None:
        raise RuntimeError("Fixture content stream length was not serialized.")
    original = match.group(1)
    replacement = b"1".ljust(len(original), b"0")
    path.write_bytes(data[: match.start(1)] + replacement + data[match.end(1) :])


def _malformed_xref(source: Path, path: Path) -> None:
    """Corrupt the final startxref pointer without creating a large file."""
    data = source.read_bytes()
    matches = list(re.finditer(rb"startxref\s+(\d+)", data))
    if not matches:
        raise RuntimeError("Source fixture has no startxref marker.")
    match = matches[-1]
    original = match.group(1)
    replacement = b"9" * len(original)
    path.write_bytes(data[: match.start(1)] + replacement + data[match.end(1) :])


def _malformed_object_stream(path: Path) -> None:
    """Write a tiny invalid object-stream carrier for fail-closed parsing."""
    path.write_bytes(
        b"%PDF-1.7\n1 0 obj\n<< /Type /ObjStm /N 2 /First 999 /Length 3 >>\n"
        b"stream\nabc\nendstream\nendobj\nstartxref\n0\n%%EOF\n"
    )


def _descriptions() -> list[FixtureDescription]:
    """Return the reviewed manifest metadata in stable ID order."""
    inventory = ["pdf_inventory"]
    return [
        FixtureDescription(
            "minimal-pdf-1x",
            "golden/minimal-pdf-1.7.pdf",
            "1.7",
            ["minimal_document"],
            [],
            {"static_text_package_v1": []},
            {"static_text_package_v1": inventory},
        ),
        FixtureDescription(
            "minimal-pdf-2",
            "golden/minimal-pdf-2.0.pdf",
            "2.0",
            ["minimal_document"],
            [],
            {"static_text_package_v1": []},
            {"static_text_package_v1": inventory},
        ),
        FixtureDescription(
            "static-text-package",
            "golden/static-text-package.pdf",
            "2.0",
            [
                "document_xmp",
                "xml_json_step_members",
                "embedded_files_name_tree",
                "catalog_page_annotation_af",
                "file_attachment_annotation",
                "multi_path_same_stream",
            ],
            [],
            {"static_text_package_v1": []},
            {
                "static_text_package_v1": [
                    "pdf_inventory",
                    "xmp_metadata",
                    "extracted_files_bundle",
                    "selected_xml",
                    "selected_json",
                    "selected_step_p21",
                ]
            },
        ),
        FixtureDescription(
            "package-mechanisms",
            "golden/package-mechanisms.pdf",
            "2.0",
            [
                "document_xmp",
                "object_metadata",
                "pdf_declaration",
                "extensions",
                "requirements",
                "embedded_files_name_tree",
                "catalog_page_object_af",
                "file_attachment_annotation",
                "structure_element_af",
                "marked_content_property_af",
                "rich_media_assets",
                "three_d_stream",
                "collection",
                "multi_path_same_stream",
            ],
            ["unsupported_package_routes", "active_content"],
            {"static_text_package_v1": ["pdf.policy.static_text.*"]},
            {"static_text_package_v1": inventory},
        ),
        FixtureDescription(
            "typed-and-hazardous-members",
            "golden/typed-and-hazardous-members.pdf",
            "2.0",
            [
                "xml_json_step_members",
                "nested_pdf_zip_executable_unknown",
                "correct_missing_false_conflicting_mime",
                "duplicate_names",
                "unicode_bidi_control_absolute_drive_dot_traversal_empty_names",
            ],
            ["filename_hazards", "type_mismatch", "executable_content"],
            {
                "static_text_package_v1": [
                    "pdf.policy.static_text.unsupported_member_type",
                    "pdf.policy.static_text.declared_type_mismatch",
                    "pdf.policy.static_text.duplicate_name",
                    "pdf.policy.static_text.unsafe_filename",
                ]
            },
            {"static_text_package_v1": inventory},
        ),
        FixtureDescription(
            "interactive-signature-incremental",
            "golden/interactive-signature-incremental.pdf",
            "2.0",
            [
                "javascript_xfa_uri_launch_submit_import_reset_remote_goto",
                "automatic_rich_media_activation",
                "external_file_specification",
                "signature_dictionary",
                "incremental_revision",
            ],
            ["active_content", "external_reference"],
            {"static_text_package_v1": ["pdf.policy.static_text.*"]},
            {"static_text_package_v1": inventory},
        ),
        FixtureDescription(
            "empty-user-password",
            "golden/empty-user-password.pdf",
            "1.7",
            ["standard_encryption", "empty_user_password", "permission_inventory"],
            [],
            {"static_text_package_v1": ["pdf.policy.static_text.encryption"]},
            {"static_text_package_v1": inventory},
            deterministic=False,
        ),
        FixtureDescription(
            "password-required",
            "hostile/password-required.pdf",
            "1.7",
            ["standard_encryption", "user_password_required"],
            ["password_required"],
            {"static_text_package_v1": ["pdf.policy.static_text.encryption"]},
            {"static_text_package_v1": inventory},
            deterministic=False,
        ),
        FixtureDescription(
            "deep-cycle",
            "hostile/deep-cycle.pdf",
            "2.0",
            ["deep_indirect_graph", "cycle"],
            ["configured_object_depth_exhaustion"],
            {"low_object_depth": ["pdf.limit.object_depth"]},
            {"low_object_depth": inventory},
        ),
        FixtureDescription(
            "page-and-object-limits",
            "hostile/page-and-object-limits.pdf",
            "2.0",
            ["multiple_pages", "multiple_indirect_objects"],
            ["configured_page_limit", "configured_object_limit"],
            {
                "low_page_limit": ["pdf.limit.pages"],
                "low_object_limit": ["pdf.limit.objects"],
            },
            {"low_page_limit": inventory, "low_object_limit": inventory},
        ),
        FixtureDescription(
            "high-decode-ratio",
            "hostile/high-decode-ratio.pdf",
            "1.7",
            ["flate_encoded_embedded_stream"],
            ["bounded_decompression_ratio"],
            {"static_text_package_v1": ["pdf.limit.decode_ratio"]},
            {"static_text_package_v1": inventory},
        ),
        FixtureDescription(
            "excessive-filters",
            "hostile/excessive-filters.pdf",
            "1.7",
            ["embedded_stream_filter_chain"],
            ["excessive_filters"],
            {"static_text_package_v1": ["pdf.policy.static_text.member_stream_filter"]},
            {"static_text_package_v1": inventory},
        ),
        FixtureDescription(
            "parser-warning",
            "hostile/parser-warning.pdf",
            "1.7",
            ["incorrect_stream_length"],
            ["parser_warning_without_recovery"],
            {"static_text_package_v1": ["pdf.structure.parser_warning"]},
            {"static_text_package_v1": inventory},
        ),
        FixtureDescription(
            "malformed-xref",
            "hostile/malformed-xref.pdf",
            "1.7",
            ["cross_reference_pointer"],
            ["malformed_xref"],
            {"static_text_package_v1": ["pdf.structure.invalid"]},
            {"static_text_package_v1": inventory},
        ),
        FixtureDescription(
            "malformed-object-stream",
            "hostile/malformed-object-stream.pdf",
            "1.7",
            ["object_stream", "trailer"],
            ["malformed_object_stream", "malformed_trailer"],
            {"static_text_package_v1": ["pdf.structure.invalid"]},
            {"static_text_package_v1": inventory},
        ),
    ]


def _generate_files() -> None:
    """Generate every reviewed fixture before hashing the corpus."""
    GOLDEN.mkdir(parents=True, exist_ok=True)
    HOSTILE.mkdir(parents=True, exist_ok=True)
    _minimal(GOLDEN / "minimal-pdf-1.7.pdf", version="1.7")
    _minimal(GOLDEN / "minimal-pdf-2.0.pdf", version="2.0")
    _static_text_package(GOLDEN / "static-text-package.pdf")
    _package_mechanisms(GOLDEN / "package-mechanisms.pdf")
    _typed_and_hazardous_members(GOLDEN / "typed-and-hazardous-members.pdf")
    _interactive_and_signature(GOLDEN / "interactive-signature-incremental.pdf")
    _encrypted(GOLDEN / "empty-user-password.pdf", user_password="")
    _encrypted(HOSTILE / "password-required.pdf", user_password="reader-fixture-password")
    _deep_cycle(HOSTILE / "deep-cycle.pdf")
    _page_and_object_limits(HOSTILE / "page-and-object-limits.pdf")
    _high_ratio_member(HOSTILE / "high-decode-ratio.pdf")
    _excessive_filters(HOSTILE / "excessive-filters.pdf")
    _parser_warning(HOSTILE / "parser-warning.pdf")
    _malformed_xref(
        GOLDEN / "minimal-pdf-1.7.pdf",
        HOSTILE / "malformed-xref.pdf",
    )
    _malformed_object_stream(HOSTILE / "malformed-object-stream.pdf")


def _write_manifest(descriptions: list[FixtureDescription]) -> None:
    """Hash exact distributed bytes and write canonical provenance metadata."""
    fixtures = []
    for description in descriptions:
        path = FIXTURE_ROOT / description.relative_path
        data = path.read_bytes()
        fixtures.append(
            {
                "fixture_id": description.fixture_id,
                "path": description.relative_path,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
                "pdf_version": description.pdf_version,
                "mechanisms": description.mechanisms,
                "hazards": description.hazards,
                "expected_findings": description.expected_findings,
                "expected_artifacts": description.expected_artifacts,
                "provenance": "Repository-owned synthetic fixture generated from reviewed code.",
                "author": CORPUS_AUTHOR,
                "license": CORPUS_LICENSE,
                "synthetic": True,
                "derived_from": None,
                "redistributable": True,
                "redistribution_restriction": "",
                "generator": {
                    "id": GENERATOR_ID,
                    "version": GENERATOR_VERSION,
                    "script": "generate.py",
                    "pikepdf": pikepdf.__version__,
                    "qpdf": pikepdf.__libqpdf_version__,
                    "deterministic": description.deterministic,
                },
            }
        )
    manifest = {
        "schema_version": "validibot.pdf_test_corpus.v1",
        "corpus_version": "2.0.0",
        "generated_by": f"{GENERATOR_ID}/{GENERATOR_VERSION}",
        "fixtures": fixtures,
    }
    (FIXTURE_ROOT / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    """Regenerate exact fixtures and their digest-pinned manifest."""
    _generate_files()
    _write_manifest(_descriptions())


if __name__ == "__main__":
    main()
