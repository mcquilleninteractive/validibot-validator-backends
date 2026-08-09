"""Bounded generated properties for Validibot-owned PDF helper logic.

qpdf carries its own parser fuzzing. This suite instead generates many small,
deterministic cases around the code Validibot owns: filename handling, exact
selector semantics, safe extensions, deterministic bundle ordering, and
cycle/depth termination. Fixed seeds and strict size bounds keep it suitable
for ordinary CI while still exploring combinations beyond named examples.
"""

from __future__ import annotations

import hashlib
import random
import string
import time
import zipfile
from io import BytesIO
from pathlib import Path

import pikepdf

from validator_backends.pdf.engine import (
    _build_bundle,
    _file_spec_name,
    _filename_risks,
    _MemberRecord,
    _safe_extension,
    _selector_matches,
    inspect_pdf,
)
from validibot_shared.pdf import PdfInputs, PdfPayloadSelector, PdfProcessingLimits
from validibot_shared.validations.envelopes import ValidationStatus


FIXTURE_ROOT = Path(__file__).parent / "fixtures"
GENERATED_CASE_COUNT = 300
PROPERTY_TIMEOUT_SECONDS = 5


def _record(data: bytes, *, name: str, media_type: str) -> _MemberRecord:
    """Build one internal record with its digest and exact selector metadata."""
    record = _MemberRecord(
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        detected_media_type=media_type,
    )
    record.original_names.add(name)
    record.discovery_kinds.add("file_specification")
    return record


def test_generated_file_spec_names_round_trip_as_evidence() -> None:
    """Bounded Unicode names decode as data and are never normalized into paths."""
    randomizer = random.Random(24064)
    alphabet = string.ascii_letters + string.digits + " ./\\:\u202e\u00e9\x01"
    started = time.monotonic()

    for _case in range(GENERATED_CASE_COUNT):
        name = "".join(randomizer.choice(alphabet) for _index in range(32))
        spec = pikepdf.Dictionary(UF=pikepdf.String(name), F=pikepdf.String("fallback"))
        assert _file_spec_name(spec) == name.replace("\x00", "�")
        risks = _filename_risks(name)
        assert risks <= {
            "filename_empty",
            "filename_dot_segment",
            "filename_path_hazard",
            "filename_absolute_path",
            "filename_drive_prefix",
            "filename_control_character",
            "filename_bidi_control",
            "filename_unicode",
        }

    assert time.monotonic() - started < PROPERTY_TIMEOUT_SECONDS


def test_generated_exact_selectors_never_match_a_different_name() -> None:
    """Exact selection is equality-based and independent of traversal ordering."""
    randomizer = random.Random(32000)

    for case in range(GENERATED_CASE_COUNT):
        expected_name = f"member-{case}-{randomizer.randrange(1_000_000)}.xml"
        other_name = f"other-{case}-{randomizer.randrange(1_000_000)}.xml"
        record = _record(b"<fixture/>", name=expected_name, media_type="application/xml")
        assert _selector_matches(
            record,
            PdfPayloadSelector(original_filename=expected_name),
        )
        assert not _selector_matches(
            record,
            PdfPayloadSelector(original_filename=other_name),
        )


def test_generated_bundle_order_is_independent_of_record_insertion() -> None:
    """Hash ordering and normalized ZIP metadata make shuffled inputs identical."""
    randomizer = random.Random(16684)
    records = [
        _record(
            f"payload-{index}".encode(),
            name=f"../../member-{index}.xml",
            media_type="application/xml",
        )
        for index in range(20)
    ]
    expected = _build_bundle({record.sha256: record for record in records})

    for _case in range(50):
        randomizer.shuffle(records)
        candidate = _build_bundle({record.sha256: record for record in records})
        assert candidate == expected

    with zipfile.ZipFile(BytesIO(expected)) as archive:
        assert archive.namelist()[0] == "manifest.json"
        assert all(
            name == "manifest.json" or name.startswith("files/") for name in archive.namelist()
        )


def test_safe_extensions_depend_only_on_detected_carrier() -> None:
    """Generated hostile names cannot influence derived output leaf extensions."""
    randomizer = random.Random(19005)
    expected = {
        "application/xml": ".xml",
        "application/json": ".json",
        "application/pdf": ".pdf",
        "application/zip": ".zip",
        "model/step": ".p21",
        "application/octet-stream": ".bin",
    }
    for media_type, extension in expected.items():
        for case in range(30):
            name = f"../{randomizer.randrange(1_000_000)}.{case}.exe"
            record = _record(b"fixture", name=name, media_type=media_type)
            assert _safe_extension(record) == extension


def test_deep_cyclic_graph_terminates_under_default_and_low_depth_limits() -> None:
    """Cycle detection finishes quickly and depth exhaustion cannot pass silently."""
    path = FIXTURE_ROOT / "hostile" / "deep-cycle.pdf"
    started = time.monotonic()

    ordinary = inspect_pdf(path, source_name=path.name, inputs=PdfInputs())
    exhausted = inspect_pdf(
        path,
        source_name=path.name,
        inputs=PdfInputs(limits=PdfProcessingLimits(max_object_depth=8)),
    )

    assert time.monotonic() - started < PROPERTY_TIMEOUT_SECONDS
    assert ordinary.status == ValidationStatus.SUCCESS
    assert exhausted.status == ValidationStatus.FAILED_VALIDATION
    assert any(message.code == "pdf.limit.object_depth" for message in exhausted.messages)
