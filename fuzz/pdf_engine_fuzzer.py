"""Coverage-guided harness for Validibot's untrusted PDF inspection path.

The upstream qpdf project fuzzes its native parser. This harness adds coverage
for Validibot-owned traversal, inventory, selector-independent extraction, and
failure-envelope logic around that parser. Every iteration uses low domain
limits and a fresh attempt directory; the workflow adds outer libFuzzer time,
RSS, per-input timeout, and maximum-input-size limits.
"""

from __future__ import annotations

import itertools
import shutil
import sys
import tempfile
from pathlib import Path

import atheris


with atheris.instrument_imports():
    from validator_backends.pdf.engine import inspect_pdf
    from validibot_shared.pdf import PdfInputs, PdfProcessingLimits


_ROOT = Path(tempfile.mkdtemp(prefix="validibot-pdf-fuzz-"))
_SEQUENCE = itertools.count()
_MAX_FUZZ_INPUT_BYTES = 2 * 1024 * 1024
_FUZZ_INPUTS = PdfInputs(
    limits=PdfProcessingLimits(
        max_input_bytes=_MAX_FUZZ_INPUT_BYTES,
        max_pages=100,
        max_objects=10_000,
        max_object_depth=32,
        max_member_references=25,
        max_member_bytes=1024 * 1024,
        max_total_member_bytes=2 * 1024 * 1024,
        max_decode_ratio=100,
        max_xmp_bytes=512 * 1024,
        max_action_entries=1_000,
        max_findings=200,
        max_inventory_bytes=100_000,
        max_output_bundle_bytes=2 * 1024 * 1024,
        max_execution_seconds=2,
    )
)


def test_one_input(data: bytes) -> None:
    """Run one mutated PDF through the bounded production engine."""
    if not data or len(data) > _MAX_FUZZ_INPUT_BYTES:
        return
    case_root = _ROOT / f"case-{next(_SEQUENCE)}"
    case_root.mkdir()
    source = case_root / "input.pdf"
    source.write_bytes(data)
    try:
        inspect_pdf(
            source,
            source_name="fuzz.pdf",
            inputs=_FUZZ_INPUTS,
            workspace=case_root / "inspection",
        )
    finally:
        shutil.rmtree(case_root, ignore_errors=True)


def main() -> None:
    """Start libFuzzer with the repository corpus supplied by the caller."""
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
