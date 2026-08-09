"""Saxon Schematron worker — transpile the .sch, run it, write the SVRL.

Executed by ``engine.run_schematron`` via
``python -m validator_backends.schematron.saxon_worker <sch> <xml> <out>``
so the parent can enforce a **hard wall-clock timeout** over the whole
compile-and-run: SaxonC executes native code that Python signals cannot
interrupt, but a subprocess can always be killed. A worker crash (Saxon
abort, OOM) also stays contained — the parent maps it to the D9
engine-error taxonomy instead of taking the whole container down.

Compilation is the SchXslt2 transpiler (vendored under ``schxslt2/`` as
fixed engine tooling, like pyshacl is for SHACL — see its README for
provenance and upgrade instructions):

    .sch → transpile.xsl → (XSLT 3.0 validation stylesheet)
         → run over the submission → SVRL

SchXslt2 (MIT, <https://codeberg.org/SchXslt/schxslt2>) is the maintained
successor to both the classic ISO "skeleton" and SchXslt 1 — one
stylesheet that assembles includes, expands abstract patterns, and emits
the SVRL-producing XSLT in a single pass, run here under SaxonC-HE.

Security posture (ADR-2026-07-01 D8b): the author's rules get no ambient
authority. Python reads only the three explicit source paths, validates the two
untrusted XML documents with ``defusedxml``, and passes decoded text to Saxon.
Saxon's URI protocols are disabled before it parses or compiles anything, so
author rules never receive ``file:`` or network authority. The hard boundary
remains the container itself: no network egress, read-only rootfs, and a
locked-down service account.

Exit codes: 0 = SVRL written; 3 = the .sch failed to COMPILE (an authoring
problem → ``rules_invalid``); 2 = any other transform error.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from defusedxml import ElementTree as SafeET
from defusedxml.common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden


# The vendored transpiler (see schxslt2/README.md).
SCHXSLT2_DIR = Path(__file__).parent / "schxslt2"
TRANSPILER_STYLESHEET = "transpile.xsl"

# SaxonC 13 applies ``allowedProtocols`` to explicit ``*_file`` API inputs as
# well as XSLT retrieval functions. All Saxon inputs are therefore supplied as
# strings or XDM nodes, allowing the processor to remain at an empty protocol
# set for its entire lifetime.
ALLOW_EXTERNAL_FUNCTIONS_PROPERTY = "http://saxon.sf.net/feature/allow-external-functions"
ALLOWED_PROTOCOLS_PROPERTY = "http://saxon.sf.net/feature/allowedProtocols"
XINCLUDE_NS = "http://www.w3.org/2001/XInclude"
XINCLUDE_TAGS = {
    f"{{{XINCLUDE_NS}}}include",
    f"{{{XINCLUDE_NS}}}fallback",
}
XML_ENCODING_DECLARATION = re.compile(
    rb"encoding\s*=\s*['\"]([A-Za-z][A-Za-z0-9._-]*)['\"]",
)

EXIT_OK = 0
EXIT_TRANSFORM_ERROR = 2
EXIT_COMPILE_ERROR = 3
EXPECTED_ARG_COUNT = 3


class XMLSourceError(ValueError):
    """An authorized source path did not contain safe, decodable XML."""


def _decode_xml_bytes(payload: bytes) -> str:
    """Decode XML bytes according to their BOM, byte order, or declaration.

    SaxonC's in-memory API requires ``str`` rather than bytes. This implements
    XML's common encoding detection forms so disabling Saxon file access does
    not silently narrow submissions to UTF-8 only.
    """
    signatures = (
        (b"\x00\x00\xfe\xff", "utf-32"),
        (b"\xff\xfe\x00\x00", "utf-32"),
        (b"\xfe\xff", "utf-16"),
        (b"\xff\xfe", "utf-16"),
        (b"\xef\xbb\xbf", "utf-8-sig"),
        (b"\x00\x00\x00<", "utf-32-be"),
        (b"<\x00\x00\x00", "utf-32-le"),
        (b"\x00<\x00?", "utf-16-be"),
        (b"<\x00?\x00", "utf-16-le"),
    )
    for signature, encoding in signatures:
        if payload.startswith(signature):
            return payload.decode(encoding)

    declaration = XML_ENCODING_DECLARATION.search(payload[:256])
    encoding = declaration.group(1).decode("ascii") if declaration else "utf-8"
    return payload.decode(encoding)


def _read_safe_xml_text(path: str) -> str:
    """Read one authorized XML path and reject active inclusion constructs."""
    try:
        payload = Path(path).read_bytes()
        root = SafeET.fromstring(payload, forbid_dtd=True)
        if any(element.tag in XINCLUDE_TAGS for element in root.iter()):
            raise XMLSourceError("XInclude instructions are forbidden")
        return _decode_xml_bytes(payload)
    except XMLSourceError:
        raise
    except (
        DTDForbidden,
        EntitiesForbidden,
        ExternalReferenceForbidden,
        SafeET.ParseError,
        LookupError,
        OSError,
        UnicodeError,
    ) as exc:
        raise XMLSourceError(str(exc)) from exc


def run(sch_path: str, xml_path: str, output_path: str) -> int:
    """Transpile the Schematron source, run it, write the SVRL report."""
    from saxonche import PySaxonApiError, PySaxonProcessor

    try:
        with PySaxonProcessor(license=False) as processor:
            processor.set_configuration_property(
                ALLOW_EXTERNAL_FUNCTIONS_PROPERTY,
                "false",
            )
            processor.set_configuration_property(ALLOWED_PROTOCOLS_PROPERTY, "")
            try:
                schematron_node = processor.parse_xml(
                    xml_text=_read_safe_xml_text(sch_path),
                )
            except (PySaxonApiError, XMLSourceError) as exc:
                print(
                    f"saxon_worker: schematron compile failed: {exc}",
                    file=sys.stderr,
                )
                return EXIT_COMPILE_ERROR
            try:
                submission_node = processor.parse_xml(
                    xml_text=_read_safe_xml_text(xml_path),
                )
            except (PySaxonApiError, XMLSourceError) as exc:
                print(
                    f"saxon_worker: submission parse failed: {exc}",
                    file=sys.stderr,
                )
                return EXIT_TRANSFORM_ERROR

            xslt = processor.new_xslt30_processor()
            transpiler = xslt.compile_stylesheet(
                stylesheet_text=(SCHXSLT2_DIR / TRANSPILER_STYLESHEET).read_text(
                    encoding="utf-8",
                ),
            )

            # ── Compile: transpile the .sch into its validation stylesheet ──
            # BOTH the transpile and the compile of its output count as the
            # "compile" phase: a malformed schema fails the transpile, while
            # a bad XPath inside a rule only surfaces when Saxon compiles
            # the generated stylesheet. Either way the author's rules are at
            # fault (rules_invalid), not the engine. The intermediate stays in
            # memory so it cannot acquire ambient filesystem authority.
            try:
                validation_source = transpiler.transform_to_string(
                    xdm_node=schematron_node,
                )
                if validation_source is None:
                    print(
                        "saxon_worker: transpile produced no output",
                        file=sys.stderr,
                    )
                    return EXIT_COMPILE_ERROR
                executable = xslt.compile_stylesheet(
                    stylesheet_text=validation_source,
                )
            except PySaxonApiError as exc:
                print(
                    f"saxon_worker: schematron compile failed: {exc}",
                    file=sys.stderr,
                )
                return EXIT_COMPILE_ERROR

            # ── Run: execute the compiled rules over the submission ──
            svrl = executable.transform_to_string(xdm_node=submission_node)
    except PySaxonApiError as exc:
        print(f"saxon_worker: transform failed: {exc}", file=sys.stderr)
        return EXIT_TRANSFORM_ERROR

    if svrl is None:
        print("saxon_worker: transform produced no output", file=sys.stderr)
        return EXIT_TRANSFORM_ERROR

    Path(output_path).write_text(svrl, encoding="utf-8")
    return EXIT_OK


def main(argv: list[str]) -> int:
    """Parse the three fixed positional arguments and run one transform.

    This is the subprocess entrypoint, not a container entrypoint. It exists as a
    separate process because SaxonC is native code that cannot be interrupted
    in-process — a wall-clock timeout is only enforceable by killing something.
    The parent in ``engine.py`` supplies the arguments and reads the exit code,
    so argument handling is deliberately positional and rigid rather than
    user-friendly.

    Returns one of the ``EXIT_*`` codes, which the parent maps to distinct
    outcomes — most importantly separating a compile failure in the author's
    rules from a generic engine error.
    """
    if len(argv) != EXPECTED_ARG_COUNT:
        print(
            "usage: python -m validator_backends.schematron.saxon_worker "
            "<sch_path> <xml_path> <output_path>",
            file=sys.stderr,
        )
        return EXIT_TRANSFORM_ERROR
    return run(argv[0], argv[1], argv[2])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
