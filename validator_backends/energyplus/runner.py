"""
EnergyPlus simulation runner.

Handles downloading input files, running EnergyPlus, and extracting results.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from validator_backends.core.scratch import attempt_scratch_base
from validator_backends.core.storage_client import (
    create_attempt_work_dir,
    download_verified_file,
)
from validibot_shared.energyplus.envelopes import EnergyPlusOutputs
from validibot_shared.energyplus.models import (
    STDOUT_TAIL_CHARS,
    EnergyPlusSimulationLogs,
    EnergyPlusSimulationMetrics,
    EnergyPlusSimulationOutputs,
)


if TYPE_CHECKING:
    from validibot_shared.energyplus.envelopes import EnergyPlusInputEnvelope

logger = logging.getLogger(__name__)

GJ_TO_KWH = 1_000_000_000.0 / 3_600_000.0

REQUIRED_SQL_SUMMARY_REPORTS = (
    "AnnualBuildingUtilityPerformanceSummary",
    "DemandEndUseComponentsSummary",
)
ALL_SUMMARY_REPORTS = frozenset(
    {
        "allsummary",
        "allsummaryandmonthly",
        "allsummaryandsizingperiod",
        "allsummarymonthlyandsizingperiod",
    }
)


@dataclass(frozen=True)
class EnergyPlusInstallationEvidence:
    """Identity of the EnergyPlus executable and bundled IDD used for a run.

    Two artifacts decide what an EnergyPlus run means, and both are recorded
    because either one being wrong corrupts the result in a different way:

    - The **binary** performs the simulation.
    - The **IDD** (Input Data Dictionary) is the schema the binary uses to parse
      the model. It ships beside the executable and is located relative to it.

    An IDD from a different release than the binary is the dangerous case,
    because it usually fails *quietly*: fields shift position between versions,
    so a model can parse cleanly and simulate to completion while meaning
    something other than what its author wrote. ``_versions_match`` therefore
    compares model, binary, and IDD at major/minor precision, and this record is
    what makes that check possible. It also travels into the output envelope, so
    a stored result can later be attributed to an exact toolchain rather than to
    "EnergyPlus".

    The version fields are ``None`` when parsing fails — an unparsable version is
    recorded as unknown rather than guessed, and version comparison returns
    ``None`` (indeterminate) instead of a false match.

    Fields:
        binary_path: Resolved path to the ``energyplus`` executable found on
            ``PATH``.
        binary_version: Version parsed from ``energyplus --version``, or ``None``.
        binary_build: Build identifier from the same output, or ``None``. The
            build distinguishes two images of the same nominal version.
        idd_path: Path to ``Energy+.idd``, always resolved beside the binary so a
            stray IDD elsewhere on the image cannot be picked up.
        idd_version: Version parsed from the IDD header, or ``None``.
        idd_build: Build identifier from the IDD header, or ``None``.
    """

    binary_path: Path
    binary_version: str | None
    binary_build: str | None
    idd_path: Path
    idd_version: str | None
    idd_build: str | None


# ---------------------------------------------------------------------------
# Defense-in-depth: pre-run inspection of user-supplied model files
# ---------------------------------------------------------------------------
#
# WHY: EnergyPlus runs a native binary against an arbitrary, user-supplied
# IDF/epJSON model. Several first-class IDF object types are effectively code
# or external-resource loaders — they let a model author load shared
# libraries, reach out to the network/filesystem, or run interpreted code
# during the simulation:
#
#   * PythonPlugin:*                                  → loads & runs Python
#   * ExternalInterface (+ FMU import/export)         → loads FMU shared libs,
#                                                        opens sockets (BCVTB)
#   * EnergyManagementSystem:Program/Subroutine       → runs Erl runtime code
#   * Schedule:File pointing at an absolute/remote path → reads arbitrary files
#
# The sandboxed container is and remains the PRIMARY security boundary; this
# scan is defense-in-depth only. We reject by default so a malicious or
# accidentally-dangerous model cannot reach these capabilities even if the
# container's isolation is weakened or misconfigured. Operators with a
# legitimate need (e.g. trusted internal FMU co-simulation) can opt out via
# the ALLOW_UNSAFE_IDF_OBJECTS module constant.

# Off-by-default escape hatch. Set to True only in a deployment that fully
# trusts its model authors AND accepts that the container is the sole boundary.
ALLOW_UNSAFE_IDF_OBJECTS = False

# High-risk IDF/epJSON object-type tokens (matched case-insensitively as plain
# substrings against the raw model text). These map to capabilities that load
# code, load native libraries, open sockets, or read arbitrary files. The
# longer/more-specific tokens are intentionally listed so the reported reason
# is precise; the short prefixes catch the remaining variants.
UNSAFE_IDF_OBJECT_TOKENS = (
    "PythonPlugin",
    "ExternalInterface:FunctionalMockupUnitImport",
    "ExternalInterface:FunctionalMockupUnitExport",
    "ExternalInterface",
    "EnergyManagementSystem:Program",
    "EnergyManagementSystem:Subroutine",
)

# Schedule:File is only dangerous when it references an absolute or remote
# path (a relative path resolves inside the sandboxed work_dir). We flag it
# separately so an ordinary, in-work-dir Schedule:File is not rejected.
_SCHEDULE_FILE_TOKEN = "Schedule:File"
_REMOTE_PATH_PREFIXES = ("http://", "https://", "ftp://", "file://", "\\\\")

# Number of leading bytes of the model file to inspect. The header region of
# an IDF/epJSON is where object definitions live; capping the read keeps the
# scan cheap and bounded for very large generated models.
MODEL_SCAN_MAX_BYTES = 5_000_000


class UnsafeModelObjectError(ValueError):
    """Raised when a model file contains a high-risk IDF/epJSON object type.

    WHY: Signals that the defense-in-depth pre-run scan rejected the model
    before EnergyPlus was invoked. Subclasses ``ValueError`` so existing
    callers that treat input-validation failures as ``ValueError`` continue
    to handle it as a (non-retryable) bad-input condition.
    """


def _detect_unsafe_model_objects(model_text: str) -> str | None:
    """Return a human-readable reason if the model text uses an unsafe object.

    The scan is a conservative, case-insensitive substring match over the raw
    model text. It is intentionally coarse: it does not parse the IDF/epJSON
    grammar, so it errs toward flagging (false positives are acceptable;
    silently running dangerous objects is not).

    Args:
        model_text: Raw text of the IDF or epJSON model file.

    Returns:
        A short reason string describing the first unsafe object found, or
        ``None`` if no high-risk object types were detected.
    """
    lowered = model_text.lower()

    for token in UNSAFE_IDF_OBJECT_TOKENS:
        if token.lower() in lowered:
            return f"model references high-risk object type {token!r}"

    # Schedule:File is only flagged when its file-name field points outside the
    # work_dir, i.e. at an absolute path or a remote URL. A relative path
    # resolves inside the sandboxed work_dir and is fine. We extract each
    # Schedule:File *object body* (the text from the object type up to its
    # terminating ';') and inspect its comma-separated fields, so that an
    # absolute path in some unrelated object does not trigger a false positive.
    if _SCHEDULE_FILE_TOKEN.lower() in lowered:
        for body in _iter_object_bodies(model_text, _SCHEDULE_FILE_TOKEN):
            reason = _classify_schedule_file_path(body)
            if reason is not None:
                return reason

    return None


def _iter_object_bodies(model_text: str, object_type: str):
    """Yield the raw text of each IDF/epJSON object of ``object_type``.

    An IDF object starts with its type token and ends at the next ``;`` field
    terminator. This is a deliberately loose extractor (it also works on the
    flattened text of an epJSON file, where the field values still appear as
    substrings) used only to bound the region we inspect for unsafe paths.

    Args:
        model_text: Raw model text.
        object_type: The object type token to search for (e.g. ``Schedule:File``).

    Yields:
        The substring from each occurrence of ``object_type`` up to (and
        including) the next semicolon, or to end-of-text if none follows.
    """
    lowered = model_text.lower()
    needle = object_type.lower()
    start = lowered.find(needle)
    while start != -1:
        end = model_text.find(";", start)
        if end == -1:
            yield model_text[start:]
            return
        yield model_text[start : end + 1]
        start = lowered.find(needle, end + 1)


def _classify_schedule_file_path(object_body: str) -> str | None:
    """Return a reason if a Schedule:File object body uses an unsafe path.

    Each comma/semicolon-separated field of the object body is examined for a
    remote URL, an absolute POSIX path, or a Windows drive path. IDF comments
    run from ``!`` to end-of-line, so we strip them per physical line *before*
    splitting into fields — otherwise a comment on one line would swallow the
    field value on the next, hiding an absolute path and causing a dangerous
    false negative.

    Args:
        object_body: The raw text of one ``Schedule:File`` object.

    Returns:
        A reason string if an absolute/remote path is referenced, else ``None``.
    """
    # Strip end-of-line IDF comments line by line, then re-join.
    decommented = "\n".join(line.split("!", 1)[0] for line in object_body.splitlines())

    for raw_field in re.split(r"[,;]", decommented):
        field = raw_field.strip()
        if not field:
            continue
        lowered_field = field.lower()
        if any(prefix in lowered_field for prefix in _REMOTE_PATH_PREFIXES):
            return f"{_SCHEDULE_FILE_TOKEN} references a remote path"
        if field.startswith("/"):
            return f"{_SCHEDULE_FILE_TOKEN} references an absolute path"
        if re.match(r"[A-Za-z]:[\\/]", field):
            return f"{_SCHEDULE_FILE_TOKEN} references an absolute path"
    return None


def _scan_model_for_unsafe_objects(model_file: Path) -> None:
    """Reject a model file that contains high-risk IDF/epJSON object types.

    This is a defense-in-depth check that runs BEFORE the EnergyPlus binary is
    invoked. The sandboxed container remains the primary security boundary;
    this scan adds a cheap second layer so a model that loads code, loads
    native libraries, opens sockets, or reads arbitrary files cannot reach
    those capabilities by default.

    Set the module constant ``ALLOW_UNSAFE_IDF_OBJECTS = True`` to bypass the
    check in a deployment that fully trusts its model authors.

    Args:
        model_file: Path to the downloaded IDF or epJSON model file.

    Raises:
        UnsafeModelObjectError: If an unsafe object type is detected and
            ``ALLOW_UNSAFE_IDF_OBJECTS`` is False.
    """
    if ALLOW_UNSAFE_IDF_OBJECTS:
        logger.warning(
            "ALLOW_UNSAFE_IDF_OBJECTS is enabled; skipping model safety scan for %s",
            model_file,
        )
        return

    try:
        model_text = model_file.read_text(encoding="utf-8", errors="replace")[
            :MODEL_SCAN_MAX_BYTES
        ]
    except OSError as exc:
        # If we cannot read the model to inspect it, fail closed rather than
        # running an uninspected file through the native binary.
        raise UnsafeModelObjectError(
            f"Could not read model file for safety inspection: {model_file}",
        ) from exc

    reason = _detect_unsafe_model_objects(model_text)
    if reason is not None:
        logger.warning("Rejecting EnergyPlus model %s: %s", model_file, reason)
        raise UnsafeModelObjectError(
            "EnergyPlus model rejected by defense-in-depth safety scan: "
            f"{reason}. These object types can load code, load native "
            "libraries, open network sockets, or read arbitrary files. Set "
            "ALLOW_UNSAFE_IDF_OBJECTS=True only in a fully trusted deployment.",
        )


# ---------------------------------------------------------------------------
# Review-readiness evidence and private working-copy normalization
# ---------------------------------------------------------------------------


def _parse_energyplus_version(text: str) -> tuple[str | None, str | None]:
    """Parse the numeric version and optional build from ``--version`` text."""

    match = re.search(
        r"(?:EnergyPlus(?:\s*,)?\s*(?:Version\s*)?)?"
        r"(?P<version>\d+\.\d+(?:\.\d+)?)"
        r"(?:-(?P<build>[A-Za-z0-9._]+))?",
        text,
        re.IGNORECASE,
    )
    if not match:
        return None, None
    return match.group("version"), match.group("build")


def _parse_idd_metadata(idd_path: Path) -> tuple[str | None, str | None]:
    """Read ``!IDD_Version`` and ``!IDD_BUILD`` from the exact IDD file."""

    try:
        header = idd_path.read_text(encoding="utf-8", errors="replace")[:64_000]
    except OSError:
        logger.warning("Could not read EnergyPlus IDD metadata from %s", idd_path)
        return None, None

    version_match = re.search(
        r"^\s*!IDD_Version\s+([^\s!]+)",
        header,
        re.IGNORECASE | re.MULTILINE,
    )
    build_match = re.search(
        r"^\s*!IDD_BUILD\s+([^\s!]+)",
        header,
        re.IGNORECASE | re.MULTILINE,
    )
    return (
        version_match.group(1).strip() if version_match else None,
        build_match.group(1).strip() if build_match else None,
    )


def _collect_installation_evidence() -> EnergyPlusInstallationEvidence:
    """Locate the executable/IDD and collect the evidence used by this run."""

    binary = shutil.which("energyplus")
    if not binary:
        raise FileNotFoundError("EnergyPlus executable was not found on PATH")
    binary_path = Path(binary).resolve()
    idd_path = binary_path.parent / "Energy+.idd"
    if not idd_path.is_file():
        raise FileNotFoundError(
            f"Bundled EnergyPlus IDD was not found beside the executable: {idd_path}",
        )

    version_result = subprocess.run(
        [str(binary_path), "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    version_text = "\n".join(
        part for part in (version_result.stdout, version_result.stderr) if part
    )
    binary_version, binary_build = _parse_energyplus_version(version_text)
    idd_version, idd_build = _parse_idd_metadata(idd_path)
    return EnergyPlusInstallationEvidence(
        binary_path=binary_path,
        binary_version=binary_version,
        binary_build=binary_build,
        idd_path=idd_path,
        idd_version=idd_version,
        idd_build=idd_build,
    )


def _parse_model_version(model_file: Path) -> str | None:
    """Extract the EnergyPlus Version object from IDF or epJSON."""

    try:
        if model_file.suffix.lower() in {".epjson", ".json"}:
            payload = json.loads(model_file.read_text(encoding="utf-8"))
            versions = payload.get("Version") if isinstance(payload, dict) else None
            if isinstance(versions, dict):
                for value in versions.values():
                    if not isinstance(value, dict):
                        continue
                    identifier = value.get("version_identifier")
                    if identifier is not None and str(identifier).strip():
                        return str(identifier).strip()
            return None

        content = model_file.read_text(encoding="utf-8", errors="replace")
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None

    decommented = "\n".join(line.split("!", 1)[0] for line in content.splitlines())
    match = re.search(
        r"(?:^|;)\s*Version\s*,\s*([^,;\s]+)\s*;",
        decommented,
        re.IGNORECASE | re.MULTILINE,
    )
    return match.group(1).strip() if match else None


def _major_minor(version: str | None) -> tuple[int, int] | None:
    """Normalize a version string to the major/minor pair used by IDFs."""

    if not version:
        return None
    match = re.search(r"(\d+)\.(\d+)", version)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def _versions_match(
    idf_version: str | None,
    binary_version: str | None,
    idd_version: str | None,
) -> bool | None:
    """Compare the model, binary, and IDD at EnergyPlus major/minor precision."""

    model_pair = _major_minor(idf_version)
    binary_pair = _major_minor(binary_version)
    idd_pair = _major_minor(idd_version)
    if model_pair is None or binary_pair is None or idd_pair is None:
        return None
    return model_pair == binary_pair == idd_pair


def _idf_object_span(
    model_text: str,
    object_type: str,
) -> tuple[int, int, list[str]] | None:
    """Find one IDF object without treating comment semicolons as delimiters.

    The returned span begins at the object-type token and ends immediately
    after its terminating semicolon. Leading comments and indentation remain
    outside the span so normalization preserves the surrounding source context.
    """

    segment_start = 0
    in_comment = False
    for index, character in enumerate(model_text):
        if in_comment:
            if character in "\r\n":
                in_comment = False
            continue
        if character == "!":
            in_comment = True
            continue
        if character != ";":
            continue

        raw_segment = model_text[segment_start : index + 1]
        decommented_lines: list[str] = []
        object_start: int | None = None
        line_offset = 0
        for line in raw_segment.splitlines(keepends=True):
            code = line.split("!", 1)[0]
            decommented_lines.append(code)
            if object_start is None:
                token_match = re.search(r"\S", code)
                if token_match:
                    object_start = segment_start + line_offset + token_match.start()
            line_offset += len(line)

        decommented = "".join(decommented_lines)
        parts = [part.strip() for part in re.split(r"[,;]", decommented)]
        if parts and parts[0].casefold() == object_type.casefold():
            fields = [part for part in parts[1:] if part]
            if object_start is None:  # pragma: no cover - guarded by parsed object type
                return None
            object_end = index + 1
            trailing_comment = re.match(r"[ \t]*![^\r\n]*", model_text[object_end:])
            if trailing_comment:
                object_end += trailing_comment.end()
            return object_start, object_end, fields
        segment_start = index + 1

    return None


def _format_idf_object(object_type: str, fields: list[str]) -> str:
    """Render a small canonical IDF object for the private working copy."""

    lines = [f"{object_type},"]
    for index, field in enumerate(fields):
        terminator = ";" if index == len(fields) - 1 else ","
        lines.append(f"  {field}{terminator}")
    return "\n".join(lines)


def _replace_or_append_idf_object(
    model_text: str,
    object_type: str,
    fields: list[str],
) -> str:
    """Replace the first matching IDF object or append it when absent."""

    rendered = _format_idf_object(object_type, fields)
    existing = _idf_object_span(model_text, object_type)
    if existing is None:
        return model_text.rstrip() + f"\n\n{rendered}\n"
    start, end, _existing_fields = existing
    return f"{model_text[:start]}{rendered}{model_text[end:]}"


def _ensure_idf_sql_reporting(model_text: str) -> str:
    """Guarantee stable SI-unit tabular SQLite reports in an IDF model."""

    model_text = _replace_or_append_idf_object(
        model_text,
        "Output:SQLite",
        ["SimpleAndTabular", "None"],
    )

    existing = _idf_object_span(model_text, "Output:Table:SummaryReports")
    reports = list(existing[2]) if existing is not None else []
    normalized_reports = {report.casefold() for report in reports}
    if not normalized_reports.intersection(ALL_SUMMARY_REPORTS):
        for required_report in REQUIRED_SQL_SUMMARY_REPORTS:
            if required_report.casefold() not in normalized_reports:
                reports.append(required_report)
                normalized_reports.add(required_report.casefold())
    return _replace_or_append_idf_object(
        model_text,
        "Output:Table:SummaryReports",
        reports,
    )


def _first_epjson_instance(
    payload: dict[str, Any],
    object_type: str,
    default_name: str,
) -> dict[str, Any]:
    """Return or create the first instance of a singleton epJSON object."""

    instances = payload.get(object_type)
    if not isinstance(instances, dict) or not instances:
        instance: dict[str, Any] = {}
        payload[object_type] = {default_name: instance}
        return instance

    first_name = next(iter(instances))
    instance = instances[first_name]
    if not isinstance(instance, dict):
        instance = {}
        instances[first_name] = instance
    return instance


def _ensure_epjson_sql_reporting(payload: dict[str, Any]) -> None:
    """Guarantee stable SI-unit tabular SQLite reports in an epJSON model."""

    sqlite_output = _first_epjson_instance(
        payload,
        "Output:SQLite",
        "Validibot SQLite Output",
    )
    sqlite_output["option_type"] = "SimpleAndTabular"
    sqlite_output["unit_conversion_for_tabular_data"] = "None"

    summary_output = _first_epjson_instance(
        payload,
        "Output:Table:SummaryReports",
        "Validibot Summary Reports",
    )
    reports = summary_output.get("reports")
    if not isinstance(reports, list):
        reports = []
        summary_output["reports"] = reports

    normalized_reports = {
        str(report.get("report_name", "")).casefold()
        for report in reports
        if isinstance(report, dict)
    }
    if not normalized_reports.intersection(ALL_SUMMARY_REPORTS):
        for required_report in REQUIRED_SQL_SUMMARY_REPORTS:
            if required_report.casefold() not in normalized_reports:
                reports.append({"report_name": required_report})
                normalized_reports.add(required_report.casefold())


def _prepare_model_working_copy(
    model_file: Path,
    work_dir: Path,
    timestep_per_hour: int,
    *,
    run_simulation: bool,
) -> Path:
    """Create and normalize a private model copy without changing the source.

    Full simulations receive the SQLite and tabular-summary declarations that
    Validibot's post-processing contract requires. Conversion-only preflight
    changes only the timestep because EnergyPlus will not emit simulation SQL.
    """

    suffix = model_file.suffix.lower()
    normalized_suffix = ".epjson" if suffix in {".epjson", ".json"} else ".idf"
    working_model = work_dir / f"validibot-normalized-model{normalized_suffix}"
    shutil.copy2(model_file, working_model)

    if normalized_suffix == ".epjson":
        payload = json.loads(working_model.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("EnergyPlus epJSON model must contain a JSON object")
        timestep_objects = payload.get("Timestep")
        if not isinstance(timestep_objects, dict) or not timestep_objects:
            timestep_objects = {"Timestep 1": {}}
            payload["Timestep"] = timestep_objects
        first = next(iter(timestep_objects))
        if not isinstance(timestep_objects[first], dict):
            timestep_objects[first] = {}
        timestep_objects[first]["number_of_timesteps_per_hour"] = timestep_per_hour
        if run_simulation:
            _ensure_epjson_sql_reporting(payload)
        working_model.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return working_model

    content = working_model.read_text(encoding="utf-8", errors="replace")
    timestep_pattern = re.compile(
        r"(?:^|(?<=;))\s*Timestep\s*,.*?;",
        re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )
    replacement = f"\nTimestep,\n  {timestep_per_hour};"
    if timestep_pattern.search(content):
        content = timestep_pattern.sub(replacement, content, count=1)
    else:
        content = content.rstrip() + replacement + "\n"
    if run_simulation:
        content = _ensure_idf_sql_reporting(content)
    working_model.write_text(content, encoding="utf-8")
    return working_model


def _idf_objects(model_text: str) -> list[tuple[str, list[str]]]:
    """Return loose IDF object-type/field tuples for bounded review checks."""

    decommented = "\n".join(line.split("!", 1)[0] for line in model_text.splitlines())
    objects: list[tuple[str, list[str]]] = []
    for body in decommented.split(";"):
        parts = [part.strip() for part in body.split(",")]
        if not parts or not parts[0]:
            continue
        objects.append((parts[0], parts[1:]))
    return objects


def _review_message(
    *,
    severity: str,
    code: str,
    text: str,
    category: str,
) -> dict[str, Any]:
    """Build the internal message shape later converted to ValidationMessage."""

    return {
        "severity": severity,
        "code": code,
        "text": text,
        "category": category,
        "tags": ["energyplus-review", category],
    }


def _check_hvac_sizing(
    idf_objects: list[tuple[str, list[str]]] | None,
    epjson: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Warn when SimulationControl explicitly disables both sizing passes."""

    zone_sizing: Any = None
    system_sizing: Any = None
    if idf_objects is not None:
        for object_type, fields in idf_objects:
            if object_type.casefold() == "simulationcontrol":
                zone_sizing = fields[0] if len(fields) > 0 else None
                system_sizing = fields[1] if len(fields) > 1 else None
                break
    elif epjson is not None:
        controls = epjson.get("SimulationControl")
        if isinstance(controls, dict) and controls:
            control = next(iter(controls.values()))
            if isinstance(control, dict):
                zone_sizing = control.get("do_zone_sizing_calculation")
                system_sizing = control.get("do_system_sizing_calculation")

    def is_disabled(value: Any) -> bool:
        """Treat IDF and epJSON spellings of "off" as one value.

        The same setting arrives as the string ``"No"`` from IDF and as boolean
        ``False`` from epJSON, so both spellings are normalised here.
        """
        return value is False or str(value).strip().casefold() in {"no", "false", "0"}

    if not (is_disabled(zone_sizing) and is_disabled(system_sizing)):
        return []
    return [
        _review_message(
            severity="warning",
            code="ENERGYPLUS_REVIEW_HVAC_SIZING_DISABLED",
            text=(
                "SimulationControl disables both zone and system sizing; "
                "review autosized HVAC fields before relying on results."
            ),
            category="sizing-autosizing",
        ),
    ]


def _check_schedule_coverage(
    idf_objects: list[tuple[str, list[str]]] | None,
    epjson: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Check that each Schedule:Week:Daily names all seven day schedules."""

    incomplete: list[str] = []
    if idf_objects is not None:
        for object_type, fields in idf_objects:
            if object_type.casefold() != "schedule:week:daily":
                continue
            name = fields[0] if fields else "<unnamed>"
            day_fields = fields[1:8]
            if len(day_fields) < 7 or any(not field.strip() for field in day_fields):
                incomplete.append(name)
    elif epjson is not None:
        schedules = epjson.get("Schedule:Week:Daily")
        day_keys = (
            "sunday_schedule_day_name",
            "monday_schedule_day_name",
            "tuesday_schedule_day_name",
            "wednesday_schedule_day_name",
            "thursday_schedule_day_name",
            "friday_schedule_day_name",
            "saturday_schedule_day_name",
        )
        if isinstance(schedules, dict):
            for name, schedule in schedules.items():
                if not isinstance(schedule, dict) or any(
                    not str(schedule.get(key, "")).strip() for key in day_keys
                ):
                    incomplete.append(str(name))

    if not incomplete:
        return []
    return [
        _review_message(
            severity="warning",
            code="ENERGYPLUS_REVIEW_SCHEDULE_COVERAGE",
            text=(
                "Schedule:Week:Daily objects do not cover every weekday: "
                + ", ".join(incomplete[:10])
            ),
            category="schedule-coverage",
        ),
    ]


def run_idf_checks(model_file: Path, checks: list[str]) -> list[dict[str, Any]]:
    """Run optional Validibot modelling-review checks.

    ``duplicate-names`` remains accepted by the shared wire contract so saved
    workflows created before EnergyPlus 0.16.1 continue to execute. It is a
    deliberate no-op here: object identity is governed by the selected IDD,
    and EnergyPlus's native diagnostic is the authoritative result.
    """

    active_checks = [check for check in checks if check != "duplicate-names"]
    if not active_checks:
        return []
    try:
        if model_file.suffix.lower() == ".epjson":
            loaded = json.loads(model_file.read_text(encoding="utf-8"))
            epjson = loaded if isinstance(loaded, dict) else None
            idf_objects = None
        else:
            epjson = None
            idf_objects = _idf_objects(
                model_file.read_text(encoding="utf-8", errors="replace"),
            )
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return [
            _review_message(
                severity="error",
                code="ENERGYPLUS_REVIEW_CHECK_PARSE_FAILED",
                text=f"Validibot could not parse the model for preflight checks: {exc}",
                category="preflight-check-failure",
            ),
        ]

    check_functions = {
        "hvac-sizing": _check_hvac_sizing,
        "schedule-coverage": _check_schedule_coverage,
    }
    messages: list[dict[str, Any]] = []
    for check in active_checks:
        check_function = check_functions.get(check)
        if check_function is None:
            messages.append(
                _review_message(
                    severity="warning",
                    code="ENERGYPLUS_REVIEW_CHECK_UNSUPPORTED",
                    text=f"Unsupported EnergyPlus review check: {check}",
                    category="unsupported-review-check",
                ),
            )
            continue
        messages.extend(check_function(idf_objects, epjson))
    return messages


def run_energyplus_simulation(
    input_envelope: EnergyPlusInputEnvelope,
) -> tuple[EnergyPlusOutputs, Path, list[dict]]:
    """
    Run EnergyPlus simulation based on input envelope.

    Args:
        input_envelope: Typed input envelope with files and configuration

    Returns:
        Tuple of:
        - EnergyPlus outputs including returncode, metrics, logs, and file paths
        - Working directory containing artifacts to upload
        - List of parsed error/warning messages from .err file

    Raises:
        ValueError: If required input files are missing
        RuntimeError: If EnergyPlus execution fails critically
    """
    start_time = time.time()

    # The envelope's attempt identity, rather than its parent run, owns scratch
    # state. Exclusive creation makes stale in-container state a hard conflict.
    work_dir = create_attempt_work_dir(
        attempt_scratch_base("energyplus_run"),
        str(input_envelope.context.execution_attempt_id),
    )

    logger.info("Working directory: %s", work_dir)

    installation = _collect_installation_evidence()

    # Download input files from GCS
    logger.info("Downloading input files...")
    model_file, weather_file = _download_input_files(input_envelope, work_dir)

    # The submitted artifact remains untouched. All Validibot normalization and
    # review checks operate on a private copy that is retained as run evidence.
    working_model = _prepare_model_working_copy(
        model_file,
        work_dir,
        input_envelope.inputs.timestep_per_hour,
        run_simulation=input_envelope.inputs.run_simulation,
    )
    idf_version = _parse_model_version(working_model)
    version_match = _versions_match(
        idf_version,
        installation.binary_version,
        installation.idd_version,
    )
    review_messages = run_idf_checks(
        working_model,
        list(input_envelope.inputs.idf_checks),
    )

    # Run EnergyPlus
    logger.info(
        "Running EnergyPlus %s...",
        "simulation" if input_envelope.inputs.run_simulation else "preflight",
    )
    returncode, stdout, stderr = _run_energyplus(
        model_file=working_model,
        weather_file=weather_file,
        work_dir=work_dir,
        config=input_envelope.inputs,
        installation=installation,
    )

    execution_seconds = time.time() - start_time

    # Collect output file paths
    err_path = work_dir / "eplusout.err" if (work_dir / "eplusout.err").exists() else None
    outputs = EnergyPlusSimulationOutputs(
        eplusout_sql=work_dir / "eplusout.sql" if (work_dir / "eplusout.sql").exists() else None,
        eplusout_err=err_path,
        eplusout_csv=work_dir / "eplusout.csv" if (work_dir / "eplusout.csv").exists() else None,
        eplusout_eso=work_dir / "eplusout.eso" if (work_dir / "eplusout.eso").exists() else None,
    )

    # Extract metrics from SQL database
    logger.info("Extracting metrics...")
    metrics = _extract_metrics(outputs.eplusout_sql)

    # Collect logs
    logs = EnergyPlusSimulationLogs(
        stdout_tail=stdout[-STDOUT_TAIL_CHARS:] if stdout else None,
        stderr_tail=stderr[-STDOUT_TAIL_CHARS:] if stderr else None,
        err_tail=_read_err_tail(err_path),
    )

    # EnergyPlus normally writes diagnostics to eplusout.err, but early CLI
    # and conversion failures can appear only on stdout/stderr. Merge every
    # native source before adding Validibot-authored review/profile messages.
    logger.info("Parsing native EnergyPlus diagnostics...")
    native_messages, issue_counts = parse_energyplus_diagnostics(
        err_path,
        stdout=stdout,
        stderr=stderr,
    )
    warning_count, severe_count, fatal_count = issue_counts
    native_messages = _ensure_execution_failure_diagnostic(
        native_messages,
        returncode=returncode,
        run_simulation=input_envelope.inputs.run_simulation,
    )
    parsed_messages = [*review_messages, *native_messages]

    profile_messages = _profile_required_output_messages(
        review_profile=input_envelope.inputs.review_profile,
        run_simulation=input_envelope.inputs.run_simulation,
        version_match=version_match,
        has_sql_output=outputs.eplusout_sql is not None,
        metrics=metrics,
    )
    parsed_messages.extend(profile_messages)
    review_issue_count = sum(
        1 for message in parsed_messages if "energyplus-review" in message.get("tags", [])
    )
    completed_successfully = returncode == 0 and fatal_count == 0
    if parsed_messages:
        logger.info("Found %d EnergyPlus/review diagnostic messages", len(parsed_messages))

    logger.info(
        "Simulation complete (returncode=%d, duration=%.2fs)",
        returncode,
        execution_seconds,
    )

    return (
        EnergyPlusOutputs(
            outputs=outputs,
            metrics=metrics,
            logs=logs,
            energyplus_returncode=returncode,
            execution_seconds=execution_seconds,
            invocation_mode=input_envelope.inputs.invocation_mode,
            energyplus_binary_version=installation.binary_version,
            energyplus_binary_build=installation.binary_build,
            idd_version=installation.idd_version,
            idd_build=installation.idd_build,
            idd_path=str(installation.idd_path),
            idf_version=idf_version,
            version_match=version_match,
            completed_successfully=completed_successfully,
            warning_count=warning_count,
            severe_count=severe_count,
            fatal_count=fatal_count,
            review_issue_count=review_issue_count,
            has_sql_output=outputs.eplusout_sql is not None,
            has_err_output=outputs.eplusout_err is not None,
            has_csv_output=outputs.eplusout_csv is not None,
            has_eso_output=outputs.eplusout_eso is not None,
        ),
        work_dir,
        parsed_messages,
    )


# Declared Validibot file-port keys for this validator, and the backend-facing
# role/type vocabulary Django writes alongside them. ``port_key`` is optional on
# the shared envelope, so each matcher below accepts either identifier -- see
# ADR-2026-07-06, "Why ``port_key`` is optional in the schema".
PRIMARY_MODEL_PORT_KEY = "primary_model"
PRIMARY_MODEL_ROLE = "primary-model"
WEATHER_FILE_PORT_KEY = "weather_file"
WEATHER_ROLE = "weather"
WEATHER_RESOURCE_TYPE = "energyplus_weather"


def _matches_primary_model(file_item) -> bool:
    """Report whether an input file item is the declared primary model."""
    return file_item.port_key == PRIMARY_MODEL_PORT_KEY or file_item.role == PRIMARY_MODEL_ROLE


def _matches_weather_input_file(file_item) -> bool:
    """Report whether an input file item is the declared weather file.

    The ``weather_file`` port declares ``envelope_channel = resource_files``,
    but that only holds when the binding resolves to a managed workflow
    resource. When weather is bound from a submitted file or an upstream
    artifact, Django renders it into ``input_files`` instead, with
    ``port_key='weather_file'`` and ``role='weather'`` -- see
    ``_resolve_energyplus_file_port_items`` in the Django envelope builder.
    Both channels are current; neither is a compatibility shim.
    """
    return file_item.port_key == WEATHER_FILE_PORT_KEY or file_item.role == WEATHER_ROLE


def _matches_weather_resource(resource) -> bool:
    """Report whether a resource file item is the declared weather file."""
    return resource.port_key == WEATHER_FILE_PORT_KEY or resource.type == WEATHER_RESOURCE_TYPE


def _download_input_files(
    input_envelope: EnergyPlusInputEnvelope,
    work_dir: Path,
) -> tuple[Path, Path | None]:
    """
    Download input files and resource files to working directory.

    Input files (submission data) come from input_envelope.input_files.
    Resource files (weather, etc.) come from input_envelope.resource_files.

    Every file in the envelope is downloaded, because a model may reference
    side files this backend does not interpret. Only the primary model and the
    weather file are *identified*, and identification matches the declared
    file-port key first, falling back to the backend-facing ``role`` or
    ``type`` for envelopes that carry no port key.

    Args:
        input_envelope: Input envelope with file URIs
        work_dir: Local working directory

    Returns:
        Tuple of (primary model file, optional weather file)

    Raises:
        ValueError: If the primary model or weather file is missing, or if more
            than one item claims the primary model or weather port.
    """
    model_file = None
    weather_file = None

    # Django validates cardinality before launch, but the envelope is untrusted
    # input here. Check ambiguity up front rather than letting whichever item
    # happens to come last silently win the assignment below.
    model_matches = [item for item in input_envelope.input_files if _matches_primary_model(item)]
    if len(model_matches) > 1:
        msg = (
            f"EnergyPlus requires exactly one {PRIMARY_MODEL_PORT_KEY} input "
            f"file; found {len(model_matches)}."
        )
        raise ValueError(msg)

    # Download input files (submission data)
    for file_item in input_envelope.input_files:
        logger.info(
            "Downloading input file: %s (port_key=%s, role=%s)",
            file_item.name,
            file_item.port_key,
            file_item.role,
        )

        destination = work_dir / file_item.name
        download_verified_file(file_item, destination)

        # Track primary model file
        if _matches_primary_model(file_item):
            model_file = destination
        # Weather bound from a submitted file or an upstream artifact arrives
        # here rather than in resource_files.
        elif _matches_weather_input_file(file_item):
            weather_file = destination

    # Download resource files (weather, libraries, etc.)
    resource_files = getattr(input_envelope, "resource_files", []) or []

    weather_matches = [
        resource for resource in resource_files if _matches_weather_resource(resource)
    ]
    if len(weather_matches) > 1:
        msg = (
            f"EnergyPlus accepts at most one {WEATHER_FILE_PORT_KEY} resource "
            f"file; found {len(weather_matches)}."
        )
        raise ValueError(msg)

    for resource in resource_files:
        logger.info(
            "Downloading resource file: %s (port_key=%s, type=%s)",
            resource.id,
            resource.port_key,
            resource.type,
        )

        destination = work_dir / resource.name

        try:
            download_verified_file(resource, destination)
        except ValueError as exc:
            if _matches_weather_resource(resource):
                raise ValueError(
                    f"Weather file missing or unreadable at {resource.uri}",
                ) from exc
            raise

        # Track weather file from resource_files. A managed workflow resource
        # deliberately supersedes a weather entry found in input_files.
        if _matches_weather_resource(resource):
            weather_file = destination

    if model_file is None:
        msg = (
            "No primary-model file found in input_files "
            f"(port_key='{PRIMARY_MODEL_PORT_KEY}' or role='{PRIMARY_MODEL_ROLE}')."
        )
        raise ValueError(msg)

    if weather_file is None and input_envelope.inputs.run_simulation:
        raise ValueError(
            f"No weather file found. Provide the {WEATHER_FILE_PORT_KEY} port "
            f"via resource_files (port_key='{WEATHER_FILE_PORT_KEY}' or "
            f"type='{WEATHER_RESOURCE_TYPE}') or input_files "
            f"(port_key='{WEATHER_FILE_PORT_KEY}' or role='{WEATHER_ROLE}')."
        )

    return model_file, weather_file


def _run_energyplus(
    model_file: Path,
    weather_file: Path | None,
    work_dir: Path,
    config,
    installation: EnergyPlusInstallationEvidence,
) -> tuple[int, str, str]:
    """
    Execute EnergyPlus simulation.

    Args:
        model_file: Path to IDF or epJSON model file
        weather_file: Path to the EPW weather file for full simulations
        work_dir: Working directory for simulation
        config: EnergyPlusInputs configuration

    Returns:
        Tuple of (returncode, stdout, stderr)

    Raises:
        UnsafeModelObjectError: If the defense-in-depth scan rejects the model
            because it contains a high-risk IDF/epJSON object type.
    """
    # Defense-in-depth: inspect the user-supplied model before invoking the
    # native binary. The container is still the primary boundary; this is a
    # cheap second layer that fails closed on code/library/network/file-loading
    # object types unless ALLOW_UNSAFE_IDF_OBJECTS is explicitly enabled.
    _scan_model_for_unsafe_objects(model_file)

    # Build EnergyPlus command
    cmd = [
        str(installation.binary_path),
        "--idd",
        str(installation.idd_path),
        "--output-directory",
        str(work_dir),
    ]

    if config.run_simulation:
        if weather_file is None:
            raise ValueError("A weather file is required for full EnergyPlus simulation")
        cmd.extend(["--weather", str(weather_file)])
    else:
        cmd.append("--convert-only")

    cmd.append(str(model_file))

    logger.info("Executing: %s", " ".join(cmd))

    # Run EnergyPlus
    result = subprocess.run(
        cmd,
        check=False,
        cwd=work_dir,
        capture_output=True,
        text=True,
        timeout=3600,  # 1 hour timeout
    )

    logger.info("EnergyPlus returncode: %d", result.returncode)

    return result.returncode, result.stdout, result.stderr


def _extract_metrics(sql_path: Path | None) -> EnergyPlusSimulationMetrics:
    """
    Extract metrics from EnergyPlus SQL output database.

    Args:
        sql_path: Path to eplusout.sql file (or None if not generated)

    Returns:
        Extracted metrics (may be empty if SQL is missing)
    """
    if sql_path is None or not sql_path.exists():
        logger.warning("No SQL database found, cannot extract metrics")
        return EnergyPlusSimulationMetrics()

    try:
        with sqlite3.connect(sql_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            def fetch_tabular_metric(
                report: str,
                table: str,
                row: str,
                column: str,
                *,
                report_for: str = "Entire Facility",
                units: str | None = None,
            ) -> float | None:
                """Fetch a single value from TabularDataWithStrings.

                EnergyPlus 25.x stores tabular data with integer foreign keys
                in ``TabularData`` and provides a convenience view
                ``TabularDataWithStrings`` that resolves them.  Column names
                in the view do NOT include units (e.g. ``"Electricity"``
                rather than ``"Electricity [kWh]"``).  Energy values are in
                GJ; callers must convert to kWh when needed.
                """
                query = """
                    SELECT Value AS metric_value
                    FROM TabularDataWithStrings
                    WHERE ReportName = ?
                      AND ReportForString = ?
                      AND TableName = ?
                      AND RowName = ?
                      AND ColumnName = ?
                """
                params: list[str] = [report, report_for, table, row, column]
                if units is not None:
                    query += " AND Units = ?"
                    params.append(units)
                query += " LIMIT 1"
                result = cursor.execute(query, params).fetchone()
                if not result:
                    return None
                try:
                    return float(result["metric_value"])
                except (TypeError, ValueError):
                    return None

            def fetch_first(
                candidates: list[tuple[str, str, str, str]],
            ) -> float | None:
                """Return the first available metric across EnergyPlus table aliases."""

                for candidate in candidates:
                    value = fetch_tabular_metric(*candidate)
                    if value is not None:
                        return value
                return None

            def sum_end_use_row(row_name: str) -> float | None:
                """Sum all energy fuel columns for an End Uses row (in GJ).

                The End Uses table has separate columns per fuel type
                (Electricity, Natural Gas, District Cooling, District
                Heating Water, etc.).  For a total we sum all energy
                columns, excluding Water (m3).
                """
                result = cursor.execute(
                    """
                    SELECT SUM(CAST(Value AS REAL)) AS total_gj
                    FROM TabularDataWithStrings
                    WHERE ReportName = 'AnnualBuildingUtilityPerformanceSummary'
                      AND ReportForString = 'Entire Facility'
                      AND TableName = 'End Uses'
                      AND RowName = ?
                      AND Units = 'GJ'
                    """,
                    (row_name,),
                ).fetchone()
                if not result or result["total_gj"] is None:
                    return None
                return float(result["total_gj"])

            def total_fuel_gj(column_names: tuple[str, ...]) -> float | None:
                """Sum named fuel columns without treating absence as zero."""

                placeholders = ", ".join("?" for _ in column_names)
                result = cursor.execute(
                    f"""
                    SELECT SUM(CAST(Value AS REAL)) AS total_gj
                    FROM TabularDataWithStrings
                    WHERE ReportName = 'AnnualBuildingUtilityPerformanceSummary'
                      AND ReportForString = 'Entire Facility'
                      AND TableName = 'End Uses'
                      AND RowName = 'Total End Uses'
                      AND Units = 'GJ'
                      AND ColumnName IN ({placeholders})
                    """,
                    column_names,
                ).fetchone()
                if not result or result["total_gj"] is None:
                    return None
                return float(result["total_gj"])

            # Total site energy by fuel type (GJ → kWh).
            elec_gj = fetch_tabular_metric(
                "AnnualBuildingUtilityPerformanceSummary",
                "End Uses",
                "Total End Uses",
                "Electricity",
                units="GJ",
            )
            gas_gj = fetch_tabular_metric(
                "AnnualBuildingUtilityPerformanceSummary",
                "End Uses",
                "Total End Uses",
                "Natural Gas",
                units="GJ",
            )
            district_cooling_gj = total_fuel_gj(("District Cooling",))

            # Newer versions split district heating water/steam. Older versions
            # expose one combined District Heating column; never add both forms.
            district_heating_gj = total_fuel_gj(
                ("District Heating Water", "District Heating Steam"),
            )
            if district_heating_gj is None:
                district_heating_gj = total_fuel_gj(("District Heating",))

            building_area = fetch_tabular_metric(
                "AnnualBuildingUtilityPerformanceSummary",
                "Building Area",
                "Net Conditioned Building Area",
                "Area",
                units="m2",
            )

            # EUI uses every GJ-valued site fuel. Water is excluded by units.
            # The explicit aggregate keeps total-site derivations identical to
            # the EUI numerator when uncommon fuels appear in a model.
            total_site_gj = sum_end_use_row("Total End Uses")
            named_site_gj = sum(
                value
                for value in (
                    elec_gj,
                    gas_gj,
                    district_cooling_gj,
                    district_heating_gj,
                )
                if value is not None
            )
            other_fuels_gj = (
                max(total_site_gj - named_site_gj, 0.0) if total_site_gj is not None else None
            )
            total_site_kwh = total_site_gj * GJ_TO_KWH if total_site_gj is not None else None
            eui = (
                total_site_kwh / building_area
                if total_site_kwh is not None and building_area is not None and building_area > 0
                else None
            )

            end_use_gj = {
                "heating_energy_kwh": sum_end_use_row("Heating"),
                "cooling_energy_kwh": sum_end_use_row("Cooling"),
                "interior_lighting_kwh": sum_end_use_row("Interior Lighting"),
                "fans_energy_kwh": sum_end_use_row("Fans"),
                "pumps_energy_kwh": sum_end_use_row("Pumps"),
                "water_systems_kwh": sum_end_use_row("Water Systems"),
            }

            unmet_heating_hours = fetch_first(
                [
                    (
                        "AnnualBuildingUtilityPerformanceSummary",
                        "Comfort and Setpoint Not Met Summary",
                        "Time Setpoint Not Met During Occupied Heating",
                        "Facility",
                    ),
                    (
                        "SystemSummary",
                        "Time Setpoint Not Met",
                        "Facility",
                        "During Occupied Heating",
                    ),
                ],
            )
            unmet_cooling_hours = fetch_first(
                [
                    (
                        "AnnualBuildingUtilityPerformanceSummary",
                        "Comfort and Setpoint Not Met Summary",
                        "Time Setpoint Not Met During Occupied Cooling",
                        "Facility",
                    ),
                    (
                        "SystemSummary",
                        "Time Setpoint Not Met",
                        "Facility",
                        "During Occupied Cooling",
                    ),
                ],
            )
            peak_electric_demand_w = fetch_tabular_metric(
                "DemandEndUseComponentsSummary",
                "End Uses",
                "Total End Uses",
                "Electricity",
                units="W",
            )

            # Window envelope metrics from output variables (not tabular data).
            # These require Output:Variable objects in the IDF; if absent the
            # ReportDataDictionary won't have matching rows and we get None.
            window_heat_gain = _fetch_output_variable_sum(
                cursor,
                "Surface Window Heat Gain Energy",
            )
            window_heat_loss = _fetch_output_variable_sum(
                cursor,
                "Surface Window Heat Loss Energy",
            )
            window_transmitted_solar = _fetch_output_variable_sum(
                cursor,
                "Surface Window Transmitted Solar Radiation Energy",
            )

            _log_sql_errors(cursor)

    except Exception as exc:  # pragma: no cover - defensive, metrics best-effort
        logger.warning("Failed to extract metrics from SQL: %s", exc)
        return EnergyPlusSimulationMetrics()

    return EnergyPlusSimulationMetrics(
        site_electricity_kwh=(elec_gj * GJ_TO_KWH if elec_gj is not None else None),
        site_natural_gas_kwh=(gas_gj * GJ_TO_KWH if gas_gj is not None else None),
        site_district_cooling_kwh=(
            district_cooling_gj * GJ_TO_KWH if district_cooling_gj is not None else None
        ),
        site_district_heating_kwh=(
            district_heating_gj * GJ_TO_KWH if district_heating_gj is not None else None
        ),
        site_other_fuels_kwh=(other_fuels_gj * GJ_TO_KWH if other_fuels_gj is not None else None),
        site_eui_kwh_m2=eui,
        simulated_conditioned_area_m2=building_area,
        unmet_heating_hours=unmet_heating_hours,
        unmet_cooling_hours=unmet_cooling_hours,
        peak_electric_demand_w=peak_electric_demand_w,
        window_heat_gain_kwh=window_heat_gain,
        window_heat_loss_kwh=window_heat_loss,
        window_transmitted_solar_kwh=window_transmitted_solar,
        **{
            key: value * GJ_TO_KWH if value is not None else None
            for key, value in end_use_gj.items()
        },
    )


# Preferred reporting frequency order for output variable summation.
# "Run Period" gives a single annual total per key and avoids summing
# thousands of timestep rows.  We pick exactly one frequency to avoid
# double-counting when an IDF requests the same variable at multiple
# frequencies (each gets a separate ReportDataDictionaryIndex).
_FREQUENCY_PREFERENCE = [
    "Run Period",
    "Monthly",
    "Daily",
    "Hourly",
    "Zone Timestep",
    "HVAC System Timestep",
]

# Joules → kWh conversion factor
_J_TO_KWH = 1.0 / 3_600_000.0


def _fetch_output_variable_sum(
    cursor: sqlite3.Cursor,
    variable_name: str,
) -> float | None:
    """
    Sum an EnergyPlus output variable across all key values (surfaces) for
    the annual run period, converting Joules to kWh.

    EnergyPlus stores output variable data in two tables:
    - ReportDataDictionary: maps variable name + key + frequency → index
    - ReportData: stores timestep values keyed by that index

    Each reporting frequency requested in the IDF creates a *separate*
    dictionary entry.  To avoid double-counting we pick exactly one
    frequency, preferring "Run Period" (already annual) and falling back
    to finer granularities.

    Returns None if the variable was not requested in the IDF (no matching
    dictionary entries).
    """
    # Check whether the ReportDataDictionary table exists at all
    table_check = cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='ReportDataDictionary'",
    ).fetchone()
    if not table_check:
        return None

    # Find all frequencies available for this variable
    freq_rows = cursor.execute(
        """
        SELECT DISTINCT ReportingFrequency
        FROM ReportDataDictionary
        WHERE Name = ? AND IsMeter = 0
        """,
        (variable_name,),
    ).fetchall()

    if not freq_rows:
        return None

    available = {r[0] for r in freq_rows}

    # Pick exactly one frequency (best available)
    chosen = None
    for pref in _FREQUENCY_PREFERENCE:
        if pref in available:
            chosen = pref
            break
    if chosen is None:
        # Unknown frequency string — pick first available as last resort
        chosen = next(iter(available))

    # Sum values across all key values (surfaces) for the chosen frequency
    result = cursor.execute(
        """
        SELECT SUM(rd.Value)
        FROM ReportData rd
        JOIN ReportDataDictionary rdd
          ON rd.ReportDataDictionaryIndex = rdd.ReportDataDictionaryIndex
        WHERE rdd.Name = ?
          AND rdd.ReportingFrequency = ?
          AND rdd.IsMeter = 0
        """,
        (variable_name, chosen),
    ).fetchone()

    if result is None or result[0] is None:
        return None

    total_joules = float(result[0])
    return total_joules * _J_TO_KWH


def _log_sql_errors(cursor: sqlite3.Cursor) -> None:
    """Log non-info errors from the EnergyPlus SQL Errors table if present."""
    try:
        cols = cursor.execute("PRAGMA table_info('Errors')").fetchall()
        if not cols:
            return
        rows = cursor.execute("SELECT * FROM Errors").fetchall()
        if not rows:
            return
        columns = [c[1] if isinstance(c, tuple) else c[0] for c in cols]
        for row in rows:
            data = {columns[i]: row[i] for i in range(len(columns))}
            severity = str(
                data.get("Severity") or data.get("ErrorType") or data.get("Level") or ""
            ).lower()
            if severity == "info":
                continue
            message = str(
                data.get("Message") or data.get("ErrorMessage") or data.get("Text") or row
            )
            context = data.get("Context") or data.get("Context1") or data.get("Context2")
            logger.warning(
                "EnergyPlus SQL error [%s]: %s%s",
                severity or "unknown",
                message,
                f" (context: {context})" if context else "",
            )
    except Exception:  # pragma: no cover - best effort
        logger.debug("Could not log SQL errors", exc_info=True)


def _read_err_tail(err_path: Path | None, max_lines: int = 200) -> str | None:
    """
    Read tail of eplusout.err file.

    Args:
        err_path: Path to eplusout.err file (or None if not generated)
        max_lines: Maximum number of lines to read from end of file

    Returns:
        Tail of err file, or None if file doesn't exist
    """
    if err_path is None or not err_path.exists():
        return None

    try:
        with err_path.open("r") as f:
            lines = f.readlines()
            tail_lines = lines[-max_lines:] if len(lines) > max_lines else lines
            return "".join(tail_lines)
    except Exception as e:
        logger.warning("Failed to read err file: %s", e)
        return None


_ERR_CLASSIFIERS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "version-idd-mismatch",
        "ENERGYPLUS_REVIEW_VERSION_IDD_MISMATCH",
        re.compile(r"(?:version|idd).*(?:mismatch|different|incorrect)", re.IGNORECASE),
    ),
    (
        "duplicate-object-names",
        "ENERGYPLUS_REVIEW_DUPLICATE_OBJECT_NAME",
        re.compile(r"(?:duplicate.*name|name.*already exists)", re.IGNORECASE),
    ),
    (
        "invalid-object-reference",
        "ENERGYPLUS_REVIEW_INVALID_OBJECT_REFERENCE",
        re.compile(
            r"(?:object reference|referenced object|did not find|not found|invalid reference)",
            re.IGNORECASE,
        ),
    ),
    (
        "schedule-coverage",
        "ENERGYPLUS_REVIEW_SCHEDULE_COVERAGE",
        re.compile(r"schedule.*(?:coverage|missing|invalid|not found|day)", re.IGNORECASE),
    ),
    (
        "sizing-autosizing",
        "ENERGYPLUS_REVIEW_SIZING_AUTOSIZING",
        re.compile(r"(?:autosiz|sizing)", re.IGNORECASE),
    ),
    (
        "weather-design-day",
        "ENERGYPLUS_REVIEW_WEATHER_DESIGN_DAY",
        re.compile(r"(?:weather|design[ -]?day|epw)", re.IGNORECASE),
    ),
    (
        "unmet-hours-comfort",
        "ENERGYPLUS_REVIEW_UNMET_HOURS_COMFORT",
        re.compile(r"(?:setpoint not met|unmet|not comfortable|comfort)", re.IGNORECASE),
    ),
    (
        "output-report-configuration",
        "ENERGYPLUS_REVIEW_OUTPUT_REPORT_CONFIGURATION",
        re.compile(r"(?:output:|report.*(?:missing|not found)|requested output)", re.IGNORECASE),
    ),
    (
        "deprecated-object-field",
        "ENERGYPLUS_REVIEW_DEPRECATED_OBJECT_FIELD",
        re.compile(r"(?:deprecated|obsolete)", re.IGNORECASE),
    ),
    (
        "convergence-runtime",
        "ENERGYPLUS_REVIEW_CONVERGENCE_RUNTIME",
        re.compile(r"(?:convergence|did not converge|iteration limit)", re.IGNORECASE),
    ),
)


def _classify_err_message(message: dict[str, Any]) -> dict[str, Any]:
    """Attach a stable reviewer code/tag when an EnergyPlus message is known."""

    text = str(message.get("text", ""))
    for category, code, pattern in _ERR_CLASSIFIERS:
        if pattern.search(text):
            message["code"] = code
            message["category"] = category
            message["tags"] = ["energyplus-review", category]
            return message
    message["tags"] = ["energyplus"]
    return message


_MARKER_DIAGNOSTIC_RE = re.compile(
    r"^\s*\*\*\s*(Warning|Severe|Fatal)\s*\*\*\s*(.*)$",
    re.IGNORECASE,
)
_CONTINUATION_DIAGNOSTIC_RE = re.compile(
    r"^\s*\*\*\s*~~~\s*\*\*\s*(.*)$",
    re.IGNORECASE,
)
_PLAIN_DIAGNOSTIC_RE = re.compile(
    r"^\s*(?:EnergyPlus\s+)?(?:\*{2}\s*)?(?:\[(Warning|Severe|Fatal|Error)\]|"
    r"(Warning|Severe|Fatal|Error))\s*(?::|[-\u2013\u2014])\s*(.+?)\s*$",
    re.IGNORECASE,
)
_TERMINAL_SUMMARY_RE = re.compile(
    r"EnergyPlus\s+(?:Completed Successfully|Terminated).*?"
    r"(\d+)\s+Warning(?:s)?;\s*(\d+)\s+Severe Errors?",
    re.IGNORECASE,
)


def _native_diagnostic_message(kind: str, text: str) -> dict[str, Any]:
    """Build and classify one EnergyPlus-authored diagnostic message."""

    normalized_kind = kind.casefold()
    if normalized_kind == "warning":
        severity = "warning"
        code = "ENERGYPLUS_WARNING"
    elif normalized_kind == "fatal":
        severity = "error"
        code = "ENERGYPLUS_FATAL"
    else:
        normalized_kind = "severe"
        severity = "error"
        code = "ENERGYPLUS_SEVERE"
    return _classify_err_message(
        {
            "severity": severity,
            "text": text.strip(),
            "code": code,
            "kind": normalized_kind,
        }
    )


def _parse_energyplus_diagnostic_text(content: str) -> list[dict[str, Any]]:
    """Extract marked and plain CLI diagnostics from EnergyPlus text."""

    messages: list[dict[str, Any]] = []
    current_kind: str | None = None
    current_text = ""
    current_is_plain = False

    def save_current() -> None:
        """Flush the diagnostic being accumulated and reset for the next one.

        EnergyPlus writes multi-line diagnostics with continuation markers, so a
        message is only complete once the next one starts or the file ends. Empty
        or unclassified buffers are dropped rather than emitted as blank
        findings.
        """
        nonlocal current_is_plain, current_kind, current_text
        if current_kind is not None and current_text.strip():
            messages.append(_native_diagnostic_message(current_kind, current_text))
        current_kind = None
        current_text = ""
        current_is_plain = False

    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("*************"):
            save_current()
            continue
        if "Summary of Errors" in line or "Reference severe error" in line:
            save_current()
            continue

        marker_match = _MARKER_DIAGNOSTIC_RE.match(line)
        if marker_match:
            save_current()
            current_kind = marker_match.group(1)
            current_text = marker_match.group(2).strip()
            current_is_plain = False
            continue

        plain_match = _PLAIN_DIAGNOSTIC_RE.match(line)
        if plain_match:
            save_current()
            current_kind = plain_match.group(1) or plain_match.group(2)
            current_text = plain_match.group(3).strip()
            current_is_plain = True
            continue

        continuation_match = _CONTINUATION_DIAGNOSTIC_RE.match(line)
        if current_kind is not None and continuation_match:
            continuation = continuation_match.group(1).strip()
            if continuation:
                current_text = f"{current_text} {continuation}".strip()
            continue

        if current_kind is not None and current_is_plain and stripped:
            save_current()
            continue

        if current_kind is not None and stripped:
            current_text = f"{current_text} {stripped}".strip()

    save_current()
    return messages


def _diagnostic_identity(message: dict[str, Any]) -> tuple[str, str]:
    """Return a source-independent identity for diagnostic deduplication."""

    kind = str(message.get("kind", message.get("severity", ""))).casefold()
    text = re.sub(r"\s+", " ", str(message.get("text", ""))).strip().casefold()
    return kind, text


def _deduplicate_diagnostics(
    messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep one finding when EnergyPlus repeats a diagnostic across outputs."""

    deduplicated: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for message in messages:
        identity = _diagnostic_identity(message)
        if identity in seen:
            continue
        seen.add(identity)
        deduplicated.append(message)
    return deduplicated


def _count_diagnostic_text_issues(content: str) -> tuple[int, int, int]:
    """Count EnergyPlus issue markers, including plain CLI-only diagnostics."""

    warning_count = 0
    severe_count = 0
    fatal_count = 0
    for line in content.splitlines():
        marker_match = _MARKER_DIAGNOSTIC_RE.match(line)
        plain_match = _PLAIN_DIAGNOSTIC_RE.match(line)
        if marker_match:
            kind = marker_match.group(1).casefold()
        elif plain_match:
            kind = (plain_match.group(1) or plain_match.group(2)).casefold()
        else:
            continue
        if kind == "warning":
            warning_count += 1
        elif kind == "fatal":
            fatal_count += 1
        else:
            severe_count += 1

    summaries = _TERMINAL_SUMMARY_RE.findall(content)
    if summaries:
        summary_warning_count, summary_severe_count = summaries[-1]
        warning_count = max(warning_count, int(summary_warning_count))
        severe_count = max(severe_count, int(summary_severe_count))
    return warning_count, severe_count, fatal_count


def _count_err_issues(err_path: Path | None) -> tuple[int, int, int]:
    """Count warnings, severe errors, and fatal markers without UI deduping.

    EnergyPlus's terminal summary includes recurring warning/severe counts that
    may exceed the number of individually rendered markers. Prefer that summary
    when present and retain marker counting as the failure/preflight fallback.
    """

    if err_path is None or not err_path.exists():
        return 0, 0, 0
    try:
        content = err_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0, 0, 0
    return _count_diagnostic_text_issues(content)


def _profile_required_output_messages(
    *,
    review_profile: str,
    run_simulation: bool,
    version_match: bool | None,
    has_sql_output: bool,
    metrics: EnergyPlusSimulationMetrics,
) -> list[dict[str, Any]]:
    """Report missing/mismatched evidence with profile-specific severity."""

    strict = review_profile == "leed_review"
    messages: list[dict[str, Any]] = []
    severity = "error" if strict else "warning"

    if version_match is not True:
        messages.append(
            _review_message(
                severity=severity,
                code=(
                    "ENERGYPLUS_REVIEW_VERSION_MISMATCH"
                    if version_match is False
                    else "ENERGYPLUS_REVIEW_VERSION_EVIDENCE_MISSING"
                ),
                text=(
                    "The model Version does not match the EnergyPlus binary and IDD."
                    if version_match is False
                    else "Complete model, EnergyPlus binary, and IDD version evidence is unavailable."
                ),
                category="version-idd-mismatch",
            ),
        )

    if not run_simulation:
        return messages

    if not has_sql_output:
        messages.append(
            _review_message(
                severity=severity,
                code="ENERGYPLUS_REVIEW_SQL_OUTPUT_MISSING",
                text="The simulation did not produce eplusout.sql; metrics are unavailable.",
                category="output-report-configuration",
            ),
        )

    if metrics.simulated_conditioned_area_m2 is None:
        messages.append(
            _review_message(
                severity=severity,
                code="ENERGYPLUS_REVIEW_FLOOR_AREA_MISSING",
                text="EnergyPlus did not report conditioned floor area for EUI review.",
                category="missing-required-output",
            ),
        )

    if strict:
        strict_metrics = {
            "site_eui_kwh_m2": metrics.site_eui_kwh_m2,
            "unmet_heating_hours": metrics.unmet_heating_hours,
            "unmet_cooling_hours": metrics.unmet_cooling_hours,
        }
        for field_name, value in strict_metrics.items():
            if value is not None:
                continue
            messages.append(
                _review_message(
                    severity="error",
                    code="ENERGYPLUS_LEED_REQUIRED_OUTPUT_MISSING",
                    text=f"LEED review profile requires output {field_name!r}.",
                    category="missing-required-output",
                ),
            )
    return messages


def _ensure_execution_failure_diagnostic(
    messages: list[dict[str, Any]],
    *,
    returncode: int,
    run_simulation: bool,
) -> list[dict[str, Any]]:
    """Explain a nonzero EnergyPlus exit when native output does not."""

    if returncode == 0 or any(message.get("severity") == "error" for message in messages):
        return messages
    mode = "simulation" if run_simulation else "conversion-only preflight"
    return [
        *messages,
        {
            "severity": "error",
            "code": "ENERGYPLUS_EXECUTION_FAILED",
            "text": (
                f"EnergyPlus {mode} exited with return code {returncode} "
                "without reporting a specific error. Review the captured "
                "EnergyPlus logs for additional context."
            ),
            "kind": "execution",
            "category": "execution-failure",
            "tags": ["energyplus", "execution-failure"],
        },
    ]


def parse_err_file(err_path: Path | None) -> list[dict[str, Any]]:
    """
    Parse EnergyPlus .err file and extract error/warning messages.

    EnergyPlus .err files contain lines like:
        ** Warning ** Some warning message
        ** Severe  ** Some severe error message
        **  Fatal  ** Some fatal error message

    Multi-line messages are continued on subsequent lines until the next
    marker or summary section.

    Args:
        err_path: Path to eplusout.err file (or None if not generated)

    Returns:
        List of dicts with keys: severity, text, code (optional)
    """
    if err_path is None or not err_path.exists():
        return []

    try:
        content = err_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("Failed to read err file for parsing: %s", exc)
        return []

    return _deduplicate_diagnostics(_parse_energyplus_diagnostic_text(content))


def parse_energyplus_diagnostics(
    err_path: Path | None,
    *,
    stdout: str,
    stderr: str,
) -> tuple[list[dict[str, Any]], tuple[int, int, int]]:
    """Merge native diagnostics from EnergyPlus's file and process streams.

    The `.err` file remains the canonical and usually most complete source.
    EnergyPlus can fail before creating it, however, and conversion-only mode
    can emit useful CLI diagnostics only on stdout or stderr. Findings are
    deduplicated across sources while counts preserve EnergyPlus terminal
    summaries and repeated markers where those are available.

    Args:
        err_path: Optional path to the EnergyPlus `.err` output.
        stdout: Captured EnergyPlus standard output.
        stderr: Captured EnergyPlus standard error.

    Returns:
        A tuple of deduplicated findings and warning/severe/fatal counts.
    """

    err_content = ""
    if err_path is not None and err_path.exists():
        try:
            err_content = err_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Failed to read err file for diagnostic merging: %s", exc)

    messages = _deduplicate_diagnostics(
        [
            *_parse_energyplus_diagnostic_text(err_content),
            *_parse_energyplus_diagnostic_text(stdout),
            *_parse_energyplus_diagnostic_text(stderr),
        ]
    )

    visible_counts = {
        "warning": sum(message.get("kind") == "warning" for message in messages),
        "severe": sum(message.get("kind") == "severe" for message in messages),
        "fatal": sum(message.get("kind") == "fatal" for message in messages),
    }
    source_counts = [
        _count_diagnostic_text_issues(err_content),
        _count_diagnostic_text_issues(stdout),
        _count_diagnostic_text_issues(stderr),
    ]
    warning_count = max(
        visible_counts["warning"],
        *(counts[0] for counts in source_counts),
    )
    severe_count = max(
        visible_counts["severe"],
        *(counts[1] for counts in source_counts),
    )
    fatal_count = max(
        visible_counts["fatal"],
        *(counts[2] for counts in source_counts),
    )
    return messages, (warning_count, severe_count, fatal_count)
