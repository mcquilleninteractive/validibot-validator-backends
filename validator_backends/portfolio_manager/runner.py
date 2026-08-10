"""Execution engine for single and ZIP Portfolio Manager report submissions."""

from __future__ import annotations

import json
import re
import stat
import tempfile
import time
import zipfile
from calendar import monthrange
from collections import Counter
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from pydantic import ValidationError

from validator_backends.core.storage_client import download_verified_file
from validator_backends.portfolio_manager.parser import (
    PortfolioManagerParseError,
    parse_report_bytes,
)
from validibot_shared.portfolio_manager import (
    ExpectedBuildingsList,
    PortfolioManagerFinding,
    PortfolioManagerInputEnvelope,
    PortfolioManagerOutputs,
    PortfolioManagerPropertyResult,
    validate_expected_buildings_list_json,
)
from validibot_shared.validations.envelopes import (
    MessageLocation,
    Severity,
    ValidationMessage,
    ValidationStatus,
)
from validibot_shared.validations.file_ports import (
    FilePortLookupError,
    select_input_file,
    select_resource_file,
)


_SUPPORTED_MEMBER_SUFFIXES = {".xls", ".xlsx", ".xml"}
_MAX_COMPRESSION_RATIO = 1_000
_ONE_HUNDRED = Decimal("100")


class PortfolioManagerRunResult(NamedTuple):
    """Values needed by the entrypoint to assemble the output envelope."""

    status: ValidationStatus
    messages: list[ValidationMessage]
    outputs: PortfolioManagerOutputs


class _FindingCollector:
    """Bound findings while retaining a stable truncation signal."""

    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self.items: list[PortfolioManagerFinding] = []
        self.truncated = 0

    def add(
        self,
        severity: str,
        code: str,
        message: str,
        *,
        member_name: str = "",
        property_id: str = "",
        path: str = "",
        metadata: dict | None = None,
    ) -> None:
        """Append a finding until the configured surface limit is reached."""
        if len(self.items) >= self.maximum:
            self.truncated += 1
            return
        self.items.append(
            PortfolioManagerFinding(
                severity=severity,
                code=code,
                message=message,
                member_name=member_name,
                property_id=property_id,
                path=path,
                metadata=metadata or {},
            )
        )

    def finish(self) -> list[PortfolioManagerFinding]:
        """Use the final visible slot for an explicit truncation marker."""
        if self.truncated and self.items:
            self.items[-1] = PortfolioManagerFinding(
                severity="WARNING",
                code="portfolio_manager.findings.truncated",
                message=f"{self.truncated + 1} additional findings were suppressed.",
                metadata={"suppressed_count": self.truncated + 1},
            )
        return self.items


def run_portfolio_manager_validation(
    input_envelope: PortfolioManagerInputEnvelope,
) -> PortfolioManagerRunResult:
    """Download verified inputs, evaluate every safe report, and aggregate facts."""
    started = time.monotonic()
    inputs = input_envelope.inputs
    collector = _FindingCollector(inputs.max_findings)
    records: list[PortfolioManagerPropertyResult] = []
    file_count = 0
    invalid_file_count = 0

    with tempfile.TemporaryDirectory(prefix="portfolio-manager-") as temporary:
        workdir = Path(temporary)
        submission_item = _primary_report_item(input_envelope)
        if submission_item.size_bytes > inputs.max_input_bytes:
            collector.add(
                "ERROR",
                "portfolio_manager.input.too_large",
                "The submitted report exceeds the configured input byte limit.",
            )
        else:
            # The logical filename is evidence used for carrier recognition,
            # not a filesystem path. Keep it out of path construction even
            # though the app normally supplies a basename.
            submission_path = workdir / "submitted-report"
            download_verified_file(submission_item, submission_path)
            if inputs.submission_structure == "single_report":
                file_count = 1
                try:
                    parsed = parse_report_bytes(
                        submission_path.read_bytes(),
                        filename=submission_item.name,
                    )
                    if len(parsed) != 1:
                        raise PortfolioManagerParseError(
                            "Single-report mode requires exactly one property or grouped parent"
                        )
                    records.extend(parsed)
                except (PortfolioManagerParseError, ValidationError) as exc:
                    invalid_file_count += 1
                    collector.add(
                        "ERROR",
                        "portfolio_manager.report.invalid",
                        str(exc),
                        member_name=submission_item.name,
                    )
            else:
                (
                    records,
                    file_count,
                    invalid_file_count,
                ) = _read_zip_collection(
                    submission_path,
                    inputs=inputs,
                    collector=collector,
                )

        ebl = _load_ebl(input_envelope, workdir=workdir, collector=collector)

    _apply_checks_and_targets(
        records,
        inputs=inputs,
        ebl=ebl,
        collector=collector,
    )
    outputs = _build_outputs(
        records,
        inputs=inputs,
        ebl=ebl,
        file_count=file_count,
        invalid_file_count=invalid_file_count,
        collector=collector,
        execution_seconds=time.monotonic() - started,
    )
    messages = [_generic_message(finding) for finding in outputs.findings]
    status = (
        ValidationStatus.FAILED_VALIDATION
        if any(finding.severity == "ERROR" for finding in outputs.findings)
        else ValidationStatus.SUCCESS
    )
    return PortfolioManagerRunResult(status=status, messages=messages, outputs=outputs)


def _primary_report_item(input_envelope: PortfolioManagerInputEnvelope):
    """Return the uniquely declared submitted report."""
    return select_input_file(
        input_envelope.input_files,
        port_key="portfolio_manager_report",
        legacy_role="portfolio-manager-report",
    )


def _read_zip_collection(
    archive_path: Path,
    *,
    inputs,
    collector: _FindingCollector,
) -> tuple[list[PortfolioManagerPropertyResult], int, int]:
    """Inspect all safe archive members and continue after member-level failures."""
    records: list[PortfolioManagerPropertyResult] = []
    file_count = 0
    invalid_count = 0
    total_uncompressed = 0
    seen_names: set[str] = set()
    try:
        archive = zipfile.ZipFile(archive_path)
    except (OSError, zipfile.BadZipFile) as exc:
        collector.add(
            "ERROR",
            "portfolio_manager.archive.invalid",
            f"Could not read ZIP collection: {exc}",
        )
        return records, file_count, 1

    with archive:
        members = [item for item in archive.infolist() if not item.is_dir()]
        if len(members) > inputs.max_archive_members:
            collector.add(
                "ERROR",
                "portfolio_manager.archive.too_many_members",
                "ZIP collection exceeds the configured member limit.",
                metadata={"member_count": len(members)},
            )
            return records, len(members), len(members)
        for member in members:
            member_name = member.filename
            path = PurePosixPath(member_name)
            if _is_ignorable_archive_metadata(path):
                continue
            file_count += 1
            member_type = stat.S_IFMT(member.external_attr >> 16)
            unsafe = (
                path.is_absolute()
                or ".." in path.parts
                or len(path.parts) != 1
                or "\\" in member_name
                or "\x00" in member_name
                or member_type not in {0, stat.S_IFREG}
            )
            normalized_name = member_name.casefold()
            if normalized_name in seen_names:
                unsafe = True
            seen_names.add(normalized_name)
            suffix = path.suffix.casefold()
            if unsafe:
                invalid_count += 1
                collector.add(
                    "ERROR",
                    "portfolio_manager.archive.unsafe_member",
                    "ZIP member has an unsafe or duplicate path.",
                    member_name=member_name,
                )
                continue
            if suffix not in _SUPPORTED_MEMBER_SUFFIXES:
                invalid_count += 1
                collector.add(
                    "ERROR",
                    "portfolio_manager.archive.unsupported_member",
                    "ZIP members must be Portfolio Manager .xls, .xlsx, or .xml reports.",
                    member_name=member_name,
                )
                continue
            if member.flag_bits & 0x1:
                invalid_count += 1
                collector.add(
                    "ERROR",
                    "portfolio_manager.archive.encrypted_member",
                    "Encrypted ZIP members are not accepted.",
                    member_name=member_name,
                )
                continue
            total_uncompressed += member.file_size
            compressed_size = max(member.compress_size, 1)
            if (
                member.file_size > inputs.max_member_bytes
                or total_uncompressed > inputs.max_uncompressed_bytes
                or member.file_size / compressed_size > _MAX_COMPRESSION_RATIO
            ):
                invalid_count += 1
                collector.add(
                    "ERROR",
                    "portfolio_manager.archive.member_limit_exceeded",
                    "ZIP member exceeds the configured size or compression-ratio limits.",
                    member_name=member_name,
                )
                continue
            try:
                content = _read_member_bounded(
                    archive,
                    member,
                    maximum=inputs.max_member_bytes,
                )
                parsed = parse_report_bytes(content, filename=path.name)
                if len(parsed) != 1:
                    raise PortfolioManagerParseError(
                        "Each ZIP member must contain exactly one property or grouped parent"
                    )
                records.extend(parsed)
            except (
                OSError,
                RuntimeError,
                zipfile.BadZipFile,
                PortfolioManagerParseError,
                ValidationError,
            ) as exc:
                invalid_count += 1
                collector.add(
                    "ERROR",
                    "portfolio_manager.report.invalid",
                    str(exc),
                    member_name=member_name,
                )
        if file_count == 0:
            collector.add(
                "ERROR",
                "portfolio_manager.archive.empty",
                "ZIP collection contains no Portfolio Manager report members.",
            )
            invalid_count = max(invalid_count, 1)
    return records, file_count, invalid_count


def _read_member_bounded(
    archive: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    *,
    maximum: int,
) -> bytes:
    """Read at most one byte beyond the member cap before rejecting it."""
    with archive.open(member) as stream:
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise PortfolioManagerParseError("Archive member exceeds its byte limit")
    return content


def _is_ignorable_archive_metadata(path: PurePosixPath) -> bool:
    """Ignore operating-system metadata without broadening accepted report paths."""
    return (
        not path.parts
        or path.parts[0] == "__MACOSX"
        or path.name in {".DS_Store", "Thumbs.db"}
        or path.name.startswith("._")
    )


def _load_ebl(
    input_envelope: PortfolioManagerInputEnvelope,
    *,
    workdir: Path,
    collector: _FindingCollector,
) -> ExpectedBuildingsList | None:
    """Download and validate the optional immutable EBL resource."""
    try:
        item = select_resource_file(
            input_envelope.resource_files,
            port_key="expected_buildings_list",
            legacy_type="portfolio_manager_ebl_v1",
            required=False,
        )
    except FilePortLookupError:
        collector.add(
            "ERROR",
            "portfolio_manager.ebl.ambiguous",
            "Exactly one Expected Buildings List resource may be bound.",
        )
        return None
    if item is None:
        return None
    destination = workdir / "expected-buildings-list.json"
    try:
        download_verified_file(item, destination)
        return validate_expected_buildings_list_json(destination.read_bytes())
    except (OSError, UnicodeError, ValueError) as exc:
        collector.add(
            "ERROR",
            "portfolio_manager.ebl.invalid",
            f"Expected Buildings List is invalid: {exc}",
        )
        return None


def _apply_checks_and_targets(
    records: list[PortfolioManagerPropertyResult],
    *,
    inputs,
    ebl: ExpectedBuildingsList | None,
    collector: _FindingCollector,
) -> None:
    """Apply explicit workflow requirements and resolve each property's targets."""
    ebl_by_id = {building.id_value: building for building in ebl.buildings} if ebl else {}
    for record in records:
        identity = _identity_for_record(record, ebl) if ebl else ""
        expected = ebl_by_id.get(identity)
        record.ebl_match = expected is not None if ebl else None
        target = (
            expected.euit
            if expected is not None and expected.euit is not None
            else inputs.default_euit_kbtu_ft2_yr
        )
        record.resolved_euit_kbtu_ft2_yr = target
        record.resolved_euit_source = (
            "ebl"
            if expected is not None and expected.euit is not None
            else ("default" if target is not None else "none")
        )
        if target is not None and record.weather_normalized_site_eui_kbtu_ft2_yr is not None:
            actual = record.weather_normalized_site_eui_kbtu_ft2_yr
            record.euit_margin_kbtu_ft2_yr = target - actual
            record.euit_ratio = actual / target
            record.euit_percent_difference = ((target - actual) / target) * _ONE_HUNDRED
            record.meets_euit = actual <= target
            record.near_euit = (
                not record.meets_euit
                and actual <= target * (_ONE_HUNDRED + inputs.near_target_percent) / _ONE_HUNDRED
            )

        record.reporting_period_complete = _period_is_complete(
            record.reporting_period_start,
            record.reporting_period_end,
            months=inputs.minimum_reporting_period_months,
        )
        record.reporting_period_fresh = _period_is_fresh(
            record.reporting_period_end,
            reference_date=inputs.reporting_period_reference_date,
            maximum_age_months=inputs.maximum_reporting_period_age_months,
        )

        record.benchmark_ready = all(
            (
                record.property_id,
                _period_is_complete(
                    record.reporting_period_start,
                    record.reporting_period_end,
                    months=12,
                ),
                record.gross_floor_area_ft2 is not None,
                record.site_eui_kbtu_ft2_yr is not None,
            )
        )
        record.form_c_ready = _form_c_ready(record)
        _required_check_findings(record, inputs=inputs, collector=collector)


_FORM_C_CONDITIONAL_METRICS = {
    "weather_normalized_site_electricity_kwh",
    "weather_normalized_site_electricity_intensity_kwh_ft2",
    "weather_normalized_site_natural_gas_therms",
    "weather_normalized_site_natural_gas_intensity_therms_ft2",
    "onsite_renewable_electricity_generated_kwh",
    "onsite_renewable_electricity_exported_kwh",
    "electricity_grid_and_onsite_renewable_kbtu",
    "electricity_grid_purchase_kbtu",
    "onsite_renewable_electricity_used_onsite_kbtu",
    "natural_gas_use_kbtu",
    "percent_electricity_from_onsite_renewables",
}


def _form_c_ready(record: PortfolioManagerPropertyResult) -> bool:
    """Require the Washington Z6.3 metric bundle without inventing N/A values."""
    required_values = (
        record.benchmark_ready,
        record.weather_normalized_site_eui_kbtu_ft2_yr is not None,
        record.national_median_site_eui_kbtu_ft2_yr is not None,
        record.site_energy_use_kbtu is not None,
        record.weather_normalized_site_energy_use_kbtu is not None,
        record.heating_degree_days is not None,
        record.cooling_degree_days is not None,
        record.weather_station_id,
        record.weather_station_name,
    )
    conditional_metrics_are_reported = all(
        record.metric_states.get(metric) in {"value", "not_available"}
        for metric in _FORM_C_CONDITIONAL_METRICS
    )
    return all(required_values) and conditional_metrics_are_reported


def _required_check_findings(
    record: PortfolioManagerPropertyResult,
    *,
    inputs,
    collector: _FindingCollector,
) -> None:
    """Emit only configured readiness failures; observational facts remain outputs."""
    kwargs = {"member_name": record.member_name, "property_id": record.property_id}
    for metric, state in record.metric_states.items():
        if state == "invalid":
            collector.add(
                "ERROR",
                "portfolio_manager.invalid_metric_value",
                f"Metric {metric!r} contains an invalid value.",
                path=metric,
                **kwargs,
            )
    if inputs.require_complete_reporting_period and record.reporting_period_complete is not True:
        collector.add(
            "ERROR",
            "portfolio_manager.reporting_period.incomplete",
            (
                "The report does not prove the configured minimum of "
                f"{inputs.minimum_reporting_period_months} consecutive months."
            ),
            **kwargs,
        )
    if (
        inputs.maximum_reporting_period_age_months is not None
        and record.reporting_period_fresh is not True
    ):
        collector.add(
            "ERROR",
            "portfolio_manager.reporting_period.stale_or_unverifiable",
            (
                "The reporting period is stale or cannot be verified against "
                "the configured reference date."
            ),
            **kwargs,
        )
    if inputs.require_benchmark_ready and not record.benchmark_ready:
        collector.add(
            "ERROR",
            "portfolio_manager.readiness.benchmark_incomplete",
            "The report lacks one or more metrics required for benchmark readiness.",
            **kwargs,
        )
    if inputs.require_form_c_ready and not record.form_c_ready:
        collector.add(
            "ERROR",
            "portfolio_manager.readiness.form_c_incomplete",
            "The report lacks one or more metrics required for Form C readiness.",
            **kwargs,
        )
    if (
        inputs.require_weather_normalized_site_eui
        and record.weather_normalized_site_eui_kbtu_ft2_yr is None
    ):
        collector.add(
            "ERROR",
            "portfolio_manager.wa_euit.wneui_unavailable",
            "Weather Normalized Site EUI is unavailable in the report.",
            **kwargs,
        )
    if inputs.require_energy_star_score and record.energy_star_score is None:
        collector.add(
            "ERROR",
            "portfolio_manager.metric.energy_star_score_missing",
            "ENERGY STAR score is required but unavailable.",
            **kwargs,
        )
    if inputs.require_washington_standard_id and not record.washington_standard_id:
        collector.add(
            "ERROR",
            "portfolio_manager.identity.washington_standard_id_missing",
            ("The report does not include the State of Washington Clean Buildings Standard ID."),
            **kwargs,
        )
    _alert_policy_findings(record, inputs=inputs, collector=collector)
    if inputs.compare_to_euit:
        if record.resolved_euit_kbtu_ft2_yr is None:
            collector.add(
                "ERROR",
                "portfolio_manager.wa_euit.target_unavailable",
                "No default or EBL EUIt could be resolved for this property.",
                **kwargs,
            )
        elif record.weather_normalized_site_eui_kbtu_ft2_yr is None:
            collector.add(
                "ERROR",
                "portfolio_manager.wa_euit.wneui_unavailable",
                "Weather Normalized Site EUI is unavailable for target comparison.",
                **kwargs,
            )
        elif record.meets_euit is False:
            collector.add(
                "ERROR",
                "portfolio_manager.wa_euit.target_exceeded",
                "Weather Normalized Site EUI exceeds the resolved EUIt.",
                metadata={
                    "actual": str(record.weather_normalized_site_eui_kbtu_ft2_yr),
                    "target": str(record.resolved_euit_kbtu_ft2_yr),
                },
                **kwargs,
            )


_ALERT_POLICY_FIELDS = {
    "meter_less_than_12_months": "meter_less_than_12_months_policy",
    "meter_gap": "meter_gap_policy",
    "meter_overlap": "meter_overlap_policy",
    "no_meters_selected": "no_meters_selected_policy",
    "long_meter_entry": "long_meter_entry_policy",
    "estimated_energy": "estimated_energy_policy",
}


def _alert_policy_findings(
    record: PortfolioManagerPropertyResult,
    *,
    inputs,
    collector: _FindingCollector,
) -> None:
    """Evaluate visible Alert Metric policies without treating absence as clean."""
    categorized: dict[str, list[tuple[str, str]]] = {
        category: [] for category in _ALERT_POLICY_FIELDS
    }
    other: list[tuple[str, str]] = []
    for heading, state in record.alert_states.items():
        category = _alert_category(heading)
        if category is None:
            other.append((heading, state))
        else:
            categorized[category].append((heading, state))

    kwargs = {"member_name": record.member_name, "property_id": record.property_id}
    for category, input_field in _ALERT_POLICY_FIELDS.items():
        policy = getattr(inputs, input_field)
        if policy == "allow":
            continue
        matches = categorized[category]
        if not matches:
            collector.add(
                "ERROR",
                "portfolio_manager.check_not_verifiable",
                (
                    f"The enabled {category.replace('_', ' ')} check cannot be "
                    "verified because its Alert Metric is absent."
                ),
                metadata={"check": category, "configured_policy": policy},
                **kwargs,
            )
            continue
        for heading, state in matches:
            if state == "clean":
                continue
            collector.add(
                policy.upper(),
                f"portfolio_manager.data_quality.{category}",
                f"Alert Metric {heading!r} is {state.replace('_', ' ')}.",
                path=heading,
                metadata={"evidence_state": state},
                **kwargs,
            )

    if inputs.other_alert_policy != "allow":
        for heading, state in other:
            if state == "clean":
                continue
            collector.add(
                inputs.other_alert_policy.upper(),
                "portfolio_manager.data_quality.other_alert",
                f"Alert Metric {heading!r} is {state.replace('_', ' ')}.",
                path=heading,
                metadata={"evidence_state": state},
                **kwargs,
            )


def _alert_category(heading: str) -> str | None:
    """Map fixture-backed Portfolio Manager alert labels to stable check identities."""
    normalized = re.sub(r"[^a-z0-9]+", "", heading.casefold())
    if "month" in normalized and ("lessthan12" in normalized or "lessthantwelve" in normalized):
        return "meter_less_than_12_months"
    if "gap" in normalized:
        return "meter_gap"
    if "overlap" in normalized:
        return "meter_overlap"
    if ("nomet" in normalized and "selected" in normalized) or "meternoassociation" in normalized:
        return "no_meters_selected"
    if "65days" in normalized or "morethan65days" in normalized:
        return "long_meter_entry"
    if "estimated" in normalized and any(
        token in normalized for token in ("energy", "electricity", "naturalgas")
    ):
        return "estimated_energy"
    return None


def _build_outputs(
    records: list[PortfolioManagerPropertyResult],
    *,
    inputs,
    ebl: ExpectedBuildingsList | None,
    file_count: int,
    invalid_file_count: int,
    collector: _FindingCollector,
    execution_seconds: float,
) -> PortfolioManagerOutputs:
    """Reconcile roster/cycles and calculate overlap-safe portfolio aggregates."""
    property_ids = [record.property_id for record in records]
    counts = Counter(property_ids)
    duplicate_ids = sorted(identifier for identifier, count in counts.items() if count > 1)
    cycles = {
        (record.reporting_period_start, record.reporting_period_end)
        for record in records
        if record.reporting_period_start or record.reporting_period_end
    }
    property_id_set = set(property_ids)
    overlaps = [
        record
        for record in records
        if record.parent_property_id
        and record.parent_property_id in property_id_set
        and record.parent_property_id != record.property_id
    ]

    expected_ids = {building.id_value for building in ebl.buildings} if ebl else set()
    submitted_ebl_ids = {
        identity for record in records if (identity := _identity_for_record(record, ebl))
    }
    missing_expected = sorted(expected_ids - submitted_ebl_ids)
    unexpected = sorted(submitted_ebl_ids - expected_ids) if ebl else []

    if missing_expected:
        collector.add(
            "INFO",
            "portfolio_manager.reconciliation.expected_missing",
            f"{len(missing_expected)} expected building(s) were not submitted.",
            metadata={"ids": missing_expected},
        )
    if unexpected:
        collector.add(
            "INFO",
            "portfolio_manager.reconciliation.submitted_unexpected",
            f"{len(unexpected)} submitted building(s) were not in the EBL.",
            metadata={"ids": unexpected},
        )
    if duplicate_ids:
        collector.add(
            "INFO",
            "portfolio_manager.reconciliation.duplicate_properties",
            f"{len(duplicate_ids)} duplicate Portfolio Manager Property ID(s) were found.",
            metadata={"ids": duplicate_ids},
        )
    if len(cycles) > 1:
        collector.add(
            "INFO",
            "portfolio_manager.reconciliation.reporting_cycles_vary",
            "Submitted reports contain more than one reporting cycle.",
        )
    if overlaps:
        collector.add(
            "WARNING",
            "portfolio_manager.aggregation.parent_child_overlap",
            "Parent/child overlap makes portfolio aggregate metrics unavailable.",
            metadata={"overlap_count": len(overlaps)},
        )

    aggregate_available = not overlaps and not duplicate_ids
    areas = [record.gross_floor_area_ft2 for record in records]
    total_area = (
        sum((area for area in areas if area is not None), Decimal())
        if aggregate_available and all(area is not None for area in areas) and areas
        else None
    )
    weighted_wneui = _weighted_metric(
        records,
        "weather_normalized_site_eui_kbtu_ft2_yr",
        aggregate_available=aggregate_available,
    )
    weighted_score = _weighted_metric(
        records,
        "energy_star_score",
        aggregate_available=aggregate_available,
        allow_partial=True,
    )
    target_covered = [record for record in records if record.resolved_euit_kbtu_ft2_yr is not None]
    target_comparable = [record for record in target_covered if record.meets_euit is not None]
    target_met = [record for record in target_comparable if record.meets_euit is True]
    target_above = [record for record in target_comparable if record.meets_euit is False]
    target_near = [record for record in target_above if record.near_euit is True]
    excess = None
    if aggregate_available:
        comparable = [
            record
            for record in records
            if record.gross_floor_area_ft2 is not None
            and record.weather_normalized_site_eui_kbtu_ft2_yr is not None
            and record.resolved_euit_kbtu_ft2_yr is not None
        ]
        if comparable:
            excess = sum(
                (
                    max(
                        record.weather_normalized_site_eui_kbtu_ft2_yr
                        - record.resolved_euit_kbtu_ft2_yr,
                        Decimal(),
                    )
                    * record.gross_floor_area_ft2
                    for record in comparable
                ),
                Decimal(),
            )

    return PortfolioManagerOutputs(
        submission_structure=inputs.submission_structure,
        file_count=file_count,
        valid_file_count=max(0, file_count - invalid_file_count),
        invalid_file_count=invalid_file_count,
        property_count=len(records),
        reporting_cycle_count=len(cycles),
        reporting_cycles_match=len(cycles) <= 1,
        complete_reporting_period_property_count=sum(
            record.reporting_period_complete is True for record in records
        ),
        fresh_reporting_period_property_count=sum(
            record.reporting_period_fresh is True for record in records
        ),
        expected_building_count=len(expected_ids),
        matched_expected_building_count=len(expected_ids & submitted_ebl_ids),
        missing_expected_building_count=len(missing_expected),
        unexpected_submitted_building_count=len(unexpected),
        duplicate_submitted_property_count=len(duplicate_ids),
        parent_child_overlap_count=len(overlaps),
        target_covered_property_count=len(target_covered),
        target_uncovered_property_count=len(records) - len(target_covered),
        target_comparable_property_count=len(target_comparable),
        target_met_property_count=len(target_met),
        target_above_property_count=len(target_above),
        target_near_property_count=len(target_near),
        benchmark_ready_property_count=sum(record.benchmark_ready for record in records),
        form_c_ready_property_count=sum(record.form_c_ready for record in records),
        aggregate_metrics_available=aggregate_available,
        total_gross_floor_area_ft2=total_area,
        weighted_weather_normalized_site_eui_kbtu_ft2_yr=weighted_wneui,
        energy_star_score_property_count=sum(
            record.energy_star_score is not None for record in records
        ),
        weighted_energy_star_score=weighted_score,
        estimated_excess_energy_kbtu=excess,
        target_coverage_percent=_percent(len(target_covered), len(records)),
        target_compliance_percent=_percent(
            len(target_met),
            len(target_comparable),
        ),
        floor_area_target_compliance_percent=_floor_area_compliance_percent(
            target_comparable,
            aggregate_available=aggregate_available,
        ),
        property_results=records,
        missing_expected_ids=missing_expected,
        unexpected_submitted_ids=unexpected,
        duplicate_submitted_property_ids=duplicate_ids,
        findings=collector.finish(),
        execution_seconds=execution_seconds,
    )


def _identity_for_record(
    record: PortfolioManagerPropertyResult,
    ebl: ExpectedBuildingsList | None,
) -> str:
    """Read the configured identity without constraining it to one building."""
    if ebl is None:
        return ""
    field = ebl.id_field
    if field.kind == "property_id":
        return record.property_id
    if field.kind == "parent_property_id":
        return record.parent_property_id
    if field.kind == "standard_id":
        if field.name == "State of Washington Clean Buildings Standard":
            return record.washington_standard_id
        return record.custom_ids.get(field.name, "")
    return record.custom_ids.get(field.name, "")


def _weighted_metric(
    records: list[PortfolioManagerPropertyResult],
    field: str,
    *,
    aggregate_available: bool,
    allow_partial: bool = False,
) -> Decimal | None:
    """Return a GFA-weighted metric only with a complete, overlap-safe denominator."""
    if not aggregate_available or not records:
        return None
    pairs = [(getattr(record, field), record.gross_floor_area_ft2) for record in records]
    if allow_partial:
        pairs = [(value, area) for value, area in pairs if value is not None and area is not None]
        if not pairs:
            return None
    if any(value is None or area is None for value, area in pairs):
        return None
    denominator = sum((area for _, area in pairs), Decimal())
    if denominator <= 0:
        return None
    return sum((value * area for value, area in pairs), Decimal()) / denominator


def _percent(numerator: int, denominator: int) -> Decimal | None:
    """Return a decimal percentage or null when the denominator is empty."""
    if denominator <= 0:
        return None
    return Decimal(numerator) / Decimal(denominator) * _ONE_HUNDRED


def _floor_area_compliance_percent(
    records: list[PortfolioManagerPropertyResult],
    *,
    aggregate_available: bool,
) -> Decimal | None:
    """Return compliant GFA over comparable GFA with an explicit null denominator."""
    if (
        not aggregate_available
        or not records
        or any(record.gross_floor_area_ft2 is None for record in records)
    ):
        return None
    denominator = sum(
        (record.gross_floor_area_ft2 for record in records),
        Decimal(),
    )
    if denominator <= 0:
        return None
    numerator = sum(
        (record.gross_floor_area_ft2 for record in records if record.meets_euit is True),
        Decimal(),
    )
    return numerator / denominator * _ONE_HUNDRED


def _period_is_complete(
    start: date | None,
    end: date | None,
    *,
    months: int,
) -> bool:
    """Require a known inclusive interval spanning at least whole calendar months."""
    if start is None or end is None or end < start:
        return False
    return end >= _shift_months(start, months) - timedelta(days=1)


def _period_is_fresh(
    end: date | None,
    *,
    reference_date: date | None,
    maximum_age_months: int | None,
) -> bool | None:
    """Compare the report end date with the explicit run reference date."""
    if maximum_age_months is None:
        return None
    if end is None or reference_date is None:
        return False
    return end >= _shift_months(reference_date, -maximum_age_months)


def _shift_months(value: date, months: int) -> date:
    """Shift a date by whole calendar months while clamping its day."""
    month_index = value.year * 12 + value.month - 1 + months
    year, zero_based_month = divmod(month_index, 12)
    month = zero_based_month + 1
    day = min(value.day, monthrange(year, month)[1])
    return date(year, month, day)


def _generic_message(finding: PortfolioManagerFinding) -> ValidationMessage:
    """Project a rich domain finding into the shared generic message surface."""
    severity = {
        "ERROR": Severity.ERROR,
        "WARNING": Severity.WARNING,
        "INFO": Severity.INFO,
    }[finding.severity]
    location = None
    if finding.member_name or finding.path:
        location = MessageLocation(
            file_role="portfolio-manager-report",
            path=finding.path or finding.member_name,
        )
    return ValidationMessage(
        severity=severity,
        code=finding.code,
        text=finding.message,
        location=location,
    )


def property_results_artifact_json(outputs: PortfolioManagerOutputs) -> str:
    """Serialize the carrier-neutral result artifact deterministically."""
    payload = {
        "schema_version": "validibot.portfolio_manager.property_results.v1",
        "submission_structure": outputs.submission_structure,
        "summary": outputs.model_dump(
            mode="json",
            exclude={
                "property_results",
                "missing_expected_ids",
                "unexpected_submitted_ids",
                "duplicate_submitted_property_ids",
                "findings",
            },
        ),
        "properties": [
            record.model_dump(mode="json", exclude_none=False)
            for record in outputs.property_results
        ],
        "reconciliation": {
            "missing_expected_ids": outputs.missing_expected_ids,
            "unexpected_submitted_ids": outputs.unexpected_submitted_ids,
            "duplicate_submitted_property_ids": (outputs.duplicate_submitted_property_ids),
        },
        "findings": [
            finding.model_dump(mode="json", exclude_none=False) for finding in outputs.findings
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
