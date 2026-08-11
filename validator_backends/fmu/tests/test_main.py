"""Tests for the FMU backend entrypoint envelope assembly.

The runner tests cover FMU simulation mechanics. These tests cover the thin
container boundary around it: uploaded output files must survive into the
``FMUOutputEnvelope`` so the Django app can index them as produced artifacts.
"""

from __future__ import annotations

from validator_backends.fmu import main as fmu_main
from validibot_shared.fmu.envelopes import FMUInputEnvelope, FMUInputs, FMUOutputs
from validibot_shared.validations.envelopes import (
    ATTEMPT_CONTRACT_VERSION,
    ExecutionContext,
    InputFileItem,
    OrganizationInfo,
    SupportedMimeType,
    ValidationArtifact,
    ValidatorInfo,
    ValidatorType,
    WorkflowInfo,
)


def _input_envelope() -> FMUInputEnvelope:
    """Build the smallest valid FMU input envelope for entrypoint tests."""

    return FMUInputEnvelope(
        run_id="run-1",
        validator=ValidatorInfo(id="validator-1", type=ValidatorType.FMU, version="2"),
        org=OrganizationInfo(id="org-1", name="Org"),
        workflow=WorkflowInfo(id="workflow-1", step_id="step-1", step_name="FMU"),
        input_files=[
            InputFileItem(
                name="model.fmu",
                mime_type=SupportedMimeType.FMU,
                role="fmu",
                port_key="fmu_model",
                uri="gs://bucket/inputs/model.fmu",
                size_bytes=42,
                sha256="1" * 64,
                storage_version="1700000000000000",
            ),
        ],
        inputs=FMUInputs(),
        context=ExecutionContext(
            execution_bundle_uri="gs://bucket/runs/run-1",
            execution_attempt_id="attempt-1",
            step_run_id="step-run-1",
            attempt_contract_version=ATTEMPT_CONTRACT_VERSION,
            expected_output_uri="gs://bucket/output.json",
            skip_callback=True,
        ),
    )


def test_main_includes_uploaded_artifacts_in_output_envelope(monkeypatch, tmp_path):
    """Uploaded FMU files must be returned for Django artifact indexing.

    The backend already uploaded the output directory but previously discarded
    the returned artifact list when constructing ``FMUOutputEnvelope``. This
    pins the exact callback-boundary behavior that Django relies on.
    """

    captured = {}
    uploaded_artifact = ValidationArtifact(
        name="result.json",
        type="file",
        mime_type="application/json",
        uri="gs://bucket/runs/run-1/outputs/result.json",
        size_bytes=42,
        sha256="2" * 64,
        storage_version="1700000000000001",
    )
    raw_outputs = fmu_main.RawOutputs(
        format="directory",
        manifest_uri="gs://bucket/runs/run-1/outputs/manifest.json",
    )

    monkeypatch.setattr(fmu_main, "load_input_envelope", lambda _model: _input_envelope())
    monkeypatch.setattr(
        fmu_main,
        "replay_existing_output",
        lambda _input, _output_type: False,
    )
    monkeypatch.setattr(
        fmu_main,
        "run_fmu_simulation",
        lambda _envelope: (
            FMUOutputs(
                output_values={"y": 1.0},
                execution_seconds=0.1,
                simulation_time_reached=1.0,
            ),
            tmp_path,
        ),
    )
    monkeypatch.setattr(
        fmu_main,
        "_upload_outputs",
        lambda _work_dir, _bundle_uri: ([uploaded_artifact], raw_outputs),
    )
    monkeypatch.setattr(fmu_main, "get_output_uri", lambda _envelope: "gs://bucket/output.json")
    monkeypatch.setattr(
        fmu_main,
        "upload_envelope",
        lambda envelope, uri: captured.update({"envelope": envelope, "uri": uri}),
    )
    monkeypatch.setattr(fmu_main, "post_callback", lambda **_kwargs: None)
    monkeypatch.setattr(fmu_main, "_cleanup", lambda _work_dir: None)

    exit_code = fmu_main.main()

    assert exit_code == 0
    assert captured["uri"] == "gs://bucket/output.json"
    output = captured["envelope"]
    assert output.artifacts == [uploaded_artifact]
    assert output.raw_outputs == raw_outputs
    assert output.execution_attempt_id == "attempt-1"
    assert len(output.input_envelope_sha256) == 64
