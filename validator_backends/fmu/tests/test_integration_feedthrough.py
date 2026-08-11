"""
Integration-style FMU test using the Feedthrough.fmu fixture.

This exercises the runner against a real FMU (no network) through the same
streaming integrity verifier used in production, then asserts the output echoes
the input for the known feedthrough variable.

Two FMU fixtures are available:
- Feedthrough.fmu: FMI 2.0, x86_64 only (darwin64)
- Feedthrough_fmi3_arm64.fmu: FMI 3.0, includes aarch64-darwin for Apple Silicon
"""

from __future__ import annotations

import hashlib
import platform
import shutil
from pathlib import Path

import pytest

from validator_backends.fmu import runner
from validibot_shared.fmu.envelopes import FMUInputEnvelope, FMUInputs, FMUOutputs
from validibot_shared.validations.envelopes import (
    ATTEMPT_CONTRACT_VERSION,
    ExecutionContext,
    InputFileItem,
    SupportedMimeType,
)


def _is_apple_silicon() -> bool:
    """Check if running on Apple Silicon (ARM64 macOS)."""
    return platform.system().lower() == "darwin" and platform.machine().lower() in (
        "arm64",
        "aarch64",
    )


def _verified_local_item(fixture: Path) -> InputFileItem:
    """Describe a fixture using the strict local immutable-file contract."""
    payload = fixture.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    return InputFileItem(
        name="model.fmu",
        mime_type=SupportedMimeType.FMU,
        role="fmu",
        port_key="fmu_model",
        uri=f"file://{fixture}",
        size_bytes=len(payload),
        sha256=digest,
        storage_version=f"sha256:{digest}",
    )


@pytest.mark.integration
def test_feedthrough_fmu_echoes_input_x86(tmp_path) -> None:
    """Run FMI 2.0 Feedthrough.fmu (x86_64) and assert Int32_output matches Int32_input."""
    if _is_apple_silicon():
        pytest.skip("Feedthrough.fmu (FMI 2.0) is x86_64-only; skip on Apple Silicon.")

    fixture = Path(__file__).parent / "assets" / "Feedthrough.fmu"
    # The .fmu binaries are gitignored (see .gitignore: *.fmu), so they are
    # present for local runs but absent in CI. Skip cleanly rather than fail
    # when the fixture is not checked out — this stays a real integration test
    # where the asset exists and a no-op where it doesn't.
    if not fixture.exists():
        pytest.skip("Feedthrough.fmu fixture not present (gitignored *.fmu).")

    envelope = FMUInputEnvelope(
        run_id="test-run",
        validator={"id": "1", "type": "FMU", "version": "1"},
        org={"id": "1", "name": "Test Org"},
        workflow={"id": "1", "step_id": "1", "step_name": "Feedthrough"},
        input_files=[_verified_local_item(fixture)],
        inputs=FMUInputs(
            input_values={"Int32_input": 5},
            output_variables=["Int32_output"],
        ),
        context=ExecutionContext(
            callback_url="http://example.com",
            execution_bundle_uri=str(tmp_path),
            execution_attempt_id="attempt-1",
            step_run_id="step-run-1",
            attempt_contract_version=ATTEMPT_CONTRACT_VERSION,
            expected_output_uri=f"file://{tmp_path / 'output.json'}",
            skip_callback=True,
        ),
    )

    outputs, work_dir = runner.run_fmu_simulation(envelope)
    try:
        assert isinstance(outputs, FMUOutputs)
        assert outputs.output_values["Int32_output"] == pytest.approx(5)
    finally:
        shutil.rmtree(work_dir)


@pytest.mark.integration
def test_feedthrough_fmu_echoes_input_arm64(tmp_path) -> None:
    """Run FMI 3.0 Feedthrough.fmu (ARM64) and assert Int32_output matches Int32_input.

    This test uses the Reference FMUs from https://github.com/modelica/Reference-FMUs
    which include native aarch64-darwin binaries for Apple Silicon.
    """
    if not _is_apple_silicon():
        pytest.skip("FMI 3.0 ARM64 test only runs on Apple Silicon.")

    fixture = Path(__file__).parent / "assets" / "Feedthrough_fmi3_arm64.fmu"
    # Gitignored fixture (see .gitignore: *.fmu) — skip cleanly when absent
    # rather than fail, mirroring the x86 test above.
    if not fixture.exists():
        pytest.skip("Feedthrough_fmi3_arm64.fmu fixture not present (gitignored *.fmu).")

    envelope = FMUInputEnvelope(
        run_id="test-run",
        validator={"id": "1", "type": "FMU", "version": "1"},
        org={"id": "1", "name": "Test Org"},
        workflow={"id": "1", "step_id": "1", "step_name": "Feedthrough"},
        input_files=[_verified_local_item(fixture)],
        inputs=FMUInputs(
            input_values={"Int32_input": 5},
            output_variables=["Int32_output"],
        ),
        context=ExecutionContext(
            callback_url="http://example.com",
            execution_bundle_uri=str(tmp_path),
            execution_attempt_id="attempt-1",
            step_run_id="step-run-1",
            attempt_contract_version=ATTEMPT_CONTRACT_VERSION,
            expected_output_uri=f"file://{tmp_path / 'output.json'}",
            skip_callback=True,
        ),
    )

    outputs, work_dir = runner.run_fmu_simulation(envelope)
    try:
        assert isinstance(outputs, FMUOutputs)
        assert outputs.output_values["Int32_output"] == pytest.approx(5)
    finally:
        shutil.rmtree(work_dir)
