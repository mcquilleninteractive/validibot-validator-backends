"""
FMU simulation runner for Cloud Run Jobs.

Resolves the FMU from GCS, runs a simulation with fmpy, and returns outputs
keyed by native FMU variable names (as specified in the envelope). The core
Django app maps these back to StepIODefinition rows on ingestion.
"""

from __future__ import annotations

import logging
import multiprocessing
import time
from typing import TYPE_CHECKING

from fmpy import read_model_description, simulate_fmu

from validator_backends.core.scratch import attempt_scratch_base
from validator_backends.core.storage_client import (
    create_attempt_work_dir,
    download_verified_file,
)
from validibot_shared.fmu.envelopes import FMUOutputs
from validibot_shared.validations.file_ports import select_input_file


if TYPE_CHECKING:
    from pathlib import Path

    from validibot_shared.fmu.envelopes import FMUInputEnvelope

logger = logging.getLogger(__name__)

# Hard wall-clock budget for the untrusted FMU simulation. fmpy.simulate_fmu
# loads and executes the attacker-supplied FMU's native shared library in
# process, so a malicious or pathological model can spin (infinite loop, busy
# wait) forever. We run the call in a killable child process and terminate it
# once this budget elapses, mirroring the SHACL backend's killable-subprocess
# pattern (see ``validator_backends/shacl/engine.py``). The value sits below the
# container's outer timeout so the simulation is killed cleanly with a useful
# message instead of an opaque container kill.
FMU_SIMULATION_TIMEOUT_SECONDS = 300

# Grace period after ``terminate()`` (SIGTERM) before escalating to
# ``kill()`` (SIGKILL). Native FMU code may ignore SIGTERM, so we escalate.
_TERMINATE_GRACE_SECONDS = 5.0

# Multiprocessing start method for the killable child. "spawn" gives a fresh
# interpreter (safest/most predictable when killing native code mid-run). Kept
# as a module-level name so tests can substitute "fork" — under "fork" the
# child inherits the parent's monkeypatched ``simulate_fmu``, which lets a test
# drive the timeout path without shipping a sleeping FMU.
_MP_START_METHOD = "spawn"


class FMUSimulationTimeoutError(RuntimeError):
    """Raised when the untrusted FMU simulation exceeds its wall-clock budget.

    A dedicated subclass of ``RuntimeError`` so callers can distinguish a
    deliberate timeout kill (the security boundary doing its job) from a
    genuine simulation error, while remaining backward compatible with code
    that only catches ``RuntimeError``.
    """


def _simulate_fmu_child(
    result_queue: multiprocessing.Queue,
    *,
    fmu_path: str,
    start_time: float | None,
    stop_time: float | None,
    step_size: float | None,
    requested_outputs: list[str] | None,
    start_values: dict,
) -> None:
    """Run ``simulate_fmu`` in a child process and post the result to a queue.

    WHY: ``simulate_fmu`` executes the FMU's native shared library, which is
    attacker-supplied. Running it in a separate, killable process lets the
    parent enforce a hard wall-clock timeout — the parent can terminate this
    child without being blocked by native code that ignores in-process signals.

    The fmpy ``logger`` callback cannot cross the process boundary, so log
    messages are collected here and returned alongside the result. The result
    array (a numpy structured array) is picklable and round-trips through the
    queue.
    """
    log_messages: list[str] = []
    try:
        result = simulate_fmu(
            filename=fmu_path,
            start_time=start_time,
            stop_time=stop_time,
            step_size=step_size,
            output=requested_outputs if requested_outputs else None,
            start_values=start_values,
            logger=log_messages.append,
        )
        result_queue.put(("ok", result, log_messages))
    except Exception as exc:
        # Catch broadly: any failure in the untrusted simulation must be
        # reported back to the parent rather than crashing the child silently.
        # Pass the message (not the exception object) to avoid pickling issues
        # with exotic exception types raised by native FMU code.
        result_queue.put(("error", f"{type(exc).__name__}: {exc}", log_messages))


def _run_simulation_with_timeout(
    *,
    fmu_path: Path,
    start_time: float | None,
    stop_time: float | None,
    step_size: float | None,
    requested_outputs: list[str],
    start_values: dict,
) -> tuple[object, list[str]]:
    """Run the FMU simulation in a killable child with a hard wall-clock timeout.

    Returns ``(result, log_messages)`` on success. Raises
    :class:`FMUSimulationTimeoutError` if the child does not finish within
    :data:`FMU_SIMULATION_TIMEOUT_SECONDS`, terminating (and, if necessary,
    killing) the child first. Raises ``RuntimeError`` for any in-child error.

    WHY ``spawn``: a fresh interpreter avoids inheriting the parent's loaded
    state/threads, which is both safer and more predictable when the child must
    be killed mid-execution of native FMU code.
    """
    ctx = multiprocessing.get_context(_MP_START_METHOD)
    result_queue: multiprocessing.Queue = ctx.Queue()
    process = ctx.Process(
        target=_simulate_fmu_child,
        args=(result_queue,),
        kwargs={
            "fmu_path": str(fmu_path),
            "start_time": start_time,
            "stop_time": stop_time,
            "step_size": step_size,
            "requested_outputs": requested_outputs,
            "start_values": start_values,
        },
        daemon=True,
    )
    process.start()
    process.join(FMU_SIMULATION_TIMEOUT_SECONDS)

    if process.is_alive():
        # The child blew the budget — kill it. terminate() sends SIGTERM;
        # escalate to kill() (SIGKILL) if native code ignores it.
        logger.warning(
            "FMU simulation exceeded %ss budget; terminating child process.",
            FMU_SIMULATION_TIMEOUT_SECONDS,
        )
        process.terminate()
        process.join(_TERMINATE_GRACE_SECONDS)
        if process.is_alive():
            process.kill()
            process.join()
        raise FMUSimulationTimeoutError(
            f"FMU simulation exceeded the {FMU_SIMULATION_TIMEOUT_SECONDS}s "
            "wall-clock budget and was terminated. The model may contain an "
            "infinite loop or be too large; reduce the stop time / step count "
            "or simplify the model.",
        )

    try:
        outcome = result_queue.get_nowait()
    except Exception as exc:  # queue empty / child died without posting
        raise RuntimeError(
            "FMU simulation child process exited without returning a result "
            f"(exit code {process.exitcode}).",
        ) from exc

    status, payload, log_messages = outcome
    if status == "error":
        raise RuntimeError(str(payload))
    return payload, log_messages


def run_fmu_simulation(input_envelope: FMUInputEnvelope) -> tuple[FMUOutputs, Path]:
    """
    Execute an FMU using fmpy and return FMUOutputs plus the working directory.

    Raises:
        ValueError: If input_envelope is missing required fields
        RuntimeError: If simulation fails
    """
    # Validate required fields
    if input_envelope is None:
        raise ValueError("input_envelope is required")
    if not input_envelope.run_id:
        raise ValueError("input_envelope.run_id is required")
    if not input_envelope.input_files:
        raise ValueError("input_envelope.input_files is required")
    if input_envelope.inputs is None:
        raise ValueError("input_envelope.inputs is required")
    if input_envelope.inputs.simulation is None:
        raise ValueError("input_envelope.inputs.simulation is required")

    start_time = time.time()
    work_dir = create_attempt_work_dir(
        attempt_scratch_base("fmu_run"),
        str(input_envelope.context.execution_attempt_id),
    )

    fmu_path = _download_fmu(input_envelope, work_dir)
    if not fmu_path.exists():
        raise ValueError(f"FMU file not found at {fmu_path}")

    md = _read_model_description(fmu_path)

    sim_cfg = input_envelope.inputs.simulation
    requested_outputs = input_envelope.inputs.output_variables or []
    if not requested_outputs:
        # Fallback: discover output variables from the parsed model
        # description dict.  Use _extract_output_variables (which accepts
        # a dict) rather than the backward-compat shim
        # _discover_output_variables (which expects a Path).
        requested_outputs = _extract_output_variables(md)

    start_values = dict(input_envelope.inputs.input_values or {})
    log_messages: list[str] = []

    try:
        # SECURITY: simulate_fmu executes the attacker-supplied FMU's native
        # shared library. Run it in a killable child process with a hard
        # wall-clock timeout so a malicious/pathological model cannot hang the
        # job indefinitely. See _run_simulation_with_timeout.
        # Note: fmpy 3.x requires start_values to be a dict (not None) because it
        # calls start_values.copy(). Pass empty dict if no start values provided.
        # output=None is fine (tells fmpy to use default outputs from model).
        result, log_messages = _run_simulation_with_timeout(
            fmu_path=fmu_path,
            start_time=sim_cfg.start_time,
            stop_time=sim_cfg.stop_time,
            step_size=sim_cfg.step_size,
            requested_outputs=requested_outputs,
            start_values=start_values,  # Always pass dict, never None
        )

        sim_time_reached = _resolve_sim_time(result, sim_cfg.stop_time)
        output_values = _collect_output_values(
            result=result,
            outputs=requested_outputs,
            fallback_inputs=start_values,
        )
        execution_seconds = time.time() - start_time

        outputs = FMUOutputs(
            output_values=output_values,
            fmu_guid=md.get("guid"),
            fmi_version=md.get("fmi_version"),
            model_name=md.get("model_name"),
            execution_seconds=execution_seconds,
            simulation_time_reached=sim_time_reached,
            fmu_log="\n".join(log_messages) if log_messages else None,
        )
        return outputs, work_dir
    except FMUSimulationTimeoutError:
        # The simulation was killed for exceeding its wall-clock budget. Surface
        # the timeout as-is (distinct type + clear message) rather than burying
        # it under the generic "FMU simulation failed" wrapper below.
        logger.warning("FMU simulation timed out and was terminated.")
        raise
    except Exception as exc:
        logger.exception("FMU simulation failed: %s", exc)
        execution_seconds = time.time() - start_time
        outputs = FMUOutputs(
            output_values=start_values,
            fmu_guid=md.get("guid"),
            fmi_version=md.get("fmi_version"),
            model_name=md.get("model_name"),
            execution_seconds=execution_seconds,
            simulation_time_reached=sim_cfg.start_time,
            fmu_log="\n".join(log_messages) if log_messages else str(exc),
        )
        raise RuntimeError(f"FMU simulation failed: {exc}") from exc


# The declared Validibot file-port key for this validator, and the
# The declared key is the sole identity used at the envelope boundary.
FMU_MODEL_PORT_KEY = "fmu_model"


def _fmu_model_item(input_envelope):
    """Return the one declared FMU model through the shared matcher."""
    return select_input_file(
        input_envelope.input_files,
        port_key=FMU_MODEL_PORT_KEY,
    )


def _download_fmu(input_envelope, work_dir: Path) -> Path:
    """Download the FMU referenced in the input envelope to the working directory."""
    fmu_item = _fmu_model_item(input_envelope)

    target = work_dir / "model.fmu"
    download_verified_file(fmu_item, target)
    return target


def _discover_output_variables(fmu_path: Path) -> list[str]:
    """Backward-compat shim - kept for callers using the old signature."""
    md = _read_model_description(fmu_path)
    return _extract_output_variables(md)


def _resolve_sim_time(result, default_stop: float) -> float:
    """Extract the last simulation time if present."""
    try:
        if hasattr(result, "dtype") and "time" in result.dtype.names:
            return float(result["time"][-1])
    except Exception:
        logger.debug("Could not resolve simulation time from result.", exc_info=True)
    return default_stop


def _collect_output_values(
    *,
    result,
    outputs: list[str],
    fallback_inputs: dict[str, object],
) -> dict[str, object]:
    """
    Collect the final values for each requested output, falling back to inputs when absent.
    """
    values: dict[str, object] = {}
    for name in outputs:
        if hasattr(result, "dtype") and name in result.dtype.names:
            try:
                values[name] = result[name][-1].item()
                continue
            except Exception:
                logger.debug("Failed to extract output %s from result", name)
        if name in fallback_inputs:
            values[name] = fallback_inputs[name]
    return values


def _read_model_description(fmu_path: Path) -> dict:
    """Parse modelDescription.xml and return metadata plus variables."""
    try:
        md = read_model_description(str(fmu_path))
        return {
            "guid": getattr(md, "guid", None),
            "model_name": getattr(md, "modelName", None),
            "fmi_version": getattr(md, "fmiVersion", None),
            "variables": getattr(md, "modelVariables", []),
        }
    except Exception:
        logger.exception("Failed to read modelDescription.xml")
        return {"guid": None, "model_name": None, "fmi_version": None, "variables": []}


def _extract_output_variables(md: dict) -> list[str]:
    """Extract output variable names from parsed model description."""
    try:
        variables = md.get("variables", [])
        return [
            getattr(var, "name", "")
            for var in variables
            if getattr(var, "causality", "").lower() == "output"
        ]
    except Exception:
        logger.exception("Failed to extract output variable names")
        return []
