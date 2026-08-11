"""File-port resolution tests for the FMU runner's envelope dispatch.

ADR-2026-07-06 gives every envelope file item one stable selection identity:
the required `port_key` declared by the validator contract. Backend-facing
roles may describe files, but they cannot select or reclassify them.

This suite covers `_fmu_model_item`, which answers the single question "which
envelope item is the FMU to simulate?". It is tested directly because the
answer must not depend on list position or on which candidate happens to come
first — an FMU is executable code, and simulating the wrong one would produce
signed evidence attributing results to a model the author did not submit.

`_fmu_model_item` is separated from `_download_fmu` so these tests need no
network, no storage stub, and no real FMU archive.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from validator_backends.fmu.runner import _fmu_model_item
from validibot_shared.validations.envelopes import InputFileItem, SupportedMimeType


def _fmu_item(**overrides) -> InputFileItem:
    """Build one valid FMU input item, overriding only the identity fields.

    Everything except `port_key` and `role` is held constant so a failure
    isolates port matching rather than envelope validation.
    """
    fields = {
        "name": "model.fmu",
        "mime_type": SupportedMimeType.FMU,
        "role": "fmu",
        "port_key": "fmu_model",
        "uri": "gs://bucket/runs/run-1/model.fmu",
        "size_bytes": 8192,
        "sha256": "c" * 64,
        "storage_version": "1700000000000000",
    }
    fields.update(overrides)
    return InputFileItem(**fields)


def _envelope(*input_files: InputFileItem) -> SimpleNamespace:
    """Build the minimal envelope surface `_fmu_model_item` reads.

    Real shared models keep these tests aligned with the process-boundary
    contract rather than a hand-built approximation.
    """
    return SimpleNamespace(input_files=list(input_files))


# ── Identification by the declared contract key ───────────────────────────


def test_resolves_the_model_when_both_identifiers_are_present():
    """This is the envelope Django emits today for a bound FMU model.

    A failure here means the live FMU dispatch path is broken rather than an
    edge case being mishandled.
    """
    envelope = _envelope(_fmu_item())

    assert _fmu_model_item(envelope).name == "model.fmu"


def test_resolves_the_model_from_port_key_when_role_is_absent():
    """`role` is descriptive, so the declared port key suffices on its own."""
    envelope = _envelope(_fmu_item(role=None))

    assert _fmu_model_item(envelope).name == "model.fmu"


# ── Cardinality enforcement ───────────────────────────────────────────────
# The `fmu_model` port is declared 1..1. Django validates that before launch;
# the backend re-checks because the envelope is untrusted input.


def test_rejects_two_candidate_models():
    """Two candidates must fail loudly instead of silently taking the first."""
    envelope = _envelope(_fmu_item(name="first.fmu"), _fmu_item(name="second.fmu"))

    with pytest.raises(ValueError, match="ambiguous"):
        _fmu_model_item(envelope)


def test_rejects_an_envelope_with_no_matching_input():
    """An item matching neither identifier is not the FMU model.

    Falling back to `input_files[0]` would hand an arbitrary file to the FMI
    runtime, which executes the model description it finds inside.
    """
    envelope = _envelope(_fmu_item(role="primary-model", port_key="some_other_port"))

    with pytest.raises(ValueError, match="Required file port"):
        _fmu_model_item(envelope)


def test_rejects_an_empty_envelope():
    """A required 1..1 port with nothing bound is a contract violation."""
    envelope = _envelope()

    with pytest.raises(ValueError, match="Required file port"):
        _fmu_model_item(envelope)
