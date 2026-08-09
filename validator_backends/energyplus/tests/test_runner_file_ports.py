"""File-port resolution tests for the EnergyPlus runner's envelope dispatch.

ADR-2026-07-06 gives every envelope file item two independent names: the
Validibot-facing `port_key` (the declared port's `contract_key`, unique within
a step contract) and the older backend-facing `role` on input files or `type`
on resource files. `port_key` is optional in `validibot-shared`, so the ADR's
canonical rule is to match on `port_key` and fall back to `role`/`type`.

This suite covers `_download_input_files`, which is the only place the
EnergyPlus backend decides *which* downloaded file is the model and which is
the weather data. It is worth testing directly because a mis-identification
here is silent: EnergyPlus would run against the wrong file and produce
confident, wrong evidence rather than an error.

Two behaviours specific to this backend are pinned alongside port matching,
because they are easy to break while refactoring dispatch:

- every file in the envelope is downloaded, even ones the backend does not
  identify, since a model may reference side files it does not interpret;
- a weather file arriving as a managed workflow resource in `resource_files`
  supersedes one arriving in `input_files`, regardless of envelope order.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from validator_backends.energyplus import runner
from validibot_shared.energyplus.envelopes import EnergyPlusInputs
from validibot_shared.validations.envelopes import (
    InputFileItem,
    ResourceFileItem,
    SupportedMimeType,
)


if TYPE_CHECKING:
    from pathlib import Path


def _input_item(**overrides) -> InputFileItem:
    """Build one valid IDF input item, overriding only the identity fields.

    Everything except `port_key` and `role` is held constant so a failing test
    points at port matching rather than at envelope validation.
    """
    fields = {
        "name": "model.idf",
        "mime_type": SupportedMimeType.ENERGYPLUS_IDF,
        "role": "primary-model",
        "port_key": "primary_model",
        "uri": "gs://bucket/runs/run-1/model.idf",
        "size_bytes": 2048,
        "sha256": "a" * 64,
        "storage_version": "1700000000000000",
    }
    fields.update(overrides)
    return InputFileItem(**fields)


def _weather_resource(**overrides) -> ResourceFileItem:
    """Build one valid EPW weather resource item."""
    fields = {
        "id": "resource-1",
        "name": "melbourne.epw",
        "type": "energyplus_weather",
        "port_key": "weather_file",
        "uri": "gs://bucket/resource_files/melbourne.epw",
        "size_bytes": 4096,
        "sha256": "b" * 64,
        "storage_version": "1700000000000001",
    }
    fields.update(overrides)
    return ResourceFileItem(**fields)


def _envelope(
    *,
    input_files: list[InputFileItem] | None = None,
    resource_files: list[ResourceFileItem] | None = None,
    run_simulation: bool = False,
) -> SimpleNamespace:
    """Build the minimal envelope surface `_download_input_files` reads.

    The function touches only `input_files`, `resource_files`, and
    `inputs.run_simulation`. The file items themselves are real shared models,
    which is the part that matters here: it proves an omitted `port_key` is
    genuinely schema-valid rather than something these tests fake.
    """
    return SimpleNamespace(
        input_files=input_files or [],
        resource_files=resource_files or [],
        inputs=EnergyPlusInputs(run_simulation=run_simulation),
    )


@pytest.fixture
def downloads(monkeypatch, tmp_path: Path) -> list[Path]:
    """Record every download and create the destination file.

    Returns the list of destinations in call order, so a test can assert both
    what was identified (the return value) and what was fetched (this list).
    """
    recorded: list[Path] = []

    def fake_download(item, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"stub")
        recorded.append(destination)

    monkeypatch.setattr(runner, "download_verified_file", fake_download)
    return recorded


# ── Identification by either declared identifier ──────────────────────────
# Django writes both `port_key` and `role`, but only the latter is guaranteed
# by the shared schema, so each has to work on its own. The port-key-only case
# is the one the old role-only code could not handle at all.


def test_identifies_the_model_when_both_identifiers_are_present(downloads, tmp_path):
    """This is the envelope Django actually emits today.

    If this fails, the live EnergyPlus dispatch path is broken, not just an
    edge case.
    """
    envelope = _envelope(input_files=[_input_item()])

    model_file, weather_file = runner._download_input_files(envelope, tmp_path)

    assert model_file == tmp_path / "model.idf"
    assert weather_file is None


def test_identifies_the_model_from_port_key_when_role_is_absent(downloads, tmp_path):
    """`role` is optional, so the port key must be sufficient on its own.

    This is the case the previous role-only implementation failed: it would
    have reported no primary model at all for an otherwise valid envelope.
    """
    envelope = _envelope(input_files=[_input_item(role=None)])

    model_file, _ = runner._download_input_files(envelope, tmp_path)

    assert model_file == tmp_path / "model.idf"


def test_identifies_the_model_from_role_when_port_key_is_absent(downloads, tmp_path):
    """`port_key` is optional, so `role` must remain a working fallback.

    Envelopes built before file ports existed carry a role and no port key;
    requiring the port key would reject input the shared contract permits.
    """
    envelope = _envelope(input_files=[_input_item(port_key=None)])

    model_file, _ = runner._download_input_files(envelope, tmp_path)

    assert model_file == tmp_path / "model.idf"


def test_identifies_the_weather_resource_from_port_key_when_type_differs(
    downloads,
    tmp_path,
):
    """Resource files fall back to `type`, but the port key takes precedence.

    A weather resource stored under a different `type` string is still the
    weather file if it is bound to the `weather_file` port.
    """
    envelope = _envelope(
        input_files=[_input_item()],
        resource_files=[_weather_resource(type="some_other_type")],
        run_simulation=True,
    )

    _, weather_file = runner._download_input_files(envelope, tmp_path)

    assert weather_file == tmp_path / "melbourne.epw"


def test_identifies_the_weather_resource_from_type_when_port_key_is_absent(
    downloads,
    tmp_path,
):
    """The generic workflow-resource path in Django sets no port key.

    `_build_step_resource_item` emits resource items without one, so `type`
    has to keep working or every unmigrated EnergyPlus step loses its weather.
    """
    envelope = _envelope(
        input_files=[_input_item()],
        resource_files=[_weather_resource(port_key=None)],
        run_simulation=True,
    )

    _, weather_file = runner._download_input_files(envelope, tmp_path)

    assert weather_file == tmp_path / "melbourne.epw"


# ── Weather arriving through input_files ──────────────────────────────────
# The `weather_file` port declares `envelope_channel = resource_files`, but
# that only holds when the binding resolves to a managed workflow resource.
# Weather bound from a submitted file or an upstream artifact is rendered into
# `input_files` instead (see `_resolve_energyplus_file_port_items` in the
# Django envelope builder). Both channels are current, so both must work.


def test_accepts_weather_bound_through_input_files(downloads, tmp_path):
    """A submitted or upstream-artifact weather file still runs the simulation.

    This is what Django emits when the `weather_file` port is bound to
    anything other than a managed workflow resource. Treating it as
    unsupported would break every workflow that submits its own EPW.
    """
    envelope = _envelope(
        input_files=[
            _input_item(),
            _input_item(
                name="submitted.epw",
                mime_type=SupportedMimeType.ENERGYPLUS_EPW,
                role="weather",
                port_key="weather_file",
            ),
        ],
        run_simulation=True,
    )

    model_file, weather_file = runner._download_input_files(envelope, tmp_path)

    assert model_file == tmp_path / "model.idf"
    assert weather_file == tmp_path / "submitted.epw"


def test_accepts_weather_in_input_files_identified_by_role_alone(downloads, tmp_path):
    """An envelope carrying no port key still resolves weather by role."""
    envelope = _envelope(
        input_files=[
            _input_item(),
            _input_item(
                name="submitted.epw",
                mime_type=SupportedMimeType.ENERGYPLUS_EPW,
                role="weather",
                port_key=None,
            ),
        ],
        run_simulation=True,
    )

    _, weather_file = runner._download_input_files(envelope, tmp_path)

    assert weather_file == tmp_path / "submitted.epw"


def test_weather_resource_supersedes_weather_in_input_files(downloads, tmp_path):
    """When both channels carry weather, the managed resource wins.

    Input files are processed before resource files, so this ordering is what
    makes the outcome predictable rather than dependent on envelope order.
    """
    envelope = _envelope(
        input_files=[
            _input_item(),
            _input_item(
                name="submitted.epw",
                mime_type=SupportedMimeType.ENERGYPLUS_EPW,
                role="weather",
                port_key="weather_file",
            ),
        ],
        resource_files=[_weather_resource()],
        run_simulation=True,
    )

    _, weather_file = runner._download_input_files(envelope, tmp_path)

    assert weather_file == tmp_path / "melbourne.epw"


# ── Downloading versus identifying ────────────────────────────────────────
# Identification narrowed, but the backend must still fetch everything: an IDF
# can reference side files this backend never inspects, and refusing to
# download them would break models that worked before.


def test_downloads_every_file_including_unidentified_ones(downloads, tmp_path):
    """Narrowing identification must not narrow what gets fetched."""
    envelope = _envelope(
        input_files=[
            _input_item(),
            _input_item(name="schedule.csv", role=None, port_key="side_file"),
        ],
        resource_files=[_weather_resource()],
        run_simulation=True,
    )

    runner._download_input_files(envelope, tmp_path)

    assert downloads == [
        tmp_path / "model.idf",
        tmp_path / "schedule.csv",
        tmp_path / "melbourne.epw",
    ]


# ── Cardinality enforcement ───────────────────────────────────────────────
# `primary_model` is declared 1..1 and `weather_file` 0..1. Django validates
# this before launch; the backend re-checks because it treats its envelope as
# untrusted input. Two candidates used to resolve silently to whichever came
# last, which is the precision gap this change closes.


def test_rejects_two_candidate_primary_models(downloads, tmp_path):
    """An ambiguous model must fail loudly rather than pick the last one.

    This is the concrete risk of matching on `role` alone: two ports sharing a
    role produced a silent, arbitrary winner and evidence that named the wrong
    file.
    """
    envelope = _envelope(
        input_files=[_input_item(name="first.idf"), _input_item(name="second.idf")],
    )

    with pytest.raises(ValueError, match="exactly one primary_model"):
        runner._download_input_files(envelope, tmp_path)


def test_rejects_two_candidate_weather_resources(downloads, tmp_path):
    """Two weather resources make the simulation's climate ambiguous."""
    envelope = _envelope(
        input_files=[_input_item()],
        resource_files=[
            _weather_resource(id="resource-1", name="melbourne.epw"),
            _weather_resource(id="resource-2", name="sydney.epw"),
        ],
        run_simulation=True,
    )

    with pytest.raises(ValueError, match="at most one weather_file"):
        runner._download_input_files(envelope, tmp_path)


def test_rejects_an_envelope_with_no_primary_model(downloads, tmp_path):
    """An input file matching neither identifier is not the model.

    Falling back to `input_files[0]` here would let an unrelated side file be
    simulated and reported as the submitted model.
    """
    envelope = _envelope(
        input_files=[_input_item(role="something-else", port_key="some_other_port")],
    )

    with pytest.raises(ValueError, match="No primary-model file found"):
        runner._download_input_files(envelope, tmp_path)


def test_rejects_a_simulation_with_no_weather_anywhere(downloads, tmp_path):
    """A full simulation without weather data cannot produce valid results."""
    envelope = _envelope(input_files=[_input_item()], run_simulation=True)

    with pytest.raises(ValueError, match="No weather file found"):
        runner._download_input_files(envelope, tmp_path)


def test_allows_a_missing_weather_file_when_not_simulating(downloads, tmp_path):
    """Conversion-only preflight legitimately has no weather file.

    The weather port is 0..1 precisely so a syntax/conversion check can run
    without asking the author to attach climate data.
    """
    envelope = _envelope(input_files=[_input_item()], run_simulation=False)

    model_file, weather_file = runner._download_input_files(envelope, tmp_path)

    assert model_file == tmp_path / "model.idf"
    assert weather_file is None
