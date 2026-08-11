"""Provide an isolated staging workspace for every PDF engine invocation.

Production owns one attempt workspace and keeps it alive until all staged
artifacts have been uploaded. Engine tests exercise the same contract through
this fixture: each call gets a distinct child directory, which also prevents a
second deterministic run from accidentally comparing a file with itself.
"""

from __future__ import annotations

import itertools

import pytest


@pytest.fixture(autouse=True)
def _isolated_engine_workspaces(tmp_path, monkeypatch, request) -> None:
    """Supply unique caller-owned workspaces to direct ``inspect_pdf`` calls."""
    engine_call = getattr(request.module, "inspect_pdf", None)
    if engine_call is None:
        return

    sequence = itertools.count()

    def inspect_in_workspace(*args, **kwargs):
        kwargs.setdefault("workspace", tmp_path / f"inspection-{next(sequence)}")
        return engine_call(*args, **kwargs)

    monkeypatch.setattr(request.module, "inspect_pdf", inspect_in_workspace)
