"""Tests for process controls that shield secrets from native parser children.

The PDF decoder runs under the same UID as the Python process that holds an
attempt-scoped storage capability. A sanitized child environment is useful but
insufficient on Linux unless procfs/ptrace access to the parent is also denied.
These tests exercise the real libc control in a disposable subprocess so the
pytest process itself remains debuggable.
"""

from __future__ import annotations

import subprocess
import sys


def test_linux_process_becomes_non_dumpable_in_a_disposable_child() -> None:
    """The hardening helper must make Linux report dumpable state zero."""
    script = """
from validator_backends.core.process_hardening import current_process_dumpable
from validator_backends.core.process_hardening import protect_current_process_secrets
protect_current_process_secrets()
print(current_process_dumpable())
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )

    expected = "0" if sys.platform.startswith("linux") else "None"
    assert completed.stdout.strip() == expected


def test_pdf_image_requests_entrypoint_secret_protection() -> None:
    """A future Dockerfile edit must not expose the service or Job ancestor."""
    from pathlib import Path

    dockerfile = Path(__file__).parents[2] / "pdf" / "Dockerfile"

    assert '"--protect-process-secrets"' in dockerfile.read_text(encoding="utf-8")
