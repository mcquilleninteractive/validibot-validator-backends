"""Keep attempt authentication wired through every validator entrypoint.

Each backend has separate success and failure callback paths. Runtime tests for
one validator cannot prove that another backend did not forget to return the
attempt credentials, so this suite inspects the call structure shared by every
entrypoint. The invariant matters because transport authentication alone
identifies a runtime; the callback ID and nonce bind the notification to the
specific input envelope that runtime received.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ENTRYPOINTS = tuple(
    REPO_ROOT / "validator_backends" / slug / "main.py"
    for slug in (
        "energyplus",
        "fmu",
        "shacl",
        "schematron",
        "portfolio_manager",
        "pdf",
    )
)
EXPECTED_ATTEMPT_KEYWORDS = {
    "callback_id": "input_envelope.context.callback_id",
    "callback_nonce": "input_envelope.context.callback_nonce",
}


def _attribute_path(node: ast.expr) -> str | None:
    """Return the dotted name represented by a simple AST expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _attribute_path(node.value)
        if parent:
            return f"{parent}.{node.attr}"
    return None


@pytest.mark.parametrize("entrypoint", BACKEND_ENTRYPOINTS, ids=lambda path: path.parent.name)
def test_every_callback_path_echoes_attempt_credentials(entrypoint: Path):
    """Every success and failure POST must use credentials from its input.

    Adding a new backend branch without these keywords would otherwise create
    a callback that Django must reject—or, worse, tempt a compatibility fallback
    that weakens attempt binding. Checking the source structure makes drift fail
    in the repository-wide suite before an image is published.
    """
    tree = ast.parse(entrypoint.read_text(encoding="utf-8"), filename=str(entrypoint))
    callback_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "post_callback"
    ]

    assert callback_calls, f"{entrypoint.relative_to(REPO_ROOT)} sends no callbacks"
    for call in callback_calls:
        keywords = {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg}
        for keyword, expected_path in EXPECTED_ATTEMPT_KEYWORDS.items():
            assert keyword in keywords, (
                f"{entrypoint.relative_to(REPO_ROOT)}:{call.lineno} omits {keyword}"
            )
            assert _attribute_path(keywords[keyword]) == expected_path, (
                f"{entrypoint.relative_to(REPO_ROOT)}:{call.lineno} must source "
                f"{keyword} from {expected_path}"
            )
