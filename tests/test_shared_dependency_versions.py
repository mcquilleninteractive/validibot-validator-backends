"""Keep validator container contracts aligned with ``validibot-shared``.

Each validator image installs from its own ``requirements.txt`` rather than
the repository's root dependency set. A root-version bump can therefore leave
one or more production images on an older envelope contract. The root lockfile
must also resolve the published wheel so local tests and CI exercise the same
contract artifact that the images install. This suite makes either form of
drift visible before an image is built or released.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_REQUIREMENTS = (
    REPO_ROOT / "validator_backends" / "energyplus" / "requirements.txt",
    REPO_ROOT / "validator_backends" / "fmu" / "requirements.txt",
    REPO_ROOT / "validator_backends" / "shacl" / "requirements.txt",
    REPO_ROOT / "validator_backends" / "schematron" / "requirements.txt",
    REPO_ROOT / "validator_backends" / "portfolio_manager" / "requirements.txt",
    REPO_ROOT / "validator_backends" / "pdf" / "requirements.txt",
)
SHARED_PIN_PATTERN = re.compile(r"^validibot-shared==(?P<version>[^\s#]+)$", re.MULTILINE)
PYPI_SIMPLE_INDEX = "https://pypi.org/simple"


def _root_shared_version() -> str:
    """Return the exact shared-library version declared by the project."""
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependency = next(
        item
        for item in project["project"]["dependencies"]
        if item.startswith("validibot-shared==")
    )
    return dependency.partition("==")[2]


@pytest.mark.parametrize("requirements_path", VALIDATOR_REQUIREMENTS)
def test_container_shared_pin_matches_project(requirements_path: Path):
    """Every production image must use the repository's shared contract.

    Docker builds consume these files directly, so checking only
    ``pyproject.toml`` would allow a stale image dependency to ship unnoticed.
    """
    contents = requirements_path.read_text(encoding="utf-8")
    match = SHARED_PIN_PATTERN.search(contents)

    assert match is not None, (
        f"{requirements_path.relative_to(REPO_ROOT)} must pin validibot-shared"
    )
    assert match.group("version") == _root_shared_version()


def test_root_shared_dependency_resolves_from_pypi() -> None:
    """Local and CI tests must consume the same published contract as images."""
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    matches = [package for package in lock["package"] if package["name"] == "validibot-shared"]

    assert "validibot-shared" not in project.get("tool", {}).get("uv", {}).get(
        "sources",
        {},
    )
    assert len(matches) == 1
    assert matches[0]["version"] == _root_shared_version()
    assert matches[0]["source"] == {"registry": PYPI_SIMPLE_INDEX}
    assert matches[0].get("wheels")
