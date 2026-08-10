"""Keep local test dependencies aligned with production validator images.

The root project installs one combined development environment, while each
released container installs its own ``requirements.txt``. Dependabot updates
only ``pyproject.toml`` by default, which can make tests exercise a newer cloud
client or validation engine than the image that is ultimately published. This
suite compares the exact shared pins and each backend's optional runtime stack
so a dependency update cannot create that false confidence.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
COMMON_IMAGE_DEPENDENCIES = (
    "pydantic",
    "httpx",
    "google-cloud-storage",
    "google-auth",
    "validibot-shared",
)
BACKEND_OPTIONAL_GROUPS = {
    "energyplus": (),
    "fmu": ("fmpy",),
    "shacl": ("rdflib", "pyshacl", "owlrl", "defusedxml", "lxml"),
    "schematron": ("saxonche", "defusedxml"),
    "portfolio_manager": ("defusedxml", "openpyxl", "xlrd"),
    "pdf": ("pikepdf",),
}


def _exact_pins(requirements: list[str]) -> dict[str, str]:
    """Return package-to-version mappings for exact ``name==version`` pins."""
    pins = {}
    for requirement in requirements:
        name, separator, version = requirement.partition("==")
        if separator:
            pins[name] = version
    return pins


def _requirements_file_pins(path: Path) -> dict[str, str]:
    """Read exact package pins from one container requirements file."""
    requirements = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return _exact_pins(requirements)


@pytest.mark.parametrize("backend", BACKEND_OPTIONAL_GROUPS)
def test_container_pins_match_the_root_runtime_contract(backend: str):
    """Every published image must install the versions exercised locally.

    Common transport/storage dependencies are checked for all images. Each
    validator's optional root group is also checked where it represents code
    shipped in that image, most importantly the major SaxonC runtime used by
    Schematron.
    """
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    root_pins = _exact_pins(project["project"]["dependencies"])
    optional_pins = _exact_pins(
        project["project"]["optional-dependencies"].get(backend, []),
    )
    image_pins = _requirements_file_pins(
        REPO_ROOT / "validator_backends" / backend / "requirements.txt",
    )

    expected = {name: root_pins[name] for name in COMMON_IMAGE_DEPENDENCIES}
    expected.update(
        {name: optional_pins[name] for name in BACKEND_OPTIONAL_GROUPS[backend]},
    )

    for name, version in expected.items():
        assert image_pins.get(name) == version, (
            f"{backend} image must pin {name}=={version}, matching pyproject.toml"
        )
