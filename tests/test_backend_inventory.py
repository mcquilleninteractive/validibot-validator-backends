"""Tests for the authoritative validator backend inventory.

Schema 2 makes ``backends.toml`` the only list of release-enabled backends,
their build inputs, and the version offered to setup/update. These tests prove
that local builds and the single- and multi-backend release workflows consume
those values instead of keeping handwritten release matrices or Dockerfile
defaults.
"""

from __future__ import annotations

import re
import tomllib
from copy import deepcopy
from pathlib import Path

import pytest
from scripts.backend_inventory import (
    InventoryError,
    parse_release_tag,
    provider_resource_name,
    release_output,
    release_tags,
    validate_inventory,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "backends.toml"
JUSTFILE_PATH = REPO_ROOT / "justfile"
CI_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "release.yml"


def _manifest() -> dict:
    """Load the committed backend inventory."""
    return tomllib.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _backends() -> list[dict]:
    """Return manifest backend records in declared order."""
    return list(_manifest()["backend"])


def _justfile_slugs() -> list[str]:
    """Extract the developer backend list from git's lowercase justfile."""
    justfile = JUSTFILE_PATH.read_text(encoding="utf-8")
    match = re.search(r'^validators := "([^"]+)"$', justfile, flags=re.MULTILINE)
    assert match, "justfile must declare validators"
    return match.group(1).split()


def test_manifest_schema_and_paths_are_valid():
    """Every manifest entry must point at the files release tooling needs."""
    manifest = _manifest()
    validated = validate_inventory(manifest)

    assert manifest["schema_version"] == 2
    slugs = [backend.slug for backend in validated]
    assert len(slugs) == len(set(slugs))

    for backend in _backends():
        slug = backend["slug"]
        assert (REPO_ROOT / "validator_backends" / slug).is_dir()
        for key in (
            "dockerfile",
            "requirements",
            "requirements_lock",
            "application_sbom",
            "test_path",
        ):
            assert (REPO_ROOT / backend[key]).exists(), f"{slug}.{key} is missing"
        assert "version_source" not in backend
        assert backend["release_version"]
        assert backend["provider_resource_slug"]
        image_slug = slug.replace("_", "-")
        assert backend["image_name"] == f"validibot-validator-backend-{image_slug}"
        assert backend["platforms"] == ["linux/amd64"]
        assert backend["execution_shapes"] == ["job", "service"]
        assert backend["service_runtime_contract"] == "validibot-execution-v1"
        assert backend["service_concurrency"] == 1
        assert backend["service_max_domain_seconds"] == 1500


def test_release_and_developer_builds_are_inventory_driven():
    """Single, batch, and local build paths must use the same inventory."""
    release_slugs = [backend["slug"] for backend in _backends() if backend.get("release") is True]
    release_yml = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
    justfile = JUSTFILE_PATH.read_text(encoding="utf-8")

    assert _justfile_slugs() == release_slugs
    assert "matrix:" not in release_yml
    assert "scripts/backend_inventory.py release" in release_yml
    assert "needs.select-release.outputs.backend" in release_yml
    assert "VALIDATOR_BACKEND_VERSION=${{" in release_yml
    assert 'scripts/backend_inventory.py field "{{validator}}" release_version' in justfile
    assert '--build-arg VALIDATOR_BACKEND_VERSION="$BACKEND_VERSION"' in justfile
    assert 'verify-tag "$TAG"' in justfile
    assert "git push origin" in justfile
    assert justfile.index('verify-tag "$TAG"') < justfile.index('git push origin "$TAG"')
    assert "release-all:" in justfile
    assert "scripts/backend_inventory.py release-tags" in justfile
    assert 'git push --atomic origin "${TAGS[@]}"' not in justfile
    assert 'gh release view "$TAG"' in justfile
    assert 'LOCAL_TAG_OBJECT="$(git rev-parse "refs/tags/$TAG")"' in justfile
    assert "REMOTE_TAG_OBJECT=\"${REMOTE_TAG%%$'\\t'*}\"" in justfile
    assert 'git push origin ":refs/tags/$TAG"' not in justfile
    assert 'git push origin "refs/tags/$TAG:refs/tags/$TAG"' not in justfile
    assert "recover-releases:" not in justfile
    assert "gh workflow run release.yml" in justfile


def test_release_all_handles_batches_containing_only_retry_tags():
    """macOS Bash 3.2 must not treat an intentionally empty new-tag array as unset."""
    justfile = JUSTFILE_PATH.read_text(encoding="utf-8")

    assert 'for TAG in "${NEW_TAGS[@]+"${NEW_TAGS[@]}"}"; do' in justfile
    assert 'for TAG in "${NEW_TAGS[@]}"; do' not in justfile
    assert 'for RETRY_TAG in "${RETRY_TAGS[@]+"${RETRY_TAGS[@]}"}"; do' in justfile
    assert '[[ " ${RETRY_TAGS[*]} "' not in justfile


def test_release_workflow_uses_protected_main_as_its_trust_anchor():
    """A signed tag must not be allowed to smuggle in its own trusted key."""
    release_yml = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in release_yml
    assert "Existing signed unpublished backend release tag" in release_yml
    assert "inputs.tag || github.ref_name" in release_yml
    assert "inputs.tag || github.ref" in release_yml
    assert 'git check-ref-format "refs/tags/$RELEASE_TAG"' in release_yml
    assert 'git verify-tag -- "$RELEASE_TAG"' in release_yml
    assert release_yml.count("RELEASE_TAG: ${{ inputs.tag || github.ref_name }}") == 2
    assert release_yml.count("ref: ${{ needs.select-release.outputs.source_tag }}") == 2
    assert "origin/main:.allowed_signers" in release_yml
    assert "git merge-base --is-ancestor" in release_yml
    assert "TAG_COMMIT" in release_yml
    assert "CHECKOUT_COMMIT" in release_yml
    assert "source_commit: ${{ steps.identity.outputs.source_commit }}" in release_yml
    assert "VALIDATOR_BACKEND_REVISION=${{ needs.select-release.outputs.source_commit }}" in (
        release_yml
    )


def test_release_workflow_is_immutable_and_attests_both_sboms():
    """Published image tags, releases, and SBOM claims must be tamper-evident."""
    release_yml = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "name: ghcr" in release_yml
    assert "Refuse to overwrite a published release" in release_yml
    assert "docker buildx imagetools inspect" in release_yml
    assert "--clobber" not in release_yml
    assert release_yml.count("uses: actions/attest@") == 2
    assert release_yml.count("sbom-path:") == 2
    assert release_yml.count("push-to-registry: true") == 3


def test_release_workflow_blocks_publish_until_repository_release_gate_passes():
    """No image may publish with invalid inventory or stale generated evidence.

    The release workflow must check every backend, not only the backend selected
    by the tag. Keeping the gate as a dependency of the publish job prevents a
    valid tag from bypassing stale lockfiles or application SBOMs elsewhere in
    the release inventory.
    """
    release_yml = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
    justfile = JUSTFILE_PATH.read_text(encoding="utf-8")

    assert "name: Gate release on inventory, locks, and application SBOMs" in release_yml
    assert "scripts/backend_inventory.py validate >/dev/null" in release_yml
    assert "scripts/backend_artifacts.py check\n" in release_yml
    assert "scripts/backend_artifacts.py check --backend" not in release_yml
    assert "tests/test_backend_inventory.py" in release_yml
    assert "tests/test_release_legal_artifacts.py" in release_yml
    assert "needs: [select-release, test-selected-backend]" in release_yml

    assert "inventory-check:" in justfile
    assert "check: lint inventory-check artifacts-check licenses test" in justfile


def test_ci_exposes_one_aggregate_branch_protection_check():
    """Branch protection must depend on every security and test job together."""
    ci_yml = CI_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert re.search(r"(?m)^  ci:\n    name: ci$", ci_yml)
    assert "needs: [security, test]" in ci_yml
    assert 'test "$SECURITY_RESULT" = "success"' in ci_yml
    assert 'test "$TEST_RESULT" = "success"' in ci_yml
    assert "ruff format --check ." in ci_yml
    assert "--require-hashes" in ci_yml


def test_release_json_contains_only_the_public_adr_fields():
    """Application SBOMs may be attached separately but not alter release JSON."""
    release_yml = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
    record_expression = release_yml.split(
        "--arg schema_version",
        maxsplit=1,
    )[1].split(
        '}\' > "$RELEASE_RECORD"',
        maxsplit=1,
    )[0]

    for field in (
        "schema_version:",
        "backend:",
        "version:",
        "source_tag:",
        "source_commit:",
        "image:",
        "image_digest:",
        "shared_contract:",
        "sbom:",
        "build_verification:",
    ):
        assert field in record_expression
    assert "application_sbom:" not in record_expression


def test_shared_contract_matches_backend_requirements():
    """Each backend's requirement pin must match its manifest contract version."""
    for backend in _backends():
        requirements = (REPO_ROOT / backend["requirements"]).read_text(
            encoding="utf-8",
        )
        expected_pin = f"validibot-shared=={backend['shared_contract']}"
        assert expected_pin in requirements


def test_backend_specific_tags_select_only_the_named_inventory_entry():
    """A tag cannot release every backend or disagree with the offered version."""
    for raw_backend in _backends():
        backend = parse_release_tag(f"{raw_backend['slug']}-v{raw_backend['release_version']}")
        output = release_output(
            backend,
            tag=f"{backend.slug}-v{backend.release_version}",
        )

        assert backend.slug == raw_backend["slug"]
        assert output["test_path"] == raw_backend["test_path"]
        assert output["requirements_lock"] == raw_backend["requirements_lock"]
        assert output["application_sbom"] == raw_backend["application_sbom"]
        assert output["release_record"].endswith(f"-v{raw_backend['release_version']}.json")

    with pytest.raises(InventoryError, match=r"backends\.toml offers"):
        parse_release_tag("energyplus-v99.0.0")
    with pytest.raises(InventoryError, match="release tag must"):
        parse_release_tag("v0.16.0")


def test_batch_release_tags_follow_the_release_enabled_inventory():
    """The batch recipe must not maintain a second list of backend versions."""
    expected = tuple(
        f"{backend['slug']}-v{backend['release_version']}"
        for backend in _backends()
        if backend.get("release") is True
    )

    assert release_tags() == expected


def test_provider_resource_names_are_unique_bounded_and_release_specific():
    """Every inventory entry must yield safe Service and Job names."""
    validated = validate_inventory(_manifest())
    names = {
        provider_resource_name(kind=kind, backend=backend, stage=stage)
        for backend in validated
        for kind in ("service", "job")
        for stage in ("staging", "prod")
    }

    assert len(names) == len(validated) * 2 * 2
    assert all(len(name) <= 63 for name in names)
    assert "vb-vs-energyplus-v0-16-2" in names
    assert "vb-vj-portfolio-manager-v0-16-6-stg" in names


def test_duplicate_provider_slug_is_rejected():
    """Two backends must never resolve to the same Cloud Run resource prefix."""
    manifest = deepcopy(_manifest())
    manifest["backend"][1]["provider_resource_slug"] = manifest["backend"][0][
        "provider_resource_slug"
    ]

    with pytest.raises(InventoryError, match="duplicate provider_resource_slug"):
        validate_inventory(manifest)


def test_every_release_image_routes_job_and_service_through_shared_entrypoint():
    """A backend cannot silently bypass the common isolation/HTTP contract."""
    for backend in _backends():
        dockerfile = (REPO_ROOT / backend["dockerfile"]).read_text(encoding="utf-8")
        expected_module = f"validator_backends.{backend['slug']}.main"
        assert "validator_backends.core.entrypoint" in dockerfile
        assert f'"--backend-module", "{expected_module}"' in dockerfile


def test_every_release_image_copies_only_core_and_its_own_backend():
    """Unrelated backend code and test fixtures must not enter an image.

    The repository root is the shared Docker build context, so a broad package
    copy would make every validator image contain every backend. Each
    Dockerfile must instead copy the package marker, the shared runtime, and
    exactly its selected backend; ``.dockerignore`` removes tests and caches
    below those explicitly selected directories.
    """
    backend_slugs = {backend["slug"] for backend in _backends()}
    broad_copy = "validator_backends /app/validator_backends"

    for backend in _backends():
        slug = backend["slug"]
        dockerfile = (REPO_ROOT / backend["dockerfile"]).read_text(encoding="utf-8")
        normalized = re.sub(
            r"[ \t]+",
            " ",
            re.sub(r"\\[ \t]*\n[ \t]*", " ", dockerfile),
        )

        assert broad_copy not in normalized
        assert ("validator_backends/__init__.py /app/validator_backends/__init__.py") in normalized
        assert ("validator_backends/core/*.py /app/validator_backends/core/") in normalized
        assert (f"validator_backends/{slug}/*.py /app/validator_backends/{slug}/") in normalized

        for unrelated_slug in backend_slugs - {slug}:
            assert f"validator_backends/{unrelated_slug} " not in normalized


def test_dockerignore_excludes_local_build_noise_and_secrets():
    """The root build context must exclude local state and credential material."""
    ignored = set(
        (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines(),
    )

    for required in {
        ".git",
        ".venv",
        ".env",
        ".env.*",
        ".envs",
        ".pytest_cache",
        ".ruff_cache",
        "*.pem",
        "*.key",
        "dist",
        "build",
        "**/__pycache__",
        "validator_backends/*/tests",
    }:
        assert required in ignored
