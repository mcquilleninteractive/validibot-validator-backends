# Releasing and verifying validator backends

This document covers the maintainer release commands and the downstream
operator checks for validator backend images.

## Cut a release

Use the `just` recipes for routine releases. They read versions directly from
`backends.toml`, require a clean and synchronized `main`, confirm the repository
uses the latest published `validibot-shared`, run the complete release checks,
create signed tags, verify them against `.allowed_signers`, and push them.

Release one backend:

```bash
just release energyplus
```

Release every backend whose current `backends.toml` version has not yet been
published:

```bash
just release-all
```

`just release-all` shows the exact unpublished versions and asks for
confirmation once. It signs and verifies new tags, then pushes them one at a
time because [GitHub does not create workflow
events when more than three tags share one
push](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#push).
Each tag starts its own backend-specific GitHub Actions release. If a push
fails after tags were created locally, rerunning the same command safely
verifies and resumes them.

If a signed tag reached GitHub but no release was produced, the same command
retries it without changing its version, source commit, signature, or tag
object. It verifies that the local and remote signed tag objects are identical,
then dispatches the release workflow from protected `main` with that tag as its
verified input. Published releases are skipped, and the workflow independently
refuses to overwrite either an existing GitHub Release or versioned container
image. The repository's `ghcr` environment must allow both release tags and
protected `main`; the workflow still checks the target tag's trusted signature
and protected-main ancestry before publishing.

Before either command, update the relevant `release_version` values and
generated artifacts, commit the changes, merge them to `main`, and pull the
updated `main`. Routine releases should not be assembled with a handwritten
sequence of `git tag` and `git push` commands.

After pushing, monitor the release workflows:

```bash
gh run watch
```

## Where the images live

Validator backend container images are published to **GitHub
Container Registry (GHCR)** at:

```
ghcr.io/mcquilleninteractive/validibot-validator-backend-<validator>:<tag>
```

These images are public and can be pulled without credentials, subject to
GHCR's service limits. No GCP, AWS, or third-party registry credentials are
required.

Available backends today:

- `ghcr.io/mcquilleninteractive/validibot-validator-backend-energyplus`
- `ghcr.io/mcquilleninteractive/validibot-validator-backend-fmu`
- `ghcr.io/mcquilleninteractive/validibot-validator-backend-shacl`
- `ghcr.io/mcquilleninteractive/validibot-validator-backend-schematron`
- `ghcr.io/mcquilleninteractive/validibot-validator-backend-portfolio-manager`

Each release publishes both `:vX.Y.Z` (immutable, recommended for
production) and `:latest` (mutable convenience pointer for
development).

## How image versions are set

The Docker containers do not read `VALIDATOR_VERSION` or
`VALIDATOR_BACKEND_VERSION` at runtime. The version is **image metadata
only**. The release workflow reads `release_version` from `backends.toml` and
passes it to the Dockerfile:

- `org.opencontainers.image.version` ← `ARG VALIDATOR_BACKEND_VERSION`
  (the matching `backends.toml` `release_version`)
- `org.opencontainers.image.revision` ← the commit SHA used for the
  build (passed in by the recipe)
- `io.validibot.validator-backend.slug` identifies which backend the
  image implements (`energyplus`, `fmu`, …)

There's no Python-side `BACKEND_IMAGE_VERSION` constant, Dockerfile default,
or separate version file. `backends.toml` is the single source of truth.

### Wrapper version vs bundled-library version

`VALIDATOR_BACKEND_VERSION` is **OUR backend wrapper's version** — the
container image, the entrypoint, the envelope handling. It is
*intentionally decoupled* from the upstream library version that the
wrapper bundles (e.g. EnergyPlus 25.2.0 inside the EnergyPlus backend
container).

A fresh release ships these values:

| Backend | Wrapper version | Bundled library |
|---|---|---|
| EnergyPlus | `0.16.1` (`backends.toml`) | EnergyPlus 25.2.0 (downloaded in the Dockerfile) |
| FMU | `0.15.6` (`backends.toml`) | FMPy 0.3.30 |
| SHACL | `0.15.5` (`backends.toml`) | pySHACL 0.40.1 |
| Schematron | `0.15.5` (`backends.toml`) | SaxonC-HE 13.0.0 |
| Portfolio Manager | `0.16.5` (`backends.toml`) | openpyxl 3.1.5 and xlrd 2.0.2 |
| PDF | `0.1.1` (`backends.toml`) | pikepdf 10.11.0 with qpdf 12.3.2 |

Bumping the wrapper version does NOT imply bumping the bundled library,
and vice versa. They iterate independently.

### Bumping a backend's version

Edit only the backend's `release_version` in `backends.toml`:

```toml
[[backend]]
slug = "fmu"
release_version = "0.15.5"
```

The next `just build fmu` stamps `0.15.5`. Once the change is on `main`,
`just release fmu` signs and publishes `fmu-v0.15.5`; it does not build another
backend. Use `just release-all` when versions for several backends changed in
the same commit.

Signed tag objects and published artifacts are immutable. An unpublished tag
may be retried unchanged by `just release-all`; this does not move or recreate
the tag object. If the source must change, or a versioned image or GitHub
Release already exists, increment that backend's version and create a new
signed tag.

### Portfolio Manager V1 scope

Portfolio Manager V1 supports the reviewed XLS, XLSX, XML, and flat ZIP
contract proven by the public, anonymized SEED-derived fixtures in
`validator_backends/portfolio_manager/tests/assets/`. This is fixture-backed
compatibility, not EPA certification or a claim to accept every current
Portfolio Manager UI/API report variant. Fresh current-EPA export
certification is deferred to V2.

### Manual builds

If you build manually instead of using the just recipes, read the version from
the inventory and pass it explicitly:

```bash
VERSION="$(python3 scripts/backend_inventory.py field fmu release_version)"
docker buildx build \
  --platform linux/amd64 \
  --load \
  -f validator_backends/fmu/Dockerfile \
  --build-arg VALIDATOR_BACKEND_VERSION="$VERSION" \
  --build-arg VALIDATOR_BACKEND_REVISION="$(git rev-parse --short HEAD)" \
  --build-arg VALIDATOR_BACKEND_SLUG=fmu \
  -t "validibot-validator-backend-fmu:v$VERSION" \
  .
```

The image digest remains the exact trust root for a run; the version
label is for inventory and support readability.

## Two layers of provenance

Each release ships:

1. **A signed git tag** on the `validibot-validator-backends`
   repo, verifiable via `git verify-tag` against the `.allowed_signers`
   trust anchor stored on protected `main`. Release CI also requires the tag
   commit to be the checked-out commit and an ancestor of protected `main`.
2. **A sigstore build-provenance attestation** on the image
   digest, verifiable via `gh attestation verify`. This is what
   the runtime
   `VALIDATOR_BACKEND_IMAGE_POLICY=signed-digest` setting
   consumes when enabled.

The layers stack: the signed git tag gates the CI run that produces the image
attestations, so a verified attestation also identifies the protected-main
source commit. The tag does not supply its own trust anchor.

## Verifying a release before deploy

```bash
# Pull the image. For production, prefer pinning by digest rather
# than tag — operators running with VALIDATOR_BACKEND_IMAGE_POLICY=digest
# require this anyway.
docker pull ghcr.io/mcquilleninteractive/validibot-validator-backend-energyplus:v0.15.5

# Resolve the digest:
DIGEST=$(crane digest \
  ghcr.io/mcquilleninteractive/validibot-validator-backend-energyplus:v0.15.5)
echo "Image digest: $DIGEST"

# Verify the sigstore attestation against the digest. This
# confirms the image was built by Validibot's GitHub Actions on
# the expected commit, signed via OIDC.
gh attestation verify \
  "oci://ghcr.io/mcquilleninteractive/validibot-validator-backend-energyplus@$DIGEST" \
  --owner mcquilleninteractive
# Expected output: "Verification succeeded!"
```

`gh attestation verify` exits 0 only when:

- A sigstore attestation exists for the digest.
- The attestation was signed via OIDC by
  `mcquilleninteractive/validibot-validator-backends`'s GitHub Actions
  identity.
- The attestation chain validates against the sigstore root.

This is the *runtime* gate — independent of
`VALIDATOR_BACKEND_IMAGE_POLICY`, which a Validibot deployment
uses to refuse to *launch* an image that doesn't satisfy the
policy.

## Pulling images for production-grade environments

### From GHCR directly (recommended for self-hosted)

```yaml
# docker-compose.yml or deployment manifest
services:
  validator-energyplus:
    image: ghcr.io/mcquilleninteractive/validibot-validator-backend-energyplus@sha256:abc123...
```

Pin by digest in production. The version-tag form is convenient
during development; production deployments should reference the
specific digest the deploy was tested against.

### Mirroring to a private registry (AWS ECR, Harbor, etc.)

If your deployment infrastructure prefers pulling from a
registry inside your network or cloud (latency, IAM, egress
billing), mirror the digest to your registry:

```bash
# Install crane (preserves digest across registries):
brew install crane   # or download from go-containerregistry releases

crane copy \
  ghcr.io/mcquilleninteractive/validibot-validator-backend-energyplus:v0.15.5 \
  111122223333.dkr.ecr.us-west-2.amazonaws.com/validibot-validator-backend-energyplus:v0.15.5
```

The image digest is preserved across the copy, so
`gh attestation verify oci://your-registry@<digest>` continues to
work — the attestation is bound to the bytes, not the registry
name.

### Air-gapped deployments

```bash
# On an internet-connected transit host:
docker pull ghcr.io/mcquilleninteractive/validibot-validator-backend-energyplus:v0.15.5
gh attestation verify \
  "oci://ghcr.io/mcquilleninteractive/validibot-validator-backend-energyplus:v0.15.5" \
  --owner mcquilleninteractive
docker save -o energyplus-v0.15.5.tar \
  ghcr.io/mcquilleninteractive/validibot-validator-backend-energyplus:v0.15.5

# Transfer the tarball through your air-gap process. On the
# air-gapped host:
docker load -i energyplus-v0.15.5.tar
```

Verification happens at the network boundary (the transit host),
since `gh attestation verify` requires internet access to query
the sigstore transparency log.

## What's in a release

For each backend, every signed-tag release publishes:

1. **A backend-specific signed git tag** (`<backend>-vX.Y.Z`) verifiable via
   `git verify-tag`.
2. **Two image tags on GHCR**: `vX.Y.Z` (immutable) and `latest`
   (mutable).
3. **A sigstore build-provenance attestation** on the image
   digest, queryable via `gh attestation verify`.
4. **A SLSA in-toto provenance attestation** embedded in the OCI
   image manifest itself, queryable via
   `docker buildx imagetools inspect <ref> --format '{{ json .Provenance }}'`.
5. **A SPDX image SBOM** embedded in the OCI image manifest, queryable
   via `docker buildx imagetools inspect <ref> --format '{{ json .SBOM }}'`.
6. **A standalone image SBOM artifact** attached to the GitHub release
   page (`validibot-validator-backend-<validator>.spdx.json`) and bound to the
   exact image digest by a signed SBOM attestation.
7. **A lock-derived CycloneDX application SBOM** embedded at
   `/app/legal/APPLICATION-SBOM.cdx.json`, attached to the GitHub release, and
   bound to the exact image digest by a signed SBOM attestation.
   The image also contains `LICENSE`, `NOTICE`, the generated
   `THIRD-PARTY-LICENSES.md`, and copied wheel license files under `/app/legal`.
8. **An attested backend release JSON** named
   `validibot-validator-backend-<validator>-vX.Y.Z.json`, plus its SHA-256
   checksum. The JSON records the exact source tag, source commit, image
   digest, shared contract, image-SBOM filename, and build-verification
   reference. The application SBOM remains a separate release artifact rather
   than a second field in the strict release-record schema.

Before tagging, run `uv run python scripts/backend_artifacts.py check` and
`uv run python scripts/generate_legal_artifacts.py --policy
legal/license-policy.toml --check-only`. Release CI repeats both checks and
stops when generated locks/SBOMs are stale or an installed distribution has an
unknown or unapproved license.

## Checking image integrity in CI

For operators integrating Validibot into their own CI pipelines,
add an attestation-verify step before deploy:

```yaml
- name: Verify validator backend image
  run: |
    DIGEST=$(crane digest \
      ghcr.io/mcquilleninteractive/validibot-validator-backend-energyplus:v0.15.4)
    gh attestation verify \
      "oci://ghcr.io/mcquilleninteractive/validibot-validator-backend-energyplus@$DIGEST" \
      --owner mcquilleninteractive
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

This step exits non-zero if Validibot's CI didn't sign this exact
digest, blocking the deploy.

## Related repositories

- **`validibot`** — the Django application that orchestrates
  validator backend launches. See that repo's `RELEASING.md` for
  the source-clone verification recipe.
- **`validibot-shared`** — Pydantic models on PyPI. Verify via
  PyPI's OIDC attestation UI or the `pypi-attestations` CLI.
