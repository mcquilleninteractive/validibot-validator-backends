# =============================================================================
# Validibot Validators Justfile
# =============================================================================
#
# Build, test, and deploy validator containers for development Cloud Run Jobs.
#
# USAGE:
#   just                        # List all available commands
#   just build energyplus       # Build a specific validator locally
#   just test                   # Run all tests
#   just deploy energyplus dev  # Deploy to dev stage
#   just release-all            # Release every newly versioned backend
#
# SETUP:
#   Before using build-push or deploy commands, create a .env file:
#     cp .env.example .env
#     # Edit .env with your GCP project and region
#
# DEPLOYMENT:
#   This justfile builds and deploys development Cloud Run Jobs. The main
#   hosted operator commands live in the sibling validibot-project repository
#   and deploy verified signed releases to both Jobs and Services:
#
#     From validibot-validator-backends/:  just deploy energyplus dev
#     From validibot-project/:             just validator-status
#     Production update:                  just validator-update energyplus
#
# =============================================================================

set shell := ["bash", "-cu"]

# Load .env file if present (optional — vars can also be set via environment)
set dotenv-load

# =============================================================================
# Configuration
# =============================================================================

# GCP settings - loaded from .env, environment variables, or command line:
#   cp .env.example .env        # then edit with your values
#   export VALIDIBOT_GCP_PROJECT=my-project
#   just --set gcp_project "my-project" deploy energyplus dev
gcp_project := env("VALIDIBOT_GCP_PROJECT", "")
gcp_region := env("VALIDIBOT_GCP_REGION", "us-central1")

# Artifact Registry path (constructed from GCP settings)
ar_host := gcp_region + "-docker.pkg.dev"
ar_repo := ar_host + "/" + gcp_project + "/validibot"

# Git SHA for tagging
git_sha := `git rev-parse --short HEAD 2>/dev/null || echo "dev"`

# Available validators for local batch build/push/deploy recipes. Release CI
# selects exactly one backend from backends.toml and does not use this list.
validators := "energyplus fmu shacl schematron portfolio_manager pdf"

# =============================================================================
# Default - List Commands
# =============================================================================

@default:
    just --list

# =============================================================================
# Development
# =============================================================================

# Run all tests
test *args:
    uv run --frozen --extra dev --extra fmu --extra shacl --extra schematron --extra portfolio_manager --extra pdf pytest {{args}}

# Run tests for a specific validator
test-validator validator:
    uv run --frozen --extra dev --extra fmu --extra shacl --extra schematron --extra portfolio_manager --extra pdf pytest validator_backends/{{validator}}/tests

# Lint all code
lint:
    uv run --frozen --extra dev ruff check .

# Lint and fix
lint-fix:
    uv run --frozen --extra dev ruff check . --fix

# Verify formatting without changing files
format-check:
    uv run --frozen --extra dev ruff format --check .

# Format code
format:
    uv run --frozen --extra dev ruff format .

# Report the advisory typing backlog until a ratcheting baseline is established.
typecheck:
    uv run --frozen --extra dev mypy --explicit-package-bases validator_backends scripts

# Verify pyproject.toml and uv.lock describe the same dependency graph
lock-check:
    uv lock --check

# Regenerate hash-locked image requirements and application SBOMs
artifacts:
    uv run --frozen python scripts/backend_artifacts.py generate

# Verify generated image requirements and application SBOMs are current
artifacts-check:
    uv run --frozen python scripts/backend_artifacts.py check

# Verify the release inventory before deriving tags, image names, or build inputs
inventory-check:
    uv run --frozen python scripts/backend_inventory.py validate > /dev/null

# Reject unknown or unapproved licenses in the installed development environment
licenses:
    uv run --frozen --all-extras python scripts/generate_legal_artifacts.py --policy legal/license-policy.toml --check-only

# Audit every hash-locked validator image dependency set
audit:
    #!/usr/bin/env bash
    set -euo pipefail
    for REQUIREMENTS_FILE in validator_backends/*/requirements.lock; do
        echo "Auditing $REQUIREMENTS_FILE"
        uvx --from pip-audit==2.10.1 pip-audit \
            --require-hashes \
            --disable-pip \
            --strict \
            --requirement "$REQUIREMENTS_FILE"
    done

# Run the deterministic local integration gate used before a backend release
check: lock-check format-check lint inventory-check artifacts-check licenses test

# Require the exact main-branch commit to have a successful CI workflow.
_require-release-ci:
    #!/usr/bin/env bash
    set -euo pipefail

    gh auth status >/dev/null
    REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
    HEAD_SHA="$(git rev-parse HEAD)"
    RUN_INFO="$(
        gh run list \
            --repo "$REPO" \
            --workflow ci.yml \
            --branch main \
            --commit "$HEAD_SHA" \
            --event push \
            --limit 1 \
            --json databaseId,status,conclusion,url \
            --jq 'if length == 0 then "" else .[0] | "\(.databaseId)|\(.status)|\(.conclusion // "")|\(.url)" end'
    )"

    if [[ -z "$RUN_INFO" ]]; then
        echo "Error: No main-branch CI run exists for $HEAD_SHA."
        echo "Push main and wait for CI before releasing."
        exit 1
    fi

    IFS='|' read -r RUN_ID RUN_STATUS RUN_CONCLUSION RUN_URL <<< "$RUN_INFO"
    if [[ "$RUN_STATUS" != "completed" ]]; then
        echo "Waiting for CI run $RUN_ID to finish: $RUN_URL"
        gh run watch "$RUN_ID" --repo "$REPO" --exit-status
    elif [[ "$RUN_CONCLUSION" != "success" ]]; then
        echo "Error: CI did not succeed for $HEAD_SHA: $RUN_URL"
        exit 1
    fi

    echo "CI succeeded for $HEAD_SHA: $RUN_URL"

# Run every local and remote release prerequisite without creating a tag
release-check: check audit _require-release-ci

# =============================================================================
# Docker Build
# =============================================================================

# Build a validator container locally (for testing only)
# Build context is the repo root (validibot-validator-backends/), not the validator subdirectory
#
# Builds for the HOST architecture by default, except EnergyPlus. The bundled
# upstream EnergyPlus archive is Linux x86-64-only, so that validator defaults
# to linux/amd64 even on Apple Silicon. Other validators remain native because
# emulation can make large SHACL runs exceed their local wall-clock budgets.
# To force any explicit platform, set VALIDATOR_BUILD_PLATFORM.
build validator:
    #!/usr/bin/env bash
    set -euo pipefail
    IMAGE_SLUG="{{validator}}"
    IMAGE_SLUG="${IMAGE_SLUG//_/-}"
    build_platform="${VALIDATOR_BUILD_PLATFORM:-}"
    if [[ "{{validator}}" == "energyplus" && -z "$build_platform" ]]; then
        build_platform="linux/amd64"
    fi
    echo "Building {{validator}} container${build_platform:+ for ${build_platform}}..."
    uv run python scripts/backend_artifacts.py check --backend "{{validator}}"
    BACKEND_VERSION="$(
        python3 scripts/backend_inventory.py field "{{validator}}" release_version
    )"
    docker buildx build \
        ${build_platform:+--platform "${build_platform}"} \
        --load \
        -f validator_backends/{{validator}}/Dockerfile \
        --build-arg VALIDATOR_BACKEND_VERSION="$BACKEND_VERSION" \
        --build-arg VALIDATOR_BACKEND_REVISION="{{git_sha}}" \
        --build-arg VALIDATOR_BACKEND_SLUG="{{validator}}" \
        -t validibot-validator-backend-${IMAGE_SLUG}:latest \
        -t validibot-validator-backend-${IMAGE_SLUG}:{{git_sha}} \
        .
    echo "✓ Built validibot-validator-backend-${IMAGE_SLUG}:{{git_sha}}"

# Build all validator containers
build-all:
    #!/usr/bin/env bash
    set -euo pipefail
    for v in {{validators}}; do
        just build "$v"
    done
    echo "✓ All validators built"

# =============================================================================
# Docker Push (to Artifact Registry)
# =============================================================================

# Build and push a validator to Artifact Registry in one step
# Uses buildx with --push to avoid platform manifest issues on Apple Silicon
# Requires VALIDIBOT_GCP_PROJECT environment variable to be set
build-push validator:
    #!/usr/bin/env bash
    set -euo pipefail
    IMAGE_SLUG="{{validator}}"
    IMAGE_SLUG="${IMAGE_SLUG//_/-}"
    if [[ -z "{{gcp_project}}" ]]; then
        echo "Error: Container registry not configured."
        echo ""
        echo "Set environment variables before running:"
        echo "  export VALIDIBOT_GCP_PROJECT=your-project-id"
        echo "  export VALIDIBOT_GCP_REGION=us-central1  # optional, defaults to us-central1"
        echo ""
        echo "Or pass directly:"
        echo "  just --set gcp_project your-project-id build-push {{validator}}"
        exit 1
    fi
    echo "Building and pushing {{validator}} container..."
    uv run python scripts/backend_artifacts.py check --backend "{{validator}}"
    BACKEND_VERSION="$(
        python3 scripts/backend_inventory.py field "{{validator}}" release_version
    )"
    docker buildx build \
        --platform linux/amd64 \
        --push \
        -f validator_backends/{{validator}}/Dockerfile \
        --build-arg VALIDATOR_BACKEND_VERSION="$BACKEND_VERSION" \
        --build-arg VALIDATOR_BACKEND_REVISION="{{git_sha}}" \
        --build-arg VALIDATOR_BACKEND_SLUG="{{validator}}" \
        -t {{ar_repo}}/validibot-validator-backend-${IMAGE_SLUG}:latest \
        -t {{ar_repo}}/validibot-validator-backend-${IMAGE_SLUG}:{{git_sha}} \
        .
    echo "✓ Built and pushed {{ar_repo}}/validibot-validator-backend-${IMAGE_SLUG}:{{git_sha}}"

# Build and push all validators
build-push-all:
    #!/usr/bin/env bash
    set -euo pipefail
    for v in {{validators}}; do
        just build-push "$v"
    done
    echo "✓ All validators built and pushed"

# =============================================================================
# Cloud Run Jobs Deployment
# =============================================================================

# Deploy a validator as a development Cloud Run Job. Hosted production is
# release-only and is owned by the validibot repository's GCP recipes.
# Usage: just deploy energyplus dev
deploy validator stage:
    #!/usr/bin/env bash
    set -euo pipefail
    IMAGE_SLUG="{{validator}}"
    IMAGE_SLUG="${IMAGE_SLUG//_/-}"
    if [[ ! "{{stage}}" =~ ^(dev|staging|prod)$ ]]; then
        echo "Error: stage must be 'dev', 'staging', or 'prod'"
        exit 1
    fi
    if [ "{{stage}}" = "prod" ]; then
        echo "Error: this repository does not deploy locally built images to production." >&2
        echo "From the validibot-project repo, run:" >&2
        echo "  just validator-update {{validator}}" >&2
        exit 1
    fi
    just build-push {{validator}}

    # Compute stage-specific names.
    #
    # Two DISTINCT service accounts, matching the main repo's
    # `just gcp validator-job-deploy` (validibot/just/gcp/mod.just):
    #   * RUNTIME_SA — the dedicated, least-privilege identity the validator
    #     container RUNS AS (--service-account). It can invoke the worker for
    #     callbacks but has no ambient GCS, secrets, Cloud SQL, Cloud Tasks, or
    #     KMS role. Attempt data comes from the short-lived GCS capability.
    #   * INVOKER_SA — the main web/worker identity allowed to TRIGGER the job
    #     (granted validibot_job_runner below). The Django worker runs as this
    #     SA when it calls the Jobs API to launch a validation.
    #
    # Previously both were the broad `validibot-cloudrun-*` SA, so the container
    # ran with the full app identity (secrets/DB/tasks/KMS). Because this recipe
    # and the main repo's recipe deploy the SAME job name, whichever ran last
    # set the job's runtime identity — so the standalone path could silently
    # widen it. Using RUNTIME_SA here keeps both deploy paths in agreement on
    # least privilege. (Both SAs are created by `just gcp init-stage` in the
    # main repo; run that first.)
    if [ "{{stage}}" = "prod" ]; then
        JOB_NAME="validibot-validator-backend-${IMAGE_SLUG}"
        RUNTIME_SA="validibot-validator-prod@{{gcp_project}}.iam.gserviceaccount.com"
        INVOKER_SA="validibot-cloudrun-prod@{{gcp_project}}.iam.gserviceaccount.com"
    else
        JOB_NAME="validibot-validator-backend-${IMAGE_SLUG}-{{stage}}"
        RUNTIME_SA="validibot-validator-{{stage}}@{{gcp_project}}.iam.gserviceaccount.com"
        INVOKER_SA="validibot-cloudrun-{{stage}}@{{gcp_project}}.iam.gserviceaccount.com"
    fi

    echo "Deploying $JOB_NAME to {{stage}}..."
    gcloud run jobs deploy "$JOB_NAME" \
        --image {{ar_repo}}/validibot-validator-backend-${IMAGE_SLUG}:{{git_sha}} \
        --region {{gcp_region}} \
        --project {{gcp_project}} \
        --service-account "$RUNTIME_SA" \
        --memory 4Gi \
        --cpu 2 \
        --max-retries 0 \
        --task-timeout 3600 \
        --set-env-vars "PYTHONUNBUFFERED=1,VALIDIBOT_STAGE={{stage}},DEPLOYMENT_TARGET=gcp" \
        --labels "validator={{validator}},revision={{git_sha}},stage={{stage}}"
    echo "✓ $JOB_NAME deployed (runs as $RUNTIME_SA)"

    # Grant the MAIN web/worker SA permission to run this job with overrides.
    # Uses custom role with run.jobs.run + run.jobs.runWithOverrides (for the
    # VALIDIBOT_INPUT_URI env override). This is the INVOKER, NOT the runtime
    # identity set above.
    echo "Granting job runner permission to $INVOKER_SA on $JOB_NAME..."
    gcloud run jobs add-iam-policy-binding "$JOB_NAME" \
        --region {{gcp_region}} \
        --project {{gcp_project}} \
        --member="serviceAccount:$INVOKER_SA" \
        --role="projects/{{gcp_project}}/roles/validibot_job_runner"
    echo "✓ IAM binding added"

# Deploy all validators to a stage
# Usage: just deploy-all dev | just deploy-all prod
deploy-all stage:
    #!/usr/bin/env bash
    set -euo pipefail
    for v in {{validators}}; do
        just deploy "$v" {{stage}}
    done
    echo "✓ All validators deployed to {{stage}}"

# =============================================================================
# Cloud Run Jobs Management
# =============================================================================

# List all validator jobs
list-jobs:
    gcloud run jobs list \
        --region {{gcp_region}} \
        --project {{gcp_project}} \
        --filter "name~validibot-validator"

# Show job details
describe-job validator stage="prod":
    #!/usr/bin/env bash
    IMAGE_SLUG="{{validator}}"
    IMAGE_SLUG="${IMAGE_SLUG//_/-}"
    if [ "{{stage}}" = "prod" ]; then
        JOB_NAME="validibot-validator-backend-${IMAGE_SLUG}"
    else
        JOB_NAME="validibot-validator-backend-${IMAGE_SLUG}-{{stage}}"
    fi
    gcloud run jobs describe "$JOB_NAME" \
        --region {{gcp_region}} \
        --project {{gcp_project}}

# View recent job logs
logs validator stage="prod" lines="100":
    #!/usr/bin/env bash
    IMAGE_SLUG="{{validator}}"
    IMAGE_SLUG="${IMAGE_SLUG//_/-}"
    if [ "{{stage}}" = "prod" ]; then
        JOB_NAME="validibot-validator-backend-${IMAGE_SLUG}"
    else
        JOB_NAME="validibot-validator-backend-${IMAGE_SLUG}-{{stage}}"
    fi
    gcloud logging read \
        "resource.type=\"cloud_run_job\" AND resource.labels.job_name=\"$JOB_NAME\"" \
        --project {{gcp_project}} \
        --limit {{lines}} \
        --format "table(timestamp,textPayload)"

# Delete a validator job
delete-job validator stage="prod":
    #!/usr/bin/env bash
    IMAGE_SLUG="{{validator}}"
    IMAGE_SLUG="${IMAGE_SLUG//_/-}"
    if [ "{{stage}}" = "prod" ]; then
        JOB_NAME="validibot-validator-backend-${IMAGE_SLUG}"
    else
        JOB_NAME="validibot-validator-backend-${IMAGE_SLUG}-{{stage}}"
    fi
    echo "Deleting Cloud Run Job $JOB_NAME..."
    gcloud run jobs delete "$JOB_NAME" \
        --region {{gcp_region}} \
        --project {{gcp_project}} \
        --quiet
    echo "✓ Deleted $JOB_NAME"

# =============================================================================
# Local Development Helpers
# =============================================================================

# Run a validator container locally (for testing)
run-local validator input_uri:
    #!/usr/bin/env bash
    IMAGE_SLUG="{{validator}}"
    IMAGE_SLUG="${IMAGE_SLUG//_/-}"
    docker run --rm \
        -e VALIDIBOT_INPUT_URI={{input_uri}} \
        -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/keys/adc.json \
        -v "$HOME/.config/gcloud/application_default_credentials.json:/tmp/keys/adc.json:ro" \
        validibot-validator-backend-${IMAGE_SLUG}:latest

# Shell into a validator container (for debugging)
shell validator:
    #!/usr/bin/env bash
    IMAGE_SLUG="{{validator}}"
    IMAGE_SLUG="${IMAGE_SLUG//_/-}"
    docker run --rm -it \
        --entrypoint /bin/bash \
        validibot-validator-backend-${IMAGE_SLUG}:latest

# =============================================================================
# CI/CD Helpers
# =============================================================================

# Build, test, and deploy (for CI)
ci-deploy validator stage:
    just check
    just deploy {{validator}} {{stage}}

# Verify all validators are deployable (dry run)
verify-all:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Verifying all validators..."
    just check
    for v in {{validators}}; do
        just build "$v"
    done
    echo "✓ All validators verified"

# =============================================================================
# Release
# =============================================================================
#
# Cuts backend-specific signed tags. CI builds each tagged backend image with
# full supply-chain provenance, a release JSON record, and an SBOM.
# Published artifacts and signed tag objects are immutable. An unpublished tag
# may be re-emitted unchanged when GitHub missed its original push event.
#
# Operator verification (after pull): see RELEASING.md.

# Run the repository and dependency checks shared by every release command.
_release-preflight:
    #!/usr/bin/env bash
    set -euo pipefail

    if [[ -n $(git status --porcelain) ]]; then
        echo "✗ Working tree has uncommitted changes. Commit or stash first."
        git status --short
        exit 1
    fi

    BRANCH=$(git branch --show-current)
    if [[ "$BRANCH" != "main" ]]; then
        echo "✗ Not on main branch (currently on '$BRANCH')."
        echo "  Releases are cut from main only. Switch with: git switch main"
        exit 1
    fi

    git fetch origin main
    if [[ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]]; then
        echo "✗ Local main is not in sync with origin/main."
        echo "  Run: git pull --ff-only"
        exit 1
    fi

    # Catch a forgotten validibot-shared bump before immutable images are cut.
    # Override only when an older shared release is intentionally required.
    if [[ "${VALIDIBOT_RELEASE_ALLOW_STALE_SHARED:-0}" != "1" ]]; then
        SHARED_PINNED="$(
            sed -nE 's/.*"validibot-shared==([^" ]+)".*/\1/p' pyproject.toml |
                head -1
        )"
        if [[ -z "$SHARED_PINNED" ]]; then
            echo "⚠ Could not detect validibot-shared pin in pyproject.toml; skipping freshness check."
        else
            SHARED_LATEST="$(
                curl -s --max-time 10 https://pypi.org/pypi/validibot-shared/json 2>/dev/null |
                    jq -r '.info.version' 2>/dev/null || true
            )"
            if [[ -z "$SHARED_LATEST" ]] || [[ "$SHARED_LATEST" == "null" ]]; then
                echo "⚠ Could not query PyPI for latest validibot-shared. Currently pinned: $SHARED_PINNED."
                echo "  Press Enter to continue anyway, Ctrl+C to abort..."
                read -r
            elif [[ "$SHARED_PINNED" != "$SHARED_LATEST" ]]; then
                echo "✗ validibot-shared is pinned to $SHARED_PINNED but latest on PyPI is $SHARED_LATEST."
                echo ""
                echo "  Update pyproject.toml to validibot-shared==$SHARED_LATEST, commit it,"
                echo "  and rerun the release command."
                echo ""
                echo "  Emergency override: VALIDIBOT_RELEASE_ALLOW_STALE_SHARED=1 just release ..."
                exit 1
            else
                echo "✓ validibot-shared is at latest ($SHARED_LATEST)"
            fi
        fi
    fi

# Sign and push the version already recorded for one backend in backends.toml.
# Usage: just release energyplus
release BACKEND:
    #!/usr/bin/env bash
    set -euo pipefail

    VERSION="$(python3 scripts/backend_inventory.py field "{{BACKEND}}" release_version)"
    TAG="{{BACKEND}}-v${VERSION}"
    python3 scripts/backend_inventory.py release "$TAG" >/dev/null

    just _release-preflight

    # Refuse if tag already exists locally or remotely.
    if git show-ref --verify --quiet "refs/tags/$TAG"; then
        echo "✗ Tag $TAG already exists locally."
        exit 1
    fi
    REMOTE_TAG="$(git ls-remote --tags origin "refs/tags/$TAG")"
    if [[ -n "$REMOTE_TAG" ]]; then
        echo "✗ Tag $TAG already exists on origin."
        exit 1
    fi

    just release-check

    if [[ -n $(git status --porcelain) ]]; then
        echo "✗ Release checks changed the working tree. Review and commit those changes first."
        git status --short
        exit 1
    fi

    echo ""
    echo "About to sign and push tag $TAG."
    echo "CI will build only {{BACKEND}} at version $VERSION."
    echo "Press Enter to continue, Ctrl+C to abort..."
    read -r

    # Sign the tag. Requires `git config --global tag.gpgsign true`
    # and a signing key configured. The CI workflow at
    # .github/workflows/release.yml verifies the signature and
    # publishes the release artefacts.
    git tag -s "$TAG" -m "$TAG"
    if ! git \
        -c gpg.format=ssh \
        -c gpg.ssh.allowedSignersFile=.allowed_signers \
        verify-tag "$TAG"; then
        echo "✗ Local tag verification failed; the tag was not pushed."
        exit 1
    fi
    git push origin "$TAG"

    echo ""
    echo "✓ Pushed $TAG"
    echo "  CI will:"
    echo "    1. Verify the tag signature"
    echo "    2. Test and build only {{BACKEND}}"
    echo "    3. Push to GHCR with sigstore attestation"
    echo "    4. Generate and attest the backend release JSON"
    echo "    5. Attach the release JSON and SBOM to GitHub Releases"
    echo "  Monitor: gh run watch"

# Publish every current inventory tag that does not yet have a GitHub Release.
# GitHub suppresses workflow events when more than three tags share one push.
# Existing unpublished tags remain immutable and are retried by dispatching the
# release workflow on protected main with the verified tag as its input.
# Usage: just release-all
release-all:
    #!/usr/bin/env bash
    set -euo pipefail

    just _release-preflight
    gh auth status >/dev/null
    REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
    git fetch --tags origin

    TAGS=()
    NEW_TAGS=()
    RETRY_TAGS=()

    is_retry_tag() {
        local CANDIDATE="$1"
        local RETRY_TAG
        for RETRY_TAG in "${RETRY_TAGS[@]+"${RETRY_TAGS[@]}"}"; do
            [[ "$CANDIDATE" == "$RETRY_TAG" ]] && return 0
        done
        return 1
    }

    while IFS= read -r TAG; do
        [[ -n "$TAG" ]] || continue
        python3 scripts/backend_inventory.py release "$TAG" >/dev/null

        REMOTE_TAG="$(git ls-remote --tags origin "refs/tags/$TAG")"
        if [[ -n "$REMOTE_TAG" ]]; then
            if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
                echo "✓ Already published: $TAG"
                continue
            fi
            if ! git show-ref --verify --quiet "refs/tags/$TAG"; then
                echo "✗ Origin has $TAG, but the local tag is missing after fetch."
                exit 1
            fi
            if ! git \
                -c gpg.format=ssh \
                -c gpg.ssh.allowedSignersFile=.allowed_signers \
                verify-tag "$TAG"; then
                echo "✗ Existing tag $TAG does not have a trusted signature."
                exit 1
            fi
            LOCAL_TAG_OBJECT="$(git rev-parse "refs/tags/$TAG")"
            REMOTE_TAG_OBJECT="${REMOTE_TAG%%$'\t'*}"
            if [[ "$LOCAL_TAG_OBJECT" != "$REMOTE_TAG_OBJECT" ]]; then
                echo "✗ Local and remote tag objects differ for $TAG."
                exit 1
            fi
            if ! git merge-base --is-ancestor "${TAG}^{commit}" HEAD; then
                echo "✗ Existing tag $TAG is not on current main."
                exit 1
            fi
            echo "↻ Unpublished signed tag will be retried: $TAG"
            TAGS+=("$TAG")
            RETRY_TAGS+=("$TAG")
            continue
        fi

        if git show-ref --verify --quiet "refs/tags/$TAG"; then
            echo "↻ Resuming local signed tag: $TAG"
            if ! git \
                -c gpg.format=ssh \
                -c gpg.ssh.allowedSignersFile=.allowed_signers \
                verify-tag "$TAG"; then
                echo "✗ Existing local tag $TAG does not have a trusted signature."
                exit 1
            fi
            if [[ "$(git rev-list -n 1 "$TAG")" != "$(git rev-parse HEAD)" ]]; then
                echo "✗ Existing local tag $TAG does not point to the current main commit."
                exit 1
            fi
        else
            NEW_TAGS+=("$TAG")
        fi
        TAGS+=("$TAG")
    done < <(python3 scripts/backend_inventory.py release-tags)

    if [[ "${#TAGS[@]}" -eq 0 ]]; then
        echo "✓ Every current backend release is already published."
        exit 0
    fi

    just release-check

    if [[ -n $(git status --porcelain) ]]; then
        echo "✗ Release checks changed the working tree. Review and commit those changes first."
        git status --short
        exit 1
    fi

    echo ""
    echo "About to publish these backend releases one at a time:"
    for TAG in "${TAGS[@]}"; do
        if is_retry_tag "$TAG"; then
            echo "  - $TAG (retry unchanged signed tag)"
        else
            echo "  - $TAG (new signed tag)"
        fi
    done
    echo "Press Enter to continue, Ctrl+C to abort..."
    read -r

    for TAG in "${NEW_TAGS[@]+"${NEW_TAGS[@]}"}"; do
        git tag -s "$TAG" -m "$TAG"
    done

    for TAG in "${TAGS[@]}"; do
        if ! git \
            -c gpg.format=ssh \
            -c gpg.ssh.allowedSignersFile=.allowed_signers \
            verify-tag "$TAG"; then
            echo "✗ Local verification failed for $TAG; no tags were pushed."
            exit 1
        fi
        if is_retry_tag "$TAG"; then
            if ! git merge-base --is-ancestor "${TAG}^{commit}" HEAD; then
                echo "✗ $TAG is not on current main; no tags were pushed."
                exit 1
            fi
        else
            if [[ "$(git rev-list -n 1 "$TAG")" != "$(git rev-parse HEAD)" ]]; then
                echo "✗ $TAG does not point to the current main commit; no tags were pushed."
                exit 1
            fi
        fi
    done

    for TAG in "${TAGS[@]}"; do
        if is_retry_tag "$TAG"; then
            gh workflow run release.yml \
                --repo "$REPO" \
                --ref main \
                --raw-field "tag=$TAG"
        else
            git push origin "$TAG"
        fi
    done

    echo ""
    echo "✓ Triggered ${#TAGS[@]} backend release(s)."
    echo "  GitHub Actions will test, build, attest, and publish each backend independently."
    echo "  Monitor: gh run watch"
