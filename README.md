<div align="center">

# Validibot Validator Backends

**Containerized validator backends for the Validibot data validation platform**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/mcquilleninteractive/validibot-validator-backends/badge)](https://scorecard.dev/viewer/?uri=github.com/mcquilleninteractive/validibot-validator-backends)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

[Available Validator Backends](#available-validator-backends) •
[Quick Start](#quick-start) •
[Creating Custom Validator Backends](#creating-a-custom-validator-backend) •
[Deployment](#deployment)

</div>

---

> [!NOTE]
> This repository is part of the Validibot open-source data validation platform. These containers provide advanced validation capabilities that run in isolated Docker environments.

---

## Part of the Validibot Project

This repository is one component of the Validibot open-source data validation platform:

| Repository                                                                                      | Description                                       |
| ----------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| **[validibot](https://github.com/mcquilleninteractive/validibot)**                                   | Core platform — web UI, REST API, workflow engine |
| **[validibot-cli](https://github.com/mcquilleninteractive/validibot-cli)**                           | Command-line interface                            |
| **[validibot-validator-backends](https://github.com/mcquilleninteractive/validibot-validator-backends)** (this repo) | Validator backends for advanced validators        |
| **[validibot-shared](https://github.com/mcquilleninteractive/validibot-shared)**                     | Shared Pydantic models for data interchange       |

## What are Validibot Validator Backends?

Validibot validator backends are the external implementations used by specialized, resource-intensive validators. In the core `validibot` codebase, an `AdvancedValidator` is the Django-side wrapper that prepares the run, builds the envelope, launches external work through an `ExecutionBackend`, and processes the output. This repository contains the validator backends that wrapper launches.

The repository is named `validibot-validator-backends` to reflect that these are backend implementations invoked by the core platform's `AdvancedValidator` wrapper. If the concept becomes a formal core protocol or registry entry, `ValidatorBackend` is the right code-level name.

Unlike Validibot's built-in "simple" validators (JSON Schema, XML Schema, etc.) that run directly in the Django process, validator backends:

- **Run in isolation** — Each advanced validation runs in a one-shot container or a fresh request child process with explicit resource limits
- **Have complex dependencies** — [EnergyPlus™](https://energyplus.net/), FMPy, and other domain-specific tools
- **Are secure by default** — Network isolation, memory limits, and automatic cleanup
- **Scale independently** — Can run on separate infrastructure from the core platform

The core Validibot platform triggers these backends, passes input via the standardized envelope format (defined in [validibot-shared](https://github.com/mcquilleninteractive/validibot-shared)), and processes the results when complete.

## Available Validator Backends

| Validator | Description | Use Cases |
| --- | --- | --- |
| **EnergyPlus™** | Validates and simulates building energy models | IDF/epJSON simulation runs, EnergyPlus output metrics, model safety scanning |
| **FMU** | Validates and executes Functional Mock-up Units | FMU structure validation, variable discovery, bounded simulation testing |
| **SHACL** | Validates RDF graphs in an isolated container | RDF parsing, SHACL shapes, SHACL-AF/SPARQL isolation, semantic model checks |
| **Schematron** | Validates XML documents against Schematron rules | Peppol/EN 16931-style business rules, SVRL findings, XSLT isolation |
| **Building benchmark reports** | Validates exports from ENERGY STAR® Portfolio Manager® | XLS/XLSX/XML normalization, safe ZIP collections, EBL reconciliation, EUIt facts |

ENERGY STAR and the ENERGY STAR mark are registered trademarks owned by the
U.S. Environmental Protection Agency. The name ENERGY STAR Portfolio Manager
and the Portfolio Manager logo are registered trademarks owned by the U.S.
Environmental Protection Agency. Validibot is independent and is not approved,
certified, or endorsed by the EPA or the ENERGY STAR program.

Portfolio Manager V1 compatibility is deliberately fixture-backed. Its
reviewed, anonymized XLS, XLSX, and XML fixtures are derived from public SEED
project files, with provenance, checksums, and fixture-hygiene tests retained
in `validator_backends/portfolio_manager/tests/assets/`. V1 does not claim
fresh certification against every current EPA UI/API report variant. Fresh
current-EPA export certification is deferred to V2.

## How It Works

Validator backends receive work via a standardized "envelope" containing:

- **Input files** — URIs to files being validated (GCS or local filesystem)
- **Resource files** — managed auxiliary files such as weather data, model files, or future reusable rule packs
- **Configuration** — Validator-specific settings (e.g., simulation timestep)
- **Context** — Callback URL, execution bundle location, timeout settings

After running validation, the backend writes an output envelope with:

- **Status** — success, failure, or error
- **Messages** — Validation findings (errors, warnings, info)
- **Metrics** — Numeric results (e.g., EUI for building models)
- **Artifacts** — Generated files (reports, logs, etc.)

Every file-bearing envelope item carries a safe logical filename, exact byte
size, lowercase SHA-256, and provider-specific immutable storage version. The
backend opens the exact GCS generation (or content-addressed local file),
streams at most the declared size plus a one-byte overflow sentinel while
hashing, and atomically exposes the local file only after the complete contract
matches. Missing, interrupted, stale, short, long, or digest-mismatched inputs
fail as execution-contract errors before domain parsers or binaries see them.
Produced artifacts carry the same size, digest, and storage-version identity in
the output envelope. Verified local destinations and every published output
envelope, artifact, and directory manifest are create-only: an existing path is
a conflict even when it contains identical bytes. GCS writers enforce the same
rule with `ifGenerationMatch=0`, so no backend success, failure, or retry can
replace an object already committed to an attempt identity.

### Cloud execution shapes

Every released backend image supports the same two provider shapes:

- **Job mode** (default): the image starts its existing one-shot backend and
  exits. This remains the Cloud Run Job and long-running compatibility path.
- **Service mode** (`VALIDIBOT_EXECUTION_SHAPE=service`): one shared HTTP parent
  listens on `/v1/execute`, validates the pinned Service revision/image/task and
  absolute deadline, then launches that same one-shot backend in a fresh child
  process, operating-system session, and attempt-specific scratch directory.

Service concurrency is one. The long-lived parent never loads an input
envelope or installs a bearer credential in module state; only the fresh child
receives the attempt-scoped GCS capability. The child re-authorizes the attempt
with the worker before domain compute. Redelivery verifies an existing exact
output and retries only the idempotent callback, or recomputes into the same
create-only destination when no output exists. The Service response is
transport evidence, not validation completion authority.

On a hard deadline, the parent signals the child's complete process group with
`SIGTERM`, waits for a bounded grace period, and escalates to `SIGKILL`. Native
tools or CLI grandchildren therefore cannot outlive the request and consume
resources on the next delivery to a warm Service instance.

On GCP, current Django launchers also inject a short-lived Credential Access
Boundary token. The backend refuses any GCS URI outside that execution's
attempt prefix and uses the envelope's callback nonce to renew an expired token
only while Django still considers the attempt active. The Cloud Run service
account itself should have no storage role, so compromised backend code cannot
fall back to broader Application Default Credentials.

### File Ports

The envelope fields `input_files` and `resource_files` are the wire format.
The platform-level contract should be designed as **file ports** with explicit
roles, cardinality, accepted formats, and allowed sources.

Current backend ports:

| Backend | Ports today | Notes |
| --- | --- | --- |
| EnergyPlus | `input_files[port_key=primary_model, role=primary-model]`; managed weather uses `resource_files[port_key=weather_file, type=energyplus_weather]` | Weather bound from a submitted file or upstream artifact uses `input_files[port_key=weather_file, role=weather]` instead. Both channels are current. |
| FMU | `input_files[port_key=fmu_model, role=fmu]` | Source may be a library FMU model or a step-owned workflow resource. |
| SHACL | `input_files[port_key=data_graph, role=data-graph]`; shapes and ontology currently travel inline in typed `inputs` | Future large/reusable shapes or ontologies should become declared resource/artifact ports. |
| Schematron | `input_files[port_key=xml_document, role=xml-document]`; Schematron rules currently travel inline in typed `inputs` | Future generated or reusable `.sch` files should become declared resource/artifact ports. |
| Building benchmark reports | `input_files[port_key=portfolio_manager_report, role=portfolio-manager-report]`; optional `resource_files[port_key=expected_buildings_list]` | Accepts one XLS/XLSX/XML report or ZIP collection and emits the bounded scalar catalog plus the property-results JSON artifact. |
| PDF packages | `input_files[port_key=pdf_document, role=pdf-document]` | Emits a bounded inventory plus distinct XMP, attachment, associated-file, embedded-file, and semantic-payload artifacts for explicit downstream bindings. |

Backend code must use the shared `select_input_file()` and
`select_resource_file()` helpers. They match an exact `port_key` and fall back
to `role` or `type` only when that individual item has no port key. This detail
matters: an item carrying a different explicit key must not impersonate a port
through an old role label. The helpers also reject missing and ambiguous inputs
instead of depending on list order. Do not add backend-local matchers or read
`input_files[0]`.

## Important Disclaimers

> [!CAUTION]
> **Code execution:** Validator backend containers execute user-supplied files (IDF building models, FMU binaries, etc.) using third-party tools. While containers provide isolation, no guarantee is made regarding safety, security, or resource consumption. You are responsible for reviewing files before running them.
>
> **Cloud costs:** Cloud deployments (GCP Cloud Run, etc.) incur charges for compute, storage, and network. The authors are not liable for any costs incurred.
>
> **Data handling:** Input files are transmitted to and stored in your configured storage backend (GCS, local filesystem). You are responsible for the confidentiality and handling of your data.
>
> **No warranty for results:** Simulation and validation results (e.g., EnergyPlus™ energy metrics) are approximations only. Results should be independently verified before use in critical applications. See the [LICENSE](LICENSE) for full warranty disclaimer.

## Quick Start

### Prerequisites

- Docker (or Podman)
- Python 3.13+
- [uv](https://github.com/astral-sh/uv) package manager
- [just](https://github.com/casey/just) command runner

### Building Containers

```bash
# Clone the repository
git clone https://github.com/mcquilleninteractive/validibot-validator-backends.git
cd validibot-validator-backends

# Build a specific validator
just build energyplus

# Build all validators
just build-all

# List available commands
just --list
```

### Image version metadata

Each backend's `release_version` in [`backends.toml`](backends.toml) is the
**single source of truth** for the version offered to a new installation or
routine update. Local build recipes and the release workflow read that exact
value and pass it as `VALIDATOR_BACKEND_VERSION`; the Dockerfiles have no
version default.

- **Not in a Python constant.** No `BACKEND_IMAGE_VERSION` in
  `__metadata__.py` to drift from the inventory.
- **Not in a Dockerfile default.** The `ARG` is required and receives the
  inventory value from every supported build path.
- **Not in a runtime environment variable.** The container doesn't read its
  own version from its environment at startup; the version belongs to the
  image's identity, not the runtime caller's configuration.
- **Not in a sidecar version file.** No `VERSION` text file to keep in sync.

The trust-critical runtime identity is still the image **digest**
(`sha256:...`). The version label is for operator inventory (the
`just self-hosted validators` recipe reads it via `docker inspect`),
support, and release readability — not for cryptographic verification.

```dockerfile
# validator_backends/energyplus/Dockerfile
ARG VALIDATOR_BACKEND_VERSION
LABEL org.opencontainers.image.version="${VALIDATOR_BACKEND_VERSION}" ...
```

The `just build <validator>` and `just build-push <validator>` recipes
read the matching inventory entry and additionally stamp:

- `org.opencontainers.image.revision` = current git commit SHA
- `org.opencontainers.image.source` = this repository
- `io.validibot.validator-backend.slug` = the backend slug
  (`energyplus`, `fmu`, …)

Each backend has its own version. EnergyPlus can move to `0.17.0` while FMU
stays on `0.15.3`; changing one inventory entry does not release the others.

Current independently offered versions are:

| Backend | Version |
| --- | --- |
| EnergyPlus | `0.16.2` |
| FMU | `0.15.6` |
| SHACL | `0.15.6` |
| Schematron | `0.15.6` |
| Portfolio Manager | `0.16.6` |
| PDF | `0.1.1` |

Release tags are backend-specific, such as `energyplus-v0.16.2` and
`portfolio_manager-v0.16.6`. A failed or published tag is never moved or
reused; the correction receives a new backend version.

### Reproducible dependencies and legal evidence

Each inventory record points to a human-authored `requirements.txt`, a
generated hash-locked `requirements.lock`, and a generated CycloneDX
application SBOM. The direct pins must match the root project plus the
backend's optional dependency group. Regenerate and verify them with:

```bash
uv run python scripts/backend_artifacts.py generate
uv run python scripts/backend_artifacts.py check
```

Images install only from the generated lock. Every image contains `/app/legal`
with Validibot's `LICENSE` and `NOTICE`, the application SBOM, a generated
report of the Python distributions actually installed, and copied
wheel-provided license files. Release CI also publishes an image-level SPDX
SBOM that includes the base operating system. License-policy checks fail closed
on new, unknown, or unapproved dependency licenses.

#### Wrapper version vs bundled-library version (CRUCIAL)

`VALIDATOR_BACKEND_VERSION` is **OUR backend wrapper's version** — the
container image, the entrypoint, the envelope handling. It is *intentionally
decoupled* from the upstream library version that the wrapper bundles.

For example, the EnergyPlus inventory entry and Dockerfile describe separate
version axes:

| Axis | Value | Bumped when |
|---|---|---|
| Wrapper version (`backends.toml` `release_version`) | `0.16.0` | Wrapper code, image layout, or output semantics change |
| Bundled EnergyPlus binary | `25.2.0` | A newer EnergyPlus release is downloaded |

These are independent:

- The wrapper can iterate (0.1.0 → 0.2.0 → 0.3.0) while still bundling
  EnergyPlus 25.2.0.
- The bundled EnergyPlus version can be upgraded without bumping the
  wrapper version (though usually you'd bump both because output
  semantics may shift).

Bumping `VALIDATOR_BACKEND_VERSION` does NOT imply bumping the bundled
library version. Bumping the bundled library does NOT imply bumping
`VALIDATOR_BACKEND_VERSION` (though it usually warrants one).

#### Inspecting a built image

```bash
docker image inspect validibot-validator-backend-energyplus:latest \
  --format '{{ index .Config.Labels "org.opencontainers.image.version" }}'
# → 0.16.0

docker image inspect validibot-validator-backend-energyplus:latest \
  --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}'
# → abc1234
```

#### Manual builds

Manual Docker builds must read or pass the exact inventory version. The
supported `just build` command does that automatically:

```bash
just build energyplus

# Equivalent direct build:
VERSION="$(python3 scripts/backend_inventory.py field energyplus release_version)"
docker buildx build \
  --platform linux/amd64 --load \
  -f validator_backends/energyplus/Dockerfile \
  --build-arg VALIDATOR_BACKEND_VERSION="$VERSION" \
  --build-arg VALIDATOR_BACKEND_REVISION="$(git rev-parse --short HEAD)" \
  --build-arg VALIDATOR_BACKEND_SLUG=energyplus \
  -t "validibot-validator-backend-energyplus:v$VERSION" \
  .
```

The supported just recipes always pass the version read from
`backends.toml`; they do not accept an environment override.

> [!IMPORTANT]
> **After updating dependencies (especially `validibot-shared`):**
>
> Docker caches build layers including pip install results. When you update a
> dependency version in `uv.lock`, a normal build may reuse cached layers with
> the old package version.
>
> To ensure the new version is installed, read the backend version from the
> inventory and pass the same required identity arguments as the supported
> recipes:
>
> ```bash
> VERSION="$(python3 scripts/backend_inventory.py field energyplus release_version)"
> docker buildx build --no-cache --load \
>   -f validator_backends/energyplus/Dockerfile \
>   --build-arg VALIDATOR_BACKEND_VERSION="$VERSION" \
>   --build-arg VALIDATOR_BACKEND_REVISION="$(git rev-parse --short HEAD)" \
>   --build-arg VALIDATOR_BACKEND_SLUG=energyplus \
>   -t "validibot-validator-backend-energyplus:v$VERSION" \
>   .
> ```
>
> Signs that cached layers are being used: build output shows `CACHED` for the pip install step, and your changes don't take effect at runtime.

### Running Tests

```bash
# Install dev dependencies
uv sync --extra dev --extra fmu

# Run all tests
just test

# Run tests for a specific validator
just test-validator energyplus
```

Normal development and CI use the exact published `validibot-shared` wheel
recorded in `uv.lock`, matching the package installed in every backend image.
When coordinating an unreleased shared-contract change, opt into the sibling
checkout for the specific test command instead of committing a path source:

```bash
uv run --with-editable ../validibot-shared \
  --extra dev --extra fmu --extra shacl --extra schematron \
  --extra portfolio_manager --extra pdf pytest
```

## Deployment Modes

Validator backends support two deployment modes:

### Self-Hosted (Docker)

For self-hosted Validibot deployments, validator backends run as local Docker containers:

```bash
# Build the container
just build energyplus

# The image will be available as:
# validibot-validator-backend-energyplus:latest
```

The core platform's Celery worker manages container lifecycle:

```
Django Worker → Docker API → Validator Backend Container → Local Storage
     ↑                                                    │
     └────────────── Reads output.json ───────────────────┘
```

**Characteristics:**

- Synchronous execution (worker blocks until container exits)
- Local filesystem storage (`file://` URIs)
- No callback needed — worker reads results directly

### Cloud Deployment (Container Registry)

For cloud deployments, validator backends can run as one-shot jobs or as a
bounded HTTP Service that launches the same one-shot entrypoint in a fresh
child. Hosted GCP uses release-specific Cloud Run Services as the primary route
and retains Cloud Run Jobs for long-running work and rollback.

```bash
# Set your GCP project (see "Container Registry Setup" below)
export VALIDIBOT_GCP_PROJECT="your-project-id"

# Build and push to your container registry
just build-push energyplus

# Development Cloud Run Job only
just deploy energyplus dev
```

```
Application task → Validibot worker → deterministic provider task
                                      ├─→ private Cloud Run Service (primary)
                                      └─→ retained Cloud Run Job (long budget)
                                                  │
                                verified output + callback
```

**Characteristics:**

- Asynchronous execution with an immutable deployment selected before dispatch
- Cloud storage (`gs://` URIs for GCP, `s3://` for AWS, etc.)
- Attempt-scoped credentials and an authenticated HTTP callback when complete

Production deployment is intentionally absent from this repository. Release
the backend here, then use the `validibot-project` repository's release
operator:

```bash
just validator-status
just validator-update energyplus
```

It verifies the backend-specific signed tag, release record, attestation,
equal GHCR/GAR digest, provider revision, and IAM policy; stages both execution
shapes; runs acceptance; and activates only that backend.

## Container Registry Setup

To build and push containerized validator backends, you need access to a container registry that Validibot can pull from at runtime.

### Supported Registries

- **Google Artifact Registry** (recommended for GCP deployments)
- **AWS Elastic Container Registry (ECR)**
- **Docker Hub**
- **GitHub Container Registry (ghcr.io)**
- **Self-hosted registries**

### Configuration (GCP Artifact Registry)

1. **Set environment variables** for your GCP project:

   ```bash
   # Add to your shell profile (~/.zshrc, ~/.bashrc, etc.)
   export VALIDIBOT_GCP_PROJECT="your-gcp-project-id"
   export VALIDIBOT_GCP_REGION="us-central1"  # optional, defaults to us-central1
   ```

2. **Authenticate** with your registry:

   ```bash
   # GCP Artifact Registry
   gcloud auth configure-docker us-central1-docker.pkg.dev
   ```

3. **Build and push:**

   ```bash
   just build-push energyplus
   ```

   Or pass the project inline:

   ```bash
   VALIDIBOT_GCP_PROJECT="my-project" just build-push energyplus
   ```

See [justfile.local.example](justfile.local.example) for more configuration options and alternative registry examples.

> [!IMPORTANT]
> Never commit registry credentials or project-specific configuration to the repository. Use environment variables or your shell profile for personal settings.

## Configuration

### Environment Variables

Validator backends receive configuration via environment variables:

| Variable                         | Required          | Description                                                                                                                                     |
| -------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `VALIDIBOT_INPUT_URI`            | Yes               | Storage URI to input envelope                                                                                                                   |
| `VALIDIBOT_OUTPUT_URI`           | No                | Storage URI for output (defaults to sibling of input)                                                                                           |
| `VALIDIBOT_RUN_ID`               | No                | Validation run ID (for logging)                                                                                                                 |
| `DEPLOYMENT_TARGET`              | No                | Selects the callback auth backend: `gcp`, `docker_compose`, `aws`, `local_docker_compose`, `test`. Set to `gcp` automatically by `just deploy`. |
| `TASK_OIDC_AUDIENCE`             | GCP only          | Override the OIDC audience. If unset, derived from the callback URL's origin (scheme + host). Needed when the worker is fronted by a load balancer that signs with a different audience. |
| `WORKER_API_KEY`                 | Docker / AWS only | Shared secret sent as `Authorization: Worker-Key …` on callbacks. Must match the Django-side `WORKER_API_KEY`.                                   |
| `VALIDIBOT_GCS_CAPABILITY_REQUIRED` | Launcher-managed GCP | Makes missing or incomplete attempt credentials fail closed instead of using ambient ADC. |
| `VALIDIBOT_GCS_ACCESS_TOKEN` | Launcher-managed GCP | Short-lived bearer token limited to one attempt prefix. Never log, persist, or configure this manually. |
| `VALIDIBOT_GCS_ACCESS_TOKEN_EXPIRY` | Launcher-managed GCP | RFC 3339 expiry inherited from the source access token. |
| `VALIDIBOT_GCS_ALLOWED_PREFIX` | Launcher-managed GCP | The only `gs://` prefix this execution may address. |
| `VALIDIBOT_GCS_PROJECT_ID` | Launcher-managed GCP | Project used to construct the explicit GCS client. |
| `VALIDIBOT_GCS_CAPABILITY_REFRESH_URL` | Launcher-managed GCP | Worker-only renewal endpoint; renewal requires the attempt callback nonce. |

### Callback Authentication

Validator backend containers POST completion callbacks back to the Django
worker service. The HTTP layer in `validator_backends/core/callback_client.py`
is deployment-target agnostic — authentication headers are produced
by a pluggable backend in `validator_backends/core/callback_auth.py`:

| Deployment | Backend                     | Header sent                                                                   |
| ---------- | --------------------------- | ----------------------------------------------------------------------------- |
| **GCP**    | `GCPCallbackAuth`           | `Authorization: Bearer <google-signed OIDC id token>` fetched from the metadata server. Audience is the **callback URL's origin** (scheme+host, **no path**) to match how Cloud Tasks / Cloud Scheduler sign tokens. |
| **Docker Compose / AWS** | `SharedSecretCallbackAuth` | `Authorization: Worker-Key <WORKER_API_KEY>` (matches Django's `WorkerKeyAuthentication`). |
| **Local / test**         | `NullCallbackAuth`          | No header (Django's matching target skips the auth check).                     |

The factory (`get_callback_auth()`) reads `DEPLOYMENT_TARGET` at
startup and caches the backend for the container's lifetime, so the
google-auth transport's connection pool is reused across callbacks.

Transport authentication identifies the calling runtime. Independently, the
`validibot.attempt.v2` envelope binds each notification to one execution
attempt: Django places a fresh `callback_nonce` and its public commitment in
the input context, and the validator returns the raw nonce with `callback_id`
in the callback payload. The nonce is never logged or written to the result
envelope, and canonical input hashing replaces it with its commitment.

### Storage URIs

Validator backends support two storage backends:

```
# Google Cloud Storage (GCP deployments)
gs://my-bucket/runs/org-123/run-456/input.json

# Local filesystem (self-hosted deployments)
file:///app/storage/private/runs/org-123/run-456/input.json
```

### Django Configuration

Configure the core platform to use Docker-based validator backends:

```python
# settings/local.py or settings/production.py
VALIDATOR_RUNNER = "docker"
VALIDATOR_RUNNER_OPTIONS = {
    "memory_limit": "4g",
    "cpu_limit": "2.0",
    "timeout_seconds": 3600,
    "network_mode": "none",  # Network isolation
}
```

## Directory Structure

```
validibot-validator-backends/
├── justfile                   # Build/deploy commands
├── pyproject.toml            # Python project config
└── validator_backends/
    ├── core/                 # Shared utilities
    │   ├── storage_client.py     # Storage I/O (gs:// and file://)
    │   ├── callback_client.py    # HTTP callback transport (retry, timeout)
    │   ├── callback_auth.py      # Deployment-target-aware auth backends
    │   └── envelope_loader.py    # Envelope serialization
    │
    ├── energyplus/           # EnergyPlus validator
    ├── fmu/                  # FMU validator
    ├── shacl/                # SHACL validator
    ├── schematron/           # Schematron validator
    └── portfolio_manager/    # Building benchmark report validator
```

## Creating a Custom Validator Backend

You can create custom validator backends for domain-specific validation needs.

### 1. Create Validator Directory

```bash
cp -r validator_backends/energyplus validator_backends/myvalidator
```

### 2. Define Metadata

Edit `validator_backends/myvalidator/__metadata__.py`:

```python
# Note: the backend image version lives in this backend's
# ``backends.toml`` release_version. Don't redeclare it here.

METADATA = {
    "validator_type": "MYVALIDATOR",
    "validator_name": "My Custom Validator",
    "image_name": "validibot-validator-backend-myvalidator",
    "supported_input_types": ["application/json"],
    "resource_requirements": {
        "memory": "2g",
        "cpu": "1.0",
        "timeout_seconds": 600,
    },
}


def get_metadata():
    return METADATA
```

### 3. Register the Backend Version

Add one entry to `backends.toml`. This inventory entry—not the Dockerfile—is
the version authority:

```toml
[[backend]]
slug = "myvalidator"
provider_resource_slug = "myvalidator"
release_version = "0.1.0"
# Add the remaining paths and runtime fields by following an existing backend.
```

### 4. Accept the Version Build Argument in the Dockerfile

Edit `validator_backends/myvalidator/Dockerfile`:

```dockerfile
ARG VALIDATOR_BACKEND_VERSION
ARG VALIDATOR_BACKEND_REVISION="unknown"
ARG VALIDATOR_BACKEND_SOURCE="https://github.com/your-org/your-validator-backends"
ARG VALIDATOR_BACKEND_SLUG="myvalidator"

LABEL org.opencontainers.image.title="My Custom Validator backend" \
      org.opencontainers.image.version="${VALIDATOR_BACKEND_VERSION}" \
      org.opencontainers.image.revision="${VALIDATOR_BACKEND_REVISION}" \
      org.opencontainers.image.source="${VALIDATOR_BACKEND_SOURCE}" \
      io.validibot.validator-backend.slug="${VALIDATOR_BACKEND_SLUG}"
```

The build reads `0.1.0` (or the later version) from `backends.toml` and stamps
it onto the resulting image as an OCI label, where `docker inspect` and the
`just self-hosted validators` operator inventory recipe can read it back.

### 5. Create Typed Envelopes

In [validibot-shared](https://github.com/mcquilleninteractive/validibot-shared), define your typed envelopes:

```python
# validibot_shared/myvalidator/envelopes.py
from pydantic import BaseModel
from validibot_shared.validations.envelopes import (
    ValidationInputEnvelope,
    ValidationOutputEnvelope,
)


class MyValidatorInputs(BaseModel):
    strict_mode: bool = False
    max_errors: int = 100


class MyValidatorOutputs(BaseModel):
    items_checked: int
    items_passed: int


class MyValidatorInputEnvelope(ValidationInputEnvelope):
    inputs: MyValidatorInputs


class MyValidatorOutputEnvelope(ValidationOutputEnvelope):
    outputs: MyValidatorOutputs | None = None
```

### 6. Implement Runner

Edit `validator_backends/myvalidator/runner.py`:

```python
from validibot_shared.myvalidator.envelopes import (
    MyValidatorInputEnvelope,
    MyValidatorOutputEnvelope,
    MyValidatorOutputs,
)
from validibot_shared.validations.envelopes import ValidationMessage, ValidationStatus


def run_validation(envelope: MyValidatorInputEnvelope) -> MyValidatorOutputEnvelope:
    messages = []
    items_checked = 0
    items_passed = 0

    # Your validation logic here
    for input_file in envelope.input_files:
        items_checked += 1
        # ... validate file ...
        if valid:
            items_passed += 1
        else:
            messages.append(
                ValidationMessage(
                    severity="error",
                    code="MY001",
                    text=f"Validation failed for {input_file.name}",
                )
            )

    status = ValidationStatus.SUCCESS if not messages else ValidationStatus.FAILURE

    return MyValidatorOutputEnvelope(
        run_id=envelope.run_id,
        validator=envelope.validator,
        status=status,
        messages=messages,
        outputs=MyValidatorOutputs(
            items_checked=items_checked,
            items_passed=items_passed,
        ),
    )
```

### 7. Update Dockerfile

Add the backend to `backends.toml` and the matching optional dependency group
to `pyproject.toml`, then generate its lock and application SBOM. Edit
`validator_backends/myvalidator/Dockerfile` to install only from that lock:

```dockerfile
FROM python:3.13-slim@sha256:<reviewed-multi-platform-index-digest>

WORKDIR /app
ENV PYTHONPATH=/app

# Install your domain-specific tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    your-tool \
    && rm -rf /var/lib/apt/lists/*

COPY validator_backends/myvalidator/requirements.lock /tmp/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes --no-deps \
        -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

RUN mkdir -p /app/legal
COPY LICENSE NOTICE /app/legal/
COPY validator_backends/myvalidator/legal/APPLICATION-SBOM.cdx.json \
    /app/legal/APPLICATION-SBOM.cdx.json
COPY legal/license-policy.toml scripts/generate_legal_artifacts.py /tmp/
RUN python /tmp/generate_legal_artifacts.py \
        --policy /tmp/license-policy.toml \
        --output-dir /app/legal \
        --component-name validibot-validator-backend-myvalidator \
        --component-version "${VALIDATOR_BACKEND_VERSION}"

# Create non-root user BEFORE copying code so --chown works.
# The core platform runs containers with user=1000:1000 and read_only=True,
# so files must be owned by UID 1000.
RUN groupadd --gid 1000 validibot \
    && useradd --uid 1000 --gid 1000 --no-create-home validibot

RUN mkdir -p /app/validator_backends/core /app/validator_backends/myvalidator \
    && chown -R validibot:validibot /app/validator_backends
COPY --chown=validibot:validibot validator_backends/__init__.py \
    /app/validator_backends/__init__.py
COPY --chown=validibot:validibot validator_backends/core/*.py \
    /app/validator_backends/core/
COPY --chown=validibot:validibot validator_backends/myvalidator/*.py \
    /app/validator_backends/myvalidator/

USER validibot

CMD ["python", "-m", "validator_backends.myvalidator.main"]
```

### 8. Build and Test

```bash
# Build your validator
just build myvalidator

# Run tests
just test-validator myvalidator
```

## Validator Contract

Every validator backend must follow this contract:

1. **Read input location** from `VALIDIBOT_INPUT_URI` environment variable
2. **Load input envelope** from storage using typed Pydantic model
3. **Download input files** from URIs in `input_envelope.input_files`
4. **Run validation** using configuration from `input_envelope.inputs`
5. **Create output envelope** with status, messages, metrics, artifacts
6. **Upload output envelope** to storage
7. **POST callback** (GCP mode only) or exit (self-hosted mode)

The `validator_backends.core` module provides helpers for steps 2, 5, 6, and 7.

### How It Fits Together

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              End Users                                       │
│                    (Web UI, CLI, REST API clients)                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         validibot (core platform)                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Web UI  │  REST API  │  Workflow Engine  │  Built-in Validators   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│            Triggers Docker containers for advanced validations              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
         ┌─────────────────────────────┼─────────────────────────────┐
         ▼                             ▼                             ▼
┌─────────────────┐    ┌────────────────────────────┐    ┌─────────────────────┐
│ validibot-cli   │    │ validibot-validator-       │    │ validibot-shared    │
│                 │    │   backends (this repo)     │    │                     │
│ Terminal access │    │                            │    │ Pydantic models     │
│ to API          │    │ EnergyPlus™, FMU           │    │ (shared contract)   │
│                 │    │ containers                 │    │                     │
└─────────────────┘    └────────────────────────────┘    └─────────────────────┘
```

## Development

```bash
# Clone the repository
git clone https://github.com/mcquilleninteractive/validibot-validator-backends.git
cd validibot-validator-backends

# Install dependencies
uv sync --extra dev --extra fmu

# Run linter
uv run ruff check .

# Run type checker
uv run mypy validator_backends/

# Run tests
uv run --extra fmu pytest
```

## Acknowledgments

These validators build on excellent open-source projects:

- [EnergyPlus](https://energyplus.net/) — Whole building energy simulation (U.S. Department of Energy / NREL, BSD-3-Clause)
- [FMPy](https://github.com/CATIA-Systems/FMPy) — FMU simulation in Python (Dassault Systèmes, BSD-3-Clause)

## Trademarks

EnergyPlus™ is a trademark of the U.S. Department of Energy. Validibot is not affiliated with, endorsed by, or sponsored by the U.S. Department of Energy or the National Renewable Energy Laboratory (NREL).

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

[Validibot Platform](https://github.com/mcquilleninteractive/validibot) •
[Documentation](https://docs.validibot.com) •
[Report Issues](https://github.com/mcquilleninteractive/validibot-validator-backends/issues)

</div>
