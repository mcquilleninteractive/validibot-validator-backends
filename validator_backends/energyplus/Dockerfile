# Multi-stage build for EnergyPlus™ validator container
#
# EnergyPlus™ is a trademark of the U.S. Department of Energy.
# EnergyPlus is distributed under a BSD-3-Clause license by NREL.
# The EnergyPlus license is preserved at /opt/energyplus/ in the built image.
# See: https://github.com/NREL/EnergyPlus/blob/develop/LICENSE.txt
#
# Build context must be the repo root (not validator_backends/energyplus/)
# Build with: docker build -f validator_backends/energyplus/Dockerfile -t ... .

# =============================================================================
# Stage 1: Build EnergyPlus
# =============================================================================
# Builder image pinned to the reviewed Ubuntu 22.04 multi-platform index.
FROM ubuntu:22.04@sha256:3b06811b2afd352be909dd088a004166d665dc76d38b13eada33522a9d915c6f AS energyplus-builder

# Install only the tooling needed to retrieve and verify EnergyPlus.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Download the exact EnergyPlus 25.2.0 Ubuntu x86-64 release asset. The digest
# is published in the upstream v25.2.0 GitHub release metadata. Verification
# must succeed before any archive bytes are extracted into the trusted image
# filesystem.
RUN set -eux; \
    energyplus_version="25.2.0"; \
    energyplus_build_id="cf7368216c"; \
    archive_name="EnergyPlus-${energyplus_version}-${energyplus_build_id}-Linux-Ubuntu22.04-x86_64.tar.gz"; \
    archive_path="/tmp/${archive_name}"; \
    extracted_path="/tmp/${archive_name%.tar.gz}"; \
    expected_sha256="e454fecd0f40be2e7ad8b574722b58ef8b9adc15aadfa31716f1c70a93ced4da"; \
    wget --quiet --https-only --secure-protocol=TLSv1_2 \
        --output-document="${archive_path}" \
        "https://github.com/NatLabRockies/EnergyPlus/releases/download/v${energyplus_version}/${archive_name}"; \
    echo "${expected_sha256}  ${archive_path}" \
        | sha256sum --check --strict -; \
    tar -xzf "${archive_path}" -C /tmp; \
    mv "${extracted_path}" /opt/energyplus; \
    rm "${archive_path}"

# =============================================================================
# Stage 2: Runtime container
# =============================================================================
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

# Backend wrapper version. This is OUR backend's version — bump it when the
# wrapper code, image layout, or output semantics change. It is INTENTIONALLY
# decoupled from the bundled EnergyPlus binary's upstream version (currently
# 25.2.0, downloaded above) — the upstream library can stay pinned while we
# iterate on the wrapper, and vice versa.
#
# Every build passes the release_version read from backends.toml. Keeping no
# default here prevents the Dockerfile from becoming a second version authority.
ARG VALIDATOR_BACKEND_VERSION
ARG VALIDATOR_BACKEND_REVISION="unknown"
ARG VALIDATOR_BACKEND_SOURCE="https://github.com/mcquilleninteractive/validibot-validator-backends"
ARG VALIDATOR_BACKEND_SLUG="energyplus"

LABEL org.opencontainers.image.title="Validibot EnergyPlus validator backend" \
      org.opencontainers.image.version="${VALIDATOR_BACKEND_VERSION}" \
      org.opencontainers.image.revision="${VALIDATOR_BACKEND_REVISION}" \
      org.opencontainers.image.source="${VALIDATOR_BACKEND_SOURCE}" \
      io.validibot.validator-backend.slug="${VALIDATOR_BACKEND_SLUG}"

# Install runtime dependencies
# - libgomp1: OpenMP runtime for parallel processing
# - libx11-6, libxext6: X11 libs required by EnergyPlus binary
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    libx11-6 \
    libxext6 \
    && rm -rf /var/lib/apt/lists/*

# Copy EnergyPlus from builder stage (includes LICENSE.txt for BSD-3-Clause compliance)
COPY --from=energyplus-builder /opt/energyplus /opt/energyplus

# Add EnergyPlus to PATH
ENV PATH="/opt/energyplus:${PATH}"

# Set working directory
WORKDIR /app

# Add /app to PYTHONPATH so imports like "from validator_backends.core.x" work.
# We set PYTHONPATH=/app rather than /app:${PYTHONPATH} because the base
# image doesn't define PYTHONPATH; referencing the undefined var triggers
# BuildKit's UndefinedVar lint warning. The validator container needs
# nothing else on PYTHONPATH, so a fixed value is correct.
ENV PYTHONPATH=/app

# Copy requirements first (for layer caching)
COPY validator_backends/energyplus/requirements.lock /tmp/requirements.lock

# Install Python dependencies
RUN python -m pip install --no-cache-dir --require-hashes --no-deps \
        -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

RUN mkdir -p /app/legal
COPY LICENSE NOTICE /app/legal/
COPY validator_backends/energyplus/legal/APPLICATION-SBOM.cdx.json \
    /app/legal/APPLICATION-SBOM.cdx.json
COPY legal/license-policy.toml /tmp/license-policy.toml
COPY scripts/generate_legal_artifacts.py /tmp/generate_legal_artifacts.py
RUN python /tmp/generate_legal_artifacts.py \
        --policy /tmp/license-policy.toml \
        --output-dir /app/legal \
        --component-name "validibot-validator-backend-energyplus" \
        --component-version "${VALIDATOR_BACKEND_VERSION}" \
    && rm /tmp/license-policy.toml /tmp/generate_legal_artifacts.py

# Create non-root user for container execution
RUN groupadd --gid 1000 validibot \
    && useradd --uid 1000 --gid 1000 --no-create-home validibot

# Copy only the package marker, shared runtime, and this backend. The root
# .dockerignore excludes tests and caches inside these directories. Keeping
# unrelated backends out of the image prevents their fixtures and optional
# runtime material from becoming part of this release artifact.
RUN mkdir -p /app/validator_backends/core \
        /app/validator_backends/energyplus \
    && chown -R validibot:validibot /app/validator_backends
COPY --chown=validibot:validibot validator_backends/__init__.py \
    /app/validator_backends/__init__.py
COPY --chown=validibot:validibot validator_backends/core/*.py \
    /app/validator_backends/core/
COPY --chown=validibot:validibot validator_backends/energyplus/*.py \
    /app/validator_backends/energyplus/

# Create working directory for EnergyPlus runs (writable by validibot user)
# Note: when run with read_only=True + tmpfs on /tmp, this directory is
# recreated on the tmpfs mount, so ownership here is mainly for non-tmpfs usage.
RUN mkdir -p /tmp/energyplus_run && chown validibot:validibot /tmp/energyplus_run

USER validibot

# Run as a module so relative imports work correctly
CMD ["python", "-m", "validator_backends.core.entrypoint", "--backend-module", "validator_backends.energyplus.main"]
