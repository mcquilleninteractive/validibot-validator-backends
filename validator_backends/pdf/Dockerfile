# Isolated low-compute backend for bounded inspection of untrusted PDF
# packages and their embedded or associated files.
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

# Every build passes this backend's release_version from backends.toml.
ARG VALIDATOR_BACKEND_VERSION
ARG VALIDATOR_BACKEND_REVISION="unknown"
ARG VALIDATOR_BACKEND_SOURCE="https://github.com/mcquilleninteractive/validibot-validator-backends"
ARG VALIDATOR_BACKEND_SLUG="pdf"

LABEL org.opencontainers.image.title="Validibot PDF package validator backend" \
      org.opencontainers.image.version="${VALIDATOR_BACKEND_VERSION}" \
      org.opencontainers.image.revision="${VALIDATOR_BACKEND_REVISION}" \
      org.opencontainers.image.source="${VALIDATOR_BACKEND_SOURCE}" \
      io.validibot.validator-backend.slug="${VALIDATOR_BACKEND_SLUG}"

WORKDIR /app
ENV PYTHONPATH=/app

COPY validator_backends/pdf/requirements.lock /tmp/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes --no-deps \
        -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

# Bundle first-party terms, the lock-derived application SBOM, and a generated
# report for the Python distributions actually installed in this image.
RUN mkdir -p /app/legal/native-libraries/qpdf-12.3.2
COPY LICENSE NOTICE /app/legal/
COPY validator_backends/pdf/legal/APPLICATION-SBOM.cdx.json \
    /app/legal/APPLICATION-SBOM.cdx.json
COPY legal/qpdf-12.3.2/LICENSE.txt \
    /app/legal/native-libraries/qpdf-12.3.2/LICENSE.txt
COPY legal/qpdf-12.3.2/NOTICE.md \
    /app/legal/native-libraries/qpdf-12.3.2/NOTICE.md
COPY legal/license-policy.toml /tmp/license-policy.toml
COPY scripts/generate_legal_artifacts.py /tmp/generate_legal_artifacts.py
RUN python /tmp/generate_legal_artifacts.py \
        --policy /tmp/license-policy.toml \
        --output-dir /app/legal \
        --component-name "validibot-validator-backend-pdf" \
        --component-version "${VALIDATOR_BACKEND_VERSION}" \
    && rm /tmp/license-policy.toml /tmp/generate_legal_artifacts.py

RUN groupadd --gid 1000 validibot \
    && useradd --uid 1000 --gid 1000 --no-create-home validibot

# Copy only the package marker, shared runtime, and PDF backend. Tests and
# caches are excluded by .dockerignore.
RUN mkdir -p /app/validator_backends/core /app/validator_backends/pdf \
    && chown -R validibot:validibot /app/validator_backends
COPY --chown=validibot:validibot validator_backends/__init__.py \
    /app/validator_backends/__init__.py
COPY --chown=validibot:validibot validator_backends/core/*.py \
    /app/validator_backends/core/
COPY --chown=validibot:validibot validator_backends/pdf/*.py \
    /app/validator_backends/pdf/

USER validibot
CMD ["python", "-m", "validator_backends.core.entrypoint", "--protect-process-secrets", "--backend-module", "validator_backends.pdf.main"]
