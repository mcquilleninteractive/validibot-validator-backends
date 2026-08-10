"""Strict request contract for private Cloud Run validator Services.

The request contains one durable attempt identity plus one transient,
attempt-scoped GCS capability.  Unknown fields are rejected so adding a new
piece of authority requires an explicit runtime and dispatcher change.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import UUID4, AwareDatetime, BaseModel, ConfigDict, Field, HttpUrl, SecretStr


class AttemptGCSCapability(BaseModel):
    """Short-lived bearer authority limited to one attempt storage prefix.

    Cloud Run validator Services must never reach storage through their attached
    service account, because that identity can see every attempt's data. Django
    instead mints a Credential Access Boundary token whose IAM condition pins it
    to a single attempt's object prefix, and ships it inside the request. The
    container treats this as its *only* route to storage: see
    ``core/gcs_capability.py``, which additionally re-checks the prefix locally
    before the Google client issues any request, so a mis-scoped token fails here
    rather than at the far end.

    The token in ``access_token`` is deliberately a ``SecretStr``. It must not
    reach a log line, and ``core/service_runtime.py`` redacts it from captured
    child output before logging.

    Fields:
        access_token: The downscoped OAuth bearer token. Sufficient on its own to
            read ``input.json`` and nothing outside ``allowed_prefix``.
        expires_at: Absolute expiry. The runtime rejects an already-expired
            capability without starting any compute, since the child could not
            finish its work anyway.
        allowed_prefix: The ``gs://bucket/…/`` prefix this token may touch. The
            pattern requires a trailing slash so that prefix comparison cannot
            match a sibling directory — without it, a prefix ending ``/attempt-1``
            would also authorize ``/attempt-10/``.
        project_id: GCP project for the storage client. Passed explicitly because
            the container has no ambient project configuration to fall back on.
        refresh_url: The worker endpoint that reissues this token. Renewal is not
            automatic — it requires the callback nonce carried in the input
            envelope, and the worker refuses it once the attempt has reached a
            terminal state. That is what stops a task delivered after
            cancellation from continuing to do work.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    access_token: Annotated[SecretStr, Field(min_length=1)]
    expires_at: AwareDatetime
    allowed_prefix: Annotated[str, Field(pattern=r"^gs://[^/]+/.+/$", max_length=2048)]
    project_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")]
    refresh_url: HttpUrl


class ServiceExecutionRequest(BaseModel):
    """One authenticated provider-task delivery for a pinned deployment.

    This is the wire contract between Django and a Cloud Run validator Service —
    the body POSTed to ``/v1/execute``. Django builds it in
    ``validibot/validations/services/execution/gcp_service_dispatch.py``; adding
    or renaming a field here is a two-repo change, and ``extra="forbid"`` is what
    makes that mandatory rather than optional. A new piece of authority cannot be
    smuggled in as an unrecognised key.

    **Most of these fields exist to be checked, not to be used.** Cloud Tasks
    guarantees delivery but not that the request describes the container now
    receiving it: a queue can hold a task across a redeploy, so a delivery
    written for one revision can arrive at another. ``_validated_child_timeout``
    in ``core/service_runtime.py`` therefore rejects the request unless
    ``service_name``, ``service_revision``, and ``backend_image_digest`` match the
    running container's own environment. The container refuses to run work that
    was authorized for a different build of itself.

    **Deterministic redelivery.** ``attempt_id`` is the ``ExecutionAttempt``
    primary key *and* the Cloud Tasks task ID. Retries at any layer converge on a
    single provider delivery identity rather than fanning out into duplicate
    runs.

    **The timeout ladder.** Three deadlines nest, widest last:

    - ``domain_timeout_seconds`` — how long the validator's own work may take.
      Capped at 1500 (``CLOUD_RUN_SERVICE_MAXIMUM_DOMAIN_SECONDS`` in the
      community repo, enforced there at deployment-validation time; the ``le=1500``
      here is the second line of defence).
    - The Cloud Run request timeout, which must exceed the domain budget and stay
      under 1650 seconds, leaving room for the callback.
    - The Cloud Tasks dispatch deadline, fixed at 1800 seconds.

    The runtime does not simply use ``domain_timeout_seconds``. It takes the
    lesser of that budget and the time actually remaining until ``timeout_at``,
    minus a 90-second callback margin — so a task that sat in the queue gets less
    compute, and the child is always killed early enough to report its result.
    An attempt whose remaining time cannot cover both is acknowledged without
    running anything.

    Fields:
        schema_version: Pinned to 1. A future revision changes this literal, so
            an old container rejects a new payload outright instead of
            misreading it.
        attempt_id: The ``ExecutionAttempt`` UUID; doubles as the Cloud Tasks
            task ID (see deterministic redelivery above).
        deployment_id: The ``ValidatorExecutionDeployment`` this attempt is
            pinned to.
        deployment_revision: Must equal ``service_revision``. Django snapshots the
            deployment at dispatch time, and this is where the two views of
            "which revision" are reconciled.
        provider_resource_name: Canonical
            ``projects/{p}/locations/{r}/services/{s}``. Checked to end with
            ``/services/{service_name}``.
        provider_task_name: Full Cloud Tasks task name, compared against the
            ``X-CloudTasks-TaskName`` header so the body cannot claim an identity
            the transport disagrees with.
        service_name: Checked against the ``K_SERVICE`` env var set by Cloud Run.
        service_revision: Checked against ``K_REVISION``.
        backend_image_digest: Checked against ``VALIDIBOT_BACKEND_IMAGE_DIGEST``,
            baked into the image at build time. This is the strongest of the
            identity checks — it binds the request to exact bytes.
        input_uri: Location of the input envelope. Must sit inside
            ``gcs_capability.allowed_prefix``; a request pointing outside the
            capability it ships with is rejected rather than attempted.
        timeout_at: Absolute deadline for the whole attempt, from Django.
        domain_timeout_seconds: The validator's own compute budget (see ladder).
        gcs_capability: The attempt-scoped storage authority.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    schema_version: Literal[1]
    attempt_id: UUID4
    deployment_id: UUID4
    deployment_revision: Annotated[str, Field(min_length=1, max_length=128)]
    provider_resource_name: Annotated[str, Field(min_length=1, max_length=512)]
    provider_task_name: Annotated[str, Field(min_length=1, max_length=1024)]
    service_name: Annotated[
        str,
        Field(pattern=r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$"),
    ]
    service_revision: Annotated[str, Field(min_length=1, max_length=128)]
    backend_image_digest: Annotated[
        str,
        Field(pattern=r"^sha256:[0-9a-f]{64}$"),
    ]
    input_uri: Annotated[str, Field(pattern=r"^gs://[^/]+/.+\.json$", max_length=2048)]
    timeout_at: AwareDatetime
    domain_timeout_seconds: Annotated[int, Field(ge=1, le=1500)]
    gcs_capability: AttemptGCSCapability
