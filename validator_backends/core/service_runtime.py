"""Bounded HTTP parent for private Cloud Run validator Services.

The parent validates transport/deployment identity and starts a fresh one-shot
Python child for every accepted request.  Transient bearer material is placed
only in that child's environment and disappears with it.  The parent never
loads the validator envelope, GCS client, callback client, or domain runner.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import suppress
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

from pydantic import ValidationError

from validator_backends.core.gcs_capability import (
    CAPABILITY_EXPIRY_ENV,
    CAPABILITY_PREFIX_ENV,
    CAPABILITY_PROJECT_ENV,
    CAPABILITY_REFRESH_URL_ENV,
    CAPABILITY_REQUIRED_ENV,
    CAPABILITY_TOKEN_ENV,
)
from validator_backends.core.scratch import ATTEMPT_SCRATCH_ROOT_ENV
from validator_backends.core.service_contract import ServiceExecutionRequest


logger = logging.getLogger(__name__)

MAX_REQUEST_BYTES = 32 * 1024
CALLBACK_MARGIN_SECONDS = 90
CHILD_TERMINATION_GRACE_SECONDS = 10
MAX_CHILD_LOG_BYTES = 1024 * 1024
CHILD_LOG_CHUNK_BYTES = 8192
SERVICE_SHAPE_ENV = "VALIDIBOT_EXECUTION_SHAPE"
BACKEND_IMAGE_DIGEST_ENV = "VALIDIBOT_BACKEND_IMAGE_DIGEST"


class ServiceRequestError(ValueError):
    """A provider delivery does not match this immutable Service revision."""


class ServiceRequestExpired(ServiceRequestError):
    """A valid delivery is too late to authorize any further compute."""


def _validated_child_timeout(
    request: ServiceExecutionRequest,
    *,
    cloud_task_name: str = "",
) -> int:
    """Validate runtime/provider identity and return the child hard deadline."""
    expected = {
        "service name": (os.getenv("K_SERVICE", ""), request.service_name),
        "service revision": (os.getenv("K_REVISION", ""), request.service_revision),
        "backend image digest": (
            os.getenv(BACKEND_IMAGE_DIGEST_ENV, ""),
            request.backend_image_digest,
        ),
    }
    mismatches = [label for label, (actual, wanted) in expected.items() if actual != wanted]
    if mismatches:
        raise ServiceRequestError(
            "Request does not match immutable runtime identity: " + ", ".join(mismatches)
        )
    if request.deployment_revision != request.service_revision:
        raise ServiceRequestError("Deployment revision does not match the Cloud Run revision.")
    if not request.provider_resource_name.endswith(f"/services/{request.service_name}"):
        raise ServiceRequestError("Provider resource does not match the Service name.")
    if not request.input_uri.startswith(request.gcs_capability.allowed_prefix):
        raise ServiceRequestError("Input URI is outside the attempt capability prefix.")
    if cloud_task_name and cloud_task_name not in {
        request.provider_task_name,
        request.provider_task_name.rsplit("/", 1)[-1],
    }:
        raise ServiceRequestError("Cloud Tasks identity does not match the request.")
    now = datetime.now(UTC)
    if request.gcs_capability.expires_at <= now:
        raise ServiceRequestExpired("Attempt storage capability is already expired.")
    remaining_seconds = int((request.timeout_at - now).total_seconds())
    child_timeout = min(
        request.domain_timeout_seconds,
        remaining_seconds - CALLBACK_MARGIN_SECONDS,
    )
    if child_timeout < 1:
        raise ServiceRequestExpired("Attempt deadline cannot fit execution and callback margin.")
    return child_timeout


def _child_environment(
    request: ServiceExecutionRequest,
    *,
    scratch_root: Path,
) -> dict[str, str]:
    """Build one transient child environment without mutating the parent."""
    environment = dict(os.environ)
    environment.update(
        {
            "VALIDIBOT_INPUT_URI": request.input_uri,
            CAPABILITY_REQUIRED_ENV: "true",
            CAPABILITY_TOKEN_ENV: request.gcs_capability.access_token.get_secret_value(),
            CAPABILITY_EXPIRY_ENV: request.gcs_capability.expires_at.isoformat(),
            CAPABILITY_PREFIX_ENV: request.gcs_capability.allowed_prefix,
            CAPABILITY_PROJECT_ENV: request.gcs_capability.project_id,
            CAPABILITY_REFRESH_URL_ENV: str(request.gcs_capability.refresh_url),
            ATTEMPT_SCRATCH_ROOT_ENV: str(scratch_root),
            "TMPDIR": str(scratch_root),
            "VALIDIBOT_VERIFY_ATTEMPT_ACTIVE": "true",
        }
    )
    return environment


def execute_service_request(
    request: ServiceExecutionRequest,
    *,
    backend_module: str,
    cloud_task_name: str = "",
) -> int:
    """Execute one request in a fresh child and enforce its hard deadline."""
    child_timeout = _validated_child_timeout(
        request,
        cloud_task_name=cloud_task_name,
    )
    scratch_root = Path(tempfile.mkdtemp(prefix=f"validibot-{request.attempt_id}-"))
    captured_output = bytearray()
    output_truncated = [False]
    child_started = time.monotonic()

    def _drain_child_output(stream) -> None:
        """Drain without backpressure while retaining at most the log budget."""
        while chunk := stream.read(CHILD_LOG_CHUNK_BYTES):
            remaining = MAX_CHILD_LOG_BYTES - len(captured_output)
            if remaining > 0:
                captured_output.extend(chunk[:remaining])
            if len(chunk) > remaining:
                output_truncated[0] = True

    try:
        process = subprocess.Popen(
            [sys.executable, "-m", backend_module],
            env=_child_environment(request, scratch_root=scratch_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if process.stdout is None:  # pragma: no cover - Popen contract guard
            raise RuntimeError("Validator child stdout pipe was not created.")
        log_thread = threading.Thread(
            target=_drain_child_output,
            args=(process.stdout,),
            daemon=True,
        )
        log_thread.start()
        try:
            return process.wait(timeout=child_timeout)
        except subprocess.TimeoutExpired:
            logger.warning("Validator child exceeded its hard execution deadline")
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=CHILD_TERMINATION_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            return 124
        finally:
            log_thread.join(timeout=CHILD_TERMINATION_GRACE_SECONDS)
            secret = request.gcs_capability.access_token.get_secret_value()
            safe_output = captured_output.decode("utf-8", errors="replace").replace(
                secret,
                "<redacted>",
            )
            for offset in range(0, len(safe_output), CHILD_LOG_CHUNK_BYTES):
                logger.info(
                    "validator child: %s",
                    safe_output[offset : offset + CHILD_LOG_CHUNK_BYTES],
                )
            if output_truncated[0]:
                logger.warning(
                    "Validator child log exceeded %d bytes and was truncated",
                    MAX_CHILD_LOG_BYTES,
                )
            logger.info(
                "validator child finished attempt=%s service=%s revision=%s duration_seconds=%.3f",
                request.attempt_id,
                request.service_name,
                request.service_revision,
                time.monotonic() - child_started,
            )
    finally:
        shutil.rmtree(scratch_root, ignore_errors=True)


class ValidatorServiceHandler(BaseHTTPRequestHandler):
    """Single-request HTTP adapter configured with one backend module.

    The entire HTTP surface of a validator Service is two routes:

    - ``GET /healthz`` — liveness only. Deliberately credential-free and
      deliberately says nothing about the container's state beyond "the parent
      process is answering", so an unauthenticated prober learns nothing.
    - ``POST /v1/execute`` — one ``ServiceExecutionRequest``, executed
      synchronously. The response is returned only after the child has finished,
      because Cloud Tasks uses the HTTP status to decide whether to retry.

    **Status codes are the retry protocol**, so each is chosen for what Cloud
    Tasks will do next rather than for REST tidiness:

    - ``400`` for malformed JSON, a schema violation, or a failed identity check.
      These will never succeed on retry, and Cloud Tasks stops.
    - ``204`` for an *expired* attempt. This is the interesting one: nothing ran,
      but the delivery is acknowledged as successfully handled, because retrying
      work whose deadline has already passed only burns quota. Expiry is a normal
      outcome, not an error, and is logged at info level.
    - ``500`` when the child failed or could not be started, inviting a retry.
    - ``200`` with ``{"accepted": true}`` when the child exited cleanly. Note that
      this reports *execution*, not validation success — a validator that found
      problems in the submission still exits 0 and reports its findings through
      the callback.

    ``backend_module`` is a class variable rather than an instance attribute
    because ``BaseHTTPRequestHandler`` constructs a fresh handler per request and
    offers no hook to pass one in. ``serve()`` sets it once at startup, and it is
    immutable for the process lifetime — each image serves exactly one validator.

    Request bodies are capped at 32 KiB before being read. The body carries only
    identifiers and one token; the submission itself is fetched from storage, so
    anything larger is malformed or hostile and is rejected without buffering.
    """

    backend_module: ClassVar[str]
    server_version = "ValidibotValidatorService/1"

    def do_GET(self) -> None:
        """Expose a credential-free liveness endpoint."""
        if self.path != "/healthz":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def do_POST(self) -> None:
        """Validate one provider task and synchronously wait for its child."""
        if self.path != "/v1/execute":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if self.headers.get_content_type() != "application/json":
            self.send_error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if content_length < 1 or content_length > MAX_REQUEST_BYTES:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        try:
            payload = json.loads(self.rfile.read(content_length))
            request = ServiceExecutionRequest.model_validate(payload)
            logger.info(
                "validator request accepted attempt=%s deployment=%s task=%s",
                request.attempt_id,
                request.deployment_id,
                request.provider_task_name.rsplit("/", 1)[-1],
            )
            exit_code = execute_service_request(
                request,
                backend_module=self.backend_module,
                cloud_task_name=self.headers.get("X-CloudTasks-TaskName", ""),
            )
        except ServiceRequestExpired:
            logger.info("Acknowledged expired validator Service request without compute")
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return
        except (json.JSONDecodeError, ValidationError, ServiceRequestError):
            logger.warning("Rejected invalid validator Service request")
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        except OSError:
            logger.exception("Failed to start validator child process")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if exit_code != 0:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        response = json.dumps({"accepted": True}).encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format: str, *args) -> None:
        """Emit bounded access metadata without request bodies or headers."""
        logger.info("validator service http: " + format, *args)


def serve(*, backend_module: str, port: int) -> None:
    """Run a deliberately single-threaded HTTP server for concurrency one."""
    ValidatorServiceHandler.backend_module = backend_module
    server = HTTPServer(("0.0.0.0", port), ValidatorServiceHandler)
    logger.info("Starting validator Service runtime on port %d", port)
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    """Parse the immutable backend module and start the HTTP parent."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend-module", required=True)
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    port = int(os.getenv("PORT", "8080"))
    serve(backend_module=args.backend_module, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
