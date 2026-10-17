# syntax=docker/dockerfile:1.7
# axis-runtime — the Python process model / run service (runtime/scripts/run_server.py) and the
# Eval Hub runner (runtime/scripts/eval_runner.py). Both are "process entry points (dev/e2e)": env- or
# file-configured, static tokens, in-memory stores unless a Postgres-backed audit/control-plane URL is
# given (see each script's own docstring). Browser-worker support (the `browser` extra, Playwright +
# Chromium) is NOT installed here: it is a separate concern (services the run service calls out to),
# not needed by the run service or eval runner themselves, and would roughly double image size.
# Build from the monorepo root as build context:
#   docker build -f runtime/Dockerfile -t axis/runtime:dev .
#
# Building behind a TLS-intercepting egress proxy (e.g. this repo's sandboxed dev environments):
# pass --build-context ciproxyca=<dir containing ca-bundle.crt> --build-arg CI_PROXY_CA_BASE=ciproxyca
# --network=host. Omit all three and this is a no-op (no cert is appended, SSL_CERT_FILE still
# points at the distro's own bundle). See docs/runbooks/local-cluster.md.
ARG CI_PROXY_CA_BASE=ca-empty
FROM scratch AS ca-empty
FROM ${CI_PROXY_CA_BASE} AS ca-src

FROM python:3.12-slim AS builder
COPY --from=ca-src ca-bundle.cr[t] /tmp/
RUN if [ -f /tmp/ca-bundle.crt ]; then cat /tmp/ca-bundle.crt >> /etc/ssl/certs/ca-certificates.crt; fi
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt
RUN pip install --no-cache-dir uv==0.8.17
WORKDIR /repo
COPY pyproject.toml uv.lock ./
COPY runtime/pyproject.toml runtime/pyproject.toml
COPY sdk/python/pyproject.toml sdk/python/pyproject.toml
COPY runtime/src runtime/src
COPY sdk/python/src sdk/python/src
RUN uv sync --frozen --no-dev --no-editable --package axis-runtime

FROM python:3.12-slim AS runtime
RUN groupadd -r axis && useradd -r -g axis axis
WORKDIR /app
COPY --from=builder --chown=axis:axis /repo/.venv /app/.venv
COPY --chown=axis:axis runtime/scripts /app/scripts
# load_process_model()'s default path assumes a monorepo checkout (packages/contracts/ next to runtime/);
# a wheel install breaks that, so the frozen process-model.json ships in the image and
# AXIS_PROCESS_MODEL_PATH points at it explicitly (runtime/src/axis_runtime/process.py).
COPY --chown=axis:axis packages/contracts/process-model.json /app/contracts/process-model.json
COPY --chown=axis:axis packages/contracts/schemas/ipc-envelope-v1.schema.json /app/contracts/ipc-envelope-v1.schema.json
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    AXIS_BIND_HOST=0.0.0.0 \
    AXIS_PROCESS_MODEL_PATH=/app/contracts/process-model.json \
    AXIS_IPC_SCHEMA_PATH=/app/contracts/ipc-envelope-v1.schema.json
USER axis
EXPOSE 8081
# Overridden per Deployment (run-server vs eval-runner) via the Helm chart's `args`.
ENTRYPOINT ["python"]
CMD ["scripts/run_server.py"]
