# syntax=docker/dockerfile:1
#
# Production image for the Next-Gen DevSecOps Automation Engine.
#
# Base: python:3.13-slim (Debian). Chosen over -alpine deliberately: pydantic-core
# ships manylinux wheels but its musllinux wheels lag, so an alpine build can fall
# back to a full Rust compile. glibc + slim is small once build deps are dropped
# and tracks the same CVE cadence for this dependency set. See Dockerfile.alpine
# for a musl variant.
#
# Multi-stage: the build toolchain never reaches the runtime layer.

########################  builder  ########################
FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY requirements.txt ./
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r requirements.txt

########################  runtime  ########################
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    DEVSECOPS_ENVIRONMENT=production \
    DEVSECOPS_LOG_JSON=true

# curl for the container HEALTHCHECK only; drop apt lists afterwards.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system app \
 && useradd --system --gid app --home-dir /app --shell /usr/sbin/nologin app

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=app:app main.py models.py scanner.py verification.py persistence.py llm.py index.html ./

# writable directory for the optional SQLite store (mounted as a volume in compose)
RUN mkdir -p /app/data && chown app:app /app/data

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/health || exit 1

ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
