# Multi-stage hardened build for Bayora Secure AI Evaluation Infrastructure
# Enforces non-root user (UID 10001), read-only rootfs compatibility, and dropped Linux capabilities.

FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
COPY requirements.txt . 2>/dev/null || true
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir fastapi uvicorn cryptography pydantic pytest httpx

# Final Hardened Runtime Stage
FROM python:3.12-slim-bookworm AS runtime

LABEL maintainer="Bayora Security Engineering"
LABEL security.enforced="non-root,read-only-rootfs,no-docker-socket,seccomp"

# Create unprivileged service user and group (UID/GID 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

# Copy installed site-packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

WORKDIR /app

# Copy application files
COPY --chown=appuser:appgroup backend /app/backend
COPY --chown=appuser:appgroup frontend /app/frontend
COPY --chown=appuser:appgroup run.py /app/run.py

# Create writable tmpfs-backed directories for scratch data
RUN mkdir -p /app/backend/data/workspaces /app/backend/data/audit /app/backend/data/keys /app/backend/data/canaries /app/backend/data/checkpoints && \
    chown -R appuser:appgroup /app/backend/data

# Security Constraints:
# 1. Switch to unprivileged user
USER appuser:appgroup

# 2. Expose internal port only
EXPOSE 8000

# 3. Environment settings
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BAYORA_HOST="0.0.0.0" \
    BAYORA_PORT="8000"

# 4. Standard container healthcheck
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

ENTRYPOINT ["python", "run.py"]
