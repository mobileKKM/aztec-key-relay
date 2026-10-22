# ── Stage 1: build dependencies ──────────────────────────────────────────────
FROM python:3.14-slim AS builder

ENV UV_VERSION=0.11.19

RUN pip install --no-cache-dir uv==${UV_VERSION}

WORKDIR /app

COPY pyproject.toml uv.lock ./

RUN uv sync --frozen --no-dev --no-install-project

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.14-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv

COPY aztec_key_relay/ ./aztec_key_relay/

# Healthcheck probe — /health returns 200 as soon as the ASGI app answers.
# curl stays out of the image: python is already there and sufficient.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]

# state.db (cached key + Firebase installation) lives here — mount a volume.
RUN mkdir -p /app/data && chown 1000:1000 /app/data
VOLUME /app/data
USER 1000:1000
EXPOSE 8000

# --no-access-log: the relay keeps no record of which client asked for the
# key, or when (privacy is the point of this service). App logs still cover
# refreshes and errors. --no-server-header: don't advertise uvicorn.
CMD ["uvicorn", "aztec_key_relay.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-server-header"]
