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

# state.db (cached key + Firebase installation) lives here — mount a volume.
RUN mkdir -p /app/data
VOLUME /app/data

EXPOSE 8000

CMD ["uvicorn", "aztec_key_relay.main:app", "--host", "0.0.0.0", "--port", "8000"]
