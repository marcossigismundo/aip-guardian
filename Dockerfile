# =============================================================================
# AIP Integrity Guardian — Multi-stage Docker build
# =============================================================================
# Stage 1: Build dependencies
# Stage 2: Minimal runtime image
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1 — Builder
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build-time system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy only the dependency specification first (Docker layer caching)
COPY pyproject.toml ./
COPY src/ ./src/

# Install Python packages into a virtualenv that we can copy later
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .


# ---------------------------------------------------------------------------
# Stage 2 — Runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

LABEL maintainer="dev@tainacan.org"
LABEL description="AIP Integrity Guardian — Continuous integrity verification for Archivematica AIPs"
LABEL org.opencontainers.image.source="https://github.com/tainacan/aip-guardian"

WORKDIR /app

# Install minimal runtime system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 guardian \
    && useradd --uid 1000 --gid 1000 --shell /bin/bash --create-home guardian

# Copy the virtualenv from the builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY src/ ./src/

# Set PYTHONPATH so guardian package is importable
ENV PYTHONPATH=/app/src
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Switch to non-root user
USER guardian

EXPOSE 8001

# Default command: run the ASGI server
CMD ["uvicorn", "guardian.main:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "4"]
