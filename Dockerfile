# ── Production Multi-Stage Dockerfile for AgentScan ───────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install uv for fast wheel compilation
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy project specification and sources
COPY pyproject.toml README.md ./
COPY agentscan/ ./agentscan/
COPY rules/ ./rules/

# Build standalone wheel
RUN uv build --wheel --out-dir /dist

# ── Final Runtime Image ───────────────────────────────────────────────────────
FROM python:3.12-slim AS runner

LABEL maintainer="AgentScan Team <author@agentscan.dev>"
LABEL org.opencontainers.image.title="AgentScan"
LABEL org.opencontainers.image.description="Open-source security scanner and red-teaming tool for AI agents"

# Install system runtime dependencies for report generation (WeasyPrint / Pango)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libharfbuzz0b \
    libpangoft2-1.0-0 \
    libffi-dev \
    shared-mime-info \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create secure non-root user
RUN groupadd -g 10001 agentscan && \
    useradd -u 10001 -g agentscan -m -s /bin/bash agentscan

WORKDIR /workspace

# Install wheel from builder stage
COPY --from=builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl[ui] && rm -rf /tmp/*.whl

USER agentscan

ENTRYPOINT ["agentscan"]
CMD ["--help"]
