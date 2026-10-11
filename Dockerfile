# CPU service image. Runtime dependencies come from the checked-in uv.lock.
# Release operators must also pin the base/build-tool images to verified digests.
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.12.3 /uv /bin/uv
WORKDIR /build
ENV UV_PROJECT_ENVIRONMENT=/opt/agentscan UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md LICENSE CHANGELOG.md ./
COPY agentscan/ ./agentscan/
COPY rules/ai_rules.yaml ./rules/ai_rules.yaml
RUN uv sync --locked --no-dev --no-install-project --extra ui --extra api --extra telemetry
RUN uv build --wheel --no-sources --out-dir /dist && \
    uv pip install --python /opt/agentscan/bin/python --no-deps /dist/*.whl

FROM python:3.12-slim AS runner
LABEL org.opencontainers.image.title="AgentScan"
LABEL org.opencontainers.image.description="AI agent security assessment service"
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 shared-mime-info ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 10001 agentscan && \
    useradd -u 10001 -g agentscan -m -s /usr/sbin/nologin agentscan && \
    mkdir /workspace && chown agentscan:agentscan /workspace
COPY --from=builder /opt/agentscan /opt/agentscan
ENV PATH="/opt/agentscan/bin:$PATH" PYTHONUNBUFFERED=1
WORKDIR /workspace
USER 10001:10001
ENTRYPOINT ["agentscan"]
CMD ["--help"]
