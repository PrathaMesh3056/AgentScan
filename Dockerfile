# Scan-only image: no PyTorch / transformers / sentence-transformers.
# Use Dockerfile.deep (or `pip install .`) when inputs.deep is true.

FROM python:3.12-slim-bookworm

WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY agentscan ./agentscan
COPY rules ./rules

RUN pip install --no-cache-dir \
        "pydantic>=2.0" \
        "httpx>=0.27" \
        "typer[all]>=0.12" \
        "rich>=13.0" \
        "pyyaml>=6.0" \
        "loguru>=0.7" \
        "jinja2>=3.1.6" \
        "python-dotenv>=1.2.2" \
        "networkx>=3.2" \
        "websockets>=14.0" \
    && pip install --no-cache-dir --no-deps .

WORKDIR /work
ENTRYPOINT ["agentscan"]
CMD ["--help"]
