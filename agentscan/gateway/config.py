"""Gateway TOML configuration model skeleton."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class GatewaySettings(BaseModel):
    """Validated gateway settings; security-specific checks are added in later phases."""

    model_config = ConfigDict(extra="forbid")

    tenant: str = Field(min_length=1)
    gateway_id: str = Field(min_length=1)
    chain_id: str = Field(min_length=1)
    writer_id: str = Field(min_length=1)
    audience: str = Field(min_length=1)
    trusted_issuer: str = Field(min_length=1)
    listen_host: str = Field(min_length=1)
    listen_port: int = Field(gt=0, le=65535)
    upstream_url: str = Field(min_length=1)
    upstream_server_id: str = Field(min_length=1)
    upstream_credential_env: str = Field(min_length=1)
    policy_bundle: str = Field(min_length=1)
    policy_public_key: str = Field(min_length=1)
    trust_keys: str = Field(min_length=1)
    receipt_dir: str = Field(min_length=1)


class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gateway: GatewaySettings


def load_config(path: str | Path) -> GatewayConfig:
    """Load a TOML file and reject unknown fields."""
    with Path(path).open("rb") as stream:
        raw: dict[str, Any] = tomllib.load(stream)
    return GatewayConfig.model_validate(raw)
