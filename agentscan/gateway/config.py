"""Validated TOML configuration for the runtime gateway."""

from __future__ import annotations

import ipaddress
import re
import tomllib
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_PATH_FIELDS = ("receipt_dir", "policy_bundle", "policy_public_key", "trust_keys")
_CHAIN_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def _contains_parent_segment(value: str) -> bool:
    return ".." in re.split(r"[\\/]+", value)


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


class GatewaySettings(BaseModel):
    """Validated gateway settings with conservative runtime defaults."""

    model_config = ConfigDict(extra="forbid")

    tenant: str = Field(min_length=1)
    gateway_id: str = Field(min_length=1)
    chain_id: str = Field(min_length=1)
    writer_id: str = Field(min_length=1)
    audience: str = Field(min_length=1)
    trusted_issuer: str = Field(min_length=1)
    listen_host: str = Field(min_length=1)
    listen_port: int = Field(strict=True, gt=0, le=65535)
    upstream_url: str = Field(min_length=1)
    upstream_server_id: str = Field(min_length=1)
    upstream_credential_env: str = Field(min_length=1)
    policy_bundle: str = Field(min_length=1)
    policy_public_key: str = Field(min_length=1)
    trust_keys: str = Field(min_length=1)
    receipt_dir: str = Field(min_length=1)

    retention_days: int = Field(default=30, strict=True, gt=0)
    session_idle_timeout_seconds: int = Field(default=900, strict=True, gt=0)
    session_max_lifetime_seconds: int = Field(default=3600, strict=True, gt=0)
    max_request_bytes: int = Field(default=65536, strict=True, gt=0)
    max_argument_bytes: int = Field(default=8192, strict=True, gt=0)
    max_total_argument_bytes: int = Field(default=32768, strict=True, gt=0)
    max_idempotency_key_bytes: int = Field(default=256, strict=True, ge=1, le=1024)
    upstream_timeout_seconds: float = Field(default=5.0, strict=True, gt=0)
    clock_skew_seconds: int = Field(default=30, strict=True, ge=0, le=300)
    deny_spike_threshold: int = Field(default=10, strict=True, gt=0)
    deny_spike_window_seconds: int = Field(default=60, strict=True, gt=0)
    pending_alert_seconds: int = Field(default=60, strict=True, gt=0)
    mode: Literal["enforce", "shadow"] = "enforce"
    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1:8765", "localhost:8765"])
    allowed_origins: list[str] = Field(default_factory=lambda: ["http://127.0.0.1:8765"])
    tls_certfile: str = ""
    tls_keyfile: str = ""
    mtls_ca_file: str = ""

    @field_validator("tenant")
    @classmethod
    def validate_tenant(cls, value: str) -> str:
        if "/" in value or "\\" in value or ".." in value:
            raise ValueError("tenant contains an unsafe path component")
        return value

    @field_validator("chain_id")
    @classmethod
    def validate_chain_id(cls, value: str) -> str:
        if not _CHAIN_RE.fullmatch(value) or ".." in value:
            raise ValueError("chain_id contains invalid characters or traversal")
        return value

    @field_validator(*_PATH_FIELDS)
    @classmethod
    def validate_paths(cls, value: str) -> str:
        if _contains_parent_segment(value):
            raise ValueError("path must not contain a parent traversal segment")
        return value

    @field_validator("upstream_url")
    @classmethod
    def validate_upstream_url(cls, value: str) -> str:
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("upstream_url is invalid") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "upstream_url must be an HTTP(S) URL without credentials/query/fragment"
            )
        if parsed.scheme == "http" and not _is_loopback(hostname):
            raise ValueError("HTTP upstream_url is allowed only for loopback hosts")
        return value

    @field_validator("allowed_hosts")
    @classmethod
    def validate_allowed_hosts(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("allowed_hosts must be non-empty")
        for value in values:
            if not isinstance(value, str) or not value or "*" in value or "://" in value:
                raise ValueError("allowed_hosts entries must be concrete host:port values")
            try:
                parsed = urlsplit(f"//{value}")
                hostname = parsed.hostname
                port = parsed.port
            except ValueError as exc:
                raise ValueError("allowed_hosts entry is invalid") from exc
            if (
                hostname is None
                or port is None
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("allowed_hosts entries must not include schemes or paths")
        return values

    @field_validator("allowed_origins")
    @classmethod
    def validate_allowed_origins(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("allowed_origins must be non-empty")
        for value in values:
            if not isinstance(value, str) or "*" in value:
                raise ValueError("allowed_origins must be concrete origins")
            try:
                parsed = urlsplit(value)
                hostname = parsed.hostname
                _ = parsed.port
            except ValueError as exc:
                raise ValueError("allowed_origins entry is invalid") from exc
            if (
                parsed.scheme not in {"http", "https"}
                or hostname is None
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("allowed_origins entries must be HTTP(S) origins without paths")
        return values

    @model_validator(mode="after")
    def validate_relations(self) -> GatewaySettings:
        if self.session_max_lifetime_seconds <= self.session_idle_timeout_seconds:
            raise ValueError("session_max_lifetime_seconds must exceed idle timeout")
        if not self.max_argument_bytes <= self.max_total_argument_bytes <= self.max_request_bytes:
            raise ValueError("argument and request byte limits are inconsistent")
        for value in self.allowed_hosts:
            try:
                port = urlsplit(f"//{value}").port
            except ValueError as exc:
                raise ValueError("allowed_hosts entry is invalid") from exc
            if port != self.listen_port:
                raise ValueError("allowed_hosts entries must include listen_port")
        if not _is_loopback(self.listen_host) and (not self.tls_certfile or not self.tls_keyfile):
            raise ValueError("non-loopback listeners require both TLS certificate and key files")
        return self


class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gateway: GatewaySettings


def load_config(path: str | Path) -> GatewayConfig:
    """Load TOML configuration and reject unknown fields."""
    with Path(path).open("rb") as stream:
        raw: dict[str, Any] = tomllib.load(stream)
    return GatewayConfig.model_validate(raw)
