"""Validated job contracts used at both HTTP and worker trust boundaries."""

from __future__ import annotations

import os
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentscan.core.egress import canonical_origin
from agentscan.core.factuality import FactualityBaseline

ScanState = Literal["queued", "running", "completed", "inconclusive", "failed", "cancelled"]
TERMINAL_STATES = frozenset({"completed", "inconclusive", "failed", "cancelled"})


def allowed_target_hosts() -> frozenset[str]:
    """Exact administrator-enrolled hosts; private targets need explicit enrollment."""
    hosts = frozenset(
        host.strip().lower().rstrip(".")
        for host in os.environ.get("AGENTSCAN_ALLOWED_TARGET_HOSTS", "").split(",")
        if host.strip()
    )
    if not hosts or "*" in hosts:
        raise ValueError("Configure AGENTSCAN_ALLOWED_TARGET_HOSTS with exact enrolled hostnames.")
    return hosts


def validate_remote_target(url: str) -> str:
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    _ = parsed.port
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or "\\" in url
        or any(ord(char) <= 32 for char in url)
    ):
        raise ValueError("Remote scans require an HTTP(S) URL without credentials.")
    if hostname not in allowed_target_hosts():
        raise ValueError("Target hostname is not enrolled for this service.")
    canonical_origin(url)
    return url


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_url: str = Field(max_length=4096)
    scan_mode: Literal["SCAN", "EXPLOIT", "DEEP"] = "SCAN"
    system_prompt: str | None = Field(default=None, max_length=65536)
    indirect_adapter: Literal["document_v1"] | None = None
    factuality_baseline: FactualityBaseline | None = None
    framework: str = "auto"
    timeout: int = Field(default=30, ge=5, le=300)
    concurrency: int | None = Field(default=None, ge=1, le=50)
    headers: dict[str, str] = Field(default_factory=dict)
    analysis_mode: Literal["deterministic", "local", "external"] = "deterministic"
    data_classification: Literal["sensitive", "non_sensitive"] = "sensitive"

    @model_validator(mode="after")
    def sensitive_analysis_policy(self):
        if self.analysis_mode == "external" and self.data_classification != "non_sensitive":
            raise ValueError("External analysis is blocked for sensitive scans.")
        if self.factuality_baseline is not None and (
            self.factuality_baseline.target_url != self.target_url
            or self.scan_mode != "SCAN"
            or self.analysis_mode != "deterministic"
            or self.indirect_adapter is not None
        ):
            raise ValueError(
                "Approved-answer checks require their exact target URL, deterministic SCAN "
                "and no document adapter."
            )
        return self

    @field_validator("headers")
    @classmethod
    def safe_headers(cls, value: dict[str, str]) -> dict[str, str]:
        import re

        if len(value) > 32 or sum(len(k) + len(v) for k, v in value.items()) > 16384:
            raise ValueError("Target headers exceed the service size limit.")
        for name, content in value.items():
            if (
                not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or any(ord(char) < 32 or ord(char) == 127 for char in content)
                or name.lower()
                in {
                    "host",
                    "content-length",
                    "transfer-encoding",
                    "connection",
                    "proxy-authorization",
                }
                or name.lower().startswith("x-forwarded-")
            ):
                raise ValueError("Invalid or routing-sensitive target header.")
        return value

    @field_validator("target_url")
    @classmethod
    def enrolled_remote_url(cls, value: str) -> str:
        return validate_remote_target(value)


class ScanJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    target: ScanRequest | None = None
