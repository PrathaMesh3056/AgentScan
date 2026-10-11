"""Administrator-owned tenant target permissions and bounded service settings."""

from __future__ import annotations

import ipaddress
import json
import os

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentscan.api.contracts import allowed_target_hosts
from agentscan.core.egress import canonical_origin


class TenantPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    origins: list[str] = Field(min_length=1, max_length=100)
    networks: list[str] = Field(default_factory=list, max_length=100)
    max_active_scans: int = Field(default=5, ge=1, le=100)
    submissions_per_hour: int = Field(default=60, ge=1, le=10000)
    max_scan_seconds: int = Field(default=600, ge=5, le=3600)
    max_target_requests: int = Field(default=500, ge=1, le=10000)
    allow_local_model_analysis: bool = False
    allow_external_model_analysis: bool = False

    @field_validator("origins")
    @classmethod
    def normalize_origins(cls, values: list[str]) -> list[str]:
        from urllib.parse import urlsplit

        for value in values:
            parsed = urlsplit(value)
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError("Enroll origins (scheme, hostname and port), not URL paths.")
        return sorted({canonical_origin(value) for value in values})

    @field_validator("networks")
    @classmethod
    def normalize_networks(cls, values: list[str]) -> list[str]:
        networks = [ipaddress.ip_network(value, strict=True) for value in values]
        if any(network.prefixlen == 0 for network in networks):
            raise ValueError("Unrestricted network ranges are not allowed.")
        return sorted({str(network) for network in networks})


def tenant_policies() -> dict[str, TenantPolicy]:
    try:
        values = json.loads(os.environ.get("AGENTSCAN_TENANT_POLICIES_JSON", "{}"))
        if not isinstance(values, dict) or not values:
            raise ValueError("At least one tenant policy is required.")
        policies = {key: TenantPolicy.model_validate(value) for key, value in values.items()}
        enrolled = allowed_target_hosts()
        from urllib.parse import urlsplit

        if any(
            urlsplit(origin).hostname not in enrolled
            for p in policies.values()
            for origin in p.origins
        ):
            raise ValueError("Tenant origins must also be service-enrolled hosts.")
        return policies
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Configure valid AGENTSCAN_TENANT_POLICIES_JSON tenant permissions."
        ) from exc


def authorize_target(tenant_id: str, url: str) -> TenantPolicy:
    policy = tenant_policies().get(tenant_id)
    if policy is None or canonical_origin(url) not in policy.origins:
        raise PermissionError("Target origin is not authorized for this tenant.")
    return policy
