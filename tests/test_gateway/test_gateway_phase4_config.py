from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agentscan.gateway.config import GatewaySettings


def settings(**changes: object) -> GatewaySettings:
    values: dict[str, object] = {
        "tenant": "tenant-a",
        "gateway_id": "gw-a",
        "chain_id": "chain/a",
        "writer_id": "writer-a",
        "audience": "agentscan",
        "trusted_issuer": "issuer-a",
        "listen_host": "127.0.0.1",
        "listen_port": 8765,
        "upstream_url": "http://127.0.0.1:9999",
        "upstream_server_id": "mock",
        "upstream_credential_env": "MOCK_TOKEN",
        "policy_bundle": "policy.yaml",
        "policy_public_key": "policy.pub",
        "trust_keys": "trust.json",
        "receipt_dir": "receipts",
    }
    values.update(changes)
    return GatewaySettings.model_validate(values)


def test_defaults_and_valid_minimal_configuration() -> None:
    value = settings()
    assert value.retention_days == 30
    assert value.session_idle_timeout_seconds == 900
    assert value.session_max_lifetime_seconds == 3600
    assert value.mode == "enforce"


@pytest.mark.parametrize(
    "field,value",
    [
        ("unknown", True),
        ("session_idle_timeout_seconds", 0),
        ("max_request_bytes", 0),
        ("max_argument_bytes", 0),
        ("max_total_argument_bytes", 0),
        ("deny_spike_threshold", 0),
        ("deny_spike_window_seconds", 0),
        ("pending_alert_seconds", 0),
        ("max_idempotency_key_bytes", 0),
        ("max_idempotency_key_bytes", 1025),
        ("clock_skew_seconds", 301),
        ("upstream_timeout_seconds", 0),
        ("session_max_lifetime_seconds", 900),
    ],
)
def test_invalid_limits_and_unknown_fields(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        settings(**{field: value})


@pytest.mark.parametrize(
    "changes",
    [
        {"max_argument_bytes": 100, "max_total_argument_bytes": 99},
        {"max_total_argument_bytes": 70000},
        {"max_argument_bytes": 40000},
    ],
)
def test_argument_limit_order(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        settings(**changes)


@pytest.mark.parametrize(
    "upstream",
    [
        "http://example.com:1234",
        "https://user:pass@example.com",
        "https://example.com?q=x",
        "https://example.com#frag",
    ],
)
def test_rejects_unsafe_upstream_url(upstream: str) -> None:
    with pytest.raises(ValidationError):
        settings(upstream_url=upstream)


@pytest.mark.parametrize(
    "changes",
    [
        {"allowed_hosts": ["*"]},
        {"allowed_hosts": ["example.com:9999"]},
        {"allowed_hosts": ["http://localhost:8765"]},
        {"allowed_origins": ["*"]},
        {"allowed_origins": ["http://localhost:8765/path"]},
        {"listen_host": "0.0.0.0"},
        {"tenant": "a/../b"},
        {"chain_id": "../chain"},
        {"receipt_dir": "a/../b"},
        {"policy_bundle": "../policy"},
        {"policy_public_key": "x/../key"},
        {"trust_keys": "../trust.json"},
        {"listen_port": True},
        {"max_request_bytes": True},
    ],
)
def test_rejects_unsafe_config_values(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        settings(**changes)


def test_absolute_paths_are_allowed(tmp_path: Path) -> None:
    assert settings(receipt_dir=str(tmp_path / "receipts")).receipt_dir == str(
        tmp_path / "receipts"
    )
