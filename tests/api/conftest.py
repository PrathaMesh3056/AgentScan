from __future__ import annotations

import json

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentscan.api import auth


@pytest.fixture(autouse=True)
def configured_api_auth(monkeypatch, tmp_path):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "test-signing.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.delenv("AGENTSCAN_JWT_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("AGENTSCAN_JWT_PRIVATE_KEY_FILE", str(path))
    monkeypatch.setenv(
        "AGENTSCAN_TENANT_CREDENTIALS_JSON",
        json.dumps({"tenant-a": "a" * 40, "tenant-b": "b" * 40}),
    )
    monkeypatch.setenv("AGENTSCAN_ALLOWED_TARGET_HOSTS", "agent.test,localhost,127.0.0.1")
    monkeypatch.setenv(
        "AGENTSCAN_TENANT_POLICIES_JSON",
        json.dumps(
            {
                "tenant-a": {
                    "origins": ["http://agent.test", "http://localhost", "http://127.0.0.1"],
                    "networks": ["127.0.0.1/32"],
                },
                "tenant-b": {"origins": ["http://localhost"], "networks": ["127.0.0.1/32"]},
            }
        ),
    )
    data_key = tmp_path / "service-data.key"
    data_key.write_bytes(Fernet.generate_key())
    monkeypatch.setenv("AGENTSCAN_DATA_KEY_FILE", str(data_key))
    monkeypatch.setattr(auth, "default_token_manager", None)
    monkeypatch.setattr(auth, "_tenant_credentials", {})
    auth.configure_auth()
    return key
