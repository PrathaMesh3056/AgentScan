from __future__ import annotations

import base64
import hashlib
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as generate_rsa_key

from agentscan.gateway.canonical import canonical_json
from agentscan.gateway.policy import (
    MAX_BUNDLE_BYTES,
    PolicyError,
    evaluate_policy,
    load_policy_yaml,
    policy_key_id,
    redact_arguments,
    sign_policy,
    sign_policy_file,
    validate_policy,
    verify_policy_bundle,
    write_signed_policy_atomic,
)

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
ISSUED_AT = "2026-11-10T00:00:00Z"
EXPIRES_AT = "2026-12-10T00:00:00Z"


def _private_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture
def keys() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    return private, _public_pem(private)


def _rule(
    rule_id: str = "allow-support",
    decision: str = "allow",
    **conditions: Any,
) -> dict[str, Any]:
    return {"id": rule_id, **conditions, "decision": decision}


def _tool(
    *,
    risk: str = "high",
    enforcement: str = "inline",
    resource_tenant_enforced: str | None = "upstream",
    rules: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "server": "crm-mcp",
        "risk": risk,
        "enforcement": enforcement,
        "schema_hash": "sha256:" + "a" * 64,
        "rules": rules if rules is not None else [_rule("allow-support", principal_role="support")],
    }
    if resource_tenant_enforced is not None:
        result["resource_tenant_enforced"] = resource_tenant_enforced
    return result


def _policy(
    *,
    tools: Mapping[str, Any] | None = None,
    redaction: dict[str, Any] | None = None,
) -> dict[str, Any]:
    policy: dict[str, Any] = {
        "version": 1,
        "policy_id": "test-policy",
        "tenant": "tenant-demo",
        "default": "deny",
        "tools": dict(tools or {"delete_customer_record": _tool()}),
    }
    if redaction is not None:
        policy["redaction"] = redaction
    return policy


def _signed_raw_envelope(
    private: Ed25519PrivateKey,
    *,
    policy: Mapping[str, Any] | None = None,
    issued_at: Any = ISSUED_AT,
    expires_at: Any = EXPIRES_AT,
    tenant: str = "tenant-demo",
    extras: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "format": "agentscan-policy-bundle/v1",
        "bundle_id": "bundle-test",
        "tenant": tenant,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "key_id": policy_key_id(private.public_key()),
        "policy": dict(policy or _policy()),
    }
    envelope.update(extras or {})
    signature = private.sign(canonical_json(envelope))
    return {**envelope, "signature": "base64:" + base64.b64encode(signature).decode("ascii")}


def _resign(envelope: Mapping[str, Any], private: Ed25519PrivateKey) -> dict[str, Any]:
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    signature = private.sign(canonical_json(unsigned))
    return {**unsigned, "signature": "base64:" + base64.b64encode(signature).decode("ascii")}


def _yaml(value: Any) -> bytes:
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=False).encode("utf-8")


def _verify(envelope: Mapping[str, Any], public_pem: bytes, now: datetime = NOW):
    return verify_policy_bundle(_yaml(envelope), public_pem, now=now)


def test_signed_round_trip_and_hash_are_stable(keys: tuple[Ed25519PrivateKey, bytes]) -> None:
    private, public_pem = keys
    envelope = sign_policy(
        _policy(),
        _private_pem(private),
        bundle_id="bundle-test",
        tenant="tenant-demo",
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        now=NOW,
    )
    first = _verify(envelope, public_pem)
    second = verify_policy_bundle(_yaml(envelope), public_pem, now=NOW)
    expected_hash = (
        "sha256:"
        + hashlib.sha256(
            canonical_json({key: value for key, value in envelope.items() if key != "signature"})
        ).hexdigest()
    )
    assert first.policy_hash == second.policy_hash == expected_hash
    assert first.key_id == second.key_id == policy_key_id(private.public_key())
    assert first.policy.tools["delete_customer_record"].risk == "high"


@pytest.mark.parametrize("tamper", ["policy", "envelope"])
def test_tampering_fails_signature(keys: tuple[Ed25519PrivateKey, bytes], tamper: str) -> None:
    private, public_pem = keys
    envelope = _signed_raw_envelope(private)
    if tamper == "policy":
        envelope["policy"]["policy_id"] = "changed"
    else:
        envelope["bundle_id"] = "changed"
    with pytest.raises(PolicyError, match="signature verification"):
        _verify(envelope, public_pem)


def test_bad_signature_precedes_policy_regex_validation(
    keys: tuple[Ed25519PrivateKey, bytes],
) -> None:
    private, public_pem = keys
    invalid_policy = _policy(
        tools={
            "delete_customer_record": _tool(
                rules=[_rule(arguments={"customer_id": {"pattern": "["}})]
            )
        }
    )
    envelope = _signed_raw_envelope(private, policy=invalid_policy)
    signature = bytearray(base64.b64decode(envelope["signature"][7:]))
    signature[0] ^= 1
    envelope["signature"] = "base64:" + base64.b64encode(signature).decode("ascii")
    with pytest.raises(PolicyError, match="signature verification"):
        _verify(envelope, public_pem)


def test_invalid_regex_is_rejected_after_valid_signature(
    keys: tuple[Ed25519PrivateKey, bytes],
) -> None:
    private, public_pem = keys
    envelope = _signed_raw_envelope(
        private,
        policy=_policy(
            tools={
                "delete_customer_record": _tool(
                    rules=[_rule(arguments={"customer_id": {"pattern": "["}})]
                )
            }
        ),
    )
    with pytest.raises(PolicyError, match="pattern .* invalid"):
        _verify(envelope, public_pem)


@pytest.mark.parametrize(
    "signature", ["base64:%%", "base64:" + base64.b64encode(b"x" * 63).decode()]
)
def test_invalid_signature_encoding_or_length(
    keys: tuple[Ed25519PrivateKey, bytes], signature: str
) -> None:
    private, public_pem = keys
    envelope = _signed_raw_envelope(private)
    envelope["signature"] = signature
    expected = "strict base64" if signature == "base64:%%" else "64 bytes"
    with pytest.raises(PolicyError, match=expected):
        _verify(envelope, public_pem)


def test_wrong_key_and_key_id_mismatch_are_rejected(keys: tuple[Ed25519PrivateKey, bytes]) -> None:
    private, _ = keys
    envelope = _signed_raw_envelope(private)
    other = Ed25519PrivateKey.generate()
    with pytest.raises(PolicyError, match="key ID"):
        _verify(envelope, _public_pem(other))
    envelope["key_id"] = "ed25519:" + "0" * 64
    with pytest.raises(PolicyError, match="key ID"):
        _verify(envelope, _public_pem(private))


@pytest.mark.parametrize(
    ("issued_at", "expires_at", "message"),
    [
        ("2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z", "expired"),
        (None, EXPIRES_AT, "issued_at"),
        ("2026-11-10", EXPIRES_AT, "issued_at"),
        (ISSUED_AT, 123, "expires_at"),
        ("2026-11-10T00:00:00+02:00", EXPIRES_AT, "UTC"),
        ("2026-12-10T00:00:00Z", ISSUED_AT, "later than"),
        (ISSUED_AT, ISSUED_AT, "later than"),
    ],
)
def test_timestamps_are_strict_utc_and_unexpired(
    keys: tuple[Ed25519PrivateKey, bytes],
    issued_at: Any,
    expires_at: Any,
    message: str,
) -> None:
    private, public_pem = keys
    envelope = _signed_raw_envelope(private, issued_at=issued_at, expires_at=expires_at)
    with pytest.raises(PolicyError, match=message):
        _verify(envelope, public_pem)


def test_yaml_timestamp_is_kept_as_a_string() -> None:
    value = load_policy_yaml(b"issued_at: 2026-11-10T00:00:00Z\n")
    assert value["issued_at"] == "2026-11-10T00:00:00Z"
    assert isinstance(value["issued_at"], str)


def test_envelope_and_policy_tenant_must_match(keys: tuple[Ed25519PrivateKey, bytes]) -> None:
    private, public_pem = keys
    envelope = _signed_raw_envelope(private, tenant="tenant-other")
    with pytest.raises(PolicyError, match="tenant"):
        _verify(envelope, public_pem)
    with pytest.raises(PolicyError, match="tenant"):
        sign_policy(
            _policy(),
            _private_pem(private),
            bundle_id="bundle-test",
            tenant="tenant-other",
            issued_at=ISSUED_AT,
            expires_at=EXPIRES_AT,
            now=NOW,
        )


@pytest.mark.parametrize(
    "source",
    [
        b"format: a\nformat: b\n",
        b"policy:\n  version: 1\n  version: 1\n",
        b"policy:\n  tools:\n    t:\n      server: a\n      server: b\n",
        b"policy:\n  tools:\n    t:\n      rules:\n        - id: a\n          id: b\n",
        b"policy:\n  tools:\n    t:\n      rules:\n        - arguments:\n            customer_id:\n              pattern: a\n              pattern: b\n",
        b"1: number\n'1': string\n",
    ],
)
def test_duplicate_yaml_keys_are_rejected_at_every_depth(source: bytes) -> None:
    with pytest.raises(PolicyError):
        load_policy_yaml(source)


@pytest.mark.parametrize(
    "source",
    [
        b"value: &base one\n",
        b"value: &base one\nalias: *base\n",
        b"base: &base {a: one}\nmerged: {<<: *base}\n",
        b"merged: {<<: {a: one}}\n",
    ],
)
def test_yaml_anchors_aliases_and_merge_keys_are_rejected(source: bytes) -> None:
    with pytest.raises(PolicyError):
        load_policy_yaml(source)


def test_non_mapping_root_and_non_string_keys_are_rejected() -> None:
    with pytest.raises(PolicyError, match="root must be a mapping"):
        load_policy_yaml(b"- item\n")
    with pytest.raises(PolicyError, match="keys must be strings"):
        load_policy_yaml(b"1: value\n")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda p: p.update(extra=True), "unknown policy field"),
        (lambda p: p.update(version=2), "version must be 1"),
        (lambda p: p.update(default="allow"), "default must be"),
        (lambda p: p["tools"]["delete_customer_record"].update(extra=True), "unknown tool"),
        (
            lambda p: p["tools"]["delete_customer_record"]["rules"][0].update(extra=True),
            "unknown tool",
        ),
        (
            lambda p: p["tools"]["delete_customer_record"]["rules"][0].update(
                arguments={"customer_id": {"pattern": "x", "extra": 1}}
            ),
            "unknown argument pattern",
        ),
        (
            lambda p: p["tools"]["delete_customer_record"].update(schema_hash="sha256:ABC"),
            "schema_hash",
        ),
        (
            lambda p: p["tools"]["delete_customer_record"].update(enforcement="shadow"),
            "enforcement",
        ),
        (lambda p: p["tools"]["delete_customer_record"].update(enforcement="observe"), "high-risk"),
        (
            lambda p: p["tools"]["delete_customer_record"].update(
                resource_tenant_enforced="gateway"
            ),
            "high-risk",
        ),
        (
            lambda p: p["tools"]["delete_customer_record"].update(resource_tenant_enforced=None),
            "resource_tenant_enforced",
        ),
        (
            lambda p: p["tools"]["delete_customer_record"].pop("resource_tenant_enforced"),
            "high-risk",
        ),
        (
            lambda p: p["tools"]["delete_customer_record"].update(status_operation=" "),
            "status_operation",
        ),
        (
            lambda p: p["tools"]["delete_customer_record"].update(status_operation=None),
            "status_operation",
        ),
        (
            lambda p: p["tools"]["delete_customer_record"].update(
                risk="low", resource_tenant_enforced=None
            ),
            "resource_tenant_enforced",
        ),
        (
            lambda p: p["tools"]["delete_customer_record"]["rules"][0].update(principal_role=None),
            "principal_role",
        ),
        (
            lambda p: p["tools"]["delete_customer_record"]["rules"][0].update(tenant_match=None),
            "tenant_match",
        ),
        (lambda p: p["tools"]["delete_customer_record"].update(risk="critical"), "risk"),
        (lambda p: p["tools"]["delete_customer_record"].update(risk=[]), "risk"),
        (lambda p: p["tools"]["delete_customer_record"].update(enforcement=[]), "enforcement"),
        (
            lambda p: p["tools"]["delete_customer_record"].update(resource_tenant_enforced=[]),
            "resource_tenant_enforced",
        ),
        (
            lambda p: p["tools"]["delete_customer_record"]["rules"][0].update(decision=[]),
            "decision",
        ),
        (lambda p: p["tools"]["delete_customer_record"].update(rules=[]), "non-empty list"),
        (
            lambda p: p["tools"]["delete_customer_record"]["rules"][0].update(tenant_match=False),
            "cannot be false",
        ),
    ],
)
def test_policy_validation_rejects_invalid_structure(mutate, message: str) -> None:
    policy = _policy()
    mutate(policy)
    with pytest.raises(PolicyError, match=message):
        validate_policy(policy)


def test_unknown_fields_at_envelope_level_are_rejected_after_verification(
    keys: tuple[Ed25519PrivateKey, bytes],
) -> None:
    private, public_pem = keys
    envelope = _signed_raw_envelope(private, extras={"unknown": 1})
    with pytest.raises(PolicyError, match="unknown envelope field"):
        _verify(envelope, public_pem)


def test_wrong_format_and_missing_envelope_fields_are_rejected_after_verification(
    keys: tuple[Ed25519PrivateKey, bytes],
) -> None:
    private, public_pem = keys
    wrong_format = _signed_raw_envelope(private)
    wrong_format["format"] = "agentscan-policy-bundle/v2"
    with pytest.raises(PolicyError, match="format"):
        _verify(_resign(wrong_format, private), public_pem)

    missing_bundle_id = _signed_raw_envelope(private)
    missing_bundle_id.pop("bundle_id")
    with pytest.raises(PolicyError, match="bundle_id"):
        _verify(_resign(missing_bundle_id, private), public_pem)

    missing_issued_at = _signed_raw_envelope(private)
    missing_issued_at.pop("issued_at")
    with pytest.raises(PolicyError, match="issued_at"):
        _verify(_resign(missing_issued_at, private), public_pem)

    missing_expires_at = _signed_raw_envelope(private)
    missing_expires_at.pop("expires_at")
    with pytest.raises(PolicyError, match="expires_at"):
        _verify(_resign(missing_expires_at, private), public_pem)


def test_rule_ids_are_unique_per_tool_only() -> None:
    same_ids = _policy(
        tools={
            "first": _tool(risk="low", rules=[_rule("same")]),
            "second": _tool(risk="low", rules=[_rule("same")]),
        }
    )
    validate_policy(same_ids)
    duplicate = _policy(
        tools={
            "first": _tool(rules=[_rule("same"), _rule("same", "deny")]),
        }
    )
    with pytest.raises(PolicyError, match="duplicate rule id"):
        validate_policy(duplicate)


def test_regex_length_and_compile_errors_are_rejected() -> None:
    too_long = _policy(
        tools={"tool": _tool(rules=[_rule(arguments={"x": {"pattern": "x" * 257}})])}
    )
    invalid = _policy(tools={"tool": _tool(rules=[_rule(arguments={"x": {"pattern": "["}})])})
    with pytest.raises(PolicyError, match="exceeds 256"):
        validate_policy(too_long)
    with pytest.raises(PolicyError, match="pattern .* invalid"):
        validate_policy(invalid)


def test_rule_argument_shape_is_validated_without_schema_membership() -> None:
    policy = _policy(
        tools={
            "delete_customer_record": _tool(
                rules=[_rule(arguments={"future_catalog_field": {"pattern": "^x$"}})]
            )
        }
    )
    assert validate_policy(policy).tools["delete_customer_record"].rules[0].arguments


def test_policy_precedence_overlap_and_first_match() -> None:
    policy = validate_policy(
        _policy(
            tools={
                "tool": _tool(
                    rules=[
                        _rule("allow-first", "allow", arguments={"target": {"pattern": ".*"}}),
                        _rule("allow-second", "allow"),
                        _rule("approval-first", "require_approval"),
                        _rule("approval-second", "require_approval"),
                        _rule("deny-first", "deny"),
                        _rule("deny-second", "deny"),
                    ]
                )
            }
        )
    )
    denied = evaluate_policy(
        policy, "tool", role="support", tenant="tenant-demo", arguments={"target": "ok"}
    )
    assert (denied.decision, denied.rule_id, denied.reason) == (
        "deny",
        "deny-first",
        "explicit_deny",
    )

    approval_policy = validate_policy(
        _policy(
            tools={
                "tool": _tool(
                    rules=[
                        _rule("allow", "allow"),
                        _rule("approval-first", "require_approval"),
                        _rule("approval-second", "require_approval"),
                    ]
                )
            }
        )
    )
    approval = evaluate_policy(
        approval_policy, "tool", role="support", tenant="tenant-demo", arguments={}
    )
    assert (approval.decision, approval.rule_id, approval.reason) == (
        "require_approval",
        "approval-first",
        "approval_required",
    )

    allow_policy = validate_policy(
        _policy(
            tools={
                "tool": _tool(
                    rules=[
                        _rule("allow-first", "allow"),
                        _rule("allow-second", "allow"),
                    ]
                )
            }
        )
    )
    allow = evaluate_policy(
        allow_policy, "tool", role="support", tenant="tenant-demo", arguments={}
    )
    assert (allow.decision, allow.rule_id, allow.reason) == ("allow", "allow-first", "allow_rule")


def test_role_tenant_and_fullmatch_conditions_and_default_deny() -> None:
    policy = validate_policy(
        _policy(
            tools={
                "tool": _tool(
                    rules=[
                        _rule(
                            "specific",
                            principal_role="support",
                            tenant_match=True,
                            arguments={"customer_id": {"pattern": "cust-[0-9]{4}"}},
                        )
                    ]
                )
            }
        )
    )

    def call(
        role: str | None,
        tenant: str | None,
        arguments: Mapping[str, Any] | None = None,
    ):
        return evaluate_policy(
            policy,
            "tool",
            role=role,
            tenant=tenant,
            arguments=arguments or {},
        )

    assert (
        call(role="support", tenant="tenant-demo", arguments={"customer_id": "cust-1234"}).decision
        == "allow"
    )
    assert (
        call(role="intern", tenant="tenant-demo", arguments={"customer_id": "cust-1234"}).reason
        == "default_deny"
    )
    assert (
        call(role="support", tenant="other", arguments={"customer_id": "cust-1234"}).decision
        == "deny"
    )
    assert (
        call(
            role="support", tenant="tenant-demo", arguments={"customer_id": "x-cust-1234"}
        ).decision
        == "deny"
    )
    assert (
        call(role="support", tenant="tenant-demo", arguments={"customer_id": 1234}).decision
        == "deny"
    )
    assert call(role="support", tenant="tenant-demo").decision == "deny"


def test_resource_tenant_precheck_scope_and_unknown_tool_fail_closed() -> None:
    low_policy = validate_policy(
        _policy(tools={"tool": _tool(risk="low", resource_tenant_enforced="none")})
    )
    missing_scope = evaluate_policy(
        low_policy, "tool", role="support", tenant="tenant-demo", arguments={}, token_scope=[]
    )
    assert missing_scope.reason == "token_scope"
    unknown = evaluate_policy(
        low_policy, "unknown", role="support", tenant="tenant-demo", arguments={}
    )
    assert (unknown.decision, unknown.reason) == ("deny", "default_deny")

    # Construct a legacy/untrusted in-memory value to exercise the mandatory
    # fail-closed precheck independently of loader validation.
    unsafe = validate_policy(_policy(tools={"tool": _tool(risk="low")}))
    tool = unsafe.tools["tool"]
    from dataclasses import replace

    unsafe = replace(
        unsafe, tools={"tool": replace(tool, risk="high", resource_tenant_enforced="none")}
    )
    decision = evaluate_policy(unsafe, "tool", role="support", tenant="tenant-demo", arguments={})
    assert (decision.decision, decision.reason) == ("deny", "resource_tenant_unverified")


def test_redaction_defaults_configuration_and_max_length() -> None:
    defaults = validate_policy(_policy()).redaction
    assert defaults.redact_arguments == (
        "password",
        "token",
        "secret",
        "authorization",
        "cookie",
        "api_key",
    )
    assert defaults.max_value_length == 256
    custom = validate_policy(
        _policy(redaction={"redact_arguments": ["customer_name"], "max_value_length": 4})
    )
    result = redact_arguments(
        {
            "customer_name": "Alice",
            "note": "123456",
            "credential": "hidden",
            "nested": {"Token": "secret"},
        },
        custom.redaction,
    )
    assert result == {
        "customer_name": "[REDACTED]",
        "note": "1234",
        "credential": "[REDACTED]",
        "nested": {"Token": "[REDACTED]"},
    }
    for invalid in (
        {"redact_arguments": "token"},
        {"redact_arguments": ["token", 1]},
        {"max_value_length": True},
        {"max_value_length": 0},
        {"unknown": 1},
    ):
        with pytest.raises(PolicyError):
            validate_policy(_policy(redaction=invalid))
    null_redaction = _policy()
    null_redaction["redaction"] = None
    with pytest.raises(PolicyError, match="redaction must be a mapping"):
        validate_policy(null_redaction)


def test_public_private_and_non_ed25519_keys_are_rejected(
    keys: tuple[Ed25519PrivateKey, bytes],
) -> None:
    private, public_pem = keys
    envelope = _signed_raw_envelope(private)
    with pytest.raises(PolicyError, match="private key"):
        _verify(envelope, _private_pem(private))
    with pytest.raises(PolicyError, match="invalid public key"):
        _verify(envelope, b"not a public key")
    rsa_private = generate_rsa_key(public_exponent=65537, key_size=2048)
    rsa_public = rsa_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    rsa_private_pem = rsa_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(PolicyError, match="public key must be Ed25519"):
        _verify(envelope, rsa_public)
    with pytest.raises(PolicyError, match="private key must be Ed25519"):
        sign_policy(
            _policy(),
            rsa_private_pem,
            bundle_id="bundle-test",
            tenant="tenant-demo",
            issued_at=ISSUED_AT,
            expires_at=EXPIRES_AT,
            now=NOW,
        )
    assert public_pem


def test_bundle_and_signing_input_size_limit(
    tmp_path: Path, keys: tuple[Ed25519PrivateKey, bytes]
) -> None:
    _, public_pem = keys
    with pytest.raises(PolicyError, match="1 MiB"):
        load_policy_yaml(b" " * (MAX_BUNDLE_BYTES + 1))
    with pytest.raises(PolicyError, match="1 MiB"):
        verify_policy_bundle(b" " * (MAX_BUNDLE_BYTES + 1), public_pem, now=NOW)
    oversized_policy = tmp_path / "oversized-policy.yaml"
    oversized_policy.write_bytes(b"#" * (MAX_BUNDLE_BYTES + 1))
    with pytest.raises(PolicyError, match="1 MiB"):
        sign_policy_file(
            oversized_policy,
            tmp_path / "unused-private.pem",
            bundle_id="bundle-test",
            tenant="tenant-demo",
            issued_at=ISSUED_AT,
            expires_at=EXPIRES_AT,
            now=NOW,
            output_path=tmp_path / "out.yaml",
        )


def test_policy_key_rotation_old_and_new_bundles_verify_only_with_their_key() -> None:
    old_private = Ed25519PrivateKey.generate()
    new_private = Ed25519PrivateKey.generate()
    old_bundle = sign_policy(
        _policy(),
        _private_pem(old_private),
        bundle_id="old",
        tenant="tenant-demo",
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        now=NOW,
    )
    new_bundle = sign_policy(
        _policy(),
        _private_pem(new_private),
        bundle_id="new",
        tenant="tenant-demo",
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        now=NOW,
    )
    old_hash = _verify(old_bundle, _public_pem(old_private)).policy_hash
    assert _verify(old_bundle, _public_pem(old_private)).key_id == policy_key_id(
        old_private.public_key()
    )
    assert _verify(new_bundle, _public_pem(new_private)).key_id == policy_key_id(
        new_private.public_key()
    )
    assert _verify(old_bundle, _public_pem(old_private)).policy_hash == old_hash
    with pytest.raises(PolicyError, match="key ID"):
        _verify(new_bundle, _public_pem(old_private))
    with pytest.raises(PolicyError, match="key ID"):
        _verify(old_bundle, _public_pem(new_private))


def test_atomic_bundle_writer_replaces_target_without_temp_artifacts(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    envelope = sign_policy(
        _policy(),
        _private_pem(private),
        bundle_id="bundle",
        tenant="tenant-demo",
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        now=NOW,
    )
    target = tmp_path / "bundle.yaml"
    target.write_text("old content", encoding="utf-8")
    write_signed_policy_atomic(envelope, target)
    verified = verify_policy_bundle(target, _public_pem(private), now=NOW)
    assert verified.policy.policy_id == "test-policy"
    assert target.read_text(encoding="utf-8").startswith("format: agentscan-policy-bundle/v1")
    assert list(tmp_path.iterdir()) == [target]


def test_cli_sign_verify_round_trip_and_tenant_failure(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    policy_path = tmp_path / "policy.yaml"
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    bundle_path = tmp_path / "signed.yaml"
    policy_path.write_bytes(_yaml(_policy()))
    private_path.write_bytes(_private_pem(private))
    public_path.write_bytes(_public_pem(private))

    # The CLI always validates against the process clock, so its window must be live:
    # an absolute fixture date would start failing the moment that date passed.
    signed_at = datetime.now(UTC) - timedelta(minutes=5)
    issued_at = signed_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at = (signed_at + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

    command = [
        sys.executable,
        "-m",
        "agentscan.gateway",
        "policy",
        "sign",
        "--policy",
        str(policy_path),
        "--private-key",
        str(private_path),
        "--bundle-id",
        "cli-test",
        "--tenant",
        "tenant-demo",
        "--issued-at",
        issued_at,
        "--expires-at",
        expires_at,
        "--out",
        str(bundle_path),
    ]
    signed = subprocess.run(command, capture_output=True, text=True, check=False)
    assert signed.returncode == 0, signed.stderr
    assert "PRIVATE KEY" not in signed.stdout + signed.stderr
    assert private_path.read_text(encoding="utf-8") not in signed.stdout + signed.stderr
    verified = subprocess.run(
        [
            sys.executable,
            "-m",
            "agentscan.gateway",
            "policy",
            "verify",
            "--bundle",
            str(bundle_path),
            "--public-key",
            str(public_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    assert "policy_hash=sha256:" in verified.stdout
    assert "key_id=ed25519:" in verified.stdout
    assert private_path.read_text(encoding="utf-8") not in verified.stdout + verified.stderr
    assert list(tmp_path.glob(".signed.yaml.*.tmp")) == []

    mismatch = subprocess.run(
        [
            *command[: command.index("--tenant") + 1],
            "tenant-other",
            *command[command.index("--tenant") + 2 :],
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert mismatch.returncode != 0
    assert "tenant" in mismatch.stderr
