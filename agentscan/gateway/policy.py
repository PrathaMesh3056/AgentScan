"""Ed25519-signed gateway policy bundles and pure policy evaluation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, NoReturn, cast

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from yaml.events import AliasEvent

from agentscan.gateway.canonical import canonical_json

MAX_BUNDLE_BYTES = 1024 * 1024
_BUNDLE_FORMAT = "agentscan-policy-bundle/v1"
_MISSING = object()
_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_CREDENTIAL_ARGUMENTS = frozenset(
    {"password", "secret", "token", "authorization", "cookie", "api_key", "credential"}
)
_ENVELOPE_FIELDS = {
    "format",
    "bundle_id",
    "tenant",
    "issued_at",
    "expires_at",
    "key_id",
    "policy",
    "signature",
}
_POLICY_FIELDS = {"version", "policy_id", "tenant", "default", "redaction", "tools"}
_REDACTION_FIELDS = {"redact_arguments", "max_value_length"}
_TOOL_FIELDS = {
    "server",
    "risk",
    "enforcement",
    "resource_tenant_enforced",
    "schema_hash",
    "status_operation",
    "rules",
}
_RULE_FIELDS = {"id", "principal_role", "tenant_match", "arguments", "decision"}

PolicyActionName = Literal["allow", "deny", "require_approval"]


class PolicyError(ValueError):
    """Invalid policy material. Messages are safe for CLI display."""


class _BundleSafeLoader(yaml.SafeLoader):
    """SafeLoader variant rejecting aliases, anchors, timestamps, and bad keys."""

    yaml_implicit_resolvers = {
        first: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:timestamp"]
        for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def compose_node(self, parent: Any, index: Any) -> yaml.Node:
        if self.check_event(AliasEvent):
            raise PolicyError("YAML aliases are not allowed")
        event = self.peek_event()
        if getattr(event, "anchor", None) is not None:
            raise PolicyError("YAML anchors are not allowed")
        node = super().compose_node(parent, index)
        if node is None:
            raise PolicyError("unexpected end of YAML document")
        return node


class _BundleSafeDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:
        return True


def _construct_unique_mapping(
    loader: _BundleSafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[str, Any]:
    if not isinstance(node, yaml.MappingNode):
        raise PolicyError("expected a YAML mapping")
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise PolicyError("YAML merge keys are not allowed")
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str):
            raise PolicyError("YAML mapping keys must be strings")
        if key == "<<":
            raise PolicyError("YAML merge keys are not allowed")
        if key in result:
            raise PolicyError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_BundleSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


@dataclass(frozen=True, slots=True)
class RedactionConfig:
    redact_arguments: tuple[str, ...] = (
        "password",
        "token",
        "secret",
        "authorization",
        "cookie",
        "api_key",
    )
    max_value_length: int = 256


@dataclass(frozen=True, slots=True)
class ArgumentPattern:
    pattern: str
    compiled: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class PolicyRule:
    id: str
    decision: PolicyActionName
    principal_role: str | None
    tenant_match: bool | None
    arguments: Mapping[str, ArgumentPattern]


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    server: str
    risk: Literal["high", "low"]
    enforcement: Literal["inline", "observe"]
    resource_tenant_enforced: Literal["upstream", "gateway", "none"] | None
    schema_hash: str
    status_operation: str | None
    rules: tuple[PolicyRule, ...]


@dataclass(frozen=True, slots=True)
class Policy:
    version: Literal[1]
    policy_id: str
    tenant: str
    default: Literal["deny"]
    redaction: RedactionConfig
    tools: Mapping[str, ToolPolicy]


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    decision: PolicyActionName
    policy_id: str
    rule_id: str | None
    resource_tenant_enforced: str | None
    reason: Literal[
        "allow_rule",
        "explicit_deny",
        "approval_required",
        "default_deny",
        "resource_tenant_unverified",
        "token_scope",
    ]
    risk: Literal["high", "low"]
    enforcement: Literal["inline", "observe"]


@dataclass(frozen=True, slots=True)
class VerifiedPolicyBundle:
    envelope: Mapping[str, Any]
    policy: Policy
    policy_hash: str
    key_id: str


def _fail(message: str) -> NoReturn:
    raise PolicyError(message)


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{name} must be a mapping")
    if any(not isinstance(key, str) for key in value):
        _fail(f"{name} keys must be strings")
    return value


def _check_fields(value: Mapping[str, Any], allowed: set[str], name: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        _fail(f"unknown {name} field: {sorted(unknown)[0]}")


def _required_string(value: Mapping[str, Any], field: str, name: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item.strip():
        _fail(f"{name}.{field} must be a non-empty string")
    return item


def _parse_utc_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        _fail(f"{field} must be an ISO-8601 UTC string")
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except (TypeError, ValueError):
        _fail(f"{field} must be an ISO-8601 UTC string")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _fail(f"{field} must be an ISO-8601 UTC string")
    return parsed.astimezone(UTC)


def _now_utc(now: datetime | None) -> datetime:
    value = datetime.now(UTC) if now is None else now
    if value.tzinfo is None or value.utcoffset() is None:
        _fail("now must be timezone-aware")
    return value.astimezone(UTC)


def _read_limited(source: str | Path | bytes | bytearray, source_name: str) -> bytes:
    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    else:
        try:
            with Path(source).open("rb") as stream:
                data = stream.read(MAX_BUNDLE_BYTES + 1)
        except OSError as exc:
            raise PolicyError(f"cannot read {source_name}") from exc
    if len(data) > MAX_BUNDLE_BYTES:
        _fail(f"{source_name} exceeds the 1 MiB limit")
    return data


def _load_yaml_mapping(data: bytes, source_name: str) -> dict[str, Any]:
    try:
        value = yaml.load(data, Loader=_BundleSafeLoader)
    except PolicyError:
        raise
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid {source_name} YAML") from exc
    if not isinstance(value, dict):
        _fail(f"{source_name} root must be a mapping")
    return value


def load_policy_yaml(source: str | Path | bytes | bytearray) -> dict[str, Any]:
    """Read a policy or bundle YAML mapping with the hardened loader."""
    return _load_yaml_mapping(_read_limited(source, "YAML input"), "YAML input")


def _public_key_from_pem(pem: bytes | str) -> Ed25519PublicKey:
    raw_pem = pem.encode("utf-8") if isinstance(pem, str) else pem
    if b"PRIVATE KEY" in raw_pem:
        _fail("public key file must not contain a private key")
    try:
        key = serialization.load_pem_public_key(raw_pem)
    except (TypeError, ValueError) as exc:
        raise PolicyError("invalid public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        _fail("public key must be Ed25519")
    return key


def policy_key_id(public_key: Ed25519PublicKey | bytes | str) -> str:
    """Return the policy key ID derived from the raw Ed25519 public key."""
    key = (
        public_key if isinstance(public_key, Ed25519PublicKey) else _public_key_from_pem(public_key)
    )
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{hashlib.sha256(raw).hexdigest()}"


def _validate_redaction(value: Any) -> RedactionConfig:
    if value is _MISSING:
        return RedactionConfig()
    mapping = _require_mapping(value, "redaction")
    _check_fields(mapping, _REDACTION_FIELDS, "redaction")
    names = mapping.get("redact_arguments", list(RedactionConfig().redact_arguments))
    if not isinstance(names, list) or any(not isinstance(name, str) or not name for name in names):
        _fail("redaction.redact_arguments must be a list of non-empty strings")
    max_length = mapping.get("max_value_length", 256)
    if type(max_length) is not int or max_length < 1:
        _fail("redaction.max_value_length must be a positive integer")
    return RedactionConfig(tuple(names), max_length)


def validate_policy(value: Any) -> Policy:
    """Validate and construct a policy object from already trusted input."""
    policy = _require_mapping(value, "policy")
    _check_fields(policy, _POLICY_FIELDS, "policy")
    version = policy.get("version")
    if type(version) is not int or version != 1:
        _fail("policy.version must be 1")
    policy_id = _required_string(policy, "policy_id", "policy")
    tenant = _required_string(policy, "tenant", "policy")
    if policy.get("default") != "deny":
        _fail('policy.default must be "deny"')
    redaction = _validate_redaction(policy.get("redaction", _MISSING))

    raw_tools = _require_mapping(policy.get("tools"), "policy.tools")
    if not raw_tools:
        _fail("policy.tools must not be empty")
    tools: dict[str, ToolPolicy] = {}
    for tool_name, raw_tool in raw_tools.items():
        if not tool_name.strip():
            _fail("tool names must be non-empty strings")
        tool = _require_mapping(raw_tool, f"tool {tool_name}")
        _check_fields(tool, _TOOL_FIELDS, f"tool {tool_name}")
        server = _required_string(tool, "server", f"tool {tool_name}")
        risk = tool.get("risk")
        if not isinstance(risk, str) or risk not in {"high", "low"}:
            _fail(f"tool {tool_name}.risk must be high or low")
        enforcement = tool.get("enforcement")
        if not isinstance(enforcement, str) or enforcement not in {"inline", "observe"}:
            _fail(f"tool {tool_name}.enforcement must be inline or observe")
        resource_tenant = tool.get("resource_tenant_enforced")
        if "resource_tenant_enforced" in tool and (
            not isinstance(resource_tenant, str)
            or resource_tenant not in {"upstream", "gateway", "none"}
        ):
            _fail(f"tool {tool_name}.resource_tenant_enforced is invalid")
        if risk == "high" and (enforcement != "inline" or resource_tenant != "upstream"):
            _fail(
                f"high-risk tool {tool_name} requires inline enforcement and upstream tenant enforcement"
            )
        schema_hash = _required_string(tool, "schema_hash", f"tool {tool_name}")
        if not _SHA256_PATTERN.fullmatch(schema_hash):
            _fail(f"tool {tool_name}.schema_hash is invalid")
        status_operation = tool.get("status_operation")
        if "status_operation" in tool and (
            not isinstance(status_operation, str) or not status_operation.strip()
        ):
            _fail(f"tool {tool_name}.status_operation must be a non-empty string")

        raw_rules = tool.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            _fail(f"tool {tool_name}.rules must be a non-empty list")
        rules: list[PolicyRule] = []
        seen_rule_ids: set[str] = set()
        for index, raw_rule in enumerate(raw_rules):
            rule = _require_mapping(raw_rule, f"tool {tool_name} rule")
            _check_fields(rule, _RULE_FIELDS, f"tool {tool_name} rule")
            rule_id = _required_string(rule, "id", f"tool {tool_name} rule")
            if rule_id in seen_rule_ids:
                _fail(f"duplicate rule id in tool {tool_name}: {rule_id}")
            seen_rule_ids.add(rule_id)
            decision = rule.get("decision")
            if not isinstance(decision, str) or decision not in {
                "allow",
                "deny",
                "require_approval",
            }:
                _fail(f"tool {tool_name} rule {index} has an invalid decision")
            role = rule.get("principal_role")
            if "principal_role" in rule and (not isinstance(role, str) or not role.strip()):
                _fail(f"tool {tool_name} rule {rule_id}.principal_role must be a non-empty string")
            tenant_match = rule.get("tenant_match")
            if "tenant_match" in rule and type(tenant_match) is not bool:
                _fail(f"tool {tool_name} rule {rule_id}.tenant_match must be a boolean")
            if tenant_match is False:
                _fail(f"tool {tool_name} rule {rule_id}.tenant_match cannot be false")

            raw_arguments = rule.get("arguments", {})
            argument_map = _require_mapping(raw_arguments, f"tool {tool_name} rule arguments")
            arguments: dict[str, ArgumentPattern] = {}
            for argument_name, raw_pattern in argument_map.items():
                if not argument_name.strip():
                    _fail("argument names must be non-empty strings")
                pattern_map = _require_mapping(raw_pattern, f"argument pattern {argument_name}")
                _check_fields(pattern_map, {"pattern"}, f"argument pattern {argument_name}")
                pattern = pattern_map.get("pattern")
                if not isinstance(pattern, str):
                    _fail(f"argument pattern {argument_name}.pattern must be a string")
                if len(pattern) > 256:
                    _fail(f"argument pattern {argument_name}.pattern exceeds 256 characters")
                try:
                    compiled = re.compile(pattern)
                except re.error as exc:
                    raise PolicyError(f"argument pattern {argument_name} is invalid") from exc
                arguments[argument_name] = ArgumentPattern(pattern, compiled)
            rules.append(
                PolicyRule(
                    id=rule_id,
                    decision=cast(PolicyActionName, decision),
                    principal_role=role,
                    tenant_match=tenant_match,
                    arguments=arguments,
                )
            )

        tools[tool_name] = ToolPolicy(
            server=server,
            risk=cast(Literal["high", "low"], risk),
            enforcement=cast(Literal["inline", "observe"], enforcement),
            resource_tenant_enforced=cast(
                Literal["upstream", "gateway", "none"] | None,
                resource_tenant,
            ),
            schema_hash=schema_hash,
            status_operation=status_operation,
            rules=tuple(rules),
        )

    return Policy(
        version=1,
        policy_id=policy_id,
        tenant=tenant,
        default="deny",
        redaction=redaction,
        tools=tools,
    )


def _validate_timestamps(
    issued_at: Any, expires_at: Any, now: datetime | None
) -> tuple[datetime, datetime]:
    issued = _parse_utc_timestamp(issued_at, "issued_at")
    expires = _parse_utc_timestamp(expires_at, "expires_at")
    if expires <= issued:
        _fail("expires_at must be later than issued_at")
    if expires <= _now_utc(now):
        _fail("policy bundle has expired")
    return issued, expires


def _signature_input(envelope: Mapping[str, Any]) -> bytes:
    unsigned = dict(envelope)
    unsigned.pop("signature", None)
    try:
        return canonical_json(unsigned)
    except (TypeError, ValueError) as exc:
        raise PolicyError("bundle is not valid canonical JSON data") from exc


def sign_policy(
    policy_data: Mapping[str, Any],
    private_key_pem: bytes | str,
    *,
    bundle_id: str,
    tenant: str,
    issued_at: str,
    expires_at: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate and sign an unsigned policy object as a v1 YAML envelope.

    The default clock is the process clock, so callers cannot silently extend or
    ignore the validity window. Tests inject a fixed instant instead.
    """
    if not isinstance(bundle_id, str) or not bundle_id.strip():
        _fail("bundle_id must be a non-empty string")
    if not isinstance(tenant, str) or not tenant.strip():
        _fail("tenant must be a non-empty string")
    _validate_timestamps(issued_at, expires_at, now)
    parsed_policy = validate_policy(policy_data)
    if tenant != parsed_policy.tenant:
        _fail("envelope tenant must match policy tenant")
    raw_pem = (
        private_key_pem.encode("utf-8") if isinstance(private_key_pem, str) else private_key_pem
    )
    try:
        private_key = serialization.load_pem_private_key(raw_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise PolicyError("invalid private key") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        _fail("private key must be Ed25519")
    public_key = private_key.public_key()
    envelope: dict[str, Any] = {
        "format": _BUNDLE_FORMAT,
        "bundle_id": bundle_id,
        "tenant": tenant,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "key_id": policy_key_id(public_key),
        "policy": dict(policy_data),
    }
    signature_input = _signature_input(envelope)
    signature = private_key.sign(signature_input)
    envelope["signature"] = "base64:" + base64.b64encode(signature).decode("ascii")
    return envelope


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not value.startswith("base64:"):
        _fail("signature must use the base64: encoding")
    encoded = value[len("base64:") :]
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PolicyError("signature is not valid strict base64") from exc
    if len(decoded) != 64:
        _fail("Ed25519 signature must be exactly 64 bytes")
    return decoded


def verify_policy_bundle(
    bundle: str | Path | bytes | bytearray,
    public_key_pem: bytes | str,
    *,
    now: datetime | None = None,
) -> VerifiedPolicyBundle:
    """Verify bundle signature before validating or compiling any policy rule."""
    raw = _read_limited(bundle, "policy bundle")
    envelope = _load_yaml_mapping(raw, "policy bundle")
    signature = _decode_signature(envelope.get("signature"))
    public_key = _public_key_from_pem(public_key_pem)
    expected_key_id = policy_key_id(public_key)
    claimed_key_id = envelope.get("key_id")
    if not isinstance(claimed_key_id, str) or claimed_key_id != expected_key_id:
        _fail("policy key ID does not match the active public key")

    signature_input = _signature_input(envelope)
    try:
        public_key.verify(signature, signature_input)
    except InvalidSignature as exc:
        raise PolicyError("policy bundle signature verification failed") from exc

    # Policy construction (including regex compilation) happens only after the
    # exact signed bytes have been authenticated.
    _check_fields(envelope, _ENVELOPE_FIELDS, "envelope")
    if envelope.get("format") != _BUNDLE_FORMAT:
        _fail("unsupported policy bundle format")
    bundle_id = _required_string(envelope, "bundle_id", "envelope")
    del bundle_id
    envelope_tenant = _required_string(envelope, "tenant", "envelope")
    _, _ = _validate_timestamps(envelope.get("issued_at"), envelope.get("expires_at"), now)
    policy_data = _require_mapping(envelope.get("policy"), "policy")
    policy = validate_policy(policy_data)
    if envelope_tenant != policy.tenant:
        _fail("envelope tenant must match policy tenant")

    policy_hash = "sha256:" + hashlib.sha256(signature_input).hexdigest()
    return VerifiedPolicyBundle(
        envelope=envelope,
        policy=policy,
        policy_hash=policy_hash,
        key_id=expected_key_id,
    )


def write_signed_policy_atomic(envelope: Mapping[str, Any], output: str | Path) -> None:
    """Write a signed YAML envelope through a same-directory temporary file."""
    destination = Path(output)
    try:
        rendered = yaml.dump(
            dict(envelope),
            Dumper=_BundleSafeDumper,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        ).encode("utf-8")
    except yaml.YAMLError as exc:
        raise PolicyError("cannot serialize policy bundle") from exc
    if len(rendered) > MAX_BUNDLE_BYTES:
        _fail("signed policy bundle exceeds the 1 MiB limit")
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = stream.name
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, destination)
    except OSError as exc:
        if temporary_path is not None:
            with suppress(OSError):
                os.unlink(temporary_path)
        raise PolicyError("cannot atomically write policy bundle") from exc


def _rule_matches(
    rule: PolicyRule,
    *,
    role: str | None,
    tenant: str | None,
    policy_tenant: str,
    arguments: Mapping[str, Any],
) -> bool:
    if rule.principal_role is not None and role != rule.principal_role:
        return False
    if rule.tenant_match is True and tenant != policy_tenant:
        return False
    for name, argument_pattern in rule.arguments.items():
        value = arguments.get(name)
        if not isinstance(value, str) or argument_pattern.compiled.fullmatch(value) is None:
            return False
    return True


def evaluate_policy(
    policy: Policy,
    tool_name: str,
    *,
    role: str | None,
    tenant: str | None,
    arguments: Mapping[str, Any],
    token_scope: Sequence[str] | None = None,
) -> PolicyDecision:
    """Evaluate rules without I/O, side effects, or policy mutation."""
    tool = policy.tools.get(tool_name)
    if tool is None:
        return PolicyDecision(
            "deny", policy.policy_id, None, None, "default_deny", "high", "inline"
        )

    if tool.risk == "high" and tool.resource_tenant_enforced != "upstream":
        return PolicyDecision(
            "deny",
            policy.policy_id,
            None,
            tool.resource_tenant_enforced,
            "resource_tenant_unverified",
            tool.risk,
            tool.enforcement,
        )
    if token_scope is not None and tool_name not in token_scope:
        return PolicyDecision(
            "deny",
            policy.policy_id,
            None,
            tool.resource_tenant_enforced,
            "token_scope",
            tool.risk,
            tool.enforcement,
        )

    matches: dict[str, PolicyRule] = {}
    for action in ("deny", "require_approval", "allow"):
        match = next(
            (
                rule
                for rule in tool.rules
                if rule.decision == action
                and _rule_matches(
                    rule,
                    role=role,
                    tenant=tenant,
                    policy_tenant=policy.tenant,
                    arguments=arguments,
                )
            ),
            None,
        )
        if match is not None:
            matches[action] = match
    for action, reason in (
        ("deny", "explicit_deny"),
        ("require_approval", "approval_required"),
        ("allow", "allow_rule"),
    ):
        rule = matches.get(action)
        if rule is not None:
            return PolicyDecision(
                action,  # type: ignore[arg-type]
                policy.policy_id,
                rule.id,
                tool.resource_tenant_enforced,
                reason,  # type: ignore[arg-type]
                tool.risk,
                tool.enforcement,
            )
    return PolicyDecision(
        "deny",
        policy.policy_id,
        None,
        tool.resource_tenant_enforced,
        "default_deny",
        tool.risk,
        tool.enforcement,
    )


def redact_arguments(
    arguments: Mapping[str, Any], redaction: RedactionConfig | None = None
) -> dict[str, Any]:
    """Return recursively redacted arguments with strings bounded by config."""
    config = redaction or RedactionConfig()
    redact_names = {name.casefold() for name in config.redact_arguments} | _CREDENTIAL_ARGUMENTS

    def redact(value: Any, key: str | None = None) -> Any:
        if key is not None and key.casefold() in redact_names:
            return "[REDACTED]"
        if isinstance(value, Mapping):
            return {str(name): redact(item, str(name)) for name, item in value.items()}
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, str) and len(value) > config.max_value_length:
            return value[: config.max_value_length]
        return value

    return {str(name): redact(value, str(name)) for name, value in arguments.items()}


def sign_policy_file(
    policy_path: str | Path,
    private_key_path: str | Path,
    *,
    bundle_id: str,
    tenant: str,
    issued_at: str,
    expires_at: str,
    output_path: str | Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    """CLI helper: load bounded inputs, sign, and atomically write an envelope."""
    policy_data = load_policy_yaml(policy_path)
    try:
        private_key_pem = _read_limited(private_key_path, "private key file")
    except PolicyError as exc:
        raise PolicyError("cannot read private key file") from exc
    envelope = sign_policy(
        policy_data,
        private_key_pem,
        bundle_id=bundle_id,
        tenant=tenant,
        issued_at=issued_at,
        expires_at=expires_at,
        now=now,
    )
    write_signed_policy_atomic(envelope, output_path)
    return envelope


def verify_policy_file(
    bundle_path: str | Path,
    public_key_path: str | Path,
    *,
    now: datetime | None = None,
) -> VerifiedPolicyBundle:
    """CLI helper: verify bounded bundle and public-key files."""
    bundle_data = _read_limited(bundle_path, "policy bundle")
    public_key_pem = _read_limited(public_key_path, "public key file")
    return verify_policy_bundle(bundle_data, public_key_pem, now=now)
