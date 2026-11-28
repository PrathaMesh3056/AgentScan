"""Phase 5 tool runtime: policy-checked MCP dispatch with durable receipts.

The runtime owns the full `tools/call` sequence: identity binding, catalog
consistency, argument validation, policy evaluation, two-phase receipt
appending, idempotent replay, and sanitized upstream dispatch. It never
returns a successful tool result without a durable outcome receipt.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from mcp.types import CallToolResult, TextContent, Tool

from agentscan.gateway.canonical import canonical_json
from agentscan.gateway.catalog import CatalogTool, ToolCatalog
from agentscan.gateway.config import GatewaySettings
from agentscan.gateway.errors import GatewayError, tool_error_result
from agentscan.gateway.idempotency import (
    IdempotencyAction,
    IdempotencyDecision,
    IdempotencyError,
    IdempotencyIndex,
    IdempotencyState,
    append_outcome,
    compute_request_hash,
    hash_key,
)
from agentscan.gateway.identity import VerifiedIdentity
from agentscan.gateway.metrics import MetricsRegistry
from agentscan.gateway.models import ErrorCode
from agentscan.gateway.policy import ToolPolicy, VerifiedPolicyBundle, evaluate_policy
from agentscan.gateway.receipts import (
    GENESIS_HASH,
    GatewayReceipt,
    ReceiptAuthorization,
    ReceiptChainStore,
    ReceiptError,
    ReceiptEvidence,
    ReceiptResult,
    ReceiptTool,
    prepare_arguments,
    utc_timestamp,
)
from agentscan.gateway.server import GatewayRequestContext, Readiness
from agentscan.gateway.upstream import UpstreamError, UpstreamTimeout

_IDEMPOTENCY_META = "agentscan.idempotency_key"
_KEY_HASH_META = "agentscan.key_hash"
_REQUEST_HASH_META = "agentscan.request_hash"

_PolicyDecisionName = Literal["allow", "deny", "require_approval"]
_EnforcementMode = Literal["inline", "observe", "shadow"]
_EffectiveAction = Literal["forwarded", "blocked"]
_OutcomeStatus = Literal["success", "error", "timeout", "unknown"]


class UpstreamPort(Protocol):
    async def list_tools(self) -> tuple[Tool, ...]: ...

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        meta: Mapping[str, Any] | None = None,
        timeout_seconds: float | None = None,
    ) -> CallToolResult: ...


def _invalid_arguments() -> GatewayError:
    return GatewayError(ErrorCode.GATEWAY_UNAVAILABLE, "invalid tool arguments", 503)


def _meta_value(meta: Mapping[str, Any] | None, key: str) -> Any:
    """Read one meta entry from a mapping or the MCP request-meta model."""
    if meta is None:
        return None
    if isinstance(meta, Mapping):
        return meta.get(key)
    extras = getattr(meta, "model_extra", None)
    if isinstance(extras, Mapping):
        return extras.get(key)
    return None


def _tenant_enforcement(value: str | None) -> Literal["upstream", "gateway", "none"]:
    if value == "upstream":
        return "upstream"
    if value == "gateway":
        return "gateway"
    return "none"


def _result_hash(result: CallToolResult) -> str:
    encoded = canonical_json(result.model_dump(mode="json"))
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _validate_arguments(
    arguments: Mapping[str, Any],
    *,
    max_argument_bytes: int,
    max_total_argument_bytes: int,
) -> None:
    """Reject arguments that cannot be canonicalized, bounded, and hashed."""
    try:
        stack: list[Any] = [arguments]
        while stack:
            value = stack.pop()
            if isinstance(value, Mapping):
                for key, item in value.items():
                    if not isinstance(key, str):
                        raise _invalid_arguments()
                    if len(key.encode("utf-8")) > max_argument_bytes:
                        raise _invalid_arguments()
                    stack.append(item)
            elif isinstance(value, (list, tuple)):
                stack.extend(value)
            elif isinstance(value, str):
                if len(value.encode("utf-8")) > max_argument_bytes:
                    raise _invalid_arguments()
            elif isinstance(value, float) and not math.isfinite(value):
                raise _invalid_arguments()
        encoded = canonical_json(arguments)
    except (TypeError, ValueError) as exc:
        raise _invalid_arguments() from exc
    if len(encoded) > max_total_argument_bytes:
        raise _invalid_arguments()


class GatewayRuntime:
    """Dispatch tool calls through policy, receipts, and idempotency state."""

    def __init__(
        self,
        *,
        settings: GatewaySettings,
        bundle: VerifiedPolicyBundle,
        store: ReceiptChainStore,
        index: IdempotencyIndex,
        upstream: UpstreamPort,
        catalog: ToolCatalog,
        metrics: MetricsRegistry | None = None,
        clock: Callable[[], datetime] | None = None,
        upstream_alive: Callable[[], bool] | None = None,
        is_shutting_down: Callable[[], bool] | None = None,
    ) -> None:
        if (store.tenant, store.gateway_id, store.chain_id) != (
            settings.tenant,
            settings.gateway_id,
            settings.chain_id,
        ):
            raise ValueError("store scope does not match gateway settings")
        index.rebuild(store.receipts)
        self._settings = settings
        self._bundle = bundle
        self._store = store
        self._index = index
        self._upstream = upstream
        self._catalog = catalog
        self._metrics = metrics if metrics is not None else MetricsRegistry()
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._catalog_lock = asyncio.Lock()
        self._idempotency_lock = asyncio.Lock()
        self._sink_failed = False
        self._upstream_alive = upstream_alive if upstream_alive is not None else (lambda: True)
        self._is_shutting_down = is_shutting_down if is_shutting_down is not None else (lambda: False)

    async def list_tools(self, context: GatewayRequestContext) -> Sequence[Tool]:
        if not isinstance(context.identity, VerifiedIdentity) or context.session is None:
            raise GatewayError(ErrorCode.IDENTITY_MISSING, "verified identity required", 401)
        await self._refresh_catalog()
        self._metrics.increment("decisions", tool="tools_list", decision="allow")
        return self._catalog.approved_tools(self._bundle.policy)

    async def call_tool(
        self,
        context: GatewayRequestContext,
        name: str,
        arguments: Mapping[str, Any],
        *,
        meta: Mapping[str, Any] | None = None,
    ) -> CallToolResult:
        started = time.monotonic()
        if self._sink_failed:
            raise GatewayError(ErrorCode.GATEWAY_UNAVAILABLE, "receipt sink unavailable", 503)
        identity = context.identity
        if not isinstance(identity, VerifiedIdentity) or context.session is None:
            self._metrics.increment("identity_mismatches", reason="identity_missing")
            raise GatewayError(ErrorCode.IDENTITY_MISSING, "verified identity required", 401)
        session = context.session
        if (
            identity.tenant != self._settings.tenant
            or session.tenant != identity.tenant
            or session.principal != identity.principal
            or session.agent != identity.agent
            or session.session_identity_hash != identity.session_identity_hash
        ):
            self._metrics.increment("identity_mismatches", reason="identity_mismatch")
            raise GatewayError(ErrorCode.IDENTITY_MISMATCH, "identity binding mismatch", 403)

        if not self._catalog.loaded:
            await self._refresh_catalog()
        entry = self._catalog.get(name)
        if entry is None:
            raise GatewayError(
                ErrorCode.GATEWAY_UNAVAILABLE, "tool is missing from the loaded catalog", 503
            )
        policy = self._bundle.policy
        policy_tool = policy.tools.get(name)
        if policy_tool is not None and policy_tool.server != self._catalog.server_id:
            raise GatewayError(
                ErrorCode.GATEWAY_UNAVAILABLE, "policy server does not match the catalog", 503
            )
        if any(
            mismatch.reason in {"schema_drift", "rule_argument_missing"}
            for mismatch in self._catalog.check_policy(policy)
            if mismatch.tool_name == name
        ):
            self._record_schema_drift(
                context=context,
                identity=identity,
                entry=entry,
                policy_tool=policy_tool,
                arguments=arguments,
                started=started,
            )
            raise GatewayError(ErrorCode.SCHEMA_DRIFT, "tool schema does not match the policy", 403)

        _validate_arguments(
            arguments,
            max_argument_bytes=self._settings.max_argument_bytes,
            max_total_argument_bytes=self._settings.max_total_argument_bytes,
        )
        try:
            arguments_for_receipt, arguments_hash = prepare_arguments(arguments, policy.redaction)
            request_hash = compute_request_hash(
                tenant=identity.tenant,
                principal=identity.principal,
                agent=identity.agent,
                tool_identity_hash=entry.tool_identity,
                arguments=arguments,
            )
        except (ReceiptError, IdempotencyError, TypeError, ValueError) as exc:
            raise _invalid_arguments() from exc

        evaluation_started = time.monotonic()
        decision = evaluate_policy(
            policy,
            name,
            role=identity.role,
            tenant=identity.tenant,
            arguments=arguments,
            token_scope=identity.scope,
        )
        decision_latency_ms = (time.monotonic() - evaluation_started) * 1000.0
        self._metrics.observe("policy_latency_seconds", decision_latency_ms / 1000.0)
        self._metrics.increment("decisions", tool="tools_call", decision=decision.decision)

        if self._settings.mode == "shadow":
            enforcement_mode: _EnforcementMode = "shadow"
        elif decision.enforcement == "observe":
            enforcement_mode = "observe"
        else:
            enforcement_mode = "inline"
        would_deny = decision.decision != "allow"
        if decision.decision == "require_approval" or (
            decision.decision == "deny" and enforcement_mode == "inline"
        ):
            effective_action: _EffectiveAction = "blocked"
        else:
            effective_action = "forwarded"

        if effective_action == "blocked":
            summary = (
                "approval required"
                if decision.decision == "require_approval"
                else "policy denied the tool call"
            )
            self._append_receipt(
                self._decision_receipt(
                    context=context,
                    identity=identity,
                    entry=entry,
                    arguments_for_receipt=arguments_for_receipt,
                    arguments_hash=arguments_hash,
                    request_hash=request_hash,
                    now=self._clock(),
                    decision_latency_ms=decision_latency_ms,
                    policy_decision=decision.decision,
                    authorization_decision="deny",
                    rule_id=decision.rule_id,
                    reason=decision.reason,
                    resource_tenant_enforced=_tenant_enforcement(decision.resource_tenant_enforced),
                    enforcement_mode=enforcement_mode,
                    effective_action="blocked",
                    would_deny=True,
                    result_status="denied",
                    summary=summary,
                    idempotency_key=None,
                )
            )
            if decision.decision == "require_approval":
                self._metrics.increment("approval_required")
                raise GatewayError(ErrorCode.APPROVAL_REQUIRED, "approval required", 403)
            raise GatewayError(ErrorCode.POLICY_DENIED, "policy denied the tool call", 403)

        key_hash: str | None = None
        raw_key = _meta_value(meta, _IDEMPOTENCY_META)
        if raw_key is not None:
            try:
                key_hash = hash_key(raw_key, max_bytes=self._settings.max_idempotency_key_bytes)
            except IdempotencyError:
                key_hash = None
        if decision.risk == "high" and key_hash is None:
            self._append_receipt(
                self._decision_receipt(
                    context=context,
                    identity=identity,
                    entry=entry,
                    arguments_for_receipt=arguments_for_receipt,
                    arguments_hash=arguments_hash,
                    request_hash=request_hash,
                    now=self._clock(),
                    decision_latency_ms=decision_latency_ms,
                    policy_decision=decision.decision,
                    authorization_decision="deny",
                    rule_id=decision.rule_id,
                    reason="idempotency_required",
                    resource_tenant_enforced=_tenant_enforcement(decision.resource_tenant_enforced),
                    enforcement_mode=enforcement_mode,
                    effective_action="blocked",
                    would_deny=would_deny,
                    result_status="denied",
                    summary="idempotency key required",
                    idempotency_key=None,
                )
            )
            raise GatewayError(
                ErrorCode.IDEMPOTENCY_REQUIRED, "a valid idempotency key is required", 403
            )

        now = self._clock()
        async with self._idempotency_lock:
            if key_hash is not None:
                try:
                    idem = self._index.check(
                        tenant=identity.tenant,
                        principal=identity.principal,
                        tool_identity_hash=entry.tool_identity,
                        key_hash=key_hash,
                        request_hash=request_hash,
                        now=now,
                    )
                except IdempotencyError as exc:
                    raise GatewayError(
                        ErrorCode.GATEWAY_UNAVAILABLE, "idempotency state unavailable", 503
                    ) from exc
                if idem.action == IdempotencyAction.REPLAY:
                    return self._replay_result(idem)
                if idem.action == IdempotencyAction.OUTCOME_UNKNOWN:
                    raise GatewayError(ErrorCode.OUTCOME_UNKNOWN, "tool outcome is unknown", 409)
                if idem.action == IdempotencyAction.CONFLICT:
                    raise GatewayError(
                        ErrorCode.IDEMPOTENCY_CONFLICT,
                        "idempotency key conflicts with the request",
                        409,
                    )
            sealed = self._append_receipt(
                self._decision_receipt(
                    context=context,
                    identity=identity,
                    entry=entry,
                    arguments_for_receipt=arguments_for_receipt,
                    arguments_hash=arguments_hash,
                    request_hash=request_hash,
                    now=now,
                    decision_latency_ms=decision_latency_ms,
                    policy_decision=decision.decision,
                    authorization_decision="allow" if decision.decision == "allow" else "deny",
                    rule_id=decision.rule_id,
                    reason=decision.reason,
                    resource_tenant_enforced=_tenant_enforcement(decision.resource_tenant_enforced),
                    enforcement_mode=enforcement_mode,
                    effective_action="forwarded",
                    would_deny=would_deny,
                    result_status="pending",
                    summary="awaiting upstream outcome",
                    idempotency_key=key_hash,
                )
            )
            try:
                self._index.record(sealed, now=now)
            except Exception as exc:
                self._sink_failed = True
                raise GatewayError(
                    ErrorCode.GATEWAY_UNAVAILABLE, "idempotency state unavailable", 503
                ) from exc

        upstream_meta = (
            {_KEY_HASH_META: key_hash, _REQUEST_HASH_META: request_hash}
            if key_hash is not None
            else None
        )
        returned: CallToolResult
        try:
            result = await self._upstream.call_tool(
                name,
                arguments,
                meta=upstream_meta,
                timeout_seconds=self._settings.upstream_timeout_seconds,
            )
        except asyncio.CancelledError:
            if self._is_shutting_down():
                raise
            status: _OutcomeStatus = "unknown"
            summary_text = "upstream effect unconfirmed"
            returned = tool_error_result(
                ErrorCode.OUTCOME_UNKNOWN, "upstream effect could not be confirmed"
            )
        except UpstreamTimeout:
            status = "timeout"
            summary_text = "upstream call timed out"
            returned = tool_error_result(ErrorCode.TIMEOUT, "upstream request timed out")
        except UpstreamError as exc:
            if getattr(exc, "may_have_sent", False):
                status = "unknown"
                summary_text = "upstream effect unconfirmed"
                returned = tool_error_result(
                    ErrorCode.OUTCOME_UNKNOWN, "upstream effect could not be confirmed"
                )
            else:
                status = "error"
                summary_text = "upstream call failed"
                returned = tool_error_result(ErrorCode.UPSTREAM_ERROR, "upstream call failed")
        except Exception:
            status = "unknown"
            summary_text = "upstream effect unconfirmed"
            returned = tool_error_result(
                ErrorCode.OUTCOME_UNKNOWN, "upstream effect could not be confirmed"
            )
        else:
            if result.isError:
                status = "error"
                summary_text = "upstream tool call failed"
                returned = tool_error_result(ErrorCode.UPSTREAM_ERROR, "upstream tool call failed")
            else:
                status = "success"
                summary_text = "upstream call succeeded"
                returned = result

        response_hash: str | None = None
        if status != "unknown":
            try:
                response_hash = _result_hash(returned)
            except (TypeError, ValueError):
                status = "unknown"
                summary_text = "upstream effect unconfirmed"
                returned = tool_error_result(
                    ErrorCode.OUTCOME_UNKNOWN, "upstream effect could not be confirmed"
                )
        if status == "unknown":
            self._metrics.increment("unknown_outcomes")
        elif status == "timeout":
            self._metrics.increment("upstream_timeouts")
        elif status == "error":
            self._metrics.increment("upstream_errors")

        try:
            outcome = append_outcome(
                self._store,
                sealed,
                status=status,
                summary=summary_text,
                response_hash=response_hash,
                now=self._clock(),
            )
        except Exception:
            try:
                outcome = append_outcome(
                    self._store,
                    sealed,
                    status="unknown",
                    summary="upstream effect unconfirmed",
                    response_hash=None,
                    now=self._clock(),
                )
            except Exception as exc:
                self._sink_failed = True
                raise GatewayError(
                    ErrorCode.GATEWAY_UNAVAILABLE, "receipt sink unavailable", 503
                ) from exc
            # The durable outcome is unknown, so the caller must not receive the
            # original success/timeout result even though the fallback append
            # succeeded.
            if status != "unknown":
                self._metrics.increment("unknown_outcomes")
            status = "unknown"
            summary_text = "upstream effect unconfirmed"
            response_hash = None
            returned = tool_error_result(
                ErrorCode.OUTCOME_UNKNOWN, "upstream effect could not be confirmed"
            )
        try:
            async with self._idempotency_lock:
                self._index.record(outcome, now=self._clock())
        except Exception as exc:
            self._sink_failed = True
            raise GatewayError(
                ErrorCode.GATEWAY_UNAVAILABLE, "idempotency state unavailable", 503
            ) from exc
        return returned

    def readiness(self) -> Readiness:
        try:
            now = self._clock()
            if now.tzinfo is None or now.utcoffset() is None:
                raise ValueError("readiness clock must be timezone-aware")
            return Readiness(
                policy_loaded=self._bundle.policy.tenant == self._settings.tenant,
                policy_expired=self._policy_expired(now),
                chain_verified=self._chain_verified(),
                writer_lease_held=self._store.lease_held,
                receipt_sink_healthy=self._store.healthy and not self._sink_failed,
                upstream_catalog_loaded=self._catalog.loaded,
                upstream_lost=not self._upstream_alive(),
            )
        except Exception:
            return Readiness()

    async def _refresh_catalog(self) -> None:
        async with self._catalog_lock:
            try:
                tools = await self._upstream.list_tools()
                self._catalog.replace(tools)
            except asyncio.CancelledError:
                if self._is_shutting_down():
                    raise
                raise GatewayError(
                    ErrorCode.GATEWAY_UNAVAILABLE, "upstream catalog unavailable", 503
                ) from None
            except Exception:
                raise GatewayError(
                    ErrorCode.GATEWAY_UNAVAILABLE, "upstream catalog unavailable", 503
                ) from None

    def _record_schema_drift(
        self,
        *,
        context: GatewayRequestContext,
        identity: VerifiedIdentity,
        entry: CatalogTool,
        policy_tool: ToolPolicy | None,
        arguments: Mapping[str, Any],
        started: float,
    ) -> None:
        policy = self._bundle.policy
        try:
            arguments_for_receipt, arguments_hash = prepare_arguments(arguments, policy.redaction)
            request_hash = compute_request_hash(
                tenant=identity.tenant,
                principal=identity.principal,
                agent=identity.agent,
                tool_identity_hash=entry.tool_identity,
                arguments=arguments,
            )
        except (ReceiptError, IdempotencyError, TypeError, ValueError) as exc:
            raise _invalid_arguments() from exc
        self._append_receipt(
            self._decision_receipt(
                context=context,
                identity=identity,
                entry=entry,
                arguments_for_receipt=arguments_for_receipt,
                arguments_hash=arguments_hash,
                request_hash=request_hash,
                now=self._clock(),
                decision_latency_ms=(time.monotonic() - started) * 1000.0,
                policy_decision="deny",
                authorization_decision="deny",
                rule_id=None,
                reason="schema_drift",
                resource_tenant_enforced=_tenant_enforcement(
                    policy_tool.resource_tenant_enforced if policy_tool is not None else None
                ),
                enforcement_mode=self._default_enforcement_mode(
                    policy_tool.enforcement if policy_tool is not None else None
                ),
                effective_action="blocked",
                would_deny=True,
                result_status="denied",
                summary="schema drift detected",
                idempotency_key=None,
            )
        )
        self._metrics.increment("decisions", tool="tools_call", decision="deny")

    def _decision_receipt(
        self,
        *,
        context: GatewayRequestContext,
        identity: VerifiedIdentity,
        entry: CatalogTool,
        arguments_for_receipt: dict[str, Any],
        arguments_hash: str,
        request_hash: str,
        now: datetime,
        decision_latency_ms: float,
        policy_decision: _PolicyDecisionName,
        authorization_decision: Literal["allow", "deny"],
        rule_id: str | None,
        reason: str,
        resource_tenant_enforced: Literal["upstream", "gateway", "none"],
        enforcement_mode: _EnforcementMode,
        effective_action: _EffectiveAction,
        would_deny: bool,
        result_status: Literal["pending", "denied"],
        summary: str,
        idempotency_key: str | None,
    ) -> GatewayReceipt:
        return GatewayReceipt(
            trace_id=context.trace_id,
            phase="decision",
            tenant_id=self._settings.tenant,
            gateway_id=self._settings.gateway_id,
            chain_id=self._settings.chain_id,
            writer_epoch=max(self._store.writer_epoch or 1, 1),
            writer_id=self._settings.writer_id,
            idempotency_key=idempotency_key,
            principal=identity.principal,
            agent=identity.agent,
            tool=ReceiptTool(
                name=entry.name,
                server=entry.server_id,
                schema_hash=entry.schema_hash,
                identity_hash=entry.tool_identity,
            ),
            arguments=arguments_for_receipt,
            arguments_hash=arguments_hash,
            authorization=ReceiptAuthorization(
                decision=authorization_decision,
                policy_id=self._bundle.policy.policy_id,
                rule_id=rule_id,
                resource_tenant_enforced=resource_tenant_enforced,
                reason=reason,
            ),
            policy_decision=policy_decision,
            enforcement_mode=enforcement_mode,
            effective_action=effective_action,
            would_deny=would_deny,
            result=ReceiptResult(status=result_status, summary=summary),
            evidence=ReceiptEvidence(hash="", prev_hash=GENESIS_HASH),
            timestamp=utc_timestamp(now),
            request_hash=request_hash,
            policy_hash=self._bundle.policy_hash,
            policy_key_id=self._bundle.key_id,
            decision_latency_ms=decision_latency_ms,
            mcp_request_id=context.request_id or context.trace_id,
        )

    def _append_receipt(self, receipt: GatewayReceipt) -> GatewayReceipt:
        append_started = time.monotonic()
        try:
            return self._store.append(receipt)
        except Exception as exc:
            self._sink_failed = True
            raise GatewayError(
                ErrorCode.GATEWAY_UNAVAILABLE, "receipt sink unavailable", 503
            ) from exc
        finally:
            self._metrics.observe(
                "receipt_append_latency_seconds", time.monotonic() - append_started
            )

    def _replay_result(self, idem: IdempotencyDecision) -> CallToolResult:
        if idem.state == IdempotencyState.SUCCESS:
            return CallToolResult(
                content=[TextContent(type="text", text="replayed outcome: success")],
                structuredContent={"status": "success", "replayed": True},
            )
        if idem.state == IdempotencyState.NO_EFFECT:
            return CallToolResult(
                content=[TextContent(type="text", text="replayed outcome: no_effect")],
                structuredContent={"status": "no_effect", "replayed": True},
            )
        if idem.state == IdempotencyState.ERROR:
            return tool_error_result(ErrorCode.UPSTREAM_ERROR, "recorded outcome replayed")
        if idem.state == IdempotencyState.TIMEOUT:
            return tool_error_result(ErrorCode.TIMEOUT, "recorded outcome replayed")
        return tool_error_result(ErrorCode.OUTCOME_UNKNOWN)

    def _default_enforcement_mode(self, enforcement: str | None = None) -> _EnforcementMode:
        if self._settings.mode == "shadow":
            return "shadow"
        if enforcement == "observe":
            return "observe"
        return "inline"

    def _chain_verified(self) -> bool:
        verification = self._store.verify()
        return verification.head_hash == self._store.head_hash

    def _policy_expired(self, now: datetime) -> bool:
        """True only when the parsed envelope expiry has passed."""
        raw = self._bundle.envelope.get("expires_at")
        if not isinstance(raw, str) or not raw:
            return False
        try:
            normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
            expires = datetime.fromisoformat(normalized)
        except (TypeError, ValueError):
            return False
        if expires.tzinfo is None or expires.utcoffset() is None:
            return False
        return now >= expires
