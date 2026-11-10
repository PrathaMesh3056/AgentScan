"""Durable receipt records, hash chains, WAL recovery, and single-writer fencing."""

from __future__ import annotations

import hashlib
import math
import os
import re
import sys
import tempfile
import threading
from collections.abc import Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from filelock import FileLock, Timeout
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentscan.gateway.canonical import canonical_json, loads_json
from agentscan.gateway.policy import RedactionConfig, redact_arguments

GENESIS_HASH = "sha256:" + "0" * 64
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^ed25519:[0-9a-f]{64}$")
_TENANT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_CHAIN_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_WAL_FORMAT = "agentscan-wal-record/v1"


class ReceiptError(ValueError):
    """Receipt data or local receipt storage is invalid."""


class ReceiptChainError(ReceiptError):
    """The JSONL receipt chain cannot be verified or recovered."""


class WriterLeaseError(ReceiptError):
    """The process cannot safely acquire or use the single-writer lease."""


class ReceiptTool(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    server: str = Field(min_length=1)
    schema_hash: str
    identity_hash: str

    @field_validator("schema_hash", "identity_hash")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if not _HASH_RE.fullmatch(value):
            raise ValueError("tool hashes must use sha256:<64 lowercase hex>")
        return value


class ReceiptAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Literal["allow", "deny"]
    policy_id: str = Field(min_length=1)
    rule_id: str | None
    resource_tenant_enforced: Literal["upstream", "gateway", "none"]
    reason: str = Field(min_length=1)


class ReceiptResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["pending", "denied", "success", "error", "timeout", "unknown", "no_effect"]
    summary: str

    @field_validator("summary")
    @classmethod
    def bound_summary(cls, value: str) -> str:
        encoded = value.encode("utf-8")
        if len(encoded) <= 512:
            return value
        return encoded[:512].decode("utf-8", errors="ignore")


class ReceiptEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hash: str
    prev_hash: str

    @field_validator("hash")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if value != "" and not _HASH_RE.fullmatch(value):
            raise ValueError("evidence.hash must be empty before sealing or a sha256 hash")
        return value

    @field_validator("prev_hash")
    @classmethod
    def validate_prev_hash(cls, value: str) -> str:
        if not _HASH_RE.fullmatch(value):
            raise ValueError("evidence.prev_hash must use sha256:<64 lowercase hex>")
        return value


class GatewayReceipt(BaseModel):
    """Versioned, canonicalizable record for one decision, outcome, or handoff."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format: Literal["agentscan-receipt/v1"] = "agentscan-receipt/v1"
    trace_id: str = Field(min_length=1)
    phase: Literal["decision", "outcome", "handoff"]
    tenant_id: str = Field(min_length=1)
    gateway_id: str = Field(min_length=1)
    chain_id: str = Field(min_length=1)
    writer_epoch: int = Field(ge=1)
    writer_id: str = Field(min_length=1)
    idempotency_key: str | None = None
    principal: str = Field(min_length=1)
    agent: str = Field(min_length=1)
    tool: ReceiptTool
    arguments: dict[str, Any]
    arguments_hash: str
    authorization: ReceiptAuthorization
    policy_decision: Literal["allow", "deny", "require_approval"]
    enforcement_mode: Literal["inline", "observe", "shadow"]
    effective_action: Literal["forwarded", "blocked"]
    would_deny: bool
    result: ReceiptResult
    evidence: ReceiptEvidence
    timestamp: str
    request_hash: str
    response_hash: str | None = None
    policy_hash: str
    policy_key_id: str
    decision_latency_ms: float
    transport: Literal["mcp-http"] = "mcp-http"
    mcp_request_id: str = Field(min_length=1)
    approval_id: str | None = None
    reconciliation: dict[str, Any] | None = None

    @field_validator("idempotency_key", "arguments_hash", "request_hash", "policy_hash")
    @classmethod
    def validate_optional_or_required_hash(cls, value: str | None) -> str | None:
        if value is not None and not _HASH_RE.fullmatch(value):
            raise ValueError("hash must use sha256:<64 lowercase hex>")
        return value

    @field_validator("response_hash")
    @classmethod
    def validate_response_hash(cls, value: str | None) -> str | None:
        if value is not None and not _HASH_RE.fullmatch(value):
            raise ValueError("response_hash must use sha256:<64 lowercase hex>")
        return value

    @field_validator("policy_key_id")
    @classmethod
    def validate_policy_key_id(cls, value: str) -> str:
        if not _KEY_ID_RE.fullmatch(value):
            raise ValueError("policy_key_id must use ed25519:<64 lowercase hex>")
        return value

    @field_validator("arguments")
    @classmethod
    def redact_credential_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        # The caller may apply the bundle's additional PII rules first. This
        # model-level pass makes credential redaction mandatory in all cases.
        return redact_arguments(value)

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: str) -> str:
        if not _TIMESTAMP_RE.fullmatch(value):
            raise ValueError("timestamp must be canonical UTC with millisecond precision")
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError as exc:
            raise ValueError("timestamp is invalid") from exc
        return value

    @field_validator("decision_latency_ms")
    @classmethod
    def validate_latency(cls, value: float) -> float:
        if not math.isfinite(value) or value < 0:
            raise ValueError("decision_latency_ms must be finite and non-negative")
        return value

    @model_validator(mode="after")
    def validate_phase_status(self) -> GatewayReceipt:
        allowed = {
            "decision": {"pending", "denied"},
            "outcome": {"success", "error", "timeout", "unknown", "no_effect"},
            "handoff": {"success"},
        }
        if self.result.status not in allowed[self.phase]:
            raise ValueError(f"result.status {self.result.status!r} is invalid for {self.phase}")
        if self.policy_decision == "require_approval" and (
            self.authorization.decision != "deny"
            or self.effective_action != "blocked"
            or self.result.status != "denied"
        ):
            raise ValueError("require_approval must be denied, blocked, and terminal in v1")
        return self


@dataclass(frozen=True, slots=True)
class ChainVerification:
    receipts: tuple[GatewayReceipt, ...]
    head_hash: str


def utc_timestamp(now: datetime | None = None) -> str:
    """Format a timestamp as canonical UTC with millisecond precision."""
    value = datetime.now(UTC) if now is None else now
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReceiptError("timestamp source must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def prepare_arguments(
    arguments: Mapping[str, Any], redaction: RedactionConfig | None = None
) -> tuple[dict[str, Any], str]:
    """Return redacted argument values and a hash of the unredacted canonical input."""
    try:
        arguments_hash = "sha256:" + hashlib.sha256(canonical_json(arguments)).hexdigest()
    except (TypeError, ValueError) as exc:
        raise ReceiptError("arguments are not canonical JSON data") from exc
    return redact_arguments(arguments, redaction), arguments_hash


def _hash_payload(receipt: GatewayReceipt) -> bytes:
    payload = receipt.model_dump(mode="json")
    payload["evidence"]["hash"] = ""
    try:
        return canonical_json(payload)
    except (TypeError, ValueError) as exc:
        raise ReceiptError("receipt is not canonical JSON data") from exc


def receipt_hash(receipt: GatewayReceipt) -> str:
    return "sha256:" + hashlib.sha256(_hash_payload(receipt)).hexdigest()


def seal_receipt(receipt: GatewayReceipt, prev_hash: str = GENESIS_HASH) -> GatewayReceipt:
    """Seal a receipt by binding its previous link and canonical payload hash."""
    if not _HASH_RE.fullmatch(prev_hash):
        raise ReceiptError("previous hash is invalid")
    unsigned = receipt.model_copy(
        update={"evidence": ReceiptEvidence(hash="", prev_hash=prev_hash)}
    )
    return unsigned.model_copy(
        update={"evidence": ReceiptEvidence(hash=receipt_hash(unsigned), prev_hash=prev_hash)}
    )


def verify_receipt_hash(receipt: GatewayReceipt) -> bool:
    return receipt.evidence.hash == receipt_hash(receipt)


def verify_receipt_chain(receipts: Iterable[GatewayReceipt]) -> ChainVerification:
    """Verify receipt hashes, genesis, links, and writer epoch fencing."""
    verified: list[GatewayReceipt] = []
    previous_hash = GENESIS_HASH
    previous_epoch = 0
    previous_writer: str | None = None
    chain_identity: tuple[str, str, str] | None = None
    for receipt in receipts:
        current_identity = (receipt.tenant_id, receipt.gateway_id, receipt.chain_id)
        if chain_identity is None:
            chain_identity = current_identity
        elif current_identity != chain_identity:
            raise ReceiptChainError("receipt tenant, gateway, or chain changed within chain")
        if receipt.evidence.prev_hash != previous_hash:
            raise ReceiptChainError("receipt chain link does not match previous hash")
        if not verify_receipt_hash(receipt):
            raise ReceiptChainError("receipt hash verification failed")
        if receipt.writer_epoch < previous_epoch:
            raise ReceiptChainError("writer epoch moved backwards")
        if (
            receipt.writer_epoch == previous_epoch
            and previous_writer is not None
            and receipt.writer_id != previous_writer
        ):
            raise ReceiptChainError("writer identity changed without a new epoch")
        if previous_writer is not None and receipt.writer_id != previous_writer:
            raise ReceiptChainError("writer handoff requires an authenticated handoff record")
        previous_hash = receipt.evidence.hash
        previous_epoch = receipt.writer_epoch
        previous_writer = receipt.writer_id
        verified.append(receipt)
    return ChainVerification(tuple(verified), previous_hash)


def _receipt_from_line(line: bytes) -> GatewayReceipt:
    try:
        value = loads_json(line)
        receipt = GatewayReceipt.model_validate(value)
    except Exception as exc:
        if isinstance(exc, ReceiptError):
            raise
        raise ReceiptChainError("invalid receipt JSONL record") from exc
    if canonical_json(receipt.model_dump(mode="json")) != line:
        raise ReceiptChainError("receipt JSONL record is not canonical")
    return receipt


def verify_jsonl_chain(data: bytes) -> ChainVerification:
    """Verify a complete JSONL chain from genesis; partial final lines fail."""
    if data and not data.endswith(b"\n"):
        raise ReceiptChainError("partial JSONL line")
    receipts: list[GatewayReceipt] = []
    for line in data.splitlines(keepends=True):
        if not line.endswith(b"\n"):
            raise ReceiptChainError("partial JSONL line")
        receipts.append(_receipt_from_line(line[:-1]))
    return verify_receipt_chain(receipts)


def verify_jsonl_file(path: str | Path) -> ChainVerification:
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        data = b""
    except OSError as exc:
        raise ReceiptChainError("cannot read receipt chain") from exc
    return verify_jsonl_chain(data)


def _safe_chain_paths(receipt_dir: str | Path, tenant: str, chain_id: str) -> tuple[Path, str]:
    if not isinstance(tenant, str) or not _TENANT_RE.fullmatch(tenant) or ".." in tenant:
        raise ReceiptError("tenant is not safe for receipt storage")
    if not isinstance(chain_id, str) or not _CHAIN_RE.fullmatch(chain_id) or ".." in chain_id:
        raise ReceiptError("chain_id is not safe for receipt storage")
    safe_chain = chain_id.replace("/", "__")
    directory = Path(receipt_dir) / tenant
    return directory, safe_chain


def _append_fsynced(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0)
    created = not path.exists()
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as exc:
        raise ReceiptError("durable receipt append failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if created:
        _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    """Flush a directory entry after creating or replacing a durable file."""
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
            create_file = kernel32.CreateFileW
            create_file.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            create_file.restype = wintypes.HANDLE
            handle = create_file(
                str(path),
                0x40000000,  # GENERIC_WRITE
                0x1 | 0x2 | 0x4,  # share read, write, and delete
                None,
                3,  # OPEN_EXISTING
                0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
                None,
            )
            if handle == wintypes.HANDLE(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                if not kernel32.FlushFileBuffers(handle):
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                kernel32.CloseHandle(handle)
            return

        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ReceiptError("cannot fsync receipt directory") from exc


def _wal_line(receipt: GatewayReceipt) -> bytes:
    record = {"format": _WAL_FORMAT, "receipt": receipt.model_dump(mode="json")}
    return canonical_json(record) + b"\n"


def _read_wal(path: Path) -> tuple[GatewayReceipt, ...]:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise ReceiptChainError("cannot read receipt WAL") from exc
    if data and not data.endswith(b"\n"):
        raise ReceiptChainError("partial WAL record")
    receipts: list[GatewayReceipt] = []
    for line in data.splitlines(keepends=True):
        try:
            record = loads_json(line[:-1])
            if not isinstance(record, dict) or set(record) != {"format", "receipt"}:
                raise ReceiptChainError("invalid WAL record")
            if record["format"] != _WAL_FORMAT:
                raise ReceiptChainError("unsupported WAL record format")
            receipt = GatewayReceipt.model_validate(record["receipt"])
        except Exception as exc:
            if isinstance(exc, ReceiptChainError):
                raise
            raise ReceiptChainError("invalid WAL record") from exc
        if (
            canonical_json({"format": _WAL_FORMAT, "receipt": receipt.model_dump(mode="json")})
            != line[:-1]
        ):
            raise ReceiptChainError("WAL record is not canonical")
        if not verify_receipt_hash(receipt):
            raise ReceiptChainError("WAL receipt hash verification failed")
        receipts.append(receipt)
    return tuple(receipts)


def _read_epoch(path: Path) -> int:
    try:
        value = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return 0
    except OSError as exc:
        raise WriterLeaseError("cannot read writer epoch") from exc
    try:
        epoch = int(value)
    except ValueError as exc:
        raise WriterLeaseError("writer epoch file is invalid") from exc
    if epoch < 1:
        raise WriterLeaseError("writer epoch file is invalid")
    return epoch


def _write_epoch_atomic(path: Path, epoch: int) -> None:
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="ascii",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = stream.name
            stream.write(f"{epoch}\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        _fsync_directory(path.parent)
    except (OSError, ReceiptError) as exc:
        if temporary_path is not None:
            with suppress(OSError):
                os.unlink(temporary_path)
        raise WriterLeaseError("cannot persist writer epoch") from exc


def _timestamp_value(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ReceiptError("receipt timestamp is invalid") from exc


class RetentionDedupeIndex:
    """In-memory index rebuilt from durable receipts within the retention window."""

    def __init__(self, retention_days: int = 30, dedupe_window_days: int | None = None) -> None:
        if type(retention_days) is not int or retention_days < 1:
            raise ReceiptError("retention_days must be a positive integer")
        dedupe_days = retention_days if dedupe_window_days is None else dedupe_window_days
        if type(dedupe_days) is not int or dedupe_days != retention_days:
            raise ReceiptError("dedupe window must equal receipt retention")
        self.retention_days = retention_days
        self.dedupe_window_days = dedupe_days
        self._entries: dict[tuple[str, str, str, str], list[GatewayReceipt]] = {}

    def is_expired(self, timestamp: str, now: datetime | None = None) -> bool:
        current = datetime.now(UTC) if now is None else now
        if current.tzinfo is None or current.utcoffset() is None:
            raise ReceiptError("retention clock must be timezone-aware")
        cutoff = current.astimezone(UTC) - timedelta(days=self.retention_days)
        return _timestamp_value(timestamp) <= cutoff

    @staticmethod
    def _scope(receipt: GatewayReceipt) -> tuple[str, str, str, str] | None:
        if receipt.idempotency_key is None:
            return None
        return (
            receipt.tenant_id,
            receipt.principal,
            receipt.tool.identity_hash,
            receipt.idempotency_key,
        )

    def rebuild(self, receipts: Iterable[GatewayReceipt], now: datetime | None = None) -> None:
        self._entries.clear()
        for receipt in receipts:
            scope = self._scope(receipt)
            if scope is not None and not self.is_expired(receipt.timestamp, now):
                self._entries.setdefault(scope, []).append(receipt)

    def add(self, receipt: GatewayReceipt, now: datetime | None = None) -> None:
        scope = self._scope(receipt)
        if scope is not None and not self.is_expired(receipt.timestamp, now):
            self._entries.setdefault(scope, []).append(receipt)

    def lookup(
        self,
        tenant: str,
        principal: str,
        tool_identity_hash: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> tuple[GatewayReceipt, ...]:
        scope = (tenant, principal, tool_identity_hash, idempotency_key)
        active = tuple(
            receipt
            for receipt in self._entries.get(scope, ())
            if not self.is_expired(receipt.timestamp, now)
        )
        if active:
            self._entries[scope] = list(active)
        else:
            self._entries.pop(scope, None)
        return active

    def __len__(self) -> int:
        return len(self._entries)


class ReceiptChainStore:
    """Single-writer local JSONL chain with fsynced write-ahead recovery."""

    def __init__(
        self,
        receipt_dir: str | Path,
        *,
        tenant: str,
        gateway_id: str,
        chain_id: str,
        writer_id: str,
        retention_days: int = 30,
        dedupe_window_days: int | None = None,
    ) -> None:
        if not gateway_id or not writer_id:
            raise ReceiptError("gateway_id and writer_id are required")
        directory, safe_chain = _safe_chain_paths(receipt_dir, tenant, chain_id)
        self.tenant = tenant
        self.gateway_id = gateway_id
        self.chain_id = chain_id
        self.writer_id = writer_id
        self.directory = directory
        self.chain_path = directory / f"{safe_chain}.jsonl"
        self.wal_path = directory / f"{safe_chain}.wal"
        self.epoch_path = directory / f"{safe_chain}.epoch"
        self.lock_path = directory / f".{safe_chain}.lock"
        self.retention_index = RetentionDedupeIndex(retention_days, dedupe_window_days)
        self.writer_epoch: int | None = None
        self._lease: FileLock | None = None
        self._receipts: tuple[GatewayReceipt, ...] = ()
        self._head_hash = GENESIS_HASH
        self._healthy = True
        self._append_lock = threading.RLock()

    @property
    def receipts(self) -> tuple[GatewayReceipt, ...]:
        return self._receipts

    @property
    def head_hash(self) -> str:
        return self._head_hash

    @property
    def lease_held(self) -> bool:
        return self._lease is not None and self._lease.is_locked

    def acquire_writer_lease(self) -> int:
        if self.lease_held:
            raise WriterLeaseError("writer lease is already held")
        directory_existed = self.directory.exists()
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            if not directory_existed:
                _fsync_directory(self.directory.parent)
        except (OSError, ReceiptError) as exc:
            raise WriterLeaseError("cannot create or fsync receipt directory") from exc
        lease = FileLock(str(self.lock_path), timeout=0, is_singleton=False)
        try:
            lease.acquire(timeout=0)
        except Timeout as exc:
            raise WriterLeaseError("another writer holds this receipt chain") from exc
        self._lease = lease
        try:
            verified = self._recover_storage()
            last = verified.receipts[-1] if verified.receipts else None
            if last is not None and last.writer_id != self.writer_id:
                raise WriterLeaseError("writer handoff requires an authenticated handoff record")
            previous_epoch = max(
                last.writer_epoch if last is not None else 0,
                _read_epoch(self.epoch_path),
            )
            self.writer_epoch = previous_epoch + 1
            _write_epoch_atomic(self.epoch_path, self.writer_epoch)
            self._receipts = verified.receipts
            self._head_hash = verified.head_hash
            self.retention_index.rebuild(self._receipts)
            self._healthy = True
            return self.writer_epoch
        except Exception:
            self._lease.release()
            self._lease = None
            self.writer_epoch = None
            raise

    def release_writer_lease(self) -> None:
        lease = self._lease
        self._lease = None
        self.writer_epoch = None
        if lease is not None and lease.is_locked:
            lease.release()

    def __enter__(self) -> ReceiptChainStore:
        self.acquire_writer_lease()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.release_writer_lease()

    def verify(self) -> ChainVerification:
        return verify_jsonl_file(self.chain_path)

    def _verify_prefix(self, data: bytes) -> tuple[ChainVerification, bytes]:
        if not data or data.endswith(b"\n"):
            return verify_jsonl_chain(data), b""
        split = data.rfind(b"\n")
        complete = data[: split + 1] if split >= 0 else b""
        partial = data[split + 1 :]
        return verify_jsonl_chain(complete), partial

    def _validate_store_scope(self, receipt: GatewayReceipt) -> None:
        if (
            receipt.tenant_id != self.tenant
            or receipt.gateway_id != self.gateway_id
            or receipt.chain_id != self.chain_id
        ):
            raise ReceiptChainError("receipt tenant, gateway, or chain does not match this store")

    def _recover_storage(self) -> ChainVerification:
        try:
            chain_data = self.chain_path.read_bytes()
        except FileNotFoundError:
            chain_data = b""
        except OSError as exc:
            raise ReceiptChainError("cannot read receipt chain") from exc
        wal_receipts = _read_wal(self.wal_path)
        for wal_receipt in wal_receipts:
            self._validate_store_scope(wal_receipt)

        prefix, partial = self._verify_prefix(chain_data)
        for stored_receipt in prefix.receipts:
            self._validate_store_scope(stored_receipt)
        proposed = list(prefix.receipts)
        if partial:
            candidates = [
                receipt
                for receipt in wal_receipts
                if receipt.evidence.prev_hash == prefix.head_hash
                and (canonical_json(receipt.model_dump(mode="json")) + b"\n").startswith(partial)
            ]
            if len(candidates) != 1:
                raise ReceiptChainError(
                    "partial JSONL line has no unique matching durable WAL record"
                )
            proposed.append(candidates[0])

        proposed_by_hash = {receipt.evidence.hash: receipt for receipt in proposed}
        proposed_head = proposed[-1].evidence.hash if proposed else GENESIS_HASH
        replay: list[GatewayReceipt] = []
        for wal_receipt in wal_receipts:
            self._validate_store_scope(wal_receipt)
            existing = proposed_by_hash.get(wal_receipt.evidence.hash)
            if existing is not None:
                if canonical_json(existing.model_dump(mode="json")) != canonical_json(
                    wal_receipt.model_dump(mode="json")
                ):
                    raise ReceiptChainError("WAL record conflicts with receipt chain")
                continue
            if wal_receipt.evidence.prev_hash != proposed_head:
                raise ReceiptChainError("WAL replay does not extend the verified chain head")
            replay.append(wal_receipt)
            proposed.append(wal_receipt)
            proposed_by_hash[wal_receipt.evidence.hash] = wal_receipt
            proposed_head = wal_receipt.evidence.hash

        verified = verify_receipt_chain(proposed)
        if verified.receipts and verified.receipts[-1].writer_id != self.writer_id:
            raise WriterLeaseError("writer handoff requires an authenticated handoff record")
        if partial:
            partial_receipt = proposed[len(prefix.receipts)]
            complete_line = canonical_json(partial_receipt.model_dump(mode="json")) + b"\n"
            _append_fsynced(self.chain_path, complete_line[len(partial) :])
        if replay:
            appended = b"".join(
                canonical_json(receipt.model_dump(mode="json")) + b"\n" for receipt in replay
            )
            _append_fsynced(self.chain_path, appended)
        return verified

    def append(self, receipt: GatewayReceipt) -> GatewayReceipt:
        return self.append_many((receipt,))[0]

    def append_many(self, receipts: Iterable[GatewayReceipt]) -> tuple[GatewayReceipt, ...]:
        batch = tuple(receipts)
        if not batch:
            return ()
        with self._append_lock:
            if not self.lease_held or self.writer_epoch is None:
                raise WriterLeaseError("writer lease is not held")
            if not self._healthy:
                raise ReceiptError("receipt sink is unhealthy; reopen after recovery")
            sealed: list[GatewayReceipt] = []
            previous_hash = self._head_hash
            for receipt in batch:
                if receipt.tenant_id != self.tenant or receipt.chain_id != self.chain_id:
                    raise ReceiptError("receipt tenant or chain does not match this store")
                if receipt.gateway_id != self.gateway_id:
                    raise ReceiptError("receipt gateway does not match this store")
                prepared = receipt.model_copy(
                    update={"writer_epoch": self.writer_epoch, "writer_id": self.writer_id}
                )
                sealed_receipt = seal_receipt(prepared, previous_hash)
                sealed.append(sealed_receipt)
                previous_hash = sealed_receipt.evidence.hash
            wal_data = b"".join(_wal_line(receipt) for receipt in sealed)
            jsonl_data = b"".join(
                canonical_json(receipt.model_dump(mode="json")) + b"\n" for receipt in sealed
            )
            try:
                # A batch is one group commit: all WAL records are fsynced before
                # any receipt in the batch is appended to the authoritative JSONL.
                _append_fsynced(self.wal_path, wal_data)
                _append_fsynced(self.chain_path, jsonl_data)
            except ReceiptError:
                self._healthy = False
                raise
            self._receipts += tuple(sealed)
            self._head_hash = previous_hash
            self.retention_index.rebuild(self._receipts)
            return tuple(sealed)

    def close(self) -> None:
        self.release_writer_lease()
