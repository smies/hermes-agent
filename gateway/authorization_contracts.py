"""Immutable bounded contracts for the durable authorization store."""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from typing import Optional

SCHEMA_VERSION = 7
MAX_ID = 256
MAX_FIELDS = 64
MAX_RETRIES = 8
# Security bounds for durable notification authority.  These are deliberately
# independent of SQLite lock retry policy: neither coordinator restarts nor a
# hostile sequence of definitive failures may create unbounded work.
MAX_NOTIFICATION_CLAIM_GENERATIONS = 8
MAX_NOTIFICATION_RETRY_ORDINAL = 8
# Audit verification reads the complete authenticated task chain.  Bound the
# durable chain explicitly so verification cannot be turned into unbounded
# memory or CPU work by a corrupted database.
MAX_AUDIT_EVENTS_PER_TASK = 100_000

TASK_TRANSITIONS: dict[str, set[str]] = {
    "approval_required": {"approved", "denied", "expired", "canceled"},
    "approved": {"claimed", "denied", "expired", "canceled"},
    "claimed": {"consumed", "failed_consumed"},
    "consumed": set(),
    "denied": set(),
    "expired": set(),
    "canceled": set(),
    "failed_consumed": set(),
}


class AuthorizationStoreError(RuntimeError):
    """Base error with deliberately path- and payload-free messages."""


class UnsafeAuthorizationStorePath(AuthorizationStoreError):
    """The host-supplied database path failed ownership/type/mode checks."""


class CoordinatorFenceError(AuthorizationStoreError):
    """No live singleton coordinator lease matches the local epoch fence."""


class AuthorizationIntegrityError(AuthorizationStoreError):
    """A requested durable row failed authenticated reconstruction."""


def _bounded(value: str, label: str, *, maximum: int = MAX_ID) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{label} must be a non-empty bounded string")
    if "\x00" in value:
        raise ValueError(f"{label} must be a non-empty bounded string")
    return value


def _epoch_us(value: int, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be integer UTC epoch microseconds")
    return value


@dataclass(frozen=True)
class TrustedAuthorizationBinding:
    """One validated immutable request plus authenticated transport bindings.

    Construction is intentionally typed rather than dictionary merging: model
    proposals cannot supply or override identity and destination properties at
    this persistence boundary.
    """

    task_id: str
    correlation_id: str
    tool_call_id: str
    requester_profile: str
    requester_agent: str
    source_platform: str
    source_account: str
    source_user: str
    source_chat: str
    source_thread: str
    source_message: str
    source_provenance: str
    operation: str
    resource_type: str
    resource_id: str
    fields: tuple[str, ...]
    parameter_fingerprint: str
    approval_profile: str
    approval_account: str
    approval_user: str
    approval_chat: str
    approval_thread: str
    delivery_profile: str
    delivery_account: str
    delivery_chat: str
    delivery_thread: str
    created_at_us: int
    expires_at_us: int
    pdp_identity: str
    policy_identity: str
    model_identity: str
    delivery_platform: str = ""
    delivery_transport_implementation: str = ""
    delivery_runtime_identity: str = ""
    delivery_account_binding: str = ""
    delivery_connection_epoch: int = 0
    policy_version: str = ""
    policy_hash: str = ""

    def __post_init__(self) -> None:
        extension_values = (
            self.delivery_platform,
            self.delivery_transport_implementation,
            self.delivery_runtime_identity,
            self.delivery_account_binding,
            self.policy_version,
            self.policy_hash,
        )
        legacy = all(value == "" for value in extension_values) and self.delivery_connection_epoch == 0
        current = all(value != "" for value in extension_values) and (
            isinstance(self.delivery_connection_epoch, int)
            and not isinstance(self.delivery_connection_epoch, bool)
            and self.delivery_connection_epoch > 0
        )
        if not (legacy or current):
            raise ValueError("delivery authorization binding must be complete")
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if field.name in {
                "fields",
                "created_at_us",
                "expires_at_us",
                "delivery_connection_epoch",
            }:
                continue
            if legacy and field.name in {
                "delivery_platform",
                "delivery_transport_implementation",
                "delivery_runtime_identity",
                "delivery_account_binding",
                "policy_version",
                "policy_hash",
            }:
                continue
            _bounded(value, field.name)
        _epoch_us(self.created_at_us, "created_at_us")
        _epoch_us(self.expires_at_us, "expires_at_us")
        if self.expires_at_us <= self.created_at_us:
            raise ValueError("expiry must be after creation")
        if not isinstance(self.fields, tuple) or not self.fields or len(self.fields) > MAX_FIELDS:
            raise ValueError("fields must be a non-empty bounded tuple")
        normalized = tuple(sorted(set(self.fields)))
        if len(normalized) != len(self.fields):
            raise ValueError("fields must be unique")
        for value in normalized:
            _bounded(value, "field", maximum=128)
        object.__setattr__(self, "fields", normalized)
        if len(self.parameter_fingerprint) != 64 or any(
            char not in "0123456789abcdef" for char in self.parameter_fingerprint
        ):
            raise ValueError("parameter_fingerprint must be 64 lowercase hex characters")
        if not legacy and (len(self.policy_hash) != 64 or any(
            char not in "0123456789abcdef" for char in self.policy_hash
        )):
            raise ValueError("policy_hash must be 64 lowercase hex characters")
        if self.source_provenance not in {
            "authenticated_inbound",
            "authenticated_api",
            "authenticated_internal",
        }:
            raise ValueError("unsupported authenticated source provenance")

    def canonical_bytes(self) -> bytes:
        data = dataclasses.asdict(self)
        if self._legacy_delivery_binding:
            for name in (
                "delivery_platform",
                "delivery_transport_implementation",
                "delivery_runtime_identity",
                "delivery_account_binding",
                "delivery_connection_epoch",
                "policy_version",
                "policy_hash",
            ):
                data.pop(name)
        data["fields"] = list(self.fields)
        return json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @property
    def has_delivery_acceptance_binding(self) -> bool:
        return not self._legacy_delivery_binding

    @property
    def _legacy_delivery_binding(self) -> bool:
        return self.delivery_connection_epoch == 0 and all(
            value == ""
            for value in (
                self.delivery_platform,
                self.delivery_transport_implementation,
                self.delivery_runtime_identity,
                self.delivery_account_binding,
                self.policy_version,
                self.policy_hash,
            )
        )


@dataclass(frozen=True)
class OwnerDecision:
    decision_id: str
    task_id: str
    correlation_id: str
    owner_profile: str
    owner_account: str
    owner_user: str
    owner_chat: str
    owner_thread: str
    source_message: str
    provenance: str
    challenge_attempt_id: str
    challenge_generation: int
    challenge_nonce: str
    challenge_provider_message_id: str
    reply_to_provider_message_id: str
    adapter_instance_id: str
    account_binding: str
    connection_epoch: int

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            if field.name in {"challenge_generation", "connection_epoch"}:
                continue
            _bounded(getattr(self, field.name), field.name)
        if (
            not isinstance(self.challenge_generation, int)
            or isinstance(self.challenge_generation, bool)
            or self.challenge_generation < 1
        ):
            raise ValueError("challenge_generation must be a positive integer")
        if (
            not isinstance(self.connection_epoch, int)
            or isinstance(self.connection_epoch, bool)
            or self.connection_epoch < 1
        ):
            raise ValueError("connection_epoch must be a positive integer")
        if self.provenance != "authenticated_reply":
            raise ValueError("owner decision requires authenticated reply provenance")
        if len(self.challenge_nonce) < 32:
            raise ValueError("challenge nonce must be at least 32 characters")

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            dataclasses.asdict(self), sort_keys=True, separators=(",", ":")
        ).encode()


@dataclass(frozen=True)
class ClaimIdentity:
    owner_profile: str
    owner_agent: str
    owner_account: str
    nonce: str
    generation: int

    def __post_init__(self) -> None:
        for name in ("owner_profile", "owner_agent", "owner_account", "nonce"):
            _bounded(getattr(self, name), name)
        if not isinstance(self.generation, int) or isinstance(self.generation, bool) or self.generation < 1:
            raise ValueError("claim generation must be a positive integer")

    def owner_bytes(self) -> bytes:
        return json.dumps(
            {
                "owner_account": self.owner_account,
                "owner_agent": self.owner_agent,
                "owner_profile": self.owner_profile,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


@dataclass(frozen=True)
class CoordinatorIdentity:
    owner_id: str
    nonce: str

    def __post_init__(self) -> None:
        _bounded(self.owner_id, "coordinator owner_id")
        _bounded(self.nonce, "coordinator nonce")
        if len(self.nonce) < 32:
            raise ValueError("coordinator nonce must be at least 32 characters")


@dataclass(frozen=True)
class CoordinatorFence:
    owner_digest: str
    nonce_digest: str
    key_version: str
    epoch: int
    lease_expires_at_us: int


@dataclass(frozen=True)
class AuthorizationTask:
    task_id: str
    correlation_id: str
    status: str
    request_digest: str
    created_at_us: int
    expires_at_us: int
    version: int
    claim_generation: Optional[int] = None
    claim_lease_expires_at_us: Optional[int] = None
    send_started_at_us: Optional[int] = None
    completed_at_us: Optional[int] = None
    receipt_code: Optional[str] = None
    winning_challenge_attempt_id: Optional[str] = None
    winning_challenge_generation: Optional[int] = None


@dataclass(frozen=True)
class AuthorizationTaskWorkItem:
    """Authenticated, payload-free task metadata for a trusted worker."""

    binding: TrustedAuthorizationBinding
    task: AuthorizationTask
    key_version: str
    binding_digest: str

    def __post_init__(self) -> None:
        if type(self.binding) is not TrustedAuthorizationBinding:
            raise TypeError("exact trusted authorization binding is required")
        if type(self.task) is not AuthorizationTask:
            raise TypeError("exact authorization task is required")
        _bounded(self.key_version, "key_version", maximum=64)
        _bounded(self.binding_digest, "binding_digest")
        for name in ("task_id", "correlation_id", "status", "request_digest"):
            _bounded(getattr(self.task, name), name)
        if self.task.status not in TASK_TRANSITIONS:
            raise ValueError("unsupported authorization task status")
        for name in ("created_at_us", "expires_at_us", "version"):
            value = getattr(self.task, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.task.version < 1:
            raise ValueError("version must be a positive integer")
        for name in (
            "claim_generation", "claim_lease_expires_at_us", "send_started_at_us",
            "completed_at_us", "winning_challenge_generation",
        ):
            value = getattr(self.task, name)
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"{name} must be an optional non-negative integer")
        if (
            self.task.task_id != self.binding.task_id
            or self.task.correlation_id != self.binding.correlation_id
        ):
            raise ValueError("task work item identity is inconsistent")

    @property
    def task_id(self) -> str:
        return self.binding.task_id

    @property
    def correlation_id(self) -> str:
        return self.binding.correlation_id

    @property
    def tool_call_id(self) -> str:
        return self.binding.tool_call_id


@dataclass(frozen=True)
class MutationResult:
    applied: bool
    idempotent: bool = False
    task: Optional[AuthorizationTask] = None


@dataclass(frozen=True)
class NotificationAttemptSpec:
    attempt_id: str
    challenge_generation: int
    kind: str
    destination_profile: str
    destination_account: str
    destination_chat: str
    destination_thread: str
    created_at_us: int
    due_at_us: int
    challenge_nonce: str

    def __post_init__(self) -> None:
        for name in (
            "attempt_id",
            "destination_profile",
            "destination_account",
            "destination_chat",
            "destination_thread",
        ):
            _bounded(getattr(self, name), name)
        if self.kind not in {"approval_challenge", "approval_resolution"}:
            raise ValueError("unsupported notification kind")
        if (
            not isinstance(self.challenge_generation, int)
            or isinstance(self.challenge_generation, bool)
            or self.challenge_generation < 1
        ):
            raise ValueError("challenge_generation must be a positive integer")
        _bounded(self.challenge_nonce, "challenge_nonce")
        if self.kind == "approval_challenge" and len(self.challenge_nonce) < 32:
            raise ValueError("approval challenge nonce must be at least 32 characters")
        _epoch_us(self.created_at_us, "created_at_us")
        _epoch_us(self.due_at_us, "due_at_us")
        if self.due_at_us < self.created_at_us:
            raise ValueError("notification due time cannot precede creation")

    def destination_bytes(self) -> bytes:
        return json.dumps(
            {
                "account": self.destination_account,
                "chat": self.destination_chat,
                "profile": self.destination_profile,
                "thread": self.destination_thread,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


@dataclass(frozen=True)
class NotificationAttempt:
    attempt_id: str
    task_id: str
    kind: str
    status: str
    created_at_us: int
    due_at_us: int
    version: int
    claim_generation: Optional[int] = None
    claim_lease_expires_at_us: Optional[int] = None
    send_started_at_us: Optional[int] = None
    completed_at_us: Optional[int] = None
    receipt_code: Optional[str] = None
    challenge_generation: int = 1
    challenge_state: str = "unaccepted"
    provider_accepted_at_us: Optional[int] = None
    retry_ordinal: int = 1
    supersedes_attempt_id: Optional[str] = None


@dataclass(frozen=True)
class AuthorizationNotificationWorkItem:
    """Authenticated, payload-free notification metadata for a trusted worker.

    The raw challenge nonce is deliberately absent. ``task_id``, ``attempt_id``,
    generation, and key version are sufficient inputs for a later host nonce
    authority to regenerate it deterministically.
    """

    binding: TrustedAuthorizationBinding
    notification: NotificationAttempt
    correlation_id: str
    request_digest: str
    key_version: str
    binding_digest: str
    nonce_verifier_version: str
    destination_profile: str
    destination_account: str
    destination_chat: str
    destination_thread: str

    def __post_init__(self) -> None:
        if type(self.binding) is not TrustedAuthorizationBinding:
            raise TypeError("exact trusted authorization binding is required")
        if type(self.notification) is not NotificationAttempt:
            raise TypeError("exact notification attempt is required")
        for name in (
            "correlation_id",
            "request_digest",
            "key_version",
            "binding_digest",
            "nonce_verifier_version",
            "destination_profile",
            "destination_account",
            "destination_chat",
            "destination_thread",
        ):
            _bounded(getattr(self, name), name)
        for name in ("attempt_id", "task_id", "kind", "status"):
            _bounded(getattr(self.notification, name), name)
        if self.notification.kind not in {"approval_challenge", "approval_resolution"}:
            raise ValueError("unsupported notification kind")
        if self.notification.status not in {
            "pending", "claimed", "provider_accepted", "failed"
        }:
            raise ValueError("unsupported notification status")
        for name in ("created_at_us", "due_at_us"):
            value = getattr(self.notification, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        for name in ("version", "challenge_generation", "retry_ordinal"):
            value = getattr(self.notification, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name in (
            "claim_generation", "claim_lease_expires_at_us", "send_started_at_us",
            "completed_at_us", "provider_accepted_at_us",
        ):
            value = getattr(self.notification, name)
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"{name} must be an optional non-negative integer")
        if (
            self.notification.task_id != self.binding.task_id
            or self.correlation_id != self.binding.correlation_id
        ):
            raise ValueError("notification work item identity is inconsistent")

    @property
    def task_id(self) -> str:
        return self.binding.task_id

    @property
    def attempt_id(self) -> str:
        return self.notification.attempt_id

    @property
    def challenge_generation(self) -> int:
        return self.notification.challenge_generation

    @property
    def tool_call_id(self) -> str:
        return self.binding.tool_call_id


@dataclass(frozen=True)
class ProviderAcceptanceEvidence:
    """Content-free evidence returned by a separately audited adapter.

    Provider acceptance is not evidence of recipient delivery or read.
    """

    task_id: str
    correlation_id: str
    attempt_id: str
    challenge_generation: int
    worker_claim_generation: int
    status: str
    provider_message_id: str
    accepted_at_us: int
    adapter_instance_id: str
    account_binding: str
    connection_epoch: int
    destination_profile: str
    destination_account: str
    destination_chat: str
    destination_thread: str

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            if field.name in {
                "challenge_generation",
                "worker_claim_generation",
                "accepted_at_us",
                "connection_epoch",
            }:
                continue
            _bounded(getattr(self, field.name), field.name)
        if self.status != "provider_accepted":
            raise ValueError("provider acceptance status must be provider_accepted")
        _epoch_us(self.accepted_at_us, "accepted_at_us")
        for name in (
            "challenge_generation",
            "worker_claim_generation",
            "connection_epoch",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class PdpDecisionEvidence:
    """Bounded authoritative evidence assembled by the store factory."""

    evidence_id: str
    stage: str
    decision: str
    request_digest: str
    model_identity: str
    policy_revision: str
    checked_at_us: int
    consistency: str
    pdp_call_id: str
    context_id: str
    cache_used: bool
    task_id: str
    binding_digest: str
    key_version: str
    coordinator_owner_id: str
    coordinator_nonce: str
    coordinator_epoch: int
    worker_profile: str
    worker_agent: str
    worker_account: str
    claim_nonce: str
    claim_generation: int
    factory_seal: str

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            if field.name in {
                "checked_at_us",
                "cache_used",
                "coordinator_epoch",
                "claim_generation",
            }:
                continue
            _bounded(getattr(self, field.name), field.name)
        _epoch_us(self.checked_at_us, "checked_at_us")
        if self.stage not in {"pre_claim", "pre_private_read"}:
            raise ValueError("unsupported PDP check stage")
        if self.decision not in {"allow", "deny", "failure"}:
            raise ValueError("unsupported PDP decision")
        if self.consistency not in {"strongest", "unknown"}:
            raise ValueError("unsupported PDP consistency indicator")
        if not isinstance(self.cache_used, bool):
            raise ValueError("cache_used must be boolean")
        for name in ("coordinator_epoch", "claim_generation"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class AuthorizationPdpCheckContext:
    """Store-authenticated immutable input for one external PDP check.

    Adapters must send :attr:`consistency_preference` on every call.  This is
    the OpenFGA ``HIGHER_CONSISTENCY`` request preference; it is not described
    as server-issued linearizability or a server attestation.
    """

    context_id: str
    pdp_call_id: str
    stage: str
    created_at_us: int
    task_version: int
    task_status: str
    binding: TrustedAuthorizationBinding
    request_digest: str
    binding_digest: str
    key_version: str
    model_identity: str
    policy_identity: str
    coordinator_owner_id: str
    coordinator_epoch: int
    worker_profile: str
    worker_agent: str
    worker_account: str
    claim_generation: int

    def __post_init__(self) -> None:
        if type(self.binding) is not TrustedAuthorizationBinding:
            raise TypeError("exact trusted authorization binding is required")
        for field in dataclasses.fields(self):
            if field.name in {
                "binding", "created_at_us", "task_version", "coordinator_epoch",
                "claim_generation",
            }:
                continue
            _bounded(getattr(self, field.name), field.name)
        _epoch_us(self.created_at_us, "created_at_us")
        if self.stage not in {"pre_claim", "pre_private_read"}:
            raise ValueError("unsupported PDP check stage")
        for name in ("task_version", "coordinator_epoch", "claim_generation"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.model_identity != self.binding.model_identity:
            raise ValueError("PDP context model identity is inconsistent")
        if self.policy_identity != self.binding.policy_identity:
            raise ValueError("PDP context policy identity is inconsistent")

    @property
    def task_id(self) -> str:
        return self.binding.task_id

    @property
    def correlation_id(self) -> str:
        return self.binding.correlation_id

    @property
    def tool_call_id(self) -> str:
        return self.binding.tool_call_id

    @property
    def consistency_preference(self) -> str:
        return "HIGHER_CONSISTENCY"


@dataclass(frozen=True)
class ExternalPdpDecisionResult:
    """The bounded result returned by the sole external PDP adapter.

    ``context_id`` and ``pdp_call_id`` must echo the exact host-generated
    outbound request. The call ID is generated by the host and is not issued
    by the PDP server.
    ``consistency='strongest'`` records the audited outbound request mode:
    the adapter sent the required ``HIGHER_CONSISTENCY`` preference (or a
    strictly stronger provider mode). It does not claim server-issued
    linearizability. ``cache_used=False`` records local client and
    application-cache behavior, not a server attestation.
    """

    context_id: str
    pdp_call_id: str
    decision: str
    checked_at_us: int
    consistency: str
    cache_used: bool

    def __post_init__(self) -> None:
        _bounded(self.context_id, "context_id")
        _bounded(self.pdp_call_id, "pdp_call_id")
        _epoch_us(self.checked_at_us, "checked_at_us")
        if self.decision not in {"allow", "deny", "failure"}:
            raise ValueError("unsupported PDP decision")
        if self.consistency not in {"strongest", "unknown"}:
            raise ValueError("unsupported PDP consistency indicator")
        if type(self.cache_used) is not bool:
            raise ValueError("cache_used must be boolean")


@dataclass(frozen=True)
class DeliveryAcceptanceEvidence:
    """Immutable, payload-free evidence for the task's delivery acceptance."""

    task_id: str
    correlation_id: str
    operation: str
    request_digest: str
    request_key_version: str
    policy_version: str
    policy_hash: str
    worker_profile: str
    worker_agent: str
    worker_account: str
    claim_nonce: str
    claim_generation: int
    delivery_profile: str
    delivery_platform: str
    delivery_account: str
    delivery_chat: str
    delivery_thread: str
    transport_implementation: str
    runtime_identity: str
    account_binding: str
    connection_epoch: int
    provider_message_id: str
    status: str
    accepted_at_us: int

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            if field.name in {"claim_generation", "connection_epoch", "accepted_at_us"}:
                continue
            _bounded(getattr(self, field.name), field.name)
        if self.status != "provider_accepted":
            raise ValueError("delivery acceptance status must be provider_accepted")
        _epoch_us(self.accepted_at_us, "accepted_at_us")
        for name in ("claim_generation", "connection_epoch"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if len(self.policy_hash) != 64 or any(
            char not in "0123456789abcdef" for char in self.policy_hash
        ):
            raise ValueError("policy_hash must be 64 lowercase hex characters")


@dataclass(frozen=True)
class NotificationMutationResult:
    applied: bool
    idempotent: bool = False
    attempt: Optional[NotificationAttempt] = None


@dataclass(frozen=True)
class ReconciliationReport:
    tasks_failed_consumed: int
    notifications_failed: int


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    task_id: str
    kind: str
    reason_code: str
    actor_token: str
    target_token: str
    request_digest: str
    key_version: str
    occurred_at_us: int
    audit_sequence: int
    previous_record_digest: str
