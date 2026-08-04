"""Dormant trusted-host creation of configured private-read requests.

This module resolves a bounded model capability identifier against immutable
host configuration and creates only durable pending authorization state. It
does not evaluate policy, send a challenge, read private data, or deliver a
sensitive value.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Protocol

from gateway.authorization_contracts import (
    MAX_FIELDS,
    NotificationAttemptSpec,
    TrustedAuthorizationBinding,
)
from gateway.authorization_tasks import AuthorizationTaskStore


MAX_CAPABILITY_ID_BYTES = 128
MAX_CONFIGURED_CAPABILITIES = 64
SQLITE_SIGNED_INT64_MAX = (1 << 63) - 1
_MAX_CONTEXT_ID_BYTES = 256
_MAX_OPERATION_BYTES = 128
_MAX_RESOURCE_TYPE_BYTES = 128
_MAX_FIELD_BYTES = 128
_MAX_ID_HMAC_KEY_BYTES = 4_096
_SOURCE_PROVENANCE = frozenset(
    {
        "authenticated_inbound",
        "authenticated_api",
        "authenticated_internal",
    }
)


class PrivateReadAuthorizationError(RuntimeError):
    """A content-free orchestration failure safe for a terminal boundary."""


def _bounded_text(value: object, label: str, *, maximum: int) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError(f"{label} must be an exact non-empty bounded string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(
            f"{label} must be an exact non-empty bounded string"
        ) from None
    if len(encoded) > maximum:
        raise ValueError(f"{label} must be an exact non-empty bounded string")
    return value


def _positive_epoch_us(value: object, label: str) -> int:
    if (
        type(value) is not int
        or value < 1
        or value > SQLITE_SIGNED_INT64_MAX
    ):
        raise ValueError(
            f"{label} must be a positive signed SQLite 64-bit UTC epoch "
            "in microseconds"
        )
    return value


def _lower_hex(value: object, label: str) -> str:
    text = _bounded_text(value, label, maximum=64)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise ValueError(f"{label} must be 64 lowercase hexadecimal characters")
    return text


@dataclass(frozen=True, slots=True)
class TrustedPrivateReadHostContext:
    """Exact request-local identities supplied by the authenticated host."""

    requester_profile: str
    requester_agent: str
    source_platform: str
    source_account: str
    source_user: str
    source_chat: str
    source_thread: str
    source_message: str
    source_provenance: str
    resource_id: str
    approval_profile: str
    approval_account: str
    approval_user: str
    approval_chat: str
    approval_thread: str
    delivery_profile: str
    delivery_platform: str
    delivery_account: str
    delivery_chat: str
    delivery_thread: str
    delivery_transport_implementation: str
    delivery_runtime_identity: str
    delivery_account_binding: str
    delivery_connection_epoch: int
    created_at_us: int
    expires_at_us: int
    pdp_identity: str
    policy_identity: str
    policy_version: str
    policy_hash: str
    model_identity: str

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            if field.name in {
                "delivery_connection_epoch",
                "created_at_us",
                "expires_at_us",
            }:
                continue
            value = getattr(self, field.name)
            if field.name == "policy_hash":
                _lower_hex(value, field.name)
            else:
                _bounded_text(value, field.name, maximum=_MAX_CONTEXT_ID_BYTES)
        if self.source_provenance not in _SOURCE_PROVENANCE:
            raise ValueError("source_provenance must be authenticated host provenance")
        _positive_epoch_us(self.delivery_connection_epoch, "delivery_connection_epoch")
        _positive_epoch_us(self.created_at_us, "created_at_us")
        _positive_epoch_us(self.expires_at_us, "expires_at_us")
        if self.expires_at_us <= self.created_at_us:
            raise ValueError("expires_at_us must be after created_at_us")

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            dataclasses.asdict(self),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class PrivateReadCapabilitySpec:
    """One exact host-configured capability, never constructed by the model."""

    capability_id: str
    operation: str
    resource_type: str
    fields: tuple[str, ...]

    def __post_init__(self) -> None:
        _bounded_text(
            self.capability_id,
            "capability_id",
            maximum=MAX_CAPABILITY_ID_BYTES,
        )
        _bounded_text(self.operation, "operation", maximum=_MAX_OPERATION_BYTES)
        _bounded_text(
            self.resource_type,
            "resource_type",
            maximum=_MAX_RESOURCE_TYPE_BYTES,
        )
        if type(self.fields) is not tuple or not self.fields:
            raise ValueError("fields must be an exact non-empty bounded tuple")
        if len(self.fields) > MAX_FIELDS:
            raise ValueError("fields must be an exact non-empty bounded tuple")
        seen: set[str] = set()
        for field in self.fields:
            value = _bounded_text(field, "field", maximum=_MAX_FIELD_BYTES)
            if value in seen:
                raise ValueError("fields must be unique")
            seen.add(value)

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "capability_id": self.capability_id,
                "fields": list(self.fields),
                "operation": self.operation,
                "resource_type": self.resource_type,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class PrivateReadCapabilityRegistry:
    """Bounded immutable registry materialized entirely by the trusted host."""

    capabilities: tuple[PrivateReadCapabilitySpec, ...]

    def __post_init__(self) -> None:
        if type(self.capabilities) is not tuple:
            raise TypeError("configured capabilities must be an exact bounded tuple")
        if not self.capabilities or len(self.capabilities) > MAX_CONFIGURED_CAPABILITIES:
            raise ValueError("configured capabilities must be a non-empty bounded tuple")
        seen: set[str] = set()
        for capability in self.capabilities:
            if type(capability) is not PrivateReadCapabilitySpec:
                raise TypeError("configured capability has an invalid type")
            if capability.capability_id in seen:
                raise ValueError("configured capability IDs must be unique")
            seen.add(capability.capability_id)

    def resolve(self, capability_id: object) -> PrivateReadCapabilitySpec:
        exact_id = _bounded_text(
            capability_id,
            "capability_id",
            maximum=MAX_CAPABILITY_ID_BYTES,
        )
        for capability in self.capabilities:
            if capability.capability_id == exact_id:
                return capability
        raise ValueError("capability_id is not configured")


@dataclass(frozen=True, slots=True)
class PrivateReadProposal:
    """The complete, closed model-controlled surface."""

    capability_id: str

    def __post_init__(self) -> None:
        _bounded_text(
            self.capability_id,
            "capability_id",
            maximum=MAX_CAPABILITY_ID_BYTES,
        )

    @classmethod
    def from_model_args(cls, args: object) -> "PrivateReadProposal":
        if type(args) is not dict or len(args) != 1:
            raise ValueError("private read arguments do not match the reviewed shape")
        keys = tuple(args.keys())
        if type(keys[0]) is not str or keys[0] != "capability_id":
            raise ValueError("private read arguments do not match the reviewed shape")
        return cls(capability_id=args[keys[0]])


@dataclass(frozen=True, slots=True)
class PendingAuthorizationRequest:
    task_id: str
    correlation_id: str
    status: str
    idempotent: bool

    def __post_init__(self) -> None:
        _bounded_text(self.task_id, "task_id", maximum=_MAX_CONTEXT_ID_BYTES)
        _bounded_text(
            self.correlation_id,
            "correlation_id",
            maximum=_MAX_CONTEXT_ID_BYTES,
        )
        if self.status != "approval_required":
            raise ValueError("initial authorization status must require approval")


class TrustedHostContextProvider(Protocol):
    """Request-local authenticated context supplied by the host service."""

    def current(self) -> TrustedPrivateReadHostContext | None: ...


@dataclass(frozen=True, slots=True)
class PrivateReadRequestRuntime:
    """Complete host configuration required before the tool is available."""

    store: AuthorizationTaskStore
    id_hmac_key: bytes
    host_contexts: TrustedHostContextProvider
    capabilities: PrivateReadCapabilityRegistry
    enabled: bool = False

    def __post_init__(self) -> None:
        if type(self.store) is not AuthorizationTaskStore:
            raise TypeError("private read request store has an invalid type")
        if (
            type(self.id_hmac_key) is not bytes
            or len(self.id_hmac_key) < 32
            or len(self.id_hmac_key) > _MAX_ID_HMAC_KEY_BYTES
        ):
            raise ValueError("private read request ID key must be bounded and at least 32 bytes")
        if self.host_contexts is None or not callable(
            getattr(self.host_contexts, "current", None)
        ):
            raise TypeError("private read request host context provider is incomplete")
        if type(self.capabilities) is not PrivateReadCapabilityRegistry:
            raise TypeError("private read capability registry has an invalid type")
        if type(self.enabled) is not bool:
            raise TypeError("private read request enabled flag must be boolean")


def _opaque_hmac(key: bytes, domain: bytes, value: bytes, *, size: int = 48) -> str:
    return hmac.new(key, domain + b"\0" + value, hashlib.sha256).hexdigest()[:size]


class PrivateReadAuthorizationOrchestrator:
    """Create an exact, payload-free pending task and challenge atomically."""

    def __init__(self, store: AuthorizationTaskStore, *, id_hmac_key: bytes) -> None:
        if type(store) is not AuthorizationTaskStore:
            raise TypeError("authorization task store has an invalid type")
        if (
            type(id_hmac_key) is not bytes
            or len(id_hmac_key) < 32
            or len(id_hmac_key) > _MAX_ID_HMAC_KEY_BYTES
        ):
            raise ValueError("authorization ID key must be bounded and at least 32 bytes")
        self._store = store
        self._id_hmac_key = bytes(id_hmac_key)

    def create_pending(
        self,
        capability: PrivateReadCapabilitySpec,
        *,
        host_context: TrustedPrivateReadHostContext,
        tool_call_id: str,
    ) -> PendingAuthorizationRequest:
        if type(capability) is not PrivateReadCapabilitySpec:
            raise TypeError("configured private read capability required")
        if type(host_context) is not TrustedPrivateReadHostContext:
            raise TypeError("trusted private read host context required")
        exact_tool_call_id = _bounded_text(
            tool_call_id,
            "tool_call_id",
            maximum=_MAX_CONTEXT_ID_BYTES,
        )

        capability_bytes = capability.canonical_bytes()
        parameter_fingerprint = hashlib.sha256(capability_bytes).hexdigest()
        request_material = b"\0".join(
            (
                capability_bytes,
                host_context.canonical_bytes(),
                exact_tool_call_id.encode("utf-8"),
            )
        )
        task_id = "task-" + _opaque_hmac(
            self._id_hmac_key, b"private-read-request-task-v1", request_material
        )
        correlation_id = "corr-" + _opaque_hmac(
            self._id_hmac_key,
            b"private-read-request-correlation-v1",
            request_material,
        )
        request_key = "private-read-request:v1:" + _opaque_hmac(
            self._id_hmac_key,
            b"private-read-request-key-v1",
            request_material,
        )
        attempt_id = "attempt-" + _opaque_hmac(
            self._id_hmac_key,
            b"private-read-request-attempt-v1",
            request_material,
        )
        challenge_nonce = _opaque_hmac(
            self._id_hmac_key,
            b"private-read-request-challenge-v1",
            request_material,
            size=64,
        )

        binding = TrustedAuthorizationBinding(
            task_id=task_id,
            correlation_id=correlation_id,
            tool_call_id=exact_tool_call_id,
            requester_profile=host_context.requester_profile,
            requester_agent=host_context.requester_agent,
            source_platform=host_context.source_platform,
            source_account=host_context.source_account,
            source_user=host_context.source_user,
            source_chat=host_context.source_chat,
            source_thread=host_context.source_thread,
            source_message=host_context.source_message,
            source_provenance=host_context.source_provenance,
            operation=capability.operation,
            resource_type=capability.resource_type,
            resource_id=host_context.resource_id,
            fields=capability.fields,
            parameter_fingerprint=parameter_fingerprint,
            approval_profile=host_context.approval_profile,
            approval_account=host_context.approval_account,
            approval_user=host_context.approval_user,
            approval_chat=host_context.approval_chat,
            approval_thread=host_context.approval_thread,
            delivery_profile=host_context.delivery_profile,
            delivery_account=host_context.delivery_account,
            delivery_chat=host_context.delivery_chat,
            delivery_thread=host_context.delivery_thread,
            created_at_us=host_context.created_at_us,
            expires_at_us=host_context.expires_at_us,
            pdp_identity=host_context.pdp_identity,
            policy_identity=host_context.policy_identity,
            model_identity=host_context.model_identity,
            delivery_platform=host_context.delivery_platform,
            delivery_transport_implementation=(
                host_context.delivery_transport_implementation
            ),
            delivery_runtime_identity=host_context.delivery_runtime_identity,
            delivery_account_binding=host_context.delivery_account_binding,
            delivery_connection_epoch=host_context.delivery_connection_epoch,
            policy_version=host_context.policy_version,
            policy_hash=host_context.policy_hash,
        )
        notification = NotificationAttemptSpec(
            attempt_id=attempt_id,
            challenge_generation=1,
            kind="approval_challenge",
            destination_profile=host_context.approval_profile,
            destination_account=host_context.approval_account,
            destination_chat=host_context.approval_chat,
            destination_thread=host_context.approval_thread,
            created_at_us=host_context.created_at_us,
            due_at_us=host_context.created_at_us,
            challenge_nonce=challenge_nonce,
        )
        mutation = None
        try:
            mutation = self._store.create_pending(
                binding,
                request_key=request_key,
                notification=notification,
            )
        except BaseException:
            # Construct the bounded failure after leaving the handler so a
            # provider exception and its potentially private arguments are
            # not retained as ``__context__``.
            pass
        if (
            mutation is None
            or not mutation.applied
            or mutation.task is None
            or mutation.task.status != "approval_required"
        ):
            raise PrivateReadAuthorizationError(
                "authorization request creation failed"
            ) from None
        return PendingAuthorizationRequest(
            task_id=mutation.task.task_id,
            correlation_id=mutation.task.correlation_id,
            status="approval_required",
            idempotent=mutation.idempotent,
        )


__all__ = [
    "MAX_CAPABILITY_ID_BYTES",
    "MAX_CONFIGURED_CAPABILITIES",
    "SQLITE_SIGNED_INT64_MAX",
    "PendingAuthorizationRequest",
    "PrivateReadAuthorizationError",
    "PrivateReadAuthorizationOrchestrator",
    "PrivateReadCapabilityRegistry",
    "PrivateReadCapabilitySpec",
    "PrivateReadProposal",
    "PrivateReadRequestRuntime",
    "TrustedHostContextProvider",
    "TrustedPrivateReadHostContext",
]
