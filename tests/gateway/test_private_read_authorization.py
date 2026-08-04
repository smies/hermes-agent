"""Durable and privacy invariants for dormant private-read authorization."""

from __future__ import annotations

import dataclasses
import json
import sqlite3
from pathlib import Path

import pytest

from gateway.authorization_contracts import CoordinatorIdentity, MAX_FIELDS
from gateway.authorization_tasks import AuthorizationTaskStore
from gateway.private_read_authorization import (
    MAX_CAPABILITY_ID_BYTES,
    MAX_CONFIGURED_CAPABILITIES,
    SQLITE_SIGNED_INT64_MAX,
    PrivateReadAuthorizationError,
    PrivateReadAuthorizationOrchestrator,
    PrivateReadCapabilityRegistry,
    PrivateReadCapabilitySpec,
    PrivateReadProposal,
    PrivateReadRequestRuntime,
    TrustedPrivateReadHostContext,
)


PRIVATE_SENTINEL = "PRIVATE-VALUE-MUST-NEVER-CROSS-REQUEST-BOUNDARY"
AUDIT_KEY = b"private-read-audit-key-for-tests-32b"
REQUEST_KEY = b"private-read-request-key-tests-32b"
OPAQUE_ID_KEY = b"private-read-opaque-key-for-tests-32"


class TextSubclass(str):
    pass


class IntSubclass(int):
    pass


class MaliciousAuthorizationTaskStore(AuthorizationTaskStore):
    create_pending_calls = 0

    def create_pending(self, *_args: object, **_kwargs: object) -> object:
        type(self).create_pending_calls += 1
        raise AssertionError("malicious subclass side effect reached")


def _activate_store(
    tmp_path: Path,
    *,
    coordinator_now_us: int = 1_000_000,
    coordinator_lease_expires_at_us: int = 20_000_000,
) -> AuthorizationTaskStore:
    root = (tmp_path / "authorization").absolute()
    root.mkdir(mode=0o700)
    store = AuthorizationTaskStore(
        db_path=root / "tasks.db",
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="private-read-test-k1",
    )
    lock = store.acquire_coordinator_lock()
    assert lock is not None
    fence = store.acquire_coordinator(
        CoordinatorIdentity(owner_id="private-read-test-host", nonce="c" * 32),
        now_us=coordinator_now_us,
        lease_expires_at_us=coordinator_lease_expires_at_us,
        lock_session=lock,
    )
    assert fence is not None
    return store


def _context(**changes: object) -> TrustedPrivateReadHostContext:
    values: dict[str, object] = {
        "requester_profile": "requester-profile",
        "requester_agent": "requester-agent",
        "source_platform": "source-platform",
        "source_account": "source-account",
        "source_user": "source-user",
        "source_chat": "source-chat",
        "source_thread": "source-thread",
        "source_message": "source-message",
        "source_provenance": "authenticated_inbound",
        "resource_id": "trusted-resource-id",
        "approval_profile": "approval-profile",
        "approval_account": "approval-account",
        "approval_user": "approval-user",
        "approval_chat": "approval-chat",
        "approval_thread": "approval-thread",
        "delivery_profile": "delivery-profile",
        "delivery_platform": "delivery-platform",
        "delivery_account": "delivery-account",
        "delivery_chat": "delivery-chat",
        "delivery_thread": "delivery-thread",
        "delivery_transport_implementation": "delivery-transport-v1",
        "delivery_runtime_identity": "delivery-runtime",
        "delivery_account_binding": "delivery-binding",
        "delivery_connection_epoch": 7,
        "created_at_us": 2_000_000,
        "expires_at_us": 10_000_000,
        "pdp_identity": "decision-service-instance",
        "policy_identity": "policy-identity",
        "policy_version": "policy-version",
        "policy_hash": "a" * 64,
        "model_identity": "model-identity",
    }
    values.update(changes)
    return TrustedPrivateReadHostContext(**values)


def _capability(**changes: object) -> PrivateReadCapabilitySpec:
    values: dict[str, object] = {
        "capability_id": "records.summary.read",
        "operation": "retrieve",
        "resource_type": "synthetic.record",
        "fields": ("summary", "timestamp"),
    }
    values.update(changes)
    return PrivateReadCapabilitySpec(**values)


def _counts(store: AuthorizationTaskStore) -> tuple[int, int, int]:
    with sqlite3.connect(store.db_path) as connection:
        return tuple(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "authorization_tasks",
                "authorization_notification_attempts",
                "authorization_audit_events",
            )
        )


def test_epoch_bounds_accept_and_persist_exact_sqlite_maximum(
    tmp_path: Path,
) -> None:
    context = _context(
        delivery_connection_epoch=SQLITE_SIGNED_INT64_MAX,
        created_at_us=SQLITE_SIGNED_INT64_MAX - 1,
        expires_at_us=SQLITE_SIGNED_INT64_MAX,
    )

    assert context.delivery_connection_epoch == SQLITE_SIGNED_INT64_MAX
    assert context.expires_at_us == SQLITE_SIGNED_INT64_MAX
    assert json.loads(context.canonical_bytes())["expires_at_us"] == (
        SQLITE_SIGNED_INT64_MAX
    )

    store = _activate_store(
        tmp_path,
        coordinator_now_us=SQLITE_SIGNED_INT64_MAX - 2,
        coordinator_lease_expires_at_us=SQLITE_SIGNED_INT64_MAX,
    )
    try:
        PrivateReadAuthorizationOrchestrator(
            store,
            id_hmac_key=OPAQUE_ID_KEY,
        ).create_pending(
            _capability(),
            host_context=context,
            tool_call_id="provider-sqlite-boundary",
        )
        with sqlite3.connect(store.db_path) as connection:
            persisted = connection.execute(
                "SELECT created_at_us,expires_at_us,binding_json "
                "FROM authorization_tasks"
            ).fetchone()
            notification = connection.execute(
                "SELECT created_at_us,due_at_us "
                "FROM authorization_notification_attempts"
            ).fetchone()

        assert persisted[:2] == (
            SQLITE_SIGNED_INT64_MAX - 1,
            SQLITE_SIGNED_INT64_MAX,
        )
        assert json.loads(persisted[2])["delivery_connection_epoch"] == (
            SQLITE_SIGNED_INT64_MAX
        )
        assert notification == (
            SQLITE_SIGNED_INT64_MAX - 1,
            SQLITE_SIGNED_INT64_MAX - 1,
        )
    finally:
        store.close()


@pytest.mark.parametrize(
    "invalid",
    [
        True,
        IntSubclass(7),
        SQLITE_SIGNED_INT64_MAX + 1,
        10**100,
    ],
)
@pytest.mark.parametrize(
    "field",
    ["delivery_connection_epoch", "created_at_us", "expires_at_us"],
)
def test_epoch_bounds_reject_non_exact_or_sqlite_overflowing_integers(
    field: str,
    invalid: object,
) -> None:
    with pytest.raises(ValueError, match="signed SQLite 64-bit"):
        _context(**{field: invalid})


def test_created_and_expiry_order_remains_strict_at_sqlite_boundary() -> None:
    with pytest.raises(ValueError, match="expires_at_us must be after"):
        _context(
            created_at_us=SQLITE_SIGNED_INT64_MAX,
            expires_at_us=SQLITE_SIGNED_INT64_MAX,
        )


def test_store_subclass_is_rejected_before_create_pending_side_effect() -> None:
    malicious = object.__new__(MaliciousAuthorizationTaskStore)
    MaliciousAuthorizationTaskStore.create_pending_calls = 0

    with pytest.raises(TypeError, match="store has an invalid type"):
        PrivateReadRequestRuntime(
            store=malicious,
            id_hmac_key=OPAQUE_ID_KEY,
            host_contexts=object(),
            capabilities=object(),
            enabled=True,
        )
    with pytest.raises(TypeError, match="store has an invalid type"):
        PrivateReadAuthorizationOrchestrator(
            malicious,
            id_hmac_key=OPAQUE_ID_KEY,
        )

    assert MaliciousAuthorizationTaskStore.create_pending_calls == 0


def test_create_pending_is_payload_free_atomic_and_non_sending(tmp_path: Path) -> None:
    store = _activate_store(tmp_path)
    try:
        result = PrivateReadAuthorizationOrchestrator(
            store, id_hmac_key=OPAQUE_ID_KEY
        ).create_pending(
            _capability(),
            host_context=_context(),
            tool_call_id="provider-tool-call-001",
        )

        assert result.status == "approval_required"
        assert result.idempotent is False
        assert result.task_id.startswith("task-")
        assert result.correlation_id.startswith("corr-")
        assert _counts(store) == (1, 1, 2)

        database_bytes = store.db_path.read_bytes()
        assert PRIVATE_SENTINEL.encode() not in database_bytes
        with sqlite3.connect(store.db_path) as connection:
            task = connection.execute(
                "SELECT status,scoped_request_key,binding_json FROM authorization_tasks"
            ).fetchone()
            notifications = connection.execute(
                "SELECT status,send_started_at_us "
                "FROM authorization_notification_attempts"
            ).fetchall()
            audit_rows = connection.execute(
                "SELECT actor_token,target_token,request_digest "
                "FROM authorization_audit_events"
            ).fetchall()

        assert task[0] == "approval_required"
        assert task[1].startswith("private-read-request:v1:")
        assert len(task[1].encode("utf-8")) <= 256
        binding = json.loads(task[2])
        assert binding["tool_call_id"] == "provider-tool-call-001"
        assert binding["operation"] == "retrieve"
        assert binding["resource_type"] == "synthetic.record"
        assert binding["resource_id"] == "trusted-resource-id"
        assert binding["fields"] == ["summary", "timestamp"]
        assert all(PRIVATE_SENTINEL not in value for row in audit_rows for value in row)
        assert notifications == [("pending", None)]
    finally:
        store.close()


def test_exact_replay_is_idempotent_without_duplicate_challenge(tmp_path: Path) -> None:
    store = _activate_store(tmp_path)
    orchestrator = PrivateReadAuthorizationOrchestrator(
        store, id_hmac_key=OPAQUE_ID_KEY
    )
    try:
        first = orchestrator.create_pending(
            _capability(), host_context=_context(), tool_call_id="provider-call-replay"
        )
        second = orchestrator.create_pending(
            _capability(), host_context=_context(), tool_call_id="provider-call-replay"
        )

        assert first.task_id == second.task_id
        assert first.correlation_id == second.correlation_id
        assert first.idempotent is False
        assert second.idempotent is True
        assert _counts(store) == (1, 1, 2)
    finally:
        store.close()


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("source_chat", "different-chat"),
        ("source_user", "different-user"),
        ("source_message", "different-message"),
        ("source_account", "different-account"),
        ("resource_id", "different-resource"),
        ("policy_identity", "different-policy"),
        ("policy_version", "different-policy-version"),
        ("policy_hash", "b" * 64),
        ("model_identity", "different-model"),
        ("delivery_runtime_identity", "different-runtime"),
        ("delivery_connection_epoch", 8),
    ],
)
def test_trusted_context_mismatch_cannot_reuse_task(
    tmp_path: Path, field: str, changed: object
) -> None:
    store = _activate_store(tmp_path)
    orchestrator = PrivateReadAuthorizationOrchestrator(
        store, id_hmac_key=OPAQUE_ID_KEY
    )
    try:
        first = orchestrator.create_pending(
            _capability(), host_context=_context(), tool_call_id="provider-call"
        )
        second = orchestrator.create_pending(
            _capability(),
            host_context=dataclasses.replace(_context(), **{field: changed}),
            tool_call_id="provider-call",
        )

        assert first.task_id != second.task_id
        assert first.correlation_id != second.correlation_id
        assert _counts(store)[0:2] == (2, 2)
    finally:
        store.close()


@pytest.mark.parametrize(
    "capability",
    [
        _capability(capability_id="records.details.read"),
        _capability(operation="inspect"),
        _capability(resource_type="synthetic.archive"),
        _capability(fields=("summary",)),
    ],
)
def test_capability_difference_cannot_reuse_task(
    tmp_path: Path, capability: PrivateReadCapabilitySpec
) -> None:
    store = _activate_store(tmp_path)
    orchestrator = PrivateReadAuthorizationOrchestrator(
        store, id_hmac_key=OPAQUE_ID_KEY
    )
    try:
        first = orchestrator.create_pending(
            _capability(), host_context=_context(), tool_call_id="provider-call"
        )
        second = orchestrator.create_pending(
            capability, host_context=_context(), tool_call_id="provider-call"
        )

        assert first.task_id != second.task_id
        assert first.correlation_id != second.correlation_id
        assert _counts(store)[0:2] == (2, 2)
    finally:
        store.close()


def test_tool_call_id_mismatch_cannot_reuse_task(tmp_path: Path) -> None:
    store = _activate_store(tmp_path)
    orchestrator = PrivateReadAuthorizationOrchestrator(
        store, id_hmac_key=OPAQUE_ID_KEY
    )
    try:
        first = orchestrator.create_pending(
            _capability(), host_context=_context(), tool_call_id="provider-call-a"
        )
        second = orchestrator.create_pending(
            _capability(), host_context=_context(), tool_call_id="provider-call-b"
        )

        assert first.task_id != second.task_id
        assert _counts(store)[0:2] == (2, 2)
    finally:
        store.close()


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("capability_id", ""),
        ("capability_id", "\x00bad"),
        ("capability_id", "\ud800"),
        ("capability_id", "é" * (MAX_CAPABILITY_ID_BYTES // 2 + 1)),
        ("capability_id", TextSubclass("subclass")),
        ("operation", TextSubclass("retrieve")),
        ("resource_type", "\udfff"),
        ("fields", ["summary"]),
        ("fields", ("summary", "summary")),
        ("fields", tuple(f"field-{index}" for index in range(MAX_FIELDS + 1))),
        ("fields", (TextSubclass("summary"),)),
    ],
)
def test_capability_spec_rejects_malformed_values(field: str, invalid: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        _capability(**{field: invalid})


def test_capability_registry_rejects_duplicates_and_overflow() -> None:
    with pytest.raises(ValueError, match="unique"):
        PrivateReadCapabilityRegistry((_capability(), _capability()))

    overflowing = tuple(
        _capability(capability_id=f"synthetic.capability.{index}")
        for index in range(MAX_CONFIGURED_CAPABILITIES + 1)
    )
    with pytest.raises(ValueError, match="bounded"):
        PrivateReadCapabilityRegistry(overflowing)


def test_capability_registry_rejects_mapping_and_generator_without_iteration() -> None:
    with pytest.raises(TypeError, match="exact bounded tuple"):
        PrivateReadCapabilityRegistry({"capability": _capability()})

    iterated = False

    def capabilities():
        nonlocal iterated
        iterated = True
        yield _capability()

    with pytest.raises(TypeError, match="exact bounded tuple"):
        PrivateReadCapabilityRegistry(capabilities())
    assert iterated is False


@pytest.mark.parametrize(
    "args",
    [
        {"capability_id": "\x00bad"},
        {"capability_id": "\ud800"},
        {"capability_id": "x" * (MAX_CAPABILITY_ID_BYTES + 1)},
        {"capability_id": TextSubclass("subclass")},
        {TextSubclass("capability_id"): "records.summary.read"},
        (("capability_id", "records.summary.read"),),
    ],
)
def test_model_proposal_rejects_non_exact_or_malformed_values(args: object) -> None:
    with pytest.raises(ValueError):
        PrivateReadProposal.from_model_args(args)


def test_private_exception_text_is_sealed_from_exception_and_log(tmp_path, caplog) -> None:
    store = _activate_store(tmp_path)

    def fail_on_write(step: str) -> None:
        if step == "transition.before":
            raise RuntimeError(PRIVATE_SENTINEL)

    store._fault_hook = fail_on_write
    try:
        with pytest.raises(PrivateReadAuthorizationError) as caught:
            PrivateReadAuthorizationOrchestrator(
                store, id_hmac_key=OPAQUE_ID_KEY
            ).create_pending(
                _capability(),
                host_context=_context(),
                tool_call_id="provider-call-failure",
            )

        assert PRIVATE_SENTINEL not in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert PRIVATE_SENTINEL not in caplog.text
        assert PRIVATE_SENTINEL.encode() not in store.db_path.read_bytes()
        assert _counts(store) == (0, 0, 0)
    finally:
        store.close()
