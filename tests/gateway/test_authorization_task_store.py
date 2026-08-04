from __future__ import annotations

import os
import random
import sqlite3
import stat
import time
import traceback
import hashlib
import hmac
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from gateway.authorization_tasks import (
    AuthorizationIntegrityError,
    AuthorizationTaskStore,
    ClaimIdentity,
    CoordinatorFenceError,
    CoordinatorIdentity,
    DeliveryAcceptanceEvidence,
    ExternalPdpDecisionResult,
    MAX_NOTIFICATION_CLAIM_GENERATIONS,
    MAX_NOTIFICATION_RETRY_ORDINAL,
    NotificationAttemptSpec,
    PdpDecisionEvidence,
    ProviderAcceptanceEvidence,
    SCHEMA_VERSION,
    OwnerDecision,
    TrustedAuthorizationBinding,
    TASK_TRANSITIONS,
    UnsafeAuthorizationStorePath,
)
from gateway.authorization_schema import (
    _AUDIT_V2,
    _AUDIT_V6,
    _INDEXES_V2,
    _LEASE,
    _NOTIFICATIONS_V2,
    _NOTIFICATIONS_V3,
    _PDP_V2,
    _PDP_V3,
    _SCHEMA_V1,
    _TASKS_V2,
    _TASKS_V3,
)


def _lock_probe(lock_path: str, result_queue: object) -> None:
    from gateway.authorization_lock import AuthorizationCoordinatorLockSession

    session = AuthorizationCoordinatorLockSession.acquire(Path(lock_path))
    result_queue.put(session is not None)  # type: ignore[attr-defined]
    if session is not None:
        session.close()


AUDIT_KEY = b"audit-key-for-tests-32-bytes-long"
REQUEST_KEY = b"request-key-for-tests-32-bytes-lon"
COORDINATOR = CoordinatorIdentity(owner_id="gateway-host", nonce="c" * 32)


def activate(
    value: AuthorizationTaskStore,
    *,
    identity: CoordinatorIdentity = COORDINATOR,
    now_us: int = 500_000,
    lease_expires_at_us: int = 10_000_000,
) -> AuthorizationTaskStore:
    lock_session = value.acquire_coordinator_lock()
    assert lock_session is not None
    fence = value.acquire_coordinator(
        identity,
        now_us=now_us,
        lease_expires_at_us=lease_expires_at_us,
        lock_session=lock_session,
    )
    assert fence is not None
    return value


def delete_coordinator_lease(value: AuthorizationTaskStore) -> None:
    with sqlite3.connect(value.db_path) as conn:
        conn.execute("DELETE FROM authorization_coordinator_lease")


def binding(**changes: object) -> TrustedAuthorizationBinding:
    values: dict[str, object] = {
        "task_id": "task-001",
        "correlation_id": "corr-001",
        "tool_call_id": "call-001",
        "requester_profile": "requester-profile",
        "requester_agent": "requester-agent",
        "source_platform": "platform-a",
        "source_account": "account-a",
        "source_user": "user-a",
        "source_chat": "chat-a",
        "source_thread": "thread-a",
        "source_message": "message-a",
        "source_provenance": "authenticated_inbound",
        "operation": "read",
        "resource_type": "resource.type",
        "resource_id": "resource-001",
        "fields": ("field-a", "field-b"),
        "parameter_fingerprint": "a" * 64,
        "approval_profile": "owner-profile",
        "approval_account": "owner-account",
        "approval_user": "owner-user",
        "approval_chat": "owner-chat",
        "approval_thread": "owner-thread",
        "delivery_profile": "delivery-profile",
        "delivery_platform": "platform-b",
        "delivery_account": "delivery-account",
        "delivery_chat": "delivery-chat",
        "delivery_thread": "delivery-thread",
        "delivery_transport_implementation": "isolated-transport-v1",
        "delivery_runtime_identity": "delivery-runtime-001",
        "delivery_account_binding": "delivery-account",
        "delivery_connection_epoch": 11,
        "created_at_us": 1_000_000,
        "expires_at_us": 2_000_000,
        "pdp_identity": "pdp-a",
        "policy_identity": "policy-a",
        "policy_version": "policy-v1",
        "policy_hash": "b" * 64,
        "model_identity": "model-a",
    }
    values.update(changes)
    return TrustedAuthorizationBinding(**values)


@pytest.fixture
def store(tmp_path: Path):
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    value = activate(AuthorizationTaskStore(
        db_path=(root / "authorization.db").absolute(),
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    yield value
    value.close()


def decision(**changes: object) -> OwnerDecision:
    values: dict[str, object] = {
        "decision_id": "decision-001",
        "task_id": "task-001",
        "correlation_id": "corr-001",
        "owner_profile": "owner-profile",
        "owner_account": "owner-account",
        "owner_user": "owner-user",
        "owner_chat": "owner-chat",
        "owner_thread": "owner-thread",
        "source_message": "owner-message-001",
        "provenance": "authenticated_reply",
        "challenge_attempt_id": "challenge-task-001",
        "challenge_generation": 1,
        "challenge_nonce": "challenge-task-001-" + "n" * 32,
        "challenge_provider_message_id": "provider-challenge-task-001",
        "reply_to_provider_message_id": "provider-challenge-task-001",
        "adapter_instance_id": "adapter-runtime-001",
        "account_binding": "owner-account",
        "connection_epoch": 7,
    }
    values.update(changes)
    return OwnerDecision(**values)


def claim(*, generation: int = 1, nonce: str = "nonce-001", **changes: object) -> ClaimIdentity:
    values: dict[str, object] = {
        "owner_profile": "delivery-profile",
        "owner_agent": "delivery-worker",
        "owner_account": "delivery-account",
        "nonce": nonce,
        "generation": generation,
    }
    values.update(changes)
    return ClaimIdentity(**values)


def claim_pdp(
    value: AuthorizationTaskStore,
    item: TrustedAuthorizationBinding,
    now_us: int,
    worker: ClaimIdentity | None = None,
) -> PdpDecisionEvidence:
    task = value.load_task(item.task_id, item)
    return pdp_evidence(
        value, item, task, stage="pre_claim", checked_at_us=now_us,
        worker=worker or claim(),
    )


def private_read_pdp(
    value: AuthorizationTaskStore,
    item: TrustedAuthorizationBinding,
    now_us: int,
    worker: ClaimIdentity | None = None,
) -> PdpDecisionEvidence:
    task = value.load_task(item.task_id, item)
    return pdp_evidence(
        value, item, task, stage="pre_private_read", checked_at_us=now_us,
        worker=worker or claim(),
    )


def delivery_acceptance(
    value: AuthorizationTaskStore,
    item: TrustedAuthorizationBinding,
    worker: ClaimIdentity,
    *,
    accepted_at_us: int,
    provider_message_id: str = "provider-message-001",
    **changes: object,
) -> DeliveryAcceptanceEvidence:
    task = value.load_task(item.task_id, item)
    values: dict[str, object] = {
        "task_id": item.task_id,
        "correlation_id": item.correlation_id,
        "operation": item.operation,
        "request_digest": task.request_digest,
        "request_key_version": "test-k1",
        "policy_version": item.policy_version,
        "policy_hash": item.policy_hash,
        "worker_profile": worker.owner_profile,
        "worker_agent": worker.owner_agent,
        "worker_account": worker.owner_account,
        "claim_nonce": worker.nonce,
        "claim_generation": worker.generation,
        "delivery_profile": item.delivery_profile,
        "delivery_platform": item.delivery_platform,
        "delivery_account": item.delivery_account,
        "delivery_chat": item.delivery_chat,
        "delivery_thread": item.delivery_thread,
        "transport_implementation": item.delivery_transport_implementation,
        "runtime_identity": item.delivery_runtime_identity,
        "account_binding": item.delivery_account_binding,
        "connection_epoch": item.delivery_connection_epoch,
        "provider_message_id": provider_message_id,
        "status": "provider_accepted",
        "accepted_at_us": accepted_at_us,
    }
    values.update(changes)
    return DeliveryAcceptanceEvidence(**values)


def test_requires_explicit_absolute_canonical_host_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute"):
        AuthorizationTaskStore(
            db_path=Path("authorization.db"),
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )


def test_mutations_require_current_singleton_coordinator_epoch(tmp_path: Path) -> None:
    root = tmp_path / "coordinator"
    root.mkdir(mode=0o700)
    db_path = (root / "authorization.db").absolute()
    first = AuthorizationTaskStore(
        db_path=db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    with pytest.raises(CoordinatorFenceError):
        first.create_pending(binding(), request_key="no-coordinator")

    first_lock = first.acquire_coordinator_lock()
    assert first_lock is not None
    first_fence = first.acquire_coordinator(
        COORDINATOR,
        now_us=500_000,
        lease_expires_at_us=700_000,
        lock_session=first_lock,
    )
    assert first_fence is not None and first_fence.epoch == 1
    second = AuthorizationTaskStore(
        db_path=db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    assert second.acquire_coordinator_lock() is None
    first.close()
    second_lock = second.acquire_coordinator_lock()
    assert second_lock is not None
    takeover = second.acquire_coordinator(
        CoordinatorIdentity(owner_id="second-host", nonce="d" * 32),
        now_us=700_000,
        lease_expires_at_us=2_000_000,
        lock_session=second_lock,
    )
    assert takeover is not None and takeover.epoch == 2
    with pytest.raises(CoordinatorFenceError):
        first.create_pending(binding(), request_key="stale-coordinator")
    assert second.create_pending(binding(), request_key="current-coordinator").applied


def test_same_coordinator_can_renew_without_incrementing_epoch(store: AuthorizationTaskStore) -> None:
    renewed = store.acquire_coordinator(
        COORDINATOR,
        now_us=600_000,
        lease_expires_at_us=11_000_000,
        lock_session=store._coordinator_lock,  # type: ignore[arg-type]
    )
    assert renewed is not None and renewed.epoch == 1


def test_same_session_missing_lease_reconstruction_burns_pre_send_claim_and_old_authority(
    tmp_path: Path,
) -> None:
    root = tmp_path / "same-session-missing-lease"
    root.mkdir(mode=0o700)
    value = activate(
        AuthorizationTaskStore(
            db_path=(root / "authorization.db").absolute(),
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )
    )
    trusted = binding()
    stage_challenge(value, trusted, request_key="missing-lease-pre-send")
    assert approve_decision(
        value, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    ).applied
    worker = claim()
    assert value.claim(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_200_000,
        lease_expires_at_us=1_500_000,
        pdp_evidence=claim_pdp(value, trusted, 1_200_000, worker),
    ).applied
    old_private_read_evidence = private_read_pdp(
        value, trusted, 1_205_000, worker
    )

    delete_coordinator_lease(value)
    fence = value.acquire_coordinator(
        COORDINATOR,
        now_us=1_250_000,
        lease_expires_at_us=2_000_000,
        lock_session=value._coordinator_lock,  # type: ignore[arg-type]
    )

    assert fence is not None and fence.epoch == 1
    burned = value.load_task(trusted.task_id, trusted)
    assert (burned.status, burned.receipt_code, burned.send_started_at_us) == (
        "failed_consumed",
        "ambiguous_after_restart",
        None,
    )
    with pytest.raises(AuthorizationIntegrityError, match="stale or ineligible"):
        value.create_pdp_check_context(
            trusted.task_id,
            worker,
            stage="pre_private_read",
            now_us=1_251_000,
        )
    assert not value.authorize_private_read(
        trusted.task_id,
        trusted,
        worker,
        old_private_read_evidence,
        now_us=1_251_000,
    ).applied
    assert not value.record_send_started(
        trusted.task_id, trusted, worker, now_us=1_251_000
    ).applied
    value.close()


def test_same_session_missing_lease_reconstruction_burns_send_started_claim(
    tmp_path: Path,
) -> None:
    root = tmp_path / "same-session-missing-lease-send-started"
    root.mkdir(mode=0o700)
    value = activate(
        AuthorizationTaskStore(
            db_path=(root / "authorization.db").absolute(),
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )
    )
    trusted = binding()
    stage_challenge(value, trusted, request_key="missing-lease-send-started")
    assert approve_decision(
        value, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    ).applied
    worker = claim()
    assert value.claim(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_200_000,
        lease_expires_at_us=1_500_000,
        pdp_evidence=claim_pdp(value, trusted, 1_200_000, worker),
    ).applied
    assert value.authorize_private_read(
        trusted.task_id,
        trusted,
        worker,
        private_read_pdp(value, trusted, 1_205_000, worker),
        now_us=1_205_000,
    ).applied
    assert value.record_send_started(
        trusted.task_id, trusted, worker, now_us=1_210_000
    ).applied

    delete_coordinator_lease(value)
    fence = value.acquire_coordinator(
        COORDINATOR,
        now_us=1_250_000,
        lease_expires_at_us=2_000_000,
        lock_session=value._coordinator_lock,  # type: ignore[arg-type]
    )

    assert fence is not None and fence.epoch == 1
    burned = value.load_task(trusted.task_id, trusted)
    assert (burned.status, burned.receipt_code, burned.send_started_at_us) == (
        "failed_consumed",
        "ambiguous_after_restart",
        1_210_000,
    )
    value.close()


def test_missing_lease_reconstruction_is_safe_for_empty_store(tmp_path: Path) -> None:
    root = tmp_path / "missing-lease-empty"
    root.mkdir(mode=0o700)
    value = activate(
        AuthorizationTaskStore(
            db_path=(root / "authorization.db").absolute(),
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )
    )

    delete_coordinator_lease(value)
    fence = value.acquire_coordinator(
        COORDINATOR,
        now_us=1_250_000,
        lease_expires_at_us=2_000_000,
        lock_session=value._coordinator_lock,  # type: ignore[arg-type]
    )

    assert fence is not None and fence.epoch == 1
    with sqlite3.connect(value.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM authorization_tasks").fetchone()[0] == 0
        assert conn.execute(
            "SELECT epoch,heartbeat_at_us,lease_expires_at_us "
            "FROM authorization_coordinator_lease"
        ).fetchone() == (1, 1_250_000, 2_000_000)
    value.close()


def test_missing_lease_reconstruction_preserves_pending_approved_and_terminal_tasks(
    tmp_path: Path,
) -> None:
    root = tmp_path / "missing-lease-safe-task-states"
    root.mkdir(mode=0o700)
    value = activate(
        AuthorizationTaskStore(
            db_path=(root / "authorization.db").absolute(),
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )
    )
    pending = binding(task_id="task-pending", correlation_id="corr-pending")
    approved = binding(task_id="task-approved", correlation_id="corr-approved")
    denied = binding(task_id="task-denied", correlation_id="corr-denied")
    value.create_pending(pending, request_key="missing-lease-pending")
    for item in (approved, denied):
        stage_challenge(value, item, request_key=f"missing-lease-{item.task_id}")
    assert approve_decision(
        value,
        approved.task_id,
        approved,
        decision_for(approved, decision_id="decision-approved"),
        now_us=1_100_000,
    ).applied
    assert deny_decision(
        value,
        denied.task_id,
        denied,
        decision_for(denied, decision_id="decision-denied"),
        now_us=1_100_000,
        reason_code="owner_rejected",
    ).applied
    before = {
        item.task_id: value.load_task(item.task_id, item)
        for item in (pending, approved, denied)
    }

    delete_coordinator_lease(value)
    assert value.acquire_coordinator(
        COORDINATOR,
        now_us=1_250_000,
        lease_expires_at_us=2_000_000,
        lock_session=value._coordinator_lock,  # type: ignore[arg-type]
    ) is not None

    assert value.load_task(pending.task_id, pending) == before[pending.task_id]
    assert value.load_task(approved.task_id, approved) == before[approved.task_id]
    assert value.load_task(denied.task_id, denied) == before[denied.task_id]
    value.close()


def test_missing_lease_reconstruction_preserves_pre_send_notifications_and_burns_crossed_send(
    tmp_path: Path,
) -> None:
    root = tmp_path / "missing-lease-notifications"
    root.mkdir(mode=0o700)
    value = activate(
        AuthorizationTaskStore(
            db_path=(root / "authorization.db").absolute(),
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )
    )
    attempts = (
        ("pending", "notice-pending"),
        ("pre-send", "notice-pre-send"),
        ("crossed-send", "notice-crossed-send"),
    )
    for index, (_, attempt_id) in enumerate(attempts, 1):
        item = binding(
            task_id=f"task-notice-{index}", correlation_id=f"corr-notice-{index}"
        )
        value.create_pending(
            item,
            request_key=f"missing-lease-{attempt_id}",
            notification=notification(attempt_id=attempt_id),
        )
    worker = claim(nonce="notification-reconstruction-claim")
    for attempt_id in ("notice-pre-send", "notice-crossed-send"):
        assert value.claim_notification(
            attempt_id,
            worker,
            now_us=1_100_000,
            lease_expires_at_us=1_300_000,
        ).applied
    assert value.record_notification_send_started(
        "notice-crossed-send", worker, now_us=1_110_000
    ).applied

    delete_coordinator_lease(value)
    assert value.acquire_coordinator(
        COORDINATOR,
        now_us=1_250_000,
        lease_expires_at_us=2_000_000,
        lock_session=value._coordinator_lock,  # type: ignore[arg-type]
    ) is not None

    pending = value.load_notification_work_item(
        "notice-pending", now_us=1_250_000
    ).notification
    pre_send = value.load_notification_work_item(
        "notice-pre-send", now_us=1_250_000
    ).notification
    crossed_send = value.load_notification_work_item(
        "notice-crossed-send", now_us=1_250_000
    ).notification
    assert (pending.status, pending.receipt_code) == ("pending", None)
    assert (pre_send.status, pre_send.receipt_code, pre_send.send_started_at_us) == (
        "claimed",
        None,
        None,
    )
    assert (
        crossed_send.status,
        crossed_send.receipt_code,
        crossed_send.send_started_at_us,
    ) == ("failed", "ambiguous_after_restart", 1_110_000)
    value.close()


def test_missing_lease_reconciliation_fault_rolls_back_lease_and_does_not_publish_fence(
    tmp_path: Path,
) -> None:
    root = tmp_path / "missing-lease-reconciliation-fault"
    root.mkdir(mode=0o700)
    value = activate(
        AuthorizationTaskStore(
            db_path=(root / "authorization.db").absolute(),
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )
    )
    trusted = binding()
    stage_challenge(value, trusted, request_key="missing-lease-fault")
    assert approve_decision(
        value, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    ).applied
    worker = claim()
    assert value.claim(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_200_000,
        lease_expires_at_us=1_500_000,
        pdp_evidence=claim_pdp(value, trusted, 1_200_000, worker),
    ).applied
    previous_fence = value._fence
    delete_coordinator_lease(value)

    def fault(step: str) -> None:
        if step == "audit.before":
            raise RuntimeError("missing lease reconciliation fault")

    value._fault_hook = fault
    with pytest.raises(RuntimeError, match="missing lease reconciliation fault"):
        value.acquire_coordinator(
            COORDINATOR,
            now_us=1_250_000,
            lease_expires_at_us=2_000_000,
            lock_session=value._coordinator_lock,  # type: ignore[arg-type]
        )
    assert value._fence is previous_fence
    with sqlite3.connect(value.db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_coordinator_lease"
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT status,receipt_code FROM authorization_tasks WHERE task_id=?",
            (trusted.task_id,),
        ).fetchone() == ("claimed", None)
    with pytest.raises(CoordinatorFenceError, match="epoch or lease is stale"):
        value.create_pdp_check_context(
            trusted.task_id, worker, stage="pre_private_read", now_us=1_251_000
        )

    value._fault_hook = None
    fence = value.acquire_coordinator(
        COORDINATOR,
        now_us=1_250_000,
        lease_expires_at_us=2_000_000,
        lock_session=value._coordinator_lock,  # type: ignore[arg-type]
    )
    assert fence is not None and fence.epoch == 1
    assert value.load_task(trusted.task_id, trusted).status == "failed_consumed"
    value.close()


def test_same_session_expiry_takeover_burns_claim_before_epoch_two_is_returned(
    tmp_path: Path,
) -> None:
    root = tmp_path / "same-session-expiry"
    root.mkdir(mode=0o700)
    value = activate(
        AuthorizationTaskStore(
            db_path=(root / "authorization.db").absolute(),
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        ),
        lease_expires_at_us=1_300_000,
    )
    trusted = binding()
    stage_challenge(value, trusted, request_key="same-session-expiry")
    assert approve_decision(
        value, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    ).applied
    worker = claim()
    evidence = claim_pdp(value, trusted, 1_200_000, worker)
    assert value.claim(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_200_000,
        lease_expires_at_us=1_500_000,
        pdp_evidence=evidence,
    ).applied

    raised = False

    def fault(step: str) -> None:
        nonlocal raised
        if step == "audit.before" and not raised:
            raised = True
            raise RuntimeError("epoch reconciliation fault")

    value._fault_hook = fault
    with pytest.raises(RuntimeError, match="epoch reconciliation fault"):
        value.acquire_coordinator(
            COORDINATOR,
            now_us=1_300_000,
            lease_expires_at_us=1_800_000,
            lock_session=value._coordinator_lock,  # type: ignore[arg-type]
        )
    with sqlite3.connect(value.db_path) as conn:
        assert conn.execute(
            "SELECT epoch FROM authorization_coordinator_lease"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT status FROM authorization_tasks WHERE task_id=?",
            (trusted.task_id,),
        ).fetchone()[0] == "claimed"

    value._fault_hook = None
    fence = value.acquire_coordinator(
        COORDINATOR,
        now_us=1_300_000,
        lease_expires_at_us=1_800_000,
        lock_session=value._coordinator_lock,  # type: ignore[arg-type]
    )
    assert fence is not None and fence.epoch == 2
    burned = value.load_task(trusted.task_id, trusted)
    assert (burned.status, burned.receipt_code) == (
        "failed_consumed",
        "ambiguous_after_restart",
    )
    with pytest.raises(AuthorizationIntegrityError, match="stale or ineligible"):
        value.create_pdp_check_context(
            trusted.task_id,
            worker,
            stage="pre_private_read",
            now_us=1_310_000,
        )
    assert not value.record_send_started(
        trusted.task_id, trusted, worker, now_us=1_310_000
    ).applied
    value.close()


def test_second_live_coordinator_cannot_reconcile_first_live_send(
    tmp_path: Path,
) -> None:
    root = tmp_path / "reconcile-fence"
    root.mkdir(mode=0o700)
    db_path = (root / "authorization.db").absolute()
    first = activate(
        AuthorizationTaskStore(
            db_path=db_path,
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        ),
        lease_expires_at_us=1_500_000,
    )
    trusted = binding()
    stage_challenge(first, trusted, request_key="request-live-send-fence")
    approve_decision(first,
        trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    )
    first.claim(
        trusted.task_id,
        trusted,
        claim(),
        now_us=1_200_000,
        lease_expires_at_us=1_300_000,
        pdp_evidence=claim_pdp(first, trusted, 1_200_000),
    )
    first.authorize_private_read(
        trusted.task_id,
        trusted,
        claim(),
        private_read_pdp(first, trusted, 1_205_000),
        now_us=1_205_000,
    )
    first.record_send_started(
        trusted.task_id, trusted, claim(), now_us=1_210_000
    )

    second = AuthorizationTaskStore(
        db_path=db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    assert second.acquire_coordinator_lock() is None
    with pytest.raises(CoordinatorFenceError):
        second.reconcile_restart(now_us=1_250_000)
    first.close()
    second_lock = second.acquire_coordinator_lock()
    assert second_lock is not None
    takeover = second.acquire_coordinator(
        CoordinatorIdentity(owner_id="second-host", nonce="s" * 32),
        now_us=1_500_000,
        lease_expires_at_us=2_500_000,
        lock_session=second_lock,
    )
    assert takeover is not None and takeover.epoch == 2
    assert second.load_task(trusted.task_id, trusted).status == "failed_consumed"
    assert second.reconcile_restart(now_us=1_500_001).tasks_failed_consumed == 0


def test_coordinator_acquire_requires_live_owned_os_lock(
    tmp_path: Path,
) -> None:
    root = tmp_path / "lock-assumption"
    root.mkdir(mode=0o700)
    candidate = AuthorizationTaskStore(
        db_path=(root / "authorization.db").absolute(),
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    with pytest.raises(ValueError, match="live owned"):
        candidate.acquire_coordinator(
            COORDINATOR,
            now_us=500_000,
            lease_expires_at_us=1_000_000,
            lock_session=object(),  # type: ignore[arg-type]
        )
    session = candidate.acquire_coordinator_lock()
    assert session is not None
    session.close()
    with pytest.raises(ValueError, match="live owned"):
        candidate.acquire_coordinator(
            COORDINATOR,
            now_us=500_000,
            lease_expires_at_us=1_000_000,
            lock_session=session,
        )


def test_secure_initialization_and_schema_are_payload_free(store: AuthorizationTaskStore) -> None:
    db_path = store.db_path
    assert stat.S_IMODE(db_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600

    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {"authorization_tasks", "authorization_audit_events", "authorization_notification_attempts"} <= tables
        columns = {
            row[1]
            for table in tables
            if not table.startswith("sqlite_")
            for row in conn.execute(f'SELECT * FROM pragma_table_info("{table}")')
        }
        challenge_columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(authorization_notification_attempts)"
            )
        }
        pdp_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(authorization_pdp_evidence)")
        }
        task_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(authorization_tasks)")
        }
    forbidden = {"payload", "body", "content", "prompt", "result", "exception", "path"}
    assert not {name for name in columns if any(word in name for word in forbidden)}
    assert {
        "correlation_id",
        "challenge_generation",
        "challenge_nonce_digest",
        "provider_message_verifier",
        "provider_acceptance_status",
        "provider_accepted_at_us",
        "adapter_instance_id",
        "account_binding_token",
        "connection_epoch",
        "challenge_state",
        "challenge_resolved_at_us",
        "challenge_decision_digest",
        "challenge_record_digest",
    } <= challenge_columns
    assert {
        "stage",
        "decision",
        "request_digest",
        "model_identity",
        "policy_revision",
        "checked_at_us",
        "consistency",
        "pdp_call_id_verifier",
        "cache_used",
        "evidence_digest",
        "binding_digest",
        "coordinator_owner_digest",
        "coordinator_nonce_digest",
        "coordinator_epoch",
        "claim_owner_digest",
        "claim_nonce_digest",
        "claim_generation",
        "context_record_digest",
    } <= pdp_columns
    assert {
        "delivery_acceptance_status",
        "delivery_accepted_at_us",
        "delivery_transport_implementation",
        "delivery_runtime_identity",
        "delivery_account_binding_token",
        "delivery_connection_epoch",
        "delivery_record_digest",
    } <= task_columns


def test_binding_is_immutable_canonical_and_bounded() -> None:
    first = binding(fields=("field-b", "field-a"))
    second = binding(fields=("field-a", "field-b"))
    assert first.canonical_bytes() == second.canonical_bytes()
    with pytest.raises(Exception):
        first.source_user = "changed"  # type: ignore[misc]
    with pytest.raises(ValueError, match="bounded"):
        binding(source_user="x" * 300)


def test_transition_times_require_integer_utc_epoch_microseconds(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    store.create_pending(trusted, request_key="request-integer-time")
    with pytest.raises(ValueError, match="integer UTC epoch microseconds"):
        approve_decision(store, "task-001", trusted, decision(), now_us=1_100_000.5)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="integer UTC epoch microseconds"):
        store.expire_due(now_us=True)  # type: ignore[arg-type]


def test_exact_duplicate_create_is_idempotent_but_binding_change_fails_closed(
    store: AuthorizationTaskStore,
) -> None:
    exact = binding()
    created = store.create_pending(exact, request_key="scope/request-001")
    duplicate = store.create_pending(exact, request_key="scope/request-001")
    mismatch = store.create_pending(
        binding(source_chat="chat-b"), request_key="scope/request-001"
    )

    assert created.applied and not created.idempotent
    assert duplicate.applied and duplicate.idempotent
    assert duplicate.task == created.task
    assert not mismatch.applied and mismatch.task is None
    assert store.load_task("task-001", exact).request_digest == created.task.request_digest
    assert len(store.list_audit_events(task_id="task-001")) == 1


def test_hmac_tokens_are_scoped_stable_and_do_not_contain_raw_identity(
    store: AuthorizationTaskStore,
) -> None:
    token_a1 = store.audit_token("source-user", "user-a")
    token_a2 = store.audit_token("source-user", "user-a")
    token_scope = store.audit_token("source-chat", "user-a")
    other_root = store.db_path.parent / "other"
    other_root.mkdir(mode=0o700)
    other = AuthorizationTaskStore(
        db_path=(other_root / "authorization.db").absolute(),
        audit_hmac_key=b"different-audit-key-32-bytes-long",
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    assert token_a1 == token_a2
    assert token_a1 != token_scope
    assert token_a1 != other.audit_token("source-user", "user-a")
    assert "user-a" not in token_a1


def test_unknown_or_mismatched_binding_key_version_denies_transition(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    store.create_pending(trusted, request_key="request-key-version")
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "UPDATE authorization_tasks SET key_version='unknown-version' WHERE task_id=?",
            (trusted.task_id,),
        )
    result = store.cancel(
        trusted.task_id,
        trusted,
        now_us=1_100_000,
        reason_code="request_canceled",
    )
    assert not result.applied
    with pytest.raises(AuthorizationIntegrityError, match="expiry scan"):
        store.expire_due(now_us=trusted.expires_at_us)
    with pytest.raises(AuthorizationIntegrityError, match="task list"):
        store.list_tasks(
            status="approval_required",
            due_before_us=trusted.expires_at_us,
            now_us=1_100_000,
        )
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT status FROM authorization_tasks WHERE task_id=?", (trusted.task_id,)
        ).fetchone()[0] == "approval_required"


@pytest.mark.parametrize(
    ("changed", "value"),
    [
        ("owner_profile", "wrong-profile"),
        ("owner_account", "wrong-account"),
        ("owner_user", "wrong-user"),
        ("owner_chat", "wrong-chat"),
        ("owner_thread", "wrong-thread"),
    ],
)
def test_approve_requires_exact_owner_and_provenance(
    store: AuthorizationTaskStore, changed: str, value: str
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="request-approve-exact")
    assert not approve_decision(store,
        "task-001", trusted, replace(decision_for(trusted), **{changed: value}), now_us=1_100_000
    ).applied
    assert store.load_task("task-001", trusted).status == "approval_required"
    assert "task_approved" not in [
        event.kind for event in store.list_audit_events(task_id="task-001")
    ]


def test_approve_is_exactly_idempotent_and_decision_ids_are_unique(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="request-approve")
    first = approve_decision(store, "task-001", trusted, decision_for(trusted), now_us=1_100_000)
    duplicate = approve_decision(store, "task-001", trusted, decision_for(trusted), now_us=1_100_001)
    wrong_decision = approve_decision(store,
        "task-001", trusted, decision_for(trusted, decision_id="decision-002"), now_us=1_100_002
    )
    wrong_duplicate_source = approve_decision(store,
        "task-001", trusted, decision_for(trusted, source_message="different-owner-message"), now_us=1_100_003
    )
    assert first.applied and not first.idempotent and first.task.status == "approved"
    assert duplicate.applied and duplicate.idempotent
    assert not wrong_decision.applied
    assert not wrong_duplicate_source.applied
    assert [event.kind for event in store.list_audit_events(task_id="task-001")].count(
        "task_approved"
    ) == 1


def test_deny_is_idempotent_only_for_exact_decision(store: AuthorizationTaskStore) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="request-deny-idempotent")
    first = deny_decision(store,
        "task-001",
        trusted,
        decision_for(trusted),
        now_us=1_100_000,
        reason_code="owner_rejected",
    )
    duplicate = deny_decision(store,
        "task-001",
        trusted,
        decision_for(trusted),
        now_us=1_100_001,
        reason_code="owner_rejected",
    )
    mismatch = deny_decision(store,
        "task-001",
        trusted,
        decision_for(trusted, source_message="different"),
        now_us=1_100_002,
        reason_code="owner_rejected",
    )
    assert first.applied and not first.idempotent
    assert duplicate.applied and duplicate.idempotent
    assert not mismatch.applied


def test_deny_cancel_and_terminal_states_never_reopen(store: AuthorizationTaskStore) -> None:
    for suffix, terminal in (("deny", "denied"), ("cancel", "canceled")):
        trusted = binding(task_id=f"task-{suffix}", correlation_id=f"corr-{suffix}")
        if terminal == "denied":
            stage_challenge(store, trusted, request_key=f"request-{suffix}")
            result = deny_decision(store,
                trusted.task_id,
                trusted,
                decision_for(trusted, decision_id=f"decision-{suffix}"),
                now_us=1_100_000,
                reason_code="owner_rejected",
            )
        else:
            store.create_pending(trusted, request_key=f"request-{suffix}")
            result = store.cancel(
                trusted.task_id, trusted, now_us=1_100_000, reason_code="request_canceled"
            )
        assert result.applied and result.task.status == terminal
        assert not approve_decision(store,
            trusted.task_id,
            trusted,
            decision_for(trusted, decision_id=f"late-{suffix}"),
            now_us=1_200_000,
        ).applied
        with pytest.raises(AuthorizationIntegrityError, match="stale or ineligible"):
            store.create_pdp_check_context(
                trusted.task_id, claim(), stage="pre_claim", now_us=1_200_000
            )


def test_expiry_uses_strict_integer_microsecond_equality_boundary(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    store.create_pending(trusted, request_key="request-expiry")
    assert store.expire_due(now_us=trusted.expires_at_us - 1) == 0
    assert store.load_task("task-001", trusted).status == "approval_required"
    assert store.expire_due(now_us=trusted.expires_at_us) == 1
    assert store.load_task("task-001", trusted).status == "expired"
    assert not approve_decision(store,
        "task-001", trusted, decision(), now_us=trusted.expires_at_us
    ).applied


def test_cancel_cannot_win_at_expiry_boundary(store: AuthorizationTaskStore) -> None:
    trusted = binding()
    store.create_pending(trusted, request_key="request-cancel-expired")
    assert not store.cancel(
        "task-001",
        trusted,
        now_us=trusted.expires_at_us,
        reason_code="request_canceled",
    ).applied
    assert store.expire_due(now_us=trusted.expires_at_us) == 1


def test_claim_heartbeat_send_boundary_and_consumed_finish(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="request-consume")
    approve_decision(store, "task-001", trusted, decision_for(trusted), now_us=1_100_000)
    claimed = store.claim(
        "task-001", trusted, claim(), now_us=1_200_000, lease_expires_at_us=1_300_000,
        pdp_evidence=claim_pdp(store, trusted, 1_200_000),
    )
    assert claimed.applied and claimed.task.status == "claimed"
    assert not store.heartbeat(
        "task-001",
        trusted,
        claim(nonce="wrong"),
        now_us=1_210_000,
        lease_expires_at_us=1_310_000,
    ).applied
    assert store.heartbeat(
        "task-001",
        trusted,
        claim(),
        now_us=1_210_000,
        lease_expires_at_us=1_310_000,
    ).applied
    assert store.authorize_private_read(
        "task-001",
        trusted,
        claim(),
        private_read_pdp(store, trusted, 1_215_000),
        now_us=1_215_000,
    ).applied
    assert store.record_send_started(
        "task-001", trusted, claim(), now_us=1_220_000
    ).applied
    finished = store.finish(
        "task-001",
        trusted,
        claim(),
        now_us=1_230_000,
        outcome="consumed",
        receipt_code="provider_accepted",
        evidence=delivery_acceptance(
            store, trusted, claim(), accepted_at_us=1_225_000
        ),
    )
    assert finished.applied and finished.task.status == "consumed"
    assert not store.heartbeat(
        "task-001",
        trusted,
        claim(),
        now_us=1_240_000,
        lease_expires_at_us=1_340_000,
    ).applied
    assert not store.finish(
        "task-001",
        trusted,
        claim(),
        now_us=1_240_000,
        outcome="failed_consumed",
        receipt_code="provider_timeout",
    ).applied


def test_claim_requires_live_approval_and_exact_binding(store: AuthorizationTaskStore) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="request-claim-exact")
    approve_decision(store, "task-001", trusted, decision_for(trusted), now_us=1_100_000)
    assert not store.claim(
        "task-001",
        binding(delivery_chat="wrong-chat"),
        claim(),
        now_us=1_200_000,
        lease_expires_at_us=1_300_000,
        pdp_evidence=claim_pdp(store, trusted, 1_200_000),
    ).applied
    with pytest.raises(AuthorizationIntegrityError, match="stale or ineligible"):
        store.create_pdp_check_context(
            "task-001", claim(), stage="pre_claim", now_us=trusted.expires_at_us
        )


def test_concurrent_approve_and_claim_have_exactly_one_transition_winner(
    tmp_path: Path,
) -> None:
    root = tmp_path / "concurrent-host"
    root.mkdir(mode=0o700)
    db_path = (root / "authorization.db").absolute()
    first_store = activate(AuthorizationTaskStore(
        db_path=db_path, audit_hmac_key=AUDIT_KEY, request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    trusted = binding()
    stage_challenge(first_store, trusted, request_key="request-concurrent")

    def approve_once(index: int) -> bool:
        return approve_decision(first_store,
            "task-001",
            trusted,
            decision_for(trusted, decision_id=f"decision-{index}"),
            now_us=1_100_000 + index,
        ).applied

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(approve_once, range(8))) == 1

    def claim_once(index: int) -> bool:
        try:
            return first_store.claim(
                "task-001",
                trusted,
                claim(nonce=f"nonce-{index}"),
                now_us=1_200_000,
                lease_expires_at_us=1_300_000,
                pdp_evidence=claim_pdp(
                    first_store, trusted, 1_200_000, claim(nonce=f"nonce-{index}")
                ),
            ).applied
        except AuthorizationIntegrityError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(claim_once, range(8))) == 1


def notification(**changes: object) -> NotificationAttemptSpec:
    values: dict[str, object] = {
        "attempt_id": "notification-001",
        "challenge_generation": 1,
        "kind": "approval_challenge",
        "destination_profile": "owner-profile",
        "destination_account": "owner-account",
        "destination_chat": "owner-chat",
        "destination_thread": "owner-thread",
        "created_at_us": 1_000_001,
        "due_at_us": 1_000_002,
        "challenge_nonce": "notification-challenge-" + "n" * 32,
    }
    values.update(changes)
    return NotificationAttemptSpec(**values)


def acceptance(
    item: TrustedAuthorizationBinding,
    *,
    attempt_id: str,
    challenge_generation: int = 1,
    worker_claim_generation: int = 1,
    provider_message_id: str | None = None,
    **changes: object,
) -> ProviderAcceptanceEvidence:
    values: dict[str, object] = {
        "task_id": item.task_id,
        "correlation_id": item.correlation_id,
        "attempt_id": attempt_id,
        "challenge_generation": challenge_generation,
        "worker_claim_generation": worker_claim_generation,
        "status": "provider_accepted",
        "provider_message_id": provider_message_id or f"provider-{attempt_id}",
        "accepted_at_us": 1_070_000,
        "adapter_instance_id": "adapter-runtime-001",
        "account_binding": item.approval_account,
        "connection_epoch": 7,
        "destination_profile": item.approval_profile,
        "destination_account": item.approval_account,
        "destination_chat": item.approval_chat,
        "destination_thread": item.approval_thread,
    }
    values.update(changes)
    return ProviderAcceptanceEvidence(**values)


def decision_for(item: TrustedAuthorizationBinding, **changes: object) -> OwnerDecision:
    values: dict[str, object] = {
        "challenge_attempt_id": f"challenge-{item.task_id}",
        "task_id": item.task_id,
        "correlation_id": item.correlation_id,
        "challenge_generation": 1,
        "challenge_nonce": f"challenge-{item.task_id}-" + "n" * 32,
        "challenge_provider_message_id": f"provider-challenge-{item.task_id}",
        "reply_to_provider_message_id": f"provider-challenge-{item.task_id}",
        "adapter_instance_id": "adapter-runtime-001",
        "account_binding": item.approval_account,
        "connection_epoch": 7,
    }
    values.update(changes)
    return decision(**values)


def decision_resolution(
    value: AuthorizationTaskStore,
    item: TrustedAuthorizationBinding,
    owner_decision: OwnerDecision,
    *,
    created_at_us: int,
) -> NotificationAttemptSpec:
    for event in value.list_audit_events(task_id=item.task_id):
        if event.event_id in {
            f"task-approved:{owner_decision.decision_id}",
            f"task-denied:{owner_decision.decision_id}",
        }:
            created_at_us = event.occurred_at_us
            break
    return notification(
        attempt_id=f"resolution-{owner_decision.decision_id}",
        kind="approval_resolution",
        challenge_generation=owner_decision.challenge_generation,
        created_at_us=created_at_us,
        due_at_us=created_at_us,
        challenge_nonce=f"resolution-{owner_decision.decision_id}",
        destination_profile=item.approval_profile,
        destination_account=item.approval_account,
        destination_chat=item.approval_chat,
        destination_thread=item.approval_thread,
    )


def approve_decision(
    value: AuthorizationTaskStore,
    task_id: str,
    item: TrustedAuthorizationBinding,
    owner_decision: OwnerDecision,
    *,
    now_us: int,
    resolution_notification: NotificationAttemptSpec | None = None,
):
    resolution_notification = resolution_notification or decision_resolution(
        value, item, owner_decision, created_at_us=now_us
    )
    return value.approve(
        task_id,
        item,
        owner_decision,
        now_us=now_us,
        resolution_notification=resolution_notification,
    )


def deny_decision(
    value: AuthorizationTaskStore,
    task_id: str,
    item: TrustedAuthorizationBinding,
    owner_decision: OwnerDecision,
    *,
    now_us: int,
    reason_code: str,
    resolution_notification: NotificationAttemptSpec | None = None,
):
    resolution_notification = resolution_notification or decision_resolution(
        value, item, owner_decision, created_at_us=now_us
    )
    return value.deny(
        task_id,
        item,
        owner_decision,
        now_us=now_us,
        reason_code=reason_code,
        resolution_notification=resolution_notification,
    )


def stage_challenge(
    store: AuthorizationTaskStore,
    item: TrustedAuthorizationBinding,
    *,
    request_key: str,
) -> None:
    attempt_id = f"challenge-{item.task_id}"
    nonce = f"challenge-{item.task_id}-" + "n" * 32
    store.create_pending(
        item,
        request_key=request_key,
        notification=notification(
            attempt_id=attempt_id,
            challenge_nonce=nonce,
            destination_profile=item.approval_profile,
            destination_account=item.approval_account,
            destination_chat=item.approval_chat,
            destination_thread=item.approval_thread,
        ),
    )
    notification_claim = claim(nonce=f"notification-claim-{item.task_id}")
    store.claim_notification(
        attempt_id,
        notification_claim,
        now_us=1_050_000,
        lease_expires_at_us=1_080_000,
    )
    store.record_notification_send_started(
        attempt_id, notification_claim, now_us=1_060_000
    )
    store.finish_notification(
        attempt_id,
        notification_claim,
        now_us=1_070_000,
        outcome="provider_accepted",
        receipt_code="provider_accepted",
        evidence=acceptance(
            item,
            attempt_id=attempt_id,
            provider_message_id=f"provider-challenge-{item.task_id}",
        ),
    )


def test_approval_requires_single_use_provider_accepted_challenge_and_exact_reply(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="request-challenge-binding")
    assert not approve_decision(store,
        trusted.task_id,
        trusted,
        decision_for(trusted, challenge_nonce="wrong-" + "n" * 32),
        now_us=1_100_000,
    ).applied
    assert not approve_decision(store,
        trusted.task_id,
        trusted,
        decision_for(trusted, reply_to_provider_message_id="copied-message-id"),
        now_us=1_100_000,
    ).applied
    for unsupported_provenance in ("forwarded_text", "pasted_text"):
        with pytest.raises(ValueError, match="authenticated reply"):
            decision_for(trusted, provenance=unsupported_provenance)
    accepted = approve_decision(store,
        trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    )
    assert accepted.applied and accepted.task.status == "approved"
    with sqlite3.connect(store.db_path) as conn:
        consumed = conn.execute(
            "SELECT challenge_resolved_at_us FROM authorization_notification_attempts "
            "WHERE attempt_id=?",
            ("challenge-task-001",),
        ).fetchone()[0]
    assert consumed == 1_100_000


def test_create_can_atomically_enqueue_payload_free_notification(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    result = store.create_pending(
        trusted,
        request_key="request-with-notification",
        notification=notification(),
    )
    assert result.applied
    attempts = store.list_notifications(
        status="pending", due_before_us=1_000_002, now_us=1_000_002
    )
    assert len(attempts) == 1
    attempt = attempts[0]
    assert attempt.attempt_id == "notification-001"
    assert attempt.status == "pending"
    assert not hasattr(attempt, "body") and not hasattr(attempt, "payload")
    with sqlite3.connect(store.db_path) as conn:
        destination = conn.execute(
            "SELECT destination_profile,destination_account,destination_chat,destination_thread "
            "FROM authorization_notification_attempts"
        ).fetchone()
    assert destination == ("owner-profile", "owner-account", "owner-chat", "owner-thread")
    assert [event.kind for event in store.list_audit_events(task_id="task-001")] == [
        "task_created",
        "notification_created",
    ]


def test_notification_claim_reclaim_send_and_receipt_crash_windows(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    store.create_pending(
        trusted,
        request_key="request-notification-claim",
        notification=notification(),
    )
    first = store.claim_notification(
        "notification-001",
        claim(),
        now_us=1_100_000,
        lease_expires_at_us=1_200_000,
    )
    assert first.applied and first.attempt.status == "claimed"
    assert not store.heartbeat_notification(
        "notification-001",
        claim(nonce="wrong"),
        now_us=1_110_000,
        lease_expires_at_us=1_210_000,
    ).applied
    assert store.heartbeat_notification(
        "notification-001",
        claim(),
        now_us=1_110_000,
        lease_expires_at_us=1_200_000,
    ).applied
    assert not store.take_over_stale_notification(
        "notification-001",
        claim(generation=2, nonce="nonce-002"),
        now_us=1_199_999,
        lease_expires_at_us=1_300_000,
    ).applied
    takeover = store.take_over_stale_notification(
        "notification-001",
        claim(generation=2, nonce="nonce-002"),
        now_us=1_200_000,
        lease_expires_at_us=1_300_000,
    )
    assert takeover.applied
    assert store.record_notification_send_started(
        "notification-001", claim(generation=2, nonce="nonce-002"), now_us=1_210_000
    ).applied
    assert not store.take_over_stale_notification(
        "notification-001",
        claim(generation=3, nonce="nonce-003"),
        now_us=1_300_000,
        lease_expires_at_us=1_400_000,
    ).applied
    finished = store.finish_notification(
        "notification-001",
        claim(generation=2, nonce="nonce-002"),
        now_us=1_220_000,
        outcome="provider_accepted",
        receipt_code="provider_accepted",
        evidence=acceptance(
            trusted,
            attempt_id="notification-001",
            worker_claim_generation=2,
            provider_message_id="provider-notification-001",
            accepted_at_us=1_220_000,
        ),
    )
    assert finished.applied and finished.attempt.status == "provider_accepted"
    with sqlite3.connect(store.db_path) as conn:
        stored = conn.execute(
            "SELECT provider_message_verifier FROM authorization_notification_attempts"
        ).fetchone()[0]
    assert "provider-notification-001" not in stored


def test_notification_acceptance_exact_retry_after_uncertain_commit(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    spec = notification(attempt_id="notification-terminal-retry")
    store.create_pending(
        trusted, request_key="notification-terminal-retry", notification=spec
    )
    worker = claim(nonce="notification-terminal-worker")
    assert store.claim_notification(
        spec.attempt_id,
        worker,
        now_us=1_020_000,
        lease_expires_at_us=1_100_000,
    ).applied
    assert store.record_notification_send_started(
        spec.attempt_id, worker, now_us=1_025_000
    ).applied
    proof = acceptance(
        trusted,
        attempt_id=spec.attempt_id,
        provider_message_id="notification-provider-id",
        accepted_at_us=1_030_000,
    )
    raised = False

    def fault(step: str) -> None:
        nonlocal raised
        if step == "commit.after" and not raised:
            raised = True
            raise RuntimeError("uncertain notification commit")

    store._fault_hook = fault
    with pytest.raises(RuntimeError, match="uncertain notification commit"):
        store.finish_notification(
            spec.attempt_id,
            worker,
            now_us=1_030_000,
            outcome="provider_accepted",
            receipt_code="provider_accepted",
            evidence=proof,
        )
    store._fault_hook = None
    retry = store.finish_notification(
        spec.attempt_id,
        worker,
        now_us=1_030_000,
        outcome="provider_accepted",
        receipt_code="provider_accepted",
        evidence=proof,
    )
    assert retry.applied and retry.idempotent
    mismatches = (
        replace(proof, provider_message_id="wrong-provider-id"),
        replace(proof, adapter_instance_id="wrong-runtime"),
        replace(proof, account_binding="wrong-account"),
        replace(proof, worker_claim_generation=2),
        replace(proof, accepted_at_us=1_030_001),
    )
    for wrong in mismatches:
        assert not store.finish_notification(
            spec.attempt_id,
            worker,
            now_us=max(1_030_000, wrong.accepted_at_us),
            outcome="provider_accepted",
            receipt_code="provider_accepted",
            evidence=wrong,
        ).applied
    assert not store.finish_notification(
        spec.attempt_id,
        replace(worker, generation=2),
        now_us=1_030_000,
        outcome="provider_accepted",
        receipt_code="provider_accepted",
        evidence=proof,
    ).applied
    assert not store.finish_notification(
        spec.attempt_id,
        worker,
        now_us=1_030_000,
        outcome="failed",
        receipt_code="provider_timeout",
    ).applied
    with pytest.raises(ValueError, match="status"):
        replace(proof, status="provider_rejected")
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events "
            "WHERE kind='notification_provider_accepted'"
        ).fetchone()[0] == 1


def test_notification_failure_exact_retry_requires_same_claim_receipt_and_time(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    spec = notification(attempt_id="notification-failure-retry")
    store.create_pending(
        trusted, request_key="notification-failure-retry", notification=spec
    )
    worker = claim(nonce="notification-failure-worker")
    assert store.claim_notification(
        spec.attempt_id,
        worker,
        now_us=1_020_000,
        lease_expires_at_us=1_100_000,
    ).applied
    raised = False

    def fault(step: str) -> None:
        nonlocal raised
        if step == "commit.after" and not raised:
            raised = True
            raise RuntimeError("uncertain notification failure commit")

    store._fault_hook = fault
    with pytest.raises(RuntimeError, match="uncertain notification failure commit"):
        store.finish_notification(
            spec.attempt_id,
            worker,
            now_us=1_030_000,
            outcome="failed",
            receipt_code="ambiguous_after_restart",
        )
    store._fault_hook = None
    retry = store.finish_notification(
        spec.attempt_id,
        worker,
        now_us=1_030_000,
        outcome="failed",
        receipt_code="ambiguous_after_restart",
    )
    assert retry.applied and retry.idempotent
    assert not store.finish_notification(
        spec.attempt_id,
        replace(worker, nonce="wrong-claim"),
        now_us=1_030_000,
        outcome="failed",
        receipt_code="ambiguous_after_restart",
    ).applied
    assert not store.finish_notification(
        spec.attempt_id,
        worker,
        now_us=1_030_001,
        outcome="failed",
        receipt_code="ambiguous_after_restart",
    ).applied
    assert not store.finish_notification(
        spec.attempt_id,
        worker,
        now_us=1_030_000,
        outcome="failed",
        receipt_code="provider_timeout",
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events "
            "WHERE kind='notification_failed'"
        ).fetchone()[0] == 1


def test_sensitive_task_claim_has_no_takeover_and_restart_burns_pre_send(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="request-task-takeover")
    approve_decision(store, "task-001", trusted, decision_for(trusted), now_us=1_100_000)
    store.claim(
        "task-001", trusted, claim(), now_us=1_200_000, lease_expires_at_us=1_300_000,
        pdp_evidence=claim_pdp(store, trusted, 1_200_000),
    )
    assert not hasattr(store, "take_over_stale_claim")
    report = store.reconcile_restart(now_us=1_250_000)
    assert report.tasks_failed_consumed == 1
    assert store.load_task(trusted.task_id, trusted).status == "failed_consumed"


def test_restart_reconciliation_preserves_safe_states_and_fails_send_started(
    store: AuthorizationTaskStore,
) -> None:
    pending = binding(task_id="task-pending", correlation_id="corr-pending")
    approved = binding(task_id="task-approved", correlation_id="corr-approved")
    claimed = binding(task_id="task-claimed", correlation_id="corr-claimed")
    started = binding(task_id="task-started", correlation_id="corr-started")
    store.create_pending(pending, request_key=f"request-{pending.task_id}")
    for item in (approved, claimed, started):
        stage_challenge(store, item, request_key=f"request-{item.task_id}")
    for index, item in enumerate((approved, claimed, started), 1):
        approve_decision(store,
            item.task_id,
            item,
            decision_for(item, decision_id=f"decision-restart-{index}"),
            now_us=1_100_000,
        )
    for item in (claimed, started):
        store.claim(
            item.task_id,
            item,
            claim(),
            now_us=1_200_000,
            lease_expires_at_us=1_300_000,
            pdp_evidence=claim_pdp(store, item, 1_200_000),
        )
    store.authorize_private_read(
        started.task_id,
        started,
        claim(),
        private_read_pdp(store, started, 1_205_000),
        now_us=1_205_000,
    )
    store.record_send_started(started.task_id, started, claim(), now_us=1_210_000)

    report = store.reconcile_restart(now_us=1_250_000)
    assert report.tasks_failed_consumed == 2
    assert store.load_task(pending.task_id, pending).status == "approval_required"
    assert store.load_task(approved.task_id, approved).status == "approved"
    assert store.load_task(claimed.task_id, claimed).status == "failed_consumed"
    assert store.load_task(started.task_id, started).status == "failed_consumed"
    assert store.reconcile_restart(now_us=1_250_001).tasks_failed_consumed == 0


def test_restart_reconciliation_notification_boundaries(store: AuthorizationTaskStore) -> None:
    first = binding(task_id="task-notice-pending", correlation_id="corr-notice-pending")
    second = binding(task_id="task-notice-started", correlation_id="corr-notice-started")
    store.create_pending(
        first,
        request_key="request-notice-pending",
        notification=notification(attempt_id="notice-pending"),
    )
    store.create_pending(
        second,
        request_key="request-notice-started",
        notification=notification(attempt_id="notice-started"),
    )
    store.claim_notification(
        "notice-started", claim(), now_us=1_100_000, lease_expires_at_us=1_200_000
    )
    store.record_notification_send_started("notice-started", claim(), now_us=1_110_000)
    report = store.reconcile_restart(now_us=1_120_000)
    assert report.notifications_failed == 1
    assert store.list_notifications(
        status="pending", due_before_us=2_000_000, now_us=1_120_000
    )[0].attempt_id == "notice-pending"
    assert store.list_notifications(
        status="failed", due_before_us=2_000_000, now_us=1_120_000
    )[0].attempt_id == "notice-started"
    assert store.reconcile_restart(now_us=1_120_001).notifications_failed == 0


@pytest.mark.parametrize(
    "fault_step",
    [
        "transition.before",
        "transition.after",
        "audit.before",
        "audit.after",
        "notification.before",
        "notification.after",
    ],
)
def test_transition_and_audit_roll_back_together_before_commit(
    tmp_path: Path, fault_step: str
) -> None:
    root = tmp_path / f"fault-{fault_step.replace('.', '-')}"
    root.mkdir(mode=0o700)
    db_path = (root / "authorization.db").absolute()

    def fault(step: str) -> None:
        if step == fault_step:
            raise RuntimeError("UNIQUE_PRIVATE_SENTINEL")

    failing = activate(AuthorizationTaskStore(
        db_path=db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
        _fault_hook=fault,
    ))
    with pytest.raises(RuntimeError, match="UNIQUE_PRIVATE_SENTINEL"):
        failing.create_pending(
            binding(), request_key="request-fault", notification=notification()
        )
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM authorization_tasks").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM authorization_audit_events").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM authorization_notification_attempts").fetchone()[0] == 0
    assert b"UNIQUE_PRIVATE_SENTINEL" not in db_path.read_bytes()


def test_exception_after_commit_is_retry_idempotent(tmp_path: Path) -> None:
    root = tmp_path / "after-commit"
    root.mkdir(mode=0o700)
    db_path = (root / "authorization.db").absolute()

    def fault(step: str) -> None:
        if step == "commit.after":
            raise RuntimeError("after commit")

    failing = activate(AuthorizationTaskStore(
        db_path=db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
        _fault_hook=fault,
    ))
    with pytest.raises(RuntimeError, match="after commit"):
        failing.create_pending(binding(), request_key="request-after-commit")
    failing.close()
    healthy = activate(AuthorizationTaskStore(
        db_path=db_path, audit_hmac_key=AUDIT_KEY, request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    retry = healthy.create_pending(binding(), request_key="request-after-commit")
    assert retry.applied and retry.idempotent
    assert len(healthy.list_audit_events(task_id="task-001")) == 1


def test_explicit_transition_table_has_closed_terminal_states() -> None:
    assert TASK_TRANSITIONS["approval_required"] == {
        "approved",
        "denied",
        "expired",
        "canceled",
    }
    assert TASK_TRANSITIONS["approved"] == {"claimed", "denied", "expired", "canceled"}
    assert TASK_TRANSITIONS["claimed"] == {"consumed", "failed_consumed"}
    for terminal in ("consumed", "denied", "expired", "canceled", "failed_consumed"):
        assert TASK_TRANSITIONS[terminal] == set()


def test_list_tasks_is_bounded_and_filters_exact_state_and_due_time(
    store: AuthorizationTaskStore,
) -> None:
    for index in range(3):
        item = binding(
            task_id=f"task-list-{index}",
            correlation_id=f"corr-list-{index}",
            expires_at_us=2_000_000 + index,
        )
        store.create_pending(item, request_key=f"request-list-{index}")
    rows = store.list_tasks(
        status="approval_required", due_before_us=2_000_001, now_us=1_100_000, limit=1
    )
    assert [row.task_id for row in rows] == ["task-list-0"]
    with pytest.raises(ValueError, match="limit"):
        store.list_tasks(
            status="approval_required", due_before_us=3_000_000, now_us=1_100_000, limit=501
        )


def test_concurrent_create_has_one_creator_and_exact_idempotent_retries(
    tmp_path: Path,
) -> None:
    root = tmp_path / "create-race"
    root.mkdir(mode=0o700)
    db_path = (root / "authorization.db").absolute()
    initial = activate(
        AuthorizationTaskStore(
            db_path=db_path,
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )
    )

    def create_once(_index: int) -> tuple[bool, bool]:
        result = initial.create_pending(binding(), request_key="request-create-race")
        return result.applied, result.idempotent

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(create_once, range(8)))
    assert outcomes.count((True, False)) == 1
    assert outcomes.count((True, True)) == 7


def test_concurrent_initialization_and_current_schema_open_is_noop(
    tmp_path: Path,
) -> None:
    root = tmp_path / "init-race"
    root.mkdir(mode=0o700)
    db_path = (root / "authorization.db").absolute()

    def initialize(_index: int) -> None:
        AuthorizationTaskStore(
            db_path=db_path, audit_hmac_key=AUDIT_KEY, request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(initialize, range(8)))
    before = db_path.stat().st_mtime_ns
    time.sleep(0.01)
    initialize(99)
    assert db_path.stat().st_mtime_ns == before
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_versioned_migration_is_idempotent_after_partial_version_marker(
    tmp_path: Path,
) -> None:
    root = tmp_path / "migration-race"
    root.mkdir(mode=0o700)
    db_path = (root / "authorization.db").absolute()
    AuthorizationTaskStore(
        db_path=db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA user_version=1")

    def migrate(_index: int) -> None:
        AuthorizationTaskStore(
            db_path=db_path,
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(migrate, range(6)))
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def _downgrade_authorization_store(
    value: AuthorizationTaskStore, *, version: int
) -> None:
    """Turn a populated v7 fixture into an authentic v5/v6 snapshot."""

    assert version in {5, 6}
    with sqlite3.connect(value.db_path) as conn:
        conn.row_factory = sqlite3.Row
        for row in conn.execute("SELECT * FROM authorization_tasks").fetchall():
            conn.execute(
                "UPDATE authorization_tasks SET mutable_state_digest=? WHERE task_id=?",
                (value._task_state_digest_v6(row), row["task_id"]),
            )
        conn.execute("ALTER TABLE authorization_tasks DROP COLUMN audit_event_count")
        conn.execute("ALTER TABLE authorization_tasks DROP COLUMN audit_head_digest")
        legacy_audits = conn.execute(
            "SELECT * FROM authorization_audit_events "
            "ORDER BY task_id,occurred_at_us,event_id"
        ).fetchall()
        conn.execute("DROP INDEX IF EXISTS idx_authorization_audit_task_time")
        conn.execute(
            "ALTER TABLE authorization_audit_events "
            "RENAME TO authorization_audit_events_v7"
        )
        conn.execute(_AUDIT_V6.format(table="authorization_audit_events"))
        for row in legacy_audits:
            values = {
                name: row[name]
                for name in (
                    "event_id", "task_id", "kind", "reason_code", "actor_token",
                    "target_token", "request_digest", "key_version", "occurred_at_us",
                )
            }
            conn.execute(
                "INSERT INTO authorization_audit_events VALUES (?,?,?,?,?,?,?,?,?,?)",
                (*values.values(), value._audit_record_digest_v6(values)),
            )
        conn.execute("DROP TABLE authorization_audit_events_v7")
        if version == 5:
            conn.execute(
                "ALTER TABLE authorization_tasks DROP COLUMN mutable_state_digest"
            )
            conn.execute(
                "ALTER TABLE authorization_notification_attempts "
                "DROP COLUMN mutable_state_digest"
            )
            conn.execute(
                "ALTER TABLE authorization_audit_events DROP COLUMN record_digest"
            )
        conn.execute(f"PRAGMA user_version={version}")


def test_populated_v6_migration_chains_snapshot_and_terminalizes_all_authority(
    tmp_path: Path,
) -> None:
    root = tmp_path / "populated-v6"
    root.mkdir(mode=0o700)
    signer = activate(
        AuthorizationTaskStore(
            db_path=(root / "authorization.db").absolute(),
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )
    )
    approved = binding(task_id="v6-approved", correlation_id="v6-approved-corr")
    claimed = binding(task_id="v6-claimed", correlation_id="v6-claimed-corr")
    for item in (approved, claimed):
        stage_challenge(signer, item, request_key=f"request-{item.task_id}")
        assert approve_decision(
            signer,
            item.task_id,
            item,
            decision_for(item, decision_id=f"decision-{item.task_id}"),
            now_us=1_100_000,
        ).applied
    worker = claim(nonce="v6-claimed-worker")
    evidence = claim_pdp(signer, claimed, 1_200_000, worker)
    assert signer.claim(
        claimed.task_id,
        claimed,
        worker,
        now_us=1_200_000,
        lease_expires_at_us=1_400_000,
        pdp_evidence=evidence,
    ).applied
    signer.close()

    _downgrade_authorization_store(signer, version=6)

    migrated = activate(
        AuthorizationTaskStore(
            db_path=signer.db_path,
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )
    )
    approved_task = migrated.load_task(approved.task_id, approved)
    assert (approved_task.status, approved_task.receipt_code) == (
        "denied",
        "ambiguous_after_restart",
    )
    claimed_task = migrated.load_task(claimed.task_id, claimed)
    assert (claimed_task.status, claimed_task.receipt_code) == (
        "failed_consumed",
        "ambiguous_after_restart",
    )
    for item in (approved, claimed):
        events = migrated.list_audit_events(task_id=item.task_id, limit=500)
        assert [event.audit_sequence for event in events] == list(
            range(1, len(events) + 1)
        )
        with sqlite3.connect(migrated.db_path) as conn:
            count, head = conn.execute(
                "SELECT audit_event_count,audit_head_digest FROM authorization_tasks "
                "WHERE task_id=?",
                (item.task_id,),
            ).fetchone()
        assert count == len(events)
        assert head
    migrated.close()


@pytest.mark.parametrize("legacy_version", [5, 6])
@pytest.mark.parametrize("delete_later_audit", [True, False])
def test_legacy_approved_snapshot_replay_cannot_restore_active_authority(
    tmp_path: Path,
    legacy_version: int,
    delete_later_audit: bool,
) -> None:
    root = tmp_path / f"legacy-v{legacy_version}-replay-{delete_later_audit}"
    root.mkdir(mode=0o700)
    signer = activate(AuthorizationTaskStore(
        db_path=(root / "authorization.db").absolute(),
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    trusted = binding(
        task_id=f"legacy-v{legacy_version}-replay",
        correlation_id=f"legacy-v{legacy_version}-replay-corr",
    )
    stage_challenge(signer, trusted, request_key=f"legacy-v{legacy_version}-replay")
    assert approve_decision(
        signer,
        trusted.task_id,
        trusted,
        decision_for(trusted, decision_id=f"legacy-v{legacy_version}-decision"),
        now_us=1_100_000,
    ).applied
    with sqlite3.connect(signer.db_path) as conn:
        conn.row_factory = sqlite3.Row
        approved_snapshot = dict(conn.execute(
            "SELECT * FROM authorization_tasks WHERE task_id=?",
            (trusted.task_id,),
        ).fetchone())
    worker = claim(nonce=f"legacy-v{legacy_version}-worker")
    pdp = claim_pdp(signer, trusted, 1_200_000, worker)
    assert signer.claim(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_200_000,
        lease_expires_at_us=1_400_000,
        pdp_evidence=pdp,
    ).applied
    private_context = signer.create_pdp_check_context(
        trusted.task_id,
        worker,
        stage="pre_private_read",
        now_us=1_210_000,
    )
    private_result = ExternalPdpDecisionResult(
        context_id=private_context.context_id,
        pdp_call_id=private_context.pdp_call_id,
        decision="allow",
        checked_at_us=1_210_000,
        consistency="strongest",
        cache_used=False,
    )
    signer.close()
    _downgrade_authorization_store(signer, version=legacy_version)

    with sqlite3.connect(signer.db_path) as conn:
        conn.row_factory = sqlite3.Row
        columns = [
            row[1] for row in conn.execute("PRAGMA table_info(authorization_tasks)")
        ]
        restored = {name: approved_snapshot[name] for name in columns}
        if legacy_version == 6:
            restored["mutable_state_digest"] = signer._task_state_digest_v6(restored)
        assignments = ",".join(f'"{name}"=?' for name in columns)
        conn.execute(
            f"UPDATE authorization_tasks SET {assignments} WHERE task_id=?",
            (*(restored[name] for name in columns), trusted.task_id),
        )
        if delete_later_audit:
            conn.execute(
                "DELETE FROM authorization_audit_events WHERE task_id=? "
                "AND kind IN ('pdp_check_allowed','task_claimed')",
                (trusted.task_id,),
            )

    migrated = activate(AuthorizationTaskStore(
        db_path=signer.db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    task = migrated.load_task(trusted.task_id, trusted)
    assert (task.status, task.receipt_code) == (
        "denied",
        "ambiguous_after_restart",
    )
    assert task.claim_generation is None
    assert task.claim_lease_expires_at_us is None
    assert task.send_started_at_us is None
    assert migrated.list_approved_task_work_items(now_us=1_300_000) == []
    assert not migrated.claim(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_300_000,
        lease_expires_at_us=1_500_000,
        pdp_evidence=pdp,
    ).applied
    with pytest.raises(AuthorizationIntegrityError, match="stale or ineligible"):
        migrated.create_pdp_check_context(
            trusted.task_id,
            worker,
            stage="pre_claim",
            now_us=1_300_000,
        )
    with pytest.raises(AuthorizationIntegrityError, match="stale"):
        migrated.create_pdp_decision_evidence(
            private_context,
            worker,
            private_result,
        )
    assert migrated.list_pending_due_notification_work_items(
        now_us=1_300_000
    ) == []
    assert migrated.list_stale_pre_send_notification_work_items(
        now_us=1_500_000
    ) == []
    events = migrated.list_audit_events(task_id=trusted.task_id, limit=500)
    assert any(event.event_id.startswith("task-migrated-v") for event in events)
    assert any(event.kind == "task_claimed" for event in events) is (
        not delete_later_audit
    )
    with sqlite3.connect(migrated.db_path) as conn:
        row = conn.execute(
            "SELECT decision_id,decision_digest,winning_challenge_attempt_id,"
            "winning_challenge_generation,claim_owner_digest,claim_nonce_digest,"
            "claimed_at_us,heartbeat_at_us,receipt_token,delivery_record_digest,"
            "resolution_spec_digest FROM authorization_tasks WHERE task_id=?",
            (trusted.task_id,),
        ).fetchone()
        assert row == (None,) * 11
    migrated.close()


@pytest.mark.parametrize("legacy_version", [5, 6])
def test_legacy_migration_terminalizes_every_active_task_and_notification(
    tmp_path: Path,
    legacy_version: int,
) -> None:
    root = tmp_path / f"legacy-v{legacy_version}-active-matrix"
    root.mkdir(mode=0o700)
    signer = activate(AuthorizationTaskStore(
        db_path=(root / "authorization.db").absolute(),
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    pending = binding(task_id="legacy-pending", correlation_id="legacy-pending-corr")
    approved = binding(task_id="legacy-approved", correlation_id="legacy-approved-corr")
    claimed_task = binding(task_id="legacy-claimed", correlation_id="legacy-claimed-corr")
    notice_claimed = binding(
        task_id="legacy-notice-claimed", correlation_id="legacy-notice-claimed-corr"
    )
    notice_crossed = binding(
        task_id="legacy-notice-crossed", correlation_id="legacy-notice-crossed-corr"
    )
    signer.create_pending(
        pending,
        request_key="legacy-pending",
        notification=notification(attempt_id="legacy-notice-pending"),
    )
    for index, item in enumerate((approved, claimed_task), 1):
        stage_challenge(signer, item, request_key=f"legacy-active-{index}")
        assert approve_decision(
            signer,
            item.task_id,
            item,
            decision_for(item, decision_id=f"legacy-active-decision-{index}"),
            now_us=1_100_000,
        ).applied
    task_worker = claim(nonce="legacy-task-worker")
    assert signer.claim(
        claimed_task.task_id,
        claimed_task,
        task_worker,
        now_us=1_200_000,
        lease_expires_at_us=1_500_000,
        pdp_evidence=claim_pdp(signer, claimed_task, 1_200_000, task_worker),
    ).applied
    for item, attempt_id, worker_nonce in (
        (notice_claimed, "legacy-notice-claimed", "legacy-notice-worker"),
        (notice_crossed, "legacy-notice-crossed", "legacy-crossed-worker"),
    ):
        signer.create_pending(
            item,
            request_key=f"request-{attempt_id}",
            notification=notification(attempt_id=attempt_id),
        )
        notification_worker = claim(nonce=worker_nonce)
        assert signer.claim_notification(
            attempt_id,
            notification_worker,
            now_us=1_050_000,
            lease_expires_at_us=1_500_000,
        ).applied
        if item is notice_crossed:
            assert signer.record_notification_send_started(
                attempt_id, notification_worker, now_us=1_060_000
            ).applied
    signer.close()
    _downgrade_authorization_store(signer, version=legacy_version)

    migrated = activate(AuthorizationTaskStore(
        db_path=signer.db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    expected = {
        pending.task_id: "denied",
        approved.task_id: "denied",
        claimed_task.task_id: "failed_consumed",
        notice_claimed.task_id: "denied",
        notice_crossed.task_id: "denied",
    }
    bindings = {item.task_id: item for item in (
        pending, approved, claimed_task, notice_claimed, notice_crossed
    )}
    for task_id, status in expected.items():
        task = migrated.load_task(task_id, bindings[task_id])
        assert (task.status, task.receipt_code) == (
            status,
            "ambiguous_after_restart",
        )
        assert task.claim_generation is None
        assert task.claim_lease_expires_at_us is None
        assert task.send_started_at_us is None
    active_attempt_ids = {
        "legacy-notice-pending",
        "legacy-notice-claimed",
        "legacy-notice-crossed",
        "resolution-legacy-active-decision-1",
        "resolution-legacy-active-decision-2",
    }
    with sqlite3.connect(migrated.db_path) as conn:
        rows = conn.execute(
            "SELECT attempt_id,status,receipt_code,claim_owner_digest,"
            "claim_nonce_digest,claim_generation,claim_lease_expires_at_us,"
            "send_started_at_us,provider_message_verifier,adapter_instance_id,"
            "account_binding_token,connection_epoch "
            "FROM authorization_notification_attempts"
        ).fetchall()
        by_id = {row[0]: row for row in rows}
        for attempt_id in active_attempt_ids:
            assert by_id[attempt_id][1:3] == (
                "failed",
                "ambiguous_after_restart",
            )
            assert by_id[attempt_id][3:] == (None,) * 9
        # Already terminal accepted challenges stay terminal history.
        assert by_id[f"challenge-{approved.task_id}"][1] == "provider_accepted"
    assert migrated.list_pending_due_notification_work_items(
        now_us=1_500_000
    ) == []
    assert migrated.list_stale_pre_send_notification_work_items(
        now_us=1_500_000
    ) == []
    assert migrated.reconcile_restart(now_us=1_500_000).tasks_failed_consumed == 0
    migrated.close()

    before = signer.db_path.stat().st_mtime_ns
    reopened = AuthorizationTaskStore(
        db_path=signer.db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    reopened.close()
    assert signer.db_path.stat().st_mtime_ns == before


@pytest.mark.parametrize("legacy_version", [5, 6])
@pytest.mark.parametrize("receipt_code", ["provider_rejected", "internal_failure"])
def test_legacy_denied_failed_resolution_cannot_create_retry_authority(
    tmp_path: Path,
    legacy_version: int,
    receipt_code: str,
) -> None:
    root = tmp_path / f"legacy-v{legacy_version}-denied-retry-{receipt_code}"
    root.mkdir(mode=0o700)
    signer = activate(AuthorizationTaskStore(
        db_path=(root / "authorization.db").absolute(),
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    trusted = binding(
        task_id=f"legacy-v{legacy_version}-denied-{receipt_code}",
        correlation_id=f"legacy-v{legacy_version}-denied-{receipt_code}-corr",
    )
    stage_challenge(
        signer,
        trusted,
        request_key=f"legacy-v{legacy_version}-denied-{receipt_code}",
    )
    owner_decision = decision_for(
        trusted,
        decision_id=f"legacy-v{legacy_version}-denied-{receipt_code}-decision",
    )
    original = decision_resolution(
        signer, trusted, owner_decision, created_at_us=1_100_000
    )
    assert deny_decision(
        signer,
        trusted.task_id,
        trusted,
        owner_decision,
        now_us=1_100_000,
        reason_code="owner_rejected",
        resolution_notification=original,
    ).applied
    notification_worker = claim(
        nonce=f"legacy-v{legacy_version}-{receipt_code}-worker"
    )
    assert signer.claim_notification(
        original.attempt_id,
        notification_worker,
        now_us=1_110_000,
        lease_expires_at_us=1_200_000,
    ).applied
    assert signer.finish_notification(
        original.attempt_id,
        notification_worker,
        now_us=1_120_000,
        outcome="failed",
        receipt_code=receipt_code,
    ).applied
    forensic_event_ids = sorted(
        event.event_id
        for event in signer.list_audit_events(task_id=trusted.task_id, limit=500)
    )
    signer.close()
    _downgrade_authorization_store(signer, version=legacy_version)

    migrated = activate(AuthorizationTaskStore(
        db_path=signer.db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    migrated_task = migrated.load_task(trusted.task_id, trusted)
    assert (migrated_task.status, migrated_task.completed_at_us) == (
        "denied",
        1_100_000,
    )
    assert sorted(
        event.event_id
        for event in migrated.list_audit_events(task_id=trusted.task_id, limit=500)
    ) == forensic_event_ids
    failed_notifications = migrated.list_notifications(
        status="failed",
        due_before_us=1_130_000,
        now_us=1_130_000,
    )
    assert [
        (attempt.attempt_id, attempt.receipt_code)
        for attempt in failed_notifications
    ] == [(original.attempt_id, receipt_code)]
    replacement = replace(
        original,
        attempt_id=f"legacy-v{legacy_version}-{receipt_code}-retry",
        challenge_nonce=f"legacy-v{legacy_version}-{receipt_code}-retry",
        created_at_us=1_130_000,
        due_at_us=1_130_000,
    )
    task_authority_sql = (
        "SELECT decision_id,decision_digest,winning_challenge_attempt_id,"
        "winning_challenge_generation,claim_owner_digest,claim_nonce_digest,"
        "claim_generation,claim_lease_expires_at_us,claimed_at_us,heartbeat_at_us,"
        "send_started_at_us,receipt_token,delivery_acceptance_status,"
        "delivery_accepted_at_us,delivery_transport_implementation,"
        "delivery_runtime_identity,delivery_account_binding_token,"
        "delivery_connection_epoch,delivery_record_digest,resolution_spec_digest "
        "FROM authorization_tasks WHERE task_id=?"
    )
    with sqlite3.connect(migrated.db_path) as conn:
        authority = conn.execute(
            task_authority_sql,
            (trusted.task_id,),
        ).fetchone()
        before = (
            conn.execute(
                "SELECT COUNT(*) FROM authorization_notification_attempts"
            ).fetchone()[0],
            conn.execute(
                "SELECT COUNT(*) FROM authorization_audit_events"
            ).fetchone()[0],
        )
    assert authority == (None,) * 20

    assert not migrated.retry_resolution_notification(
        trusted.task_id,
        trusted,
        owner_decision,
        failed_attempt_id=original.attempt_id,
        replacement_notification=replacement,
        now_us=1_130_000,
    ).applied
    assert migrated.list_pending_due_notification_work_items(now_us=1_130_000) == []
    assert migrated.list_stale_pre_send_notification_work_items(now_us=1_300_000) == []
    assert migrated.reconcile_restart(now_us=1_300_000).tasks_failed_consumed == 0
    with sqlite3.connect(migrated.db_path) as conn:
        after = (
            conn.execute(
                "SELECT COUNT(*) FROM authorization_notification_attempts"
            ).fetchone()[0],
            conn.execute(
                "SELECT COUNT(*) FROM authorization_audit_events"
            ).fetchone()[0],
        )
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_notification_attempts "
            "WHERE attempt_id=?",
            (replacement.attempt_id,),
        ).fetchone()[0] == 0
    assert after == before
    migrated.close()

    reopened = AuthorizationTaskStore(
        db_path=signer.db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    assert reopened.load_task(trusted.task_id, trusted).status == "denied"
    with sqlite3.connect(reopened.db_path) as conn:
        assert conn.execute(
            task_authority_sql,
            (trusted.task_id,),
        ).fetchone() == (None,) * 20
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM authorization_notification_attempts"
            ).fetchone()[0],
            conn.execute(
                "SELECT COUNT(*) FROM authorization_audit_events"
            ).fetchone()[0],
        ) == after
    reopened.close()


@pytest.mark.parametrize("legacy_version", [5, 6])
def test_legacy_migration_keeps_terminal_tasks_terminal(
    tmp_path: Path,
    legacy_version: int,
) -> None:
    root = tmp_path / f"legacy-v{legacy_version}-terminal-matrix"
    root.mkdir(mode=0o700)
    signer = activate(AuthorizationTaskStore(
        db_path=(root / "authorization.db").absolute(),
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    denied = binding(task_id="legacy-denied", correlation_id="legacy-denied-corr")
    canceled = binding(task_id="legacy-canceled", correlation_id="legacy-canceled-corr")
    expired = binding(
        task_id="legacy-expired",
        correlation_id="legacy-expired-corr",
        expires_at_us=1_100_000,
    )
    failed = binding(task_id="legacy-failed", correlation_id="legacy-failed-corr")
    consumed = binding(task_id="legacy-consumed", correlation_id="legacy-consumed-corr")
    stage_challenge(signer, denied, request_key="legacy-denied")
    assert deny_decision(
        signer,
        denied.task_id,
        denied,
        decision_for(denied, decision_id="legacy-denied-decision"),
        now_us=1_090_000,
        reason_code="owner_rejected",
    ).applied
    signer.create_pending(canceled, request_key="legacy-canceled")
    assert signer.cancel(
        canceled.task_id,
        canceled,
        now_us=1_050_000,
        reason_code="request_canceled",
    ).applied
    signer.create_pending(expired, request_key="legacy-expired")
    assert signer.expire_due(now_us=expired.expires_at_us) == 1
    failed_worker = claim(nonce="legacy-failed-worker")
    stage_challenge(signer, failed, request_key="claimed-legacy-failed")
    assert approve_decision(
        signer,
        failed.task_id,
        failed,
        decision_for(failed, decision_id="legacy-failed-decision"),
        now_us=1_100_000,
    ).applied
    assert signer.claim(
        failed.task_id,
        failed,
        failed_worker,
        now_us=1_200_000,
        lease_expires_at_us=1_400_000,
        pdp_evidence=claim_pdp(signer, failed, 1_200_000, failed_worker),
    ).applied
    assert signer.finish(
        failed.task_id,
        failed,
        failed_worker,
        now_us=1_250_000,
        outcome="failed_consumed",
        receipt_code="provider_timeout",
    ).applied
    consumed_worker = claim(nonce="legacy-consumed-worker")
    stage_challenge(signer, consumed, request_key="claimed-legacy-consumed")
    assert approve_decision(
        signer,
        consumed.task_id,
        consumed,
        decision_for(consumed, decision_id="legacy-consumed-decision"),
        now_us=1_100_000,
    ).applied
    assert signer.claim(
        consumed.task_id,
        consumed,
        consumed_worker,
        now_us=1_200_000,
        lease_expires_at_us=1_400_000,
        pdp_evidence=claim_pdp(signer, consumed, 1_200_000, consumed_worker),
    ).applied
    assert signer.authorize_private_read(
        consumed.task_id,
        consumed,
        consumed_worker,
        private_read_pdp(signer, consumed, 1_210_000, consumed_worker),
        now_us=1_210_000,
    ).applied
    assert signer.record_send_started(
        consumed.task_id, consumed, consumed_worker, now_us=1_220_000
    ).applied
    assert signer.finish(
        consumed.task_id,
        consumed,
        consumed_worker,
        now_us=1_240_000,
        outcome="consumed",
        receipt_code="provider_accepted",
        evidence=delivery_acceptance(
            signer,
            consumed,
            consumed_worker,
            accepted_at_us=1_230_000,
            provider_message_id="legacy-consumed-provider",
        ),
    ).applied
    expected = {
        denied.task_id: "denied",
        canceled.task_id: "canceled",
        expired.task_id: "expired",
        failed.task_id: "failed_consumed",
        consumed.task_id: "consumed",
    }
    signer.close()
    _downgrade_authorization_store(signer, version=legacy_version)
    migrated = activate(AuthorizationTaskStore(
        db_path=signer.db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    bindings = {item.task_id: item for item in (
        denied, canceled, expired, failed, consumed
    )}
    assert {
        task_id: migrated.load_task(task_id, bindings[task_id]).status
        for task_id in expected
    } == expected
    migrated.close()


@pytest.mark.parametrize("legacy_version", [5, 6])
def test_legacy_migration_fault_rolls_back_entire_snapshot(
    tmp_path: Path,
    legacy_version: int,
) -> None:
    root = tmp_path / f"legacy-v{legacy_version}-fault"
    root.mkdir(mode=0o700)
    signer = activate(AuthorizationTaskStore(
        db_path=(root / "authorization.db").absolute(),
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    trusted = binding(
        task_id=f"legacy-v{legacy_version}-fault",
        correlation_id=f"legacy-v{legacy_version}-fault-corr",
    )
    signer.create_pending(
        trusted,
        request_key=f"legacy-v{legacy_version}-fault",
        notification=notification(attempt_id=f"legacy-v{legacy_version}-fault-notice"),
    )
    signer.close()
    _downgrade_authorization_store(signer, version=legacy_version)
    with sqlite3.connect(signer.db_path) as conn:
        before_dump = list(conn.iterdump())
        before_version = conn.execute("PRAGMA user_version").fetchone()[0]

    fault_step = (
        "migration.v6.after_terminalization"
        if legacy_version == 5
        else "migration.v7.after_terminalization"
    )

    def fault(step: str) -> None:
        if step == fault_step:
            raise RuntimeError("migration fault")

    with pytest.raises(RuntimeError, match="migration fault"):
        AuthorizationTaskStore(
            db_path=signer.db_path,
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
            _fault_hook=fault,
        )
    with sqlite3.connect(signer.db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == before_version
        assert list(conn.iterdump()) == before_dump

    migrated = activate(AuthorizationTaskStore(
        db_path=signer.db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    assert migrated.load_task(trusted.task_id, trusted).status == "denied"
    migrated.close()


def test_real_v1_to_v2_to_v3_migration_preserves_rows_and_hmacs_under_concurrent_restart(
    tmp_path: Path,
) -> None:
    scratch_root = tmp_path / "scratch-v2"
    scratch_root.mkdir(mode=0o700)
    signer = AuthorizationTaskStore(
        db_path=(scratch_root / "authorization.db").absolute(),
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    trusted = replace(
        binding(),
        delivery_platform="",
        delivery_transport_implementation="",
        delivery_runtime_identity="",
        delivery_account_binding="",
        delivery_connection_epoch=0,
        policy_version="",
        policy_hash="",
    )
    request_key = "migrated-request"
    spec = notification(attempt_id="migrated-challenge", challenge_generation=1)
    destination_digest = hmac.new(
        REQUEST_KEY,
        b"hermes-authorization-notification-destination-v1\0"
        + spec.destination_bytes(),
        hashlib.sha256,
    ).hexdigest()

    root = tmp_path / "real-v1"
    root.mkdir(mode=0o700)
    db_path = (root / "authorization.db").absolute()
    db_path.touch(mode=0o600)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_SCHEMA_V1)
        conn.execute(
            "INSERT INTO authorization_tasks "
            "(task_id,correlation_id,scoped_request_key,binding_json,binding_digest,"
            "request_digest,key_version,status,created_at_us,expires_at_us) "
            "VALUES (?,?,?,?,?,?,?,'approval_required',?,?)",
            (
                trusted.task_id,
                trusted.correlation_id,
                request_key,
                trusted.canonical_bytes().decode(),
                signer._binding_digest(trusted),
                signer._request_digest(request_key, trusted),
                "test-k1",
                trusted.created_at_us,
                trusted.expires_at_us,
            ),
        )
        conn.execute(
            "INSERT INTO authorization_audit_events VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "task-created:task-001",
                trusted.task_id,
                "task_created",
                "created",
                signer.audit_token("source-user", trusted.source_user),
                signer.audit_token("approval-user", trusted.approval_user),
                signer._request_digest(request_key, trusted),
                "test-k1",
                trusted.created_at_us,
            ),
        )
        conn.execute(
            "INSERT INTO authorization_notification_attempts "
            "(attempt_id,task_id,kind,destination_profile,destination_account,"
            "destination_chat,destination_thread,destination_digest,key_version,status,"
            "created_at_us,due_at_us,completed_at_us,receipt_code,provider_message_token,"
            "challenge_nonce_digest) VALUES (?,?,?,?,?,?,?,?,?,'sent',?,?,?,?,?,?)",
            (
                spec.attempt_id,
                trusted.task_id,
                spec.kind,
                spec.destination_profile,
                spec.destination_account,
                spec.destination_chat,
                spec.destination_thread,
                destination_digest,
                "test-k1",
                spec.created_at_us,
                spec.due_at_us,
                1_070_000,
                "deliver" + "ed",
                signer.audit_token("provider-message", "legacy-provider-message"),
                signer._challenge_nonce_digest(
                    spec.challenge_nonce, verifier_version="v1"
                ),
            ),
        )

    def migrate(_index: int) -> None:
        AuthorizationTaskStore(
            db_path=db_path,
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(migrate, range(8)))
    migrated = activate(AuthorizationTaskStore(
        db_path=db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    migrated_task = migrated.load_task(trusted.task_id, trusted)
    assert migrated_task.status == "denied"
    assert migrated_task.receipt_code == "incomplete_delivery_binding"
    assert [event.kind for event in migrated.list_audit_events(task_id=trusted.task_id)] == [
        "task_created",
        "task_denied",
    ]
    attempts = migrated.list_notifications(
        status="failed", due_before_us=spec.due_at_us, now_us=spec.due_at_us
    )
    assert [(attempt.attempt_id, attempt.challenge_generation) for attempt in attempts] == [
        (spec.attempt_id, 1)
    ]
    assert not approve_decision(migrated,
        trusted.task_id,
        trusted,
        decision_for(
            trusted,
            challenge_attempt_id=spec.attempt_id,
            challenge_nonce=spec.challenge_nonce,
            challenge_provider_message_id="legacy-provider-message",
            reply_to_provider_message_id="legacy-provider-message",
        ),
        now_us=1_100_000,
    ).applied
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        columns = [
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(authorization_notification_attempts)"
            )
        ]
        indexes = [
            row[1]
            for row in conn.execute(
                "PRAGMA index_list(authorization_notification_attempts)"
            )
        ]
    assert len(columns) == len(set(columns))
    assert len(indexes) == len(set(indexes))


def test_secure_path_rejects_symlink_nonregular_modes_and_unsafe_ancestor(
    tmp_path: Path,
) -> None:
    root = tmp_path / "secure-paths"
    root.mkdir(mode=0o700)
    target = root / "target.db"
    target.touch(mode=0o600)
    symlink = root / "symlink.db"
    symlink.symlink_to(target)
    with pytest.raises(UnsafeAuthorizationStorePath):
        AuthorizationTaskStore(
            db_path=symlink.absolute(), audit_hmac_key=AUDIT_KEY, request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )

    insecure_file = root / "insecure.db"
    insecure_file.touch(mode=0o600)
    insecure_file.chmod(0o644)
    with pytest.raises(UnsafeAuthorizationStorePath):
        AuthorizationTaskStore(
            db_path=insecure_file.absolute(), audit_hmac_key=AUDIT_KEY, request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )
    assert stat.S_IMODE(insecure_file.stat().st_mode) == 0o644

    unsafe_parent = tmp_path / "unsafe-parent"
    unsafe_parent.mkdir(mode=0o700)
    unsafe_parent.chmod(0o777)
    with pytest.raises(UnsafeAuthorizationStorePath):
        AuthorizationTaskStore(
            db_path=(unsafe_parent / "auth.db").absolute(),
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        )
    assert stat.S_IMODE(unsafe_parent.stat().st_mode) == 0o777


def test_open_rechecks_file_identity_after_replacement(store: AuthorizationTaskStore) -> None:
    original = store.db_path.with_suffix(".old")
    store.db_path.rename(original)
    store.db_path.touch(mode=0o600)
    with pytest.raises(UnsafeAuthorizationStorePath, match="identity changed"):
        store.list_audit_events(task_id="task-001")


def test_audit_rows_have_no_raw_enumerable_identity(store: AuthorizationTaskStore) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="request-redacted-audit")
    approve_decision(store, "task-001", trusted, decision_for(trusted), now_us=1_100_000)
    with sqlite3.connect(store.db_path) as conn:
        serialized = repr(
            conn.execute("SELECT * FROM authorization_audit_events").fetchall()
        )
    for raw in ("user-a", "owner-user", "chat-a", "owner-chat", "delivery-chat"):
        assert raw not in serialized


@pytest.mark.parametrize("position", ["first", "middle", "final"])
def test_terminal_audit_chain_rejects_first_middle_and_final_deletion(
    store: AuthorizationTaskStore, position: str
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key=f"audit-delete-{position}")
    assert store.cancel(
        trusted.task_id, trusted, now_us=1_200_000, reason_code="request_canceled"
    ).applied
    events = store.list_audit_events(task_id=trusted.task_id, limit=500)
    assert len(events) >= 3
    index = {"first": 0, "middle": len(events) // 2, "final": -1}[position]
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "DELETE FROM authorization_audit_events WHERE event_id=?",
            (events[index].event_id,),
        )
    with pytest.raises(AuthorizationIntegrityError, match="audit task"):
        store.list_audit_events(task_id=trusted.task_id, limit=500)
    with pytest.raises(AuthorizationIntegrityError):
        store.load_task(trusted.task_id, trusted)


def test_terminal_audit_chain_rejects_reorder_and_duplicate_insertion(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="audit-reorder")
    assert store.cancel(
        trusted.task_id, trusted, now_us=1_200_000, reason_code="request_canceled"
    ).applied
    events = store.list_audit_events(task_id=trusted.task_id, limit=500)
    with sqlite3.connect(store.db_path) as conn:
        conn.execute("PRAGMA ignore_check_constraints=ON")
        conn.execute(
            "UPDATE authorization_audit_events SET audit_sequence=-1 "
            "WHERE task_id=? AND audit_sequence=1",
            (trusted.task_id,),
        )
        conn.execute(
            "UPDATE authorization_audit_events SET audit_sequence=1 "
            "WHERE task_id=? AND audit_sequence=2",
            (trusted.task_id,),
        )
        conn.execute(
            "UPDATE authorization_audit_events SET audit_sequence=2 "
            "WHERE task_id=? AND audit_sequence=-1",
            (trusted.task_id,),
        )
    with pytest.raises(AuthorizationIntegrityError):
        store.list_audit_events(task_id=trusted.task_id, limit=500)

    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "DELETE FROM authorization_audit_events WHERE task_id=?", (trusted.task_id,)
        )
        for event in events:
            values = {
                "event_id": event.event_id,
                "task_id": event.task_id,
                "kind": event.kind,
                "reason_code": event.reason_code,
                "actor_token": event.actor_token,
                "target_token": event.target_token,
                "request_digest": event.request_digest,
                "key_version": event.key_version,
                "occurred_at_us": event.occurred_at_us,
                "audit_sequence": event.audit_sequence,
                "previous_record_digest": event.previous_record_digest,
            }
            conn.execute(
                "INSERT INTO authorization_audit_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (*values.values(), store._audit_record_digest(values)),
            )
        tail = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE task_id=? "
            "ORDER BY audit_sequence DESC LIMIT 1",
            (trusted.task_id,),
        ).fetchone()
        conn.execute(
            "INSERT INTO authorization_audit_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "duplicate-insertion", trusted.task_id, tail[2], tail[3], tail[4],
                tail[5], tail[6], tail[7], tail[8], len(events) + 1,
                tail[11], tail[11],
            ),
        )
    with pytest.raises(AuthorizationIntegrityError):
        store.list_audit_events(task_id=trusted.task_id, limit=500)


def test_audit_chain_rejects_cross_task_transplant(store: AuthorizationTaskStore) -> None:
    source = binding(task_id="task-source", correlation_id="corr-source")
    target = binding(task_id="task-target", correlation_id="corr-target")
    assert store.create_pending(
        source,
        request_key="audit-transplant-source",
        notification=notification(attempt_id="audit-transplant-notification"),
    ).applied
    assert store.create_pending(target, request_key="audit-transplant-target").applied
    with sqlite3.connect(store.db_path) as conn:
        moved = conn.execute(
            "SELECT event_id FROM authorization_audit_events "
            "WHERE task_id=? AND audit_sequence=2",
            (source.task_id,),
        ).fetchone()[0]
        conn.execute(
            "UPDATE authorization_audit_events SET task_id=? WHERE event_id=?",
            (target.task_id, moved),
        )
    for task in (source, target):
        with pytest.raises(AuthorizationIntegrityError):
            store.list_audit_events(task_id=task.task_id, limit=500)


def test_pdp_evidence_cannot_authorize_or_change_approved_state(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="request-pdp-hook")
    approve_decision(store,
        trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    )
    approved = store.load_task(trusted.task_id, trusted)
    mismatch = store.record_pdp_evidence(
        trusted.task_id,
        trusted,
        claim(),
        pdp_evidence(
            store, trusted, approved, stage="pre_private_read", checked_at_us=1_150_000
        ),
        now_us=1_150_002,
    )
    assert not mismatch.applied
    assert store.load_task(trusted.task_id, trusted).status == "approved"


def test_schema_rejects_unbounded_audit_reason_codes(store: AuthorizationTaskStore) -> None:
    store.create_pending(binding(), request_key="request-audit-reason-check")
    with sqlite3.connect(store.db_path) as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO authorization_audit_events "
            "(event_id,task_id,kind,reason_code,actor_token,target_token,request_digest,occurred_at_us) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ("bad-event", "task-001", "task_created", "free form prose", "h1:a", "h1:b", "h1:c", 1),
        )


def test_private_sentinel_cannot_enter_store_rows_or_error_tracebacks(
    store: AuthorizationTaskStore,
) -> None:
    sentinel = "PRIVATE_RESULT_SENTINEL_78af5d"
    trusted = binding()
    stage_challenge(store, trusted, request_key="request-sentinel")
    approve_decision(store, "task-001", trusted, decision_for(trusted), now_us=1_100_000)
    store.claim(
        "task-001", trusted, claim(), now_us=1_200_000, lease_expires_at_us=1_300_000,
        pdp_evidence=claim_pdp(store, trusted, 1_200_000),
    )
    store.authorize_private_read(
        "task-001",
        trusted,
        claim(),
        private_read_pdp(store, trusted, 1_205_000),
        now_us=1_205_000,
    )
    store.record_send_started("task-001", trusted, claim(), now_us=1_210_000)
    store.finish(
        "task-001",
        trusted,
        claim(),
        now_us=1_220_000,
        outcome="consumed",
        receipt_code="provider_accepted",
        evidence=delivery_acceptance(
            store,
            trusted,
            claim(),
            accepted_at_us=1_215_000,
            provider_message_id=sentinel,
        ),
    )
    with sqlite3.connect(store.db_path) as conn:
        all_rows = repr(
            {
                table: conn.execute(f'SELECT * FROM "{table}"').fetchall()
                for (table,) in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
        )
    assert sentinel not in all_rows
    assert sentinel.encode() not in store.db_path.read_bytes()
    try:
        store.finish(
            "task-001",
            trusted,
            claim(),
            now_us=1_230_000,
            outcome="not-an-outcome",
            receipt_code="provider_accepted",
            provider_receipt_id=sentinel,
        )
    except ValueError as exc:
        rendered = "".join(traceback.format_exception(exc))
        assert sentinel not in str(exc)
        assert sentinel not in rendered


def test_randomized_state_machine_never_reopens_terminal_state(
    store: AuthorizationTaskStore,
) -> None:
    rng = random.Random(20260804)
    for index in range(25):
        item = binding(task_id=f"task-random-{index}", correlation_id=f"corr-random-{index}")
        stage_challenge(store, item, request_key=f"request-random-{index}")
        owner_decision = decision_for(item, decision_id=f"decision-random-{index}")
        actions = ["approve", "deny", "cancel", "expire"]
        rng.shuffle(actions)
        for action in actions:
            if action == "approve":
                approve_decision(store, item.task_id, item, owner_decision, now_us=1_100_000)
            elif action == "deny":
                deny_decision(store,
                    item.task_id,
                    item,
                    owner_decision,
                    now_us=1_100_000,
                    reason_code="owner_rejected",
                )
            elif action == "cancel":
                store.cancel(
                    item.task_id, item, now_us=1_100_000, reason_code="request_canceled"
                )
            else:
                store.expire_due(now_us=2_000_000)
        terminal = store.load_task(item.task_id, item).status
        assert terminal in {"denied", "canceled", "expired"}
        assert not approve_decision(store,
            item.task_id,
            item,
            decision_for(item, decision_id=f"late-random-{index}"),
            now_us=1_200_000,
        ).applied
        assert store.load_task(item.task_id, item).status == terminal


def pdp_evidence(
    value: AuthorizationTaskStore,
    item: TrustedAuthorizationBinding,
    task: object,
    *,
    stage: str,
    checked_at_us: int,
    **changes: object,
) -> PdpDecisionEvidence:
    worker = changes.pop("worker", claim())
    assert isinstance(worker, ClaimIdentity)
    current_task = value.load_task(item.task_id, item)
    eligible_stage = (
        "pre_claim" if current_task.status == "approved" else "pre_private_read"
    )
    context = value.create_pdp_check_context(
        item.task_id, worker, stage=eligible_stage, now_us=checked_at_us
    )
    decision_value = changes.pop("decision", "allow")
    consistency = changes.pop("consistency", "strongest")
    cache_used = changes.pop("cache_used", False)
    result = ExternalPdpDecisionResult(
        context_id=context.context_id,
        pdp_call_id=context.pdp_call_id,
        decision=decision_value,
        checked_at_us=checked_at_us,
        consistency=consistency,
        cache_used=cache_used,
    )
    evidence = value.create_pdp_decision_evidence(context, worker, result)
    replacements = dict(changes)
    if stage != eligible_stage:
        replacements["stage"] = stage
    return replace(evidence, **replacements) if replacements else evidence


def add_accepted_generation(
    value: AuthorizationTaskStore,
    item: TrustedAuthorizationBinding,
    *,
    generation: int,
    nonce_suffix: str,
) -> tuple[NotificationAttemptSpec, ClaimIdentity, ProviderAcceptanceEvidence]:
    attempt_id = f"challenge-{item.task_id}-{generation}"
    spec = notification(
        attempt_id=attempt_id,
        challenge_generation=generation,
        challenge_nonce=f"nonce-{nonce_suffix}-" + "n" * 32,
        created_at_us=1_000_000 + generation,
        due_at_us=1_000_010 + generation,
        destination_profile=item.approval_profile,
        destination_account=item.approval_account,
        destination_chat=item.approval_chat,
        destination_thread=item.approval_thread,
    )
    assert value.create_notification(item.task_id, item, spec).applied
    worker = claim(nonce=f"worker-{generation}")
    assert value.claim_notification(
        attempt_id,
        worker,
        now_us=1_020_000 + generation,
        lease_expires_at_us=1_040_000 + generation,
    ).applied
    assert value.record_notification_send_started(
        attempt_id, worker, now_us=1_025_000 + generation
    ).applied
    proof = acceptance(
        item,
        attempt_id=attempt_id,
        challenge_generation=generation,
        provider_message_id=f"provider-{generation}",
    )
    assert value.finish_notification(
        attempt_id,
        worker,
        now_us=proof.accepted_at_us,
        outcome="provider_accepted",
        receipt_code="provider_accepted",
        evidence=proof,
    ).applied
    return spec, worker, proof


def generation_decision(
    item: TrustedAuthorizationBinding,
    spec: NotificationAttemptSpec,
    proof: ProviderAcceptanceEvidence,
    *,
    decision_id: str,
    source_message: str,
) -> OwnerDecision:
    return decision_for(
        item,
        decision_id=decision_id,
        source_message=source_message,
        challenge_attempt_id=spec.attempt_id,
        challenge_generation=spec.challenge_generation,
        challenge_nonce=spec.challenge_nonce,
        challenge_provider_message_id=proof.provider_message_id,
        reply_to_provider_message_id=proof.provider_message_id,
        adapter_instance_id=proof.adapter_instance_id,
        account_binding=proof.account_binding,
        connection_epoch=proof.connection_epoch,
    )


def test_provider_acceptance_requires_complete_typed_live_evidence(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    spec = notification(attempt_id="typed-evidence", challenge_generation=1)
    store.create_pending(
        trusted, request_key="typed-evidence", notification=spec
    )
    worker = claim(nonce="typed-evidence-worker")
    store.claim_notification(
        spec.attempt_id,
        worker,
        now_us=1_020_000,
        lease_expires_at_us=1_040_000,
    )
    store.record_notification_send_started(
        spec.attempt_id, worker, now_us=1_025_000
    )
    with pytest.raises(TypeError, match="typed provider acceptance evidence"):
        store.finish_notification(
            spec.attempt_id,
            worker,
            now_us=1_030_000,
            outcome="provider_accepted",
            receipt_code="provider_accepted",
            evidence={"provider_message_id": "only-an-id"},  # type: ignore[arg-type]
        )
    exact = acceptance(trusted, attempt_id=spec.attempt_id)
    mismatches = (
        replace(exact, task_id="wrong-task"),
        replace(exact, correlation_id="wrong-correlation"),
        replace(exact, attempt_id="wrong-attempt"),
        replace(exact, challenge_generation=2),
        replace(exact, worker_claim_generation=2),
        replace(exact, account_binding="wrong-account"),
        replace(exact, destination_profile="wrong-profile"),
        replace(exact, destination_chat="wrong-chat"),
        replace(exact, accepted_at_us=1_024_999),
    )
    for wrong in mismatches:
        assert not store.finish_notification(
            spec.attempt_id,
            worker,
            now_us=max(1_030_000, wrong.accepted_at_us),
            outcome="provider_accepted",
            receipt_code="provider_accepted",
            evidence=wrong,
        ).applied
    assert store.finish_notification(
        spec.attempt_id,
        worker,
        now_us=1_035_000,
        outcome="failed",
        receipt_code="provider_timeout",
    ).applied
    attempted = decision_for(
        trusted,
        challenge_attempt_id=spec.attempt_id,
        challenge_generation=1,
        challenge_nonce=spec.challenge_nonce,
        challenge_provider_message_id="only-an-id",
        reply_to_provider_message_id="only-an-id",
    )
    assert not approve_decision(store,
        trusted.task_id, trusted, attempted, now_us=1_100_000
    ).applied
    retry_spec, _retry_worker, retry_proof = add_accepted_generation(
        store, trusted, generation=2, nonce_suffix="typed-retry"
    )
    assert approve_decision(store,
        trusted.task_id,
        trusted,
        generation_decision(
            trusted,
            retry_spec,
            retry_proof,
            decision_id="typed-retry-decision",
            source_message="typed-retry-reply",
        ),
        now_us=1_100_001,
    ).applied


@pytest.mark.parametrize("winning_generation", [1, 2])
def test_any_provider_accepted_generation_can_win_and_supersedes_all_others(
    store: AuthorizationTaskStore, winning_generation: int
) -> None:
    trusted = binding()
    store.create_pending(trusted, request_key=f"multi-{winning_generation}")
    generations = {
        generation: add_accepted_generation(
            store, trusted, generation=generation, nonce_suffix=str(generation)
        )
        for generation in (1, 2)
    }
    spec, _worker, proof = generations[winning_generation]
    winner = generation_decision(
        trusted,
        spec,
        proof,
        decision_id=f"winner-{winning_generation}",
        source_message=f"reply-{winning_generation}",
    )
    assert approve_decision(store,
        trusted.task_id, trusted, winner, now_us=1_100_000
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        states = dict(
            conn.execute(
                "SELECT challenge_generation,challenge_state "
                "FROM authorization_notification_attempts "
                "WHERE task_id=? AND kind='approval_challenge'",
                (trusted.task_id,),
            )
        )
    assert states[winning_generation] == "consumed"
    assert states[3 - winning_generation] == "superseded"
    losing_spec, _worker, losing_proof = generations[3 - winning_generation]
    loser = generation_decision(
        trusted,
        losing_spec,
        losing_proof,
        decision_id="loser",
        source_message="losing-reply",
    )
    assert not approve_decision(store,
        trusted.task_id, trusted, loser, now_us=1_100_001
    ).applied
    assert approve_decision(store,
        trusted.task_id, trusted, winner, now_us=1_100_002
    ).idempotent


def test_conflicting_replies_to_distinct_generations_have_one_decision_and_audit(
    tmp_path: Path,
) -> None:
    root = tmp_path / "challenge-race"
    root.mkdir(mode=0o700)
    db_path = (root / "authorization.db").absolute()
    initial = activate(AuthorizationTaskStore(
        db_path=db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    trusted = binding()
    initial.create_pending(trusted, request_key="challenge-race")
    first = add_accepted_generation(
        initial, trusted, generation=1, nonce_suffix="one"
    )
    second = add_accepted_generation(
        initial, trusted, generation=2, nonce_suffix="two"
    )
    approve_reply = generation_decision(
        trusted, first[0], first[2], decision_id="approve-race", source_message="reply-a"
    )
    deny_reply = generation_decision(
        trusted, second[0], second[2], decision_id="deny-race", source_message="reply-b"
    )

    def decide(approve: bool) -> bool:
        if approve:
            return approve_decision(initial,
                trusted.task_id, trusted, approve_reply, now_us=1_100_000
            ).applied
        return deny_decision(initial,
            trusted.task_id,
            trusted,
            deny_reply,
            now_us=1_100_000,
            reason_code="owner_rejected",
        ).applied

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(decide, (True, False)))
    assert sum(outcomes) == 1
    events = initial.list_audit_events(task_id=trusted.task_id)
    assert sum(event.kind in {"task_approved", "task_denied"} for event in events) == 1


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("task_id", "wrong-task"),
        ("correlation_id", "wrong-correlation"),
        ("challenge_generation", 9),
        ("challenge_nonce", "wrong-" + "n" * 32),
        ("challenge_provider_message_id", "wrong-provider-id"),
        ("reply_to_provider_message_id", "copied-provider-id"),
        ("account_binding", "wrong-account"),
        ("connection_epoch", 99),
        ("adapter_instance_id", "wrong-adapter"),
    ],
)
def test_generation_reply_binding_mismatch_denies_without_transition(
    store: AuthorizationTaskStore, field: str, wrong: object
) -> None:
    trusted = binding()
    store.create_pending(trusted, request_key=f"wrong-{field}")
    spec, _worker, proof = add_accepted_generation(
        store, trusted, generation=1, nonce_suffix="exact"
    )
    exact = generation_decision(
        trusted, spec, proof, decision_id=f"decision-{field}", source_message="reply"
    )
    assert not approve_decision(store,
        trusted.task_id, trusted, replace(exact, **{field: wrong}), now_us=1_100_000
    ).applied
    assert store.load_task(trusted.task_id, trusted).status == "approval_required"


def test_restart_between_generations_preserves_both_until_expiry(
    tmp_path: Path,
) -> None:
    root = tmp_path / "generation-restart"
    root.mkdir(mode=0o700)
    db_path = (root / "authorization.db").absolute()
    first_store = activate(AuthorizationTaskStore(
        db_path=db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    trusted = binding()
    first_store.create_pending(trusted, request_key="generation-restart")
    first = add_accepted_generation(
        first_store, trusted, generation=1, nonce_suffix="before"
    )
    first_store.close()
    restarted = activate(AuthorizationTaskStore(
        db_path=db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    ))
    add_accepted_generation(restarted, trusted, generation=2, nonce_suffix="after")
    winning = generation_decision(
        trusted, first[0], first[2], decision_id="restart-winner", source_message="reply"
    )
    assert approve_decision(restarted,
        trusted.task_id, trusted, winning, now_us=1_100_000
    ).applied

    expired = binding(task_id="task-expired-generation", correlation_id="corr-expired-generation")
    restarted.create_pending(expired, request_key="expired-generation")
    exp_spec, _worker, exp_proof = add_accepted_generation(
        restarted, expired, generation=1, nonce_suffix="expired"
    )
    assert restarted.expire_due(now_us=expired.expires_at_us) >= 1
    assert restarted.load_task(expired.task_id, expired).status == "expired"
    assert not approve_decision(restarted,
        expired.task_id,
        expired,
        generation_decision(
            expired, exp_spec, exp_proof, decision_id="late", source_message="late"
        ),
        now_us=expired.expires_at_us,
    ).applied


@pytest.mark.parametrize(
    "column",
    [
        "correlation_id",
        "challenge_generation",
        "challenge_nonce_digest",
        "provider_message_verifier",
        "provider_acceptance_status",
        "provider_accepted_at_us",
        "adapter_instance_id",
        "account_binding_token",
        "connection_epoch",
        "challenge_state",
    ],
)
def test_generation_field_hmac_tampering_denies_without_task_transition(
    store: AuthorizationTaskStore, column: str
) -> None:
    trusted = binding()
    store.create_pending(trusted, request_key=f"tamper-{column}")
    spec, _worker, proof = add_accepted_generation(
        store, trusted, generation=1, nonce_suffix="tamper"
    )
    with sqlite3.connect(store.db_path) as conn:
        current = conn.execute(
            f'SELECT "{column}" FROM authorization_notification_attempts WHERE attempt_id=?',
            (spec.attempt_id,),
        ).fetchone()[0]
        if column == "provider_acceptance_status":
            replacement = None
        elif column == "challenge_state":
            replacement = "superseded"
        else:
            replacement = current + 1 if isinstance(current, int) else f"{current}-tampered"
        conn.execute(
            f'UPDATE authorization_notification_attempts SET "{column}"=? WHERE attempt_id=?',
            (replacement, spec.attempt_id),
        )
    reply = generation_decision(
        trusted, spec, proof, decision_id=f"tamper-{column}", source_message="reply"
    )
    assert not approve_decision(store,
        trusted.task_id, trusted, reply, now_us=1_100_000
    ).applied
    assert store.load_task(trusted.task_id, trusted).status == "approval_required"


def test_pdp_allow_evidence_is_typed_uncached_strong_and_stage_specific(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="typed-pdp")
    approved = approve_decision(store,
        trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    ).task
    assert approved is not None
    for changes in (
        {"cache_used": True},
        {"consistency": "eventual"},
        {"request_digest": "wrong-request"},
        {"model_identity": "wrong-model"},
        {"policy_revision": "wrong-policy"},
        {"checked_at_us": 1_199_999},
    ):
        evidence_changes = dict(changes)
        checked_at_us = evidence_changes.pop("checked_at_us", 1_200_000)
        with pytest.raises(ValueError):
            store.claim(
                trusted.task_id,
                trusted,
                claim(),
                now_us=1_200_000,
                lease_expires_at_us=1_300_000,
                pdp_evidence=pdp_evidence(
                    store,
                    trusted,
                    approved,
                    stage="pre_claim",
                    checked_at_us=checked_at_us,
                    **evidence_changes,
                ),
            )
    pre_claim = pdp_evidence(
        store, trusted, approved, stage="pre_claim", checked_at_us=1_200_000
    )
    assert store.claim(
        trusted.task_id,
        trusted,
        claim(),
        now_us=1_200_000,
        lease_expires_at_us=1_300_000,
        pdp_evidence=pre_claim,
    ).applied
    pre_read = pdp_evidence(
        store, trusted, approved, stage="pre_private_read", checked_at_us=1_210_000
    )
    assert store.record_pdp_evidence(
        trusted.task_id,
        trusted,
        claim(),
        pre_read,
        now_us=1_210_000,
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        rows = conn.execute(
            "SELECT stage,decision,cache_used,consistency FROM authorization_pdp_evidence "
            "WHERE task_id=? ORDER BY checked_at_us",
            (trusted.task_id,),
        ).fetchall()
    assert rows == [
        ("pre_claim", "allow", 0, "strongest"),
        ("pre_private_read", "allow", 0, "strongest"),
    ]


def test_pdp_deny_and_failure_evidence_close_work_fail_closed(
    store: AuthorizationTaskStore,
) -> None:
    pre_claim_binding = binding(
        task_id="task-pdp-deny", correlation_id="corr-pdp-deny"
    )
    stage_challenge(store, pre_claim_binding, request_key="pdp-deny")
    approved = approve_decision(store,
        pre_claim_binding.task_id,
        pre_claim_binding,
        decision_for(pre_claim_binding, decision_id="approve-pdp-deny"),
        now_us=1_100_000,
    ).task
    assert approved is not None
    denied = store.reject_from_pdp(
        pre_claim_binding.task_id,
        pre_claim_binding,
        pdp_evidence(
            store,
            pre_claim_binding,
            approved,
            stage="pre_claim",
            checked_at_us=1_150_000,
            decision="deny",
            consistency="unknown",
            cache_used=True,
        ),
        now_us=1_150_000,
    )
    assert denied.applied and denied.task.status == "denied"

    pre_read_binding = binding(
        task_id="task-pdp-failure", correlation_id="corr-pdp-failure"
    )
    stage_challenge(store, pre_read_binding, request_key="pdp-failure")
    approved = approve_decision(store,
        pre_read_binding.task_id,
        pre_read_binding,
        decision_for(pre_read_binding, decision_id="approve-pdp-failure"),
        now_us=1_100_000,
    ).task
    assert approved is not None
    worker = claim()
    store.claim(
        pre_read_binding.task_id,
        pre_read_binding,
        worker,
        now_us=1_200_000,
        lease_expires_at_us=1_300_000,
        pdp_evidence=claim_pdp(store, pre_read_binding, 1_200_000),
    )
    failed = store.record_pdp_evidence(
        pre_read_binding.task_id,
        pre_read_binding,
        worker,
        pdp_evidence(
            store,
            pre_read_binding,
            approved,
            stage="pre_private_read",
            checked_at_us=1_210_000,
            decision="failure",
            consistency="unknown",
        ),
        now_us=1_210_000,
    )
    assert failed.applied and failed.task.status == "failed_consumed"


def _prepare_claimed_delivery(
    value: AuthorizationTaskStore,
    item: TrustedAuthorizationBinding,
    *,
    worker: ClaimIdentity | None = None,
    lease_expires_at_us: int = 1_300_000,
) -> ClaimIdentity:
    worker = worker or claim()
    stage_challenge(value, item, request_key=f"delivery-{item.task_id}")
    assert approve_decision(value,
        item.task_id, item, decision_for(item), now_us=1_100_000
    ).applied
    assert value.claim(
        item.task_id,
        item,
        worker,
        now_us=1_200_000,
        lease_expires_at_us=lease_expires_at_us,
        pdp_evidence=claim_pdp(value, item, 1_200_000, worker),
    ).applied
    assert value.authorize_private_read(
        item.task_id,
        item,
        worker,
        private_read_pdp(value, item, 1_210_000, worker),
        now_us=1_210_000,
    ).applied
    assert value.record_send_started(
        item.task_id, item, worker, now_us=1_220_000
    ).applied
    return worker


@pytest.mark.parametrize("negative_decision", ["deny", "failure"])
def test_claim_never_accepts_negative_pdp_evidence(
    store: AuthorizationTaskStore, negative_decision: str
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key=f"negative-claim-{negative_decision}")
    approved = approve_decision(store,
        trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    ).task
    assert approved is not None
    negative = pdp_evidence(
        store,
        trusted,
        approved,
        stage="pre_claim",
        checked_at_us=1_200_000,
        decision=negative_decision,
        consistency="unknown",
        cache_used=True,
    )
    assert not store.claim(
        trusted.task_id,
        trusted,
        claim(),
        now_us=1_200_000,
        lease_expires_at_us=1_300_000,
        pdp_evidence=negative,
    ).applied
    assert store.load_task(trusted.task_id, trusted).status == "approved"
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_pdp_evidence WHERE task_id=?",
            (trusted.task_id,),
        ).fetchone()[0] == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"decision": "deny", "consistency": "unknown"},
        {"decision": "failure", "consistency": "unknown"},
        {"stage": "pre_claim"},
        {"cache_used": True},
        {"consistency": "unknown"},
    ],
)
def test_private_read_gate_returns_no_authorization_for_non_exact_allow(
    store: AuthorizationTaskStore, changes: dict[str, object]
) -> None:
    trusted = binding()
    worker = claim()
    stage_challenge(store, trusted, request_key=f"private-gate-{sorted(changes)}")
    approve_decision(
        store, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    )
    assert store.claim(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_200_000,
        lease_expires_at_us=1_300_000,
        pdp_evidence=claim_pdp(store, trusted, 1_200_000, worker),
    ).applied
    evidence = replace(
        private_read_pdp(store, trusted, 1_210_000, worker), **changes
    )
    gate = store.authorize_private_read(
        trusted.task_id,
        trusted,
        worker,
        evidence,
        now_us=1_210_000,
    )
    assert not gate.applied and not gate.idempotent and gate.task is None
    assert store.load_task(trusted.task_id, trusted).status == "claimed"
    assert not store.record_send_started(
        trusted.task_id, trusted, worker, now_us=1_211_000
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_pdp_evidence "
            "WHERE task_id=? AND stage='pre_private_read'",
            (trusted.task_id,),
        ).fetchone()[0] == 0


def test_private_read_gate_rejects_expired_task_lease_and_stale_generation(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding(expires_at_us=1_300_000)
    first = claim()
    stage_challenge(store, trusted, request_key="private-gate-fences")
    approve_decision(
        store, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    )
    assert store.claim(
        trusted.task_id,
        trusted,
        first,
        now_us=1_200_000,
        lease_expires_at_us=1_250_000,
        pdp_evidence=claim_pdp(store, trusted, 1_200_000, first),
    ).applied
    stale = claim(generation=2, nonce="stale-generation")
    with pytest.raises(AuthorizationIntegrityError, match="stale or ineligible"):
        store.create_pdp_check_context(
            trusted.task_id, stale, stage="pre_private_read", now_us=1_240_000
        )
    with pytest.raises(AuthorizationIntegrityError, match="stale or ineligible"):
        store.create_pdp_check_context(
            trusted.task_id, first, stage="pre_private_read", now_us=1_250_000
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"cache_used": True},
        {"consistency": "unknown"},
        {"stage": "pre_private_read"},
    ],
)
def test_claim_rejects_cached_weak_or_wrong_stage_allow_directly(
    store: AuthorizationTaskStore, changes: dict[str, object]
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key=f"bad-claim-{sorted(changes)}")
    approve_decision(store, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000)
    evidence = replace(claim_pdp(store, trusted, 1_200_000), **changes)
    with pytest.raises(ValueError):
        store.claim(
            trusted.task_id,
            trusted,
            claim(),
            now_us=1_200_000,
            lease_expires_at_us=1_300_000,
            pdp_evidence=evidence,
        )
    assert store.load_task(trusted.task_id, trusted).status == "approved"


def test_pre_private_read_is_mandatory_before_send_or_consumption(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="pre-read-required")
    approve_decision(store, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000)
    store.claim(
        trusted.task_id,
        trusted,
        claim(),
        now_us=1_200_000,
        lease_expires_at_us=1_300_000,
        pdp_evidence=claim_pdp(store, trusted, 1_200_000),
    )
    assert not store.record_send_started(
        trusted.task_id, trusted, claim(), now_us=1_210_000
    ).applied
    proof = delivery_acceptance(
        store, trusted, claim(), accepted_at_us=1_220_000
    )
    assert not store.finish(
        trusted.task_id,
        trusted,
        claim(),
        now_us=1_230_000,
        outcome="consumed",
        receipt_code="provider_accepted",
        evidence=proof,
    ).applied
    assert store.load_task(trusted.task_id, trusted).status == "claimed"


@pytest.mark.parametrize("boundary", ["claim", "task"])
def test_pre_private_read_equality_boundaries_are_expired(
    store: AuthorizationTaskStore, boundary: str
) -> None:
    expires_at_us = 1_300_000 if boundary == "task" else 2_000_000
    lease_expires_at_us = 1_400_000 if boundary == "task" else 1_300_000
    trusted = binding(expires_at_us=expires_at_us)
    stage_challenge(store, trusted, request_key=f"pre-read-boundary-{boundary}")
    approve_decision(store, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000)
    store.claim(
        trusted.task_id,
        trusted,
        claim(),
        now_us=1_200_000,
        lease_expires_at_us=lease_expires_at_us,
        pdp_evidence=claim_pdp(store, trusted, 1_200_000),
    )
    boundary_us = 1_300_000
    with pytest.raises(AuthorizationIntegrityError, match="stale or ineligible"):
        store.create_pdp_check_context(
            trusted.task_id, claim(), stage="pre_private_read", now_us=boundary_us
        )


@pytest.mark.parametrize("boundary", ["claim", "task"])
def test_recorded_pre_read_is_not_reusable_after_expiry(
    store: AuthorizationTaskStore, boundary: str
) -> None:
    trusted = binding(expires_at_us=1_270_000 if boundary == "task" else 2_000_000)
    lease_expires_at_us = 1_300_000
    stage_challenge(store, trusted, request_key=f"record-expiry-{boundary}")
    approve_decision(store, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000)
    store.claim(
        trusted.task_id,
        trusted,
        claim(),
        now_us=1_200_000,
        lease_expires_at_us=lease_expires_at_us,
        pdp_evidence=claim_pdp(store, trusted, 1_200_000),
    )
    assert store.authorize_private_read(
        trusted.task_id,
        trusted,
        claim(),
        private_read_pdp(store, trusted, 1_250_000),
        now_us=1_250_000,
    ).applied
    expired_at = trusted.expires_at_us if boundary == "task" else lease_expires_at_us
    assert not store.record_send_started(
        trusted.task_id, trusted, claim(), now_us=expired_at
    ).applied


def test_send_start_idempotency_does_not_survive_claim_expiry(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    worker = _prepare_claimed_delivery(
        store, trusted, lease_expires_at_us=1_250_000
    )
    assert not store.record_send_started(
        trusted.task_id, trusted, worker, now_us=1_250_000
    ).applied


def test_consumed_requires_complete_typed_delivery_acceptance(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    worker = _prepare_claimed_delivery(store, trusted)
    with pytest.raises(TypeError, match="typed delivery acceptance"):
        store.finish(
            trusted.task_id,
            trusted,
            worker,
            now_us=1_240_000,
            outcome="consumed",
            receipt_code="provider_accepted",
        )
    with pytest.raises(TypeError, match="typed delivery acceptance"):
        store.finish(
            trusted.task_id,
            trusted,
            worker,
            now_us=1_240_000,
            outcome="consumed",
            receipt_code="provider_accepted",
            evidence={"status": "provider_accepted"},  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="typed evidence"):
        store.finish(
            trusted.task_id,
            trusted,
            worker,
            now_us=1_240_000,
            outcome="consumed",
            receipt_code="provider_accepted",
            provider_receipt_id="wrong-provider-id",
            evidence=delivery_acceptance(
                store, trusted, worker, accepted_at_us=1_230_000
            ),
        )
    assert store.load_task(trusted.task_id, trusted).status == "claimed"


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("task_id", "wrong-task"),
        ("correlation_id", "wrong-correlation"),
        ("operation", "wrong-operation"),
        ("request_digest", "wrong-request"),
        ("request_key_version", "wrong-key"),
        ("policy_version", "wrong-policy-version"),
        ("policy_hash", "c" * 64),
        ("worker_agent", "wrong-worker"),
        ("claim_nonce", "wrong-claim-token"),
        ("claim_generation", 2),
        ("delivery_profile", "wrong-profile"),
        ("delivery_platform", "wrong-platform"),
        ("delivery_account", "wrong-account"),
        ("delivery_chat", "wrong-chat"),
        ("delivery_thread", "wrong-thread"),
        ("transport_implementation", "wrong-transport"),
        ("runtime_identity", "wrong-runtime"),
        ("account_binding", "wrong-binding"),
        ("connection_epoch", 99),
        ("accepted_at_us", 1_219_999),
    ],
)
def test_consumed_rejects_mismatched_delivery_acceptance(
    store: AuthorizationTaskStore, field: str, wrong: object
) -> None:
    trusted = binding()
    worker = _prepare_claimed_delivery(store, trusted)
    proof = replace(
        delivery_acceptance(store, trusted, worker, accepted_at_us=1_230_000),
        **{field: wrong},
    )
    assert not store.finish(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_240_000,
        outcome="consumed",
        receipt_code="provider_accepted",
        evidence=proof,
    ).applied
    assert store.load_task(trusted.task_id, trusted).status == "claimed"


def test_consumed_rejects_future_or_expired_acceptance_and_accepts_exact_proof(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    worker = _prepare_claimed_delivery(store, trusted, lease_expires_at_us=1_250_000)
    future = delivery_acceptance(store, trusted, worker, accepted_at_us=1_245_000)
    assert not store.finish(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_240_000,
        outcome="consumed",
        receipt_code="provider_accepted",
        evidence=future,
    ).applied
    exact = delivery_acceptance(
        store,
        trusted,
        worker,
        accepted_at_us=1_245_000,
        provider_message_id="exact-provider-message",
    )
    assert not store.finish(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_250_000,
        outcome="consumed",
        receipt_code="provider_accepted",
        evidence=exact,
    ).applied
    assert store.heartbeat(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_249_000,
        lease_expires_at_us=1_300_000,
    ).applied
    assert store.finish(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_260_000,
        outcome="consumed",
        receipt_code="provider_accepted",
        evidence=exact,
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        row = conn.execute(
            "SELECT receipt_token,delivery_account_binding_token,delivery_acceptance_status,"
            "delivery_transport_implementation,delivery_runtime_identity,"
            "delivery_connection_epoch,delivery_record_digest FROM authorization_tasks "
            "WHERE task_id=?",
            (trusted.task_id,),
        ).fetchone()
    assert row[2:] == (
        "provider_accepted",
        trusted.delivery_transport_implementation,
        trusted.delivery_runtime_identity,
        trusted.delivery_connection_epoch,
        row[6],
    )
    assert "exact-provider-message" not in row[0]
    assert trusted.delivery_account_binding not in row[1]
    assert row[6]


def test_failed_consumed_needs_no_positive_delivery_evidence(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="failed-without-positive")
    approve_decision(store, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000)
    store.claim(
        trusted.task_id,
        trusted,
        claim(),
        now_us=1_200_000,
        lease_expires_at_us=1_210_000,
        pdp_evidence=claim_pdp(store, trusted, 1_200_000),
    )
    assert store.finish(
        trusted.task_id,
        trusted,
        claim(),
        now_us=1_220_000,
        outcome="failed_consumed",
        receipt_code="provider_timeout",
        provider_receipt_id="bounded-ambiguous-submission",
    ).applied


def test_consumed_exact_retry_after_uncertain_commit_is_already_applied(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    worker = _prepare_claimed_delivery(store, trusted)
    proof = delivery_acceptance(
        store,
        trusted,
        worker,
        accepted_at_us=1_230_000,
        provider_message_id="uncertain-delivery-provider-id",
    )
    raised = False

    def fault(step: str) -> None:
        nonlocal raised
        if step == "commit.after" and not raised:
            raised = True
            raise RuntimeError("uncertain delivery commit")

    store._fault_hook = fault
    with pytest.raises(RuntimeError, match="uncertain delivery commit"):
        store.finish(
            trusted.task_id,
            trusted,
            worker,
            now_us=1_240_000,
            outcome="consumed",
            receipt_code="provider_accepted",
            evidence=proof,
        )
    store._fault_hook = None
    retry = store.finish(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_240_000,
        outcome="consumed",
        receipt_code="provider_accepted",
        evidence=proof,
    )
    assert retry.applied and retry.idempotent and retry.task.status == "consumed"
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events WHERE kind='task_consumed'"
        ).fetchone()[0] == 1

    mismatches = (
        replace(proof, provider_message_id="wrong-provider-id"),
        replace(proof, runtime_identity="wrong-runtime"),
        replace(proof, account_binding="wrong-account"),
        replace(proof, claim_generation=2),
        replace(proof, accepted_at_us=1_230_001),
    )
    for wrong in mismatches:
        assert not store.finish(
            trusted.task_id,
            trusted,
            worker,
            now_us=1_240_000,
            outcome="consumed",
            receipt_code="provider_accepted",
            evidence=wrong,
        ).applied
    assert not store.finish(
        trusted.task_id,
        trusted,
        replace(worker, generation=2),
        now_us=1_240_000,
        outcome="consumed",
        receipt_code="provider_accepted",
        evidence=proof,
    ).applied
    assert not store.finish(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_240_001,
        outcome="consumed",
        receipt_code="provider_accepted",
        evidence=proof,
    ).applied
    assert not store.finish(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_240_000,
        outcome="failed_consumed",
        receipt_code="provider_timeout",
    ).applied
    with pytest.raises(ValueError, match="status"):
        replace(proof, status="provider_rejected")


def test_failed_consumed_exact_retry_requires_identical_receipt_claim_and_time(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    worker = claim()
    stage_challenge(store, trusted, request_key="failed-terminal-retry")
    approve_decision(
        store, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    )
    assert store.claim(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_200_000,
        lease_expires_at_us=1_210_000,
        pdp_evidence=claim_pdp(store, trusted, 1_200_000, worker),
    ).applied
    kwargs = {
        "now_us": 1_220_000,
        "outcome": "failed_consumed",
        "receipt_code": "ambiguous_after_restart",
        "provider_receipt_id": "ambiguous-submission-id",
    }
    raised = False

    def fault(step: str) -> None:
        nonlocal raised
        if step == "commit.after" and not raised:
            raised = True
            raise RuntimeError("uncertain failed consumption commit")

    store._fault_hook = fault
    with pytest.raises(RuntimeError, match="uncertain failed consumption commit"):
        store.finish(trusted.task_id, trusted, worker, **kwargs)
    store._fault_hook = None
    retry = store.finish(trusted.task_id, trusted, worker, **kwargs)
    assert retry.applied and retry.idempotent
    assert not store.finish(
        trusted.task_id,
        trusted,
        worker,
        **{**kwargs, "provider_receipt_id": "other-submission-id"},
    ).applied
    assert not store.finish(
        trusted.task_id,
        trusted,
        replace(worker, nonce="other-claim"),
        **kwargs,
    ).applied
    assert not store.finish(
        trusted.task_id,
        trusted,
        worker,
        **{**kwargs, "now_us": 1_220_001},
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events "
            "WHERE kind='task_failed_consumed'"
        ).fetchone()[0] == 1


@pytest.mark.parametrize(
    "column",
    [
        "receipt_token",
        "delivery_acceptance_status",
        "delivery_accepted_at_us",
        "delivery_transport_implementation",
        "delivery_runtime_identity",
        "delivery_account_binding_token",
        "delivery_connection_epoch",
        "delivery_record_digest",
    ],
)
def test_consumed_delivery_record_tampering_fails_hmac_verification(
    store: AuthorizationTaskStore, column: str
) -> None:
    trusted = binding()
    worker = _prepare_claimed_delivery(store, trusted)
    assert store.finish(
        trusted.task_id,
        trusted,
        worker,
        now_us=1_240_000,
        outcome="consumed",
        receipt_code="provider_accepted",
        evidence=delivery_acceptance(
            store, trusted, worker, accepted_at_us=1_230_000
        ),
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        current = conn.execute(
            f'SELECT "{column}" FROM authorization_tasks WHERE task_id=?',
            (trusted.task_id,),
        ).fetchone()[0]
        if column == "delivery_acceptance_status":
            replacement = None
        elif isinstance(current, int):
            replacement = current + 1
        else:
            replacement = f"{current}-tampered"
        conn.execute(
            f'UPDATE authorization_tasks SET "{column}"=? WHERE task_id=?',
            (replacement, trusted.task_id),
        )
    with pytest.raises(AuthorizationIntegrityError):
        store.load_task(trusted.task_id, trusted)


def _resolution(item: TrustedAuthorizationBinding, *, attempt_id: str) -> NotificationAttemptSpec:
    return notification(
        attempt_id=attempt_id,
        kind="approval_resolution",
        challenge_generation=1,
        created_at_us=1_100_000,
        due_at_us=1_100_000,
        challenge_nonce=f"resolution-{attempt_id}",
        destination_profile=item.approval_profile,
        destination_account=item.approval_account,
        destination_chat=item.approval_chat,
        destination_thread=item.approval_thread,
    )


@pytest.mark.parametrize(("decision_kind", "terminal"), [("approve", "approved"), ("deny", "denied")])
def test_decision_atomically_enqueues_same_generation_resolution(
    store: AuthorizationTaskStore, decision_kind: str, terminal: str
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key=f"resolution-{decision_kind}")
    owner_decision = decision_for(trusted)
    resolution = _resolution(trusted, attempt_id=f"resolution-{decision_kind}")
    if decision_kind == "approve":
        result = approve_decision(store,
            trusted.task_id,
            trusted,
            owner_decision,
            now_us=1_100_000,
            resolution_notification=resolution,
        )
    else:
        result = deny_decision(store,
            trusted.task_id,
            trusted,
            owner_decision,
            now_us=1_100_000,
            reason_code="owner_rejected",
            resolution_notification=resolution,
        )
    assert result.applied and result.task.status == terminal
    retry = (
        approve_decision(store,
            trusted.task_id,
            trusted,
            owner_decision,
            now_us=1_100_001,
            resolution_notification=resolution,
        )
        if decision_kind == "approve"
        else deny_decision(store,
            trusted.task_id,
            trusted,
            owner_decision,
            now_us=1_100_001,
            reason_code="owner_rejected",
            resolution_notification=resolution,
        )
    )
    assert retry.applied and retry.idempotent
    with sqlite3.connect(store.db_path) as conn:
        rows = conn.execute(
            "SELECT kind,challenge_generation FROM authorization_notification_attempts "
            "WHERE task_id=? ORDER BY kind",
            (trusted.task_id,),
        ).fetchall()
        resolution_count = conn.execute(
            "SELECT COUNT(*) FROM authorization_notification_attempts "
            "WHERE task_id=? AND kind='approval_resolution'",
            (trusted.task_id,),
        ).fetchone()[0]
    assert rows == [("approval_challenge", 1), ("approval_resolution", 1)]
    assert resolution_count == 1


def test_owner_decision_public_apis_require_typed_resolution(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="resolution-required")
    owner_decision = decision_for(trusted)
    with pytest.raises(TypeError, match="resolution_notification"):
        store.approve(  # type: ignore[call-arg]
            trusted.task_id, trusted, owner_decision, now_us=1_100_000
        )
    with pytest.raises(TypeError, match="resolution_notification"):
        store.deny(  # type: ignore[call-arg]
            trusted.task_id,
            trusted,
            owner_decision,
            now_us=1_100_000,
            reason_code="owner_rejected",
        )
    assert store.load_task(trusted.task_id, trusted).status == "approval_required"


@pytest.mark.parametrize("decision_kind", ["approve", "deny"])
@pytest.mark.parametrize(
    "fault_boundary",
    [
        "transition.before",
        "transition.after",
        "decision_audit.before",
        "decision_audit.after",
        "notification.before",
        "notification.after",
        "resolution_audit.before",
        "resolution_audit.after",
        "commit.before",
    ],
)
def test_owner_decision_faults_roll_back_state_audit_and_resolution(
    store: AuthorizationTaskStore,
    decision_kind: str,
    fault_boundary: str,
) -> None:
    trusted = binding()
    stage_challenge(
        store, trusted, request_key=f"decision-fault-{decision_kind}-{fault_boundary}"
    )
    owner_decision = decision_for(
        trusted, decision_id=f"decision-{decision_kind}-{fault_boundary}"
    )
    resolution = decision_resolution(
        store, trusted, owner_decision, created_at_us=1_100_000
    )
    audit_count = 0

    def fault(step: str) -> None:
        nonlocal audit_count
        label = step
        if step in {"audit.before", "audit.after"}:
            if step == "audit.after":
                audit_count += 1
            ordinal = audit_count + (1 if step == "audit.before" else 0)
            label = (
                "decision_audit" if ordinal == 1 else "resolution_audit"
            ) + step.removeprefix("audit")
        if label == fault_boundary:
            raise RuntimeError(f"fault at {fault_boundary}")

    store._fault_hook = fault
    with pytest.raises(RuntimeError, match="fault at"):
        if decision_kind == "approve":
            store.approve(
                trusted.task_id,
                trusted,
                owner_decision,
                now_us=1_100_000,
                resolution_notification=resolution,
            )
        else:
            store.deny(
                trusted.task_id,
                trusted,
                owner_decision,
                now_us=1_100_000,
                reason_code="owner_rejected",
                resolution_notification=resolution,
            )
    store._fault_hook = None
    assert store.load_task(trusted.task_id, trusted).status == "approval_required"
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT challenge_state FROM authorization_notification_attempts "
            "WHERE kind='approval_challenge'"
        ).fetchone()[0] == "accepted"
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_notification_attempts "
            "WHERE kind='approval_resolution'"
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events "
            "WHERE kind IN ('task_approved','task_denied')"
        ).fetchone()[0] == 0


@pytest.mark.parametrize("decision_kind", ["approve", "deny"])
def test_owner_decision_exact_retry_after_uncertain_commit_is_idempotent(
    store: AuthorizationTaskStore, decision_kind: str
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key=f"decision-commit-{decision_kind}")
    owner_decision = decision_for(trusted, decision_id=f"commit-{decision_kind}")
    resolution = decision_resolution(
        store, trusted, owner_decision, created_at_us=1_100_000
    )
    raised = False

    def fault(step: str) -> None:
        nonlocal raised
        if step == "commit.after" and not raised:
            raised = True
            raise RuntimeError("uncertain owner decision commit")

    store._fault_hook = fault
    with pytest.raises(RuntimeError, match="uncertain owner decision commit"):
        if decision_kind == "approve":
            store.approve(
                trusted.task_id,
                trusted,
                owner_decision,
                now_us=1_100_000,
                resolution_notification=resolution,
            )
        else:
            store.deny(
                trusted.task_id,
                trusted,
                owner_decision,
                now_us=1_100_000,
                reason_code="owner_rejected",
                resolution_notification=resolution,
            )
    store._fault_hook = None
    retry = (
        store.approve(
            trusted.task_id,
            trusted,
            owner_decision,
            now_us=1_100_000,
            resolution_notification=resolution,
        )
        if decision_kind == "approve"
        else store.deny(
            trusted.task_id,
            trusted,
            owner_decision,
            now_us=1_100_000,
            reason_code="owner_rejected",
            resolution_notification=resolution,
        )
    )
    assert retry.applied and retry.idempotent
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_notification_attempts "
            "WHERE kind='approval_resolution'"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events "
            "WHERE kind IN ('task_approved','task_denied')"
        ).fetchone()[0] == 1


@pytest.mark.parametrize("decision_kind", ["approve", "deny"])
def test_exact_legacy_decision_without_resolution_is_repaired_once(
    store: AuthorizationTaskStore, decision_kind: str
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key=f"legacy-resolution-{decision_kind}")
    owner_decision = decision_for(trusted, decision_id=f"legacy-{decision_kind}")
    resolution = decision_resolution(
        store, trusted, owner_decision, created_at_us=1_100_000
    )
    if decision_kind == "approve":
        assert store.approve(
            trusted.task_id,
            trusted,
            owner_decision,
            now_us=1_100_000,
            resolution_notification=resolution,
        ).applied
    else:
        assert store.deny(
            trusted.task_id,
            trusted,
            owner_decision,
            now_us=1_100_000,
            reason_code="owner_rejected",
            resolution_notification=resolution,
        ).applied
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "DELETE FROM authorization_audit_events WHERE event_id=?",
            (f"notification-created:{resolution.attempt_id}",),
        )
        conn.execute(
            "DELETE FROM authorization_notification_attempts WHERE attempt_id=?",
            (resolution.attempt_id,),
        )
    repaired = (
        store.approve(
            trusted.task_id,
            trusted,
            owner_decision,
            now_us=1_100_001,
            resolution_notification=resolution,
        )
        if decision_kind == "approve"
        else store.deny(
            trusted.task_id,
            trusted,
            owner_decision,
            now_us=1_100_001,
            reason_code="owner_rejected",
            resolution_notification=resolution,
        )
    )
    assert not repaired.applied
    with pytest.raises(AuthorizationIntegrityError):
        store.load_task(trusted.task_id, trusted)


def test_decided_retry_and_legacy_repair_reject_mismatched_resolution_spec(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="resolution-mismatch")
    owner_decision = decision_for(trusted, decision_id="resolution-mismatch")
    exact = decision_resolution(
        store, trusted, owner_decision, created_at_us=1_100_000
    )
    assert store.approve(
        trusted.task_id,
        trusted,
        owner_decision,
        now_us=1_100_000,
        resolution_notification=exact,
    ).applied
    mismatches = (
        replace(exact, attempt_id="wrong-resolution-attempt"),
        replace(exact, challenge_generation=2),
        replace(exact, challenge_nonce="wrong-resolution-nonce"),
        replace(exact, due_at_us=1_100_001),
        replace(exact, destination_profile="wrong-profile"),
        replace(exact, destination_account="wrong-destination"),
        replace(exact, destination_chat="wrong-chat"),
        replace(exact, destination_thread="wrong-thread"),
        replace(exact, created_at_us=1_100_001, due_at_us=1_100_001),
    )
    for wrong in mismatches:
        assert not store.approve(
            trusted.task_id,
            trusted,
            owner_decision,
            now_us=1_100_001,
            resolution_notification=wrong,
        ).applied
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "DELETE FROM authorization_audit_events WHERE event_id=?",
            (f"notification-created:{exact.attempt_id}",),
        )
        conn.execute(
            "DELETE FROM authorization_notification_attempts WHERE attempt_id=?",
            (exact.attempt_id,),
        )
    assert not store.approve(
        trusted.task_id,
        trusted,
        owner_decision,
        now_us=1_100_002,
        resolution_notification=mismatches[-1],
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_notification_attempts "
            "WHERE kind='approval_resolution'"
        ).fetchone()[0] == 0


def test_resolution_enqueue_fault_rolls_back_decision_audit_and_challenge_cas(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="resolution-rollback")

    def fault(step: str) -> None:
        if step == "notification.after":
            raise RuntimeError("resolution enqueue fault")

    store._fault_hook = fault
    with pytest.raises(RuntimeError, match="resolution enqueue fault"):
        approve_decision(store,
            trusted.task_id,
            trusted,
            decision_for(trusted),
            now_us=1_100_000,
            resolution_notification=_resolution(trusted, attempt_id="resolution-fault"),
        )
    store._fault_hook = None
    assert store.load_task(trusted.task_id, trusted).status == "approval_required"
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_notification_attempts "
            "WHERE kind='approval_resolution'"
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT challenge_state FROM authorization_notification_attempts "
            "WHERE kind='approval_challenge'"
        ).fetchone()[0] == "accepted"
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events WHERE kind='task_approved'"
        ).fetchone()[0] == 0


def test_real_v2_to_v3_migration_preserves_rows_as_non_authoritative_evidence(
    tmp_path: Path,
) -> None:
    signer_root = tmp_path / "v2-signer"
    signer_root.mkdir(mode=0o700)
    signer = AuthorizationTaskStore(
        db_path=(signer_root / "authorization.db").absolute(),
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    trusted = replace(
        binding(),
        delivery_platform="",
        delivery_transport_implementation="",
        delivery_runtime_identity="",
        delivery_account_binding="",
        delivery_connection_epoch=0,
        policy_version="",
        policy_hash="",
    )
    request_key = "v2-request"
    root = tmp_path / "real-v2"
    root.mkdir(mode=0o700)
    db_path = (root / "authorization.db").absolute()
    db_path.touch(mode=0o600)
    schema_v2 = ";".join(
        (
            _TASKS_V2.format(table="authorization_tasks"),
            _AUDIT_V2.format(table="authorization_audit_events"),
            _NOTIFICATIONS_V2.format(table="authorization_notification_attempts"),
            _PDP_V2.format(table="authorization_pdp_evidence"),
            _LEASE,
            _INDEXES_V2,
            "PRAGMA user_version=2",
        )
    )
    with sqlite3.connect(db_path) as conn:
        conn.executescript(schema_v2)
        conn.execute(
            "INSERT INTO authorization_tasks "
            "(task_id,correlation_id,scoped_request_key,binding_json,binding_digest,"
            "request_digest,key_version,status,created_at_us,expires_at_us) "
            "VALUES (?,?,?,?,?,?,?,'approved',?,?)",
            (
                trusted.task_id,
                trusted.correlation_id,
                request_key,
                trusted.canonical_bytes().decode(),
                signer._binding_digest(trusted),
                signer._request_digest(request_key, trusted),
                "test-k1",
                trusted.created_at_us,
                trusted.expires_at_us,
            ),
        )
        conn.execute(
            "INSERT INTO authorization_pdp_evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "legacy-v2-allow",
                trusted.task_id,
                "pre_private_read",
                "allow",
                signer._request_digest(request_key, trusted),
                trusted.model_identity,
                trusted.policy_identity,
                1_200_000,
                "strongest",
                signer.audit_token("pdp-consistency", "legacy"),
                0,
                "legacy-evidence-digest",
                "test-k1",
            ),
        )
    migrated = AuthorizationTaskStore(
        db_path=db_path,
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        legacy = conn.execute(
            "SELECT binding_digest,coordinator_epoch,claim_generation,context_record_digest "
            "FROM authorization_pdp_evidence WHERE evidence_id='legacy-v2-allow'"
        ).fetchone()
        task_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(authorization_tasks)")
        }
        notification_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='authorization_notification_attempts'"
        ).fetchone()[0]
    assert legacy == (None, None, None, None)
    assert "delivery_record_digest" in task_columns
    assert "UNIQUE(task_id, kind, challenge_generation, retry_ordinal)" in notification_sql
    migrated_task = migrated.load_task(trusted.task_id, trusted)
    assert migrated_task.status == "denied"
    assert migrated_task.receipt_code == "incomplete_delivery_binding"


def test_authorization_journal_mode_is_explicit_and_profile_neutral(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "hermes_state.is_sqlite_wal_reset_vulnerable", lambda **_kwargs: False
    )
    observed = []
    for profile_mode in ("wal", "delete"):
        profile_home = tmp_path / f"profile-{profile_mode}"
        profile_home.mkdir(mode=0o700)
        (profile_home / "config.yaml").write_text(
            f"database:\n  journal_mode: {profile_mode}\n", encoding="utf-8"
        )
        monkeypatch.setenv("HERMES_HOME", str(profile_home))
        host_root = tmp_path / f"host-{profile_mode}"
        host_root.mkdir(mode=0o700)
        candidate = AuthorizationTaskStore(
            db_path=(host_root / "authorization.db").absolute(),
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
            journal_mode="delete",
        )
        with sqlite3.connect(candidate.db_path) as conn:
            observed.append(conn.execute("PRAGMA journal_mode").fetchone()[0].lower())
    assert observed == ["delete", "delete"]


def test_real_lock_denies_competitors_wrong_path_and_closed_sessions(
    tmp_path: Path,
) -> None:
    root = tmp_path / "real-lock"
    root.mkdir(mode=0o700)
    candidate = AuthorizationTaskStore(
        db_path=(root / "authorization.db").absolute(),
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    session = candidate.acquire_coordinator_lock()
    assert session is not None
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    process = context.Process(
        target=_lock_probe,
        args=(str(candidate.coordinator_lock_path), result_queue),
    )
    process.start()
    process.join(timeout=10)
    assert process.exitcode == 0
    assert result_queue.get(timeout=2) is False
    result_queue.close()
    result_queue.join_thread()

    wrong_root = tmp_path / "wrong-lock"
    wrong_root.mkdir(mode=0o700)
    from gateway.authorization_lock import AuthorizationCoordinatorLockSession

    wrong = AuthorizationCoordinatorLockSession.acquire(
        (wrong_root / "authorization.coordinator.lock").absolute()
    )
    assert wrong is not None
    with pytest.raises(ValueError, match="live owned"):
        candidate.acquire_coordinator(
            COORDINATOR,
            now_us=500_000,
            lease_expires_at_us=1_000_000,
            lock_session=wrong,
        )
    wrong.close()

    fence = candidate.acquire_coordinator(
        COORDINATOR,
        now_us=500_000,
        lease_expires_at_us=1_000_000,
        lock_session=session,
    )
    assert fence is not None
    session.close()
    with pytest.raises(CoordinatorFenceError):
        candidate.create_pending(binding(), request_key="closed-lock-session")


def test_same_owner_coordinator_renewal_never_shortens_lease(
    store: AuthorizationTaskStore,
) -> None:
    assert store._fence is not None
    original_expiry = store._fence.lease_expires_at_us
    renewed = store.acquire_coordinator(
        COORDINATOR,
        now_us=600_000,
        lease_expires_at_us=original_expiry - 1,
        lock_session=store._coordinator_lock,  # type: ignore[arg-type]
    )
    assert renewed is not None
    assert renewed.lease_expires_at_us == original_expiry
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT lease_expires_at_us FROM authorization_coordinator_lease"
        ).fetchone()[0] == original_expiry


def _require_real_fork_lock() -> None:
    if not hasattr(os, "fork") or not hasattr(os, "register_at_fork"):
        pytest.skip("real fork cleanup is unavailable on this platform")
    from gateway.authorization_lock import fcntl

    if fcntl is None:
        pytest.skip("flock authorization capability is unavailable")


def test_forked_child_close_cannot_unlock_or_authorize_parent_session(
    tmp_path: Path,
) -> None:
    _require_real_fork_lock()
    root = tmp_path / "fork-close"
    root.mkdir(mode=0o700)
    candidate = AuthorizationTaskStore(
        db_path=(root / "authorization.db").absolute(),
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    session = candidate.acquire_coordinator_lock()
    assert session is not None
    assert candidate.acquire_coordinator(
        COORDINATOR,
        now_us=500_000,
        lease_expires_at_us=2_000_000,
        lock_session=session,
    ) is not None
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - assertions are reported by pipe
        os.close(read_fd)
        try:
            session.close()
            try:
                candidate.create_pending(
                    binding(task_id="child-task", correlation_id="child-corr"),
                    request_key="child-must-not-authorize",
                )
            except CoordinatorFenceError:
                os.write(write_fd, b"denied")
            else:
                os.write(write_fd, b"authorized")
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    try:
        assert os.read(read_fd, 32) == b"denied"
        waited, status = os.waitpid(child_pid, 0)
        assert waited == child_pid and os.waitstatus_to_exitcode(status) == 0

        from gateway.authorization_lock import AuthorizationCoordinatorLockSession

        assert AuthorizationCoordinatorLockSession.acquire(
            candidate.coordinator_lock_path
        ) is None
        assert candidate.create_pending(
            binding(task_id="parent-task", correlation_id="parent-corr"),
            request_key="parent-remains-live",
        ).applied
        candidate.close()
        competitor = AuthorizationCoordinatorLockSession.acquire(
            candidate.coordinator_lock_path
        )
        assert competitor is not None
        competitor.close()
    finally:
        os.close(read_fd)
        candidate.close()


def test_passive_fork_child_cannot_retain_lock_after_true_parent_exit(
    tmp_path: Path,
) -> None:
    _require_real_fork_lock()
    root = tmp_path / "fork-passive"
    root.mkdir(mode=0o700)
    lock_path = (root / "authorization.coordinator.lock").absolute()
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    done_read, done_write = os.pipe()
    holder_pid = os.fork()
    if holder_pid == 0:  # pragma: no cover - assertions are reported by pipe
        os.close(ready_read)
        os.close(release_write)
        os.close(done_read)
        from gateway.authorization_lock import AuthorizationCoordinatorLockSession

        held = AuthorizationCoordinatorLockSession.acquire(lock_path)
        if held is None:
            os.write(ready_write, b"failed")
            os._exit(2)
        passive_pid = os.fork()
        if passive_pid == 0:
            # Reaching user code proves the child-side at-fork cleanup has
            # completed before the test probes takeover.
            os.write(ready_write, b"ready")
            os.close(ready_write)
            os.read(release_read, 1)
            os.write(done_write, b"done")
            os._exit(0)
        os.close(release_read)
        os.close(done_write)
        os.close(ready_write)
        # Deliberately bypass close: only the holder's process exit and the
        # child's at-fork plain-close may release this open-file description.
        os._exit(0)

    os.close(ready_write)
    os.close(release_read)
    os.close(done_write)
    try:
        assert os.read(ready_read, 16) == b"ready"
        waited, status = os.waitpid(holder_pid, 0)
        assert waited == holder_pid and os.waitstatus_to_exitcode(status) == 0
        from gateway.authorization_lock import AuthorizationCoordinatorLockSession

        competitor = AuthorizationCoordinatorLockSession.acquire(lock_path)
        assert competitor is not None
        competitor.close()
        os.write(release_write, b"x")
        assert os.read(done_read, 16) == b"done"
    finally:
        os.close(ready_read)
        os.close(release_write)
        os.close(done_read)


def _stage_claimed_task(
    value: AuthorizationTaskStore,
    item: TrustedAuthorizationBinding,
    *,
    worker: ClaimIdentity | None = None,
) -> ClaimIdentity:
    worker = worker or claim()
    stage_challenge(value, item, request_key=f"claimed-{item.task_id}")
    assert approve_decision(
        value, item.task_id, item, decision_for(item), now_us=1_100_000
    ).applied
    assert value.claim(
        item.task_id, item, worker, now_us=1_200_000,
        lease_expires_at_us=1_400_000,
        pdp_evidence=claim_pdp(value, item, 1_200_000, worker),
    ).applied
    return worker


@pytest.mark.parametrize("decision_value", ["deny", "failure"])
def test_explicit_negative_private_read_transition_is_exact_retry_safe(
    store: AuthorizationTaskStore, decision_value: str
) -> None:
    trusted = binding()
    worker = _stage_claimed_task(store, trusted)
    checked_at_us = 1_250_000
    evidence = pdp_evidence(
        store,
        trusted,
        store.load_task(trusted.task_id, trusted),
        stage="pre_private_read",
        checked_at_us=checked_at_us,
        decision=decision_value,
        consistency="unknown",
        worker=worker,
    )
    raised = False

    def fault(step: str) -> None:
        nonlocal raised
        if step == "commit.after" and not raised:
            raised = True
            raise RuntimeError("uncertain private-read close")

    store._fault_hook = fault
    transition = (
        store.deny_private_read_from_pdp
        if decision_value == "deny"
        else store.fail_private_read_from_pdp
    )
    with pytest.raises(RuntimeError, match="uncertain private-read close"):
        transition(trusted.task_id, trusted, worker, evidence, now_us=checked_at_us)
    store._fault_hook = None
    retry = transition(
        trusted.task_id, trusted, worker, evidence, now_us=checked_at_us
    )
    assert retry.applied and retry.idempotent
    assert retry.task is not None and retry.task.status == "failed_consumed"
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_pdp_evidence WHERE evidence_id=?",
            (evidence.evidence_id,),
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events WHERE event_id=?",
            (f"task-pdp-failed:{evidence.evidence_id}",),
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events WHERE event_id=?",
            (f"pdp-evidence:{evidence.evidence_id}",),
        ).fetchone()[0] == 0
    assert not transition(
        trusted.task_id,
        trusted,
        replace(worker, nonce="different-claim"),
        replace(evidence, claim_nonce="different-claim"),
        now_us=checked_at_us,
    ).applied


@pytest.mark.parametrize("decision_value", ["deny", "failure"])
def test_pre_claim_pdp_rejection_exact_retry_after_uncertain_commit(
    store: AuthorizationTaskStore, decision_value: str
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key=f"pre-claim-{decision_value}-retry")
    approved = approve_decision(
        store, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    ).task
    assert approved is not None
    checked_at_us = 1_150_000
    evidence = pdp_evidence(
        store,
        trusted,
        approved,
        stage="pre_claim",
        checked_at_us=checked_at_us,
        decision=decision_value,
        consistency="unknown",
        cache_used=True,
    )
    before_version = approved.version
    raised = False

    def fault(step: str) -> None:
        nonlocal raised
        if step == "commit.after" and not raised:
            raised = True
            raise RuntimeError("uncertain pre-claim rejection")

    store._fault_hook = fault
    with pytest.raises(RuntimeError, match="uncertain pre-claim rejection"):
        store.reject_from_pdp(
            trusted.task_id, trusted, evidence, now_us=checked_at_us
        )
    store._fault_hook = None

    retry = store.reject_from_pdp(
        trusted.task_id, trusted, evidence, now_us=checked_at_us
    )
    assert retry.applied and retry.idempotent
    assert retry.task is not None and retry.task.status == "denied"
    assert retry.task.version == before_version + 1

    evidence_mismatches = (
        replace(evidence, stage="pre_private_read"),
        replace(
            evidence,
            decision="failure" if decision_value == "deny" else "deny",
        ),
        replace(
            evidence,
            consistency="strongest" if evidence.consistency == "unknown" else "unknown",
        ),
        replace(evidence, cache_used=not evidence.cache_used),
        replace(evidence, task_id="wrong-task"),
        replace(evidence, binding_digest="wrong-binding"),
        replace(evidence, request_digest="wrong-request"),
        replace(evidence, model_identity="wrong-model"),
        replace(evidence, policy_revision="wrong-policy"),
        replace(evidence, pdp_call_id="wrong-pdp-call-id"),
        replace(evidence, checked_at_us=checked_at_us + 1),
        replace(evidence, coordinator_epoch=evidence.coordinator_epoch + 1),
        replace(evidence, evidence_id="missing-evidence"),
    )
    for mismatch in evidence_mismatches:
        assert not store.reject_from_pdp(
            trusted.task_id, trusted, mismatch, now_us=checked_at_us
        ).applied
    assert not store.reject_from_pdp(
        "wrong-task", trusted, evidence, now_us=checked_at_us
    ).applied
    assert not store.reject_from_pdp(
        trusted.task_id,
        replace(trusted, correlation_id="wrong-correlation"),
        evidence,
        now_us=checked_at_us,
    ).applied

    evidence_event_id = f"pdp-evidence:{evidence.evidence_id}"
    terminal_event_id = f"task-pdp-denied:{evidence.evidence_id}"
    tamper_cases = (
        (
            "authorization_pdp_evidence",
            "context_record_digest",
            "evidence_id",
            evidence.evidence_id,
            "tampered-context-record",
        ),
        (
            "authorization_pdp_evidence",
            "evidence_digest",
            "evidence_id",
            evidence.evidence_id,
            "tampered-evidence-record",
        ),
        (
            "authorization_audit_events",
            "actor_token",
            "event_id",
            evidence_event_id,
            "tampered-evidence-audit",
        ),
        (
            "authorization_audit_events",
            "reason_code",
            "event_id",
            terminal_event_id,
            "owner_rejected",
        ),
        (
            "authorization_tasks",
            "status",
            "task_id",
            trusted.task_id,
            "canceled",
        ),
        (
            "authorization_tasks",
            "completed_at_us",
            "task_id",
            trusted.task_id,
            checked_at_us + 1,
        ),
        (
            "authorization_tasks",
            "receipt_code",
            "task_id",
            trusted.task_id,
            "internal_failure",
        ),
        (
            "authorization_tasks",
            "receipt_token",
            "task_id",
            trusted.task_id,
            "unexpected-receipt",
        ),
    )
    with sqlite3.connect(store.db_path) as conn:
        for table, column, key_column, key, tampered in tamper_cases:
            original = conn.execute(
                f"SELECT {column} FROM {table} WHERE {key_column}=?", (key,)
            ).fetchone()[0]
            conn.execute(
                f"UPDATE {table} SET {column}=? WHERE {key_column}=?",
                (tampered, key),
            )
            conn.commit()
            assert not store.reject_from_pdp(
                trusted.task_id, trusted, evidence, now_us=checked_at_us
            ).applied
            conn.execute(
                f"UPDATE {table} SET {column}=? WHERE {key_column}=?",
                (original, key),
            )
            conn.commit()

        for table, key_column, key in (
            ("authorization_pdp_evidence", "evidence_id", evidence.evidence_id),
            ("authorization_audit_events", "event_id", evidence_event_id),
            ("authorization_audit_events", "event_id", terminal_event_id),
        ):
            missing_key = f"missing:{key}"
            conn.execute(
                f"UPDATE {table} SET {key_column}=? WHERE {key_column}=?",
                (missing_key, key),
            )
            conn.commit()
            assert not store.reject_from_pdp(
                trusted.task_id, trusted, evidence, now_us=checked_at_us
            ).applied
            conn.execute(
                f"UPDATE {table} SET {key_column}=? WHERE {key_column}=?",
                (key, missing_key),
            )
            conn.commit()

        assert conn.execute(
            "SELECT version FROM authorization_tasks WHERE task_id=?",
            (trusted.task_id,),
        ).fetchone()[0] == before_version + 1
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_pdp_evidence WHERE evidence_id=?",
            (evidence.evidence_id,),
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events "
            "WHERE event_id IN (?,?)",
            (evidence_event_id, terminal_event_id),
        ).fetchone()[0] == 2


def _start_notification_with_uncertain_commit(
    store: AuthorizationTaskStore,
    *,
    attempt_id: str,
    lease_expires_at_us: int = 1_200_000,
) -> tuple[TrustedAuthorizationBinding, ClaimIdentity, int]:
    trusted = binding()
    store.create_pending(
        trusted,
        request_key=f"send-start-{attempt_id}",
        notification=notification(attempt_id=attempt_id),
    )
    worker = claim(nonce=f"worker-{attempt_id}")
    assert store.claim_notification(
        attempt_id,
        worker,
        now_us=1_100_000,
        lease_expires_at_us=lease_expires_at_us,
    ).applied
    raised = False

    def fault(step: str) -> None:
        nonlocal raised
        if step == "commit.after" and not raised:
            raised = True
            raise RuntimeError("uncertain notification send start")

    store._fault_hook = fault
    with pytest.raises(RuntimeError, match="uncertain notification send start"):
        store.record_notification_send_started(
            attempt_id, worker, now_us=1_150_000
        )
    store._fault_hook = None
    with sqlite3.connect(store.db_path) as conn:
        version = conn.execute(
            "SELECT version FROM authorization_notification_attempts WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()[0]
    return trusted, worker, version


@pytest.mark.parametrize("retry_at_us", [1_200_000, 1_200_001])
def test_notification_send_start_retry_requires_unexpired_lease(
    store: AuthorizationTaskStore, retry_at_us: int
) -> None:
    attempt_id = f"send-start-boundary-{retry_at_us}"
    _, worker, committed_version = _start_notification_with_uncertain_commit(
        store, attempt_id=attempt_id
    )
    before_expiry = store.record_notification_send_started(
        attempt_id, worker, now_us=1_150_000
    )
    assert before_expiry.applied and before_expiry.idempotent
    assert not store.record_notification_send_started(
        attempt_id, worker, now_us=retry_at_us
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT version FROM authorization_notification_attempts WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()[0] == committed_version
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events "
            "WHERE event_id=?",
            (f"notification-send-started:{attempt_id}:{worker.generation}",),
        ).fetchone()[0] == 1


@pytest.mark.parametrize(
    "stale_path",
    ["owner", "nonce", "generation", "task", "binding", "coordinator"],
)
def test_notification_send_start_retry_rechecks_every_delivery_fence(
    store: AuthorizationTaskStore, stale_path: str
) -> None:
    attempt_id = f"send-start-stale-{stale_path}"
    trusted, worker, committed_version = _start_notification_with_uncertain_commit(
        store, attempt_id=attempt_id
    )
    retry_worker = worker
    if stale_path == "owner":
        retry_worker = replace(worker, owner_agent="stale-worker")
    elif stale_path == "nonce":
        retry_worker = replace(worker, nonce="stale-nonce")
    elif stale_path == "generation":
        retry_worker = replace(worker, generation=worker.generation + 1)
    elif stale_path == "task":
        assert store.cancel(
            trusted.task_id,
            trusted,
            now_us=1_160_000,
            reason_code="request_canceled",
        ).applied
    elif stale_path == "binding":
        with sqlite3.connect(store.db_path) as conn:
            conn.execute(
                "UPDATE authorization_tasks SET binding_digest='stale-binding' "
                "WHERE task_id=?",
                (trusted.task_id,),
            )
            conn.commit()
    else:
        store.close()

    if stale_path == "coordinator":
        with pytest.raises(CoordinatorFenceError):
            store.record_notification_send_started(
                attempt_id, retry_worker, now_us=1_170_000
            )
    else:
        assert not store.record_notification_send_started(
            attempt_id, retry_worker, now_us=1_170_000
        ).applied
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT version FROM authorization_notification_attempts WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()[0] == committed_version
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events "
            "WHERE event_id=?",
            (f"notification-send-started:{attempt_id}:{worker.generation}",),
        ).fetchone()[0] == 1


def test_task_claim_and_heartbeat_exact_retry_and_monotonic_lease(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="claim-exact-retry")
    assert approve_decision(
        store, trusted.task_id, trusted, decision_for(trusted), now_us=1_100_000
    ).applied
    worker = claim()
    evidence = claim_pdp(store, trusted, 1_200_000, worker)
    raised = False

    def fault(step: str) -> None:
        nonlocal raised
        if step == "commit.after" and not raised:
            raised = True
            raise RuntimeError("uncertain task claim")

    store._fault_hook = fault
    with pytest.raises(RuntimeError, match="uncertain task claim"):
        store.claim(
            trusted.task_id, trusted, worker, now_us=1_200_000,
            lease_expires_at_us=1_300_000, pdp_evidence=evidence,
        )
    store._fault_hook = None
    retry = store.claim(
        trusted.task_id, trusted, worker, now_us=1_200_000,
        lease_expires_at_us=1_300_000, pdp_evidence=evidence,
    )
    assert retry.applied and retry.idempotent
    assert not store.claim(
        trusted.task_id, trusted, replace(worker, nonce="other"),
        now_us=1_200_000, lease_expires_at_us=1_300_000,
        pdp_evidence=replace(evidence, claim_nonce="other"),
    ).applied
    assert not store.heartbeat(
        trusted.task_id, trusted, worker, now_us=1_210_000,
        lease_expires_at_us=1_299_999,
    ).applied
    assert store.heartbeat(
        trusted.task_id, trusted, worker, now_us=1_210_000,
        lease_expires_at_us=1_300_000,
    ).applied
    repeated = store.heartbeat(
        trusted.task_id, trusted, worker, now_us=1_210_000,
        lease_expires_at_us=1_300_000,
    )
    assert repeated.applied and repeated.idempotent
    assert store.heartbeat(
        trusted.task_id, trusted, worker, now_us=1_220_000,
        lease_expires_at_us=1_350_000,
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events WHERE kind='task_heartbeat'"
        ).fetchone()[0] == 2


def test_notification_claim_and_heartbeat_exact_retry_and_monotonic_lease(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    store.create_pending(
        trusted, request_key="notification-exact-retry", notification=notification()
    )
    worker = claim()
    raised = False

    def fault(step: str) -> None:
        nonlocal raised
        if step == "commit.after" and not raised:
            raised = True
            raise RuntimeError("uncertain notification claim")

    store._fault_hook = fault
    with pytest.raises(RuntimeError, match="uncertain notification claim"):
        store.claim_notification(
            "notification-001", worker, now_us=1_100_000,
            lease_expires_at_us=1_300_000,
        )
    store._fault_hook = None
    retry = store.claim_notification(
        "notification-001", worker, now_us=1_100_000,
        lease_expires_at_us=1_300_000,
    )
    assert retry.applied and retry.idempotent
    assert not store.heartbeat_notification(
        "notification-001", worker, now_us=1_200_000,
        lease_expires_at_us=1_299_999,
    ).applied
    assert store.heartbeat_notification(
        "notification-001", worker, now_us=1_200_000,
        lease_expires_at_us=1_300_000,
    ).applied
    repeated = store.heartbeat_notification(
        "notification-001", worker, now_us=1_200_000,
        lease_expires_at_us=1_300_000,
    )
    assert repeated.applied and repeated.idempotent
    assert store.heartbeat_notification(
        "notification-001", worker, now_us=1_210_000,
        lease_expires_at_us=1_350_000,
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events "
            "WHERE kind='notification_heartbeat'"
        ).fetchone()[0] == 2


def test_failed_pre_send_resolution_can_retry_once_but_ambiguous_cannot(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="resolution-retry")
    owner_decision = decision_for(trusted, decision_id="resolution-retry")
    original = decision_resolution(
        store, trusted, owner_decision, created_at_us=1_100_000
    )
    assert store.approve(
        trusted.task_id, trusted, owner_decision, now_us=1_100_000,
        resolution_notification=original,
    ).applied
    notification_worker = claim(nonce="resolution-worker")
    assert store.claim_notification(
        original.attempt_id, notification_worker, now_us=1_110_000,
        lease_expires_at_us=1_200_000,
    ).applied
    assert store.finish_notification(
        original.attempt_id, notification_worker, now_us=1_120_000,
        outcome="failed", receipt_code="internal_failure",
    ).applied
    assert not store.approve(
        trusted.task_id, trusted, owner_decision, now_us=1_100_000,
        resolution_notification=original,
    ).applied
    replacement = replace(
        original, attempt_id="resolution-retry-2",
        challenge_nonce="resolution-retry-2-nonce",
        created_at_us=1_130_000, due_at_us=1_130_000,
    )
    retried = store.retry_resolution_notification(
        trusted.task_id, trusted, owner_decision,
        failed_attempt_id=original.attempt_id,
        replacement_notification=replacement, now_us=1_130_000,
    )
    assert retried.applied and not retried.idempotent
    exact = store.retry_resolution_notification(
        trusted.task_id, trusted, owner_decision,
        failed_attempt_id=original.attempt_id,
        replacement_notification=replacement, now_us=1_130_000,
    )
    assert exact.applied and exact.idempotent
    assert not store.retry_resolution_notification(
        trusted.task_id, trusted, owner_decision,
        failed_attempt_id=original.attempt_id,
        replacement_notification=replace(
            replacement, attempt_id="duplicate-active", challenge_nonce="duplicate-active"
        ), now_us=1_130_000,
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        rows = conn.execute(
            "SELECT attempt_id,status,retry_ordinal,supersedes_attempt_id "
            "FROM authorization_notification_attempts WHERE kind='approval_resolution' "
            "ORDER BY retry_ordinal"
        ).fetchall()
    assert rows == [
        (original.attempt_id, "failed", 1, None),
        (replacement.attempt_id, "pending", 2, original.attempt_id),
    ]


def test_current_v7_denied_task_can_retry_failed_resolution(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="denied-resolution-retry")
    owner_decision = decision_for(trusted, decision_id="denied-resolution-retry")
    original = decision_resolution(
        store, trusted, owner_decision, created_at_us=1_100_000
    )
    assert deny_decision(
        store,
        trusted.task_id,
        trusted,
        owner_decision,
        now_us=1_100_000,
        reason_code="owner_rejected",
        resolution_notification=original,
    ).applied
    notification_worker = claim(nonce="denied-resolution-worker")
    assert store.claim_notification(
        original.attempt_id,
        notification_worker,
        now_us=1_110_000,
        lease_expires_at_us=1_200_000,
    ).applied
    assert store.finish_notification(
        original.attempt_id,
        notification_worker,
        now_us=1_120_000,
        outcome="failed",
        receipt_code="internal_failure",
    ).applied
    replacement = replace(
        original,
        attempt_id="denied-resolution-retry-2",
        challenge_nonce="denied-resolution-retry-2",
        created_at_us=1_130_000,
        due_at_us=1_130_000,
    )

    retried = store.retry_resolution_notification(
        trusted.task_id,
        trusted,
        owner_decision,
        failed_attempt_id=original.attempt_id,
        replacement_notification=replacement,
        now_us=1_130_000,
    )

    assert retried.applied and not retried.idempotent
    assert retried.attempt is not None
    assert (retried.attempt.status, retried.attempt.retry_ordinal) == ("pending", 2)


def test_post_send_resolution_failure_is_not_retryable(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="resolution-ambiguous")
    owner_decision = decision_for(trusted, decision_id="resolution-ambiguous")
    original = decision_resolution(
        store, trusted, owner_decision, created_at_us=1_100_000
    )
    assert store.approve(
        trusted.task_id, trusted, owner_decision, now_us=1_100_000,
        resolution_notification=original,
    ).applied
    worker = claim(nonce="ambiguous-resolution-worker")
    assert store.claim_notification(
        original.attempt_id, worker, now_us=1_110_000,
        lease_expires_at_us=1_200_000,
    ).applied
    assert store.record_notification_send_started(
        original.attempt_id, worker, now_us=1_120_000
    ).applied
    assert store.finish_notification(
        original.attempt_id, worker, now_us=1_130_000,
        outcome="failed", receipt_code="provider_timeout",
    ).applied
    replacement = replace(
        original, attempt_id="ambiguous-retry", challenge_nonce="ambiguous-retry",
        created_at_us=1_140_000, due_at_us=1_140_000,
    )
    assert not store.retry_resolution_notification(
        trusted.task_id, trusted, owner_decision,
        failed_attempt_id=original.attempt_id,
        replacement_notification=replacement, now_us=1_140_000,
    ).applied


def test_notification_reclaim_generation_cap_survives_concurrency_and_restart(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    attempt_id = "bounded-reclaim"
    assert store.create_pending(
        trusted,
        request_key="bounded-reclaim",
        notification=notification(attempt_id=attempt_id),
    ).applied
    first = claim(nonce="bounded-reclaim-1", generation=1)
    assert store.claim_notification(
        attempt_id, first, now_us=1_010_000, lease_expires_at_us=1_020_000
    ).applied
    lease_end = 1_020_000
    for generation in range(2, MAX_NOTIFICATION_CLAIM_GENERATIONS):
        next_claim = claim(
            nonce=f"bounded-reclaim-{generation}", generation=generation
        )
        assert store.take_over_stale_notification(
            attempt_id,
            next_claim,
            now_us=lease_end,
            lease_expires_at_us=lease_end + 10_000,
        ).applied
        lease_end += 10_000

    assert [
        item.attempt_id
        for item in store.list_stale_pre_send_notification_work_items(now_us=lease_end)
    ] == [attempt_id]
    cap_claim = claim(
        nonce="bounded-reclaim-cap",
        generation=MAX_NOTIFICATION_CLAIM_GENERATIONS,
    )

    def take_cap(_index: int):
        return store.take_over_stale_notification(
            attempt_id,
            cap_claim,
            now_us=lease_end,
            lease_expires_at_us=lease_end + 10_000,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(take_cap, range(2)))
    assert sorted((item.applied, item.idempotent) for item in outcomes) == [
        (True, False),
        (True, True),
    ]
    exhausted_at = lease_end + 10_000
    assert store.list_stale_pre_send_notification_work_items(
        now_us=exhausted_at
    ) == []
    with sqlite3.connect(store.db_path) as conn:
        before = conn.execute(
            "SELECT version,(SELECT COUNT(*) FROM authorization_audit_events) "
            "FROM authorization_notification_attempts WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
    assert not store.take_over_stale_notification(
        attempt_id,
        claim(
            nonce="bounded-reclaim-over-cap",
            generation=MAX_NOTIFICATION_CLAIM_GENERATIONS + 1,
        ),
        now_us=exhausted_at,
        lease_expires_at_us=exhausted_at + 10_000,
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        after = conn.execute(
            "SELECT version,(SELECT COUNT(*) FROM authorization_audit_events) "
            "FROM authorization_notification_attempts WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
    assert after == before

    db_path = store.db_path
    store.close()
    restarted = activate(
        AuthorizationTaskStore(
            db_path=db_path,
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        ),
        now_us=exhausted_at,
        lease_expires_at_us=10_000_000,
    )
    assert restarted.list_stale_pre_send_notification_work_items(
        now_us=exhausted_at
    ) == []
    assert not restarted.take_over_stale_notification(
        attempt_id,
        claim(nonce="restart-over-cap", generation=MAX_NOTIFICATION_CLAIM_GENERATIONS + 1),
        now_us=exhausted_at,
        lease_expires_at_us=exhausted_at + 10_000,
    ).applied
    restarted.close()


def test_resolution_retry_ordinal_cap_has_no_row_or_audit_on_rejection(
    store: AuthorizationTaskStore,
) -> None:
    trusted = binding()
    stage_challenge(store, trusted, request_key="bounded-resolution-retry")
    owner_decision = decision_for(trusted, decision_id="bounded-resolution-retry")
    current = decision_resolution(
        store, trusted, owner_decision, created_at_us=1_100_000
    )
    assert store.approve(
        trusted.task_id,
        trusted,
        owner_decision,
        now_us=1_100_000,
        resolution_notification=current,
    ).applied

    for ordinal in range(1, MAX_NOTIFICATION_RETRY_ORDINAL):
        now_us = 1_110_000 + ordinal * 10_000
        worker = claim(nonce=f"retry-worker-{ordinal}")
        assert store.claim_notification(
            current.attempt_id,
            worker,
            now_us=now_us,
            lease_expires_at_us=now_us + 5_000,
        ).applied
        assert store.finish_notification(
            current.attempt_id,
            worker,
            now_us=now_us + 1_000,
            outcome="failed",
            receipt_code="internal_failure",
        ).applied
        replacement = replace(
            current,
            attempt_id=f"bounded-resolution-{ordinal + 1}",
            challenge_nonce=f"bounded-resolution-{ordinal + 1}",
            created_at_us=now_us + 2_000,
            due_at_us=now_us + 2_000,
        )
        if ordinal == MAX_NOTIFICATION_RETRY_ORDINAL - 1:
            def create_cap(_index: int):
                return store.retry_resolution_notification(
                    trusted.task_id,
                    trusted,
                    owner_decision,
                    failed_attempt_id=current.attempt_id,
                    replacement_notification=replacement,
                    now_us=now_us + 2_000,
                )

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(create_cap, range(2)))
            assert sorted((item.applied, item.idempotent) for item in results) == [
                (True, False),
                (True, True),
            ]
        else:
            created = store.retry_resolution_notification(
                trusted.task_id,
                trusted,
                owner_decision,
                failed_attempt_id=current.attempt_id,
                replacement_notification=replacement,
                now_us=now_us + 2_000,
            )
            assert created.applied and created.attempt is not None
            assert created.attempt.retry_ordinal == ordinal + 1
        current = replacement

    cap_now = 1_300_000
    cap_worker = claim(nonce="retry-worker-cap")
    assert store.claim_notification(
        current.attempt_id,
        cap_worker,
        now_us=cap_now,
        lease_expires_at_us=cap_now + 5_000,
    ).applied
    assert store.finish_notification(
        current.attempt_id,
        cap_worker,
        now_us=cap_now + 1_000,
        outcome="failed",
        receipt_code="internal_failure",
    ).applied
    rejected = replace(
        current,
        attempt_id="bounded-resolution-over-cap",
        challenge_nonce="bounded-resolution-over-cap",
        created_at_us=cap_now + 2_000,
        due_at_us=cap_now + 2_000,
    )
    with sqlite3.connect(store.db_path) as conn:
        before = conn.execute(
            "SELECT COUNT(*) FROM authorization_notification_attempts"
        ).fetchone()[0], conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events"
        ).fetchone()[0]
    assert not store.retry_resolution_notification(
        trusted.task_id,
        trusted,
        owner_decision,
        failed_attempt_id=current.attempt_id,
        replacement_notification=rejected,
        now_us=cap_now + 2_000,
    ).applied
    with sqlite3.connect(store.db_path) as conn:
        after = conn.execute(
            "SELECT COUNT(*) FROM authorization_notification_attempts"
        ).fetchone()[0], conn.execute(
            "SELECT COUNT(*) FROM authorization_audit_events"
        ).fetchone()[0]
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_notification_attempts WHERE attempt_id=?",
            (rejected.attempt_id,),
        ).fetchone()[0] == 0
    assert after == before

    db_path = store.db_path
    store.close()
    restarted = activate(
        AuthorizationTaskStore(
            db_path=db_path,
            audit_hmac_key=AUDIT_KEY,
            request_hmac_key=REQUEST_KEY,
            key_version="test-k1",
        ),
        now_us=cap_now + 3_000,
        lease_expires_at_us=10_000_000,
    )
    assert not restarted.retry_resolution_notification(
        trusted.task_id,
        trusted,
        owner_decision,
        failed_attempt_id=current.attempt_id,
        replacement_notification=replace(
            rejected,
            attempt_id="bounded-resolution-over-cap-after-restart",
            challenge_nonce="bounded-resolution-over-cap-after-restart",
            created_at_us=cap_now + 3_000,
            due_at_us=cap_now + 3_000,
        ),
        now_us=cap_now + 3_000,
    ).applied
    restarted.close()


@pytest.mark.parametrize(
    ("legacy_status", "send_started", "expected_status", "expected_receipt"),
    [
        ("approval_required", None, "denied", "incomplete_delivery_binding"),
        ("approved", None, "denied", "incomplete_delivery_binding"),
        ("claimed", None, "failed_consumed", "incomplete_delivery_binding"),
        ("claimed", 1_300_000, "failed_consumed", "ambiguous_after_restart"),
        ("denied", None, "denied", None),
    ],
)
def test_real_v3_to_v4_migration_terminalizes_incomplete_delivery_bindings(
    tmp_path: Path,
    legacy_status: str,
    send_started: int | None,
    expected_status: str,
    expected_receipt: str | None,
) -> None:
    signer_root = tmp_path / f"signer-{legacy_status}-{send_started}"
    signer_root.mkdir(mode=0o700)
    signer = AuthorizationTaskStore(
        db_path=(signer_root / "authorization.db").absolute(),
        audit_hmac_key=AUDIT_KEY, request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    legacy = replace(
        binding(task_id=f"legacy-{legacy_status}-{send_started}",
                correlation_id=f"corr-{legacy_status}-{send_started}"),
        delivery_platform="", delivery_transport_implementation="",
        delivery_runtime_identity="", delivery_account_binding="",
        delivery_connection_epoch=0, policy_version="", policy_hash="",
    )
    root = tmp_path / f"v3-{legacy_status}-{send_started}"
    root.mkdir(mode=0o700)
    db_path = (root / "authorization.db").absolute()
    db_path.touch(mode=0o600)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(";".join((
            _TASKS_V3.format(table="authorization_tasks"),
            _AUDIT_V2.format(table="authorization_audit_events"),
            _NOTIFICATIONS_V3.format(table="authorization_notification_attempts"),
            _PDP_V3.format(table="authorization_pdp_evidence"),
            _LEASE, _INDEXES_V2, "PRAGMA user_version=3",
        )))
        worker = claim()
        owner_digest, nonce_digest = signer._claim_digests(worker)
        request_key = f"request-{legacy.task_id}"
        conn.execute(
            "INSERT INTO authorization_tasks "
            "(task_id,correlation_id,scoped_request_key,binding_json,binding_digest,"
            "request_digest,key_version,status,created_at_us,expires_at_us,"
            "claim_owner_digest,claim_nonce_digest,claim_generation,"
            "claim_lease_expires_at_us,claimed_at_us,heartbeat_at_us,send_started_at_us) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                legacy.task_id, legacy.correlation_id, request_key,
                legacy.canonical_bytes().decode(), signer._binding_digest(legacy),
                signer._request_digest(request_key, legacy), "test-k1", legacy_status,
                legacy.created_at_us, legacy.expires_at_us,
                owner_digest if legacy_status == "claimed" else None,
                nonce_digest if legacy_status == "claimed" else None,
                1 if legacy_status == "claimed" else None,
                1_500_000 if legacy_status == "claimed" else None,
                1_200_000 if legacy_status == "claimed" else None,
                1_200_000 if legacy_status == "claimed" else None,
                send_started,
            ),
        )
        if legacy_status == "approval_required":
            notification_spec = notification(
                attempt_id=f"legacy-notification-{legacy.task_id}",
                destination_profile=legacy.approval_profile,
                destination_account=legacy.approval_account,
                destination_chat=legacy.approval_chat,
                destination_thread=legacy.approval_thread,
            )
            destination_digest = hmac.new(
                REQUEST_KEY,
                b"hermes-authorization-notification-destination-v1\0"
                + notification_spec.destination_bytes(),
                hashlib.sha256,
            ).hexdigest()
            notification_values = {
                "attempt_id": notification_spec.attempt_id,
                "task_id": legacy.task_id,
                "correlation_id": legacy.correlation_id,
                "kind": notification_spec.kind,
                "challenge_generation": notification_spec.challenge_generation,
                "destination_profile": notification_spec.destination_profile,
                "destination_account": notification_spec.destination_account,
                "destination_chat": notification_spec.destination_chat,
                "destination_thread": notification_spec.destination_thread,
                "destination_digest": destination_digest,
                "key_version": "test-k1",
                "challenge_nonce_digest": signer._challenge_nonce_digest(
                    notification_spec.challenge_nonce,
                    task_id=legacy.task_id,
                    attempt_id=notification_spec.attempt_id,
                    challenge_generation=notification_spec.challenge_generation,
                ),
                "nonce_verifier_version": "v2",
                "provider_message_verifier": None,
                "provider_verifier_version": None,
                "provider_acceptance_status": None,
                "provider_accepted_at_us": None,
                "adapter_instance_id": None,
                "account_binding_token": None,
                "connection_epoch": None,
                "challenge_state": "unaccepted",
                "challenge_resolved_at_us": None,
                "challenge_decision_digest": None,
            }
            conn.execute(
                "INSERT INTO authorization_notification_attempts "
                "(attempt_id,task_id,correlation_id,kind,challenge_generation,"
                "destination_profile,destination_account,destination_chat,destination_thread,"
                "destination_digest,key_version,status,created_at_us,due_at_us,"
                "challenge_nonce_digest,nonce_verifier_version,challenge_state,"
                "challenge_record_digest) VALUES (?,?,?,?,?,?,?,?,?,?,?,'pending',?,?,?,?,?,?)",
                (
                    notification_spec.attempt_id, legacy.task_id, legacy.correlation_id,
                    notification_spec.kind, notification_spec.challenge_generation,
                    notification_spec.destination_profile,
                    notification_spec.destination_account,
                    notification_spec.destination_chat,
                    notification_spec.destination_thread,
                    destination_digest, "test-k1", notification_spec.created_at_us,
                    notification_spec.due_at_us,
                    notification_values["challenge_nonce_digest"], "v2", "unaccepted",
                    signer._legacy_challenge_record_digest_v3(
                        REQUEST_KEY, "test-k1", notification_values
                    ),
                ),
            )
    migrated = AuthorizationTaskStore(
        db_path=db_path, audit_hmac_key=AUDIT_KEY, request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
    )
    task = migrated.load_task(legacy.task_id, legacy)
    assert (task.status, task.receipt_code) == (expected_status, expected_receipt)
    activate(migrated)
    legacy_worker = claim()
    with pytest.raises(AuthorizationIntegrityError, match="stale or ineligible"):
        migrated.create_pdp_check_context(
            legacy.task_id, legacy_worker, stage="pre_claim", now_us=1_400_000
        )
    with pytest.raises(AuthorizationIntegrityError, match="stale or ineligible"):
        migrated.create_pdp_check_context(
            legacy.task_id,
            legacy_worker,
            stage="pre_private_read",
            now_us=1_400_000,
        )
    assert not migrated.record_send_started(
        legacy.task_id, legacy, legacy_worker, now_us=1_400_000
    ).applied
    if legacy_status == "approval_required":
        attempts = migrated.list_notifications(
            status="failed", due_before_us=1_400_000, now_us=1_400_000
        )
        assert len(attempts) == 1
        assert attempts[0].receipt_code == "incomplete_delivery_binding"
        assert not migrated.claim_notification(
            attempts[0].attempt_id, legacy_worker, now_us=1_400_000,
            lease_expires_at_us=1_500_000,
        ).applied
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
