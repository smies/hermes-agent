from __future__ import annotations

import dataclasses
import sqlite3
from pathlib import Path

import pytest

from gateway.authorization_contracts import (
    AuthorizationIntegrityError,
    AuthorizationNotificationWorkItem,
    AuthorizationPdpCheckContext,
    AuthorizationTaskWorkItem,
    CoordinatorFenceError,
    ExternalPdpDecisionResult,
    SCHEMA_VERSION,
)
from gateway.authorization_tasks import AuthorizationTaskStore, CoordinatorIdentity
from gateway.authorization_schema import _AUDIT_V4
from tests.gateway.test_authorization_task_store import (
    AUDIT_KEY,
    COORDINATOR,
    REQUEST_KEY,
    activate,
    approve_decision,
    binding,
    claim,
    decision_for,
    notification,
    stage_challenge,
)


def new_store(root: Path, *, active: bool = True) -> AuthorizationTaskStore:
    root.mkdir(mode=0o700, exist_ok=True)
    value = AuthorizationTaskStore(
        db_path=root / "authorization.db",
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="test-k1",
        journal_mode="delete",
    )
    return activate(value) if active else value


def pending_with_notification(
    value: AuthorizationTaskStore,
    *,
    task_id: str = "task-001",
    correlation_id: str = "corr-001",
    attempt_id: str = "attempt-001",
) -> None:
    item = binding(task_id=task_id, correlation_id=correlation_id)
    spec = notification(attempt_id=attempt_id)
    assert value.create_pending(
        item, request_key=f"request-{task_id}", notification=spec
    ).applied


def approved_task(value: AuthorizationTaskStore, *, task_id: str = "task-001"):
    correlation_id = task_id.replace("task", "corr")
    item = binding(task_id=task_id, correlation_id=correlation_id)
    stage_challenge(value, item, request_key=f"approved-{task_id}")
    result = approve_decision(
        value,
        item.task_id,
        item,
        decision_for(item, decision_id=f"decision-{task_id}"),
        now_us=1_100_000,
    )
    assert result.applied
    return item


def external_result(
    context: AuthorizationPdpCheckContext | None = None,
    *,
    pdp_call_id: str = "host-call",
    decision: str = "allow",
    checked_at_us: int = 1_200_000,
    consistency: str = "strongest",
    cache_used: bool = False,
) -> ExternalPdpDecisionResult:
    return ExternalPdpDecisionResult(
        context_id=context.context_id if context is not None else "context-id",
        pdp_call_id=context.pdp_call_id if context is not None else pdp_call_id,
        decision=decision,
        checked_at_us=checked_at_us,
        consistency=consistency,
        cache_used=cache_used,
    )


def test_exact_work_items_round_trip_after_restart_and_lists_are_bounded(
    tmp_path: Path,
) -> None:
    root = tmp_path / "roundtrip"
    first = new_store(root)
    pending_with_notification(first)

    task_work = first.load_task_work_item("task-001", now_us=1_000_000)
    notification_work = first.load_notification_work_item(
        "attempt-001", now_us=1_000_000
    )
    assert type(task_work) is AuthorizationTaskWorkItem
    assert type(notification_work) is AuthorizationNotificationWorkItem
    assert task_work.task_id == notification_work.task_id == "task-001"
    assert task_work.tool_call_id == notification_work.tool_call_id == "call-001"
    assert notification_work.attempt_id == "attempt-001"
    assert notification_work.challenge_generation == 1
    assert notification_work.key_version == "test-k1"

    serialized = repr((dataclasses.asdict(task_work), dataclasses.asdict(notification_work)))
    assert notification().challenge_nonce not in serialized
    first.close()

    restarted = new_store(root)
    assert restarted.load_task_work_item("task-001", now_us=1_000_001) == task_work
    assert restarted.load_notification_work_item(
        "attempt-001", now_us=1_000_001
    ) == notification_work
    for ordinal in range(2, 6):
        approved_task(restarted, task_id=f"task-{ordinal:03d}")
    assert len(
        restarted.list_approved_task_work_items(now_us=1_100_001, limit=2)
    ) == 2
    assert len(
        restarted.list_pending_due_notification_work_items(
            now_us=1_100_001, limit=3
        )
    ) == 3


@pytest.mark.parametrize(
    ("column", "replacement"),
    [
        ("binding_json", "{}"),
        ("binding_digest", "tampered-binding"),
        ("request_digest", "tampered-request"),
        ("key_version", "unknown-key"),
        ("correlation_id", "wrong-correlation"),
        ("scoped_request_key", "wrong-request-key"),
        ("created_at_us", 999_999),
        ("expires_at_us", 1_999_999),
        ("status", "approval_required"),
        ("decision_id", "tampered-decision"),
        ("decision_digest", "tampered-decision-digest"),
        ("winning_challenge_attempt_id", "tampered-attempt"),
        ("winning_challenge_generation", 99),
        ("claim_owner_digest", "tampered-owner"),
        ("claim_nonce_digest", "tampered-nonce"),
        ("claim_generation", 99),
        ("claim_lease_expires_at_us", 1_900_000),
        ("claimed_at_us", 1_200_000),
        ("heartbeat_at_us", 1_200_000),
        ("send_started_at_us", 1_200_000),
        ("completed_at_us", 1_200_000),
        ("receipt_code", "internal_failure"),
        ("receipt_token", "tampered-receipt"),
        ("delivery_acceptance_status", "provider_accepted"),
        ("delivery_accepted_at_us", 1_200_000),
        ("delivery_transport_implementation", "tampered-transport"),
        ("delivery_runtime_identity", "tampered-runtime"),
        ("delivery_account_binding_token", "tampered-account"),
        ("delivery_connection_epoch", 99),
        ("delivery_record_digest", "tampered-delivery-record"),
        ("resolution_spec_digest", "tampered-resolution"),
        ("audit_event_count", 99),
        ("audit_head_digest", "tampered-audit-head"),
        ("version", 99),
        ("mutable_state_digest", "tampered-state"),
    ],
)
def test_task_work_item_tamper_is_corruption_not_authority(
    tmp_path: Path, column: str, replacement: object
) -> None:
    value = new_store(tmp_path / column)
    approved_task(value)
    with sqlite3.connect(value.db_path) as conn:
        conn.execute("PRAGMA ignore_check_constraints=ON")
        conn.execute(
            f"UPDATE authorization_tasks SET {column}=? WHERE task_id='task-001'",
            (replacement,),
        )
    with pytest.raises(
        AuthorizationIntegrityError,
        match="authorization task failed integrity verification",
    ):
        value.load_task_work_item("task-001", now_us=1_000_000)
    with sqlite3.connect(value.db_path) as conn:
        status = conn.execute(
            "SELECT status FROM authorization_tasks WHERE task_id='task-001'"
        ).fetchone()[0]
    with pytest.raises(AuthorizationIntegrityError, match="task list"):
        value.list_tasks(
            status=status, due_before_us=2_000_000, now_us=1_200_000
        )


@pytest.mark.parametrize(
    ("column", "replacement"),
    [
        ("correlation_id", "wrong-correlation"),
        ("kind", "wrong-kind"),
        ("challenge_generation", 9),
        ("destination_profile", "wrong-profile"),
        ("destination_account", "wrong-account"),
        ("destination_chat", "wrong-chat"),
        ("destination_thread", "wrong-thread"),
        ("destination_digest", "tampered-destination"),
        ("key_version", "unknown-key"),
        ("status", "claimed"),
        ("created_at_us", 999_999),
        ("due_at_us", 999_999),
        ("claim_owner_digest", "tampered-owner"),
        ("claim_nonce_digest", "tampered-nonce"),
        ("claim_generation", 99),
        ("claim_lease_expires_at_us", 1_000_000),
        ("send_started_at_us", 1_000_000),
        ("completed_at_us", 1_000_000),
        ("receipt_code", "internal_failure"),
        ("challenge_nonce_digest", "tampered-challenge-nonce"),
        ("nonce_verifier_version", "tampered-algorithm"),
        ("provider_message_verifier", "tampered-provider-message"),
        ("provider_verifier_version", "tampered-provider-version"),
        ("provider_acceptance_status", "provider_accepted"),
        ("provider_accepted_at_us", 1_000_000),
        ("adapter_instance_id", "tampered-adapter"),
        ("account_binding_token", "tampered-binding"),
        ("connection_epoch", 99),
        ("challenge_state", "accepted"),
        ("challenge_resolved_at_us", 1_000_000),
        ("challenge_decision_digest", "tampered-challenge-decision"),
        ("notification_spec_digest", "tampered-spec"),
        ("challenge_record_digest", "tampered-record"),
        ("retry_ordinal", 99),
        ("supersedes_attempt_id", "tampered-supersedes"),
        ("version", 99),
        ("mutable_state_digest", "tampered-state"),
    ],
)
def test_notification_work_item_tamper_is_corruption_not_authority(
    tmp_path: Path, column: str, replacement: object
) -> None:
    value = new_store(tmp_path / column)
    pending_with_notification(value)
    with sqlite3.connect(value.db_path) as conn:
        conn.execute("PRAGMA ignore_check_constraints=ON")
        conn.execute(
            f"UPDATE authorization_notification_attempts SET {column}=? "
            "WHERE attempt_id='attempt-001'",
            (replacement,),
        )
    with pytest.raises(
        AuthorizationIntegrityError,
        match="authorization notification failed integrity verification",
    ):
        value.load_notification_work_item("attempt-001", now_us=1_000_000)
    with sqlite3.connect(value.db_path) as conn:
        status = conn.execute(
            "SELECT status FROM authorization_notification_attempts "
            "WHERE attempt_id='attempt-001'"
        ).fetchone()[0]
    with pytest.raises(AuthorizationIntegrityError, match="notification list"):
        value.list_notifications(
            status=status, due_before_us=2_000_000, now_us=1_100_000
        )


@pytest.mark.parametrize(
    ("table", "identifier", "column", "replacement"),
    [
        ("authorization_tasks", "task-001", "status", sqlite3.Binary(b"approved")),
        ("authorization_tasks", "task-001", "status", "x" * 70_000),
        (
            "authorization_notification_attempts", "attempt-001", "status",
            sqlite3.Binary(b"pending"),
        ),
        (
            "authorization_notification_attempts", "attempt-001", "status",
            "x" * 70_000,
        ),
    ],
)
def test_malformed_or_huge_authority_values_normalize_to_integrity_error(
    tmp_path: Path,
    table: str,
    identifier: str,
    column: str,
    replacement: object,
) -> None:
    value = new_store(tmp_path / f"malformed-{table}-{type(replacement).__name__}")
    pending_with_notification(value)
    key = "task_id" if table == "authorization_tasks" else "attempt_id"
    with sqlite3.connect(value.db_path) as conn:
        conn.execute("PRAGMA ignore_check_constraints=ON")
        conn.execute(
            f"UPDATE {table} SET {column}=? WHERE {key}=?",
            (replacement, identifier),
        )
    loader = (
        value.load_task_work_item
        if table == "authorization_tasks"
        else value.load_notification_work_item
    )
    with pytest.raises(AuthorizationIntegrityError) as caught:
        loader(identifier, now_us=1_100_000)
    assert "serializer" not in str(caught.value).lower()


def test_forged_approval_without_transition_audit_never_becomes_authority(
    tmp_path: Path,
) -> None:
    value = new_store(tmp_path / "forged-approval")
    pending_with_notification(value)
    with sqlite3.connect(value.db_path) as conn:
        conn.execute("DELETE FROM authorization_audit_events WHERE task_id='task-001'")
        conn.execute(
            "UPDATE authorization_tasks SET status='approved' WHERE task_id='task-001'"
        )
    with pytest.raises(AuthorizationIntegrityError, match="task list"):
        value.list_approved_task_work_items(now_us=1_200_000)
    with pytest.raises(AuthorizationIntegrityError, match="task failed"):
        value.create_pdp_check_context(
            "task-001", claim(), stage="pre_claim", now_us=1_200_000
        )


@pytest.mark.parametrize("removed", ["approval-audit", "winning-challenge"])
def test_approved_state_requires_complete_authenticated_transition_chain(
    tmp_path: Path, removed: str
) -> None:
    value = new_store(tmp_path / removed)
    item = approved_task(value)
    with sqlite3.connect(value.db_path) as conn:
        if removed == "approval-audit":
            conn.execute(
                "DELETE FROM authorization_audit_events WHERE event_id=?",
                (f"task-approved:decision-{item.task_id}",),
            )
        else:
            conn.execute(
                "PRAGMA foreign_keys=OFF"
            )
            conn.execute(
                "DELETE FROM authorization_notification_attempts WHERE attempt_id=?",
                (f"challenge-{item.task_id}",),
            )
    with pytest.raises(AuthorizationIntegrityError, match="task list"):
        value.list_approved_task_work_items(now_us=1_200_000)
    with pytest.raises(AuthorizationIntegrityError, match="task failed"):
        value.create_pdp_check_context(
            item.task_id, claim(), stage="pre_claim", now_us=1_200_000
        )


def test_focused_selectors_observe_exact_boundaries_and_notification_eligibility(
    tmp_path: Path,
) -> None:
    value = new_store(tmp_path / "focused-selectors")
    approved = approved_task(value)
    assert [item.task_id for item in value.list_approved_task_work_items(
        now_us=approved.expires_at_us - 1
    )] == [approved.task_id]
    assert value.list_approved_task_work_items(now_us=approved.expires_at_us) == []

    pending_with_notification(
        value, task_id="task-pending", correlation_id="corr-pending",
        attempt_id="attempt-pending",
    )
    assert value.list_pending_due_notification_work_items(now_us=1_000_001) == []
    due = value.list_pending_due_notification_work_items(now_us=1_000_002)
    assert [item.attempt_id for item in due] == ["attempt-pending"]
    assert due[0].binding_digest and due[0].nonce_verifier_version == "v2"

    worker = claim()
    assert value.claim_notification(
        "attempt-pending", worker, now_us=1_000_002,
        lease_expires_at_us=1_100_000,
    ).applied
    assert value.list_stale_pre_send_notification_work_items(
        now_us=1_099_999
    ) == []
    stale = value.list_stale_pre_send_notification_work_items(now_us=1_100_000)
    assert [item.attempt_id for item in stale] == ["attempt-pending"]


def test_corrupt_first_candidate_fails_list_explicitly_without_starvation(
    tmp_path: Path,
) -> None:
    value = new_store(tmp_path / "list-starvation")
    approved_task(value, task_id="task-001")
    approved_task(value, task_id="task-002")
    pending_with_notification(
        value, task_id="task-003", correlation_id="corr-003",
        attempt_id="attempt-003",
    )
    pending_with_notification(
        value, task_id="task-004", correlation_id="corr-004",
        attempt_id="attempt-004",
    )
    with sqlite3.connect(value.db_path) as conn:
        conn.execute(
            "UPDATE authorization_tasks SET version=99 WHERE task_id='task-001'"
        )
        conn.execute(
            "UPDATE authorization_notification_attempts SET version=99 "
            "WHERE attempt_id='attempt-003'"
        )
    with pytest.raises(AuthorizationIntegrityError, match="task list"):
        value.list_approved_task_work_items(now_us=1_200_000, limit=1)
    with pytest.raises(AuthorizationIntegrityError, match="notification list"):
        value.list_pending_due_notification_work_items(now_us=1_100_000, limit=1)


def test_new_coordinator_reconciles_pre_send_sensitive_claim_before_work(
    tmp_path: Path,
) -> None:
    root = tmp_path / "coordinator-loss"
    first_store = new_store(root)
    item = approved_task(first_store)
    worker = claim()
    context = first_store.create_pdp_check_context(
        item.task_id, worker, stage="pre_claim", now_us=1_200_000
    )
    evidence = first_store.create_pdp_decision_evidence(
        context, worker, external_result(context)
    )
    assert first_store.claim(
        item.task_id, item, worker, now_us=1_200_000,
        lease_expires_at_us=1_300_000, pdp_evidence=evidence,
    ).applied
    assert first_store.load_task(item.task_id, item).send_started_at_us is None
    first_store.close()

    replacement = new_store(root, active=False)
    activate(replacement, now_us=1_250_000)
    burned = replacement.load_task(item.task_id, item)
    assert burned.status == "failed_consumed"
    assert burned.receipt_code == "ambiguous_after_restart"
    assert replacement.list_approved_task_work_items(now_us=1_250_000) == []


def test_pdp_factory_seal_rejects_tampering_of_every_authority_field(
    tmp_path: Path,
) -> None:
    value = new_store(tmp_path / "pdp-rebind")
    first = approved_task(value, task_id="task-001")
    second = approved_task(value, task_id="task-002")
    worker = claim()
    first_context = value.create_pdp_check_context(
        first.task_id, worker, stage="pre_claim", now_us=1_200_000
    )
    second_context = value.create_pdp_check_context(
        second.task_id, worker, stage="pre_claim", now_us=1_200_000
    )
    first_result = external_result(first_context)
    with pytest.raises(AuthorizationIntegrityError, match="result binding"):
        value.create_pdp_decision_evidence(second_context, worker, first_result)
    evidence = value.create_pdp_decision_evidence(first_context, worker, first_result)
    for field in dataclasses.fields(evidence):
        if field.name == "factory_seal":
            continue
        original = getattr(evidence, field.name)
        if field.name == "stage":
            changed = "pre_private_read"
        elif field.name == "decision":
            changed = "deny"
        elif field.name == "consistency":
            changed = "unknown"
        elif type(original) is bool:
            changed = not original
        elif type(original) is int:
            changed = original + 1
        else:
            changed = f"{original}-tampered"
        modified = dataclasses.replace(evidence, **{field.name: changed})
        with pytest.raises(ValueError, match="stale or mismatched"):
            value.claim(
                first.task_id, first, worker, now_us=1_200_000,
                lease_expires_at_us=1_300_000, pdp_evidence=modified,
            )
    forged_values = dataclasses.asdict(evidence)
    forged_values["factory_seal"] = "forged-seal"
    forged = type(evidence)(**forged_values)
    with pytest.raises(ValueError, match="stale or mismatched"):
        value.claim(
            first.task_id, first, worker, now_us=1_200_000,
            lease_expires_at_us=1_300_000, pdp_evidence=forged,
        )


def test_populated_v5_migration_terminalizes_all_legacy_active_state(
    tmp_path: Path,
) -> None:
    root = tmp_path / "populated-v5"
    value = new_store(root)
    approved = approved_task(value, task_id="task-approved")
    claimed = approved_task(value, task_id="task-claimed")
    worker = claim()
    context = value.create_pdp_check_context(
        claimed.task_id, worker, stage="pre_claim", now_us=1_200_000
    )
    evidence = value.create_pdp_decision_evidence(
        context, worker, external_result(context)
    )
    assert value.claim(
        claimed.task_id, claimed, worker, now_us=1_200_000,
        lease_expires_at_us=1_300_000, pdp_evidence=evidence,
    ).applied
    pending_with_notification(
        value, task_id="task-pending", correlation_id="corr-pending",
        attempt_id="attempt-pending",
    )
    pending_with_notification(
        value, task_id="task-forged", correlation_id="corr-forged",
        attempt_id="attempt-forged",
    )
    value.close()
    with sqlite3.connect(root / "authorization.db") as conn:
        conn.execute("ALTER TABLE authorization_tasks DROP COLUMN mutable_state_digest")
        conn.execute("ALTER TABLE authorization_tasks DROP COLUMN audit_event_count")
        conn.execute("ALTER TABLE authorization_tasks DROP COLUMN audit_head_digest")
        conn.execute(
            "ALTER TABLE authorization_notification_attempts "
            "DROP COLUMN mutable_state_digest"
        )
        conn.execute("DROP INDEX IF EXISTS idx_authorization_audit_task_time")
        conn.execute(
            "ALTER TABLE authorization_audit_events "
            "RENAME TO authorization_audit_events_v7"
        )
        conn.execute(_AUDIT_V4.format(table="authorization_audit_events"))
        conn.execute(
            "INSERT INTO authorization_audit_events "
            "(event_id,task_id,kind,reason_code,actor_token,target_token,"
            "request_digest,key_version,occurred_at_us) "
            "SELECT event_id,task_id,kind,reason_code,actor_token,target_token,"
            "request_digest,key_version,occurred_at_us "
            "FROM authorization_audit_events_v7"
        )
        conn.execute("DROP TABLE authorization_audit_events_v7")
        conn.execute(
            "UPDATE authorization_tasks SET status='approved' "
            "WHERE task_id='task-forged'"
        )
        conn.execute("PRAGMA user_version=5")

    migrated = new_store(root)
    approved_state = migrated.load_task(approved.task_id, approved)
    assert (approved_state.status, approved_state.receipt_code) == (
        "denied",
        "ambiguous_after_restart",
    )
    claimed_state = migrated.load_task(claimed.task_id, claimed)
    assert (claimed_state.status, claimed_state.receipt_code) == (
        "failed_consumed",
        "ambiguous_after_restart",
    )
    forged_binding = binding(task_id="task-forged", correlation_id="corr-forged")
    assert migrated.load_task("task-forged", forged_binding).status == "denied"
    pending_binding = binding(task_id="task-pending", correlation_id="corr-pending")
    assert migrated.load_task("task-pending", pending_binding).status == "denied"
    assert migrated.list_pending_due_notification_work_items(now_us=1_100_000) == []
    assert migrated.list_stale_pre_send_notification_work_items(now_us=1_400_000) == []
    with pytest.raises(AuthorizationIntegrityError, match="stale or ineligible"):
        migrated.create_pdp_check_context(
            approved.task_id, worker, stage="pre_claim", now_us=1_200_001
        )
    # The opaque legacy evidence remains historical, but terminal task state
    # prevents it from being turned back into a current PDP context.
    with sqlite3.connect(root / "authorization.db") as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM authorization_pdp_evidence WHERE task_id=?",
            (claimed.task_id,),
        ).fetchone()[0] == 1


@pytest.mark.parametrize("decision", ["allow", "deny", "failure"])
def test_store_factory_owns_exact_pdp_context_and_evidence(
    tmp_path: Path, decision: str
) -> None:
    value = new_store(tmp_path / decision)
    item = approved_task(value)
    worker = claim()
    context = value.create_pdp_check_context(
        item.task_id, worker, stage="pre_claim", now_us=1_200_000
    )
    assert type(context) is AuthorizationPdpCheckContext
    result = external_result(
        context,
        decision=decision,
        consistency="strongest" if decision == "allow" else "unknown",
        cache_used=decision != "allow",
    )
    evidence = value.create_pdp_decision_evidence(context, worker, result)
    assert (
        evidence.evidence_id,
        evidence.pdp_call_id,
        evidence.decision,
        evidence.request_digest,
        evidence.binding_digest,
        evidence.key_version,
        evidence.model_identity,
        evidence.policy_revision,
        evidence.coordinator_epoch,
        evidence.worker_profile,
        evidence.worker_agent,
        evidence.worker_account,
        evidence.claim_generation,
    ) == (
        result.pdp_call_id,
        result.pdp_call_id,
        decision,
        context.request_digest,
        context.binding_digest,
        context.key_version,
        context.model_identity,
        context.policy_identity,
        context.coordinator_epoch,
        context.worker_profile,
        context.worker_agent,
        context.worker_account,
        context.claim_generation,
    )
    if decision == "allow":
        assert value.claim(
            item.task_id,
            item,
            worker,
            now_us=1_200_000,
            lease_expires_at_us=1_300_000,
            pdp_evidence=evidence,
        ).applied
    else:
        assert value.reject_from_pdp(
            item.task_id, item, evidence, now_us=1_200_000
        ).applied


def test_context_revalidation_rejects_row_claim_time_stage_and_fence_changes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "stale-context"
    value = new_store(root)
    item = approved_task(value)
    worker = claim()
    context = value.create_pdp_check_context(
        item.task_id, worker, stage="pre_claim", now_us=1_200_000
    )
    with pytest.raises(ValueError, match="unsupported PDP check stage"):
        value.create_pdp_check_context(
            item.task_id, worker, stage="wrong-stage", now_us=1_200_000
        )
    with pytest.raises(AuthorizationIntegrityError, match="stale or ineligible"):
        value.create_pdp_check_context(
            item.task_id,
            dataclasses.replace(worker, generation=2),
            stage="pre_claim",
            now_us=1_200_000,
        )
    with pytest.raises(AuthorizationIntegrityError, match="stale"):
        value.create_pdp_decision_evidence(
            context,
            worker,
            external_result(context, checked_at_us=1_199_999),
        )

    evidence = value.create_pdp_decision_evidence(
        context, worker, external_result(context)
    )
    assert value.claim(
        item.task_id,
        item,
        worker,
        now_us=1_200_000,
        lease_expires_at_us=1_300_000,
        pdp_evidence=evidence,
    ).applied
    with pytest.raises(AuthorizationIntegrityError, match="stale"):
        value.create_pdp_decision_evidence(
            context, worker, external_result(context, checked_at_us=1_200_001)
        )

    private_context = value.create_pdp_check_context(
        item.task_id, worker, stage="pre_private_read", now_us=1_210_000
    )
    with pytest.raises(AuthorizationIntegrityError, match="stale"):
        value.create_pdp_decision_evidence(
            private_context,
            dataclasses.replace(worker, nonce="wrong-claim"),
            external_result(private_context, checked_at_us=1_210_000),
        )
    assert value.heartbeat(
        item.task_id,
        item,
        worker,
        now_us=1_211_000,
        lease_expires_at_us=1_310_000,
    ).applied
    with pytest.raises(AuthorizationIntegrityError, match="stale"):
        value.create_pdp_decision_evidence(
            private_context,
            worker,
            external_result(private_context, checked_at_us=1_212_000),
        )

    value.close()
    replacement = new_store(root, active=False)
    lock = replacement.acquire_coordinator_lock()
    assert lock is not None
    assert replacement.acquire_coordinator(
        CoordinatorIdentity(owner_id="replacement", nonce="r" * 32),
        now_us=10_000_000,
        lease_expires_at_us=11_000_000,
        lock_session=lock,
    ) is not None
    with pytest.raises(CoordinatorFenceError):
        value.load_task_work_item(item.task_id, now_us=10_000_001)
    with pytest.raises(AuthorizationIntegrityError, match="stale"):
        replacement.create_pdp_decision_evidence(
            private_context,
            worker,
            external_result(private_context, checked_at_us=10_000_001),
        )


def test_external_result_is_exact_bounded_and_cannot_inject_authority(
    tmp_path: Path,
) -> None:
    class StringSubclass(str):
        pass

    class IntegerSubclass(int):
        pass

    with pytest.raises(TypeError):
        ExternalPdpDecisionResult(  # type: ignore[call-arg]
            context_id="context-id",
            pdp_call_id="call",
            decision="allow",
            checked_at_us=1,
            consistency="strongest",
            cache_used=False,
            binding_digest="injected",
        )
    with pytest.raises(ValueError, match="bounded string"):
        external_result(pdp_call_id="x" * 257)
    with pytest.raises(ValueError, match="bounded string"):
        external_result(pdp_call_id=StringSubclass("subclass"))
    with pytest.raises(ValueError, match="epoch microseconds"):
        external_result(checked_at_us=IntegerSubclass(1))

    value = new_store(tmp_path / "exact-inputs")
    pending_with_notification(value)
    with pytest.raises(ValueError, match="bounded string"):
        value.load_task_work_item(StringSubclass("task-001"), now_us=1_000_000)
    with pytest.raises(ValueError, match="between 1 and 500"):
        value.list_approved_task_work_items(now_us=1_000_000, limit=True)


def test_vocabulary_and_public_objects_are_payload_free(tmp_path: Path) -> None:
    value = new_store(tmp_path / "payload-free")
    pending_with_notification(value)
    sentinel = "PRIVATE-SENTINEL-DO-NOT-EXPOSE"
    objects = (
        value.load_task_work_item("task-001", now_us=1_000_000),
        value.load_notification_work_item("attempt-001", now_us=1_000_000),
    )
    assert sentinel not in repr(objects)
    with sqlite3.connect(value.db_path) as conn:
        dump = "\n".join(conn.iterdump())
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(authorization_pdp_evidence)")
        }
    assert sentinel not in dump
    assert "pdp_call_id_verifier" in columns
    source = "\n".join(
        Path(path).read_text()
        for path in (
            "gateway/authorization_contracts.py",
            "gateway/authorization_tasks.py",
            "gateway/authorization_transitions.py",
            "gateway/authorization_schema.py",
        )
    )
    forbidden = "consistency" + "_token"
    assert forbidden not in source
    doc = ExternalPdpDecisionResult.__doc__ or ""
    assert "generated by the host" in doc
    assert "audited outbound request mode" in doc
    assert "local client" in doc


def test_v4_pdp_rows_migrate_without_reinterpreting_old_opaque_evidence(
    tmp_path: Path,
) -> None:
    root = tmp_path / "v4-migration"
    value = new_store(root)
    value.close()
    old_column = "consistency" + "_token_verifier"
    with sqlite3.connect(value.db_path) as conn:
        conn.execute(
            "ALTER TABLE authorization_pdp_evidence "
            f"RENAME COLUMN pdp_call_id_verifier TO {old_column}"
        )
        conn.execute("PRAGMA user_version=4")

    migrated = new_store(root, active=False)
    with sqlite3.connect(migrated.db_path) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(authorization_pdp_evidence)")
        }
    assert version == SCHEMA_VERSION
    assert "pdp_call_id_verifier" in columns
    assert old_column not in columns
