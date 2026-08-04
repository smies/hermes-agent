"""Closed authorization-task transitions and external-PDP audit envelopes."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from typing import Optional

from gateway.authorization_contracts import (
    AuthorizationIntegrityError,
    AuthorizationTask,
    ClaimIdentity,
    CoordinatorIdentity,
    DeliveryAcceptanceEvidence,
    MAX_NOTIFICATION_RETRY_ORDINAL,
    MutationResult,
    NotificationMutationResult,
    NotificationAttemptSpec,
    OwnerDecision,
    PdpDecisionEvidence,
    TrustedAuthorizationBinding,
    _epoch_us,
)


class AuthorizationTaskTransitionMixin:
    def _resolution_spec_matches_decision(
        self,
        binding: TrustedAuthorizationBinding,
        decision: OwnerDecision,
        notification: NotificationAttemptSpec,
        *,
        decision_at_us: int,
        persisted_digest: Optional[str] = None,
    ) -> bool:
        basic = (
            isinstance(notification, NotificationAttemptSpec)
            and notification.kind == "approval_resolution"
            and notification.challenge_generation == decision.challenge_generation
            and notification.destination_profile == binding.approval_profile
            and notification.destination_account == binding.approval_account
            and notification.destination_chat == binding.approval_chat
            and notification.destination_thread == binding.approval_thread
            and notification.created_at_us == decision_at_us
        )
        if not basic:
            return False
        if persisted_digest is None:
            return True
        return hmac.compare_digest(
            persisted_digest,
            self._resolution_spec_digest(binding, notification),
        )

    def _resolution_spec_digest(
        self,
        binding: TrustedAuthorizationBinding,
        notification: NotificationAttemptSpec,
        *,
        retry_ordinal: int = 1,
        supersedes_attempt_id: Optional[str] = None,
    ) -> str:
        destination_digest = hmac.new(
            self._request_key,
            b"hermes-authorization-notification-destination-v1\0"
            + notification.destination_bytes(),
            hashlib.sha256,
        ).hexdigest()
        nonce_digest = self._challenge_nonce_digest(
            notification.challenge_nonce,
            task_id=binding.task_id,
            attempt_id=notification.attempt_id,
            challenge_generation=notification.challenge_generation,
        )
        return self._notification_spec_digest(
            {
                "attempt_id": notification.attempt_id,
                "task_id": binding.task_id,
                "correlation_id": binding.correlation_id,
                "kind": notification.kind,
                "challenge_generation": notification.challenge_generation,
                "destination_profile": notification.destination_profile,
                "destination_account": notification.destination_account,
                "destination_chat": notification.destination_chat,
                "destination_thread": notification.destination_thread,
                "destination_digest": destination_digest,
                "key_version": self._key_version,
                "created_at_us": notification.created_at_us,
                "due_at_us": notification.due_at_us,
                "challenge_nonce_digest": nonce_digest,
                "nonce_verifier_version": "v2",
                "retry_ordinal": retry_ordinal,
                "supersedes_attempt_id": supersedes_attempt_id,
            }
        )

    def _decision_audit_matches(
        self,
        conn: sqlite3.Connection,
        binding: TrustedAuthorizationBinding,
        decision: OwnerDecision,
        *,
        approved: bool,
        reason_code: str,
    ) -> Optional[int]:
        row = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE event_id=?",
            (
                f"task-{'approved' if approved else 'denied'}:"
                f"{decision.decision_id}",
            ),
        ).fetchone()
        if not self._audit_record_matches(row):
            return None
        expected = (
            binding.task_id,
            "task_approved" if approved else "task_denied",
            reason_code,
            self.audit_token("approval-user", decision.owner_user),
            self.audit_token("source-user", binding.source_user),
            self._key_version,
        )
        actual = (
            row["task_id"],
            row["kind"],
            row["reason_code"],
            row["actor_token"],
            row["target_token"],
            row["key_version"],
        )
        if actual != expected or not hmac.compare_digest(
            row["request_digest"],
            self._request_digest(
                conn.execute(
                    "SELECT scoped_request_key FROM authorization_tasks WHERE task_id=?",
                    (binding.task_id,),
                ).fetchone()[0],
                binding,
            ),
        ):
            return None
        return int(row["occurred_at_us"])

    def _resolution_notification_matches(
        self,
        conn: sqlite3.Connection,
        binding: TrustedAuthorizationBinding,
        decision: OwnerDecision,
        notification: NotificationAttemptSpec,
    ) -> bool:
        if (
            notification.kind != "approval_resolution"
            or notification.challenge_generation != decision.challenge_generation
        ):
            return False
        row = self._notification_with_task(conn, notification.attempt_id)
        if row is None:
            return False
        expected_nonce = self._challenge_nonce_digest(
            notification.challenge_nonce,
            task_id=binding.task_id,
            attempt_id=notification.attempt_id,
            challenge_generation=notification.challenge_generation,
            verifier_version=row["nonce_verifier_version"],
        )
        audit = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE event_id=?",
            (f"notification-created:{notification.attempt_id}",),
        ).fetchone()
        return (
            row["task_id"] == binding.task_id
            and row["kind"] == "approval_resolution"
            and row["challenge_generation"] == decision.challenge_generation
            and row["destination_profile"] == notification.destination_profile
            and row["destination_account"] == notification.destination_account
            and row["destination_chat"] == notification.destination_chat
            and row["destination_thread"] == notification.destination_thread
            and row["created_at_us"] == notification.created_at_us
            and row["due_at_us"] == notification.due_at_us
            and row["retry_ordinal"] == 1
            and row["supersedes_attempt_id"] is None
            and row["status"] in {"pending", "claimed", "provider_accepted"}
            and hmac.compare_digest(
                row["notification_spec_digest"],
                self._resolution_spec_digest(binding, notification),
            )
            and hmac.compare_digest(row["challenge_nonce_digest"], expected_nonce)
            and audit is not None
            and self._audit_record_matches(audit)
            and (
                audit["task_id"], audit["kind"], audit["reason_code"],
                audit["actor_token"], audit["target_token"],
                audit["request_digest"], audit["key_version"], audit["occurred_at_us"],
            ) == (
                binding.task_id, "notification_created", "approval_resolution",
                self.audit_token("host", "authorization-store"),
                self.audit_token("notification-destination", row["destination_digest"]),
                row["request_digest"], self._key_version, notification.created_at_us,
            )
        )

    @staticmethod
    def _decision_matches_binding(
        binding: TrustedAuthorizationBinding, decision: OwnerDecision
    ) -> bool:
        return (
            decision.owner_profile == binding.approval_profile
            and decision.task_id == binding.task_id
            and decision.correlation_id == binding.correlation_id
            and decision.owner_account == binding.approval_account
            and decision.owner_user == binding.approval_user
            and decision.owner_chat == binding.approval_chat
            and decision.owner_thread == binding.approval_thread
            and decision.provenance == "authenticated_reply"
        )

    def _challenge_matches(
        self,
        conn: sqlite3.Connection,
        binding: TrustedAuthorizationBinding,
        decision: OwnerDecision,
        decision_digest: str,
        *,
        allow_consumed: bool,
    ) -> Optional[sqlite3.Row]:
        row = self._notification_with_task(conn, decision.challenge_attempt_id)
        if row is None:
            return None
        expected_provider_verifier = self._provider_message_verifier(
            binding.task_id,
            decision.challenge_attempt_id,
            decision.challenge_generation,
            decision.challenge_provider_message_id,
        )
        expected_nonce = self._challenge_nonce_digest(
            decision.challenge_nonce,
            task_id=binding.task_id,
            attempt_id=decision.challenge_attempt_id,
            challenge_generation=decision.challenge_generation,
            verifier_version=row["nonce_verifier_version"],
        )
        consumed_ok = (
            allow_consumed
            and row["challenge_state"] == "consumed"
            and row["challenge_decision_digest"] == decision_digest
        )
        if (
            row["task_id"] != binding.task_id
            or row["correlation_id"] != binding.correlation_id
            or row["challenge_generation"] != decision.challenge_generation
            or row["kind"] != "approval_challenge"
            or row["status"] != "provider_accepted"
            or row["destination_profile"] != binding.approval_profile
            or row["destination_account"] != binding.approval_account
            or row["destination_chat"] != binding.approval_chat
            or row["destination_thread"] != binding.approval_thread
            or not hmac.compare_digest(
                row["challenge_nonce_digest"],
                expected_nonce,
            )
            or row["provider_message_verifier"] is None
            or not hmac.compare_digest(
                row["provider_message_verifier"], expected_provider_verifier
            )
            or row["provider_acceptance_status"] != "provider_accepted"
            or row["adapter_instance_id"] != decision.adapter_instance_id
            or row["account_binding_token"]
            != self._account_binding_token(decision.account_binding)
            or row["connection_epoch"] != decision.connection_epoch
            or decision.reply_to_provider_message_id
            != decision.challenge_provider_message_id
            or (row["challenge_state"] != "accepted" and not consumed_ok)
        ):
            return None
        return row

    def _resolve_challenge_generations(
        self,
        conn: sqlite3.Connection,
        binding: TrustedAuthorizationBinding,
        winning_attempt_id: str,
        decision_digest: str,
        now_us: int,
    ) -> None:
        attempts = conn.execute(
            "SELECT attempt_id FROM authorization_notification_attempts "
            "WHERE task_id=? AND kind='approval_challenge' ORDER BY challenge_generation",
            (binding.task_id,),
        ).fetchall()
        verified: list[sqlite3.Row] = []
        for attempt in attempts:
            row = self._notification_with_task(conn, attempt["attempt_id"])
            if row is None:
                raise ValueError("challenge generation failed integrity verification")
            verified.append(row)
        for row in verified:
            if row["challenge_state"] != "accepted":
                continue
            state = "consumed" if row["attempt_id"] == winning_attempt_id else "superseded"
            values = dict(row)
            values.update(
                {
                    "challenge_state": state,
                    "challenge_resolved_at_us": now_us,
                    "challenge_decision_digest": decision_digest,
                }
            )
            cursor = conn.execute(
                "UPDATE authorization_notification_attempts SET challenge_state=?,"
                "challenge_resolved_at_us=?,challenge_decision_digest=?,challenge_record_digest=?,"
                "version=version+1 WHERE attempt_id=? AND challenge_state='accepted' "
                "AND challenge_record_digest=?",
                (
                    state,
                    now_us,
                    decision_digest,
                    self._challenge_record_digest(values),
                    row["attempt_id"],
                    row["challenge_record_digest"],
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("challenge generation resolution lost its exact CAS")
            self._refresh_notification_state(conn, row["attempt_id"])

    def _validate_pdp_evidence(
        self,
        row: sqlite3.Row,
        binding: TrustedAuthorizationBinding,
        evidence: PdpDecisionEvidence,
        *,
        stage: str,
        now_us: int,
        claim: Optional[ClaimIdentity] = None,
        require_allow: bool = False,
    ) -> None:
        if type(evidence) is not PdpDecisionEvidence:
            raise TypeError("exact factory PDP evidence is required")
        if (
            not self._pdp_factory_seal_matches(evidence)
            or
            evidence.stage != stage
            or evidence.task_id != binding.task_id
            or evidence.request_digest != row["request_digest"]
            or evidence.binding_digest != row["binding_digest"]
            or evidence.key_version != row["key_version"]
            or evidence.model_identity != binding.model_identity
            or evidence.policy_revision != binding.policy_identity
            or evidence.checked_at_us != now_us
        ):
            raise ValueError("PDP evidence is stale or mismatched")
        if require_allow and evidence.decision != "allow":
            raise ValueError("positive PDP allow evidence is required")
        if evidence.decision == "allow" and (
            evidence.consistency != "strongest" or evidence.cache_used
        ):
            raise ValueError("PDP allow evidence is cached or weak")
        fence = self._fence
        if fence is None:
            raise ValueError("PDP evidence has no current coordinator binding")
        coordinator_owner, coordinator_nonce = self._coordinator_digests(
            CoordinatorIdentity(
                owner_id=evidence.coordinator_owner_id,
                nonce=evidence.coordinator_nonce,
            )
        )
        if (
            coordinator_owner != fence.owner_digest
            or coordinator_nonce != fence.nonce_digest
            or evidence.coordinator_epoch != fence.epoch
        ):
            raise ValueError("PDP evidence coordinator binding is stale")
        if claim is not None and (
            evidence.worker_profile != claim.owner_profile
            or evidence.worker_agent != claim.owner_agent
            or evidence.worker_account != claim.owner_account
            or evidence.claim_nonce != claim.nonce
            or evidence.claim_generation != claim.generation
        ):
            raise ValueError("PDP evidence worker claim binding is stale")

    def _insert_pdp_evidence(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        binding: TrustedAuthorizationBinding,
        evidence: PdpDecisionEvidence,
        claim: Optional[ClaimIdentity] = None,
        *,
        insert_audit: bool = True,
    ) -> bool:
        if type(evidence) is not PdpDecisionEvidence or not self._pdp_factory_seal_matches(
            evidence
        ):
            raise ValueError("exact factory PDP evidence is required")
        digest = self._pdp_evidence_digest(evidence)
        context_claim = claim or ClaimIdentity(
            owner_profile=evidence.worker_profile,
            owner_agent=evidence.worker_agent,
            owner_account=evidence.worker_account,
            nonce=evidence.claim_nonce,
            generation=evidence.claim_generation,
        )
        claim_owner_digest, claim_nonce_digest = self._claim_digests(context_claim)
        fence = self._fence
        if fence is None:
            raise ValueError("PDP evidence has no current coordinator binding")
        values = {
            "evidence_id": evidence.evidence_id,
            "task_id": binding.task_id,
            "stage": evidence.stage,
            "decision": evidence.decision,
            "request_digest": evidence.request_digest,
            "model_identity": evidence.model_identity,
            "policy_revision": evidence.policy_revision,
            "checked_at_us": evidence.checked_at_us,
            "consistency": evidence.consistency,
            "pdp_call_id_verifier": self.audit_token(
                "pdp-call-id", evidence.pdp_call_id
            ),
            "cache_used": int(evidence.cache_used),
            "evidence_digest": digest,
            "binding_digest": row["binding_digest"],
            "coordinator_owner_digest": fence.owner_digest,
            "coordinator_nonce_digest": fence.nonce_digest,
            "coordinator_epoch": fence.epoch,
            "claim_owner_digest": claim_owner_digest,
            "claim_nonce_digest": claim_nonce_digest,
            "claim_generation": context_claim.generation,
            "key_version": self._key_version,
        }
        values["context_record_digest"] = self._pdp_context_record_digest(values)
        existing = conn.execute(
            "SELECT * FROM authorization_pdp_evidence WHERE evidence_id=?",
            (evidence.evidence_id,),
        ).fetchone()
        if existing is not None:
            exact = (
                existing["task_id"] == binding.task_id
                and existing["evidence_digest"] == digest
                and existing["key_version"] == self._key_version
                and existing["context_record_digest"]
                == values["context_record_digest"]
            )
            if not exact:
                raise ValueError("PDP evidence identifier collision")
            return True
        conn.execute(
            "INSERT INTO authorization_pdp_evidence "
            "(evidence_id,task_id,stage,decision,request_digest,model_identity,policy_revision,"
            "checked_at_us,consistency,pdp_call_id_verifier,cache_used,evidence_digest,"
            "binding_digest,coordinator_owner_digest,coordinator_nonce_digest,coordinator_epoch,"
            "claim_owner_digest,claim_nonce_digest,claim_generation,context_record_digest,key_version) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                evidence.evidence_id,
                binding.task_id,
                evidence.stage,
                evidence.decision,
                evidence.request_digest,
                evidence.model_identity,
                evidence.policy_revision,
                evidence.checked_at_us,
                evidence.consistency,
                values["pdp_call_id_verifier"],
                int(evidence.cache_used),
                digest,
                row["binding_digest"],
                fence.owner_digest,
                fence.nonce_digest,
                fence.epoch,
                claim_owner_digest,
                claim_nonce_digest,
                context_claim.generation,
                values["context_record_digest"],
                self._key_version,
            ),
        )
        kind = {
            "allow": "pdp_check_allowed",
            "deny": "pdp_check_denied",
            "failure": "pdp_check_failed",
        }[evidence.decision]
        reason = {
            "allow": "policy_allowed",
            "deny": "policy_denied",
            "failure": "pdp_unavailable",
        }[evidence.decision]
        if insert_audit:
            self._audit_insert(
                conn,
                event_id=f"pdp-evidence:{evidence.evidence_id}",
                binding=binding,
                kind=kind,
                reason_code=reason,
                actor_scope="pdp",
                actor_value=binding.pdp_identity,
                target_scope="policy",
                target_value=binding.policy_identity,
                request_digest=row["request_digest"],
                at_us=evidence.checked_at_us,
            )
        return False

    def _has_current_pre_private_read_allow(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        binding: TrustedAuthorizationBinding,
        claim: ClaimIdentity,
        *,
        now_us: int,
    ) -> bool:
        if (
            not binding.has_delivery_acceptance_binding
            or not self._claim_matches(row, claim)
            or now_us >= row["claim_lease_expires_at_us"]
            or now_us >= row["expires_at_us"]
        ):
            return False
        fence = self._fence
        if fence is None:
            return False
        owner_digest, nonce_digest = self._claim_digests(claim)
        evidence_rows = conn.execute(
            "SELECT * FROM authorization_pdp_evidence WHERE task_id=? "
            "AND stage='pre_private_read' AND decision='allow' ORDER BY checked_at_us DESC",
            (binding.task_id,),
        ).fetchall()
        for evidence_row in evidence_rows:
            if (
                evidence_row["request_digest"] != row["request_digest"]
                or evidence_row["binding_digest"] != row["binding_digest"]
                or evidence_row["model_identity"] != binding.model_identity
                or evidence_row["policy_revision"] != binding.policy_identity
                or evidence_row["consistency"] != "strongest"
                or evidence_row["cache_used"] != 0
                or evidence_row["key_version"] != self._key_version
                or evidence_row["coordinator_owner_digest"] != fence.owner_digest
                or evidence_row["coordinator_nonce_digest"] != fence.nonce_digest
                or evidence_row["coordinator_epoch"] != fence.epoch
                or evidence_row["claim_owner_digest"] != owner_digest
                or evidence_row["claim_nonce_digest"] != nonce_digest
                or evidence_row["claim_generation"] != claim.generation
                or evidence_row["context_record_digest"] is None
                or not hmac.compare_digest(
                    evidence_row["context_record_digest"],
                    self._pdp_context_record_digest(evidence_row),
                )
            ):
                continue
            return True
        return False

    def _pdp_terminal_retry_matches(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        binding: TrustedAuthorizationBinding,
        claim: ClaimIdentity,
        evidence: PdpDecisionEvidence,
        *,
        now_us: int,
    ) -> bool:
        owner_digest, nonce_digest = self._claim_digests(claim)
        evidence_row = conn.execute(
            "SELECT * FROM authorization_pdp_evidence WHERE evidence_id=?",
            (evidence.evidence_id,),
        ).fetchone()
        terminal_audit = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE event_id=?",
            (f"task-pdp-failed:{evidence.evidence_id}",),
        ).fetchone()
        reason = "policy_denied" if evidence.decision == "deny" else "pdp_unavailable"
        if (
            row["status"] != "failed_consumed"
            or row["completed_at_us"] != now_us
            or row["receipt_code"] != "internal_failure"
            or row["claim_owner_digest"] != owner_digest
            or row["claim_nonce_digest"] != nonce_digest
            or row["claim_generation"] != claim.generation
            or now_us >= row["claim_lease_expires_at_us"]
            or now_us >= row["expires_at_us"]
            or evidence_row is None
            or evidence_row["evidence_digest"] != self._pdp_evidence_digest(evidence)
            or evidence_row["context_record_digest"] is None
            or not hmac.compare_digest(
                evidence_row["context_record_digest"],
                self._pdp_context_record_digest(evidence_row),
            )
            or terminal_audit is None
            or not self._audit_record_matches(terminal_audit)
        ):
            return False
        common = (row["request_digest"], self._key_version, now_us)
        return (
            terminal_audit["task_id"], terminal_audit["kind"], terminal_audit["reason_code"],
            terminal_audit["actor_token"], terminal_audit["target_token"],
            terminal_audit["request_digest"], terminal_audit["key_version"],
            terminal_audit["occurred_at_us"],
        ) == (
            binding.task_id, "task_failed_consumed", reason,
            self.audit_token("pdp", binding.pdp_identity),
            self.audit_token("task", binding.task_id), *common,
        )

    def _pre_claim_pdp_terminal_retry_matches(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        binding: TrustedAuthorizationBinding,
        evidence: PdpDecisionEvidence,
        *,
        now_us: int,
    ) -> bool:
        """Verify the exact durable deny/failure written by reject_from_pdp."""
        fence = self._fence
        context_claim = ClaimIdentity(
            owner_profile=evidence.worker_profile,
            owner_agent=evidence.worker_agent,
            owner_account=evidence.worker_account,
            nonce=evidence.claim_nonce,
            generation=evidence.claim_generation,
        )
        claim_owner_digest, claim_nonce_digest = self._claim_digests(context_claim)
        evidence_row = conn.execute(
            "SELECT * FROM authorization_pdp_evidence WHERE evidence_id=?",
            (evidence.evidence_id,),
        ).fetchone()
        evidence_audit = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE event_id=?",
            (f"pdp-evidence:{evidence.evidence_id}",),
        ).fetchone()
        terminal_audit = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE event_id=?",
            (f"task-pdp-denied:{evidence.evidence_id}",),
        ).fetchone()
        reason = "policy_denied" if evidence.decision == "deny" else "pdp_unavailable"
        evidence_kind = (
            "pdp_check_denied" if evidence.decision == "deny" else "pdp_check_failed"
        )
        if (
            fence is None
            or row["status"] != "denied"
            or row["completed_at_us"] != now_us
            or row["claim_owner_digest"] is not None
            or row["claim_nonce_digest"] is not None
            or row["claim_generation"] is not None
            or row["claim_lease_expires_at_us"] is not None
            or row["claimed_at_us"] is not None
            or row["heartbeat_at_us"] is not None
            or row["send_started_at_us"] is not None
            or row["receipt_code"] is not None
            or row["receipt_token"] is not None
            or row["delivery_acceptance_status"] is not None
            or row["delivery_accepted_at_us"] is not None
            or row["delivery_transport_implementation"] is not None
            or row["delivery_runtime_identity"] is not None
            or row["delivery_account_binding_token"] is not None
            or row["delivery_connection_epoch"] is not None
            or row["delivery_record_digest"] is not None
            or evidence_row is None
            or evidence_audit is None
            or terminal_audit is None
            or not self._audit_record_matches(evidence_audit)
            or not self._audit_record_matches(terminal_audit)
        ):
            return False
        expected_evidence_digest = self._pdp_evidence_digest(evidence)
        if (
            evidence_row["task_id"] != binding.task_id
            or evidence_row["stage"] != "pre_claim"
            or evidence_row["decision"] != evidence.decision
            or evidence_row["request_digest"] != row["request_digest"]
            or evidence_row["model_identity"] != binding.model_identity
            or evidence_row["policy_revision"] != binding.policy_identity
            or evidence_row["checked_at_us"] != now_us
            or evidence_row["consistency"] != evidence.consistency
            or evidence_row["pdp_call_id_verifier"]
            != self.audit_token("pdp-call-id", evidence.pdp_call_id)
            or evidence_row["cache_used"] != int(evidence.cache_used)
            or not hmac.compare_digest(
                evidence_row["evidence_digest"], expected_evidence_digest
            )
            or evidence_row["binding_digest"] != row["binding_digest"]
            or evidence_row["coordinator_owner_digest"] != fence.owner_digest
            or evidence_row["coordinator_nonce_digest"] != fence.nonce_digest
            or evidence_row["coordinator_epoch"] != fence.epoch
            or evidence_row["claim_owner_digest"] != claim_owner_digest
            or evidence_row["claim_nonce_digest"] != claim_nonce_digest
            or evidence_row["claim_generation"] != evidence.claim_generation
            or evidence_row["key_version"] != self._key_version
            or evidence_row["context_record_digest"] is None
            or not hmac.compare_digest(
                evidence_row["context_record_digest"],
                self._pdp_context_record_digest(evidence_row),
            )
        ):
            return False
        common = (row["request_digest"], self._key_version, now_us)
        return (
            evidence_audit["task_id"], evidence_audit["kind"],
            evidence_audit["reason_code"], evidence_audit["actor_token"],
            evidence_audit["target_token"], evidence_audit["request_digest"],
            evidence_audit["key_version"], evidence_audit["occurred_at_us"],
        ) == (
            binding.task_id, evidence_kind, reason,
            self.audit_token("pdp", binding.pdp_identity),
            self.audit_token("policy", binding.policy_identity), *common,
        ) and (
            terminal_audit["task_id"], terminal_audit["kind"],
            terminal_audit["reason_code"], terminal_audit["actor_token"],
            terminal_audit["target_token"], terminal_audit["request_digest"],
            terminal_audit["key_version"], terminal_audit["occurred_at_us"],
        ) == (
            binding.task_id, "task_denied", reason,
            self.audit_token("pdp", binding.pdp_identity),
            self.audit_token("task", binding.task_id), *common,
        )

    def record_pdp_evidence(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        claim: ClaimIdentity,
        evidence: PdpDecisionEvidence,
        *,
        now_us: int,
    ) -> MutationResult:
        """Record the consumer's second live check without interpreting policy."""
        _epoch_us(now_us, "now_us")
        if evidence.decision in {"deny", "failure"}:
            return self._close_private_read_from_pdp(
                task_id,
                binding,
                claim,
                evidence,
                now_us=now_us,
                expected_decision=evidence.decision,
            )

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            row = self._exact_row(conn, task_id, binding)
            if (
                row is None
                or not binding.has_delivery_acceptance_binding
                or not self._claim_matches(row, claim)
                or now_us >= row["claim_lease_expires_at_us"]
                or now_us >= row["expires_at_us"]
            ):
                return MutationResult(False)
            self._validate_pdp_evidence(
                row,
                binding,
                evidence,
                stage="pre_private_read",
                now_us=now_us,
                claim=claim,
            )
            idempotent = self._insert_pdp_evidence(
                conn, row, binding, evidence, claim
            )
            return MutationResult(True, idempotent, self._task(row))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]

    def authorize_private_read(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        claim: ClaimIdentity,
        evidence: PdpDecisionEvidence,
        *,
        now_us: int,
    ) -> MutationResult:
        """Authorize private access only with an exact live positive PDP allow."""
        _epoch_us(now_us, "now_us")

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            row = self._exact_row(conn, task_id, binding)
            if (
                row is None
                or not binding.has_delivery_acceptance_binding
                or not self._claim_matches(row, claim)
                or now_us >= row["claim_lease_expires_at_us"]
                or now_us >= row["expires_at_us"]
            ):
                return MutationResult(False)
            try:
                self._validate_pdp_evidence(
                    row,
                    binding,
                    evidence,
                    stage="pre_private_read",
                    now_us=now_us,
                    claim=claim,
                    require_allow=True,
                )
            except ValueError:
                return MutationResult(False)
            idempotent = self._insert_pdp_evidence(
                conn, row, binding, evidence, claim
            )
            return MutationResult(True, idempotent, self._task(row))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]

    def _close_private_read_from_pdp(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        claim: ClaimIdentity,
        evidence: PdpDecisionEvidence,
        *,
        now_us: int,
        expected_decision: str,
    ) -> MutationResult:
        _epoch_us(now_us, "now_us")
        if evidence.stage != "pre_private_read" or evidence.decision != expected_decision:
            raise ValueError(f"exact pre-private-read {expected_decision} evidence is required")

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            row = self._exact_row(conn, task_id, binding)
            if row is None or not binding.has_delivery_acceptance_binding:
                return MutationResult(False)
            try:
                self._validate_pdp_evidence(
                    row, binding, evidence, stage="pre_private_read",
                    now_us=now_us, claim=claim,
                )
            except ValueError:
                return MutationResult(False)
            if row["status"] == "failed_consumed":
                if self._pdp_terminal_retry_matches(
                    conn, row, binding, claim, evidence, now_us=now_us
                ):
                    return MutationResult(True, True, self._task(row))
                return MutationResult(False)
            if (
                not self._claim_matches(row, claim)
                or now_us >= row["claim_lease_expires_at_us"]
                or now_us >= row["expires_at_us"]
            ):
                return MutationResult(False)
            self._insert_pdp_evidence(
                conn, row, binding, evidence, claim, insert_audit=False
            )
            cursor = conn.execute(
                "UPDATE authorization_tasks SET status='failed_consumed',completed_at_us=?,"
                "receipt_code='internal_failure',version=version+1 WHERE task_id=? "
                "AND status='claimed' AND claim_owner_digest=? AND claim_nonce_digest=? "
                "AND claim_generation=? AND claim_lease_expires_at_us>? AND expires_at_us>?",
                (
                    now_us, task_id, row["claim_owner_digest"], row["claim_nonce_digest"],
                    claim.generation, now_us, now_us,
                ),
            )
            if cursor.rowcount != 1:
                return MutationResult(False)
            self._refresh_task_state(conn, task_id)
            reason = "policy_denied" if expected_decision == "deny" else "pdp_unavailable"
            self._audit_insert(
                conn,
                event_id=f"task-pdp-failed:{evidence.evidence_id}",
                binding=binding,
                kind="task_failed_consumed",
                reason_code=reason,
                actor_scope="pdp",
                actor_value=binding.pdp_identity,
                target_scope="task",
                target_value=task_id,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            updated = conn.execute(
                "SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            return MutationResult(True, False, self._task(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]

    def deny_private_read_from_pdp(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        claim: ClaimIdentity,
        evidence: PdpDecisionEvidence,
        *,
        now_us: int,
    ) -> MutationResult:
        """Durably close a claim on an exact pre-private-read PDP denial."""
        return self._close_private_read_from_pdp(
            task_id, binding, claim, evidence, now_us=now_us, expected_decision="deny"
        )

    def fail_private_read_from_pdp(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        claim: ClaimIdentity,
        evidence: PdpDecisionEvidence,
        *,
        now_us: int,
    ) -> MutationResult:
        """Durably close a claim on an exact pre-private-read PDP failure."""
        return self._close_private_read_from_pdp(
            task_id, binding, claim, evidence, now_us=now_us, expected_decision="failure"
        )

    def reject_from_pdp(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        evidence: PdpDecisionEvidence,
        *,
        now_us: int,
    ) -> MutationResult:
        """Record a pre-claim deny/failure and close the task fail closed."""
        _epoch_us(now_us, "now_us")
        if evidence.decision not in {"deny", "failure"}:
            raise ValueError("positive pre-claim evidence must be consumed by claim")

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            row = self._exact_row(conn, task_id, binding)
            if row is None:
                return MutationResult(False)
            if row["status"] == "denied":
                try:
                    self._validate_pdp_evidence(
                        row, binding, evidence, stage="pre_claim", now_us=now_us
                    )
                except ValueError:
                    return MutationResult(False)
                if self._pre_claim_pdp_terminal_retry_matches(
                    conn, row, binding, evidence, now_us=now_us
                ):
                    return MutationResult(True, True, self._task(row))
                return MutationResult(False)
            if row["status"] != "approved":
                return MutationResult(False)
            self._validate_pdp_evidence(
                row, binding, evidence, stage="pre_claim", now_us=now_us
            )
            self._insert_pdp_evidence(conn, row, binding, evidence)
            cursor = conn.execute(
                "UPDATE authorization_tasks SET status='denied',completed_at_us=?,version=version+1 "
                "WHERE task_id=? AND status='approved' AND binding_digest=?",
                (now_us, task_id, self._binding_digest(binding)),
            )
            if cursor.rowcount != 1:
                return MutationResult(False)
            self._refresh_task_state(conn, task_id)
            self._audit_insert(
                conn,
                event_id=f"task-pdp-denied:{evidence.evidence_id}",
                binding=binding,
                kind="task_denied",
                reason_code=(
                    "policy_denied" if evidence.decision == "deny" else "pdp_unavailable"
                ),
                actor_scope="pdp",
                actor_value=binding.pdp_identity,
                target_scope="task",
                target_value=task_id,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            updated = conn.execute(
                "SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            return MutationResult(True, False, self._task(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]
    def approve(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        decision: OwnerDecision,
        *,
        resolution_notification: NotificationAttemptSpec,
        now_us: int,
    ) -> MutationResult:
        _epoch_us(now_us, "now_us")
        if not isinstance(resolution_notification, NotificationAttemptSpec):
            raise TypeError("typed approval resolution notification is required")
        if not self._decision_matches_binding(binding, decision):
            return MutationResult(False)
        digest = self._decision_digest(decision)

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            row = self._exact_row(conn, task_id, binding)
            if row is None or not binding.has_delivery_acceptance_binding:
                return MutationResult(False)
            if (
                row["status"] == "approved"
                and row["decision_id"] == decision.decision_id
                and row["decision_digest"] == digest
                and row["winning_challenge_attempt_id"] == decision.challenge_attempt_id
                and row["winning_challenge_generation"] == decision.challenge_generation
            ):
                challenge = self._challenge_matches(
                    conn, binding, decision, digest, allow_consumed=True
                )
                decision_at_us = self._decision_audit_matches(
                    conn,
                    binding,
                    decision,
                    approved=True,
                    reason_code="owner_approved",
                )
                if challenge is None or decision_at_us is None:
                    return MutationResult(False)
                if (
                    challenge["challenge_resolved_at_us"] != decision_at_us
                    or not self._resolution_spec_matches_decision(
                        binding,
                        decision,
                        resolution_notification,
                        decision_at_us=decision_at_us,
                        persisted_digest=row["resolution_spec_digest"],
                    )
                ):
                    return MutationResult(False)
                if not self._resolution_notification_matches(
                    conn, binding, decision, resolution_notification
                ):
                    if row["resolution_spec_digest"] is None:
                        return MutationResult(False)
                    existing = conn.execute(
                        "SELECT 1 FROM authorization_notification_attempts "
                        "WHERE task_id=? AND kind='approval_resolution' "
                        "AND challenge_generation=?",
                        (task_id, decision.challenge_generation),
                    ).fetchone()
                    if existing is not None:
                        return MutationResult(False)
                    self._insert_notification(
                        conn, binding, resolution_notification, row["request_digest"]
                    )
                return MutationResult(True, True, self._task(row))
            if row["status"] != "approval_required" or now_us >= row["expires_at_us"]:
                return MutationResult(False)
            reused = conn.execute(
                "SELECT 1 FROM authorization_tasks WHERE decision_id=? AND task_id<>?",
                (decision.decision_id, task_id),
            ).fetchone()
            if reused:
                return MutationResult(False)
            challenge = self._challenge_matches(
                conn, binding, decision, digest, allow_consumed=False
            )
            if challenge is None:
                return MutationResult(False)
            if not self._resolution_spec_matches_decision(
                binding, decision, resolution_notification, decision_at_us=now_us
            ):
                return MutationResult(False)
            self._fault("transition.before")
            self._resolve_challenge_generations(
                conn, binding, decision.challenge_attempt_id, digest, now_us
            )
            cursor = conn.execute(
                "UPDATE authorization_tasks SET status='approved',decision_id=?,decision_digest=?,"
                "winning_challenge_attempt_id=?,winning_challenge_generation=?,"
                "resolution_spec_digest=?,version=version+1 "
                "WHERE task_id=? AND binding_digest=? AND status='approval_required' AND expires_at_us>?",
                (
                    decision.decision_id,
                    digest,
                    decision.challenge_attempt_id,
                    decision.challenge_generation,
                    self._resolution_spec_digest(binding, resolution_notification),
                    task_id,
                    self._binding_digest(binding),
                    now_us,
                ),
            )
            self._fault("transition.after")
            if cursor.rowcount != 1:
                return MutationResult(False)
            self._refresh_task_state(conn, task_id)
            self._audit_insert(
                conn,
                event_id=f"task-approved:{decision.decision_id}",
                binding=binding,
                kind="task_approved",
                reason_code="owner_approved",
                actor_scope="approval-user",
                actor_value=decision.owner_user,
                target_scope="source-user",
                target_value=binding.source_user,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            self._insert_notification(
                conn, binding, resolution_notification, row["request_digest"]
            )
            updated = conn.execute("SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)).fetchone()
            return MutationResult(True, False, self._task(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]

    def deny(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        decision: OwnerDecision,
        *,
        resolution_notification: NotificationAttemptSpec,
        now_us: int,
        reason_code: str,
    ) -> MutationResult:
        _epoch_us(now_us, "now_us")
        if not isinstance(resolution_notification, NotificationAttemptSpec):
            raise TypeError("typed approval resolution notification is required")
        if reason_code not in {"owner_rejected", "policy_denied"}:
            raise ValueError("unsupported denial reason code")
        if not self._decision_matches_binding(binding, decision):
            return MutationResult(False)
        digest = self._decision_digest(decision)

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            row = self._exact_row(conn, task_id, binding)
            if row is None or not binding.has_delivery_acceptance_binding:
                return MutationResult(False)
            if (
                row["status"] == "denied"
                and row["decision_id"] == decision.decision_id
                and row["decision_digest"] == digest
                and row["winning_challenge_attempt_id"] == decision.challenge_attempt_id
                and row["winning_challenge_generation"] == decision.challenge_generation
            ):
                challenge = self._challenge_matches(
                    conn, binding, decision, digest, allow_consumed=True
                )
                decision_at_us = self._decision_audit_matches(
                    conn,
                    binding,
                    decision,
                    approved=False,
                    reason_code=reason_code,
                )
                if challenge is None or decision_at_us is None:
                    return MutationResult(False)
                if (
                    challenge["challenge_resolved_at_us"] != decision_at_us
                    or not self._resolution_spec_matches_decision(
                        binding,
                        decision,
                        resolution_notification,
                        decision_at_us=decision_at_us,
                        persisted_digest=row["resolution_spec_digest"],
                    )
                ):
                    return MutationResult(False)
                if not self._resolution_notification_matches(
                    conn, binding, decision, resolution_notification
                ):
                    if row["resolution_spec_digest"] is None:
                        return MutationResult(False)
                    existing = conn.execute(
                        "SELECT 1 FROM authorization_notification_attempts "
                        "WHERE task_id=? AND kind='approval_resolution' "
                        "AND challenge_generation=?",
                        (task_id, decision.challenge_generation),
                    ).fetchone()
                    if existing is not None:
                        return MutationResult(False)
                    self._insert_notification(
                        conn, binding, resolution_notification, row["request_digest"]
                    )
                return MutationResult(True, True, self._task(row))
            if row["status"] != "approval_required" or now_us >= row["expires_at_us"]:
                return MutationResult(False)
            if conn.execute(
                "SELECT 1 FROM authorization_tasks WHERE decision_id=? AND task_id<>?",
                (decision.decision_id, task_id),
            ).fetchone():
                return MutationResult(False)
            challenge = self._challenge_matches(
                conn, binding, decision, digest, allow_consumed=False
            )
            if challenge is None:
                return MutationResult(False)
            if not self._resolution_spec_matches_decision(
                binding, decision, resolution_notification, decision_at_us=now_us
            ):
                return MutationResult(False)
            self._fault("transition.before")
            self._resolve_challenge_generations(
                conn, binding, decision.challenge_attempt_id, digest, now_us
            )
            cursor = conn.execute(
                "UPDATE authorization_tasks SET status='denied',decision_id=?,"
                "decision_digest=?,winning_challenge_attempt_id=?,winning_challenge_generation=?,"
                "resolution_spec_digest=?,completed_at_us=?,version=version+1 "
                "WHERE task_id=? AND binding_digest=? AND status='approval_required' AND expires_at_us>?",
                (
                    decision.decision_id,
                    digest,
                    decision.challenge_attempt_id,
                    decision.challenge_generation,
                    self._resolution_spec_digest(binding, resolution_notification),
                    now_us,
                    task_id,
                    self._binding_digest(binding),
                    now_us,
                ),
            )
            self._fault("transition.after")
            if cursor.rowcount != 1:
                return MutationResult(False)
            self._refresh_task_state(conn, task_id)
            self._audit_insert(
                conn,
                event_id=f"task-denied:{decision.decision_id}",
                binding=binding,
                kind="task_denied",
                reason_code=reason_code,
                actor_scope="approval-user",
                actor_value=decision.owner_user,
                target_scope="source-user",
                target_value=binding.source_user,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            self._insert_notification(
                conn, binding, resolution_notification, row["request_digest"]
            )
            updated = conn.execute("SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)).fetchone()
            return MutationResult(True, False, self._task(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]

    def retry_resolution_notification(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        decision: OwnerDecision,
        *,
        failed_attempt_id: str,
        replacement_notification: NotificationAttemptSpec,
        now_us: int,
    ) -> NotificationMutationResult:
        """Create one exact successor after a definitive pre-send failure."""
        _epoch_us(now_us, "now_us")
        if not isinstance(replacement_notification, NotificationAttemptSpec):
            raise TypeError("typed replacement resolution notification is required")
        if replacement_notification.created_at_us != now_us:
            raise ValueError("replacement resolution creation time must equal now")
        if not self._decision_matches_binding(binding, decision):
            return NotificationMutationResult(False)
        decision_digest = self._decision_digest(decision)

        def mutate(conn: sqlite3.Connection) -> NotificationMutationResult:
            task_row = self._exact_row(conn, task_id, binding)
            if (
                task_row is None
                or task_row["status"] not in {"approved", "denied"}
                or task_row["decision_id"] != decision.decision_id
                or task_row["decision_digest"] != decision_digest
                or task_row["winning_challenge_attempt_id"] != decision.challenge_attempt_id
                or task_row["winning_challenge_generation"] != decision.challenge_generation
                or task_row["resolution_spec_digest"] is None
            ):
                return NotificationMutationResult(False)
            challenge = self._challenge_matches(
                conn, binding, decision, decision_digest, allow_consumed=True
            )
            if challenge is None:
                return NotificationMutationResult(False)
            failed = self._notification_with_task(conn, failed_attempt_id)
            if (
                failed is None
                or failed["task_id"] != task_id
                or failed["kind"] != "approval_resolution"
                or failed["challenge_generation"] != decision.challenge_generation
                or failed["status"] != "failed"
                or failed["send_started_at_us"] is not None
                or failed["receipt_code"] not in {"provider_rejected", "internal_failure"}
                or failed["destination_profile"] != binding.approval_profile
                or failed["destination_account"] != binding.approval_account
                or failed["destination_chat"] != binding.approval_chat
                or failed["destination_thread"] != binding.approval_thread
            ):
                return NotificationMutationResult(False)
            if (
                type(failed["retry_ordinal"]) is not int
                or not 1
                <= failed["retry_ordinal"]
                <= MAX_NOTIFICATION_RETRY_ORDINAL
            ):
                return NotificationMutationResult(False)
            ordinal = failed["retry_ordinal"] + 1
            if ordinal > MAX_NOTIFICATION_RETRY_ORDINAL:
                return NotificationMutationResult(False)
            if (
                replacement_notification.kind != "approval_resolution"
                or replacement_notification.challenge_generation
                != decision.challenge_generation
                or replacement_notification.destination_profile != binding.approval_profile
                or replacement_notification.destination_account != binding.approval_account
                or replacement_notification.destination_chat != binding.approval_chat
                or replacement_notification.destination_thread != binding.approval_thread
            ):
                return NotificationMutationResult(False)
            existing = self._notification_with_task(
                conn, replacement_notification.attempt_id
            )
            replacement_digest = self._resolution_spec_digest(
                binding,
                replacement_notification,
                retry_ordinal=ordinal,
                supersedes_attempt_id=failed_attempt_id,
            )
            if existing is not None:
                audit = conn.execute(
                    "SELECT * FROM authorization_audit_events WHERE event_id=?",
                    (f"notification-created:{replacement_notification.attempt_id}",),
                ).fetchone()
                if (
                    existing["task_id"] == task_id
                    and existing["kind"] == "approval_resolution"
                    and existing["challenge_generation"] == decision.challenge_generation
                    and existing["retry_ordinal"] == ordinal
                    and existing["supersedes_attempt_id"] == failed_attempt_id
                    and hmac.compare_digest(
                        existing["notification_spec_digest"], replacement_digest
                    )
                    and existing["status"] in {"pending", "claimed", "provider_accepted"}
                    and audit is not None
                    and self._audit_record_matches(audit)
                    and (
                        audit["task_id"], audit["kind"], audit["reason_code"],
                        audit["actor_token"], audit["target_token"],
                        audit["request_digest"], audit["key_version"], audit["occurred_at_us"],
                    ) == (
                        task_id, "notification_created", "approval_resolution",
                        self.audit_token("host", "authorization-store"),
                        self.audit_token(
                            "notification-destination", existing["destination_digest"]
                        ),
                        task_row["request_digest"], self._key_version, now_us,
                    )
                ):
                    return NotificationMutationResult(
                        True, True, self._notification(existing)
                    )
                return NotificationMutationResult(False)
            if conn.execute(
                "SELECT 1 FROM authorization_notification_attempts WHERE task_id=? "
                "AND kind='approval_resolution' AND challenge_generation=? "
                "AND status IN ('pending','claimed','provider_accepted')",
                (task_id, decision.challenge_generation),
            ).fetchone() is not None:
                return NotificationMutationResult(False)
            self._insert_notification(
                conn,
                binding,
                replacement_notification,
                task_row["request_digest"],
                retry_ordinal=ordinal,
                supersedes_attempt_id=failed_attempt_id,
            )
            created = self._notification_with_task(
                conn, replacement_notification.attempt_id
            )
            if created is None or not hmac.compare_digest(
                created["notification_spec_digest"], replacement_digest
            ):
                raise ValueError("replacement resolution failed exact persistence")
            return NotificationMutationResult(True, False, self._notification(created))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]

    def cancel(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        *,
        now_us: int,
        reason_code: str,
    ) -> MutationResult:
        _epoch_us(now_us, "now_us")
        if reason_code not in {"request_canceled", "host_shutdown"}:
            raise ValueError("unsupported cancellation reason code")

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            row = self._exact_row(conn, task_id, binding)
            if (
                row is None
                or row["status"] not in {"approval_required", "approved"}
                or now_us >= row["expires_at_us"]
            ):
                return MutationResult(False)
            self._fault("transition.before")
            self._resolve_challenge_generations(
                conn,
                binding,
                "no-winning-challenge",
                f"terminal:canceled:{row['request_digest']}",
                now_us,
            )
            cursor = conn.execute(
                "UPDATE authorization_tasks SET status='canceled',completed_at_us=?,version=version+1 "
                "WHERE task_id=? AND binding_digest=? AND status IN ('approval_required','approved') "
                "AND expires_at_us>?",
                (now_us, task_id, self._binding_digest(binding), now_us),
            )
            self._fault("transition.after")
            if cursor.rowcount != 1:
                return MutationResult(False)
            self._refresh_task_state(conn, task_id)
            self._audit_insert(
                conn,
                event_id=f"task-canceled:{task_id}:{row['version'] + 1}",
                binding=binding,
                kind="task_canceled",
                reason_code=reason_code,
                actor_scope="requester-profile",
                actor_value=binding.requester_profile,
                target_scope="approval-user",
                target_value=binding.approval_user,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            updated = conn.execute("SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)).fetchone()
            return MutationResult(True, False, self._task(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]

    def expire_due(self, *, now_us: int, limit: int = 100) -> int:
        _epoch_us(now_us, "now_us")
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            rows = conn.execute(
                "SELECT * FROM authorization_tasks WHERE status IN ('approval_required','approved') "
                "AND expires_at_us<=? ORDER BY expires_at_us,task_id LIMIT ?",
                (now_us, limit),
            ).fetchall()
            count = 0
            for row in rows:
                try:
                    binding = self._binding_from_json(row["binding_json"])
                except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                    raise AuthorizationIntegrityError(
                        "authorization expiry scan failed integrity verification"
                    ) from None
                if self._exact_row(conn, row["task_id"], binding) is None:
                    raise AuthorizationIntegrityError(
                        "authorization expiry scan failed integrity verification"
                    )
                self._fault("transition.before")
                self._resolve_challenge_generations(
                    conn,
                    binding,
                    "no-winning-challenge",
                    f"terminal:expired:{row['request_digest']}",
                    now_us,
                )
                cursor = conn.execute(
                    "UPDATE authorization_tasks SET status='expired',completed_at_us=?,version=version+1 "
                    "WHERE task_id=? AND status IN ('approval_required','approved') AND expires_at_us<=?",
                    (now_us, row["task_id"], now_us),
                )
                self._fault("transition.after")
                if cursor.rowcount != 1:
                    continue
                self._refresh_task_state(conn, row["task_id"])
                count += 1
                self._audit_insert(
                    conn,
                    event_id=f"task-expired:{row['task_id']}:{row['version'] + 1}",
                    binding=binding,
                    kind="task_expired",
                    reason_code="approval_expired",
                    actor_scope="host",
                    actor_value="authorization-store",
                    target_scope="source-user",
                    target_value=binding.source_user,
                    request_digest=row["request_digest"],
                    at_us=now_us,
                )
            return MutationResult(True, False, AuthorizationTask("", "", "", "", count, 0, 0))

        result = self._write(mutate, at_us=now_us)
        assert result.task is not None
        return result.task.created_at_us

    def claim(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        claim: ClaimIdentity,
        *,
        now_us: int,
        lease_expires_at_us: int,
        pdp_evidence: PdpDecisionEvidence,
    ) -> MutationResult:
        """Consume one local execution opportunity after a live PDP check.

        The SQLite CAS supplies one-shot fencing only; it is not an
        authorization decision and cannot replace the external PDP evidence.
        """
        _epoch_us(now_us, "now_us")
        _epoch_us(lease_expires_at_us, "lease_expires_at_us")
        if lease_expires_at_us <= now_us:
            raise ValueError("claim lease must end after now")
        owner_digest, nonce_digest = self._claim_digests(claim)

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            row = self._exact_row(conn, task_id, binding)
            if row is None or not binding.has_delivery_acceptance_binding:
                return MutationResult(False)
            if row["status"] == "claimed":
                try:
                    self._validate_pdp_evidence(
                        row, binding, pdp_evidence, stage="pre_claim",
                        now_us=now_us, claim=claim, require_allow=True,
                    )
                except ValueError:
                    return MutationResult(False)
                evidence_row = conn.execute(
                    "SELECT * FROM authorization_pdp_evidence WHERE evidence_id=?",
                    (pdp_evidence.evidence_id,),
                ).fetchone()
                evidence_audit = conn.execute(
                    "SELECT * FROM authorization_audit_events WHERE event_id=?",
                    (f"pdp-evidence:{pdp_evidence.evidence_id}",),
                ).fetchone()
                claim_audit = conn.execute(
                    "SELECT * FROM authorization_audit_events WHERE event_id=?",
                    (f"task-claimed:{task_id}:{claim.generation}",),
                ).fetchone()
                if (
                    self._claim_matches(row, claim)
                    and row["claimed_at_us"] == now_us
                    and row["heartbeat_at_us"] == now_us
                    and row["claim_lease_expires_at_us"] == lease_expires_at_us
                    and now_us < row["expires_at_us"]
                    and evidence_row is not None
                    and evidence_row["evidence_digest"] == self._pdp_evidence_digest(pdp_evidence)
                    and evidence_row["context_record_digest"] is not None
                    and hmac.compare_digest(
                        evidence_row["context_record_digest"],
                        self._pdp_context_record_digest(evidence_row),
                    )
                    and evidence_audit is not None
                    and claim_audit is not None
                    and self._audit_record_matches(evidence_audit)
                    and self._audit_record_matches(claim_audit)
                    and (
                        evidence_audit["task_id"], evidence_audit["kind"],
                        evidence_audit["reason_code"], evidence_audit["actor_token"],
                        evidence_audit["target_token"], evidence_audit["request_digest"],
                        evidence_audit["key_version"], evidence_audit["occurred_at_us"],
                    ) == (
                        task_id, "pdp_check_allowed", "policy_allowed",
                        self.audit_token("pdp", binding.pdp_identity),
                        self.audit_token("policy", binding.policy_identity),
                        row["request_digest"], self._key_version, now_us,
                    )
                    and (
                        claim_audit["task_id"], claim_audit["kind"],
                        claim_audit["reason_code"], claim_audit["actor_token"],
                        claim_audit["target_token"], claim_audit["request_digest"],
                        claim_audit["key_version"], claim_audit["occurred_at_us"],
                    ) == (
                        task_id, "task_claimed", "claim_acquired",
                        self.audit_token("claim-owner", owner_digest),
                        self.audit_token("delivery-chat", binding.delivery_chat),
                        row["request_digest"], self._key_version, now_us,
                    )
                ):
                    return MutationResult(True, True, self._task(row))
                return MutationResult(False)
            if row["status"] != "approved" or now_us >= row["expires_at_us"] or claim.generation != 1:
                return MutationResult(False)
            self._validate_pdp_evidence(
                row,
                binding,
                pdp_evidence,
                stage="pre_claim",
                now_us=now_us,
                claim=claim,
            )
            if pdp_evidence.decision != "allow":
                return MutationResult(False)
            self._fault("transition.before")
            cursor = conn.execute(
                "UPDATE authorization_tasks SET status='claimed',claim_owner_digest=?,claim_nonce_digest=?,"
                "claim_generation=?,claim_lease_expires_at_us=?,claimed_at_us=?,heartbeat_at_us=?,version=version+1 "
                "WHERE task_id=? AND binding_digest=? AND status='approved' AND expires_at_us>?",
                (
                    owner_digest,
                    nonce_digest,
                    claim.generation,
                    lease_expires_at_us,
                    now_us,
                    now_us,
                    task_id,
                    self._binding_digest(binding),
                    now_us,
                ),
            )
            self._fault("transition.after")
            if cursor.rowcount != 1:
                return MutationResult(False)
            self._refresh_task_state(conn, task_id)
            self._insert_pdp_evidence(conn, row, binding, pdp_evidence, claim)
            self._audit_insert(
                conn,
                event_id=f"task-claimed:{task_id}:{claim.generation}",
                binding=binding,
                kind="task_claimed",
                reason_code="claim_acquired",
                actor_scope="claim-owner",
                actor_value=owner_digest,
                target_scope="delivery-chat",
                target_value=binding.delivery_chat,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            updated = conn.execute("SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)).fetchone()
            return MutationResult(True, False, self._task(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]

    def _claim_matches(self, row: sqlite3.Row, claim: ClaimIdentity) -> bool:
        owner_digest, nonce_digest = self._claim_digests(claim)
        return (
            row["status"] == "claimed"
            and row["claim_owner_digest"] == owner_digest
            and row["claim_nonce_digest"] == nonce_digest
            and row["claim_generation"] == claim.generation
        )

    def heartbeat(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        claim: ClaimIdentity,
        *,
        now_us: int,
        lease_expires_at_us: int,
    ) -> MutationResult:
        _epoch_us(now_us, "now_us")
        _epoch_us(lease_expires_at_us, "lease_expires_at_us")
        if lease_expires_at_us <= now_us:
            raise ValueError("claim lease must end after now")

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            row = self._exact_row(conn, task_id, binding)
            if (
                row is None
                or not binding.has_delivery_acceptance_binding
                or not self._claim_matches(row, claim)
                or now_us >= row["claim_lease_expires_at_us"]
            ):
                return MutationResult(False)
            audit = conn.execute(
                "SELECT * FROM authorization_audit_events WHERE event_id=?",
                (f"task-heartbeat:{task_id}:{claim.generation}:{now_us}",),
            ).fetchone()
            if audit is not None:
                if (
                    self._audit_record_matches(audit)
                    and
                    row["heartbeat_at_us"] == now_us
                    and row["claim_lease_expires_at_us"] == lease_expires_at_us
                    and (
                        audit["task_id"], audit["kind"], audit["reason_code"],
                        audit["actor_token"], audit["target_token"],
                        audit["request_digest"], audit["key_version"], audit["occurred_at_us"],
                    ) == (
                        task_id, "task_heartbeat", "claim_extended",
                        self.audit_token("claim-owner", row["claim_owner_digest"]),
                        self.audit_token("task", task_id), row["request_digest"],
                        self._key_version, now_us,
                    )
                ):
                    return MutationResult(True, True, self._task(row))
                return MutationResult(False)
            if lease_expires_at_us < row["claim_lease_expires_at_us"]:
                return MutationResult(False)
            self._fault("transition.before")
            cursor = conn.execute(
                "UPDATE authorization_tasks SET heartbeat_at_us=?,claim_lease_expires_at_us=?,version=version+1 "
                "WHERE task_id=? AND binding_digest=? AND status='claimed' AND claim_owner_digest=? "
                "AND claim_nonce_digest=? AND claim_generation=? AND claim_lease_expires_at_us>?",
                (
                    now_us,
                    lease_expires_at_us,
                    task_id,
                    self._binding_digest(binding),
                    row["claim_owner_digest"],
                    row["claim_nonce_digest"],
                    claim.generation,
                    now_us,
                ),
            )
            self._fault("transition.after")
            if cursor.rowcount != 1:
                return MutationResult(False)
            self._refresh_task_state(conn, task_id)
            self._audit_insert(
                conn,
                event_id=f"task-heartbeat:{task_id}:{claim.generation}:{now_us}",
                binding=binding,
                kind="task_heartbeat",
                reason_code="claim_extended",
                actor_scope="claim-owner",
                actor_value=row["claim_owner_digest"],
                target_scope="task",
                target_value=task_id,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            updated = conn.execute("SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)).fetchone()
            return MutationResult(True, False, self._task(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]

    def record_send_started(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        claim: ClaimIdentity,
        *,
        now_us: int,
    ) -> MutationResult:
        _epoch_us(now_us, "now_us")

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            row = self._exact_row(conn, task_id, binding)
            if row is None or not self._claim_matches(row, claim):
                return MutationResult(False)
            if (
                not binding.has_delivery_acceptance_binding
                or
                now_us >= row["claim_lease_expires_at_us"]
                or now_us >= row["expires_at_us"]
                or not self._has_current_pre_private_read_allow(
                    conn, row, binding, claim, now_us=now_us
                )
            ):
                return MutationResult(False)
            if row["send_started_at_us"] is not None:
                return MutationResult(True, True, self._task(row))
            self._fault("transition.before")
            cursor = conn.execute(
                "UPDATE authorization_tasks SET send_started_at_us=?,version=version+1 WHERE task_id=? "
                "AND binding_digest=? AND status='claimed' AND claim_owner_digest=? AND claim_nonce_digest=? "
                "AND claim_generation=? AND send_started_at_us IS NULL AND claim_lease_expires_at_us>? "
                "AND expires_at_us>?",
                (
                    now_us,
                    task_id,
                    self._binding_digest(binding),
                    row["claim_owner_digest"],
                    row["claim_nonce_digest"],
                    claim.generation,
                    now_us,
                    now_us,
                ),
            )
            self._fault("transition.after")
            if cursor.rowcount != 1:
                return MutationResult(False)
            self._refresh_task_state(conn, task_id)
            self._audit_insert(
                conn,
                event_id=f"send-started:{task_id}:{claim.generation}",
                binding=binding,
                kind="send_started",
                reason_code="provider_send_started",
                actor_scope="claim-owner",
                actor_value=row["claim_owner_digest"],
                target_scope="delivery-chat",
                target_value=binding.delivery_chat,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            updated = conn.execute("SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)).fetchone()
            return MutationResult(True, False, self._task(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]

    def _terminal_finish_matches(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        binding: TrustedAuthorizationBinding,
        claim: ClaimIdentity,
        *,
        now_us: int,
        outcome: str,
        receipt_code: str,
        receipt_token: Optional[str],
        evidence: Optional[DeliveryAcceptanceEvidence],
    ) -> bool:
        owner_digest, nonce_digest = self._claim_digests(claim)
        if (
            row["status"] != outcome
            or row["completed_at_us"] != now_us
            or row["receipt_code"] != receipt_code
            or row["claim_owner_digest"] != owner_digest
            or row["claim_nonce_digest"] != nonce_digest
            or row["claim_generation"] != claim.generation
        ):
            return False
        if outcome == "consumed":
            assert evidence is not None
            expected_receipt = self._delivery_provider_message_verifier(
                binding.task_id, claim.generation, evidence.provider_message_id
            )
            if (
                evidence.task_id != binding.task_id
                or evidence.correlation_id != binding.correlation_id
                or evidence.operation != binding.operation
                or evidence.request_digest != row["request_digest"]
                or evidence.request_key_version != row["key_version"]
                or evidence.policy_version != binding.policy_version
                or evidence.policy_hash != binding.policy_hash
                or evidence.worker_profile != claim.owner_profile
                or evidence.worker_agent != claim.owner_agent
                or evidence.worker_account != claim.owner_account
                or evidence.claim_nonce != claim.nonce
                or evidence.claim_generation != claim.generation
                or evidence.delivery_profile != binding.delivery_profile
                or evidence.delivery_platform != binding.delivery_platform
                or evidence.delivery_account != binding.delivery_account
                or evidence.delivery_chat != binding.delivery_chat
                or evidence.delivery_thread != binding.delivery_thread
                or evidence.transport_implementation
                != binding.delivery_transport_implementation
                or evidence.runtime_identity != binding.delivery_runtime_identity
                or evidence.account_binding != binding.delivery_account_binding
                or evidence.connection_epoch != binding.delivery_connection_epoch
                or row["send_started_at_us"] is None
                or evidence.accepted_at_us < row["send_started_at_us"]
                or evidence.accepted_at_us > now_us
                or row["receipt_token"] is None
                or not hmac.compare_digest(row["receipt_token"], expected_receipt)
                or row["delivery_acceptance_status"] != evidence.status
                or row["delivery_accepted_at_us"] != evidence.accepted_at_us
                or row["delivery_transport_implementation"]
                != evidence.transport_implementation
                or row["delivery_runtime_identity"] != evidence.runtime_identity
                or row["delivery_account_binding_token"]
                != self._account_binding_token(evidence.account_binding)
                or row["delivery_connection_epoch"] != evidence.connection_epoch
                or row["delivery_record_digest"] is None
                or not hmac.compare_digest(
                    row["delivery_record_digest"],
                    self._delivery_record_digest(row, binding),
                )
            ):
                return False
        elif (
            evidence is not None
            or row["receipt_token"] != receipt_token
            or any(
                row[name] is not None
                for name in (
                    "delivery_acceptance_status",
                    "delivery_accepted_at_us",
                    "delivery_transport_implementation",
                    "delivery_runtime_identity",
                    "delivery_account_binding_token",
                    "delivery_connection_epoch",
                    "delivery_record_digest",
                )
            )
        ):
            return False
        audit = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE event_id=?",
            (f"task-finished:{binding.task_id}:{claim.generation}",),
        ).fetchone()
        return self._audit_record_matches(audit) and (
            audit["task_id"],
            audit["kind"],
            audit["reason_code"],
            audit["actor_token"],
            audit["target_token"],
            audit["request_digest"],
            audit["key_version"],
            audit["occurred_at_us"],
        ) == (
            binding.task_id,
            "task_consumed" if outcome == "consumed" else "task_failed_consumed",
            receipt_code,
            self.audit_token("claim-owner", owner_digest),
            self.audit_token("delivery-chat", binding.delivery_chat),
            row["request_digest"],
            self._key_version,
            now_us,
        )

    def finish(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        claim: ClaimIdentity,
        *,
        now_us: int,
        outcome: str,
        receipt_code: str,
        provider_receipt_id: Optional[str] = None,
        evidence: Optional[DeliveryAcceptanceEvidence] = None,
    ) -> MutationResult:
        _epoch_us(now_us, "now_us")
        allowed_receipts = {
            "provider_accepted",
            "provider_rejected",
            "provider_timeout",
            "render_failed",
            "internal_failure",
            "ambiguous_after_restart",
        }
        if outcome not in {"consumed", "failed_consumed"}:
            raise ValueError("unsupported terminal outcome")
        if receipt_code not in allowed_receipts:
            raise ValueError("unsupported receipt code")
        if outcome == "consumed" and receipt_code != "provider_accepted":
            raise ValueError("consumed requires provider-accepted receipt")
        if outcome == "consumed":
            if not isinstance(evidence, DeliveryAcceptanceEvidence):
                raise TypeError("typed delivery acceptance evidence is required")
            if provider_receipt_id is not None:
                raise ValueError("consumed delivery identity must come from typed evidence")
        elif evidence is not None:
            raise ValueError("failed consumption cannot carry acceptance evidence")
        receipt_token = None
        if provider_receipt_id is not None:
            receipt_token = self.audit_token("provider-receipt", provider_receipt_id)

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            row = self._exact_row(conn, task_id, binding)
            if row is None or not binding.has_delivery_acceptance_binding:
                return MutationResult(False)
            if row["status"] in {"consumed", "failed_consumed"}:
                if self._terminal_finish_matches(
                    conn,
                    row,
                    binding,
                    claim,
                    now_us=now_us,
                    outcome=outcome,
                    receipt_code=receipt_code,
                    receipt_token=receipt_token,
                    evidence=evidence,
                ):
                    return MutationResult(True, True, self._task(row))
                return MutationResult(False)
            if not self._claim_matches(row, claim):
                return MutationResult(False)
            stored_receipt_token = receipt_token
            acceptance_values = {
                "delivery_acceptance_status": None,
                "delivery_accepted_at_us": None,
                "delivery_transport_implementation": None,
                "delivery_runtime_identity": None,
                "delivery_account_binding_token": None,
                "delivery_connection_epoch": None,
            }
            if outcome == "consumed":
                assert evidence is not None
                if (
                    row["send_started_at_us"] is None
                    or now_us >= row["claim_lease_expires_at_us"]
                    or now_us >= row["expires_at_us"]
                    or not self._has_current_pre_private_read_allow(
                        conn, row, binding, claim, now_us=now_us
                    )
                    or evidence.task_id != binding.task_id
                    or evidence.correlation_id != binding.correlation_id
                    or evidence.operation != binding.operation
                    or evidence.request_digest != row["request_digest"]
                    or evidence.request_key_version != self._key_version
                    or evidence.policy_version != binding.policy_version
                    or evidence.policy_hash != binding.policy_hash
                    or evidence.worker_profile != claim.owner_profile
                    or evidence.worker_agent != claim.owner_agent
                    or evidence.worker_account != claim.owner_account
                    or evidence.claim_nonce != claim.nonce
                    or evidence.claim_generation != claim.generation
                    or evidence.delivery_profile != binding.delivery_profile
                    or evidence.delivery_platform != binding.delivery_platform
                    or evidence.delivery_account != binding.delivery_account
                    or evidence.delivery_chat != binding.delivery_chat
                    or evidence.delivery_thread != binding.delivery_thread
                    or evidence.transport_implementation
                    != binding.delivery_transport_implementation
                    or evidence.runtime_identity != binding.delivery_runtime_identity
                    or evidence.account_binding != binding.delivery_account_binding
                    or evidence.connection_epoch != binding.delivery_connection_epoch
                    or evidence.accepted_at_us < row["send_started_at_us"]
                    or evidence.accepted_at_us > now_us
                ):
                    return MutationResult(False)
                stored_receipt_token = self._delivery_provider_message_verifier(
                    task_id, claim.generation, evidence.provider_message_id
                )
                acceptance_values = {
                    "delivery_acceptance_status": evidence.status,
                    "delivery_accepted_at_us": evidence.accepted_at_us,
                    "delivery_transport_implementation": evidence.transport_implementation,
                    "delivery_runtime_identity": evidence.runtime_identity,
                    "delivery_account_binding_token": self._account_binding_token(
                        evidence.account_binding
                    ),
                    "delivery_connection_epoch": evidence.connection_epoch,
                }
            updated_values = dict(row)
            updated_values.update(acceptance_values)
            updated_values["receipt_token"] = stored_receipt_token
            delivery_record_digest = (
                self._delivery_record_digest(updated_values, binding)
                if outcome == "consumed"
                else None
            )
            self._fault("transition.before")
            cursor = conn.execute(
                "UPDATE authorization_tasks SET status=?,completed_at_us=?,"
                "receipt_code=?,receipt_token=?,delivery_acceptance_status=?,"
                "delivery_accepted_at_us=?,delivery_transport_implementation=?,"
                "delivery_runtime_identity=?,delivery_account_binding_token=?,"
                "delivery_connection_epoch=?,delivery_record_digest=?,version=version+1 "
                "WHERE task_id=? AND binding_digest=? AND status='claimed' AND claim_owner_digest=? "
                "AND claim_nonce_digest=? AND claim_generation=?"
                + (
                    " AND claim_lease_expires_at_us>? AND expires_at_us>?"
                    if outcome == "consumed"
                    else ""
                ),
                (
                    outcome,
                    now_us,
                    receipt_code,
                    stored_receipt_token,
                    acceptance_values["delivery_acceptance_status"],
                    acceptance_values["delivery_accepted_at_us"],
                    acceptance_values["delivery_transport_implementation"],
                    acceptance_values["delivery_runtime_identity"],
                    acceptance_values["delivery_account_binding_token"],
                    acceptance_values["delivery_connection_epoch"],
                    delivery_record_digest,
                    task_id,
                    self._binding_digest(binding),
                    row["claim_owner_digest"],
                    row["claim_nonce_digest"],
                    claim.generation,
                    *((now_us, now_us) if outcome == "consumed" else ()),
                ),
            )
            self._fault("transition.after")
            if cursor.rowcount != 1:
                return MutationResult(False)
            self._refresh_task_state(conn, task_id)
            kind = "task_consumed" if outcome == "consumed" else "task_failed_consumed"
            self._audit_insert(
                conn,
                event_id=f"task-finished:{task_id}:{claim.generation}",
                binding=binding,
                kind=kind,
                reason_code=receipt_code,
                actor_scope="claim-owner",
                actor_value=row["claim_owner_digest"],
                target_scope="delivery-chat",
                target_value=binding.delivery_chat,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            updated = conn.execute("SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)).fetchone()
            return MutationResult(True, False, self._task(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]
