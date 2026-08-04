"""Notification-attempt mechanics for the durable authorization store."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from typing import Optional

from gateway.authorization_contracts import (
    AuthorizationIntegrityError,
    AuthorizationNotificationWorkItem,
    AuthorizationStoreError,
    ClaimIdentity,
    MAX_NOTIFICATION_CLAIM_GENERATIONS,
    NotificationAttempt,
    NotificationMutationResult,
    ProviderAcceptanceEvidence,
    _bounded,
    _epoch_us,
)


class AuthorizationNotificationStoreMixin:
    def _notification_task_allows_delivery(self, row: sqlite3.Row, now_us: int) -> bool:
        try:
            binding = self._binding_from_json(row["binding_json"])
        except (TypeError, ValueError, KeyError, json.JSONDecodeError):
            return False
        if not binding.has_delivery_acceptance_binding:
            return False
        if row["kind"] == "approval_challenge":
            return (
                row["task_status"] == "approval_required"
                and now_us < row["task_expires_at_us"]
            )
        return row["kind"] == "approval_resolution" and row["task_status"] in {
            "approved",
            "denied",
        }

    @staticmethod
    def _notification(row: sqlite3.Row) -> NotificationAttempt:
        return NotificationAttempt(
            attempt_id=row["attempt_id"],
            task_id=row["task_id"],
            kind=row["kind"],
            status=row["status"],
            created_at_us=row["created_at_us"],
            due_at_us=row["due_at_us"],
            version=row["version"],
            claim_generation=row["claim_generation"],
            claim_lease_expires_at_us=row["claim_lease_expires_at_us"],
            send_started_at_us=row["send_started_at_us"],
            completed_at_us=row["completed_at_us"],
            receipt_code=row["receipt_code"],
            challenge_generation=row["challenge_generation"],
            challenge_state=row["challenge_state"],
            provider_accepted_at_us=row["provider_accepted_at_us"],
            retry_ordinal=row["retry_ordinal"],
            supersedes_attempt_id=row["supersedes_attempt_id"],
        )

    def list_notifications(
        self, *, status: str, due_before_us: int, now_us: int, limit: int = 100
    ) -> list[NotificationAttempt]:
        _epoch_us(due_before_us, "due_before_us")
        _epoch_us(now_us, "now_us")
        if status not in {"pending", "claimed", "provider_accepted", "failed"}:
            raise ValueError("unsupported notification status")
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        conn = self._connect()
        try:
            conn.execute("BEGIN")
            self._require_live_fence(conn, now_us)
            rows = conn.execute(
                "SELECT * FROM authorization_notification_attempts WHERE status=? AND due_at_us<=? "
                "ORDER BY due_at_us,attempt_id LIMIT ?",
                (status, due_before_us, limit),
            ).fetchall()
            verified: list[NotificationAttempt] = []
            for row in rows:
                exact = self._notification_with_task(conn, row["attempt_id"])
                if exact is None:
                    raise AuthorizationIntegrityError(
                        "authorization notification list failed integrity verification"
                    )
                verified.append(self._notification(exact))
            return verified
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            conn.close()

    def _notification_work_item(
        self, row: sqlite3.Row
    ) -> AuthorizationNotificationWorkItem:
        binding = self._binding_from_json(row["binding_json"])
        return AuthorizationNotificationWorkItem(
            binding=binding,
            notification=self._notification(row),
            correlation_id=row["correlation_id"],
            request_digest=row["request_digest"],
            key_version=row["key_version"],
            binding_digest=row["task_binding_digest"],
            nonce_verifier_version=row["nonce_verifier_version"],
            destination_profile=row["destination_profile"],
            destination_account=row["destination_account"],
            destination_chat=row["destination_chat"],
            destination_thread=row["destination_thread"],
        )

    def load_notification_work_item(
        self, attempt_id: str, *, now_us: int
    ) -> AuthorizationNotificationWorkItem:
        """Load one authenticated notification view, distinguishing corruption."""
        _bounded(attempt_id, "attempt_id")
        _epoch_us(now_us, "now_us")
        conn = self._connect()
        try:
            conn.execute("BEGIN")
            self._require_live_fence(conn, now_us)
            present = conn.execute(
                "SELECT 1 FROM authorization_notification_attempts WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
            if present is None:
                raise KeyError("authorization notification not found")
            row = self._notification_with_task(conn, attempt_id)
            if row is None:
                raise AuthorizationIntegrityError(
                    "authorization notification failed integrity verification"
                )
            try:
                return self._notification_work_item(row)
            except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                raise AuthorizationIntegrityError(
                    "authorization notification failed integrity verification"
                ) from None
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            conn.close()

    def _list_notification_work_items(
        self, *, selector: str, now_us: int, limit: int
    ) -> list[AuthorizationNotificationWorkItem]:
        _epoch_us(now_us, "now_us")
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        if selector == "pending_due":
            where = "n.status='pending' AND n.due_at_us<=?"
            order = "n.due_at_us,n.attempt_id"
        elif selector == "stale_pre_send":
            where = (
                "n.status='claimed' AND n.send_started_at_us IS NULL "
                "AND n.claim_lease_expires_at_us<=? "
                "AND n.claim_generation<?"
            )
            order = "n.claim_lease_expires_at_us,n.attempt_id"
        else:
            raise ValueError("unsupported notification work selector")
        conn = self._connect()
        try:
            conn.execute("BEGIN")
            self._require_live_fence(conn, now_us)
            scan_budget = min(4_000, max(64, limit * 8))
            rows = conn.execute(
                "SELECT n.attempt_id FROM authorization_notification_attempts n "
                f"WHERE {where} "
                f"ORDER BY {order} LIMIT ?",
                (
                    (now_us, MAX_NOTIFICATION_CLAIM_GENERATIONS, scan_budget + 1)
                    if selector == "stale_pre_send"
                    else (now_us, scan_budget + 1)
                ),
            ).fetchall()
            work: list[AuthorizationNotificationWorkItem] = []
            for candidate in rows[:scan_budget]:
                row = self._notification_with_task(conn, candidate["attempt_id"])
                if row is None:
                    raise AuthorizationIntegrityError(
                        "authorization notification list failed integrity verification"
                    )
                if not self._notification_task_allows_delivery(row, now_us):
                    continue
                try:
                    work.append(self._notification_work_item(row))
                except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                    raise AuthorizationIntegrityError(
                        "authorization notification list failed integrity verification"
                    ) from None
                if len(work) == limit:
                    break
            if len(work) < limit and len(rows) > scan_budget:
                raise AuthorizationStoreError(
                    "authorization notification list exceeded bounded verification window"
                )
            return work
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            conn.close()

    def list_pending_due_notification_work_items(
        self, *, now_us: int, limit: int = 100
    ) -> list[AuthorizationNotificationWorkItem]:
        """List authenticated due pending notifications eligible for delivery."""
        return self._list_notification_work_items(
            selector="pending_due", now_us=now_us, limit=limit
        )

    def list_stale_pre_send_notification_work_items(
        self, *, now_us: int, limit: int = 100
    ) -> list[AuthorizationNotificationWorkItem]:
        """List authenticated expired notification claims before the send fence."""
        return self._list_notification_work_items(
            selector="stale_pre_send", now_us=now_us, limit=limit
        )



    def _notification_with_task(
        self, conn: sqlite3.Connection, attempt_id: str
    ) -> Optional[sqlite3.Row]:
        row = conn.execute(
            "SELECT n.*,t.binding_json,t.binding_digest AS task_binding_digest,"
            "t.request_digest,t.status AS task_status,"
            "t.expires_at_us AS task_expires_at_us,t.correlation_id AS task_correlation_id "
            "FROM authorization_notification_attempts n "
            "JOIN authorization_tasks t ON t.task_id=n.task_id WHERE n.attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if (
            row is None
            or not self._notification_state_matches(row)
            or type(row["attempt_id"]) is not str
            or type(row["task_id"]) is not str
            or type(row["correlation_id"]) is not str
            or type(row["kind"]) is not str
            or type(row["key_version"]) is not str
            or type(row["binding_json"]) is not str
            or type(row["request_digest"]) is not str
            or type(row["destination_profile"]) is not str
            or type(row["destination_account"]) is not str
            or type(row["destination_chat"]) is not str
            or type(row["destination_thread"]) is not str
            or type(row["destination_digest"]) is not str
            or type(row["notification_spec_digest"]) is not str
            or type(row["challenge_record_digest"]) is not str
            or type(row["challenge_nonce_digest"]) is not str
            or type(row["nonce_verifier_version"]) is not str
            or row["key_version"] != self._key_version
        ):
            return None
        try:
            binding = self._binding_from_json(row["binding_json"])
        except (TypeError, ValueError, KeyError, json.JSONDecodeError):
            return None
        if self._exact_row(conn, row["task_id"], binding) is None:
            return None
        if not self._notification_transition_audit_matches(conn, row):
            return None
        destination = json.dumps(
            {
                "account": row["destination_account"],
                "chat": row["destination_chat"],
                "profile": row["destination_profile"],
                "thread": row["destination_thread"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        expected = hmac.new(
            self._request_key,
            b"hermes-authorization-notification-destination-v1\0" + destination,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(row["destination_digest"], expected):
            return None
        if (
            row["correlation_id"] != binding.correlation_id
            or row["task_correlation_id"] != binding.correlation_id
            or row["kind"] not in {"approval_challenge", "approval_resolution"}
            or type(row["challenge_generation"]) is not int
            or row["challenge_generation"] < 1
            or row["destination_profile"] != binding.approval_profile
            or row["destination_account"] != binding.approval_account
            or row["destination_chat"] != binding.approval_chat
            or row["destination_thread"] != binding.approval_thread
            or not hmac.compare_digest(
                row["notification_spec_digest"],
                self._notification_spec_digest(row),
            )
            or not hmac.compare_digest(
                row["challenge_record_digest"],
                self._challenge_record_digest(row),
            )
        ):
            return None
        return row

    def claim_notification(
        self,
        attempt_id: str,
        claim: ClaimIdentity,
        *,
        now_us: int,
        lease_expires_at_us: int,
    ) -> NotificationMutationResult:
        _epoch_us(now_us, "now_us")
        _epoch_us(lease_expires_at_us, "lease_expires_at_us")
        if lease_expires_at_us <= now_us:
            raise ValueError("claim lease must end after now")
        owner_digest, nonce_digest = self._claim_digests(claim)

        def mutate(conn: sqlite3.Connection) -> NotificationMutationResult:
            row = self._notification_with_task(conn, attempt_id)
            if row is not None and row["status"] == "claimed":
                audit = conn.execute(
                    "SELECT * FROM authorization_audit_events WHERE event_id=?",
                    (f"notification-claimed:{attempt_id}:{claim.generation}",),
                ).fetchone()
                if (
                    self._notification_claim_matches(row, claim)
                    and self._notification_task_allows_delivery(row, now_us)
                    and row["claim_lease_expires_at_us"] == lease_expires_at_us
                    and audit is not None
                    and self._notification_audit_matches(
                        audit, row, claim, now_us=now_us,
                        kind="notification_claimed", reason_code="claim_acquired",
                    )
                ):
                    return NotificationMutationResult(True, True, self._notification(row))
                return NotificationMutationResult(False)
            if (
                row is None
                or row["status"] != "pending"
                or not self._notification_task_allows_delivery(row, now_us)
                or row["due_at_us"] > now_us
                or claim.generation != 1
                or claim.generation > MAX_NOTIFICATION_CLAIM_GENERATIONS
            ):
                return NotificationMutationResult(False)
            self._fault("notification.before")
            cursor = conn.execute(
                "UPDATE authorization_notification_attempts SET status='claimed',claim_owner_digest=?,"
                "claim_nonce_digest=?,claim_generation=?,claim_lease_expires_at_us=?,version=version+1 "
                "WHERE attempt_id=? AND status='pending' AND due_at_us<=?",
                (owner_digest, nonce_digest, claim.generation, lease_expires_at_us, attempt_id, now_us),
            )
            self._fault("notification.after")
            if cursor.rowcount != 1:
                return NotificationMutationResult(False)
            self._refresh_notification_state(conn, attempt_id)
            binding = self._binding_from_json(row["binding_json"])
            self._audit_insert(
                conn,
                event_id=f"notification-claimed:{attempt_id}:{claim.generation}",
                binding=binding,
                kind="notification_claimed",
                reason_code="claim_acquired",
                actor_scope="claim-owner",
                actor_value=owner_digest,
                target_scope="notification",
                target_value=attempt_id,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            updated = conn.execute(
                "SELECT * FROM authorization_notification_attempts WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            return NotificationMutationResult(True, False, self._notification(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]
    def take_over_stale_notification(
        self,
        attempt_id: str,
        claim: ClaimIdentity,
        *,
        now_us: int,
        lease_expires_at_us: int,
    ) -> NotificationMutationResult:
        _epoch_us(now_us, "now_us")
        _epoch_us(lease_expires_at_us, "lease_expires_at_us")
        if lease_expires_at_us <= now_us:
            raise ValueError("claim lease must end after now")
        owner_digest, nonce_digest = self._claim_digests(claim)

        def mutate(conn: sqlite3.Connection) -> NotificationMutationResult:
            row = self._notification_with_task(conn, attempt_id)
            if row is not None and row["status"] == "claimed" and self._notification_claim_matches(row, claim):
                audit = conn.execute(
                    "SELECT * FROM authorization_audit_events WHERE event_id=?",
                    (f"notification-reclaimed:{attempt_id}:{claim.generation}",),
                ).fetchone()
                if (
                    row["claim_lease_expires_at_us"] == lease_expires_at_us
                    and self._notification_task_allows_delivery(row, now_us)
                    and audit is not None
                    and self._notification_audit_matches(
                        audit, row, claim, now_us=now_us,
                        kind="notification_reclaimed", reason_code="stale_pre_send_claim",
                    )
                ):
                    return NotificationMutationResult(True, True, self._notification(row))
            if (
                row is None
                or row["status"] != "claimed"
                or row["send_started_at_us"] is not None
                or row["claim_lease_expires_at_us"] > now_us
                or not self._notification_task_allows_delivery(row, now_us)
                or claim.generation != row["claim_generation"] + 1
                or claim.generation > MAX_NOTIFICATION_CLAIM_GENERATIONS
            ):
                return NotificationMutationResult(False)
            self._fault("notification.before")
            cursor = conn.execute(
                "UPDATE authorization_notification_attempts SET claim_owner_digest=?,claim_nonce_digest=?,"
                "claim_generation=?,claim_lease_expires_at_us=?,version=version+1 WHERE attempt_id=? "
                "AND status='claimed' AND send_started_at_us IS NULL AND claim_generation=? "
                "AND claim_lease_expires_at_us<=?",
                (
                    owner_digest,
                    nonce_digest,
                    claim.generation,
                    lease_expires_at_us,
                    attempt_id,
                    claim.generation - 1,
                    now_us,
                ),
            )
            self._fault("notification.after")
            if cursor.rowcount != 1:
                return NotificationMutationResult(False)
            self._refresh_notification_state(conn, attempt_id)
            binding = self._binding_from_json(row["binding_json"])
            self._audit_insert(
                conn,
                event_id=f"notification-reclaimed:{attempt_id}:{claim.generation}",
                binding=binding,
                kind="notification_reclaimed",
                reason_code="stale_pre_send_claim",
                actor_scope="claim-owner",
                actor_value=owner_digest,
                target_scope="notification",
                target_value=attempt_id,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            updated = conn.execute(
                "SELECT * FROM authorization_notification_attempts "
                "WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
            return NotificationMutationResult(True, False, self._notification(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]

    def heartbeat_notification(
        self,
        attempt_id: str,
        claim: ClaimIdentity,
        *,
        now_us: int,
        lease_expires_at_us: int,
    ) -> NotificationMutationResult:
        _epoch_us(now_us, "now_us")
        _epoch_us(lease_expires_at_us, "lease_expires_at_us")
        if lease_expires_at_us <= now_us:
            raise ValueError("claim lease must end after now")

        def mutate(conn: sqlite3.Connection) -> NotificationMutationResult:
            row = self._notification_with_task(conn, attempt_id)
            if (
                row is None
                or not self._notification_claim_matches(row, claim)
                or now_us >= row["claim_lease_expires_at_us"]
                or not self._notification_task_allows_delivery(row, now_us)
            ):
                return NotificationMutationResult(False)
            audit = conn.execute(
                "SELECT * FROM authorization_audit_events WHERE event_id=?",
                (f"notification-heartbeat:{attempt_id}:{claim.generation}:{now_us}",),
            ).fetchone()
            if audit is not None:
                if (
                    row["claim_lease_expires_at_us"] == lease_expires_at_us
                    and self._notification_audit_matches(
                        audit, row, claim, now_us=now_us,
                        kind="notification_heartbeat", reason_code="claim_extended",
                    )
                ):
                    return NotificationMutationResult(True, True, self._notification(row))
                return NotificationMutationResult(False)
            if lease_expires_at_us < row["claim_lease_expires_at_us"]:
                return NotificationMutationResult(False)
            self._fault("notification.before")
            cursor = conn.execute(
                "UPDATE authorization_notification_attempts SET claim_lease_expires_at_us=?,version=version+1 "
                "WHERE attempt_id=? AND status='claimed' AND claim_owner_digest=? AND claim_nonce_digest=? "
                "AND claim_generation=? AND claim_lease_expires_at_us>?",
                (
                    lease_expires_at_us,
                    attempt_id,
                    row["claim_owner_digest"],
                    row["claim_nonce_digest"],
                    claim.generation,
                    now_us,
                ),
            )
            self._fault("notification.after")
            if cursor.rowcount != 1:
                return NotificationMutationResult(False)
            self._refresh_notification_state(conn, attempt_id)
            binding = self._binding_from_json(row["binding_json"])
            self._audit_insert(
                conn,
                event_id=f"notification-heartbeat:{attempt_id}:{claim.generation}:{now_us}",
                binding=binding,
                kind="notification_heartbeat",
                reason_code="claim_extended",
                actor_scope="claim-owner",
                actor_value=row["claim_owner_digest"],
                target_scope="notification",
                target_value=attempt_id,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            updated = conn.execute(
                "SELECT * FROM authorization_notification_attempts WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
            return NotificationMutationResult(True, False, self._notification(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]

    def _notification_claim_matches(self, row: sqlite3.Row, claim: ClaimIdentity) -> bool:
        owner_digest, nonce_digest = self._claim_digests(claim)
        return (
            row["status"] == "claimed"
            and row["claim_owner_digest"] == owner_digest
            and row["claim_nonce_digest"] == nonce_digest
            and row["claim_generation"] == claim.generation
        )

    def _notification_audit_matches(
        self,
        audit: sqlite3.Row,
        row: sqlite3.Row,
        claim: ClaimIdentity,
        *,
        now_us: int,
        kind: str,
        reason_code: str,
    ) -> bool:
        owner_digest, _ = self._claim_digests(claim)
        return self._audit_record_matches(audit) and (
            audit["task_id"], audit["kind"], audit["reason_code"],
            audit["actor_token"], audit["target_token"], audit["request_digest"],
            audit["key_version"], audit["occurred_at_us"],
        ) == (
            row["task_id"], kind, reason_code,
            self.audit_token("claim-owner", owner_digest),
            self.audit_token("notification", row["attempt_id"]),
            row["request_digest"], self._key_version, now_us,
        )

    def record_notification_send_started(
        self, attempt_id: str, claim: ClaimIdentity, *, now_us: int
    ) -> NotificationMutationResult:
        _epoch_us(now_us, "now_us")

        def mutate(conn: sqlite3.Connection) -> NotificationMutationResult:
            row = self._notification_with_task(conn, attempt_id)
            if row is None or not self._notification_claim_matches(row, claim):
                return NotificationMutationResult(False)
            if (
                now_us >= row["claim_lease_expires_at_us"]
                or not self._notification_task_allows_delivery(row, now_us)
            ):
                return NotificationMutationResult(False)
            if row["send_started_at_us"] is not None:
                return NotificationMutationResult(True, True, self._notification(row))
            self._fault("notification.before")
            cursor = conn.execute(
                "UPDATE authorization_notification_attempts SET send_started_at_us=?,version=version+1 "
                "WHERE attempt_id=? AND status='claimed' AND claim_owner_digest=? AND claim_nonce_digest=? "
                "AND claim_generation=? AND send_started_at_us IS NULL AND claim_lease_expires_at_us>?",
                (now_us, attempt_id, row["claim_owner_digest"], row["claim_nonce_digest"], claim.generation, now_us),
            )
            self._fault("notification.after")
            if cursor.rowcount != 1:
                return NotificationMutationResult(False)
            self._refresh_notification_state(conn, attempt_id)
            binding = self._binding_from_json(row["binding_json"])
            self._audit_insert(
                conn,
                event_id=f"notification-send-started:{attempt_id}:{claim.generation}",
                binding=binding,
                kind="notification_send_started",
                reason_code="provider_send_started",
                actor_scope="claim-owner",
                actor_value=row["claim_owner_digest"],
                target_scope="notification",
                target_value=attempt_id,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            updated = conn.execute(
                "SELECT * FROM authorization_notification_attempts "
                "WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
            return NotificationMutationResult(True, False, self._notification(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]

    def _terminal_notification_matches(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        claim: ClaimIdentity,
        *,
        now_us: int,
        outcome: str,
        receipt_code: str,
        evidence: Optional[ProviderAcceptanceEvidence],
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
        expected_state = "unaccepted"
        if outcome == "provider_accepted":
            assert evidence is not None
            expected_verifier = self._provider_message_verifier(
                row["task_id"],
                row["attempt_id"],
                row["challenge_generation"],
                evidence.provider_message_id,
            )
            expected_state = (
                "accepted" if row["kind"] == "approval_challenge" else "unaccepted"
            )
            if (
                evidence.task_id != row["task_id"]
                or evidence.correlation_id != row["correlation_id"]
                or evidence.attempt_id != row["attempt_id"]
                or evidence.challenge_generation != row["challenge_generation"]
                or evidence.worker_claim_generation != claim.generation
                or evidence.destination_profile != row["destination_profile"]
                or evidence.destination_account != row["destination_account"]
                or evidence.destination_chat != row["destination_chat"]
                or evidence.destination_thread != row["destination_thread"]
                or evidence.account_binding != row["destination_account"]
                or row["send_started_at_us"] is None
                or evidence.accepted_at_us < row["send_started_at_us"]
                or evidence.accepted_at_us > now_us
                or row["provider_message_verifier"] is None
                or not hmac.compare_digest(
                    row["provider_message_verifier"], expected_verifier
                )
                or row["provider_verifier_version"] != "v2"
                or row["provider_acceptance_status"] != evidence.status
                or row["provider_accepted_at_us"] != evidence.accepted_at_us
                or row["adapter_instance_id"] != evidence.adapter_instance_id
                or row["account_binding_token"]
                != self._account_binding_token(evidence.account_binding)
                or row["connection_epoch"] != evidence.connection_epoch
            ):
                return False
        elif evidence is not None or any(
            row[name] is not None
            for name in (
                "provider_message_verifier",
                "provider_verifier_version",
                "provider_acceptance_status",
                "provider_accepted_at_us",
                "adapter_instance_id",
                "account_binding_token",
                "connection_epoch",
            )
        ):
            return False
        if row["challenge_state"] != expected_state:
            return False
        binding = self._binding_from_json(row["binding_json"])
        audit = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE event_id=?",
            (f"notification-finished:{row['attempt_id']}:{claim.generation}",),
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
            row["task_id"],
            (
                "notification_provider_accepted"
                if outcome == "provider_accepted"
                else "notification_failed"
            ),
            receipt_code,
            self.audit_token("claim-owner", owner_digest),
            self.audit_token("notification", row["attempt_id"]),
            row["request_digest"],
            self._key_version,
            now_us,
        ) and binding.correlation_id == row["correlation_id"]

    def finish_notification(
        self,
        attempt_id: str,
        claim: ClaimIdentity,
        *,
        now_us: int,
        outcome: str,
        receipt_code: str,
        evidence: Optional[ProviderAcceptanceEvidence] = None,
    ) -> NotificationMutationResult:
        _epoch_us(now_us, "now_us")
        if outcome not in {"provider_accepted", "failed"}:
            raise ValueError("unsupported notification outcome")
        if receipt_code not in {
            "provider_accepted",
            "provider_rejected",
            "provider_timeout",
            "ambiguous_after_restart",
            "internal_failure",
        }:
            raise ValueError("unsupported notification receipt code")
        if outcome == "provider_accepted":
            if not isinstance(evidence, ProviderAcceptanceEvidence):
                raise TypeError("typed provider acceptance evidence is required")
            if receipt_code != "provider_accepted":
                raise ValueError("provider-accepted notification requires matching receipt code")
        elif evidence is not None:
            raise ValueError("failed notification cannot carry acceptance evidence")

        def mutate(conn: sqlite3.Connection) -> NotificationMutationResult:
            row = self._notification_with_task(conn, attempt_id)
            if row is None:
                return NotificationMutationResult(False)
            try:
                binding = self._binding_from_json(row["binding_json"])
            except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                return NotificationMutationResult(False)
            if not binding.has_delivery_acceptance_binding:
                return NotificationMutationResult(False)
            if row["status"] in {"provider_accepted", "failed"}:
                if self._terminal_notification_matches(
                    conn,
                    row,
                    claim,
                    now_us=now_us,
                    outcome=outcome,
                    receipt_code=receipt_code,
                    evidence=evidence,
                ):
                    return NotificationMutationResult(
                        True, True, self._notification(row)
                    )
                return NotificationMutationResult(False)
            if not self._notification_claim_matches(row, claim):
                return NotificationMutationResult(False)
            if outcome == "provider_accepted" and (
                not self._notification_task_allows_delivery(row, now_us)
            ):
                return NotificationMutationResult(False)
            if outcome == "provider_accepted" and row["send_started_at_us"] is None:
                return NotificationMutationResult(False)
            provider_verifier = None
            account_token = None
            challenge_state = "unaccepted"
            if evidence is not None:
                if (
                    evidence.task_id != row["task_id"]
                    or evidence.correlation_id != row["correlation_id"]
                    or evidence.attempt_id != row["attempt_id"]
                    or evidence.challenge_generation != row["challenge_generation"]
                    or evidence.worker_claim_generation != row["claim_generation"]
                    or evidence.destination_profile != row["destination_profile"]
                    or evidence.destination_account != row["destination_account"]
                    or evidence.destination_chat != row["destination_chat"]
                    or evidence.destination_thread != row["destination_thread"]
                    or evidence.account_binding != row["destination_account"]
                    or evidence.accepted_at_us < row["send_started_at_us"]
                    or evidence.accepted_at_us > now_us
                ):
                    return NotificationMutationResult(False)
                provider_verifier = self._provider_message_verifier(
                    row["task_id"],
                    row["attempt_id"],
                    row["challenge_generation"],
                    evidence.provider_message_id,
                )
                account_token = self._account_binding_token(evidence.account_binding)
                challenge_state = (
                    "accepted"
                    if row["kind"] == "approval_challenge"
                    else "unaccepted"
                )
            updated_values = dict(row)
            updated_values.update(
                {
                    "provider_message_verifier": provider_verifier,
                    "provider_verifier_version": "v2" if evidence is not None else None,
                    "provider_acceptance_status": evidence.status if evidence is not None else None,
                    "provider_accepted_at_us": evidence.accepted_at_us if evidence is not None else None,
                    "adapter_instance_id": evidence.adapter_instance_id if evidence is not None else None,
                    "account_binding_token": account_token,
                    "connection_epoch": evidence.connection_epoch if evidence is not None else None,
                    "challenge_state": challenge_state,
                }
            )
            self._fault("notification.before")
            cursor = conn.execute(
                "UPDATE authorization_notification_attempts SET status=?,completed_at_us=?,receipt_code=?,"
                "provider_message_verifier=?,provider_verifier_version=?,provider_acceptance_status=?,"
                "provider_accepted_at_us=?,adapter_instance_id=?,account_binding_token=?,connection_epoch=?,"
                "challenge_state=?,challenge_record_digest=?,version=version+1 "
                "WHERE attempt_id=? AND status='claimed' "
                "AND claim_owner_digest=? AND claim_nonce_digest=? AND claim_generation=?",
                (
                    outcome,
                    now_us,
                    receipt_code,
                    provider_verifier,
                    "v2" if evidence is not None else None,
                    evidence.status if evidence is not None else None,
                    evidence.accepted_at_us if evidence is not None else None,
                    evidence.adapter_instance_id if evidence is not None else None,
                    account_token,
                    evidence.connection_epoch if evidence is not None else None,
                    challenge_state,
                    self._challenge_record_digest(updated_values),
                    attempt_id,
                    row["claim_owner_digest"],
                    row["claim_nonce_digest"],
                    claim.generation,
                ),
            )
            self._fault("notification.after")
            if cursor.rowcount != 1:
                return NotificationMutationResult(False)
            self._refresh_notification_state(conn, attempt_id)
            self._audit_insert(
                conn,
                event_id=f"notification-finished:{attempt_id}:{claim.generation}",
                binding=binding,
                kind=(
                    "notification_provider_accepted"
                    if outcome == "provider_accepted"
                    else "notification_failed"
                ),
                reason_code=receipt_code,
                actor_scope="claim-owner",
                actor_value=row["claim_owner_digest"],
                target_scope="notification",
                target_value=attempt_id,
                request_digest=row["request_digest"],
                at_us=now_us,
            )
            updated = conn.execute(
                "SELECT * FROM authorization_notification_attempts "
                "WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
            return NotificationMutationResult(True, False, self._notification(updated))

        return self._write(mutate, at_us=now_us)  # type: ignore[return-value]
