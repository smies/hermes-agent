"""Durable, payload-free authorization task coordination.

This module is deliberately host-owned and profile-neutral.  Callers must pass
an absolute canonical database path selected from the gateway/host root; there
is no profile-derived default.  The database stores trusted routing bindings,
bounded state/receipt codes, and keyed digests, but never private result data,
message bodies, prompts, credentials, exceptions, or artifact paths.

Filesystem checks and owner-only modes are defense in depth, not a profile
security boundary. Profiles, terminals, installed Python plugins, and code
running under one OS uid can read or alter one another's files; installed
plugins and explicitly trusted owner profiles are therefore in the TCB. Any
deployment with adversarial same-uid terminal/file/code/MCP capability needs a
separate uid, sandbox, or service identity. Python's sqlite3 API also does not
expose SQLite's opened file descriptor, so pathname/inode rechecks cannot
eliminate malicious same-uid replacement races.

Audit rows are application-append-only by API convention and transactionally
paired with mutations. They are not tamper-evident against TCB code with DB
file access. Coordinator epochs fence stale writers, but callers must also
hold a verified owner-only OS lock capability for the coordinator session
lifetime.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import dataclasses
import os
import random
import secrets
import sqlite3
import stat
import time
from pathlib import Path
from typing import Callable, Optional


from gateway.authorization_contracts import (
    AuditEvent,
    AuthorizationIntegrityError,
    AuthorizationPdpCheckContext,
    AuthorizationStoreError,
    AuthorizationTask,
    AuthorizationTaskWorkItem,
    ClaimIdentity,
    CoordinatorFence,
    CoordinatorFenceError,
    CoordinatorIdentity,
    DeliveryAcceptanceEvidence,
    ExternalPdpDecisionResult,
    MAX_AUDIT_EVENTS_PER_TASK,
    MAX_NOTIFICATION_CLAIM_GENERATIONS,
    MAX_NOTIFICATION_RETRY_ORDINAL,
    MAX_RETRIES,
    MutationResult,
    NotificationAttemptSpec,
    OwnerDecision,
    PdpDecisionEvidence,
    ProviderAcceptanceEvidence,
    ReconciliationReport,
    SCHEMA_VERSION,
    TASK_TRANSITIONS,
    TrustedAuthorizationBinding,
    UnsafeAuthorizationStorePath,
    _bounded,
    _epoch_us,
)
from gateway.authorization_lock import AuthorizationCoordinatorLockSession
from gateway.authorization_notifications import AuthorizationNotificationStoreMixin
from gateway.authorization_schema import (
    _AUDIT_V2,
    _AUDIT_V4,
    _AUDIT_V7,
    _INDEXES_V2,
    _INDEXES_V4,
    _NOTIFICATIONS_V2,
    _NOTIFICATIONS_V3,
    _NOTIFICATIONS_V4,
    _PDP_V2,
    _PDP_V3,
    _PRIVATE_READ_MVP,
    _SCHEMA,
    _TASKS_V2,
    _TASKS_V4,
)
from gateway.authorization_transitions import AuthorizationTaskTransitionMixin
from hermes_state import apply_wal_with_fallback


_V1_ACCEPTANCE_CODE = "deliver" + "ed"
_V1_ACCEPTED_EVENT = "notification_" + "sent"

_TASK_STATE_COLUMNS = (
    "task_id", "correlation_id", "scoped_request_key", "binding_json",
    "binding_digest", "request_digest", "key_version", "status", "created_at_us",
    "expires_at_us", "decision_id", "decision_digest",
    "winning_challenge_attempt_id", "winning_challenge_generation",
    "claim_owner_digest", "claim_nonce_digest", "claim_generation",
    "claim_lease_expires_at_us", "claimed_at_us", "heartbeat_at_us",
    "send_started_at_us", "completed_at_us", "receipt_code", "receipt_token",
    "delivery_acceptance_status", "delivery_accepted_at_us",
    "delivery_transport_implementation", "delivery_runtime_identity",
    "delivery_account_binding_token", "delivery_connection_epoch",
    "delivery_record_digest", "resolution_spec_digest", "audit_event_count",
    "audit_head_digest", "version",
)

_TASK_STATE_COLUMNS_V6 = tuple(
    name for name in _TASK_STATE_COLUMNS
    if name not in {"audit_event_count", "audit_head_digest"}
)

_NOTIFICATION_STATE_COLUMNS = (
    "attempt_id", "task_id", "correlation_id", "kind", "challenge_generation",
    "destination_profile", "destination_account", "destination_chat",
    "destination_thread", "destination_digest", "key_version", "status",
    "created_at_us", "due_at_us", "claim_owner_digest", "claim_nonce_digest",
    "claim_generation", "claim_lease_expires_at_us", "send_started_at_us",
    "completed_at_us", "receipt_code", "challenge_nonce_digest",
    "nonce_verifier_version", "provider_message_verifier",
    "provider_verifier_version", "provider_acceptance_status",
    "provider_accepted_at_us", "adapter_instance_id", "account_binding_token",
    "connection_epoch", "challenge_state", "challenge_resolved_at_us",
    "challenge_decision_digest", "challenge_record_digest",
    "notification_spec_digest", "retry_ordinal", "supersedes_attempt_id", "version",
)

_AUDIT_RECORD_COLUMNS = (
    "event_id", "task_id", "kind", "reason_code", "actor_token", "target_token",
    "request_digest", "key_version", "occurred_at_us", "audit_sequence",
    "previous_record_digest",
)

_AUDIT_RECORD_COLUMNS_V6 = _AUDIT_RECORD_COLUMNS[:-2]


class AuthorizationTaskStore(
    AuthorizationTaskTransitionMixin, AuthorizationNotificationStoreMixin
):
    """SQLite source of truth for authorization tasks and notifications."""

    def __init__(
        self,
        *,
        db_path: Path,
        audit_hmac_key: bytes,
        request_hmac_key: bytes,
        key_version: str,
        journal_mode: str = "wal",
        coordinator_lock_path: Optional[Path] = None,
        _fault_hook: Optional[Callable[[str], None]] = None,
    ) -> None:
        if not isinstance(db_path, Path):
            db_path = Path(db_path)
        if not db_path.is_absolute():
            raise ValueError("authorization store path must be absolute")
        lexical = Path(os.path.abspath(os.fspath(db_path)))
        try:
            resolved = db_path.resolve(strict=False)
        except OSError as exc:
            raise UnsafeAuthorizationStorePath("authorization store path is unsafe") from exc
        if lexical != db_path or resolved != db_path:
            raise UnsafeAuthorizationStorePath(
                "authorization store path must be canonical and contain no symlinks"
            )
        if len(audit_hmac_key) < 16 or len(request_hmac_key) < 16:
            raise ValueError("HMAC keys must contain at least 16 bytes")
        _bounded(key_version, "key_version", maximum=64)
        if journal_mode not in {"wal", "delete"}:
            raise ValueError("journal_mode must be an already-resolved 'wal' or 'delete'")
        self.db_path = db_path
        self.journal_mode = journal_mode
        self.coordinator_lock_path = coordinator_lock_path or db_path.with_name(
            "authorization.coordinator.lock"
        )
        if not isinstance(self.coordinator_lock_path, Path):
            self.coordinator_lock_path = Path(self.coordinator_lock_path)
        if (
            not self.coordinator_lock_path.is_absolute()
            or Path(os.path.abspath(os.fspath(self.coordinator_lock_path)))
            != self.coordinator_lock_path
            or self.coordinator_lock_path.resolve(strict=False)
            != self.coordinator_lock_path
        ):
            raise ValueError("authorization coordinator lock path must be absolute and canonical")
        self._audit_key = bytes(audit_hmac_key)
        self._request_key = bytes(request_hmac_key)
        self._key_version = key_version
        self._fence: Optional[CoordinatorFence] = None
        self._coordinator_identity: Optional[CoordinatorIdentity] = None
        self._coordinator_lock: Optional[AuthorizationCoordinatorLockSession] = None
        self._lock_owner_token = object()
        self._fault_hook = _fault_hook
        self._prepare_secure_path()
        self._initialize()

    def _fault(self, step: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(step)

    @staticmethod
    def _uid() -> int:
        return os.getuid() if hasattr(os, "getuid") else 0

    def _validate_ancestor(self, path: Path) -> None:
        try:
            info = path.lstat()
        except OSError as exc:
            raise UnsafeAuthorizationStorePath("authorization store ancestor is unsafe") from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise UnsafeAuthorizationStorePath("authorization store ancestor is unsafe")
        if info.st_uid not in {0, self._uid()}:
            raise UnsafeAuthorizationStorePath("authorization store ancestor has unsafe ownership")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX):
            raise UnsafeAuthorizationStorePath("authorization store ancestor is writable by others")

    def _prepare_secure_path(self) -> None:
        # Authenticate every existing ancestor before creating anything.
        missing: list[Path] = []
        cursor = self.db_path.parent
        while not cursor.exists():
            missing.append(cursor)
            if cursor.parent == cursor:
                break
            cursor = cursor.parent
        chain = list(cursor.parents)[::-1] + [cursor]
        for ancestor in chain:
            self._validate_ancestor(ancestor)
        for directory in reversed(missing):
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
            self._validate_ancestor(directory)
            info = directory.lstat()
            if info.st_uid != self._uid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise UnsafeAuthorizationStorePath("authorization store directory is unsafe")

        parent_info = self.db_path.parent.lstat()
        if parent_info.st_uid != self._uid() or stat.S_IMODE(parent_info.st_mode) != 0o700:
            raise UnsafeAuthorizationStorePath("authorization store directory must be owner-only")

        try:
            info = self.db_path.lstat()
        except FileNotFoundError:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                fd = os.open(self.db_path, flags, 0o600)
            except FileExistsError:
                # A concurrent trusted initializer won O_EXCL. Authenticate
                # the resulting inode below rather than treating the race as
                # permission to create or chmod anything.
                pass
            except OSError as exc:
                raise UnsafeAuthorizationStorePath("authorization store file is unsafe") from exc
            else:
                os.close(fd)
            info = self.db_path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != self._uid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise UnsafeAuthorizationStorePath("authorization store file must be owner-only and regular")
        self._identity = (info.st_dev, info.st_ino)

    def _connect(self) -> sqlite3.Connection:
        before = self.db_path.lstat()
        if (before.st_dev, before.st_ino) != self._identity:
            raise UnsafeAuthorizationStorePath("authorization store file identity changed")
        conn = sqlite3.connect(
            self.db_path,
            isolation_level=None,
            timeout=1.0,
            check_same_thread=False,
        )
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=1000")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA secure_delete=ON")
            conn.execute("PRAGMA cell_size_check=ON")
            after = self.db_path.lstat()
            if (after.st_dev, after.st_ino) != self._identity:
                raise UnsafeAuthorizationStorePath("authorization store file identity changed")
            return conn
        except Exception:
            conn.close()
            raise

    @staticmethod
    def _locked(exc: sqlite3.OperationalError) -> bool:
        message = str(exc).lower()
        return "locked" in message or "busy" in message

    def _initialize(self) -> None:
        conn = self._connect()
        try:
            apply_wal_with_fallback(
                conn,
                db_label="authorization.db",
                journal_mode=self.journal_mode,
            )
            for attempt in range(MAX_RETRIES):
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
                    if version > SCHEMA_VERSION:
                        raise AuthorizationStoreError("authorization store schema is newer than supported")
                    if version == 0:
                        for statement in _SCHEMA.split(";"):
                            if statement.strip():
                                conn.execute(statement)
                        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                    elif version == 1:
                        self._migrate_v2(conn)
                        conn.execute("PRAGMA user_version=2")
                        version = 2
                    if version == 2:
                        self._migrate_v3(conn)
                        conn.execute("PRAGMA user_version=3")
                        version = 3
                    if version == 3:
                        self._migrate_v4(conn)
                        conn.execute("PRAGMA user_version=4")
                        version = 4
                    if version == 4:
                        self._migrate_v5(conn)
                        conn.execute("PRAGMA user_version=5")
                        version = 5
                    if version == 5:
                        try:
                            self._migrate_v6(conn)
                        except (
                            KeyError, IndexError, TypeError, ValueError, OverflowError,
                            UnicodeError,
                        ) as exc:
                            raise AuthorizationIntegrityError(
                                "authorization legacy state failed integrity migration"
                            ) from exc
                        conn.execute("PRAGMA user_version=6")
                        version = 6
                    if version == 6:
                        try:
                            self._migrate_v7(conn)
                        except (
                            KeyError, IndexError, TypeError, ValueError, OverflowError,
                            UnicodeError,
                        ) as exc:
                            raise AuthorizationIntegrityError(
                                "authorization legacy audit failed integrity migration"
                            ) from exc
                        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                    # Additive MVP storage deliberately shares this database
                    # without changing the high-assurance schema version.
                    # Upgrade checkpoint-era tables before installing the
                    # exact authenticated-event uniqueness index.
                    existing_mvp = conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' "
                        "AND name='private_read_mvp_requests'"
                    ).fetchone()
                    if existing_mvp is not None:
                        mvp_columns = {
                            row[1]
                            for row in conn.execute(
                                "PRAGMA table_info(private_read_mvp_requests)"
                            )
                        }
                        if "source_message" not in mvp_columns:
                            conn.execute(
                                "ALTER TABLE private_read_mvp_requests "
                                "ADD COLUMN source_message TEXT NOT NULL DEFAULT ''"
                            )
                        if "approval_chat" not in mvp_columns:
                            conn.execute(
                                "ALTER TABLE private_read_mvp_requests "
                                "ADD COLUMN approval_chat TEXT NOT NULL DEFAULT ''"
                            )
                    for statement in _PRIVATE_READ_MVP.split(";"):
                        if statement.strip():
                            conn.execute(statement)
                    conn.execute("COMMIT")
                    break
                except sqlite3.OperationalError as exc:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    if not self._locked(exc) or attempt == MAX_RETRIES - 1:
                        raise
                    time.sleep(random.uniform(0.005, 0.04))
        finally:
            conn.close()
        self._validate_sidecars()

    def _migrate_v2(self, conn: sqlite3.Connection) -> None:
        """Rebuild the WIP v1 tables into the authoritative v2 contracts.

        V1 provider-message-only rows are retained for forensics but become
        non-authoritative failures: typed adapter acceptance did not exist and
        cannot be inferred during migration. Existing task binding/request
        HMACs and application audit rows are copied unchanged.
        """
        notification_columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(authorization_notification_attempts)"
            )
        }
        if "challenge_record_digest" in notification_columns:
            pdp_exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='authorization_pdp_evidence'"
            ).fetchone()
            if pdp_exists is None:
                conn.execute(
                    _PDP_V2.format(table="authorization_pdp_evidence")
                )
            for statement in _INDEXES_V2.split(";"):
                if statement.strip():
                    conn.execute(statement)
            return

        conn.execute("ALTER TABLE authorization_tasks RENAME TO authorization_tasks_v1")
        conn.execute(
            "ALTER TABLE authorization_audit_events RENAME TO authorization_audit_events_v1"
        )
        conn.execute(
            "ALTER TABLE authorization_notification_attempts "
            "RENAME TO authorization_notification_attempts_v1"
        )
        conn.execute(_TASKS_V2.format(table="authorization_tasks"))
        conn.execute(_AUDIT_V2.format(table="authorization_audit_events"))
        conn.execute(
            _NOTIFICATIONS_V2.format(table="authorization_notification_attempts")
        )
        conn.execute(_PDP_V2.format(table="authorization_pdp_evidence"))

        task_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(authorization_tasks_v1)")
        }
        task_rows = conn.execute("SELECT * FROM authorization_tasks_v1").fetchall()
        task_by_id = {row["task_id"]: row for row in task_rows}
        for row in task_rows:
            key_version = row["key_version"] if "key_version" in task_columns else "unknown"
            receipt_code = row["receipt_code"]
            if receipt_code == _V1_ACCEPTANCE_CODE:
                receipt_code = "provider_accepted"
            conn.execute(
                "INSERT INTO authorization_tasks (task_id,correlation_id,scoped_request_key,"
                "binding_json,binding_digest,request_digest,key_version,status,created_at_us,"
                "expires_at_us,decision_id,decision_digest,claim_owner_digest,claim_nonce_digest,"
                "claim_generation,claim_lease_expires_at_us,claimed_at_us,heartbeat_at_us,"
                "send_started_at_us,completed_at_us,receipt_code,receipt_token,version) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    row["task_id"], row["correlation_id"], row["scoped_request_key"],
                    row["binding_json"], row["binding_digest"], row["request_digest"],
                    key_version, row["status"], row["created_at_us"], row["expires_at_us"],
                    row["decision_id"], row["decision_digest"], row["claim_owner_digest"],
                    row["claim_nonce_digest"], row["claim_generation"],
                    row["claim_lease_expires_at_us"], row["claimed_at_us"],
                    row["heartbeat_at_us"], row["send_started_at_us"],
                    row["completed_at_us"], receipt_code, row["receipt_token"], row["version"],
                ),
            )

        audit_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(authorization_audit_events_v1)")
        }
        for row in conn.execute("SELECT * FROM authorization_audit_events_v1"):
            kind = (
                "notification_provider_accepted"
                if row["kind"] == _V1_ACCEPTED_EVENT
                else row["kind"]
            )
            reason = (
                "provider_accepted"
                if row["reason_code"] == _V1_ACCEPTANCE_CODE
                else row["reason_code"]
            )
            key_version = row["key_version"] if "key_version" in audit_columns else "unknown"
            conn.execute(
                "INSERT INTO authorization_audit_events VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    row["event_id"], row["task_id"], kind, reason, row["actor_token"],
                    row["target_token"], row["request_digest"], key_version,
                    row["occurred_at_us"],
                ),
            )

        notification_columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(authorization_notification_attempts_v1)"
            )
        }
        generations: dict[str, int] = {}
        old_notifications = conn.execute(
            "SELECT * FROM authorization_notification_attempts_v1 "
            "ORDER BY task_id,created_at_us,attempt_id"
        ).fetchall()
        for row in old_notifications:
            task = task_by_id[row["task_id"]]
            generation = generations.get(row["task_id"], 0) + 1
            generations[row["task_id"]] = generation
            key_version = row["key_version"] if "key_version" in notification_columns else "unknown"
            provider_verifier = row["provider_message_token"]
            status = "failed" if row["status"] == "sent" else row["status"]
            receipt_code = row["receipt_code"]
            if row["status"] == "sent" or receipt_code == _V1_ACCEPTANCE_CODE:
                receipt_code = "ambiguous_after_restart"
            values = {
                "attempt_id": row["attempt_id"],
                "task_id": row["task_id"],
                "correlation_id": task["correlation_id"],
                "kind": row["kind"],
                "challenge_generation": generation,
                "destination_profile": row["destination_profile"],
                "destination_account": row["destination_account"],
                "destination_chat": row["destination_chat"],
                "destination_thread": row["destination_thread"],
                "destination_digest": row["destination_digest"],
                "key_version": key_version,
                "challenge_nonce_digest": row["challenge_nonce_digest"],
                "nonce_verifier_version": "v1",
                "provider_message_verifier": provider_verifier,
                "provider_verifier_version": "v1-audit" if provider_verifier else None,
                "provider_acceptance_status": None,
                "provider_accepted_at_us": None,
                "adapter_instance_id": None,
                "account_binding_token": None,
                "connection_epoch": None,
                "challenge_state": "unaccepted",
                "challenge_resolved_at_us": None,
                "challenge_decision_digest": None,
            }
            values["challenge_record_digest"] = self._challenge_record_digest(values)
            conn.execute(
                "INSERT INTO authorization_notification_attempts "
                "(attempt_id,task_id,correlation_id,kind,challenge_generation,destination_profile,"
                "destination_account,destination_chat,destination_thread,destination_digest,key_version,"
                "status,created_at_us,due_at_us,claim_owner_digest,claim_nonce_digest,claim_generation,"
                "claim_lease_expires_at_us,send_started_at_us,completed_at_us,receipt_code,"
                "challenge_nonce_digest,nonce_verifier_version,provider_message_verifier,"
                "provider_verifier_version,provider_acceptance_status,provider_accepted_at_us,"
                "adapter_instance_id,account_binding_token,connection_epoch,challenge_state,"
                "challenge_resolved_at_us,challenge_decision_digest,challenge_record_digest,version) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    row["attempt_id"], row["task_id"], task["correlation_id"], row["kind"],
                    generation, row["destination_profile"], row["destination_account"],
                    row["destination_chat"], row["destination_thread"], row["destination_digest"],
                    key_version, status, row["created_at_us"], row["due_at_us"],
                    row["claim_owner_digest"], row["claim_nonce_digest"], row["claim_generation"],
                    row["claim_lease_expires_at_us"], row["send_started_at_us"],
                    row["completed_at_us"], receipt_code, row["challenge_nonce_digest"], "v1",
                    provider_verifier, "v1-audit" if provider_verifier else None, None, None,
                    None, None, None, "unaccepted", None, None,
                    values["challenge_record_digest"], row["version"],
                ),
            )

        conn.execute("DROP TABLE authorization_audit_events_v1")
        conn.execute("DROP TABLE authorization_notification_attempts_v1")
        conn.execute("DROP TABLE authorization_tasks_v1")
        for statement in _INDEXES_V2.split(";"):
            if statement.strip():
                conn.execute(statement)

    def _migrate_v3(self, conn: sqlite3.Connection) -> None:
        """Migrate v2 evidence/notification contracts without reinterpreting them.

        Existing v2 PDP rows remain available for audit but have NULL binding
        context and therefore can never satisfy a v3 authorization check.
        Existing notification rows retain their exact signed records while the
        uniqueness boundary is widened to include notification kind.
        """
        task_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(authorization_tasks)")
        }
        if "delivery_record_digest" in task_columns:
            return
        for definition in (
            "delivery_acceptance_status TEXT CHECK (delivery_acceptance_status IS NULL OR delivery_acceptance_status='provider_accepted')",
            "delivery_accepted_at_us INTEGER",
            "delivery_transport_implementation TEXT",
            "delivery_runtime_identity TEXT",
            "delivery_account_binding_token TEXT",
            "delivery_connection_epoch INTEGER",
            "delivery_record_digest TEXT",
        ):
            conn.execute(f"ALTER TABLE authorization_tasks ADD COLUMN {definition}")

        conn.execute("DROP INDEX IF EXISTS idx_authorization_notifications_due")
        conn.execute("DROP INDEX IF EXISTS idx_authorization_provider_message")
        conn.execute(
            "ALTER TABLE authorization_notification_attempts "
            "RENAME TO authorization_notification_attempts_v2"
        )
        conn.execute(
            _NOTIFICATIONS_V3.format(table="authorization_notification_attempts")
        )
        notification_columns = (
            "attempt_id,task_id,correlation_id,kind,challenge_generation,"
            "destination_profile,destination_account,destination_chat,destination_thread,"
            "destination_digest,key_version,status,created_at_us,due_at_us,"
            "claim_owner_digest,claim_nonce_digest,claim_generation,claim_lease_expires_at_us,"
            "send_started_at_us,completed_at_us,receipt_code,challenge_nonce_digest,"
            "nonce_verifier_version,provider_message_verifier,provider_verifier_version,"
            "provider_acceptance_status,provider_accepted_at_us,adapter_instance_id,"
            "account_binding_token,connection_epoch,challenge_state,challenge_resolved_at_us,"
            "challenge_decision_digest,challenge_record_digest,version"
        )
        conn.execute(
            f"INSERT INTO authorization_notification_attempts ({notification_columns}) "
            f"SELECT {notification_columns} FROM authorization_notification_attempts_v2"
        )
        conn.execute("DROP TABLE authorization_notification_attempts_v2")

        pdp_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(authorization_pdp_evidence)")
        }
        for definition in (
            "binding_digest TEXT",
            "coordinator_owner_digest TEXT",
            "coordinator_nonce_digest TEXT",
            "coordinator_epoch INTEGER",
            "claim_owner_digest TEXT",
            "claim_nonce_digest TEXT",
            "claim_generation INTEGER",
            "context_record_digest TEXT",
        ):
            name = definition.split()[0]
            if name not in pdp_columns:
                conn.execute(
                    f"ALTER TABLE authorization_pdp_evidence ADD COLUMN {definition}"
                )
        for statement in _INDEXES_V2.split(";"):
            if statement.strip():
                conn.execute(statement)

    @staticmethod
    def _legacy_challenge_record_digest_v3(
        request_key: bytes, key_version: str, values: object
    ) -> str:
        fields = (
            "attempt_id", "task_id", "correlation_id", "kind",
            "challenge_generation", "destination_profile", "destination_account",
            "destination_chat", "destination_thread", "destination_digest", "key_version",
            "challenge_nonce_digest", "nonce_verifier_version",
            "provider_message_verifier", "provider_verifier_version",
            "provider_acceptance_status", "provider_accepted_at_us", "adapter_instance_id",
            "account_binding_token", "connection_epoch", "challenge_state",
            "challenge_resolved_at_us", "challenge_decision_digest",
        )

        def get(name: str) -> object:
            if isinstance(values, dict):
                return values.get(name)
            return values[name]  # type: ignore[index]

        canonical = json.dumps(
            {name: get(name) for name in fields},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return f"{key_version}:h2:" + hmac.new(
            request_key,
            b"hermes-authorization-challenge-record-v2\0" + canonical,
            hashlib.sha256,
        ).hexdigest()

    def _legacy_resolution_audit_matches(
        self,
        audits_by_id: dict[str, sqlite3.Row],
        task_row: sqlite3.Row,
        notification_row: sqlite3.Row,
    ) -> bool:
        audit = audits_by_id.get(
            f"notification-created:{notification_row['attempt_id']}"
        )
        return audit is not None and (
            audit["task_id"], audit["kind"], audit["reason_code"],
            audit["actor_token"], audit["target_token"], audit["request_digest"],
            audit["key_version"], audit["occurred_at_us"],
        ) == (
            task_row["task_id"], "notification_created", "approval_resolution",
            self.audit_token("host", "authorization-store"),
            self.audit_token(
                "notification-destination", notification_row["destination_digest"]
            ),
            task_row["request_digest"], self._key_version,
            notification_row["created_at_us"],
        )

    def _migrate_v4(self, conn: sqlite3.Connection) -> None:
        """Add exact notification contracts and terminalize unsafe legacy work.

        V1/v2 bindings cannot prove the delivery adapter, runtime, account,
        connection epoch, or policy version/hash.  Executable rows are closed
        without inventing that missing acceptance authority.  Existing terminal
        history is copied unchanged.
        """
        task_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(authorization_tasks)")
        }
        if "resolution_spec_digest" in task_columns:
            return

        migrated_at_us = int(time.time() * 1_000_000)
        old_tasks = conn.execute("SELECT * FROM authorization_tasks").fetchall()
        old_audits = conn.execute("SELECT * FROM authorization_audit_events").fetchall()
        old_notifications = conn.execute(
            "SELECT * FROM authorization_notification_attempts"
        ).fetchall()
        old_pdp = conn.execute("SELECT * FROM authorization_pdp_evidence").fetchall()
        audits_by_id = {row["event_id"]: row for row in old_audits}

        for index in (
            "idx_authorization_tasks_state_due", "idx_authorization_tasks_decision",
            "idx_authorization_tasks_receipt", "idx_authorization_audit_task_time",
            "idx_authorization_notifications_due", "idx_authorization_provider_message",
            "idx_authorization_pdp_task_stage",
        ):
            conn.execute(f"DROP INDEX IF EXISTS {index}")
        conn.execute(
            "ALTER TABLE authorization_notification_attempts "
            "RENAME TO authorization_notification_attempts_v3"
        )
        conn.execute(
            "ALTER TABLE authorization_pdp_evidence RENAME TO authorization_pdp_evidence_v3"
        )
        conn.execute(
            "ALTER TABLE authorization_audit_events RENAME TO authorization_audit_events_v3"
        )
        conn.execute("ALTER TABLE authorization_tasks RENAME TO authorization_tasks_v3")
        conn.execute(_TASKS_V4.format(table="authorization_tasks"))
        conn.execute(_AUDIT_V4.format(table="authorization_audit_events"))
        conn.execute(
            _NOTIFICATIONS_V4.format(table="authorization_notification_attempts")
        )
        conn.execute(_PDP_V3.format(table="authorization_pdp_evidence"))

        migrated_tasks: dict[str, tuple[sqlite3.Row, TrustedAuthorizationBinding, bool]] = {}
        resolution_digests: dict[str, str] = {}
        notifications_by_task: dict[str, list[sqlite3.Row]] = {}
        for notification_row in old_notifications:
            notifications_by_task.setdefault(notification_row["task_id"], []).append(
                notification_row
            )
        for row in old_tasks:
            try:
                binding = self._binding_from_json(row["binding_json"])
            except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                # An unauthentic binding remains historical and non-executable.
                binding = None
            complete = bool(binding and binding.has_delivery_acceptance_binding)
            status = row["status"]
            completed_at_us = row["completed_at_us"]
            receipt_code = row["receipt_code"]
            if not complete and status in {"approval_required", "approved"}:
                status = "denied"
                completed_at_us = migrated_at_us
                receipt_code = "incomplete_delivery_binding"
            elif not complete and status == "claimed":
                status = "failed_consumed"
                completed_at_us = migrated_at_us
                receipt_code = (
                    "ambiguous_after_restart"
                    if row["send_started_at_us"] is not None
                    else "incomplete_delivery_binding"
                )

            if binding is not None and row["decision_id"] is not None:
                decision_audit = audits_by_id.get(
                    f"task-{'approved' if row['status'] == 'approved' else 'denied'}:"
                    f"{row['decision_id']}"
                )
                candidates = [
                    item for item in notifications_by_task.get(row["task_id"], [])
                    if item["kind"] == "approval_resolution"
                    and item["challenge_generation"] == row["winning_challenge_generation"]
                    and item["correlation_id"] == binding.correlation_id
                    and item["destination_profile"] == binding.approval_profile
                    and item["destination_account"] == binding.approval_account
                    and item["destination_chat"] == binding.approval_chat
                    and item["destination_thread"] == binding.approval_thread
                    and decision_audit is not None
                    and item["created_at_us"] == decision_audit["occurred_at_us"]
                    and self._legacy_resolution_audit_matches(
                        audits_by_id, row, item
                    )
                    and hmac.compare_digest(
                        item["challenge_record_digest"],
                        self._legacy_challenge_record_digest_v3(
                            self._request_key, self._key_version, item
                        ),
                    )
                ]
                if len(candidates) == 1:
                    values = dict(candidates[0])
                    values.update({"retry_ordinal": 1, "supersedes_attempt_id": None})
                    resolution_digests[row["task_id"]] = self._notification_spec_digest(values)

            columns = (
                "task_id,correlation_id,scoped_request_key,binding_json,binding_digest,"
                "request_digest,key_version,status,created_at_us,expires_at_us,decision_id,"
                "decision_digest,winning_challenge_attempt_id,winning_challenge_generation,"
                "claim_owner_digest,claim_nonce_digest,claim_generation,claim_lease_expires_at_us,"
                "claimed_at_us,heartbeat_at_us,send_started_at_us,completed_at_us,receipt_code,"
                "receipt_token,delivery_acceptance_status,delivery_accepted_at_us,"
                "delivery_transport_implementation,delivery_runtime_identity,"
                "delivery_account_binding_token,delivery_connection_epoch,delivery_record_digest,"
                "resolution_spec_digest,version"
            )
            conn.execute(
                f"INSERT INTO authorization_tasks ({columns}) VALUES ({','.join('?' for _ in range(33))})",
                (
                    row["task_id"], row["correlation_id"], row["scoped_request_key"],
                    row["binding_json"], row["binding_digest"], row["request_digest"],
                    row["key_version"], status, row["created_at_us"], row["expires_at_us"],
                    row["decision_id"], row["decision_digest"],
                    row["winning_challenge_attempt_id"], row["winning_challenge_generation"],
                    row["claim_owner_digest"], row["claim_nonce_digest"], row["claim_generation"],
                    row["claim_lease_expires_at_us"], row["claimed_at_us"], row["heartbeat_at_us"],
                    row["send_started_at_us"], completed_at_us, receipt_code, row["receipt_token"],
                    row["delivery_acceptance_status"], row["delivery_accepted_at_us"],
                    row["delivery_transport_implementation"], row["delivery_runtime_identity"],
                    row["delivery_account_binding_token"], row["delivery_connection_epoch"],
                    row["delivery_record_digest"], resolution_digests.get(row["task_id"]),
                    row["version"] + (1 if status != row["status"] else 0),
                ),
            )
            if binding is not None:
                migrated_tasks[row["task_id"]] = (row, binding, complete)

        for row in old_audits:
            conn.execute(
                "INSERT INTO authorization_audit_events VALUES (?,?,?,?,?,?,?,?,?)",
                tuple(row),
            )

        for row in old_notifications:
            task_info = migrated_tasks.get(row["task_id"])
            complete = bool(task_info and task_info[2])
            status = row["status"]
            completed_at_us = row["completed_at_us"]
            receipt_code = row["receipt_code"]
            if not complete and status in {"pending", "claimed"}:
                status = "failed"
                completed_at_us = migrated_at_us
                receipt_code = (
                    "ambiguous_after_restart"
                    if row["send_started_at_us"] is not None
                    else "incomplete_delivery_binding"
                )
            values = dict(row)
            values.update(
                {
                    "status": status,
                    "completed_at_us": completed_at_us,
                    "receipt_code": receipt_code,
                    "retry_ordinal": 1,
                    "supersedes_attempt_id": None,
                }
            )
            values["notification_spec_digest"] = self._notification_spec_digest(values)
            values["challenge_record_digest"] = self._challenge_record_digest(values)
            columns = [
                item[1]
                for item in conn.execute(
                    "PRAGMA table_info(authorization_notification_attempts)"
                )
            ]
            conn.execute(
                f"INSERT INTO authorization_notification_attempts ({','.join(columns)}) "
                f"VALUES ({','.join('?' for _ in columns)})",
                tuple(values.get(name) for name in columns),
            )
            if status != row["status"] and task_info is not None:
                _, binding, _ = task_info
                self._audit_insert(
                    conn,
                    event_id=f"notification-migrated-v4:{row['attempt_id']}",
                    binding=binding,
                    kind="notification_failed",
                    reason_code=receipt_code,
                    actor_scope="host",
                    actor_value="authorization-store-migration-v4",
                    target_scope="notification",
                    target_value=row["attempt_id"],
                    request_digest=task_info[0]["request_digest"],
                    at_us=migrated_at_us,
                )

        pdp_columns = [
            item[1] for item in conn.execute("PRAGMA table_info(authorization_pdp_evidence)")
        ]
        old_pdp_columns = [
            item[1]
            for item in conn.execute("PRAGMA table_info(authorization_pdp_evidence_v3)")
        ]
        for row in old_pdp:
            values = dict(zip(old_pdp_columns, tuple(row)))
            values["pdp_call_id_verifier"] = None
            values["context_record_digest"] = None
            conn.execute(
                f"INSERT INTO authorization_pdp_evidence ({','.join(pdp_columns)}) "
                f"VALUES ({','.join('?' for _ in pdp_columns)})",
                tuple(values.get(name) for name in pdp_columns),
            )

        for task_id, (old_row, binding, complete) in migrated_tasks.items():
            if complete or old_row["status"] not in {
                "approval_required", "approved", "claimed"
            }:
                continue
            ambiguous = (
                old_row["status"] == "claimed"
                and old_row["send_started_at_us"] is not None
            )
            self._audit_insert(
                conn,
                event_id=f"task-migrated-v4:{task_id}",
                binding=binding,
                kind=("task_failed_consumed" if old_row["status"] == "claimed" else "task_denied"),
                reason_code=(
                    "ambiguous_after_restart" if ambiguous else "incomplete_delivery_binding"
                ),
                actor_scope="host",
                actor_value="authorization-store-migration-v4",
                target_scope="task",
                target_value=task_id,
                request_digest=old_row["request_digest"],
                at_us=migrated_at_us,
            )

        conn.execute("DROP TABLE authorization_notification_attempts_v3")
        conn.execute("DROP TABLE authorization_pdp_evidence_v3")
        conn.execute("DROP TABLE authorization_audit_events_v3")
        conn.execute("DROP TABLE authorization_tasks_v3")
        for statement in _INDEXES_V4.split(";"):
            if statement.strip():
                conn.execute(statement)

    def _migrate_v5(self, conn: sqlite3.Connection) -> None:
        """Rename PDP call correlation evidence without blessing legacy rows.

        Older rows remain available for audit, but their prior opaque value is
        not reinterpreted as host-generated call evidence and therefore cannot
        satisfy a current authorization check.
        """
        columns = [
            item[1]
            for item in conn.execute("PRAGMA table_info(authorization_pdp_evidence)")
        ]
        if "pdp_call_id_verifier" in columns:
            return
        conn.execute("DROP INDEX IF EXISTS idx_authorization_pdp_task_stage")
        conn.execute(
            "ALTER TABLE authorization_pdp_evidence "
            "RENAME TO authorization_pdp_evidence_v4"
        )
        conn.execute(_PDP_V3.format(table="authorization_pdp_evidence"))
        old_rows = conn.execute(
            "SELECT * FROM authorization_pdp_evidence_v4"
        ).fetchall()
        new_columns = [
            item[1]
            for item in conn.execute("PRAGMA table_info(authorization_pdp_evidence)")
        ]
        old_names = columns
        for row in old_rows:
            values = dict(zip(old_names, tuple(row)))
            # Column ten in v4 held an unrelated opaque value. Do not relabel it.
            values["pdp_call_id_verifier"] = None
            values["context_record_digest"] = None
            conn.execute(
                f"INSERT INTO authorization_pdp_evidence ({','.join(new_columns)}) "
                f"VALUES ({','.join('?' for _ in new_columns)})",
                tuple(values.get(name) for name in new_columns),
            )
        conn.execute("DROP TABLE authorization_pdp_evidence_v4")
        for statement in _INDEXES_V4.split(";"):
            if statement.strip():
                conn.execute(statement)

    @staticmethod
    def _bounded_state_record(values: object, columns: tuple[str, ...]) -> bytes:
        """Canonicalize one payload-free authority row with strict type bounds."""

        record: dict[str, object] = {}
        for name in columns:
            value = values.get(name) if isinstance(values, dict) else values[name]  # type: ignore[index]
            if value is None:
                record[name] = None
            elif type(value) is str:
                if "\x00" in value or len(value.encode("utf-8")) > 65_536:
                    raise ValueError("authorization state value is malformed")
                record[name] = value
            elif type(value) is int:
                if not -(2**63) <= value < 2**63:
                    raise ValueError("authorization state value is malformed")
                record[name] = value
            else:
                raise TypeError("authorization state value is malformed")
        return json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def _mutable_state_digest(
        self, domain: bytes, values: object, columns: tuple[str, ...]
    ) -> str:
        canonical = self._bounded_state_record(values, columns)
        return f"{self._key_version}:h6:" + hmac.new(
            self._request_key, domain + b"\0" + canonical, hashlib.sha256
        ).hexdigest()

    def _task_state_digest(self, values: object) -> str:
        return self._mutable_state_digest(
            b"hermes-authorization-task-state-v7", values, _TASK_STATE_COLUMNS
        )

    def _task_state_digest_v6(self, values: object) -> str:
        return self._mutable_state_digest(
            b"hermes-authorization-task-state-v6", values, _TASK_STATE_COLUMNS_V6
        )

    def _notification_state_digest(self, values: object) -> str:
        return self._mutable_state_digest(
            b"hermes-authorization-notification-state-v6",
            values,
            _NOTIFICATION_STATE_COLUMNS,
        )

    def _audit_record_digest(self, values: object) -> str:
        canonical = self._bounded_state_record(values, _AUDIT_RECORD_COLUMNS)
        return f"{self._key_version}:h7:" + hmac.new(
            self._audit_key,
            b"hermes-authorization-audit-record-v7\0" + canonical,
            hashlib.sha256,
        ).hexdigest()

    def _audit_record_digest_v6(self, values: object) -> str:
        canonical = self._bounded_state_record(values, _AUDIT_RECORD_COLUMNS_V6)
        return f"{self._key_version}:h6:" + hmac.new(
            self._audit_key,
            b"hermes-authorization-audit-record-v6\0" + canonical,
            hashlib.sha256,
        ).hexdigest()

    def _task_state_matches(self, row: sqlite3.Row) -> bool:
        try:
            actual = row["mutable_state_digest"]
            return type(actual) is str and hmac.compare_digest(
                actual, self._task_state_digest(row)
            )
        except (KeyError, IndexError, TypeError, ValueError, OverflowError, UnicodeError):
            return False

    def _task_state_matches_v6(self, row: sqlite3.Row) -> bool:
        try:
            actual = row["mutable_state_digest"]
            return type(actual) is str and hmac.compare_digest(
                actual, self._task_state_digest_v6(row)
            )
        except (KeyError, IndexError, TypeError, ValueError, OverflowError, UnicodeError):
            return False

    def _notification_state_matches(self, row: sqlite3.Row) -> bool:
        try:
            actual = row["mutable_state_digest"]
            return type(actual) is str and hmac.compare_digest(
                actual, self._notification_state_digest(row)
            )
        except (KeyError, IndexError, TypeError, ValueError, OverflowError, UnicodeError):
            return False

    def _audit_record_matches(self, row: Optional[sqlite3.Row]) -> bool:
        if row is None:
            return False
        try:
            actual = row["record_digest"]
            columns = set(row.keys())
            expected = (
                self._audit_record_digest(row)
                if "audit_sequence" in columns
                else self._audit_record_digest_v6(row)
            )
            return type(actual) is str and hmac.compare_digest(
                actual, expected
            )
        except (KeyError, IndexError, TypeError, ValueError, OverflowError, UnicodeError):
            return False

    def _audit_chain_matches(
        self, conn: sqlite3.Connection, task_row: sqlite3.Row
    ) -> bool:
        """Verify exact per-task audit completeness against authenticated head state."""

        try:
            if not self._task_state_matches(task_row):
                return False
            count = task_row["audit_event_count"]
            head = task_row["audit_head_digest"]
            if (
                type(count) is not int
                or not 0 <= count <= MAX_AUDIT_EVENTS_PER_TASK
                or type(head) is not str
                or "\x00" in head
                or len(head.encode("utf-8")) > 256
                or (count == 0 and head != "")
                or (count > 0 and head == "")
            ):
                return False
            rows = conn.execute(
                "SELECT * FROM authorization_audit_events WHERE task_id=? "
                "ORDER BY audit_sequence",
                (task_row["task_id"],),
            ).fetchall()
            if len(rows) != count:
                return False
            previous = ""
            for expected_sequence, row in enumerate(rows, 1):
                if (
                    type(row["audit_sequence"]) is not int
                    or row["audit_sequence"] != expected_sequence
                    or type(row["previous_record_digest"]) is not str
                    or row["previous_record_digest"] != previous
                    or row["task_id"] != task_row["task_id"]
                    or row["request_digest"] != task_row["request_digest"]
                    or row["key_version"] != task_row["key_version"]
                    or not self._audit_record_matches(row)
                ):
                    return False
                previous = row["record_digest"]
            return hmac.compare_digest(previous, head)
        except (
            KeyError, IndexError, TypeError, ValueError, OverflowError,
            UnicodeError, sqlite3.DatabaseError,
        ):
            return False

    def _refresh_task_state(self, conn: sqlite3.Connection, task_id: str) -> None:
        row = conn.execute(
            "SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if row is None:
            raise AuthorizationIntegrityError("authorization task state update was lost")
        conn.execute(
            "UPDATE authorization_tasks SET mutable_state_digest=? WHERE task_id=?",
            (self._task_state_digest(row), task_id),
        )

    def _refresh_task_state_v6(self, conn: sqlite3.Connection, task_id: str) -> None:
        row = conn.execute(
            "SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if row is None:
            raise AuthorizationIntegrityError("authorization task state update was lost")
        conn.execute(
            "UPDATE authorization_tasks SET mutable_state_digest=? WHERE task_id=?",
            (self._task_state_digest_v6(row), task_id),
        )

    def _refresh_notification_state(
        self, conn: sqlite3.Connection, attempt_id: str
    ) -> None:
        row = conn.execute(
            "SELECT * FROM authorization_notification_attempts WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if row is None:
            raise AuthorizationIntegrityError(
                "authorization notification state update was lost"
            )
        conn.execute(
            "UPDATE authorization_notification_attempts SET mutable_state_digest=? "
            "WHERE attempt_id=?",
            (self._notification_state_digest(row), attempt_id),
        )

    def _migrate_v6(self, conn: sqlite3.Connection) -> None:
        """Authenticate a fail-closed snapshot of pre-v6 authority state."""

        task_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(authorization_tasks)")
        }
        if "mutable_state_digest" in task_columns:
            return
        migrated_at_us = int(time.time() * 1_000_000)
        conn.execute(
            "ALTER TABLE authorization_tasks ADD COLUMN mutable_state_digest TEXT"
        )
        conn.execute(
            "ALTER TABLE authorization_notification_attempts "
            "ADD COLUMN mutable_state_digest TEXT"
        )
        conn.execute(
            "ALTER TABLE authorization_audit_events ADD COLUMN record_digest TEXT"
        )

        # Reconstruct legacy audit envelopes first.  These seals authenticate
        # only the surviving snapshot; v5 had no authenticated completeness.
        for audit in conn.execute("SELECT * FROM authorization_audit_events").fetchall():
            conn.execute(
                "UPDATE authorization_audit_events SET record_digest=? WHERE event_id=?",
                (self._audit_record_digest_v6(audit), audit["event_id"]),
            )

        self._terminalize_legacy_authority(
            conn,
            migrated_at_us=migrated_at_us,
            migration_version="v6",
        )
        self._fault("migration.v6.after_terminalization")

        for row in conn.execute("SELECT task_id FROM authorization_tasks").fetchall():
            self._refresh_task_state_v6(conn, row["task_id"])
        for row in conn.execute(
            "SELECT attempt_id FROM authorization_notification_attempts"
        ).fetchall():
            self._refresh_notification_state(conn, row["attempt_id"])

    def _migrate_v7(self, conn: sqlite3.Connection) -> None:
        """Snapshot legacy audit history into authenticated per-task chains.

        V6 could authenticate surviving rows but could not prove that rows had
        not been deleted.  Consequently no v5/v6 active task or notification
        is executable after migration, even when every surviving keyed record
        is valid.  Migration records that terminalization before signing the
        deterministic snapshot chain.  The chain authenticates this exact
        snapshot and every append forward; it does not claim retrospective
        completeness that the legacy schema never recorded.
        """

        task_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(authorization_tasks)")
        }
        if "audit_event_count" in task_columns:
            return
        migrated_at_us = int(time.time() * 1_000_000)

        # Verify every surviving v6 envelope before changing it.  Migration may
        # terminalize valid legacy authority, but it must never bless tampering.
        for row in conn.execute("SELECT * FROM authorization_tasks").fetchall():
            if not self._task_state_matches_v6(row):
                raise AuthorizationIntegrityError(
                    "authorization legacy task state failed integrity verification"
                )
            self._legacy_migration_binding(row)
        for row in conn.execute(
            "SELECT * FROM authorization_notification_attempts"
        ).fetchall():
            if not self._notification_state_matches(row):
                raise AuthorizationIntegrityError(
                    "authorization legacy notification state failed integrity verification"
                )

        self._terminalize_legacy_authority(
            conn,
            migrated_at_us=migrated_at_us,
            migration_version="v7",
        )
        self._fault("migration.v7.after_terminalization")

        # Every surviving v6 envelope must still authenticate.  Completeness is
        # unknowable before this point, but altered surviving history is not
        # silently blessed by migration.
        old_audits = conn.execute(
            "SELECT * FROM authorization_audit_events "
            "ORDER BY task_id,occurred_at_us,event_id"
        ).fetchall()
        per_task_counts: dict[str, int] = {}
        for audit in old_audits:
            if not self._audit_record_matches(audit):
                raise AuthorizationIntegrityError(
                    "authorization legacy audit record failed integrity verification"
                )
            count = per_task_counts.get(audit["task_id"], 0) + 1
            if count > MAX_AUDIT_EVENTS_PER_TASK:
                raise AuthorizationIntegrityError(
                    "authorization legacy audit chain exceeds security bound"
                )
            per_task_counts[audit["task_id"]] = count

        conn.execute("DROP INDEX IF EXISTS idx_authorization_audit_task_time")
        conn.execute(
            "ALTER TABLE authorization_audit_events "
            "RENAME TO authorization_audit_events_v6"
        )
        conn.execute(_AUDIT_V7.format(table="authorization_audit_events"))
        heads: dict[str, str] = {}
        sequences: dict[str, int] = {}
        for audit in old_audits:
            task_id = audit["task_id"]
            sequence = sequences.get(task_id, 0) + 1
            previous = heads.get(task_id, "")
            values = {
                name: audit[name] for name in _AUDIT_RECORD_COLUMNS_V6
            }
            values.update(
                {
                    "audit_sequence": sequence,
                    "previous_record_digest": previous,
                }
            )
            digest = self._audit_record_digest(values)
            conn.execute(
                "INSERT INTO authorization_audit_events "
                "(event_id,task_id,kind,reason_code,actor_token,target_token,"
                "request_digest,key_version,occurred_at_us,audit_sequence,"
                "previous_record_digest,record_digest) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    *(values[name] for name in _AUDIT_RECORD_COLUMNS),
                    digest,
                ),
            )
            sequences[task_id] = sequence
            heads[task_id] = digest

        conn.execute(
            "ALTER TABLE authorization_tasks ADD COLUMN audit_event_count INTEGER "
            "NOT NULL DEFAULT 0 CHECK (audit_event_count BETWEEN 0 AND 100000)"
        )
        conn.execute(
            "ALTER TABLE authorization_tasks ADD COLUMN audit_head_digest TEXT "
            "NOT NULL DEFAULT ''"
        )
        for task in conn.execute("SELECT task_id FROM authorization_tasks").fetchall():
            task_id = task["task_id"]
            conn.execute(
                "UPDATE authorization_tasks SET audit_event_count=?,audit_head_digest=? "
                "WHERE task_id=?",
                (sequences.get(task_id, 0), heads.get(task_id, ""), task_id),
            )
            self._refresh_task_state(conn, task_id)
        conn.execute("DROP TABLE authorization_audit_events_v6")
        for statement in _INDEXES_V4.split(";"):
            if statement.strip():
                conn.execute(statement)

    def _legacy_migration_binding(
        self, row: sqlite3.Row
    ) -> TrustedAuthorizationBinding:
        """Authenticate immutable task identity before sealing a legacy snapshot."""

        try:
            binding = self._binding_from_json(row["binding_json"])
            valid = (
                row["key_version"] == self._key_version
                and row["task_id"] == binding.task_id
                and row["correlation_id"] == binding.correlation_id
                and row["created_at_us"] == binding.created_at_us
                and row["expires_at_us"] == binding.expires_at_us
                and hmac.compare_digest(
                    row["binding_digest"], self._binding_digest(binding)
                )
                and hmac.compare_digest(
                    row["request_digest"],
                    self._request_digest(row["scoped_request_key"], binding),
                )
            )
        except (
            KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeError
        ):
            valid = False
        if not valid:
            raise AuthorizationIntegrityError(
                "authorization legacy task binding failed integrity verification"
            )
        return binding

    def _terminalize_legacy_authority(
        self,
        conn: sqlite3.Connection,
        *,
        migrated_at_us: int,
        migration_version: str,
    ) -> None:
        """Remove every authority-bearing v5/v6 state before v7 sealing.

        Surviving keyed rows authenticate their contents, not the absence of a
        later row or transition.  ``ambiguous_after_restart`` is the existing
        bounded receipt/reason dedicated to that uncertainty.
        """

        actor = f"authorization-store-migration-{migration_version}"
        bindings: dict[str, TrustedAuthorizationBinding] = {}
        denied_authority_columns = (
            "decision_id", "decision_digest", "winning_challenge_attempt_id",
            "winning_challenge_generation", "claim_owner_digest", "claim_nonce_digest",
            "claim_generation", "claim_lease_expires_at_us", "claimed_at_us",
            "heartbeat_at_us", "send_started_at_us", "receipt_token",
            "delivery_acceptance_status", "delivery_accepted_at_us",
            "delivery_transport_implementation", "delivery_runtime_identity",
            "delivery_account_binding_token", "delivery_connection_epoch",
            "delivery_record_digest", "resolution_spec_digest",
        )
        tasks = conn.execute("SELECT * FROM authorization_tasks").fetchall()
        for row in tasks:
            binding = self._legacy_migration_binding(row)
            bindings[row["task_id"]] = binding
            if row["status"] == "denied":
                # A denial is terminal for task execution, but it deliberately
                # remains eligible for resolution-notification retries in the
                # current schema.  Legacy audit completeness cannot prove that
                # this decision authority is the latest state, so retain the
                # denial and its forensic records while removing every mutable
                # field that could authorize a post-migration retry or send.
                if any(row[name] is not None for name in denied_authority_columns):
                    conn.execute(
                        "UPDATE authorization_tasks SET decision_id=NULL,"
                        "decision_digest=NULL,winning_challenge_attempt_id=NULL,"
                        "winning_challenge_generation=NULL,claim_owner_digest=NULL,"
                        "claim_nonce_digest=NULL,claim_generation=NULL,"
                        "claim_lease_expires_at_us=NULL,claimed_at_us=NULL,"
                        "heartbeat_at_us=NULL,send_started_at_us=NULL,receipt_token=NULL,"
                        "delivery_acceptance_status=NULL,delivery_accepted_at_us=NULL,"
                        "delivery_transport_implementation=NULL,"
                        "delivery_runtime_identity=NULL,"
                        "delivery_account_binding_token=NULL,delivery_connection_epoch=NULL,"
                        "delivery_record_digest=NULL,resolution_spec_digest=NULL,"
                        "version=version+1 WHERE task_id=?",
                        (row["task_id"],),
                    )
                    self._refresh_task_state_v6(conn, row["task_id"])
                continue
            if row["status"] not in {"approval_required", "approved", "claimed"}:
                continue
            claimed = row["status"] == "claimed"
            conn.execute(
                "UPDATE authorization_tasks SET status=?,decision_id=NULL,"
                "decision_digest=NULL,winning_challenge_attempt_id=NULL,"
                "winning_challenge_generation=NULL,claim_owner_digest=NULL,"
                "claim_nonce_digest=NULL,claim_generation=NULL,"
                "claim_lease_expires_at_us=NULL,claimed_at_us=NULL,heartbeat_at_us=NULL,"
                "send_started_at_us=NULL,completed_at_us=?,"
                "receipt_code='ambiguous_after_restart',receipt_token=NULL,"
                "delivery_acceptance_status=NULL,delivery_accepted_at_us=NULL,"
                "delivery_transport_implementation=NULL,delivery_runtime_identity=NULL,"
                "delivery_account_binding_token=NULL,delivery_connection_epoch=NULL,"
                "delivery_record_digest=NULL,resolution_spec_digest=NULL,"
                "version=version+1 WHERE task_id=?",
                (
                    "failed_consumed" if claimed else "denied",
                    migrated_at_us,
                    row["task_id"],
                ),
            )
            self._refresh_task_state_v6(conn, row["task_id"])
            self._audit_insert(
                conn,
                event_id=f"task-migrated-{migration_version}:{row['task_id']}",
                binding=binding,
                kind="task_failed_consumed" if claimed else "task_denied",
                reason_code="ambiguous_after_restart",
                actor_scope="host",
                actor_value=actor,
                target_scope="task",
                target_value=row["task_id"],
                request_digest=row["request_digest"],
                at_us=migrated_at_us,
            )

        notifications = conn.execute(
            "SELECT * FROM authorization_notification_attempts"
        ).fetchall()
        for row in notifications:
            if row["status"] not in {"pending", "claimed"}:
                continue
            values = dict(row)
            values.update(
                {
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
            )
            conn.execute(
                "UPDATE authorization_notification_attempts SET status='failed',"
                "claim_owner_digest=NULL,claim_nonce_digest=NULL,claim_generation=NULL,"
                "claim_lease_expires_at_us=NULL,send_started_at_us=NULL,completed_at_us=?,"
                "receipt_code='ambiguous_after_restart',provider_message_verifier=NULL,"
                "provider_verifier_version=NULL,provider_acceptance_status=NULL,"
                "provider_accepted_at_us=NULL,adapter_instance_id=NULL,"
                "account_binding_token=NULL,connection_epoch=NULL,"
                "challenge_state='unaccepted',challenge_resolved_at_us=NULL,"
                "challenge_decision_digest=NULL,challenge_record_digest=?,"
                "version=version+1 WHERE attempt_id=?",
                (
                    migrated_at_us,
                    self._challenge_record_digest(values),
                    row["attempt_id"],
                ),
            )
            self._refresh_notification_state(conn, row["attempt_id"])
            binding = bindings.get(row["task_id"])
            if binding is None:
                raise AuthorizationIntegrityError(
                    "authorization legacy notification task is missing"
                )
            task = conn.execute(
                "SELECT request_digest FROM authorization_tasks WHERE task_id=?",
                (row["task_id"],),
            ).fetchone()
            if task is None:
                raise AuthorizationIntegrityError(
                    "authorization legacy notification task is missing"
                )
            self._audit_insert(
                conn,
                event_id=f"notification-migrated-{migration_version}:{row['attempt_id']}",
                binding=binding,
                kind="notification_failed",
                reason_code="ambiguous_after_restart",
                actor_scope="host",
                actor_value=actor,
                target_scope="notification",
                target_value=row["attempt_id"],
                request_digest=task["request_digest"],
                at_us=migrated_at_us,
            )

    def _validate_sidecars(self) -> None:
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(self.db_path) + suffix)
            try:
                info = sidecar.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self._uid():
                raise UnsafeAuthorizationStorePath("authorization store sidecar is unsafe")
            mode = stat.S_IMODE(info.st_mode)
            if mode != 0o600:
                # Only normalize a regular sidecar after authenticating its uid.
                os.chmod(sidecar, 0o600)

    def audit_token(self, scope: str, value: str) -> str:
        _bounded(scope, "audit scope", maximum=64)
        _bounded(value, "audit value")
        digest = hmac.new(
            self._audit_key,
            b"hermes-authorization-audit-v1\0" + scope.encode() + b"\0" + value.encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"{self._key_version}:h1:{digest}"

    def _binding_digest(self, binding: TrustedAuthorizationBinding) -> str:
        digest = hmac.new(
            self._request_key,
            b"hermes-authorization-binding-v1\0"
            + self._key_version.encode()
            + b"\0"
            + binding.canonical_bytes(),
            hashlib.sha256,
        ).hexdigest()
        return f"{self._key_version}:h1:{digest}"

    def _request_digest(self, request_key: str, binding: TrustedAuthorizationBinding) -> str:
        return f"{self._key_version}:h1:" + hmac.new(
            self._request_key,
            b"hermes-authorization-request-v1\0"
            + self._key_version.encode()
            + b"\0"
            + request_key.encode()
            + b"\0"
            + binding.canonical_bytes(),
            hashlib.sha256,
        ).hexdigest()

    def _decision_digest(self, decision: OwnerDecision) -> str:
        return hmac.new(
            self._request_key,
            b"hermes-authorization-decision-v1\0" + decision.canonical_bytes(),
            hashlib.sha256,
        ).hexdigest()

    def _challenge_nonce_digest(
        self,
        nonce: str,
        *,
        task_id: Optional[str] = None,
        attempt_id: Optional[str] = None,
        challenge_generation: Optional[int] = None,
        verifier_version: str = "v2",
    ) -> str:
        if verifier_version == "v1":
            domain = (
                b"hermes-authorization-challenge-nonce-v1\0"
                + self._key_version.encode()
                + b"\0"
            )
        else:
            if task_id is None or attempt_id is None or challenge_generation is None:
                raise ValueError("v2 challenge nonce verifier requires exact generation binding")
            domain = (
                b"hermes-authorization-challenge-nonce-v2\0"
                + self._key_version.encode()
                + b"\0"
                + task_id.encode()
                + b"\0"
                + attempt_id.encode()
                + b"\0"
                + str(challenge_generation).encode()
                + b"\0"
            )
        digest = hmac.new(
            self._request_key,
            domain + nonce.encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"{self._key_version}:h1:{digest}"

    def _provider_message_verifier(
        self, task_id: str, attempt_id: str, generation: int, provider_message_id: str
    ) -> str:
        return f"{self._key_version}:h2:" + hmac.new(
            self._request_key,
            b"hermes-authorization-provider-message-v2\0"
            + self._key_version.encode()
            + b"\0"
            + task_id.encode()
            + b"\0"
            + attempt_id.encode()
            + b"\0"
            + str(generation).encode()
            + b"\0"
            + provider_message_id.encode(),
            hashlib.sha256,
        ).hexdigest()

    def _account_binding_token(self, account_binding: str) -> str:
        return f"{self._key_version}:h2:" + hmac.new(
            self._request_key,
            b"hermes-authorization-adapter-account-v2\0"
            + self._key_version.encode()
            + b"\0"
            + account_binding.encode(),
            hashlib.sha256,
        ).hexdigest()

    def _delivery_provider_message_verifier(
        self, task_id: str, claim_generation: int, provider_message_id: str
    ) -> str:
        return f"{self._key_version}:h3:" + hmac.new(
            self._request_key,
            b"hermes-authorization-delivery-provider-message-v3\0"
            + self._key_version.encode()
            + b"\0"
            + task_id.encode()
            + b"\0"
            + str(claim_generation).encode()
            + b"\0"
            + provider_message_id.encode(),
            hashlib.sha256,
        ).hexdigest()

    def _delivery_record_digest(
        self,
        values: object,
        binding: TrustedAuthorizationBinding,
    ) -> str:
        fields = (
            "task_id",
            "correlation_id",
            "binding_digest",
            "request_digest",
            "key_version",
            "claim_owner_digest",
            "claim_nonce_digest",
            "claim_generation",
            "send_started_at_us",
            "receipt_token",
            "delivery_acceptance_status",
            "delivery_accepted_at_us",
            "delivery_transport_implementation",
            "delivery_runtime_identity",
            "delivery_account_binding_token",
            "delivery_connection_epoch",
        )

        def get(name: str) -> object:
            if isinstance(values, dict):
                return values.get(name)
            return values[name]  # type: ignore[index]

        record = {name: get(name) for name in fields}
        record.update(
            {
                "operation": binding.operation,
                "policy_version": binding.policy_version,
                "policy_hash": binding.policy_hash,
                "delivery_profile": binding.delivery_profile,
                "delivery_platform": binding.delivery_platform,
                "delivery_account": binding.delivery_account,
                "delivery_chat": binding.delivery_chat,
                "delivery_thread": binding.delivery_thread,
            }
        )
        canonical = json.dumps(
            record, sort_keys=True, separators=(",", ":")
        ).encode()
        return f"{self._key_version}:h3:" + hmac.new(
            self._request_key,
            b"hermes-authorization-delivery-record-v3\0" + canonical,
            hashlib.sha256,
        ).hexdigest()

    def _challenge_record_digest(self, values: object) -> str:
        fields = (
            "attempt_id", "task_id", "correlation_id", "kind",
            "challenge_generation", "destination_profile", "destination_account",
            "destination_chat", "destination_thread", "destination_digest", "key_version",
            "challenge_nonce_digest", "nonce_verifier_version",
            "provider_message_verifier", "provider_verifier_version",
            "provider_acceptance_status", "provider_accepted_at_us", "adapter_instance_id",
            "account_binding_token", "connection_epoch", "challenge_state",
            "challenge_resolved_at_us", "challenge_decision_digest",
            "notification_spec_digest", "retry_ordinal", "supersedes_attempt_id",
        )

        def get(name: str) -> object:
            if isinstance(values, dict):
                return values.get(name)
            return values[name]  # type: ignore[index]

        canonical = json.dumps(
            {name: get(name) for name in fields},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return f"{self._key_version}:h2:" + hmac.new(
            self._request_key,
            b"hermes-authorization-challenge-record-v2\0" + canonical,
            hashlib.sha256,
        ).hexdigest()

    def _notification_spec_digest(self, values: object) -> str:
        """Authenticate every immutable notification scheduling/binding field."""
        fields = (
            "attempt_id", "task_id", "correlation_id", "kind",
            "challenge_generation", "destination_profile", "destination_account",
            "destination_chat", "destination_thread", "destination_digest", "key_version",
            "created_at_us", "due_at_us", "challenge_nonce_digest",
            "nonce_verifier_version", "retry_ordinal", "supersedes_attempt_id",
        )

        def get(name: str) -> object:
            if isinstance(values, dict):
                return values.get(name)
            return values[name]  # type: ignore[index]

        canonical = json.dumps(
            {name: get(name) for name in fields},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return f"{self._key_version}:h4:" + hmac.new(
            self._request_key,
            b"hermes-authorization-notification-spec-v4\0" + canonical,
            hashlib.sha256,
        ).hexdigest()

    def _pdp_evidence_digest(self, evidence: PdpDecisionEvidence) -> str:
        canonical = json.dumps(
            dataclasses.asdict(evidence), sort_keys=True, separators=(",", ":")
        ).encode()
        return f"{self._key_version}:h2:" + hmac.new(
            self._request_key,
            b"hermes-authorization-pdp-evidence-v2\0" + canonical,
            hashlib.sha256,
        ).hexdigest()

    def _pdp_factory_seal(self, evidence: PdpDecisionEvidence) -> str:
        values = dataclasses.asdict(evidence)
        values.pop("factory_seal")
        canonical = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
        return f"{self._key_version}:h6:" + hmac.new(
            self._request_key,
            b"hermes-authorization-pdp-factory-v6\0" + canonical,
            hashlib.sha256,
        ).hexdigest()

    def _pdp_factory_seal_matches(self, evidence: PdpDecisionEvidence) -> bool:
        try:
            return hmac.compare_digest(
                evidence.factory_seal, self._pdp_factory_seal(evidence)
            )
        except (TypeError, ValueError, OverflowError, UnicodeError):
            return False

    def _pdp_check_context_id(
        self,
        context: AuthorizationPdpCheckContext,
        claim: ClaimIdentity,
    ) -> str:
        owner_digest, nonce_digest = self._claim_digests(claim)
        fence = self._fence
        if fence is None:
            raise CoordinatorFenceError("current coordinator fence required")
        values = dataclasses.asdict(context)
        values.pop("context_id")
        values["binding"] = context.binding.canonical_bytes().decode("utf-8")
        values["claim_owner_digest"] = owner_digest
        values["claim_nonce_digest"] = nonce_digest
        values["coordinator_owner_digest"] = fence.owner_digest
        values["coordinator_nonce_digest"] = fence.nonce_digest
        canonical = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
        return f"{self._key_version}:h1:" + hmac.new(
            self._request_key,
            b"hermes-authorization-pdp-check-context-v1\0" + canonical,
            hashlib.sha256,
        ).hexdigest()

    def create_pdp_check_context(
        self,
        task_id: str,
        claim: ClaimIdentity,
        *,
        stage: str,
        now_us: int,
    ) -> AuthorizationPdpCheckContext:
        """Create one authenticated, current external-PDP request context."""
        _bounded(task_id, "task_id")
        _epoch_us(now_us, "now_us")
        if type(claim) is not ClaimIdentity:
            raise TypeError("exact claim identity is required")
        if type(stage) is not str or stage not in {"pre_claim", "pre_private_read"}:
            raise ValueError("unsupported PDP check stage")
        conn = self._connect()
        try:
            conn.execute("BEGIN")
            self._require_live_fence(conn, now_us)
            coordinator = self._coordinator_identity
            fence = self._fence
            if coordinator is None or fence is None:
                raise CoordinatorFenceError("current coordinator fence required")
            raw = conn.execute(
                "SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if raw is None:
                raise KeyError("authorization task not found")
            binding = self._verified_binding_for_task_row(conn, raw)
            if binding is None:
                raise AuthorizationIntegrityError(
                    "authorization task failed integrity verification"
                )
            valid = (
                binding.has_delivery_acceptance_binding
                and now_us < raw["expires_at_us"]
            )
            if stage == "pre_claim":
                valid = valid and raw["status"] == "approved" and claim.generation == 1
            else:
                valid = (
                    valid
                    and raw["status"] == "claimed"
                    and self._claim_matches(raw, claim)
                    and now_us < raw["claim_lease_expires_at_us"]
                )
            if not valid:
                raise AuthorizationIntegrityError(
                    "authorization PDP context is stale or ineligible"
                )
            context = AuthorizationPdpCheckContext(
                context_id="pending",
                pdp_call_id=secrets.token_urlsafe(24),
                stage=stage,
                created_at_us=now_us,
                task_version=raw["version"],
                task_status=raw["status"],
                binding=binding,
                request_digest=raw["request_digest"],
                binding_digest=raw["binding_digest"],
                key_version=raw["key_version"],
                model_identity=binding.model_identity,
                policy_identity=binding.policy_identity,
                coordinator_owner_id=coordinator.owner_id,
                coordinator_epoch=fence.epoch,
                worker_profile=claim.owner_profile,
                worker_agent=claim.owner_agent,
                worker_account=claim.owner_account,
                claim_generation=claim.generation,
            )
            return dataclasses.replace(
                context, context_id=self._pdp_check_context_id(context, claim)
            )
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            conn.close()

    def create_pdp_decision_evidence(
        self,
        context: AuthorizationPdpCheckContext,
        claim: ClaimIdentity,
        result: ExternalPdpDecisionResult,
    ) -> PdpDecisionEvidence:
        """Combine a current store context with the adapter's bounded result.

        The adapter result has no fields with which to override binding, fence,
        model, policy, or claim identity. The context is revalidated against the
        durable row and coordinator immediately before evidence is returned.
        """
        if type(context) is not AuthorizationPdpCheckContext:
            raise TypeError("exact PDP check context is required")
        if type(claim) is not ClaimIdentity:
            raise TypeError("exact claim identity is required")
        if type(result) is not ExternalPdpDecisionResult:
            raise TypeError("exact external PDP decision result is required")
        if (
            result.context_id != context.context_id
            or result.pdp_call_id != context.pdp_call_id
        ):
            raise AuthorizationIntegrityError("authorization PDP result binding is invalid")
        if result.checked_at_us < context.created_at_us:
            raise AuthorizationIntegrityError("authorization PDP context is stale")
        conn = self._connect()
        try:
            conn.execute("BEGIN")
            self._require_live_fence(conn, result.checked_at_us)
            fence = self._fence
            coordinator = self._coordinator_identity
            row = conn.execute(
                "SELECT * FROM authorization_tasks WHERE task_id=?", (context.task_id,)
            ).fetchone()
            binding = (
                self._verified_binding_for_task_row(conn, row) if row is not None else None
            )
            expected_context_id = self._pdp_check_context_id(
                dataclasses.replace(context, context_id="pending"), claim
            )
            identity_matches = (
                claim.owner_profile == context.worker_profile
                and claim.owner_agent == context.worker_agent
                and claim.owner_account == context.worker_account
                and claim.generation == context.claim_generation
            )
            current = (
                row is not None
                and binding is not None
                and fence is not None
                and coordinator is not None
                and hmac.compare_digest(context.context_id, expected_context_id)
                and identity_matches
                and binding == context.binding
                and row["version"] == context.task_version
                and row["status"] == context.task_status
                and row["request_digest"] == context.request_digest
                and row["binding_digest"] == context.binding_digest
                and row["key_version"] == context.key_version == self._key_version
                and binding.model_identity == context.model_identity
                and binding.policy_identity == context.policy_identity
                and coordinator.owner_id == context.coordinator_owner_id
                and fence.epoch == context.coordinator_epoch
                and result.checked_at_us < row["expires_at_us"]
            )
            if context.stage == "pre_claim":
                current = current and row is not None and row["status"] == "approved"
            else:
                current = (
                    current
                    and row is not None
                    and row["status"] == "claimed"
                    and self._claim_matches(row, claim)
                    and result.checked_at_us < row["claim_lease_expires_at_us"]
                )
            if not current:
                raise AuthorizationIntegrityError("authorization PDP context is stale")
            assert coordinator is not None
            evidence = PdpDecisionEvidence(
                evidence_id=result.pdp_call_id,
                stage=context.stage,
                decision=result.decision,
                request_digest=context.request_digest,
                model_identity=context.model_identity,
                policy_revision=context.policy_identity,
                checked_at_us=result.checked_at_us,
                consistency=result.consistency,
                pdp_call_id=result.pdp_call_id,
                context_id=context.context_id,
                cache_used=result.cache_used,
                task_id=context.task_id,
                binding_digest=context.binding_digest,
                key_version=context.key_version,
                coordinator_owner_id=context.coordinator_owner_id,
                coordinator_nonce=coordinator.nonce,
                coordinator_epoch=context.coordinator_epoch,
                worker_profile=context.worker_profile,
                worker_agent=context.worker_agent,
                worker_account=context.worker_account,
                claim_nonce=claim.nonce,
                claim_generation=context.claim_generation,
                factory_seal="pending",
            )
            return dataclasses.replace(
                evidence, factory_seal=self._pdp_factory_seal(evidence)
            )
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            conn.close()

    def _pdp_context_record_digest(self, values: object) -> str:
        fields = (
            "evidence_id",
            "task_id",
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
            "key_version",
        )

        def get(name: str) -> object:
            if isinstance(values, dict):
                return values.get(name)
            return values[name]  # type: ignore[index]

        canonical = json.dumps(
            {name: get(name) for name in fields},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return f"{self._key_version}:h3:" + hmac.new(
            self._request_key,
            b"hermes-authorization-pdp-context-v3\0" + canonical,
            hashlib.sha256,
        ).hexdigest()

    def _claim_digests(self, claim: ClaimIdentity) -> tuple[str, str]:
        owner = hmac.new(
            self._request_key,
            b"hermes-authorization-claim-owner-v1\0" + claim.owner_bytes(),
            hashlib.sha256,
        ).hexdigest()
        nonce = hmac.new(
            self._request_key,
            b"hermes-authorization-claim-nonce-v1\0" + claim.nonce.encode(),
            hashlib.sha256,
        ).hexdigest()
        return owner, nonce

    def _coordinator_digests(
        self, identity: CoordinatorIdentity
    ) -> tuple[str, str]:
        owner = hmac.new(
            self._request_key,
            b"hermes-authorization-coordinator-owner-v1\0"
            + self._key_version.encode()
            + b"\0"
            + identity.owner_id.encode(),
            hashlib.sha256,
        ).hexdigest()
        nonce = hmac.new(
            self._request_key,
            b"hermes-authorization-coordinator-nonce-v1\0"
            + self._key_version.encode()
            + b"\0"
            + identity.nonce.encode(),
            hashlib.sha256,
        ).hexdigest()
        return owner, nonce

    def acquire_coordinator_lock(self) -> Optional[AuthorizationCoordinatorLockSession]:
        """Open and hold the host-selected owner-only coordinator lock."""
        return AuthorizationCoordinatorLockSession.acquire(self.coordinator_lock_path)

    def close(self) -> None:
        lock, self._coordinator_lock = self._coordinator_lock, None
        self._fence = None
        self._coordinator_identity = None
        if lock is not None:
            lock.close()

    def __enter__(self) -> "AuthorizationTaskStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def acquire_coordinator(
        self,
        identity: CoordinatorIdentity,
        *,
        now_us: int,
        lease_expires_at_us: int,
        lock_session: AuthorizationCoordinatorLockSession,
    ) -> Optional[CoordinatorFence]:
        """Acquire/renew the singleton DB epoch under a caller-held OS lock.

        This DB primitive fences stale coordinators but is not a replacement
        for process exclusivity: the gateway must hold its exclusive owner
        lock for the full lease/session lifetime. A different live owner is
        never preempted. Takeover at the exact expiry boundary increments the
        epoch, invalidating every mutation from the old coordinator.
        """
        if (
            not isinstance(lock_session, AuthorizationCoordinatorLockSession)
            or not lock_session.bind_owner(self._lock_owner_token)
            or not lock_session.is_live_for(
                self.coordinator_lock_path, self._lock_owner_token
            )
        ):
            raise ValueError("live owned authorization coordinator lock is required")
        _epoch_us(now_us, "now_us")
        _epoch_us(lease_expires_at_us, "lease_expires_at_us")
        if lease_expires_at_us <= now_us:
            raise ValueError("coordinator lease must end after now")
        owner_digest, nonce_digest = self._coordinator_digests(identity)
        had_local_session = self._fence is not None
        last: Optional[sqlite3.OperationalError] = None
        for attempt in range(MAX_RETRIES):
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT * FROM authorization_coordinator_lease WHERE singleton=1"
                ).fetchone()
                effective_lease_expires_at_us = lease_expires_at_us
                needs_reconciliation = False
                if row is None:
                    epoch = 1
                    conn.execute(
                        "INSERT INTO authorization_coordinator_lease "
                        "(singleton,owner_digest,nonce_digest,key_version,epoch,heartbeat_at_us,lease_expires_at_us) "
                        "VALUES (1,?,?,?,?,?,?)",
                        (
                            owner_digest,
                            nonce_digest,
                            self._key_version,
                            epoch,
                            now_us,
                            effective_lease_expires_at_us,
                        ),
                    )
                    # A missing singleton is an authority reconstruction
                    # boundary, even when this process still holds the same
                    # OS lock and identity.  Reconcile before publishing the
                    # reconstructed epoch-one fence so durable claims cannot
                    # regain authority through matching identity/epoch data.
                    # This is also safe for a genuinely empty first bootstrap.
                    needs_reconciliation = True
                elif (
                    row["owner_digest"] == owner_digest
                    and row["nonce_digest"] == nonce_digest
                    and row["key_version"] == self._key_version
                    and now_us < row["lease_expires_at_us"]
                ):
                    epoch = row["epoch"]
                    effective_lease_expires_at_us = max(
                        lease_expires_at_us, row["lease_expires_at_us"]
                    )
                    conn.execute(
                        "UPDATE authorization_coordinator_lease SET heartbeat_at_us=?,lease_expires_at_us=? "
                        "WHERE singleton=1 AND owner_digest=? AND nonce_digest=? AND key_version=? AND epoch=?",
                        (
                            now_us,
                            effective_lease_expires_at_us,
                            owner_digest,
                            nonce_digest,
                            self._key_version,
                            epoch,
                        ),
                    )
                    # Reattaching a new local session to durable ownership is
                    # a restart boundary even when the durable epoch is live.
                    needs_reconciliation = not had_local_session
                elif now_us >= row["lease_expires_at_us"]:
                    epoch = row["epoch"] + 1
                    cursor = conn.execute(
                        "UPDATE authorization_coordinator_lease SET owner_digest=?,nonce_digest=?,key_version=?,"
                        "epoch=?,heartbeat_at_us=?,lease_expires_at_us=? WHERE singleton=1 AND epoch=? "
                        "AND lease_expires_at_us<=?",
                        (
                            owner_digest,
                            nonce_digest,
                            self._key_version,
                            epoch,
                            now_us,
                            effective_lease_expires_at_us,
                            row["epoch"],
                            now_us,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise CoordinatorFenceError(
                            "coordinator epoch takeover lost atomicity"
                        )
                    # Any expiry takeover changes ownership authority, including
                    # same owner/session reacquisition while the OS lock stayed held.
                    needs_reconciliation = True
                else:
                    conn.execute("ROLLBACK")
                    lock_session.close()
                    return None
                if needs_reconciliation:
                    # Reconcile under the same IMMEDIATE transaction as the
                    # lease/epoch update.  No new fence is published locally,
                    # and no old claimed task can survive the new epoch commit.
                    self._reconcile_restart_in_transaction(conn, now_us=now_us)
                conn.execute("COMMIT")
                fence = CoordinatorFence(
                    owner_digest=owner_digest,
                    nonce_digest=nonce_digest,
                    key_version=self._key_version,
                    epoch=epoch,
                    lease_expires_at_us=effective_lease_expires_at_us,
                )
                self._fence = fence
                self._coordinator_identity = identity
                self._coordinator_lock = lock_session
                return fence
            except sqlite3.OperationalError as exc:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                if not self._locked(exc) or attempt == MAX_RETRIES - 1:
                    raise
                last = exc
                time.sleep(random.uniform(0.005, 0.04))
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()
        raise last or CoordinatorFenceError("coordinator acquisition failed closed")

    @staticmethod
    def _binding_from_json(value: str) -> TrustedAuthorizationBinding:
        data = json.loads(value)
        data["fields"] = tuple(data["fields"])
        return TrustedAuthorizationBinding(**data)

    @staticmethod
    def _task(row: sqlite3.Row) -> AuthorizationTask:
        return AuthorizationTask(
            task_id=row["task_id"],
            correlation_id=row["correlation_id"],
            status=row["status"],
            request_digest=row["request_digest"],
            created_at_us=row["created_at_us"],
            expires_at_us=row["expires_at_us"],
            version=row["version"],
            claim_generation=row["claim_generation"],
            claim_lease_expires_at_us=row["claim_lease_expires_at_us"],
            send_started_at_us=row["send_started_at_us"],
            completed_at_us=row["completed_at_us"],
            receipt_code=row["receipt_code"],
            winning_challenge_attempt_id=row["winning_challenge_attempt_id"],
            winning_challenge_generation=row["winning_challenge_generation"],
        )

    def _audit_insert(
        self,
        conn: sqlite3.Connection,
        *,
        event_id: str,
        binding: TrustedAuthorizationBinding,
        kind: str,
        reason_code: str,
        actor_scope: str,
        actor_value: str,
        target_scope: str,
        target_value: str,
        request_digest: str,
        at_us: int,
    ) -> None:
        self._fault("audit.before")
        values = {
            "event_id": event_id,
            "task_id": binding.task_id,
            "kind": kind,
            "reason_code": reason_code,
            "actor_token": self.audit_token(actor_scope, actor_value),
            "target_token": self.audit_token(target_scope, target_value),
            "request_digest": request_digest,
            "key_version": self._key_version,
            "occurred_at_us": at_us,
        }
        audit_columns = {
            column[1]
            for column in conn.execute("PRAGMA table_info(authorization_audit_events)")
        }
        if "audit_sequence" in audit_columns:
            task_row = conn.execute(
                "SELECT * FROM authorization_tasks WHERE task_id=?",
                (binding.task_id,),
            ).fetchone()
            if task_row is None or not self._audit_chain_matches(conn, task_row):
                raise AuthorizationIntegrityError(
                    "authorization audit append failed integrity verification"
                )
            sequence = task_row["audit_event_count"] + 1
            if sequence > MAX_AUDIT_EVENTS_PER_TASK:
                raise AuthorizationIntegrityError(
                    "authorization audit append exceeds security bound"
                )
            values.update(
                {
                    "audit_sequence": sequence,
                    "previous_record_digest": task_row["audit_head_digest"],
                }
            )
            record_digest = self._audit_record_digest(values)
            conn.execute(
                "INSERT INTO authorization_audit_events "
                "(event_id,task_id,kind,reason_code,actor_token,target_token,request_digest,"
                "key_version,occurred_at_us,audit_sequence,previous_record_digest,record_digest) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    *(values[name] for name in _AUDIT_RECORD_COLUMNS),
                    record_digest,
                ),
            )
            cursor = conn.execute(
                "UPDATE authorization_tasks SET audit_event_count=?,audit_head_digest=? "
                "WHERE task_id=? AND audit_event_count=? AND audit_head_digest=?",
                (
                    sequence,
                    record_digest,
                    binding.task_id,
                    task_row["audit_event_count"],
                    task_row["audit_head_digest"],
                ),
            )
            if cursor.rowcount != 1:
                raise AuthorizationIntegrityError(
                    "authorization audit head update lost atomicity"
                )
            self._refresh_task_state(conn, binding.task_id)
        elif "record_digest" in audit_columns:
            conn.execute(
                "INSERT INTO authorization_audit_events "
                "(event_id,task_id,kind,reason_code,actor_token,target_token,request_digest,"
                "key_version,occurred_at_us,record_digest) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    *(values[name] for name in _AUDIT_RECORD_COLUMNS_V6),
                    self._audit_record_digest_v6(values),
                ),
            )
        else:
            conn.execute(
                "INSERT INTO authorization_audit_events "
                "(event_id,task_id,kind,reason_code,actor_token,target_token,request_digest,"
                "key_version,occurred_at_us) VALUES (?,?,?,?,?,?,?,?,?)",
                tuple(values[name] for name in _AUDIT_RECORD_COLUMNS_V6),
            )
        self._fault("audit.after")

    def _write(
        self,
        fn: Callable[[sqlite3.Connection], object],
        *,
        at_us: int,
    ) -> object:
        _epoch_us(at_us, "at_us")
        fence = self._fence
        if fence is None:
            raise CoordinatorFenceError("current coordinator fence required")
        last: Optional[BaseException] = None
        for attempt in range(MAX_RETRIES):
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._require_live_fence(conn, at_us)
                result = fn(conn)
                self._fault("commit.before")
                conn.execute("COMMIT")
                self._fault("commit.after")
                return result
            except sqlite3.OperationalError as exc:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                if not self._locked(exc) or attempt == MAX_RETRIES - 1:
                    raise
                last = exc
                time.sleep(random.uniform(0.005, 0.04))
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()
        raise last or AuthorizationStoreError("authorization store write failed")

    def _require_live_fence(self, conn: sqlite3.Connection, at_us: int) -> None:
        fence = self._fence
        lock = self._coordinator_lock
        if (
            fence is None
            or lock is None
            or not lock.is_live_for(
                self.coordinator_lock_path, self._lock_owner_token
            )
        ):
            raise CoordinatorFenceError("current coordinator fence required")
        live = conn.execute(
            "SELECT 1 FROM authorization_coordinator_lease WHERE singleton=1 "
            "AND owner_digest=? AND nonce_digest=? AND key_version=? AND epoch=? "
            "AND lease_expires_at_us>?",
            (
                fence.owner_digest,
                fence.nonce_digest,
                fence.key_version,
                fence.epoch,
                at_us,
            ),
        ).fetchone()
        if live is None:
            raise CoordinatorFenceError("coordinator epoch or lease is stale")

    def _insert_notification(
        self,
        conn: sqlite3.Connection,
        binding: TrustedAuthorizationBinding,
        notification: NotificationAttemptSpec,
        request_digest: str,
        *,
        retry_ordinal: int = 1,
        supersedes_attempt_id: Optional[str] = None,
    ) -> None:
        if (
            type(retry_ordinal) is not int
            or not 1 <= retry_ordinal <= MAX_NOTIFICATION_RETRY_ORDINAL
            or (retry_ordinal == 1) != (supersedes_attempt_id is None)
        ):
            raise ValueError("notification retry authority exceeds security bound")
        if supersedes_attempt_id is not None:
            _bounded(supersedes_attempt_id, "supersedes_attempt_id")
        if (
            notification.destination_profile != binding.approval_profile
            or notification.destination_account != binding.approval_account
            or notification.destination_chat != binding.approval_chat
            or notification.destination_thread != binding.approval_thread
        ):
            raise ValueError("notification destination must match immutable approval binding")
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
        values = {
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
            "challenge_nonce_digest": nonce_digest,
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
            "created_at_us": notification.created_at_us,
            "due_at_us": notification.due_at_us,
            "retry_ordinal": retry_ordinal,
            "supersedes_attempt_id": supersedes_attempt_id,
        }
        values["notification_spec_digest"] = self._notification_spec_digest(values)
        self._fault("notification.before")
        conn.execute(
            "INSERT INTO authorization_notification_attempts "
            "(attempt_id,task_id,correlation_id,kind,challenge_generation,destination_profile,"
            "destination_account,destination_chat,destination_thread,destination_digest,key_version,"
            "challenge_nonce_digest,nonce_verifier_version,challenge_state,notification_spec_digest,"
            "retry_ordinal,supersedes_attempt_id,challenge_record_digest,status,created_at_us,due_at_us,"
            "mutable_state_digest) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?,'')",
            (
                notification.attempt_id,
                binding.task_id,
                binding.correlation_id,
                notification.kind,
                notification.challenge_generation,
                notification.destination_profile,
                notification.destination_account,
                notification.destination_chat,
                notification.destination_thread,
                destination_digest,
                self._key_version,
                nonce_digest,
                "v2",
                "unaccepted",
                values["notification_spec_digest"],
                retry_ordinal,
                supersedes_attempt_id,
                self._challenge_record_digest(values),
                notification.created_at_us,
                notification.due_at_us,
            ),
        )
        self._fault("notification.after")
        self._audit_insert(
            conn,
            event_id=f"notification-created:{notification.attempt_id}",
            binding=binding,
            kind="notification_created",
            reason_code=notification.kind,
            actor_scope="host",
            actor_value="authorization-store",
            target_scope="notification-destination",
            target_value=destination_digest,
            request_digest=request_digest,
            at_us=notification.created_at_us,
        )
        self._refresh_notification_state(conn, notification.attempt_id)

    def create_pending(
        self,
        binding: TrustedAuthorizationBinding,
        *,
        request_key: str,
        notification: Optional[NotificationAttemptSpec] = None,
    ) -> MutationResult:
        _bounded(request_key, "request_key")
        if not binding.has_delivery_acceptance_binding:
            raise ValueError("new authorization tasks require a complete delivery binding")
        canonical = binding.canonical_bytes().decode("utf-8")
        binding_digest = self._binding_digest(binding)
        request_digest = self._request_digest(request_key, binding)

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            existing = conn.execute(
                "SELECT * FROM authorization_tasks WHERE task_id=? OR scoped_request_key=?",
                (binding.task_id, request_key),
            ).fetchall()
            if existing:
                for candidate in existing:
                    if self._verified_binding_for_task_row(conn, candidate) is None:
                        raise AuthorizationIntegrityError(
                            "authorization task collision failed integrity verification"
                        )
                if len(existing) == 1:
                    candidate = existing[0]
                    if (
                        candidate["key_version"] == self._key_version
                        and hmac.compare_digest(candidate["binding_digest"], binding_digest)
                        and hmac.compare_digest(candidate["request_digest"], request_digest)
                        and candidate["binding_json"] == canonical
                        and candidate["scoped_request_key"] == request_key
                    ):
                        return MutationResult(True, True, self._task(candidate))
                return MutationResult(False)
            self._fault("transition.before")
            conn.execute(
                "INSERT INTO authorization_tasks "
                "(task_id,correlation_id,scoped_request_key,binding_json,"
                "binding_digest,request_digest,key_version,status,created_at_us,"
                "expires_at_us,mutable_state_digest) "
                "VALUES (?,?,?,?,?,?,?,'approval_required',?,?,'')",
                (
                    binding.task_id,
                    binding.correlation_id,
                    request_key,
                    canonical,
                    binding_digest,
                    request_digest,
                    self._key_version,
                    binding.created_at_us,
                    binding.expires_at_us,
                ),
            )
            self._fault("transition.after")
            # Establish the authenticated empty audit head before the first
            # append; _audit_insert advances head/count and re-seals the task.
            self._refresh_task_state(conn, binding.task_id)
            self._audit_insert(
                conn,
                event_id=f"task-created:{binding.task_id}",
                binding=binding,
                kind="task_created",
                reason_code="created",
                actor_scope="source-user",
                actor_value=binding.source_user,
                target_scope="approval-user",
                target_value=binding.approval_user,
                request_digest=request_digest,
                at_us=binding.created_at_us,
            )
            if notification is not None:
                self._insert_notification(
                    conn, binding, notification, request_digest
                )
            row = conn.execute(
                "SELECT * FROM authorization_tasks WHERE task_id=?", (binding.task_id,)
            ).fetchone()
            return MutationResult(True, False, self._task(row))

        return self._write(mutate, at_us=binding.created_at_us)  # type: ignore[return-value]

    def create_notification(
        self,
        task_id: str,
        binding: TrustedAuthorizationBinding,
        notification: NotificationAttemptSpec,
    ) -> MutationResult:
        """Append one explicit challenge generation to an existing pending task."""

        def mutate(conn: sqlite3.Connection) -> MutationResult:
            row = self._exact_row(conn, task_id, binding)
            if (
                row is None
                or row["status"] != "approval_required"
                or notification.created_at_us >= row["expires_at_us"]
            ):
                return MutationResult(False)
            existing = conn.execute(
                "SELECT * FROM authorization_notification_attempts "
                "WHERE attempt_id=? OR (task_id=? AND kind=? AND challenge_generation=?)",
                (
                    notification.attempt_id,
                    task_id,
                    notification.kind,
                    notification.challenge_generation,
                ),
            ).fetchall()
            if existing:
                return MutationResult(False)
            self._insert_notification(
                conn, binding, notification, row["request_digest"]
            )
            return MutationResult(True, False, self._task(row))

        return self._write(mutate, at_us=notification.created_at_us)  # type: ignore[return-value]

    def _exact_row(
        self, conn: sqlite3.Connection, task_id: str, binding: TrustedAuthorizationBinding
    ) -> Optional[sqlite3.Row]:
        if type(binding) is not TrustedAuthorizationBinding or task_id != binding.task_id:
            return None
        row = conn.execute(
            "SELECT * FROM authorization_tasks WHERE task_id=?",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        if (
            not self._task_state_matches(row)
            or not self._audit_chain_matches(conn, row)
            or not self._task_transition_audit_matches(conn, row, binding)
            or
            type(row["task_id"]) is not str
            or type(row["correlation_id"]) is not str
            or type(row["scoped_request_key"]) is not str
            or type(row["binding_json"]) is not str
            or type(row["binding_digest"]) is not str
            or type(row["request_digest"]) is not str
            or type(row["key_version"]) is not str
            or row["task_id"] != binding.task_id
            or row["correlation_id"] != binding.correlation_id
            or row["created_at_us"] != binding.created_at_us
            or row["expires_at_us"] != binding.expires_at_us
        ):
            return None
        expected_binding = self._binding_digest(binding)
        expected_request = self._request_digest(row["scoped_request_key"], binding)
        if (
            row["key_version"] != self._key_version
            or row["binding_json"] != binding.canonical_bytes().decode("utf-8")
            or not hmac.compare_digest(row["binding_digest"], expected_binding)
            or not hmac.compare_digest(row["request_digest"], expected_request)
        ):
            return None
        if row["status"] == "consumed" and (
            row["send_started_at_us"] is None
            or row["receipt_token"] is None
            or row["delivery_acceptance_status"] != "provider_accepted"
            or row["delivery_accepted_at_us"] is None
            or row["delivery_accepted_at_us"] < row["send_started_at_us"]
            or row["completed_at_us"] is None
            or row["delivery_accepted_at_us"] > row["completed_at_us"]
            or row["delivery_transport_implementation"]
            != binding.delivery_transport_implementation
            or row["delivery_runtime_identity"] != binding.delivery_runtime_identity
            or row["delivery_account_binding_token"] is None
            or not hmac.compare_digest(
                row["delivery_account_binding_token"],
                self._account_binding_token(binding.delivery_account_binding),
            )
            or row["delivery_connection_epoch"] != binding.delivery_connection_epoch
            or row["delivery_record_digest"] is None
            or not hmac.compare_digest(
                row["delivery_record_digest"],
                self._delivery_record_digest(row, binding),
            )
        ):
            return None
        return row

    def _task_transition_audit_matches(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        binding: TrustedAuthorizationBinding,
        *,
        require_current_state: bool = True,
    ) -> bool:
        status = row["status"]
        if status not in {"approval_required", "approved", "claimed"}:
            return True
        if status == "approval_required":
            event_id = f"task-created:{row['task_id']}"
            expected = (
                row["task_id"], "task_created", "created",
                self.audit_token("source-user", binding.source_user),
                self.audit_token("approval-user", binding.approval_user),
                row["request_digest"], self._key_version, row["created_at_us"],
            )
        elif status == "approved":
            if (
                type(row["decision_id"]) is not str
                or type(row["decision_digest"]) is not str
                or type(row["winning_challenge_attempt_id"]) is not str
                or type(row["winning_challenge_generation"]) is not int
                or type(row["resolution_spec_digest"]) is not str
            ):
                return False
            event_id = f"task-approved:{row['decision_id']}"
            expected = (
                row["task_id"], "task_approved", "owner_approved",
                self.audit_token("approval-user", binding.approval_user),
                self.audit_token("source-user", binding.source_user),
                row["request_digest"], self._key_version, None,
            )
        else:
            if (
                type(row["claim_owner_digest"]) is not str
                or type(row["claim_nonce_digest"]) is not str
                or type(row["claim_generation"]) is not int
                or type(row["claimed_at_us"]) is not int
            ):
                return False
            event_id = f"task-claimed:{row['task_id']}:{row['claim_generation']}"
            expected = (
                row["task_id"], "task_claimed", "claim_acquired",
                self.audit_token("claim-owner", row["claim_owner_digest"]),
                self.audit_token("delivery-chat", binding.delivery_chat),
                row["request_digest"], self._key_version, row["claimed_at_us"],
            )
        audit = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE event_id=?", (event_id,)
        ).fetchone()
        if not self._audit_record_matches(audit):
            return False
        actual = (
            audit["task_id"], audit["kind"], audit["reason_code"],
            audit["actor_token"], audit["target_token"], audit["request_digest"],
            audit["key_version"], audit["occurred_at_us"],
        )
        matched = actual[:-1] == expected[:-1] if expected[-1] is None else actual == expected
        if status == "approved":
            return matched and self._approved_task_evidence_chain_matches(
                conn, row, require_current_state=require_current_state
            )
        return matched

    def _approved_task_evidence_chain_matches(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        require_current_state: bool,
    ) -> bool:
        challenge = conn.execute(
            "SELECT * FROM authorization_notification_attempts WHERE attempt_id=?",
            (row["winning_challenge_attempt_id"],),
        ).fetchone()
        resolutions = conn.execute(
            "SELECT * FROM authorization_notification_attempts WHERE task_id=? "
            "AND kind='approval_resolution' AND challenge_generation=?",
            (row["task_id"], row["winning_challenge_generation"]),
        ).fetchall()
        original_resolutions = [
            item
            for item in resolutions
            if item["notification_spec_digest"] == row["resolution_spec_digest"]
            and item["retry_ordinal"] == 1
            and item["supersedes_attempt_id"] is None
        ]
        decision_audit = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE event_id=?",
            (f"task-approved:{row['decision_id']}",),
        ).fetchone()
        if challenge is None or len(original_resolutions) != 1 or decision_audit is None:
            return False
        resolution = original_resolutions[0]
        challenge_created = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE event_id=?",
            (f"notification-created:{challenge['attempt_id']}",),
        ).fetchone()
        challenge_finished = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE event_id=?",
            (
                f"notification-finished:{challenge['attempt_id']}:"
                f"{challenge['claim_generation']}",
            ),
        ).fetchone()
        resolution_created = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE event_id=?",
            (f"notification-created:{resolution['attempt_id']}",),
        ).fetchone()
        try:
            state_ok = not require_current_state or (
                self._notification_state_matches(challenge)
                and self._notification_state_matches(resolution)
            )
            return (
                state_ok
                and challenge["task_id"] == row["task_id"]
                and challenge["kind"] == "approval_challenge"
                and challenge["challenge_generation"]
                == row["winning_challenge_generation"]
                and challenge["status"] == "provider_accepted"
                and challenge["provider_acceptance_status"] == "provider_accepted"
                and challenge["challenge_state"] == "consumed"
                and challenge["challenge_decision_digest"] == row["decision_digest"]
                and challenge["challenge_resolved_at_us"]
                == decision_audit["occurred_at_us"]
                and hmac.compare_digest(
                    challenge["notification_spec_digest"],
                    self._notification_spec_digest(challenge),
                )
                and hmac.compare_digest(
                    challenge["challenge_record_digest"],
                    self._challenge_record_digest(challenge),
                )
                and resolution["kind"] == "approval_resolution"
                and resolution["created_at_us"] == decision_audit["occurred_at_us"]
                and hmac.compare_digest(
                    row["resolution_spec_digest"], resolution["notification_spec_digest"]
                )
                and hmac.compare_digest(
                    resolution["notification_spec_digest"],
                    self._notification_spec_digest(resolution),
                )
                and hmac.compare_digest(
                    resolution["challenge_record_digest"],
                    self._challenge_record_digest(resolution),
                )
                and self._audit_record_matches(challenge_created)
                and self._audit_record_matches(challenge_finished)
                and self._audit_record_matches(resolution_created)
                and (
                    challenge_created["task_id"], challenge_created["kind"],
                    challenge_created["reason_code"], challenge_created["actor_token"],
                    challenge_created["target_token"], challenge_created["request_digest"],
                    challenge_created["key_version"], challenge_created["occurred_at_us"],
                ) == (
                    row["task_id"], "notification_created", "approval_challenge",
                    self.audit_token("host", "authorization-store"),
                    self.audit_token(
                        "notification-destination", challenge["destination_digest"]
                    ),
                    row["request_digest"], self._key_version, challenge["created_at_us"],
                )
                and (
                    challenge_finished["task_id"], challenge_finished["kind"],
                    challenge_finished["reason_code"], challenge_finished["actor_token"],
                    challenge_finished["target_token"], challenge_finished["request_digest"],
                    challenge_finished["key_version"], challenge_finished["occurred_at_us"],
                ) == (
                    row["task_id"], "notification_provider_accepted",
                    "provider_accepted",
                    self.audit_token("claim-owner", challenge["claim_owner_digest"]),
                    self.audit_token("notification", challenge["attempt_id"]),
                    row["request_digest"], self._key_version, challenge["completed_at_us"],
                )
                and (
                    resolution_created["task_id"], resolution_created["kind"],
                    resolution_created["reason_code"], resolution_created["actor_token"],
                    resolution_created["target_token"], resolution_created["request_digest"],
                    resolution_created["key_version"], resolution_created["occurred_at_us"],
                ) == (
                    row["task_id"], "notification_created", "approval_resolution",
                    self.audit_token("host", "authorization-store"),
                    self.audit_token(
                        "notification-destination", resolution["destination_digest"]
                    ),
                    row["request_digest"], self._key_version, resolution["created_at_us"],
                )
            )
        except (KeyError, IndexError, TypeError, ValueError, OverflowError, UnicodeError):
            return False

    def _notification_transition_audit_matches(
        self, conn: sqlite3.Connection, row: sqlite3.Row
    ) -> bool:
        status = row["status"]
        if status not in {"pending", "claimed"}:
            return True
        task = conn.execute(
            "SELECT request_digest FROM authorization_tasks WHERE task_id=?",
            (row["task_id"],),
        ).fetchone()
        if task is None:
            return False
        request_digest = task["request_digest"]
        if status == "pending":
            event_id = f"notification-created:{row['attempt_id']}"
            expected = (
                row["task_id"], "notification_created", row["kind"],
                self.audit_token("host", "authorization-store"),
                self.audit_token("notification-destination", row["destination_digest"]),
                None, self._key_version, row["created_at_us"],
            )
        else:
            if (
                type(row["claim_owner_digest"]) is not str
                or type(row["claim_nonce_digest"]) is not str
                or type(row["claim_generation"]) is not int
            ):
                return False
            claimed_id = f"notification-claimed:{row['attempt_id']}:{row['claim_generation']}"
            reclaimed_id = f"notification-reclaimed:{row['attempt_id']}:{row['claim_generation']}"
            audit = conn.execute(
                "SELECT * FROM authorization_audit_events WHERE event_id IN (?,?)",
                (claimed_id, reclaimed_id),
            ).fetchone()
            if not self._audit_record_matches(audit):
                return False
            expected_kind = (
                "notification_claimed" if audit["event_id"] == claimed_id
                else "notification_reclaimed"
            )
            expected_reason = (
                "claim_acquired" if expected_kind == "notification_claimed"
                else "stale_pre_send_claim"
            )
            return (
                audit["task_id"], audit["kind"], audit["reason_code"],
                audit["actor_token"], audit["target_token"], audit["request_digest"],
                audit["key_version"],
            ) == (
                row["task_id"], expected_kind, expected_reason,
                self.audit_token("claim-owner", row["claim_owner_digest"]),
                self.audit_token("notification", row["attempt_id"]),
                request_digest, self._key_version,
            )
        audit = conn.execute(
            "SELECT * FROM authorization_audit_events WHERE event_id=?", (event_id,)
        ).fetchone()
        if not self._audit_record_matches(audit):
            return False
        expected = expected[:5] + (request_digest,) + expected[6:]
        return (
            audit["task_id"], audit["kind"], audit["reason_code"],
            audit["actor_token"], audit["target_token"], audit["request_digest"],
            audit["key_version"], audit["occurred_at_us"],
        ) == expected

    def _verified_binding_for_task_row(
        self, conn: sqlite3.Connection, row: sqlite3.Row
    ) -> Optional[TrustedAuthorizationBinding]:
        try:
            binding = self._binding_from_json(row["binding_json"])
            exact = self._exact_row(conn, row["task_id"], binding)
        except (TypeError, ValueError, KeyError, json.JSONDecodeError, UnicodeError):
            return None
        return binding if exact is not None else None

    @staticmethod
    def _task_work_item(
        row: sqlite3.Row,
        binding: TrustedAuthorizationBinding,
    ) -> AuthorizationTaskWorkItem:
        return AuthorizationTaskWorkItem(
            binding=binding,
            task=AuthorizationTaskStore._task(row),
            key_version=row["key_version"],
            binding_digest=row["binding_digest"],
        )

    def load_task_work_item(
        self, task_id: str, *, now_us: int
    ) -> AuthorizationTaskWorkItem:
        """Load one authenticated worker view or fail closed on corruption.

        An unknown identifier raises ``KeyError``. A present row that cannot be
        reconstructed and authenticated raises ``AuthorizationIntegrityError``;
        corruption is never represented as absence or authority.
        """
        _bounded(task_id, "task_id")
        _epoch_us(now_us, "now_us")
        conn = self._connect()
        try:
            conn.execute("BEGIN")
            self._require_live_fence(conn, now_us)
            row = conn.execute(
                "SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if row is None:
                raise KeyError("authorization task not found")
            binding = self._verified_binding_for_task_row(conn, row)
            if binding is None:
                raise AuthorizationIntegrityError(
                    "authorization task failed integrity verification"
                )
            try:
                return self._task_work_item(row, binding)
            except (TypeError, ValueError):
                raise AuthorizationIntegrityError(
                    "authorization task failed integrity verification"
                ) from None
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            conn.close()

    def list_approved_task_work_items(
        self, *, now_us: int, limit: int = 100
    ) -> list[AuthorizationTaskWorkItem]:
        """Return current authenticated approved work, never expired history."""
        _epoch_us(now_us, "now_us")
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        conn = self._connect()
        try:
            conn.execute("BEGIN")
            self._require_live_fence(conn, now_us)
            rows = conn.execute(
                "SELECT * FROM authorization_tasks WHERE status='approved' "
                "AND expires_at_us>? ORDER BY created_at_us,task_id LIMIT ?",
                (now_us, limit),
            ).fetchall()
            work: list[AuthorizationTaskWorkItem] = []
            for row in rows:
                binding = self._verified_binding_for_task_row(conn, row)
                if binding is None:
                    raise AuthorizationIntegrityError(
                        "authorization task list failed integrity verification"
                    )
                try:
                    work.append(self._task_work_item(row, binding))
                except (TypeError, ValueError):
                    raise AuthorizationIntegrityError(
                        "authorization task list failed integrity verification"
                    ) from None
            return work
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            conn.close()

    def load_task(
        self, task_id: str, binding: TrustedAuthorizationBinding
    ) -> AuthorizationTask:
        _bounded(task_id, "task_id")
        conn = self._connect()
        try:
            present = conn.execute(
                "SELECT 1 FROM authorization_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if present is None:
                raise KeyError("authorization task not found")
            row = self._exact_row(conn, task_id, binding)
            if row is None:
                raise AuthorizationIntegrityError(
                    "authorization task failed integrity verification"
                )
            return self._task(row)
        finally:
            conn.close()

    def list_tasks(
        self, *, status: str, due_before_us: int, now_us: int, limit: int = 100
    ) -> list[AuthorizationTask]:
        if status not in TASK_TRANSITIONS:
            raise ValueError("unsupported authorization task status")
        _epoch_us(due_before_us, "due_before_us")
        _epoch_us(now_us, "now_us")
        if not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        conn = self._connect()
        try:
            self._require_live_fence(conn, now_us)
            rows = conn.execute(
                "SELECT * FROM authorization_tasks WHERE status=? AND expires_at_us<=? "
                "ORDER BY expires_at_us,task_id LIMIT ?",
                (status, due_before_us, limit),
            ).fetchall()
            verified: list[AuthorizationTask] = []
            for row in rows:
                try:
                    binding = self._binding_from_json(row["binding_json"])
                except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                    raise AuthorizationIntegrityError(
                        "authorization task list failed integrity verification"
                    ) from None
                exact = self._exact_row(conn, row["task_id"], binding)
                if exact is None:
                    raise AuthorizationIntegrityError(
                        "authorization task list failed integrity verification"
                    )
                verified.append(self._task(exact))
            return verified
        finally:
            conn.close()

    def list_audit_events(self, *, task_id: str, limit: int = 100) -> list[AuditEvent]:
        _bounded(task_id, "task_id")
        if not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        conn = self._connect()
        try:
            task_row = conn.execute(
                "SELECT * FROM authorization_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if task_row is None:
                return []
            try:
                binding = self._binding_from_json(task_row["binding_json"])
            except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                raise AuthorizationIntegrityError(
                    "authorization audit task failed integrity verification"
                ) from None
            exact = self._exact_row(conn, task_id, binding)
            if exact is None:
                raise AuthorizationIntegrityError(
                    "authorization audit task failed integrity verification"
                )
            rows = conn.execute(
                "SELECT * FROM authorization_audit_events WHERE task_id=? "
                "ORDER BY audit_sequence LIMIT ?",
                (task_id, limit),
            ).fetchall()
            events: list[AuditEvent] = []
            for row in rows:
                if (
                    row["request_digest"] != exact["request_digest"]
                    or row["key_version"] != self._key_version
                    or not self._audit_record_matches(row)
                ):
                    raise AuthorizationIntegrityError(
                        "authorization audit list failed integrity verification"
                    )
                events.append(
                    AuditEvent(**{name: row[name] for name in _AUDIT_RECORD_COLUMNS})
                )
            return events
        finally:
            conn.close()

    def _reconcile_restart_in_transaction(
        self, conn: sqlite3.Connection, *, now_us: int
    ) -> ReconciliationReport:
        task_rows = conn.execute(
            "SELECT * FROM authorization_tasks WHERE status='claimed'"
        ).fetchall()
        notification_rows = conn.execute(
            "SELECT n.*,t.binding_json,t.request_digest "
            "FROM authorization_notification_attempts n "
            "JOIN authorization_tasks t ON t.task_id=n.task_id "
            "WHERE n.status='claimed' AND n.send_started_at_us IS NOT NULL"
        ).fetchall()
        task_count = 0
        for row in task_rows:
            try:
                binding = self._binding_from_json(row["binding_json"])
            except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                raise AuthorizationIntegrityError(
                    "authorization restart reconciliation failed integrity verification"
                ) from None
            if self._exact_row(conn, row["task_id"], binding) is None:
                raise AuthorizationIntegrityError(
                    "authorization restart reconciliation failed integrity verification"
                )
            self._fault("transition.before")
            cursor = conn.execute(
                "UPDATE authorization_tasks SET status='failed_consumed',completed_at_us=?,"
                "receipt_code='ambiguous_after_restart',version=version+1 WHERE task_id=? "
                "AND status='claimed'",
                (now_us, row["task_id"]),
            )
            self._fault("transition.after")
            if cursor.rowcount:
                self._refresh_task_state(conn, row["task_id"])
                task_count += 1
                self._audit_insert(
                    conn,
                    event_id=f"task-reconciled:{row['task_id']}:{row['version'] + 1}",
                    binding=binding,
                    kind="task_failed_consumed",
                    reason_code="ambiguous_after_restart",
                    actor_scope="host",
                    actor_value="authorization-store",
                    target_scope="delivery-chat",
                    target_value=binding.delivery_chat,
                    request_digest=row["request_digest"],
                    at_us=now_us,
                )
        notification_count = 0
        for row in notification_rows:
            verified_notification = self._notification_with_task(
                conn, row["attempt_id"]
            )
            if verified_notification is None:
                raise AuthorizationIntegrityError(
                    "authorization restart reconciliation failed integrity verification"
                )
            binding = self._binding_from_json(row["binding_json"])
            self._fault("notification.before")
            cursor = conn.execute(
                "UPDATE authorization_notification_attempts SET status='failed',completed_at_us=?,"
                "receipt_code='ambiguous_after_restart',version=version+1 WHERE attempt_id=? "
                "AND status='claimed' AND send_started_at_us IS NOT NULL",
                (now_us, row["attempt_id"]),
            )
            self._fault("notification.after")
            if not cursor.rowcount:
                continue
            self._refresh_notification_state(conn, row["attempt_id"])
            notification_count += 1
            self._audit_insert(
                conn,
                event_id=f"notification-reconciled:{row['attempt_id']}:{row['version'] + 1}",
                binding=binding,
                kind="notification_failed",
                reason_code="ambiguous_after_restart",
                actor_scope="host",
                actor_value="authorization-store",
                target_scope="notification",
                target_value=row["attempt_id"],
                request_digest=row["request_digest"],
                at_us=now_us,
            )
        return ReconciliationReport(task_count, notification_count)

    def reconcile_restart(self, *, now_us: int) -> ReconciliationReport:
        """Burn every sensitive task claim after coordinator loss.

        Notification claims retain their separate ADR rule: only a crossed
        send-start fence burns them; stale pre-send notification reclaim stays
        available through its focused selector and exact transition.
        """

        _epoch_us(now_us, "now_us")
        return self._write(
            lambda conn: self._reconcile_restart_in_transaction(conn, now_us=now_us),
            at_us=now_us,
        )  # type: ignore[return-value]
