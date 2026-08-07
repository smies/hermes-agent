"""Durable, host-owned Juno conversation to Kite context mappings."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import hmac
import os
import secrets
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class MappingSecurityError(RuntimeError):
    """The mapping database cannot be used without weakening its boundary."""


@dataclass(frozen=True)
class MappingRecord:
    principal: str
    conversation_digest: str
    context_id: str
    correlation_id: str


@dataclass(frozen=True)
class RequestRecord:
    request_id: str
    context_id: str
    correlation_id: str
    policy_generation: str
    expires_at: int
    state: str
    action_fingerprint: str
    audience_digest: str
    conversation_binding: str
    read_capability_fingerprint: str
    action_capability_fingerprint: str
    roster_generation: str


class MappingStore:
    """One narrow SQLite store for mappings and their replay ledger.

    The canonical Juno conversation key is HMACed before storage.  No prompt,
    handoff text, transcript, tool result, platform ID, or credential is ever
    accepted by this API.
    """

    _LOCK_TIMEOUT_SECONDS = 30.0

    def __init__(self, path: str | Path, mapping_key: bytes):
        self.path = Path(path).expanduser()
        if len(mapping_key) < 32:
            raise MappingSecurityError("mapping key must contain at least 32 bytes")
        self._mapping_key = bytes(mapping_key)
        self._lock = threading.RLock()
        self._fd, self._identity = self._open_secure_path()
        self._db: Optional[sqlite3.Connection] = None
        try:
            self._db = self._new_memory_connection()
            self._create_schema()
        except Exception:
            if self._db is not None:
                self._db.close()
            os.close(self._fd)
            raise

    @staticmethod
    def _new_memory_connection() -> sqlite3.Connection:
        """Create SQLite's ephemeral working copy, never a pathname connection."""
        db = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout = 30000")
        db.execute("PRAGMA journal_mode = MEMORY")
        db.execute("PRAGMA synchronous = FULL")
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def _acquire_file_lock(self) -> None:
        deadline = time.monotonic() + self._LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise
                if time.monotonic() >= deadline:
                    raise MappingSecurityError("mapping database lock timed out") from exc
                time.sleep(0.01)

    def _reload_locked(self) -> None:
        """Load the authenticated inode into the ephemeral SQLite connection."""
        info = os.fstat(self._fd)
        self._validate_file_info(info)
        size = info.st_size
        chunks = []
        offset = 0
        while offset < size:
            chunk = os.pread(self._fd, min(1024 * 1024, size - offset), offset)
            if not chunk:
                raise MappingSecurityError("mapping database could not be read completely")
            chunks.append(chunk)
            offset += len(chunk)

        if self._db is not None:
            self._db.close()
        self._db = self._new_memory_connection()
        if chunks:
            try:
                self._db.deserialize(b"".join(chunks))
            except sqlite3.DatabaseError as exc:
                raise MappingSecurityError("mapping database is not valid SQLite") from exc
            self._db.execute("PRAGMA foreign_keys = ON")

    def _persist_locked(self) -> None:
        """Durably replace bytes on the authenticated fd, never through its path."""
        assert self._db is not None
        data = self._db.serialize()
        offset = 0
        while offset < len(data):
            written = os.pwrite(self._fd, data[offset:], offset)
            if written <= 0:
                raise MappingSecurityError("mapping database could not be written completely")
            offset += written
        os.ftruncate(self._fd, len(data))
        os.fsync(self._fd)

    @contextmanager
    def _database(self, *, write: bool):
        """Serialize every store operation around the authenticated inode."""
        with self._lock:
            self._acquire_file_lock()
            try:
                self._validate_path_identity(self._identity)
                self._reload_locked()
                assert self._db is not None
                yield self._db
                if write:
                    self._validate_path_identity(self._identity)
                    self._persist_locked()
            finally:
                fcntl.flock(self._fd, fcntl.LOCK_UN)

    @staticmethod
    def _validate_owner_only_directory(path: Path) -> None:
        try:
            info = path.lstat()
        except OSError as exc:
            raise MappingSecurityError("mapping parent cannot be inspected") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise MappingSecurityError("mapping parent must be a real directory")
        if info.st_uid != os.geteuid():
            raise MappingSecurityError("mapping parent must be owned by the current user")
        mode = stat.S_IMODE(info.st_mode)
        if mode != 0o700:
            raise MappingSecurityError(
                f"mapping directory must be owner-only (0700), found {mode:04o}"
            )

    @staticmethod
    def _validate_file_info(info: os.stat_result) -> None:
        if not stat.S_ISREG(info.st_mode):
            raise MappingSecurityError("mapping database must be a regular file")
        if info.st_uid != os.geteuid():
            raise MappingSecurityError("mapping database must be owned by the current user")
        mode = stat.S_IMODE(info.st_mode)
        if mode != 0o600:
            raise MappingSecurityError(
                f"mapping database must be owner-only (0600), found {mode:04o}"
            )
        if info.st_nlink != 1:
            raise MappingSecurityError("mapping database must have exactly one hard link")

    def _open_secure_path(self) -> tuple[int, tuple[int, int]]:
        parent = self.path.parent
        try:
            parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise MappingSecurityError("mapping parent cannot be created") from exc
        self._validate_owner_only_directory(parent)

        nofollow = getattr(os, "O_NOFOLLOW", 0)
        base_flags = os.O_RDWR | nofollow
        try:
            try:
                fd = os.open(self.path, base_flags | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                try:
                    existing = self.path.lstat()
                except OSError as exc:
                    raise MappingSecurityError(
                        "mapping database changed before secure open"
                    ) from exc
                if stat.S_ISLNK(existing.st_mode):
                    raise MappingSecurityError(
                        "mapping database may not be a symbolic link"
                    )
                self._validate_file_info(existing)
                fd = os.open(self.path, base_flags)
        except OSError as exc:
            raise MappingSecurityError("mapping database cannot be securely opened") from exc
        try:
            info = os.fstat(fd)
            self._validate_file_info(info)
            self._validate_path_identity((info.st_dev, info.st_ino))
            return fd, (info.st_dev, info.st_ino)
        except Exception:
            os.close(fd)
            raise

    def _validate_path_identity(self, identity: tuple[int, int]) -> None:
        try:
            info = self.path.lstat()
        except OSError as exc:
            raise MappingSecurityError("mapping database path cannot be inspected") from exc
        if stat.S_ISLNK(info.st_mode):
            raise MappingSecurityError("mapping database may not be a symbolic link")
        self._validate_file_info(info)
        if (info.st_dev, info.st_ino) != identity:
            raise MappingSecurityError("mapping database path changed during secure open")

    def _create_schema(self) -> None:
        with self._database(write=True) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    """
                CREATE TABLE IF NOT EXISTS mappings (
                    principal TEXT NOT NULL,
                    conversation_digest TEXT NOT NULL,
                    context_id TEXT NOT NULL UNIQUE,
                    correlation_id TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                    PRIMARY KEY (principal, conversation_digest)
                )
                    """
                )
                columns = {
                    str(row[1])
                    for row in db.execute("PRAGMA table_info(request_ledger)").fetchall()
                }
                legacy_columns = {
                    "request_id", "context_id", "correlation_id",
                    "policy_generation", "expires_at", "state",
                    "action_fingerprint", "created_at",
                }
                current_columns = legacy_columns | {
                    "audience_digest", "conversation_binding",
                    "read_capability_fingerprint", "action_capability_fingerprint",
                    "roster_generation",
                }
                if (
                    columns
                    and columns != legacy_columns
                    and columns != current_columns
                ):
                    raise MappingSecurityError("mapping request schema is not recognized")
                if columns == legacy_columns:
                    # The v1 envelope has no authenticated audience authority.
                    # Preserve its history, but terminally abort every state
                    # that could otherwise be replayed after migration.
                    db.execute("ALTER TABLE request_ledger RENAME TO request_ledger_v1")
                if not columns or columns == legacy_columns:
                    db.execute(
                        """
                CREATE TABLE request_ledger (
                    request_id TEXT PRIMARY KEY,
                    context_id TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    policy_generation TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK (
                        state IN ('issued', 'bound', 'released', 'consumed', 'aborted')
                    ),
                    action_fingerprint TEXT NOT NULL DEFAULT '',
                    audience_digest TEXT NOT NULL DEFAULT '',
                    conversation_binding TEXT NOT NULL DEFAULT '',
                    read_capability_fingerprint TEXT NOT NULL DEFAULT '',
                    action_capability_fingerprint TEXT NOT NULL DEFAULT '',
                    roster_generation TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                    FOREIGN KEY (context_id) REFERENCES mappings(context_id)
                )
                        """
                    )
                if columns == legacy_columns:
                    db.execute(
                        """
                        INSERT INTO request_ledger (
                            request_id, context_id, correlation_id,
                            policy_generation, expires_at, state,
                            action_fingerprint, created_at
                        )
                        SELECT request_id, context_id, correlation_id,
                               policy_generation, expires_at,
                               CASE WHEN state = 'consumed' THEN 'consumed' ELSE 'aborted' END,
                               action_fingerprint, created_at
                        FROM request_ledger_v1
                        """
                    )
                    db.execute("DROP TABLE request_ledger_v1")
                db.execute("DROP INDEX IF EXISTS request_ledger_context")
                db.execute(
                    """
                CREATE INDEX IF NOT EXISTS request_ledger_context
                    ON request_ledger(context_id, state)
                    """
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def _conversation_digest(self, principal: str, conversation_key: str) -> str:
        material = f"{principal}\0{conversation_key}".encode("utf-8")
        return hmac.new(self._mapping_key, material, hashlib.sha256).hexdigest()

    @staticmethod
    def _mapping_from_row(row: sqlite3.Row) -> MappingRecord:
        return MappingRecord(
            principal=str(row["principal"]),
            conversation_digest=str(row["conversation_digest"]),
            context_id=str(row["context_id"]),
            correlation_id=str(row["correlation_id"]),
        )

    @staticmethod
    def _request_from_row(row: sqlite3.Row) -> RequestRecord:
        return RequestRecord(
            request_id=str(row["request_id"]),
            context_id=str(row["context_id"]),
            correlation_id=str(row["correlation_id"]),
            policy_generation=str(row["policy_generation"]),
            expires_at=int(row["expires_at"]),
            state=str(row["state"]),
            action_fingerprint=str(row["action_fingerprint"]),
            audience_digest=str(row["audience_digest"]),
            conversation_binding=str(row["conversation_binding"]),
            read_capability_fingerprint=str(row["read_capability_fingerprint"]),
            action_capability_fingerprint=str(row["action_capability_fingerprint"]),
            roster_generation=str(row["roster_generation"]),
        )

    def resolve(self, principal: str, conversation_key: str) -> MappingRecord:
        principal = str(principal or "").strip()
        conversation_key = str(conversation_key or "").strip()
        if not principal or not conversation_key:
            raise ValueError("principal and conversation key are required")
        digest = self._conversation_digest(principal, conversation_key)
        with self._database(write=True) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT * FROM mappings WHERE principal = ? AND conversation_digest = ?",
                    (principal, digest),
                ).fetchone()
                if row is None:
                    db.execute(
                        """INSERT OR IGNORE INTO mappings
                           (principal, conversation_digest, context_id, correlation_id)
                           VALUES (?, ?, ?, ?)""",
                        (
                            principal,
                            digest,
                            "jk-" + secrets.token_urlsafe(24),
                            "corr-" + secrets.token_urlsafe(12),
                        ),
                    )
                    row = db.execute(
                        "SELECT * FROM mappings WHERE principal = ? AND conversation_digest = ?",
                        (principal, digest),
                    ).fetchone()
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        if row is None:  # pragma: no cover - protected by the transaction
            raise RuntimeError("mapping creation failed")
        return self._mapping_from_row(row)

    def get_by_context(self, context_id: str) -> Optional[MappingRecord]:
        with self._database(write=False) as db:
            row = db.execute(
                "SELECT * FROM mappings WHERE context_id = ?", (str(context_id),)
            ).fetchone()
        return self._mapping_from_row(row) if row is not None else None

    def issue_request(
        self,
        mapping: MappingRecord,
        request_id: str,
        policy_generation: str,
        expires_at: int,
        audience_digest: str = "",
        conversation_binding: str = "",
        read_capability_fingerprint: str = "",
        action_capability_fingerprint: str = "",
        roster_generation: str = "",
    ) -> None:
        with self._database(write=True) as db:
            db.execute(
                """INSERT INTO request_ledger
                   (request_id, context_id, correlation_id, policy_generation, expires_at, state,
                    audience_digest, conversation_binding, read_capability_fingerprint,
                    action_capability_fingerprint, roster_generation)
                   VALUES (?, ?, ?, ?, ?, 'issued', ?, ?, ?, ?, ?)""",
                (
                    request_id,
                    mapping.context_id,
                    mapping.correlation_id,
                    policy_generation,
                    int(expires_at),
                    audience_digest,
                    conversation_binding,
                    read_capability_fingerprint,
                    action_capability_fingerprint,
                    roster_generation,
                ),
            )

    def claim_request(
        self,
        request_id: str,
        context_id: str,
        correlation_id: str,
        policy_generation: str,
        now: int,
        audience_digest: str = "",
        conversation_binding: str = "",
        read_capability_fingerprint: str = "",
        action_capability_fingerprint: str = "",
        roster_generation: str = "",
    ) -> Optional[RequestRecord]:
        with self._database(write=True) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                changed = db.execute(
                    """UPDATE request_ledger SET state = 'bound'
                       WHERE request_id = ? AND context_id = ? AND correlation_id = ?
                         AND policy_generation = ? AND expires_at > ? AND state = 'issued'
                         AND audience_digest = ? AND conversation_binding = ?
                         AND read_capability_fingerprint = ?
                         AND action_capability_fingerprint = ?
                         AND roster_generation = ?""",
                    (
                        request_id, context_id, correlation_id, policy_generation, int(now),
                        audience_digest, conversation_binding,
                        read_capability_fingerprint, action_capability_fingerprint,
                        roster_generation,
                    ),
                ).rowcount
                row = db.execute(
                    "SELECT * FROM request_ledger WHERE request_id = ?", (request_id,)
                ).fetchone()
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return self._request_from_row(row) if changed == 1 and row is not None else None

    def get_request(self, request_id: str) -> Optional[RequestRecord]:
        with self._database(write=False) as db:
            row = db.execute(
                "SELECT * FROM request_ledger WHERE request_id = ?", (request_id,)
            ).fetchone()
        return self._request_from_row(row) if row is not None else None

    def count_records(self) -> tuple[int, int]:
        """Return opaque mapping/request counts for provider-free canaries."""
        with self._database(write=False) as db:
            mappings = int(db.execute("SELECT COUNT(*) FROM mappings").fetchone()[0])
            requests = int(
                db.execute("SELECT COUNT(*) FROM request_ledger").fetchone()[0]
            )
        return mappings, requests

    def request_state_counts(self) -> dict[str, int]:
        """Return state-only request totals without exposing ledger identifiers."""
        with self._database(write=False) as db:
            rows = db.execute(
                "SELECT state, COUNT(*) AS count FROM request_ledger GROUP BY state"
            ).fetchall()
        return {str(row["state"]): int(row["count"]) for row in rows}

    def claim_action(self, request_id: str, fingerprint: str, now: int) -> bool:
        with self._database(write=True) as db:
            changed = db.execute(
                """UPDATE request_ledger SET action_fingerprint = ?
                   WHERE request_id = ? AND state = 'bound' AND action_fingerprint = ''
                     AND expires_at > ?""",
                (fingerprint, request_id, int(now)),
            ).rowcount
        return changed == 1

    def abort_request(self, request_id: str) -> bool:
        """Terminally invalidate any request that has not been consumed."""
        with self._database(write=True) as db:
            changed = db.execute(
                """UPDATE request_ledger SET state = 'aborted'
                   WHERE request_id = ? AND state IN ('issued', 'bound', 'released')""",
                (request_id,),
            ).rowcount
        return changed == 1

    def verify_action(self, request_id: str, fingerprint: str, now: int) -> bool:
        """Recheck the claimed exact action at the final handler boundary."""
        with self._database(write=False) as db:
            row = db.execute(
                """SELECT 1 FROM request_ledger
                   WHERE request_id = ? AND state = 'bound'
                     AND action_fingerprint = ? AND expires_at > ?""",
                (request_id, fingerprint, int(now)),
            ).fetchone()
        return row is not None

    def release_request(self, request_id: str, now: int) -> bool:
        with self._database(write=True) as db:
            changed = db.execute(
                """UPDATE request_ledger SET state = 'released'
                   WHERE request_id = ? AND state = 'bound' AND expires_at > ?""",
                (request_id, int(now)),
            ).rowcount
        return changed == 1

    def consume_response(
        self,
        request_id: str,
        context_id: str,
        correlation_id: str,
        policy_generation: str,
        now: int,
    ) -> bool:
        with self._database(write=True) as db:
            changed = db.execute(
                """UPDATE request_ledger SET state = 'consumed'
                   WHERE request_id = ? AND context_id = ? AND correlation_id = ?
                     AND policy_generation = ? AND expires_at > ? AND state = 'released'""",
                (
                    request_id,
                    context_id,
                    correlation_id,
                    policy_generation,
                    int(now),
                ),
            ).rowcount
        return changed == 1

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
            os.close(self._fd)
