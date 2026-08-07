"""Durable, host-owned Juno conversation to Kite context mappings."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import stat
import threading
import time
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


class MappingStore:
    """One narrow SQLite store for mappings and their replay ledger.

    The canonical Juno conversation key is HMACed before storage.  No prompt,
    handoff text, transcript, tool result, platform ID, or credential is ever
    accepted by this API.
    """

    def __init__(self, path: str | Path, mapping_key: bytes):
        self.path = Path(path).expanduser()
        if len(mapping_key) < 32:
            raise MappingSecurityError("mapping key must contain at least 32 bytes")
        self._mapping_key = bytes(mapping_key)
        self._lock = threading.RLock()
        boundary_fd, identity = self._open_secure_path()
        self._db: Optional[sqlite3.Connection] = None
        try:
            self._db = sqlite3.connect(
                str(self.path), timeout=30, isolation_level=None, check_same_thread=False
            )
            # Detect a same-owner path replacement between the fd boundary and
            # sqlite's open.  The owner-only parent prevents later untrusted
            # replacement; keeping this check after connect closes the only
            # creation/open gap without ever chmodding through a pathname.
            self._validate_path_identity(identity)
        except Exception:
            if self._db is not None:
                self._db.close()
            raise
        finally:
            os.close(boundary_fd)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA busy_timeout = 30000")
        self._enable_wal()
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.execute("PRAGMA foreign_keys = ON")
        self._create_schema()

    def _enable_wal(self) -> None:
        deadline = time.monotonic() + 30
        while True:
            try:
                mode = self._db.execute("PRAGMA journal_mode = WAL").fetchone()
                if mode and str(mode[0]).lower() == "wal":
                    return
                raise MappingSecurityError("mapping database refused WAL mode")
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)

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
        with self._lock:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS mappings (
                    principal TEXT NOT NULL,
                    conversation_digest TEXT NOT NULL,
                    context_id TEXT NOT NULL UNIQUE,
                    correlation_id TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                    PRIMARY KEY (principal, conversation_digest)
                );
                CREATE TABLE IF NOT EXISTS request_ledger (
                    request_id TEXT PRIMARY KEY,
                    context_id TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    policy_generation TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK (
                        state IN ('issued', 'bound', 'released', 'consumed')
                    ),
                    action_fingerprint TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                    FOREIGN KEY (context_id) REFERENCES mappings(context_id)
                );
                CREATE INDEX IF NOT EXISTS request_ledger_context
                    ON request_ledger(context_id, state);
                """
            )

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
        )

    def resolve(self, principal: str, conversation_key: str) -> MappingRecord:
        principal = str(principal or "").strip()
        conversation_key = str(conversation_key or "").strip()
        if not principal or not conversation_key:
            raise ValueError("principal and conversation key are required")
        digest = self._conversation_digest(principal, conversation_key)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT * FROM mappings WHERE principal = ? AND conversation_digest = ?",
                    (principal, digest),
                ).fetchone()
                if row is None:
                    self._db.execute(
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
                    row = self._db.execute(
                        "SELECT * FROM mappings WHERE principal = ? AND conversation_digest = ?",
                        (principal, digest),
                    ).fetchone()
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        if row is None:  # pragma: no cover - protected by the transaction
            raise RuntimeError("mapping creation failed")
        return self._mapping_from_row(row)

    def get_by_context(self, context_id: str) -> Optional[MappingRecord]:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM mappings WHERE context_id = ?", (str(context_id),)
            ).fetchone()
        return self._mapping_from_row(row) if row is not None else None

    def issue_request(
        self,
        mapping: MappingRecord,
        request_id: str,
        policy_generation: str,
        expires_at: int,
    ) -> None:
        with self._lock:
            self._db.execute(
                """INSERT INTO request_ledger
                   (request_id, context_id, correlation_id, policy_generation, expires_at, state)
                   VALUES (?, ?, ?, ?, ?, 'issued')""",
                (
                    request_id,
                    mapping.context_id,
                    mapping.correlation_id,
                    policy_generation,
                    int(expires_at),
                ),
            )

    def claim_request(
        self,
        request_id: str,
        context_id: str,
        correlation_id: str,
        policy_generation: str,
        now: int,
    ) -> Optional[RequestRecord]:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                changed = self._db.execute(
                    """UPDATE request_ledger SET state = 'bound'
                       WHERE request_id = ? AND context_id = ? AND correlation_id = ?
                         AND policy_generation = ? AND expires_at > ? AND state = 'issued'""",
                    (request_id, context_id, correlation_id, policy_generation, int(now)),
                ).rowcount
                row = self._db.execute(
                    "SELECT * FROM request_ledger WHERE request_id = ?", (request_id,)
                ).fetchone()
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self._request_from_row(row) if changed == 1 and row is not None else None

    def get_request(self, request_id: str) -> Optional[RequestRecord]:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM request_ledger WHERE request_id = ?", (request_id,)
            ).fetchone()
        return self._request_from_row(row) if row is not None else None

    def claim_action(self, request_id: str, fingerprint: str, now: int) -> bool:
        with self._lock:
            changed = self._db.execute(
                """UPDATE request_ledger SET action_fingerprint = ?
                   WHERE request_id = ? AND state = 'bound' AND action_fingerprint = ''
                     AND expires_at > ?""",
                (fingerprint, request_id, int(now)),
            ).rowcount
        return changed == 1

    def release_request(self, request_id: str, now: int) -> bool:
        with self._lock:
            changed = self._db.execute(
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
        with self._lock:
            changed = self._db.execute(
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
            self._db.close()
