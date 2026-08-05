"""Independent, content-free replay authority for the Juno private-read pilot.

The journal is deliberately outside ``authorization.db``.  Its authenticated
head marker makes whole-record suffix truncation detectable; the state-key
seal makes disappearance of both journal files distinguishable from a first
install.  Appends are synchronous and are called while the authorization
store's exclusive coordinator/SQLite writer boundary is held.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import threading


JOURNAL_NAME = "mvp-replay-authority.jsonl"
MARKER_NAME = "mvp-replay-authority.head"
JOURNAL_VERSION = 1
MAX_JOURNAL_BYTES = 16 * 1024 * 1024
MAX_JOURNAL_RECORDS = 100_000
MAX_RECORD_BYTES = 1024
_KEY_MAGIC = b"\nJUNO-REPLAY-V1\n"
_KINDS = frozenset({"genesis", "source", "approval", "delivery"})


class ReplayAuthorityError(RuntimeError):
    """Sealed fail-closed journal error."""

    def __repr__(self) -> str:
        return "ReplayAuthorityError('private replay authority unavailable')"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _mac(key: bytes, domain: bytes, value: bytes) -> str:
    return hmac.new(key, domain + b"\0" + value, hashlib.sha256).hexdigest()


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_all(fd: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(fd, value[offset:])
        if written <= 0:
            raise ReplayAuthorityError("private replay authority unavailable")
        offset += written


class JunoReplayAuthority:
    """Strict append-only authority with an authenticated external head."""

    def __init__(self, state_dir: Path, key: bytes):
        if type(key) is not bytes or len(key) != 32:
            raise ReplayAuthorityError("private replay authority unavailable")
        self._dir = state_dir
        self._key = bytes(key)
        self._lock = threading.Lock()
        self._dir_fd = -1
        self._seq = 0
        self._head = ""
        self._failed = False
        self._seen: dict[str, set[str]] = {kind: set() for kind in _KINDS}
        self._open_or_create()

    def _write(self, fd: int, value: bytes) -> None:
        _write_all(fd, value)

    def _fsync_file(self, fd: int) -> None:
        os.fsync(fd)

    def _fsync_directory(self) -> None:
        os.fsync(self._dir_fd)

    def close(self) -> None:
        descriptor, self._dir_fd = self._dir_fd, -1
        if descriptor >= 0:
            os.close(descriptor)

    def __enter__(self) -> "JunoReplayAuthority":
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def contains(self, kind: str, identifier: str) -> bool:
        if self._failed:
            raise ReplayAuthorityError("private replay authority unavailable")
        return kind in self._seen and identifier in self._seen[kind]

    def healthy(self) -> bool:
        return not self._failed and self._dir_fd >= 0 and self._parent_is_pinned()

    @staticmethod
    def _bounded_digest(value: object) -> bool:
        return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)

    def append(self, kind: str, identifiers: tuple[str, ...]) -> bool:
        """Durably tombstone ``identifiers``; return False if already present.

        All identifiers are keyed/ordinary SHA-256 digests.  No provider text,
        credentials, request prose, approval text, or private payload is stored.
        """
        if kind not in _KINDS - {"genesis"} or not 1 <= len(identifiers) <= 4:
            raise ReplayAuthorityError("private replay authority unavailable")
        if (
            any(not self._bounded_digest(item) for item in identifiers)
            or len(set(identifiers)) != len(identifiers)
        ):
            raise ReplayAuthorityError("private replay authority unavailable")
        with self._lock:
            try:
                if self._failed:
                    raise ReplayAuthorityError("private replay authority unavailable")
                if any(item in self._seen[kind] for item in identifiers):
                    return False
                self._append_locked(kind, identifiers)
                self._seen[kind].update(identifiers)
                return True
            except BaseException:
                self._failed = True
                raise

    def _parent_is_pinned(self) -> bool:
        try:
            opened = os.fstat(self._dir_fd)
            named = self._dir.lstat()
            return (
                stat.S_ISDIR(opened.st_mode)
                and stat.S_IMODE(opened.st_mode) == 0o700
                and opened.st_dev == named.st_dev
                and opened.st_ino == named.st_ino
                and (not hasattr(os, "getuid") or opened.st_uid == os.getuid())
            )
        except OSError:
            return False

    def _regular_owner_file(self, name: str) -> os.stat_result:
        info = os.stat(name, dir_fd=self._dir_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        ):
            raise ReplayAuthorityError("private replay authority unavailable")
        return info

    def _read_file(self, name: str, *, maximum: int) -> bytes:
        self._regular_owner_file(name)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(name, flags, dir_fd=self._dir_fd)
        try:
            opened = os.fstat(fd)
            named = self._regular_owner_file(name)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise ReplayAuthorityError("private replay authority unavailable")
            if opened.st_size > maximum:
                raise ReplayAuthorityError("private replay authority unavailable")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            value = b"".join(chunks)
            if len(value) > maximum:
                raise ReplayAuthorityError("private replay authority unavailable")
            return value
        finally:
            os.close(fd)

    def _key_is_sealed(self) -> bool:
        value = self._read_file("mvp-store.key", maximum=256)
        if len(value) == 32:
            if not hmac.compare_digest(value, self._key):
                raise ReplayAuthorityError("private replay authority unavailable")
            return False
        expected = self._key + _KEY_MAGIC + bytes.fromhex(
            _mac(self._key, b"juno-replay-key-seal-v1", self._key + _KEY_MAGIC)
        )
        if not hmac.compare_digest(value, expected):
            raise ReplayAuthorityError("private replay authority unavailable")
        return True

    def _seal_key(self) -> None:
        suffix = _KEY_MAGIC + bytes.fromhex(
            _mac(self._key, b"juno-replay-key-seal-v1", self._key + _KEY_MAGIC)
        )
        current = self._regular_owner_file("mvp-store.key")
        flags = (
            os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open("mvp-store.key", flags, dir_fd=self._dir_fd)
        try:
            opened = os.fstat(fd)
            if (
                (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                or opened.st_size != 32
            ):
                raise ReplayAuthorityError("private replay authority unavailable")
            self._write(fd, suffix)
            self._fsync_file(fd)
        finally:
            os.close(fd)
        self._fsync_directory()
        sealed = self._regular_owner_file("mvp-store.key")
        if (sealed.st_dev, sealed.st_ino) != (current.st_dev, current.st_ino):
            raise ReplayAuthorityError("private replay authority unavailable")
        if not self._key_is_sealed():
            raise ReplayAuthorityError("private replay authority unavailable")

    def _open_or_create(self) -> None:
        try:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            self._dir_fd = os.open(self._dir, flags)
            if not self._parent_is_pinned():
                raise ReplayAuthorityError("private replay authority unavailable")
            sealed = self._key_is_sealed()
            journal_exists = self._exists(JOURNAL_NAME)
            marker_exists = self._exists(MARKER_NAME)
            if journal_exists != marker_exists:
                raise ReplayAuthorityError("private replay authority unavailable")
            if sealed and not journal_exists:
                raise ReplayAuthorityError("private replay authority unavailable")
            if not journal_exists:
                self._create_genesis()
            else:
                self._replay()
            if not sealed:
                self._seal_key()
        except ReplayAuthorityError:
            self.close()
            raise
        except BaseException as exc:
            self.close()
            raise ReplayAuthorityError("private replay authority unavailable") from None

    def _exists(self, name: str) -> bool:
        try:
            os.stat(name, dir_fd=self._dir_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def _record(self, seq: int, previous: str, kind: str, identifiers: tuple[str, ...]) -> bytes:
        unsigned = {"ids": list(identifiers), "kind": kind, "prev": previous,
                    "seq": seq, "v": JOURNAL_VERSION}
        signature = _mac(self._key, b"juno-replay-record-v1", _canonical(unsigned))
        return _canonical({**unsigned, "mac": signature})

    def _marker(self, seq: int, head: str) -> bytes:
        unsigned = {"head": head, "seq": seq, "v": JOURNAL_VERSION}
        signature = _mac(self._key, b"juno-replay-head-v1", _canonical(unsigned))
        return _canonical({**unsigned, "mac": signature}) + b"\n"

    def _create_genesis(self) -> None:
        record = self._record(1, "0" * 64, "genesis", ())
        line = record + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(JOURNAL_NAME, flags, 0o600, dir_fd=self._dir_fd)
        try:
            self._write(fd, line)
            self._fsync_file(fd)
        finally:
            os.close(fd)
        self._regular_owner_file(JOURNAL_NAME)
        self._seq, self._head = 1, _digest(record)
        self._replace_marker(self._marker(self._seq, self._head), create_only=True)
        self._replay()

    def _replace_marker(self, value: bytes, *, create_only: bool = False) -> None:
        temporary = f".{MARKER_NAME}.{secrets.token_hex(12)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temporary, flags, 0o600, dir_fd=self._dir_fd)
        try:
            self._write(fd, value)
            self._fsync_file(fd)
        finally:
            os.close(fd)
        try:
            if create_only and self._exists(MARKER_NAME):
                raise ReplayAuthorityError("private replay authority unavailable")
            os.replace(temporary, MARKER_NAME, src_dir_fd=self._dir_fd, dst_dir_fd=self._dir_fd)
            self._fsync_directory()
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=self._dir_fd)
            except OSError:
                pass
            raise
        self._regular_owner_file(MARKER_NAME)

    def _replay(self) -> None:
        journal = self._read_file(JOURNAL_NAME, maximum=MAX_JOURNAL_BYTES)
        marker = self._read_file(MARKER_NAME, maximum=MAX_RECORD_BYTES)
        if not journal or not journal.endswith(b"\n") or not marker.endswith(b"\n"):
            raise ReplayAuthorityError("private replay authority unavailable")
        lines = journal[:-1].split(b"\n")
        if not 1 <= len(lines) <= MAX_JOURNAL_RECORDS:
            raise ReplayAuthorityError("private replay authority unavailable")
        previous = "0" * 64
        seen: dict[str, set[str]] = {kind: set() for kind in _KINDS}
        for expected_seq, line in enumerate(lines, 1):
            if not line or len(line) > MAX_RECORD_BYTES:
                raise ReplayAuthorityError("private replay authority unavailable")
            try:
                record = json.loads(line)
            except (UnicodeError, json.JSONDecodeError):
                raise ReplayAuthorityError("private replay authority unavailable") from None
            if type(record) is not dict or set(record) != {"v", "seq", "prev", "kind", "ids", "mac"}:
                raise ReplayAuthorityError("private replay authority unavailable")
            kind, identifiers = record["kind"], record["ids"]
            if (
                type(record["v"]) is not int or record["v"] != JOURNAL_VERSION
                or type(record["seq"]) is not int or record["seq"] != expected_seq
                or not self._bounded_digest(record["prev"])
                or record["prev"] != previous or type(kind) is not str or kind not in _KINDS
                or type(identifiers) is not list or len(identifiers) > 4
                or len(set(identifiers)) != len(identifiers)
                or (kind == "genesis" and (expected_seq != 1 or identifiers))
                or (kind != "genesis" and (not identifiers or any(
                    not self._bounded_digest(item) for item in identifiers
                )))
            ):
                raise ReplayAuthorityError("private replay authority unavailable")
            unsigned = {name: record[name] for name in ("ids", "kind", "prev", "seq", "v")}
            expected_mac = _mac(self._key, b"juno-replay-record-v1", _canonical(unsigned))
            if type(record["mac"]) is not str or not hmac.compare_digest(record["mac"], expected_mac):
                raise ReplayAuthorityError("private replay authority unavailable")
            if any(item in seen[kind] for item in identifiers):
                raise ReplayAuthorityError("private replay authority unavailable")
            seen[kind].update(identifiers)
            previous = _digest(line)
        if lines and json.loads(lines[0])["kind"] != "genesis":
            raise ReplayAuthorityError("private replay authority unavailable")
        try:
            head = json.loads(marker)
        except (UnicodeError, json.JSONDecodeError):
            raise ReplayAuthorityError("private replay authority unavailable") from None
        if type(head) is not dict or set(head) != {"v", "seq", "head", "mac"}:
            raise ReplayAuthorityError("private replay authority unavailable")
        unsigned_head = {name: head[name] for name in ("head", "seq", "v")}
        expected_head_mac = _mac(self._key, b"juno-replay-head-v1", _canonical(unsigned_head))
        if (
            type(head["v"]) is not int or head["v"] != JOURNAL_VERSION
            or type(head["seq"]) is not int or head["seq"] != len(lines)
            or not self._bounded_digest(head["head"])
            or head["head"] != previous or type(head["mac"]) is not str
            or not hmac.compare_digest(head["mac"], expected_head_mac)
        ):
            raise ReplayAuthorityError("private replay authority unavailable")
        self._seq, self._head, self._seen = len(lines), previous, seen

    def _append_locked(self, kind: str, identifiers: tuple[str, ...]) -> None:
        if self._seq >= MAX_JOURNAL_RECORDS:
            raise ReplayAuthorityError("private replay authority exhausted")
        record = self._record(self._seq + 1, self._head, kind, identifiers)
        line = record + b"\n"
        if len(line) > MAX_RECORD_BYTES:
            raise ReplayAuthorityError("private replay authority unavailable")
        current = self._regular_owner_file(JOURNAL_NAME)
        if current.st_size + len(line) > MAX_JOURNAL_BYTES:
            raise ReplayAuthorityError("private replay authority exhausted")
        flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(JOURNAL_NAME, flags, dir_fd=self._dir_fd)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise ReplayAuthorityError("private replay authority unavailable")
            self._write(fd, line)
            self._fsync_file(fd)
        finally:
            os.close(fd)
        next_seq, next_head = self._seq + 1, _digest(record)
        self._replace_marker(self._marker(next_seq, next_head))
        if not self._parent_is_pinned():
            raise ReplayAuthorityError("private replay authority unavailable")
        self._seq, self._head = next_seq, next_head


__all__ = [
    "JOURNAL_NAME", "MARKER_NAME", "JunoReplayAuthority", "ReplayAuthorityError",
]
