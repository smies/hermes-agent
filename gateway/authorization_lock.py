"""Owned OS-lock capability for the durable authorization coordinator."""

from __future__ import annotations

import os
import stat
import threading
import weakref
from pathlib import Path
from typing import Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - authorization stays inert on Windows
    fcntl = None  # type: ignore[assignment]

from gateway.status import get_process_start_time


_CAPABILITY = object()


class AuthorizationCoordinatorLockSession:
    """A live, owner-only exclusive lock held by one open file description.

    Construction is restricted to :meth:`acquire`.  The authorization store
    revalidates the capability, process identity, path and inode on every
    fenced operation, so closing or unlocking the session immediately makes
    its database coordinator fence unusable.
    """

    __slots__ = (
        "__weakref__",
        "_capability",
        "_fd",
        "_path",
        "_identity",
        "_pid",
        "_process_started_at",
        "_owner_token",
    )

    _sessions: weakref.WeakSet["AuthorizationCoordinatorLockSession"] = (
        weakref.WeakSet()
    )
    _sessions_guard = threading.RLock()

    def __init__(
        self,
        capability: object,
        *,
        fd: int,
        path: Path,
        identity: tuple[int, int],
        pid: int,
        process_started_at: int,
    ) -> None:
        if capability is not _CAPABILITY:
            raise TypeError("authorization lock sessions must be acquired")
        self._capability = capability
        self._fd = fd
        self._path = path
        self._identity = identity
        self._pid = pid
        self._process_started_at = process_started_at
        self._owner_token: object | None = None
        self._sessions.add(self)

    @classmethod
    def _before_fork(cls) -> None:
        # Serialize fork against acquisition and close so every inherited
        # authorization-lock descriptor is present in the child snapshot.
        cls._sessions_guard.acquire()

    @classmethod
    def _after_fork_parent(cls) -> None:
        cls._sessions_guard.release()

    @classmethod
    def _after_fork_child(cls) -> None:
        # flock locks are associated with the inherited open-file description.
        # LOCK_UN here would release the live parent's lock, while retaining an
        # inherited fd would keep the lock alive after the parent exits.
        sessions = tuple(cls._sessions)
        cls._sessions.clear()
        for session in sessions:
            fd, session._fd = session._fd, -1
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        # Do not depend on the state of an inherited synchronization primitive.
        cls._sessions_guard = threading.RLock()

    @classmethod
    def acquire(cls, lock_path: Path) -> Optional["AuthorizationCoordinatorLockSession"]:
        """Acquire ``lock_path`` exclusively without waiting, or return None."""
        if fcntl is None:
            return None
        with cls._sessions_guard:
            if not isinstance(lock_path, Path):
                lock_path = Path(lock_path)
            if (
                not lock_path.is_absolute()
                or Path(os.path.abspath(os.fspath(lock_path))) != lock_path
            ):
                raise ValueError(
                    "authorization coordinator lock path must be absolute and canonical"
                )
            if lock_path.resolve(strict=False) != lock_path:
                raise ValueError(
                    "authorization coordinator lock path must contain no symlinks"
                )
            parent = lock_path.parent.lstat()
            uid = os.getuid() if hasattr(os, "getuid") else 0
            if (
                not stat.S_ISDIR(parent.st_mode)
                or stat.S_ISLNK(parent.st_mode)
                or parent.st_uid != uid
                or stat.S_IMODE(parent.st_mode) != 0o700
            ):
                raise ValueError(
                    "authorization coordinator lock directory must be owner-only"
                )

            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(lock_path, flags, 0o600)
            try:
                info = os.fstat(fd)
                path_info = lock_path.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or stat.S_ISLNK(path_info.st_mode)
                    or info.st_uid != uid
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1
                    or (info.st_dev, info.st_ino)
                    != (path_info.st_dev, path_info.st_ino)
                ):
                    raise ValueError(
                        "authorization coordinator lock file must be owner-only and regular"
                    )
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except (BlockingIOError, OSError):
                    os.close(fd)
                    return None
                pid = os.getpid()
                started_at = get_process_start_time(pid)
                if started_at is None:
                    raise RuntimeError("current process start identity is unavailable")
                return cls(
                    _CAPABILITY,
                    fd=fd,
                    path=lock_path,
                    identity=(info.st_dev, info.st_ino),
                    pid=pid,
                    process_started_at=int(started_at),
                )
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise

    def bind_owner(self, owner_token: object) -> bool:
        if self._owner_token is None:
            self._owner_token = owner_token
            return True
        return self._owner_token is owner_token

    def is_live_for(self, expected_path: Path, owner_token: object) -> bool:
        """Verify that this exact capability still owns the expected flock."""
        if type(self) is not AuthorizationCoordinatorLockSession:
            return False
        if (
            self._capability is not _CAPABILITY
            or self._owner_token is not owner_token
            or self._fd < 0
            or self._path != expected_path
        ):
            return False
        if os.getpid() != self._pid:
            return False
        if get_process_start_time(self._pid) != self._process_started_at:
            return False
        try:
            current = expected_path.lstat()
            opened = os.fstat(self._fd)
        except OSError:
            return False
        if (
            (current.st_dev, current.st_ino) != self._identity
            or (opened.st_dev, opened.st_ino) != self._identity
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != (os.getuid() if hasattr(os, "getuid") else 0)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
        ):
            return False

        # An independently opened file description must be unable to acquire
        # the same exclusive flock while this session owns it.
        flags = os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            probe = os.open(expected_path, flags)
        except OSError:
            return False
        try:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError):
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except (BlockingIOError, OSError):
                    return False
                return True
            fcntl.flock(probe, fcntl.LOCK_UN)
            return False
        finally:
            os.close(probe)

    @property
    def path(self) -> Path:
        return self._path

    def close(self) -> None:
        if os.getpid() != self._pid:
            # Fallback for platforms without register_at_fork and for code
            # paths that bypass the registered handler. Never touch flock on
            # an inherited open-file description.
            fd, self._fd = self._fd, -1
            if fd >= 0:
                os.close(fd)
            return
        with type(self)._sessions_guard:
            fd, self._fd = self._fd, -1
            type(self)._sessions.discard(self)
            if fd < 0:
                return
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def __enter__(self) -> "AuthorizationCoordinatorLockSession":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - deterministic close is tested
        try:
            self.close()
        except Exception:
            pass


if hasattr(os, "register_at_fork"):
    os.register_at_fork(
        before=AuthorizationCoordinatorLockSession._before_fork,
        after_in_parent=AuthorizationCoordinatorLockSession._after_fork_parent,
        after_in_child=AuthorizationCoordinatorLockSession._after_fork_child,
    )
