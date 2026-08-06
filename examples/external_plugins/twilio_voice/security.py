"""Security primitives for the Twilio ConversationRelay bridge.

This module is deliberately dependency-free.  Twilio's request-signing
algorithm is small, and keeping it here lets the bridge reject invalid HTTP
and WebSocket handshakes before importing or invoking the Hermes runtime.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit


_E164_RE = re.compile(r"^\+[1-9][0-9]{7,14}$")
_SID_RE = re.compile(r"^(?:AC|CA|PN|VX)[0-9A-Fa-f]{32}$")


def normalize_phone(value: str) -> str:
    """Return a strict E.164 number, or an empty string when invalid."""
    value = str(value or "").strip()
    return value if _E164_RE.fullmatch(value) else ""


def valid_sid(value: str, prefix: str) -> bool:
    value = str(value or "").strip()
    return bool(_SID_RE.fullmatch(value) and value.startswith(prefix))


def redact_phone(value: str) -> str:
    """Render only a stable digest; never retain recognizable phone digits."""
    normalized = normalize_phone(value)
    if not normalized:
        return "phone:invalid"
    return "phone:" + hashlib.sha256(normalized.encode()).hexdigest()[:10]


def redact_url(value: str) -> str:
    """Log-safe URL label that does not reveal the rotating tunnel hostname."""
    try:
        parsed = urlsplit(value)
        label = f"{parsed.scheme}://{parsed.hostname or ''}{parsed.path}"
    except Exception:
        label = str(value or "")
    return "url:" + hashlib.sha256(label.encode()).hexdigest()[:10]


def caller_subject(value: str) -> str:
    """Stable pseudonymous Hermes user id for a caller."""
    normalized = normalize_phone(value)
    if not normalized:
        raise ValueError("caller must be valid E.164")
    return "twilio-caller-" + hashlib.sha256(normalized.encode()).hexdigest()[:24]


def _signature_values(value: object) -> list[str]:
    if isinstance(value, (list, tuple)):
        # Match the official helper libraries' MultiDict handling: duplicate
        # values do not alter the canonical request string.
        return sorted({str(item) for item in value})
    return [str(value)]


def compute_twilio_signature(
    auth_token: str,
    request_url: str,
    params: Mapping[str, object] | None = None,
) -> str:
    """Compute Twilio's documented HMAC-SHA1 request signature.

    WebSocket handshakes pass ``params=None`` and sign the exact WSS URL.
    Form webhooks append every case-sensitively sorted field and value.
    """
    if not auth_token or not request_url:
        return ""
    payload = request_url
    for key in sorted((params or {}).keys()):
        for value in _signature_values((params or {})[key]):
            payload += str(key) + value
    digest = hmac.new(
        auth_token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha1
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def validate_twilio_signature(
    auth_token: str,
    request_url: str,
    params: Mapping[str, object] | None,
    signature: str,
) -> bool:
    """Constant-time validation against the exact configured public URL."""
    if not auth_token or not request_url or not signature:
        return False
    expected = compute_twilio_signature(auth_token, request_url, params)
    try:
        return hmac.compare_digest(expected.encode("ascii"), signature.encode("ascii"))
    except (UnicodeEncodeError, ValueError):
        return False


def http_to_wss(base_url: str, path: str) -> str:
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username:
        raise ValueError("public_base_url must be an https URL without credentials")
    if parsed.port not in (None, 443):
        raise ValueError("public_base_url must use the standard HTTPS port")
    if parsed.query or parsed.fragment:
        raise ValueError("public_base_url must not contain query or fragment")
    base_path = parsed.path.rstrip("/")
    return urlunsplit(("wss", parsed.netloc, base_path + path, "", ""))


def public_endpoint(base_url: str, path: str) -> str:
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username:
        raise ValueError("public_base_url must be an https URL without credentials")
    if parsed.port not in (None, 443):
        raise ValueError("public_base_url must use the standard HTTPS port")
    if parsed.query or parsed.fragment:
        raise ValueError("public_base_url must not contain query or fragment")
    return urlunsplit(("https", parsed.netloc, parsed.path.rstrip("/") + path, "", ""))


def atomic_owner_only_write(path: Path, data: str) -> None:
    """Atomically write UTF-8 data with mode 0600 and a private parent."""
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        path.chmod(0o600)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


@dataclass(frozen=True)
class PendingCall:
    nonce: str
    call_sid: str
    account_sid: str
    caller: str
    called: str
    created_at: float
    pin_verified: bool


class PendingCallStore:
    """Bounded, expiring, one-use HTTP-to-WebSocket binding state."""

    def __init__(self, ttl_seconds: float, max_entries: int = 64):
        self.ttl_seconds = max(5.0, float(ttl_seconds))
        self.max_entries = max(1, int(max_entries))
        self._entries: dict[str, PendingCall] = {}
        self._lock = RLock()

    def create(
        self,
        *,
        call_sid: str,
        account_sid: str,
        caller: str,
        called: str,
        pin_verified: bool,
        now: float | None = None,
    ) -> PendingCall:
        now = time.monotonic() if now is None else float(now)
        with self._lock:
            self._expire(now)
            if len(self._entries) >= self.max_entries:
                oldest = min(self._entries.values(), key=lambda item: item.created_at)
                self._entries.pop(oldest.nonce, None)
            entry = PendingCall(
                nonce=secrets.token_urlsafe(24),
                call_sid=call_sid,
                account_sid=account_sid,
                caller=caller,
                called=called,
                created_at=now,
                pin_verified=bool(pin_verified),
            )
            self._entries[entry.nonce] = entry
            return entry

    def consume(self, nonce: str, *, now: float | None = None) -> PendingCall | None:
        now = time.monotonic() if now is None else float(now)
        with self._lock:
            self._expire(now)
            return self._entries.pop(str(nonce or ""), None)

    def discard_call(self, call_sid: str) -> None:
        with self._lock:
            for nonce, entry in list(self._entries.items()):
                if hmac.compare_digest(entry.call_sid, str(call_sid or "")):
                    self._entries.pop(nonce, None)

    def _expire(self, now: float) -> None:
        cutoff = now - self.ttl_seconds
        for nonce, entry in list(self._entries.items()):
            if entry.created_at < cutoff:
                self._entries.pop(nonce, None)

    def __len__(self) -> int:
        with self._lock:
            self._expire(time.monotonic())
            return len(self._entries)


def allowlisted(caller: str, allowed_callers: Sequence[str]) -> bool:
    normalized = normalize_phone(caller)
    if not normalized:
        return False
    return any(
        hmac.compare_digest(normalized, candidate)
        for candidate in allowed_callers
        if normalize_phone(candidate) == candidate
    )
