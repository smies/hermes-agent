"""Fast, closed Juno private-read MVP.

This module intentionally implements only the Gmail-newest-message vertical
slice selected for the pilot.  Private values exist only between the Gmail
provider and the sensitive transport call; every durable and model-facing
result is content-free.
"""

from __future__ import annotations

import asyncio
import base64
from contextvars import ContextVar, Token
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Awaitable, Callable, Protocol
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from gateway.authorization_contracts import CoordinatorIdentity
from gateway.authorization_tasks import AuthorizationTaskStore
from gateway.config import Platform
from gateway.platforms.base import MessageEvent
from gateway.trusted_private_read_host import _owner_directory, _owner_file


CAPABILITY_ID = "gmail.newest_inbox_message.read"
GMAIL_CONTRACT_VERSION = "gmail-v1-newest-inbox-v1"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_AUTHORITY = "https://gmail.googleapis.com"
OPENFGA_AUTHORITY = "http://127.0.0.1:8080"
OPENFGA_CLIENT_CONTRACT_VERSION = "1.18.2"
MAX_PRIVATE_RENDER_BYTES = 16 * 1024
MAX_GMAIL_RESPONSE_BYTES = 128 * 1024
_APPROVAL_RE = re.compile(r"^/(approve|deny) ([A-Za-z0-9_-]{16,80})$")
_SENSITIVE_MESSAGE_ID_RE = re.compile(r"^3EB0[0-9A-F]{18}$")
_WHATSAPP_DIRECT_RE = re.compile(r"^\d{1,32}@(s\.whatsapp\.net|lid)$")
_WHATSAPP_CHAT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}@(s\.whatsapp\.net|lid|g\.us)$")


class JunoPrivateReadError(RuntimeError):
    """A fixed, content-free error safe to cross ordinary boundaries."""

    def __repr__(self) -> str:
        return "JunoPrivateReadError('private read failed')"


def _exact_dict(value: object, keys: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise JunoPrivateReadError(f"{label} configuration is invalid")
    return value


def _text(value: object, label: str, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or "\x00" in value
        or len(value.encode("utf-8")) > maximum
    ):
        raise JunoPrivateReadError(f"{label} configuration is invalid")
    return value


def _timeout(value: object, label: str) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        raise JunoPrivateReadError(f"{label} configuration is invalid")
    result = float(value)
    if not 0.1 <= result <= 300:
        raise JunoPrivateReadError(f"{label} configuration is invalid")
    return result


def _jid(value: object, label: str, *, direct: bool = True) -> str:
    result = _text(value, label)
    pattern = _WHATSAPP_DIRECT_RE if direct else _WHATSAPP_CHAT_RE
    if pattern.fullmatch(result) is None:
        raise JunoPrivateReadError(f"{label} configuration is invalid")
    return result


@dataclass(frozen=True, slots=True)
class JunoRequester:
    sender: str
    label: str
    sensitive_destination: str


@dataclass(frozen=True, slots=True, repr=False)
class JunoPrivateReadMvpConfig:
    state_dir: Path
    profile: str
    ordinary_account: str
    ordinary_chat: str
    owner_sender: str
    requesters: tuple[JunoRequester, ...]
    openfga_store_id: str
    openfga_model_id: str
    openfga_credential_file: Path
    gmail_client_file: Path
    gmail_token_file: Path
    gmail_account: str
    sensitive_registration: str
    sensitive_account: str
    sensitive_session: str
    sensitive_capability_file: Path
    request_timeout: float
    approval_timeout: float
    read_timeout: float
    submission_timeout: float

    def __repr__(self) -> str:
        return "<JunoPrivateReadMvpConfig redacted>"

    @classmethod
    def parse(cls, raw: object) -> "JunoPrivateReadMvpConfig | None":
        if raw is None:
            return None
        if type(raw) is not dict:
            raise JunoPrivateReadError("private read configuration is invalid")
        if raw.get("enabled") is not True:
            if set(raw) - {"enabled"}:
                raise JunoPrivateReadError("disabled private read configuration is invalid")
            return None
        _exact_dict(
            raw,
            {
                "version", "enabled", "state_dir", "profile", "ordinary",
                "requesters", "capability_id", "gmail_contract_version",
                "openfga", "gmail", "sensitive", "timeouts",
            },
            "private read",
        )
        if raw["version"] != 2 or raw["capability_id"] != CAPABILITY_ID:
            raise JunoPrivateReadError("private read contract is invalid")
        if raw["gmail_contract_version"] != GMAIL_CONTRACT_VERSION:
            raise JunoPrivateReadError("private read contract is invalid")
        ordinary = _exact_dict(
            raw["ordinary"], {"account", "chat", "owner_sender"}, "ordinary"
        )
        openfga = _exact_dict(
            raw["openfga"], {"store_id", "model_id", "api_credential_file"}, "openfga"
        )
        gmail = _exact_dict(
            raw["gmail"], {"oauth_client_file", "token_file", "account"}, "gmail"
        )
        sensitive = _exact_dict(
            raw["sensitive"],
            {"registration", "account", "session", "capability_file"},
            "sensitive",
        )
        timeouts = _exact_dict(
            raw["timeouts"], {"request", "approval", "read", "submission"}, "timeouts"
        )
        requester_rows = raw["requesters"]
        if type(requester_rows) is not list or not 1 <= len(requester_rows) <= 16:
            raise JunoPrivateReadError("requester configuration is invalid")
        requesters: list[JunoRequester] = []
        seen: set[str] = set()
        for item in requester_rows:
            row = _exact_dict(
                item, {"sender", "label", "sensitive_destination"}, "requester"
            )
            requester = JunoRequester(
                sender=_jid(row["sender"], "requester sender"),
                label=_text(row["label"], "requester label", 80),
                sensitive_destination=_jid(
                    row["sensitive_destination"], "sensitive destination"
                ),
            )
            if requester.sender in seen:
                raise JunoPrivateReadError("requester configuration is invalid")
            seen.add(requester.sender)
            requesters.append(requester)
        owner = _jid(ordinary["owner_sender"], "owner sender")
        if owner not in seen:
            raise JunoPrivateReadError("owner must be an allowlisted requester")
        ordinary_account = _jid(ordinary["account"], "ordinary account")
        sensitive_account = _jid(sensitive["account"], "sensitive account")
        if hmac.compare_digest(ordinary_account, sensitive_account):
            raise JunoPrivateReadError("ordinary and sensitive accounts must differ")
        state_dir = _owner_directory(Path(_text(raw["state_dir"], "state directory", 2048)))
        credential = _owner_file(
            Path(_text(openfga["api_credential_file"], "OpenFGA credential", 2048))
        )
        client = _owner_file(Path(_text(gmail["oauth_client_file"], "OAuth client", 2048)))
        token = _owner_file(Path(_text(gmail["token_file"], "OAuth token", 2048)))
        sensitive_capability = _owner_file(
            Path(_text(sensitive["capability_file"], "sensitive capability", 2048))
        )
        profile = _text(raw["profile"], "profile", 64)
        if profile != "juno":
            raise JunoPrivateReadError("private read profile is invalid")
        return cls(
            state_dir=state_dir,
            profile=profile,
            ordinary_account=ordinary_account,
            ordinary_chat=_jid(ordinary["chat"], "ordinary chat", direct=False),
            owner_sender=owner,
            requesters=tuple(requesters),
            openfga_store_id=_text(openfga["store_id"], "OpenFGA store"),
            openfga_model_id=_text(openfga["model_id"], "OpenFGA model"),
            openfga_credential_file=credential,
            gmail_client_file=client,
            gmail_token_file=token,
            gmail_account=_text(gmail["account"], "Gmail account"),
            sensitive_registration=_text(sensitive["registration"], "sensitive registration"),
            sensitive_account=sensitive_account,
            sensitive_session=_text(sensitive["session"], "sensitive session"),
            sensitive_capability_file=sensitive_capability,
            request_timeout=_timeout(timeouts["request"], "request timeout"),
            approval_timeout=_timeout(timeouts["approval"], "approval timeout"),
            read_timeout=_timeout(timeouts["read"], "read timeout"),
            submission_timeout=_timeout(timeouts["submission"], "submission timeout"),
        )

    def requester(self, sender: str) -> JunoRequester | None:
        for item in self.requesters:
            if hmac.compare_digest(item.sender, sender):
                return item
        return None


@dataclass(frozen=True, slots=True, repr=False)
class MvpEventContext:
    requester: JunoRequester
    source_profile: str
    source_account: str
    source_chat: str
    source_message: str

    def __repr__(self) -> str:
        return "<MvpEventContext redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class MvpRequest:
    request_id: str
    requester: str
    source_profile: str
    source_account: str
    source_chat: str
    capability_id: str
    destination_account: str
    destination_chat: str
    owner_sender: str
    descriptor_digest: str
    created_at_us: int
    expires_at_us: int
    status: str
    notice_claimed: bool
    version: int

    def __repr__(self) -> str:
        return f"<MvpRequest status={self.status!r}>"


class MvpAuthorizationRepository:
    """MVP lifecycle operations on the existing AuthorizationTaskStore DB."""

    def __init__(self, store: AuthorizationTaskStore, key: bytes):
        if type(store) is not AuthorizationTaskStore or len(key) < 32:
            raise TypeError("exact authorization store and key are required")
        self.store = store
        self._key = bytes(key)

    @staticmethod
    def _row(row) -> MvpRequest:
        return MvpRequest(
            request_id=row["request_id"], requester=row["requester"],
            source_profile=row["source_profile"], source_account=row["source_account"],
            source_chat=row["source_chat"], capability_id=row["capability_id"],
            destination_account=row["destination_account"],
            destination_chat=row["destination_chat"], owner_sender=row["owner_sender"],
            descriptor_digest=row["descriptor_digest"], created_at_us=row["created_at_us"],
            expires_at_us=row["expires_at_us"], status=row["status"],
            notice_claimed=bool(row["notice_claimed"]), version=row["version"],
        )

    def _digest(self, value: str) -> str:
        return hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def create(self, context: MvpEventContext, config: JunoPrivateReadMvpConfig) -> MvpRequest:
        now_us = time.time_ns() // 1000
        expires_us = now_us + int(config.approval_timeout * 1_000_000)
        request_id = secrets.token_urlsafe(18)
        descriptor = json.dumps(
            {
                "capability": CAPABILITY_ID,
                "destination": context.requester.sensitive_destination,
                "requester": context.requester.sender,
                "source_account": context.source_account,
                "source_chat": context.source_chat,
                "source_profile": context.source_profile,
                "expires_at_us": expires_us,
            }, sort_keys=True, separators=(",", ":"),
        )
        digest = self._digest(descriptor)
        initial = "approved" if hmac.compare_digest(context.requester.sender, config.owner_sender) else "pending"

        def mutate(conn):
            conn.execute(
                "INSERT INTO private_read_mvp_requests "
                "(request_id,requester,source_profile,source_account,source_chat,capability_id,"
                "destination_account,destination_chat,owner_sender,descriptor_digest,created_at_us,"
                "expires_at_us,status,updated_at_us) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (request_id, context.requester.sender, context.source_profile,
                 context.source_account, context.source_chat, CAPABILITY_ID,
                 config.sensitive_account, context.requester.sensitive_destination,
                 config.owner_sender, digest, now_us, expires_us, initial, now_us),
            )
            return self._row(conn.execute(
                "SELECT * FROM private_read_mvp_requests WHERE request_id=?", (request_id,)
            ).fetchone())

        return self.store._write(mutate, at_us=now_us)

    def expire_due(self, now_us: int) -> int:
        def mutate(conn):
            cursor = conn.execute(
                "UPDATE private_read_mvp_requests SET status='expired',updated_at_us=?,version=version+1 "
                "WHERE status IN ('pending','approved') AND expires_at_us<=?",
                (now_us, now_us),
            )
            return cursor.rowcount
        return self.store._write(mutate, at_us=now_us)

    def recover_claimed(self, now_us: int) -> int:
        """Consume interrupted submissions; the MVP never retries ambiguity."""
        def mutate(conn):
            cursor = conn.execute(
                "UPDATE private_read_mvp_requests SET status='failed_consumed',"
                "terminal_code='interrupted_after_claim',updated_at_us=?,version=version+1 "
                "WHERE status='claimed'",
                (now_us,),
            )
            return cursor.rowcount
        return self.store._write(mutate, at_us=now_us)

    def claim_notice(self, now_us: int) -> MvpRequest | None:
        def mutate(conn):
            row = conn.execute(
                "SELECT * FROM private_read_mvp_requests WHERE status='pending' "
                "AND notice_claimed=0 AND expires_at_us>? ORDER BY created_at_us LIMIT 1",
                (now_us,),
            ).fetchone()
            if row is None:
                return None
            cursor = conn.execute(
                "UPDATE private_read_mvp_requests SET notice_claimed=1,updated_at_us=?,version=version+1 "
                "WHERE request_id=? AND status='pending' AND notice_claimed=0",
                (now_us, row["request_id"]),
            )
            if cursor.rowcount != 1:
                return None
            return self._row(conn.execute(
                "SELECT * FROM private_read_mvp_requests WHERE request_id=?", (row["request_id"],)
            ).fetchone())
        return self.store._write(mutate, at_us=now_us)

    def resolve(self, request_id: str, context: MvpEventContext, approve: bool, now_us: int) -> bool:
        target = "approved" if approve else "denied"
        def mutate(conn):
            cursor = conn.execute(
                "UPDATE private_read_mvp_requests SET status=?,updated_at_us=?,version=version+1 "
                "WHERE request_id=? AND status='pending' AND expires_at_us>? AND owner_sender=? "
                "AND source_profile=? AND source_account=? AND source_chat=?",
                (target, now_us, request_id, now_us, context.requester.sender,
                 context.source_profile, context.source_account, context.source_chat),
            )
            return cursor.rowcount == 1
        return self.store._write(mutate, at_us=now_us)

    def fail_pending(self, request_id: str, now_us: int) -> bool:
        def mutate(conn):
            cursor = conn.execute(
                "UPDATE private_read_mvp_requests SET status='failed_consumed',"
                "terminal_code='ordinary_notice_failed',updated_at_us=?,version=version+1 "
                "WHERE request_id=? AND status='pending'",
                (now_us, request_id),
            )
            return cursor.rowcount == 1
        return self.store._write(mutate, at_us=now_us)

    def claim_approved(self, now_us: int) -> tuple[MvpRequest, str] | None:
        token = secrets.token_urlsafe(24)
        token_digest = self._digest(token)
        def mutate(conn):
            row = conn.execute(
                "SELECT * FROM private_read_mvp_requests WHERE status='approved' AND expires_at_us>? "
                "ORDER BY created_at_us LIMIT 1", (now_us,),
            ).fetchone()
            if row is None:
                return None
            cursor = conn.execute(
                "UPDATE private_read_mvp_requests SET status='claimed',claim_token_digest=?,"
                "updated_at_us=?,version=version+1 WHERE request_id=? AND status='approved'",
                (token_digest, now_us, row["request_id"]),
            )
            if cursor.rowcount != 1:
                return None
            current = conn.execute(
                "SELECT * FROM private_read_mvp_requests WHERE request_id=?", (row["request_id"],)
            ).fetchone()
            return self._row(current), token
        return self.store._write(mutate, at_us=now_us)

    def finish(self, request_id: str, claim_token: str, *, submitted: bool,
               provider_message_id: str | None, code: str, now_us: int) -> bool:
        final = "consumed" if submitted else "failed_consumed"
        def mutate(conn):
            cursor = conn.execute(
                "UPDATE private_read_mvp_requests SET status=?,provider_message_id=?,terminal_code=?,"
                "updated_at_us=?,version=version+1 WHERE request_id=? AND status='claimed' "
                "AND claim_token_digest=?",
                (final, provider_message_id if submitted else None, code, now_us,
                 request_id, self._digest(claim_token)),
            )
            return cursor.rowcount == 1
        return self.store._write(mutate, at_us=now_us)

    def get(self, request_id: str) -> MvpRequest | None:
        conn = self.store._connect()
        try:
            row = conn.execute(
                "SELECT * FROM private_read_mvp_requests WHERE request_id=?", (request_id,)
            ).fetchone()
            return self._row(row) if row is not None else None
        finally:
            conn.close()


class JsonTransport(Protocol):
    async def request(self, *, method: str, authority: str, path: str,
                      query: tuple[tuple[str, str], ...], headers: dict[str, str],
                      body: dict | None, timeout: float, max_bytes: int) -> dict: ...


class PrivateReadProvider(Protocol):
    async def read(self) -> str: ...


class PrivateReadAuthorizer(Protocol):
    async def check(self, request: MvpRequest) -> bool: ...


class FixedHttpJsonTransport:
    """Small built-in HTTP transport; tests use explicit fakes instead."""

    def __repr__(self) -> str:
        return "<FixedHttpJsonTransport redacted>"

    async def request(self, **kwargs) -> dict:
        return await asyncio.to_thread(self._request_sync, **kwargs)

    @staticmethod
    def _request_sync(*, method: str, authority: str, path: str,
                      query: tuple[tuple[str, str], ...], headers: dict[str, str],
                      body: dict | None, timeout: float, max_bytes: int) -> dict:
        url = authority + path
        if query:
            url += "?" + urllib_parse.urlencode(query)
        encoded = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        request = urllib_request.Request(url, data=encoded, headers=headers, method=method)
        try:
            with urllib_request.urlopen(request, timeout=timeout) as response:
                raw = response.read(max_bytes + 1)
        except (OSError, urllib_error.URLError, TimeoutError):
            raise JunoPrivateReadError("private provider unavailable") from None
        if len(raw) > max_bytes:
            raise JunoPrivateReadError("private provider response invalid")
        try:
            value = json.loads(
                raw.decode("utf-8", "strict"),
                object_pairs_hook=_unique_json_object,
            )
        except (ValueError, UnicodeError):
            raise JunoPrivateReadError("private provider response invalid") from None
        if type(value) is not dict:
            raise JunoPrivateReadError("private provider response invalid")
        return value


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _closed_json(path: Path, keys: set[str], maximum: int = 64 * 1024) -> dict:
    try:
        raw = _owner_file(path).read_bytes()
        if len(raw) > maximum:
            raise ValueError
        value = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=_unique_json_object
        )
    except BaseException:
        raise JunoPrivateReadError("private credential is invalid") from None
    return _exact_dict(value, keys, "private credential")


class GmailNewestInboxProvider:
    def __init__(self, config: JunoPrivateReadMvpConfig, transport: JsonTransport):
        self._config = config
        self._transport = transport

    def __repr__(self) -> str:
        return "<GmailNewestInboxProvider redacted>"

    async def read(self) -> str:
        try:
            token = _closed_json(
                self._config.gmail_token_file,
                {"access_token", "scope", "account", "expires_at_us"},
            )
            _closed_json(self._config.gmail_client_file, {"client_id", "client_secret"})
            if (
                token["scope"] != GMAIL_SCOPE
                or token["account"] != self._config.gmail_account
                or type(token["expires_at_us"]) is not int
                or token["expires_at_us"] <= time.time_ns() // 1000
            ):
                raise JunoPrivateReadError("private credential is invalid")
            access_token = _text(token["access_token"], "access token", 4096)
            headers = {"authorization": f"Bearer {access_token}", "accept": "application/json"}
            profile = await self._transport.request(
                method="GET", authority=GMAIL_AUTHORITY, path="/gmail/v1/users/me/profile",
                query=(), headers=headers, body=None, timeout=self._config.read_timeout,
                max_bytes=4096,
            )
            if profile != {"emailAddress": self._config.gmail_account}:
                raise JunoPrivateReadError("private account binding failed")
            listed = await self._transport.request(
                method="GET", authority=GMAIL_AUTHORITY, path="/gmail/v1/users/me/messages",
                query=(("q", "in:inbox"), ("maxResults", "1"), ("fields", "messages/id")),
                headers=headers, body=None, timeout=self._config.read_timeout,
                max_bytes=MAX_GMAIL_RESPONSE_BYTES,
            )
            if type(listed.get("messages")) is not list or len(listed["messages"]) != 1:
                raise JunoPrivateReadError("private provider response invalid")
            item = _exact_dict(listed["messages"][0], {"id"}, "Gmail list")
            message_id = _text(item["id"], "Gmail message ID", 256)
            message = await self._transport.request(
                method="GET", authority=GMAIL_AUTHORITY,
                path="/gmail/v1/users/me/messages/" + urllib_parse.quote(message_id, safe=""),
                query=(("format", "full"), (
                    "fields",
                    "id,payload(mimeType,headers(name,value),body(data,size),parts)",
                )),
                headers=headers, body=None, timeout=self._config.read_timeout,
                max_bytes=MAX_GMAIL_RESPONSE_BYTES,
            )
            return render_gmail_message(message, expected_id=message_id)
        except JunoPrivateReadError:
            raise
        except BaseException:
            raise JunoPrivateReadError("private read failed") from None


def render_gmail_message(message: object, *, expected_id: str) -> str:
    try:
        root = _exact_dict(message, {"id", "payload"}, "Gmail message")
        if root["id"] != expected_id:
            raise ValueError
        payload = _exact_dict(root["payload"], {"mimeType", "headers", "body"}, "Gmail payload")
        if payload["mimeType"] != "text/plain" or type(payload["headers"]) is not list:
            raise ValueError
        body = _exact_dict(payload["body"], {"data", "size"}, "Gmail body")
        if type(body["size"]) is not int or not 0 <= body["size"] <= MAX_PRIVATE_RENDER_BYTES:
            raise ValueError
        selected = {name: "" for name in ("from", "to", "cc", "subject", "date")}
        seen: set[str] = set()
        for header in payload["headers"]:
            row = _exact_dict(header, {"name", "value"}, "Gmail header")
            name = str(row["name"]).lower()
            if name in selected:
                if (
                    name in seen
                    or type(row["value"]) is not str
                    or "\x00" in row["value"]
                    or "\r" in row["value"]
                    or "\n" in row["value"]
                ):
                    raise ValueError
                if len(row["value"].encode("utf-8")) > 2048:
                    raise ValueError
                selected[name] = row["value"]
                seen.add(name)
        encoded = _text(body["data"], "Gmail body", MAX_PRIVATE_RENDER_BYTES * 2)
        padding = "=" * (-len(encoded) % 4)
        decoded = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
        if len(decoded) != body["size"] or len(decoded) > MAX_PRIVATE_RENDER_BYTES:
            raise ValueError
        text = decoded.decode("utf-8", "strict").replace("\r\n", "\n").replace("\r", "\n")
        rendered = (
            f"From: {selected['from']}\nTo: {selected['to']}\nCc: {selected['cc']}\n"
            f"Subject: {selected['subject']}\nDate: {selected['date']}\nBody:\n{text}"
        )
        if len(rendered.encode("utf-8")) > MAX_PRIVATE_RENDER_BYTES:
            raise ValueError
        return rendered
    except BaseException:
        raise JunoPrivateReadError("private provider response invalid") from None


class OpenFgaChecker:
    def __init__(self, config: JunoPrivateReadMvpConfig, transport: JsonTransport):
        self._config = config
        self._transport = transport
        self.last_body: dict | None = None

    def __repr__(self) -> str:
        return "<OpenFgaChecker redacted>"

    async def check(self, request: MvpRequest) -> bool:
        body = {
            "authorization_model_id": self._config.openfga_model_id,
            "consistency": "HIGHER_CONSISTENCY",
            "tuple_key": {
                "user": "requester:" + request.requester,
                "relation": "read",
                "object": "capability:" + request.capability_id,
            },
            "context": {
                "request_id": request.request_id,
                "requester": request.requester,
                "capability": request.capability_id,
                "destination_account": request.destination_account,
                "destination_chat": request.destination_chat,
                "source_profile": request.source_profile,
                "source_account": request.source_account,
                "expires_at_us": request.expires_at_us,
                "descriptor_digest": request.descriptor_digest,
            },
        }
        self.last_body = body
        try:
            credential = _owner_file(self._config.openfga_credential_file).read_text(
                encoding="utf-8"
            ).strip()
            credential = _text(credential, "OpenFGA credential", 4096)
            response = await self._transport.request(
                method="POST", authority=OPENFGA_AUTHORITY,
                path=f"/stores/{urllib_parse.quote(self._config.openfga_store_id, safe='')}/check",
                query=(), headers={"authorization": "Bearer " + credential,
                                   "content-type": "application/json", "accept": "application/json"},
                body=body, timeout=self._config.request_timeout, max_bytes=4096,
            )
            return type(response.get("allowed")) is bool and response == {"allowed": True}
        except BaseException:
            return False


@dataclass(frozen=True, slots=True, repr=False)
class SensitiveSubmission:
    state: str
    message_id: str | None
    account: str
    destination: str

    def __post_init__(self) -> None:
        if self.state not in {"submitted", "failed", "unknown"}:
            raise ValueError("invalid sensitive submission state")

    def __repr__(self) -> str:
        return f"<SensitiveSubmission state={self.state!r}>"


class SensitiveSubmitter(Protocol):
    async def submit(self, *, request: MvpRequest, plaintext: str) -> SensitiveSubmission: ...


class OrdinaryNotifier(Protocol):
    async def send(self, text: str) -> str: ...


@dataclass(frozen=True, slots=True, repr=False)
class JunoPrivateReadDependencies:
    openfga: PrivateReadAuthorizer
    gmail: PrivateReadProvider
    ordinary: OrdinaryNotifier
    sensitive: SensitiveSubmitter

    def __repr__(self) -> str:
        return "<JunoPrivateReadDependencies redacted>"


@dataclass(frozen=True, slots=True)
class ApprovalIntercept:
    matched: bool
    mutated: bool
    response: str | None


class JunoPrivateReadMvpHost:
    def __init__(self, config: JunoPrivateReadMvpConfig, dependencies: JunoPrivateReadDependencies):
        self.config = config
        self.dependencies = dependencies
        self.store: AuthorizationTaskStore | None = None
        self.repository: MvpAuthorizationRepository | None = None
        self._context: ContextVar[MvpEventContext | None] = ContextVar(
            "juno-private-read-mvp-event", default=None
        )
        self._lock = None
        self._running = False
        self._task: asyncio.Task | None = None
        self._coordinator: CoordinatorIdentity | None = None

    async def start(self, *, _background_worker: bool = True) -> bool:
        master = _load_or_create_state_key(self.config.state_dir)
        store = AuthorizationTaskStore(
            db_path=self.config.state_dir / "authorization.db",
            audit_hmac_key=hashlib.sha256(master + b"audit").digest(),
            request_hmac_key=hashlib.sha256(master + b"request").digest(),
            key_version="juno-mvp-v1",
        )
        lock = store.acquire_coordinator_lock()
        now_us = time.time_ns() // 1000
        coordinator = CoordinatorIdentity(
            "juno-private-read-mvp",
            hmac.new(master, b"coordinator", hashlib.sha256).hexdigest(),
        )
        if lock is None or store.acquire_coordinator(
            coordinator,
            now_us=now_us, lease_expires_at_us=now_us + 300_000_000,
            lock_session=lock,
        ) is None:
            store.close()
            return False
        self.store = store
        self.repository = MvpAuthorizationRepository(store, master)
        self.repository.recover_claimed(time.time_ns() // 1000)
        self._lock = lock
        self._coordinator = coordinator
        self._running = True
        from tools.private_read_request_tool import configure_private_read_mvp_handler
        configure_private_read_mvp_handler(self.request_from_tool, health_check=lambda: self._running)
        if _background_worker:
            self._task = asyncio.create_task(self._run(), name="juno-private-read-mvp")
        return True

    async def _run(self) -> None:
        try:
            while self._running:
                worked = await self.process_once()
                await asyncio.sleep(0 if worked else 0.1)
        except asyncio.CancelledError:
            raise
        except BaseException:
            self._running = False

    async def stop(self) -> None:
        self._running = False
        from tools.private_read_request_tool import configure_private_read_mvp_handler
        configure_private_read_mvp_handler(None)
        task, self._task = self._task, None
        if task is not None and task is not asyncio.current_task():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        if self.store is not None:
            self.store.close()
        self.store = None
        self.repository = None
        self._lock = None
        self._coordinator = None

    def is_healthy(self) -> bool:
        return self._running and self.store is not None and self.repository is not None

    def health(self) -> dict[str, object]:
        return {"enabled": self._running, "ready": self.is_healthy(), "worker_running": self._running}

    def bind_event(self, event: MessageEvent | None):
        from gateway.trusted_private_read_host import TrustedPrivateReadEventBinding
        context = self.context_for_event(event) if event is not None else None
        return TrustedPrivateReadEventBinding(self._context.set(context), context is not None)

    def unbind_event(self, binding) -> None:
        from gateway.trusted_private_read_host import TrustedPrivateReadEventBinding
        if type(binding) is not TrustedPrivateReadEventBinding or not isinstance(binding.token, Token):
            raise TypeError("exact trusted event binding is required")
        self._context.reset(binding.token)

    def context_for_event(self, event: MessageEvent) -> MvpEventContext | None:
        source = getattr(event, "source", None)
        if source is None or source.platform is not Platform.WHATSAPP:
            return None
        profile = source.profile or "default"
        account = event.metadata.get("whatsapp_account_id") if type(event.metadata) is dict else None
        sender = source.user_id
        requester = self.config.requester(sender) if type(sender) is str else None
        if (
            requester is None
            or profile != self.config.profile
            or account != self.config.ordinary_account
            or source.chat_id != self.config.ordinary_chat
            or type(event.message_id) is not str
            or not event.message_id
        ):
            return None
        return MvpEventContext(
            requester=requester, source_profile=profile, source_account=account,
            source_chat=source.chat_id, source_message=event.message_id,
        )

    def request_from_tool(self, capability_id: str) -> tuple[str, str]:
        if not self._running or capability_id != CAPABILITY_ID or self.repository is None:
            raise JunoPrivateReadError("private request unavailable")
        context = self._context.get()
        if context is None:
            raise JunoPrivateReadError("private request unavailable")
        request = self.repository.create(context, self.config)
        return request.status, request.request_id

    def intercept_approval(self, event: MessageEvent) -> ApprovalIntercept:
        text = event.text or ""
        if not text.startswith("/approve") and not text.startswith("/deny"):
            return ApprovalIntercept(False, False, None)
        matched = _APPROVAL_RE.fullmatch(text)
        if matched is None:
            return ApprovalIntercept(True, False, "Private-read decision rejected.")
        context = self.context_for_event(event)
        if (
            context is None
            or context.requester.sender != self.config.owner_sender
            or self.repository is None
        ):
            return ApprovalIntercept(True, False, "Private-read decision rejected.")
        changed = self.repository.resolve(
            matched.group(2), context, matched.group(1) == "approve", time.time_ns() // 1000
        )
        return ApprovalIntercept(
            True, changed,
            "Private-read request approved." if changed and matched.group(1) == "approve"
            else "Private-read request denied." if changed
            else "Private-read decision rejected.",
        )

    async def process_once(self) -> bool:
        repository = self.repository
        if not self._running or repository is None:
            return False
        now_us = time.time_ns() // 1000
        if (
            self.store is None
            or self._lock is None
            or self._coordinator is None
            or self.store.acquire_coordinator(
                self._coordinator,
                now_us=now_us,
                lease_expires_at_us=now_us + 300_000_000,
                lock_session=self._lock,
            ) is None
        ):
            self._running = False
            return False
        repository.expire_due(now_us)
        notice = repository.claim_notice(now_us)
        if notice is not None:
            requester = self.config.requester(notice.requester)
            label = requester.label if requester is not None else "trusted requester"
            expiry_seconds = max(0, (notice.expires_at_us - now_us) // 1_000_000)
            text = (
                f"Private-read approval requested by {label} for {notice.capability_id}. "
                f"Expires in {expiry_seconds}s. /approve {notice.request_id} or /deny {notice.request_id}"
            )
            try:
                await asyncio.wait_for(self.dependencies.ordinary.send(text), self.config.request_timeout)
            except BaseException:
                repository.fail_pending(notice.request_id, time.time_ns() // 1000)
            return True
        claimed = repository.claim_approved(now_us)
        if claimed is None:
            return False
        request, token = claimed
        submitted = False
        provider_message_id = None
        code = "failed"
        plaintext = None
        try:
            # The only positive authorization check is fresh, uncached and
            # immediately adjacent to private provider access.
            allowed = await asyncio.wait_for(
                self.dependencies.openfga.check(request), self.config.request_timeout
            )
            if not allowed or time.time_ns() // 1000 >= request.expires_at_us:
                code = "policy_denied"
                return True
            plaintext = await asyncio.wait_for(
                self.dependencies.gmail.read(), self.config.read_timeout
            )
            result = await asyncio.wait_for(
                self.dependencies.sensitive.submit(request=request, plaintext=plaintext),
                self.config.submission_timeout,
            )
            if (
                type(result) is SensitiveSubmission
                and result.state == "submitted"
                and type(result.message_id) is str
                and _SENSITIVE_MESSAGE_ID_RE.fullmatch(result.message_id)
                and result.account == request.destination_account
                and result.destination == request.destination_chat
            ):
                submitted = True
                provider_message_id = result.message_id
                code = "submitted"
            else:
                code = "submission_mismatch"
        except BaseException:
            code = "failed"
        finally:
            plaintext = None
            repository.finish(
                request.request_id, token, submitted=submitted,
                provider_message_id=provider_message_id, code=code,
                now_us=time.time_ns() // 1000,
            )
        return True


class _GatewayOrdinaryNotifier:
    def __init__(self, runner: object, config: JunoPrivateReadMvpConfig):
        self._runner = runner
        self._config = config

    async def send(self, text: str) -> str:
        profile_maps = getattr(self._runner, "_profile_adapters", {})
        if self._config.profile == getattr(self._runner, "profile", "default"):
            adapter = getattr(self._runner, "adapters", {}).get(Platform.WHATSAPP)
        else:
            adapter = profile_maps.get(self._config.profile, {}).get(Platform.WHATSAPP)
        if adapter is None:
            raise JunoPrivateReadError("ordinary transport unavailable")
        result = await adapter.send(self._config.ordinary_chat, text)
        message_id = getattr(result, "message_id", None)
        if getattr(result, "success", False) is not True or not message_id:
            raise JunoPrivateReadError("ordinary transport unavailable")
        return str(message_id)


class _SensitiveHttpSubmitter:
    def __init__(self, config: JunoPrivateReadMvpConfig, transport: JsonTransport):
        self._config = config
        self._transport = transport

    async def submit(self, *, request: MvpRequest, plaintext: str) -> SensitiveSubmission:
        capability = _owner_file(self._config.sensitive_capability_file).read_text(
            encoding="utf-8"
        ).strip()
        response = await self._transport.request(
            method="POST", authority="http://127.0.0.1:3011", path="/v1/submit",
            query=(), headers={"x-hermes-sensitive-capability": capability,
                               "content-type": "application/json", "accept": "application/json"},
            body={"request_id": request.request_id,
                  "registration": self._config.sensitive_registration,
                  "session": self._config.sensitive_session,
                  "account": request.destination_account,
                  "destination": request.destination_chat,
                  "private_value": plaintext},
            timeout=self._config.submission_timeout, max_bytes=4096,
        )
        if set(response) != {"state", "message_id", "account", "destination"}:
            return SensitiveSubmission("unknown", None, "mismatch", "mismatch")
        return SensitiveSubmission(
            state=response["state"], message_id=response["message_id"],
            account=response["account"], destination=response["destination"],
        )


def compose_juno_private_read_mvp_services(
    runner: object, config: JunoPrivateReadMvpConfig
) -> JunoPrivateReadDependencies:
    """Concrete code-owned production composition; config supplies data only."""
    transport = FixedHttpJsonTransport()
    return JunoPrivateReadDependencies(
        openfga=OpenFgaChecker(config, transport),
        gmail=GmailNewestInboxProvider(config, transport),
        ordinary=_GatewayOrdinaryNotifier(runner, config),
        sensitive=_SensitiveHttpSubmitter(config, transport),
    )


def _load_or_create_state_key(state_dir: Path) -> bytes:
    path = state_dir / "mvp-store.key"
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        descriptor = None
    if descriptor is not None:
        value = secrets.token_bytes(32)
        try:
            written = 0
            while written < len(value):
                written += os.write(descriptor, value[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    try:
        value = _owner_file(path).read_bytes()
    except BaseException:
        raise JunoPrivateReadError("private state key is invalid") from None
    if len(value) != 32:
        raise JunoPrivateReadError("private state key is invalid")
    return value


def private_read_tool_surface_is_closed() -> bool:
    """Verify the pilot model surface resolves to the one reviewed tool."""
    try:
        from model_tools import get_tool_definitions

        definitions = get_tool_definitions(
            enabled_toolsets=["private-read-request"],
            quiet_mode=True,
            skip_tool_search_assembly=True,
        )
        names = {item["function"]["name"] for item in definitions}
        return names == {"private_read_request"}
    except BaseException:
        return False


__all__ = [
    "ApprovalIntercept", "CAPABILITY_ID", "GMAIL_CONTRACT_VERSION", "GMAIL_SCOPE",
    "GmailNewestInboxProvider", "JunoPrivateReadDependencies", "JunoPrivateReadError",
    "JunoPrivateReadMvpConfig", "JunoPrivateReadMvpHost", "MvpAuthorizationRepository",
    "MvpEventContext", "MvpRequest", "OPENFGA_CLIENT_CONTRACT_VERSION",
    "OpenFgaChecker", "PrivateReadAuthorizer", "PrivateReadProvider",
    "SensitiveSubmission",
    "compose_juno_private_read_mvp_services", "private_read_tool_surface_is_closed",
    "render_gmail_message",
]
