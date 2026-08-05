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
MAX_GMAIL_PARTS = 64
MAX_GMAIL_DEPTH = 8
MAX_GMAIL_HEADERS = 128
_APPROVAL_RE = re.compile(r"^/(approve|deny) ([A-Za-z0-9_-]{16,80})$")
_SENSITIVE_MESSAGE_ID_RE = re.compile(r"^3EB0[0-9A-F]{18}$")
_WHATSAPP_DIRECT_RE = re.compile(r"^\d{1,32}@(s\.whatsapp\.net|lid)$")
_WHATSAPP_CHAT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}@(s\.whatsapp\.net|lid|g\.us)$")


class JunoPrivateReadError(RuntimeError):
    """A fixed, content-free error safe to cross ordinary boundaries."""

    def __str__(self) -> str:
        return "private read failed"

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


def _event_id(value: object) -> str | None:
    if type(value) is not str or not value or value != value.strip():
        return None
    if len(value.encode("utf-8")) > 512 or any(ord(character) < 32 for character in value):
        return None
    return value


@dataclass(frozen=True, slots=True)
class JunoRequester:
    sender: str
    source_chat: str
    label: str
    sensitive_destination: str


@dataclass(frozen=True, slots=True, repr=False)
class JunoPrivateReadMvpConfig:
    state_dir: Path
    profile: str
    ordinary_account: str
    owner_sender: str
    owner_chat: str
    requesters: tuple[JunoRequester, ...]
    openfga_store_id: str
    openfga_model_id: str
    openfga_credential_file: Path
    gmail_client_file: Path
    gmail_token_file: Path
    gmail_account: str
    sensitive_account: str
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
            raw["ordinary"], {"account", "owner_sender", "owner_chat"}, "ordinary"
        )
        openfga = _exact_dict(
            raw["openfga"], {"store_id", "model_id", "api_credential_file"}, "openfga"
        )
        gmail = _exact_dict(
            raw["gmail"], {"oauth_client_file", "token_file", "account"}, "gmail"
        )
        sensitive = _exact_dict(
            raw["sensitive"],
            {"account", "capability_file"},
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
                item,
                {"sender", "source_chat", "label", "sensitive_destination"},
                "requester",
            )
            requester = JunoRequester(
                sender=_jid(row["sender"], "requester sender"),
                source_chat=_jid(row["source_chat"], "requester source chat", direct=False),
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
            owner_sender=owner,
            owner_chat=_jid(ordinary["owner_chat"], "owner chat", direct=False),
            requesters=tuple(requesters),
            openfga_store_id=_text(openfga["store_id"], "OpenFGA store"),
            openfga_model_id=_text(openfga["model_id"], "OpenFGA model"),
            openfga_credential_file=credential,
            gmail_client_file=client,
            gmail_token_file=token,
            gmail_account=_text(gmail["account"], "Gmail account"),
            sensitive_account=sensitive_account,
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
    source_message: str
    capability_id: str
    destination_account: str
    destination_chat: str
    owner_sender: str
    approval_chat: str
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

    def __init__(self, store: AuthorizationTaskStore, key: bytes,
                 *, clock_us: Callable[[], int] | None = None):
        if type(store) is not AuthorizationTaskStore or len(key) < 32:
            raise TypeError("exact authorization store and key are required")
        self.store = store
        self._key = bytes(key)
        self._clock_us = clock_us or (lambda: time.time_ns() // 1000)

    @staticmethod
    def _row(row) -> MvpRequest:
        return MvpRequest(
            request_id=row["request_id"], requester=row["requester"],
            source_profile=row["source_profile"], source_account=row["source_account"],
            source_chat=row["source_chat"], source_message=row["source_message"],
            capability_id=row["capability_id"],
            destination_account=row["destination_account"],
            destination_chat=row["destination_chat"], owner_sender=row["owner_sender"],
            approval_chat=row["approval_chat"],
            descriptor_digest=row["descriptor_digest"], created_at_us=row["created_at_us"],
            expires_at_us=row["expires_at_us"], status=row["status"],
            notice_claimed=bool(row["notice_claimed"]), version=row["version"],
        )

    def _digest(self, value: str) -> str:
        return hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def create(self, context: MvpEventContext, config: JunoPrivateReadMvpConfig) -> MvpRequest:
        now_us = self._clock_us()
        expires_us = now_us + int(config.approval_timeout * 1_000_000)
        request_id = secrets.token_urlsafe(18)
        descriptor = json.dumps(
            {
                "capability": CAPABILITY_ID,
                "approval_chat": config.owner_chat,
                "destination": context.requester.sensitive_destination,
                "owner_sender": config.owner_sender,
                "requester": context.requester.sender,
                "source_account": context.source_account,
                "source_chat": context.source_chat,
                "source_message": context.source_message,
                "source_profile": context.source_profile,
                "expires_at_us": expires_us,
            }, sort_keys=True, separators=(",", ":"),
        )
        digest = self._digest(descriptor)
        initial = "approved" if hmac.compare_digest(context.requester.sender, config.owner_sender) else "pending"

        def mutate(conn):
            conn.execute(
                "INSERT INTO private_read_mvp_requests "
                "(request_id,requester,source_profile,source_account,source_chat,source_message,"
                "capability_id,destination_account,destination_chat,owner_sender,approval_chat,"
                "descriptor_digest,created_at_us,expires_at_us,status,updated_at_us) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                (request_id, context.requester.sender, context.source_profile,
                 context.source_account, context.source_chat, context.source_message, CAPABILITY_ID,
                 config.sensitive_account, context.requester.sensitive_destination,
                 config.owner_sender, config.owner_chat, digest, now_us, expires_us, initial, now_us),
            )
            return self._row(conn.execute(
                "SELECT * FROM private_read_mvp_requests WHERE source_profile=? "
                "AND source_account=? AND source_chat=? AND requester=? "
                "AND source_message=? AND capability_id=?",
                (context.source_profile, context.source_account, context.source_chat,
                 context.requester.sender, context.source_message, CAPABILITY_ID),
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

    def recover_claimed_notices(self, now_us: int) -> int:
        """Consume notice sends interrupted after the durable claim boundary."""
        def mutate(conn):
            cursor = conn.execute(
                "UPDATE private_read_mvp_requests SET status='failed_consumed',"
                "terminal_code='interrupted_notice_claim',updated_at_us=?,version=version+1 "
                "WHERE status='pending' AND notice_claimed=1",
                (now_us,),
            )
            return cursor.rowcount
        return self.store._write(mutate, at_us=now_us)

    def recover_incomplete_bindings(self, now_us: int) -> int:
        """Consume checkpoint rows that predate source/approval chat binding."""
        def mutate(conn):
            cursor = conn.execute(
                "UPDATE private_read_mvp_requests SET status='failed_consumed',"
                "terminal_code='incomplete_authority_binding',updated_at_us=?,version=version+1 "
                "WHERE status IN ('pending','approved','claimed') "
                "AND (source_message='' OR approval_chat='')",
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
                "AND source_profile=? AND source_account=? AND approval_chat=?",
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
                      body: dict | None, timeout: float, max_bytes: int) -> object: ...


class PrivateReadProvider(Protocol):
    async def read(self) -> str: ...


class PrivateReadAuthorizer(Protocol):
    async def check(self, request: MvpRequest) -> bool: ...


class _RejectRedirects(urllib_request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _TransportFailure:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<private transport failure>"


_TRANSPORT_FAILURE = _TransportFailure()


class FixedHttpJsonTransport:
    """Fixed-authority, no-redirect JSON transport with sealed failures."""

    def __init__(self, *, _test_authorities: dict[str, str] | None = None):
        self._authorities = {
            GMAIL_AUTHORITY: GMAIL_AUTHORITY,
            OPENFGA_AUTHORITY: OPENFGA_AUTHORITY,
            "http://127.0.0.1:3011": "http://127.0.0.1:3011",
        }
        if _test_authorities is not None:
            if type(_test_authorities) is not dict or not set(_test_authorities) <= set(self._authorities):
                raise TypeError("invalid test authority map")
            self._authorities.update(_test_authorities)

    def __repr__(self) -> str:
        return "<FixedHttpJsonTransport redacted>"

    async def request(self, **kwargs) -> object:
        try:
            actual = self._authorities.get(kwargs.get("authority"))
            if actual is None:
                return _TRANSPORT_FAILURE
            kwargs["authority"] = actual
            return await asyncio.to_thread(self._request_sync, **kwargs)
        except BaseException:
            return _TRANSPORT_FAILURE

    @staticmethod
    def _request_sync(*, method: str, authority: str, path: str,
                      query: tuple[tuple[str, str], ...], headers: dict[str, str],
                      body: dict | None, timeout: float, max_bytes: int) -> object:
        try:
            url = authority + path
            if query:
                url += "?" + urllib_parse.urlencode(query)
            encoded = None if body is None else json.dumps(
                body, sort_keys=True, separators=(",", ":")
            ).encode()
            request = urllib_request.Request(url, data=encoded, headers=headers, method=method)
            with urllib_request.build_opener(_RejectRedirects()).open(
                request, timeout=timeout
            ) as response:
                if not 200 <= response.status < 300:
                    return _TRANSPORT_FAILURE
                raw = response.read(max_bytes + 1)
            if len(raw) > max_bytes:
                return _TRANSPORT_FAILURE
            value = json.loads(
                raw.decode("utf-8", "strict"),
                object_pairs_hook=_unique_json_object,
            )
            return value if type(value) is dict else _TRANSPORT_FAILURE
        except BaseException:
            return _TRANSPORT_FAILURE


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _closed_json(path: Path, keys: set[str], maximum: int = 64 * 1024) -> dict | None:
    try:
        raw = _owner_file(path).read_bytes()
        if len(raw) > maximum:
            raise ValueError
        value = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=_unique_json_object
        )
        if type(value) is not dict or set(value) != keys:
            return None
        return value
    except BaseException:
        return None


class GmailNewestInboxProvider:
    def __init__(self, config: JunoPrivateReadMvpConfig, transport: JsonTransport):
        self._config = config
        self._transport = transport

    def __repr__(self) -> str:
        return "<GmailNewestInboxProvider redacted>"

    async def read(self) -> str:
        result = await _sealed_gmail_read(self._config, self._transport)
        if result is None:
            raise JunoPrivateReadError("private read failed") from None
        return result


async def _sealed_gmail_read(
    config: JunoPrivateReadMvpConfig, transport: JsonTransport
) -> str | None:
        try:
            token = _closed_json(
                config.gmail_token_file,
                {"access_token", "scope", "account", "expires_at_us"},
            )
            client = _closed_json(config.gmail_client_file, {"client_id", "client_secret"})
            if token is None or client is None or (
                token["scope"] != GMAIL_SCOPE
                or token["account"] != config.gmail_account
                or type(token["expires_at_us"]) is not int
                or token["expires_at_us"] <= time.time_ns() // 1000
            ):
                return None
            access_token = _text(token["access_token"], "access token", 4096)
            headers = {"authorization": f"Bearer {access_token}", "accept": "application/json"}
            profile = await transport.request(
                method="GET", authority=GMAIL_AUTHORITY, path="/gmail/v1/users/me/profile",
                query=(("fields", "emailAddress"),), headers=headers, body=None,
                timeout=config.read_timeout,
                max_bytes=4096,
            )
            if not _gmail_profile_matches(profile, config.gmail_account):
                return None
            listed = await transport.request(
                method="GET", authority=GMAIL_AUTHORITY, path="/gmail/v1/users/me/messages",
                query=(("q", "in:inbox"), ("maxResults", "1"),
                       ("includeSpamTrash", "false"), ("fields", "messages/id")),
                headers=headers, body=None, timeout=config.read_timeout,
                max_bytes=MAX_GMAIL_RESPONSE_BYTES,
            )
            if type(listed) is not dict or type(listed.get("messages")) is not list \
                    or len(listed["messages"]) != 1:
                return None
            item = listed["messages"][0]
            if type(item) is not dict or set(item) != {"id"}:
                return None
            message_id = _text(item["id"], "Gmail message ID", 256)
            message = await transport.request(
                method="GET", authority=GMAIL_AUTHORITY,
                path="/gmail/v1/users/me/messages/" + urllib_parse.quote(message_id, safe=""),
                query=(("format", "full"), (
                    "fields",
                    "id,payload(mimeType,headers(name,value),body(data,size,attachmentId),"
                    "parts(mimeType,headers(name,value),body(data,size,attachmentId),parts))",
                )),
                headers=headers, body=None, timeout=config.read_timeout,
                max_bytes=MAX_GMAIL_RESPONSE_BYTES,
            )
            return _sealed_render_gmail_message(message, message_id)
        except BaseException:
            return None


def _gmail_profile_matches(profile: object, account: str) -> bool:
    if type(profile) is not dict:
        return False
    if set(profile) == {"emailAddress"}:
        return profile["emailAddress"] == account
    if set(profile) == {"emailAddress", "messagesTotal", "threadsTotal", "historyId"}:
        return (
            profile["emailAddress"] == account
            and type(profile["messagesTotal"]) is int
            and type(profile["threadsTotal"]) is int
            and type(profile["historyId"]) is str
            and bool(profile["historyId"])
        )
    return False


def render_gmail_message(message: object, *, expected_id: str) -> str:
    result = _sealed_render_gmail_message(message, expected_id)
    message = None
    expected_id = ""
    if result is None:
        raise JunoPrivateReadError("private provider response invalid") from None
    return result


def _sealed_render_gmail_message(message: object, expected_id: str) -> str | None:
    try:
        if type(message) is not dict or set(message) != {"id", "payload"}:
            return None
        root = message
        if root["id"] != expected_id:
            return None
        headers, encoded, size = _select_gmail_plaintext(root["payload"])
        selected = {name: "(not present)" for name in ("from", "to", "cc", "subject", "date")}
        seen: set[str] = set()
        for row in headers:
            if type(row) is not dict or set(row) != {"name", "value"}:
                return None
            name = row["name"].lower() if type(row["name"]) is str else ""
            if name in selected:
                value = row["value"]
                if name in seen or type(value) is not str or any(c in value for c in "\x00\r\n"):
                    return None
                if not value or len(value.encode("utf-8")) > 2048:
                    return None
                selected[name] = row["value"]
                seen.add(name)
        padding = "=" * (-len(encoded) % 4)
        decoded = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
        if len(decoded) != size or len(decoded) > MAX_PRIVATE_RENDER_BYTES:
            return None
        text = decoded.decode("utf-8", "strict").replace("\r\n", "\n").replace("\r", "\n")
        rendered = (
            f"From: {selected['from']}\nTo: {selected['to']}\nCc: {selected['cc']}\n"
            f"Subject: {selected['subject']}\nDate: {selected['date']}\nBody:\n{text}"
        )
        return rendered if len(rendered.encode("utf-8")) <= MAX_PRIVATE_RENDER_BYTES else None
    except BaseException:
        return None


def _select_gmail_plaintext(payload: object) -> tuple[list[dict], str, int]:
    root_headers: list[dict] = []
    plain: list[tuple[str, int]] = []
    part_count = 0
    header_count = 0

    def visit(part: object, depth: int, *, root: bool = False) -> None:
        nonlocal part_count, header_count
        if type(part) is not dict or depth > MAX_GMAIL_DEPTH:
            raise ValueError
        if not set(part) <= {"mimeType", "headers", "body", "parts"} \
                or "mimeType" not in part:
            raise ValueError
        part_count += 1
        if part_count > MAX_GMAIL_PARTS:
            raise ValueError
        headers = part.get("headers", [])
        if type(headers) is not list:
            raise ValueError
        header_count += len(headers)
        if header_count > MAX_GMAIL_HEADERS:
            raise ValueError
        if root:
            root_headers.extend(headers)
        for header in headers:
            if type(header) is not dict or set(header) != {"name", "value"}:
                raise ValueError
            if str(header["name"]).lower() == "content-disposition" \
                    and "attachment" in str(header["value"]).lower():
                raise ValueError
        body = part.get("body", {})
        if type(body) is not dict or not set(body) <= {"data", "size", "attachmentId"}:
            raise ValueError
        if "attachmentId" in body:
            raise ValueError
        mime = part["mimeType"]
        children = part.get("parts", [])
        if children:
            if type(children) is not list or not str(mime).startswith("multipart/"):
                raise ValueError
            for child in children:
                visit(child, depth + 1)
        elif mime == "text/plain":
            if set(body) != {"data", "size"} or type(body["data"]) is not str \
                    or not body["data"] or type(body["size"]) is not int \
                    or not 0 <= body["size"] <= MAX_PRIVATE_RENDER_BYTES:
                raise ValueError
            if len(body["data"].encode("utf-8")) > MAX_PRIVATE_RENDER_BYTES * 2:
                raise ValueError
            plain.append((body["data"], body["size"]))
        elif str(mime).startswith("multipart/"):
            raise ValueError
        elif mime != "text/html":
            # The MVP permits only the ignorable HTML alternative beside the
            # one selected plain-text leaf. Other leaf types are attachments
            # or unsupported content and fail the whole operation closed.
            raise ValueError

    visit(payload, 0, root=True)
    if len(plain) != 1:
        raise ValueError
    return root_headers, plain[0][0], plain[0][1]


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
                "source_chat": request.source_chat,
                "source_message": request.source_message,
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


@dataclass(frozen=True, slots=True, repr=False)
class SensitiveRuntimeIdentity:
    registration: str
    account: str
    session: str

    def __repr__(self) -> str:
        return "<SensitiveRuntimeIdentity redacted>"


class SensitiveSubmitter(Protocol):
    async def observe_identity(self, *, request: MvpRequest) -> SensitiveRuntimeIdentity | None: ...

    async def submit(
        self, *, request: MvpRequest, plaintext: str, identity: SensitiveRuntimeIdentity
    ) -> SensitiveSubmission: ...


class OrdinaryNotifier(Protocol):
    async def send(self, destination: str, text: str) -> str: ...


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
    def __init__(self, config: JunoPrivateReadMvpConfig, dependencies: JunoPrivateReadDependencies,
                 *, _clock_us: Callable[[], int] | None = None):
        self.config = config
        self.dependencies = dependencies
        self.store: AuthorizationTaskStore | None = None
        self.repository: MvpAuthorizationRepository | None = None
        self._context: ContextVar[MvpEventContext | None] = ContextVar(
            "juno-private-read-mvp-event", default=None
        )
        self._lock = None
        self._running = False
        self._healthy = False
        self._task: asyncio.Task | None = None
        self._coordinator: CoordinatorIdentity | None = None
        self._clock_us = _clock_us or (lambda: time.time_ns() // 1000)

    async def start(self, *, _background_worker: bool = True) -> bool:
        master = _load_or_create_state_key(self.config.state_dir)
        store = AuthorizationTaskStore(
            db_path=self.config.state_dir / "authorization.db",
            audit_hmac_key=hashlib.sha256(master + b"audit").digest(),
            request_hmac_key=hashlib.sha256(master + b"request").digest(),
            key_version="juno-mvp-v1",
        )
        lock = store.acquire_coordinator_lock()
        now_us = self._clock_us()
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
        self.repository = MvpAuthorizationRepository(store, master, clock_us=self._clock_us)
        self.repository.recover_claimed(self._clock_us())
        self.repository.recover_claimed_notices(self._clock_us())
        self.repository.recover_incomplete_bindings(self._clock_us())
        self._lock = lock
        self._coordinator = coordinator
        self._running = True
        self._healthy = True
        from tools.private_read_request_tool import configure_private_read_mvp_handler
        configure_private_read_mvp_handler(self.request_from_tool, health_check=self.is_healthy)
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
            self._healthy = False

    async def stop(self) -> None:
        self._running = False
        self._healthy = False
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
        return self._running and self._healthy and self.store is not None and self.repository is not None

    def health(self) -> dict[str, object]:
        return {"enabled": self._running, "ready": self.is_healthy(),
                "worker_running": self._running and self._healthy}

    def bind_event(self, event: MessageEvent | None):
        from gateway.trusted_private_read_host import TrustedPrivateReadEventBinding
        context = self.context_for_event(event) if event is not None and self.is_healthy() else None
        return TrustedPrivateReadEventBinding(self._context.set(context), context is not None)

    def unbind_event(self, binding) -> None:
        from gateway.trusted_private_read_host import TrustedPrivateReadEventBinding
        if type(binding) is not TrustedPrivateReadEventBinding or not isinstance(binding.token, Token):
            raise TypeError("exact trusted event binding is required")
        try:
            self._context.reset(binding.token)
        except BaseException:
            self._healthy = False
            raise

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
            or source.chat_id != requester.source_chat
            or _event_id(event.message_id) is None
        ):
            return None
        return MvpEventContext(
            requester=requester, source_profile=profile, source_account=account,
            source_chat=source.chat_id, source_message=_event_id(event.message_id),
        )

    def request_from_tool(self, capability_id: str) -> tuple[str, str]:
        if not self.is_healthy() or capability_id != CAPABILITY_ID or self.repository is None:
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
        context = self._approval_context_for_event(event)
        if (
            context is None
            or context.requester.sender != self.config.owner_sender
            or self.repository is None
        ):
            return ApprovalIntercept(True, False, "Private-read decision rejected.")
        changed = self.repository.resolve(
            matched.group(2), context, matched.group(1) == "approve", self._clock_us()
        )
        return ApprovalIntercept(
            True, changed,
            "Private-read request approved." if changed and matched.group(1) == "approve"
            else "Private-read request denied." if changed
            else "Private-read decision rejected.",
        )

    def _approval_context_for_event(self, event: MessageEvent) -> MvpEventContext | None:
        source = getattr(event, "source", None)
        account = event.metadata.get("whatsapp_account_id") if type(event.metadata) is dict else None
        if (
            not self.is_healthy()
            or source is None
            or source.platform is not Platform.WHATSAPP
            or (source.profile or "default") != self.config.profile
            or source.user_id != self.config.owner_sender
            or source.chat_id != self.config.owner_chat
            or account != self.config.ordinary_account
            or _event_id(event.message_id) is None
        ):
            return None
        requester = self.config.requester(self.config.owner_sender)
        if requester is None:
            return None
        return MvpEventContext(
            requester=requester, source_profile=self.config.profile,
            source_account=account, source_chat=source.chat_id,
            source_message=_event_id(event.message_id),
        )

    async def process_once(self) -> bool:
        repository = self.repository
        if not self.is_healthy() or repository is None:
            return False
        now_us = self._clock_us()
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
            self._healthy = False
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
                await asyncio.wait_for(
                    self.dependencies.ordinary.send(notice.approval_chat, text),
                    self.config.request_timeout,
                )
            except BaseException:
                repository.fail_pending(notice.request_id, self._clock_us())
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
            identity = await asyncio.wait_for(
                self.dependencies.sensitive.observe_identity(request=request),
                self.config.request_timeout,
            )
            if not self._identity_matches_request(identity, request):
                code = "identity_unavailable"
                return True
            allowed = await asyncio.wait_for(
                self.dependencies.openfga.check(request), self.config.request_timeout
            )
            if not allowed or self._clock_us() >= request.expires_at_us:
                code = "policy_denied"
                return True
            identity_before_read = await asyncio.wait_for(
                self.dependencies.sensitive.observe_identity(request=request),
                self.config.request_timeout,
            )
            if identity_before_read != identity or not self._identity_matches_request(
                identity_before_read, request
            ):
                code = "identity_drift"
                return True
            plaintext = await asyncio.wait_for(
                self.dependencies.gmail.read(), self.config.read_timeout
            )
            if self._clock_us() >= request.expires_at_us:
                code = "expired_after_read"
                return True
            identity_at_submit = await asyncio.wait_for(
                self.dependencies.sensitive.observe_identity(request=request),
                self.config.request_timeout,
            )
            if identity_at_submit != identity_before_read or not self._identity_matches_request(
                identity_at_submit, request
            ):
                code = "identity_drift"
                return True
            if self._clock_us() >= request.expires_at_us:
                code = "expired_before_submit"
                return True
            result = await asyncio.wait_for(
                self.dependencies.sensitive.submit(
                    request=request, plaintext=plaintext, identity=identity_at_submit
                ),
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
                now_us=self._clock_us(),
            )
        return True

    def _identity_matches_request(
        self, identity: SensitiveRuntimeIdentity | None, request: MvpRequest
    ) -> bool:
        return bool(
            type(identity) is SensitiveRuntimeIdentity
            and identity.account == request.destination_account
            and identity.account == self.config.sensitive_account
            and identity.account != self.config.ordinary_account
        )


class _GatewayOrdinaryNotifier:
    def __init__(self, runner: object, config: JunoPrivateReadMvpConfig):
        self._runner = runner
        self._config = config

    async def send(self, destination: str, text: str) -> str:
        if not hmac.compare_digest(destination, self._config.owner_chat):
            raise JunoPrivateReadError("ordinary transport unavailable")
        profile_maps = getattr(self._runner, "_profile_adapters", {})
        if self._config.profile == getattr(self._runner, "profile", "default"):
            adapter = getattr(self._runner, "adapters", {}).get(Platform.WHATSAPP)
        else:
            adapter = profile_maps.get(self._config.profile, {}).get(Platform.WHATSAPP)
        if adapter is None:
            raise JunoPrivateReadError("ordinary transport unavailable")
        result = await adapter.send(destination, text)
        message_id = getattr(result, "message_id", None)
        if getattr(result, "success", False) is not True or not message_id:
            raise JunoPrivateReadError("ordinary transport unavailable")
        return str(message_id)


class _SensitiveHttpSubmitter:
    def __init__(self, config: JunoPrivateReadMvpConfig, transport: JsonTransport):
        self._config = config
        self._transport = transport

    async def observe_identity(
        self, *, request: MvpRequest
    ) -> SensitiveRuntimeIdentity | None:
        return await _sealed_sensitive_identity(self._config, self._transport, request)

    async def submit(
        self, *, request: MvpRequest, plaintext: str, identity: SensitiveRuntimeIdentity
    ) -> SensitiveSubmission:
        return await _sealed_sensitive_submit(
            self._config, self._transport, request, plaintext, identity
        )


def _read_sensitive_capability(config: JunoPrivateReadMvpConfig) -> str | None:
    try:
        value = _owner_file(config.sensitive_capability_file).read_text(encoding="utf-8").strip()
        if not 32 <= len(value.encode("utf-8")) <= 512 or any(ord(c) < 32 for c in value):
            return None
        return value
    except BaseException:
        return None


async def _sealed_sensitive_identity(
    config: JunoPrivateReadMvpConfig, transport: JsonTransport, request: MvpRequest
) -> SensitiveRuntimeIdentity | None:
    try:
        capability = _read_sensitive_capability(config)
        if capability is None:
            return None
        response = await transport.request(
            method="GET", authority="http://127.0.0.1:3011", path="/v1/identity",
            query=(), headers={"x-hermes-sensitive-capability": capability,
                               "accept": "application/json"}, body=None,
            timeout=config.request_timeout, max_bytes=4096,
        )
        required = {
            "outcome", "submitted", "provider_account_jid", "identity_observed_us",
            "adapter_runtime_id", "connection_epoch", "transport_identity",
        }
        if type(response) is not dict or set(response) != required:
            return None
        if (
            response["outcome"] != "available"
            or response["submitted"] is not False
            or response["provider_account_jid"] != request.destination_account
            or response["provider_account_jid"] == config.ordinary_account
            or type(response["identity_observed_us"]) is not int
            or response["identity_observed_us"] < 0
            or type(response["transport_identity"]) is not dict
        ):
            return None
        registration = _text(response["adapter_runtime_id"], "runtime identity", 512)
        session = _text(response["connection_epoch"], "connection epoch", 512)
        return SensitiveRuntimeIdentity(registration, response["provider_account_jid"], session)
    except BaseException:
        return None


async def _sealed_sensitive_submit(
    config: JunoPrivateReadMvpConfig, transport: JsonTransport, request: MvpRequest,
    plaintext: str, identity: SensitiveRuntimeIdentity,
) -> SensitiveSubmission:
    try:
        capability = _read_sensitive_capability(config)
        if capability is None:
            return SensitiveSubmission("failed", None, "", "")
        response = await transport.request(
            method="POST", authority="http://127.0.0.1:3011", path="/v1/submit",
            query=(), headers={"x-hermes-sensitive-capability": capability,
                               "content-type": "application/json", "accept": "application/json"},
            body={"request_id": request.request_id,
                  "registration": identity.registration,
                  "session": identity.session,
                  "account": request.destination_account,
                  "destination": request.destination_chat,
                  "private_value": plaintext},
            timeout=config.submission_timeout, max_bytes=4096,
        )
        if type(response) is not dict or set(response) != {"state", "message_id", "account", "destination"}:
            return SensitiveSubmission("unknown", None, "mismatch", "mismatch")
        return SensitiveSubmission(
            state=response["state"], message_id=response["message_id"],
            account=response["account"], destination=response["destination"],
        )
    except BaseException:
        return SensitiveSubmission("unknown", None, "mismatch", "mismatch")


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
    value = _sealed_load_or_create_state_key(state_dir)
    if value is None:
        raise JunoPrivateReadError("private state key is invalid") from None
    return value


def _sealed_load_or_create_state_key(state_dir: Path) -> bytes | None:
    path = state_dir / "mvp-store.key"
    try:
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
        value = _owner_file(path).read_bytes()
        return value if len(value) == 32 else None
    except BaseException:
        return None


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
    "FixedHttpJsonTransport", "GmailNewestInboxProvider", "JunoPrivateReadDependencies", "JunoPrivateReadError",
    "JunoPrivateReadMvpConfig", "JunoPrivateReadMvpHost", "MvpAuthorizationRepository",
    "MvpEventContext", "MvpRequest", "OPENFGA_CLIENT_CONTRACT_VERSION",
    "OpenFgaChecker", "PrivateReadAuthorizer", "PrivateReadProvider",
    "SensitiveRuntimeIdentity", "SensitiveSubmission",
    "compose_juno_private_read_mvp_services", "private_read_tool_surface_is_closed",
    "render_gmail_message",
]
