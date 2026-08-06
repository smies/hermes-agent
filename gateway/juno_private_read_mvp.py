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
import stat
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Awaitable, Callable, Protocol
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from gateway.authorization_contracts import CoordinatorIdentity
from gateway.authorization_tasks import AuthorizationTaskStore
from gateway.config import Platform
from gateway.juno_replay_journal import JunoReplayAuthority, ReplayAuthorityError
from gateway.platforms.base import MessageEvent
from gateway.trusted_private_read_host import _owner_directory, _owner_file


CAPABILITY_ID = "gmail.newest_inbox_message.read"
GMAIL_CONTRACT_VERSION = "gmail-v1-newest-inbox-v1"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_AUTHORITY = "https://gmail.googleapis.com"
OPENFGA_AUTHORITY = "http://127.0.0.1:8080"
OPENFGA_CLIENT_CONTRACT_VERSION = "1.18.2"
SENSITIVE_AUTHORITY = "http://127.0.0.1:3011"
SENSITIVE_SUBMIT_CONTRACT_VERSION = "juno-sensitive-submit-v2"
MAX_SENSITIVE_DEADLINE_AHEAD_US = 300_000_000
MIN_TRUSTED_EPOCH_US = 1_000_000_000_000_000
MAX_TRUSTED_EPOCH_US = 9_007_199_254_740_991
MAX_PRIVATE_RENDER_BYTES = 16 * 1024
MAX_GMAIL_RESPONSE_BYTES = 128 * 1024
MAX_GMAIL_PARTS = 64
MAX_GMAIL_DEPTH = 8
MAX_GMAIL_HEADERS = 128
SENSITIVE_IDENTITY_MAX_AGE_US = 5_000_000
SENSITIVE_IDENTITY_FUTURE_SKEW_US = 250_000
ORDINARY_INBOUND_PROVENANCE = "messages.upsert:registered-emitting-socket:v1"
_SENSITIVE_TRANSPORT_IDENTITY = {
    "manifest_sha256": "795fc764fb28bb3d53e6abed1dc2de4bc02c6b41f330cc6120b81312ef540232",
    "launcher_sha256": "722bbfe84f597433f0e57c398410abbac88f690a589673b80fa5915b9a91c396",
    "source_sha256": "b1edb61d9cb4e5d072832997d499aa901ef3065b6377afac0f98f6339d6ebed3",
    "package_sha256": "d3acebf298753b1009f6f5f65575fe7cdceceb05cd20bac024a0fbfaf1467d6f",
    "lock_sha256": "11763893096a6abe8b28a017dc652506bd47d39ef2ddeb0fe2ea110be58dc05a",
    "verifier_sha256": "b486e4afee374d864bf3f1d219dc301aac45578822f96e3b494f93ca91a20770",
    "node_modules_tree_sha256": "48121207ef2e275e835b08cf58b264b8f0d4ef56eddb07298e833a2720dc62ef",
    "package_name": "hermes-whatsapp-sensitive-bridge",
    "package_version": "1.0.0",
    "submit_contract_version": SENSITIVE_SUBMIT_CONTRACT_VERSION,
    "baileys_spec": "7.0.0-rc14",
    "baileys_lock_version": "7.0.0-rc14",
    "baileys_lock_resolved": "https://registry.npmjs.org/@whiskeysockets/baileys/-/baileys-7.0.0-rc14.tgz",
    "baileys_lock_integrity": "sha512-WK+X8ju8TPGxvWIsP8hrY6JB6FltYuFe+vsqKfjOYX25JObij9qLf2c3ZGdl1Q+vhFwbnT+AZmWAB5pTvzmSiQ==",
    "baileys_installed_name": "@whiskeysockets/baileys",
    "baileys_version": "7.0.0-rc14",
    "baileys_package_sha256": "b5f4f2d1a8af27239e0e9869594345b5d99ecc102193b98117332cadffcebc0d",
    "baileys_tree_sha256": "bdb0b02cb790daa88421bf29700b43b1e449378a77f51edcfd8d524e9b9f0112",
    "baileys_reviewed_release_git_head": "7e7b0757e3f9f3c7789fb1cfd2f241d5002a199a",
}
_APPROVAL_RE = re.compile(r"^/(approve|deny) ([A-Za-z0-9_-]{16,80})$")
_SENSITIVE_MESSAGE_ID_RE = re.compile(r"^3EB0[0-9A-F]{18}$")
_WHATSAPP_DIRECT_RE = re.compile(r"^\d{1,32}@(s\.whatsapp\.net|lid)$")
_WHATSAPP_CHAT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}@(s\.whatsapp\.net|lid|g\.us)$")


def _provider_authority_digest(config: "JunoPrivateReadMvpConfig") -> str:
    """Seal all fixed provider authority/contract inputs into one digest."""
    value = {
        "capability": CAPABILITY_ID,
        "gmail_account": config.gmail_account,
        "gmail_authority": GMAIL_AUTHORITY,
        "gmail_contract": GMAIL_CONTRACT_VERSION,
        "gmail_scope": GMAIL_SCOPE,
        "openfga_authority": OPENFGA_AUTHORITY,
        "openfga_client_contract": OPENFGA_CLIENT_CONTRACT_VERSION,
        "openfga_model_id": config.openfga_model_id,
        "openfga_store_id": config.openfga_store_id,
        "sensitive_authority": SENSITIVE_AUTHORITY,
        "sensitive_submit_contract": SENSITIVE_SUBMIT_CONTRACT_VERSION,
        "sensitive_transport_identity": _SENSITIVE_TRANSPORT_IDENTITY,
    }
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()).hexdigest()


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


def _direct_identity_aliases(value: str) -> frozenset[str]:
    """Return the reviewed direct-JID alias identity, failing closed."""
    if _WHATSAPP_DIRECT_RE.fullmatch(value) is None:
        raise JunoPrivateReadError("WhatsApp identity configuration is invalid")
    from gateway.whatsapp_identity import expand_whatsapp_aliases

    aliases = expand_whatsapp_aliases(value)
    if not aliases or any(re.fullmatch(r"\d{1,32}", item) is None for item in aliases):
        raise JunoPrivateReadError("WhatsApp identity configuration is invalid")
    return frozenset(aliases)


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
        ordinary_account = _jid(ordinary["account"], "ordinary account")
        ordinary_aliases = _direct_identity_aliases(ordinary_account)
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
            sensitive_destination = _jid(
                row["sensitive_destination"], "sensitive destination"
            )
            if ordinary_aliases & _direct_identity_aliases(sensitive_destination):
                raise JunoPrivateReadError(
                    "sensitive destination must differ from ordinary account"
                )
            requester = JunoRequester(
                sender=_jid(row["sender"], "requester sender"),
                source_chat=_jid(row["source_chat"], "requester source chat", direct=False),
                label=_text(row["label"], "requester label", 80),
                sensitive_destination=sensitive_destination,
            )
            if requester.sender in seen:
                raise JunoPrivateReadError("requester configuration is invalid")
            seen.add(requester.sender)
            requesters.append(requester)
        owner = _jid(ordinary["owner_sender"], "owner sender")
        if owner not in seen:
            raise JunoPrivateReadError("owner must be an allowlisted requester")
        owner_destination = next(
            item.sensitive_destination for item in requesters
            if hmac.compare_digest(item.sender, owner)
        )
        if any(
            not hmac.compare_digest(item.sensitive_destination, owner_destination)
            for item in requesters
        ):
            raise JunoPrivateReadError(
                "all private delivery must use the owner destination"
            )
        sensitive_account = _jid(sensitive["account"], "sensitive account")
        if not hmac.compare_digest(ordinary_account, sensitive_account):
            raise JunoPrivateReadError(
                "ordinary and sensitive sessions must use the same account"
            )
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
    source_provenance: str

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
    approval_message: str | None
    gmail_account: str
    openfga_store_id: str
    openfga_model_id: str
    provider_authority_digest: str
    descriptor_digest: str
    created_at_us: int
    expires_at_us: int
    status: str
    notice_claimed: bool
    claim_token_digest: str | None
    provider_message_id: str | None
    terminal_code: str | None
    updated_at_us: int
    version: int
    state_hmac: str

    def __repr__(self) -> str:
        return f"<MvpRequest status={self.status!r}>"


class MvpAuthorizationRepository:
    """MVP lifecycle operations on the existing AuthorizationTaskStore DB."""

    _STATE_FIELDS = (
        "request_id", "requester", "source_profile", "source_account",
        "source_chat", "source_message", "capability_id",
        "destination_account", "destination_chat", "owner_sender",
        "approval_chat", "approval_message", "gmail_account",
        "openfga_store_id", "openfga_model_id", "provider_authority_digest",
        "descriptor_digest",
        "created_at_us", "expires_at_us", "status", "notice_claimed",
        "claim_token_digest", "provider_message_id", "terminal_code",
        "updated_at_us", "version",
    )
    _STATUSES = {
        "pending", "approved", "denied", "expired", "claimed",
        "consumed", "failed_consumed",
    }

    def __init__(self, store: AuthorizationTaskStore, key: bytes,
                 config: JunoPrivateReadMvpConfig,
                 journal: JunoReplayAuthority,
                 *, clock_us: Callable[[], int] | None = None):
        if (
            type(store) is not AuthorizationTaskStore
            or type(config) is not JunoPrivateReadMvpConfig
            or type(journal) is not JunoReplayAuthority
            or len(key) < 32
        ):
            raise TypeError("exact authorization store, key, and config are required")
        self.store = store
        self._key = bytes(key)
        self._config = config
        self._journal = journal
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
            approval_chat=row["approval_chat"], approval_message=row["approval_message"],
            gmail_account=row["gmail_account"],
            openfga_store_id=row["openfga_store_id"],
            openfga_model_id=row["openfga_model_id"],
            provider_authority_digest=row["provider_authority_digest"],
            descriptor_digest=row["descriptor_digest"], created_at_us=row["created_at_us"],
            expires_at_us=row["expires_at_us"], status=row["status"],
            notice_claimed=bool(row["notice_claimed"]),
            claim_token_digest=row["claim_token_digest"],
            provider_message_id=row["provider_message_id"],
            terminal_code=row["terminal_code"], updated_at_us=row["updated_at_us"],
            version=row["version"], state_hmac=row["state_hmac"],
        )

    def _digest(self, value: str) -> str:
        return hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _state_value(value: object) -> object:
        if value is None or type(value) in (str, int):
            return value
        if type(value) is bytes:
            return {"invalid_bytes": base64.b64encode(value).decode("ascii")}
        return {"invalid_type": type(value).__name__}

    def _state_digest(self, values: dict[str, object]) -> str:
        framed = json.dumps(
            [[name, self._state_value(values.get(name))] for name in self._STATE_FIELDS],
            ensure_ascii=True, separators=(",", ":"),
        )
        return self._digest("juno-mvp-state-v2\n" + framed)

    @staticmethod
    def _values(row) -> dict[str, object]:
        return {name: row[name] for name in MvpAuthorizationRepository._STATE_FIELDS}

    def _descriptor(self, values: dict[str, object]) -> str:
        return json.dumps(
            {
                "approval_chat": values["approval_chat"],
                "approval_message": values["approval_message"],
                "capability": values["capability_id"],
                "created_at_us": values["created_at_us"],
                "destination_account": values["destination_account"],
                "destination": values["destination_chat"],
                "owner_sender": values["owner_sender"],
                "requester": values["requester"],
                "request_id": values["request_id"],
                "source_account": values["source_account"],
                "source_chat": values["source_chat"],
                "source_message": values["source_message"],
                "source_profile": values["source_profile"],
                "expires_at_us": values["expires_at_us"],
                "gmail_account": values["gmail_account"],
                "openfga_store_id": values["openfga_store_id"],
                "openfga_model_id": values["openfga_model_id"],
                "provider_authority_digest": values["provider_authority_digest"],
                "sensitive_authority": SENSITIVE_AUTHORITY,
                "sensitive_submit_contract": SENSITIVE_SUBMIT_CONTRACT_VERSION,
                "sensitive_transport_identity": _SENSITIVE_TRANSPORT_IDENTITY,
            }, sort_keys=True, separators=(",", ":"),
        )

    def _authority_matches_config(self, values: dict[str, object]) -> bool:
        requester_value = values["requester"]
        requester = self._config.requester(requester_value) \
            if type(requester_value) is str else None
        return bool(
            requester is not None
            and values["source_profile"] == self._config.profile
            and values["source_account"] == self._config.ordinary_account
            and values["source_chat"] == requester.source_chat
            and values["capability_id"] == CAPABILITY_ID
            and values["destination_account"] == self._config.sensitive_account
            and values["destination_chat"] == requester.sensitive_destination
            and values["owner_sender"] == self._config.owner_sender
            and values["approval_chat"] == self._config.owner_chat
            and values["gmail_account"] == self._config.gmail_account
            and values["openfga_store_id"] == self._config.openfga_store_id
            and values["openfga_model_id"] == self._config.openfga_model_id
            and values["provider_authority_digest"] == _provider_authority_digest(self._config)
        )

    def _authenticated(self, row) -> bool:
        try:
            values = self._values(row)
            text_fields = {
                "request_id", "requester", "source_profile", "source_account",
                "source_chat", "source_message", "capability_id",
                "destination_account", "destination_chat", "owner_sender",
                "approval_chat", "gmail_account", "openfga_store_id",
                "openfga_model_id", "provider_authority_digest",
                "descriptor_digest", "status",
            }
            if any(type(values[name]) is not str or not values[name] for name in text_fields):
                return False
            if values["approval_message"] is not None \
                    and _event_id(values["approval_message"]) is None:
                return False
            if any(
                values[name] is not None and type(values[name]) is not str
                for name in ("claim_token_digest", "provider_message_id", "terminal_code")
            ):
                return False
            if any(
                type(values[name]) is not int or isinstance(values[name], bool)
                for name in ("created_at_us", "expires_at_us", "notice_claimed",
                              "updated_at_us", "version")
            ):
                return False
            if (
                values["status"] not in self._STATUSES
                or values["notice_claimed"] not in (0, 1)
                or values["created_at_us"] < 0
                or values["expires_at_us"] <= values["created_at_us"]
                or values["updated_at_us"] < values["created_at_us"]
                or values["version"] < 1
                or type(row["state_hmac"]) is not str
                or not hmac.compare_digest(row["state_hmac"], self._state_digest(values))
                or not self._authority_matches_config(values)
                or not hmac.compare_digest(
                    values["descriptor_digest"], self._digest(self._descriptor(values))
                )
            ):
                return False
            if values["status"] == "claimed" and values["claim_token_digest"] is None:
                return False
            return True
        except BaseException:
            return False

    def _terminalize_invalid(self, conn, row, now_us: int) -> None:
        values = self._values(row)
        values.update({
            "status": "failed_consumed",
            "notice_claimed": 1,
            "claim_token_digest": None,
            "provider_message_id": None,
            "terminal_code": "state_integrity_failed",
            "updated_at_us": now_us,
            "version": values["version"] + 1
                if type(values["version"]) is int and values["version"] >= 0 else 1,
        })
        state_hmac = self._state_digest(values)
        conn.execute(
            "UPDATE private_read_mvp_requests SET status=?,notice_claimed=?,"
            "claim_token_digest=NULL,provider_message_id=NULL,terminal_code=?,"
            "updated_at_us=?,version=?,state_hmac=? WHERE rowid=? AND state_hmac=?",
            (values["status"], values["notice_claimed"], values["terminal_code"],
             values["updated_at_us"], values["version"], state_hmac,
             row["rowid"], row["state_hmac"]),
        )

    def _verified(self, conn, row, now_us: int):
        if row is None:
            return None
        if not self._authenticated(row):
            self._terminalize_invalid(conn, row, now_us)
            return None
        return row

    def _transition(self, conn, row, now_us: int, **changes):
        if self._verified(conn, row, now_us) is None:
            return None
        values = self._values(row)
        values.update(changes)
        values["updated_at_us"] = now_us
        values["version"] = int(values["version"]) + 1
        stored_changes = dict(changes)
        if "approval_message" in changes:
            values["descriptor_digest"] = self._digest(self._descriptor(values))
            stored_changes["descriptor_digest"] = values["descriptor_digest"]
        state_hmac = self._state_digest(values)
        assignments = list(stored_changes) + ["updated_at_us", "version", "state_hmac"]
        parameters = [values[name] for name in stored_changes]
        parameters.extend([values["updated_at_us"], values["version"], state_hmac,
                           row["rowid"], row["version"], row["state_hmac"]])
        cursor = conn.execute(
            "UPDATE private_read_mvp_requests SET "
            + ",".join(name + "=?" for name in assignments)
            + " WHERE rowid=? AND version=? AND state_hmac=?",
            parameters,
        )
        if cursor.rowcount != 1:
            return None
        return self._verified(conn, conn.execute(
            "SELECT rowid,* FROM private_read_mvp_requests WHERE rowid=?", (row["rowid"],)
        ).fetchone(), now_us)

    def _authority_digest(self, domain: str, values: object) -> str:
        framed = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return self._digest("juno-mvp-replay-" + domain + "-v1\n" + framed)

    def _request_journal_id(self, values: dict[str, object]) -> str:
        """Digest the durable request ID together with its sealed providers."""
        return self._authority_digest("request", {
            "gmail_account": values["gmail_account"],
            "openfga_model_id": values["openfga_model_id"],
            "openfga_store_id": values["openfga_store_id"],
            "provider_authority_digest": values["provider_authority_digest"],
            "request_id": values["request_id"],
        })

    def _source_journal_id(self, context: MvpEventContext) -> str:
        return self._authority_digest("source", {
            "account": context.source_account,
            "capability": CAPABILITY_ID,
            "chat": context.source_chat,
            "message": context.source_message,
            "profile": context.source_profile,
            "provenance": context.source_provenance,
            "sender": context.requester.sender,
        })

    def _approval_journal_id(self, context: MvpEventContext) -> str:
        return self._authority_digest("approval", {
            "account": context.source_account,
            "capability": CAPABILITY_ID,
            "chat": context.source_chat,
            "message": context.source_message,
            "profile": context.source_profile,
            "sender": context.requester.sender,
        })

    def _delivery_journal_id(self, values: dict[str, object]) -> str:
        return self._authority_digest("delivery", {
            "descriptor_digest": values["descriptor_digest"],
            "provider_authority_digest": values["provider_authority_digest"],
            "request_id": values["request_id"],
        })

    def create(self, context: MvpEventContext, config: JunoPrivateReadMvpConfig) -> MvpRequest:
        now_us = self._clock_us()
        expires_us = now_us + int(config.approval_timeout * 1_000_000)
        request_id = secrets.token_urlsafe(18)
        initial = "approved" if hmac.compare_digest(context.requester.sender, config.owner_sender) else "pending"
        values = {
            "request_id": request_id, "requester": context.requester.sender,
            "source_profile": context.source_profile, "source_account": context.source_account,
            "source_chat": context.source_chat, "source_message": context.source_message,
            "capability_id": CAPABILITY_ID, "destination_account": config.sensitive_account,
            "destination_chat": context.requester.sensitive_destination,
            "owner_sender": config.owner_sender, "approval_chat": config.owner_chat,
            "approval_message": None, "gmail_account": config.gmail_account,
            "openfga_store_id": config.openfga_store_id,
            "openfga_model_id": config.openfga_model_id,
            "provider_authority_digest": _provider_authority_digest(config),
            "descriptor_digest": "", "created_at_us": now_us,
            "expires_at_us": expires_us, "status": initial, "notice_claimed": 0,
            "claim_token_digest": None, "provider_message_id": None,
            "terminal_code": None, "updated_at_us": now_us, "version": 1,
        }
        values["descriptor_digest"] = self._digest(self._descriptor(values))
        state_hmac = self._state_digest(values)

        def mutate(conn):
            existing = conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests WHERE source_profile=? "
                "AND source_account=? AND source_chat=? AND requester=? "
                "AND source_message=? AND capability_id=?",
                (context.source_profile, context.source_account, context.source_chat,
                 context.requester.sender, context.source_message, CAPABILITY_ID),
            ).fetchone()
            if existing is not None:
                verified = self._verified(conn, existing, now_us)
                if verified is None:
                    raise JunoPrivateReadError("private request unavailable")
                return self._row(verified)
            source_id = self._source_journal_id(context)
            request_journal_id = self._request_journal_id(values)
            if self._journal.contains("source", source_id) or self._journal.contains(
                "source", request_journal_id
            ):
                raise JunoPrivateReadError("private request unavailable")
            if not self._journal.append("source", (source_id, request_journal_id)):
                raise JunoPrivateReadError("private request unavailable")
            conn.execute(
                "INSERT INTO private_read_mvp_requests "
                "(request_id,requester,source_profile,source_account,source_chat,source_message,"
                "capability_id,destination_account,destination_chat,owner_sender,approval_chat,"
                "approval_message,gmail_account,openfga_store_id,openfga_model_id,"
                "provider_authority_digest,descriptor_digest,created_at_us,expires_at_us,status,"
                "notice_claimed,claim_token_digest,provider_message_id,terminal_code,"
                "updated_at_us,version,state_hmac) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (request_id, context.requester.sender, context.source_profile,
                 context.source_account, context.source_chat, context.source_message, CAPABILITY_ID,
                 config.sensitive_account, context.requester.sensitive_destination,
                 config.owner_sender, config.owner_chat, None, config.gmail_account,
                 config.openfga_store_id, config.openfga_model_id,
                 values["provider_authority_digest"], values["descriptor_digest"],
                 now_us, expires_us, initial, 0, None, None, None, now_us, 1, state_hmac),
            )
            row = conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests WHERE source_profile=? "
                "AND source_account=? AND source_chat=? AND requester=? "
                "AND source_message=? AND capability_id=?",
                (context.source_profile, context.source_account, context.source_chat,
                 context.requester.sender, context.source_message, CAPABILITY_ID),
            ).fetchone()
            verified = self._verified(conn, row, now_us)
            if verified is None:
                raise JunoPrivateReadError("private request unavailable")
            return self._row(verified)

        return self.store._write(mutate, at_us=now_us)

    def expire_due(self, now_us: int) -> int:
        def mutate(conn):
            changed = 0
            rows = conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests "
                "WHERE status IN ('pending','approved') AND expires_at_us<=?", (now_us,),
            ).fetchall()
            for row in rows:
                changed += self._transition(conn, row, now_us, status="expired") is not None
            return changed
        return self.store._write(mutate, at_us=now_us)

    def quarantine_invalid_active(self, now_us: int) -> int:
        """Terminalize every actionable row whose state or authority is invalid."""
        def mutate(conn):
            changed = 0
            rows = conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests "
                "WHERE status IN ('pending','approved','claimed')"
            ).fetchall()
            for row in rows:
                if not self._authenticated(row):
                    self._terminalize_invalid(conn, row, now_us)
                    changed += 1
            return changed
        return self.store._write(mutate, at_us=now_us)

    def recover_claimed(self, now_us: int) -> int:
        """Consume interrupted submissions; the MVP never retries ambiguity."""
        def mutate(conn):
            changed = 0
            for row in conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests WHERE status='claimed'"
            ).fetchall():
                changed += self._transition(
                    conn, row, now_us, status="failed_consumed",
                    claim_token_digest=None, terminal_code="interrupted_after_claim",
                ) is not None
            return changed
        return self.store._write(mutate, at_us=now_us)

    def burn_active_runtime_authority(self, now_us: int) -> int:
        """Terminalize every request bound to a depublished runtime generation."""
        def mutate(conn):
            changed = 0
            rows = conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests "
                "WHERE status IN ('pending','approved','claimed')"
            ).fetchall()
            for row in rows:
                changed += self._transition(
                    conn, row, now_us, status="failed_consumed",
                    notice_claimed=1, claim_token_digest=None,
                    provider_message_id=None,
                    terminal_code="runtime_authority_rotated",
                ) is not None
            return changed
        return self.store._write(mutate, at_us=now_us)

    def recover_claimed_notices(self, now_us: int) -> int:
        """Consume notice sends interrupted after the durable claim boundary."""
        def mutate(conn):
            changed = 0
            for row in conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests "
                "WHERE status='pending' AND notice_claimed=1"
            ).fetchall():
                changed += self._transition(
                    conn, row, now_us, status="failed_consumed",
                    terminal_code="interrupted_notice_claim",
                ) is not None
            return changed
        return self.store._write(mutate, at_us=now_us)

    def recover_incomplete_bindings(self, now_us: int) -> int:
        """Consume checkpoint rows that predate source/approval chat binding."""
        def mutate(conn):
            changed = 0
            for row in conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests "
                "WHERE status IN ('pending','approved','claimed') "
                "AND (source_message='' OR approval_chat='' OR state_hmac='')"
            ).fetchall():
                if self._verified(conn, row, now_us) is None:
                    changed += 1
            return changed
        return self.store._write(mutate, at_us=now_us)

    def claim_notice(self, now_us: int) -> MvpRequest | None:
        def mutate(conn):
            rows = conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests WHERE status='pending' "
                "AND notice_claimed=0 AND expires_at_us>? ORDER BY created_at_us LIMIT 1",
                (now_us,),
            ).fetchall()
            for row in rows:
                current = self._transition(conn, row, now_us, notice_claimed=1)
                if current is not None:
                    return self._row(current)
            return None
        return self.store._write(mutate, at_us=now_us)

    def resolve(self, request_id: str, context: MvpEventContext, approve: bool, now_us: int) -> bool:
        target = "approved" if approve else "denied"
        def mutate(conn):
            replay = conn.execute(
                "SELECT 1 FROM private_read_mvp_requests WHERE source_profile=? "
                "AND source_account=? AND owner_sender=? AND approval_chat=? "
                "AND approval_message=? AND capability_id=? LIMIT 1",
                (context.source_profile, context.source_account, context.requester.sender,
                 context.source_chat, context.source_message, CAPABILITY_ID),
            ).fetchone()
            if replay is not None:
                return False
            row = conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            row = self._verified(conn, row, now_us)
            if (
                row is None or row["status"] != "pending" or row["expires_at_us"] <= now_us
                or row["owner_sender"] != context.requester.sender
                or row["source_profile"] != context.source_profile
                or row["source_account"] != context.source_account
                or row["approval_chat"] != context.source_chat
            ):
                return False
            approval_id = self._approval_journal_id(context)
            request_journal_id = self._request_journal_id(self._values(row))
            if self._journal.contains("approval", approval_id) or self._journal.contains(
                "approval", request_journal_id
            ):
                return False
            if not self._journal.append("approval", (approval_id, request_journal_id)):
                return False
            return self._transition(
                conn, row, now_us, status=target,
                approval_message=context.source_message,
            ) is not None
        return self.store._write(mutate, at_us=now_us)

    def fail_pending(self, request_id: str, now_us: int) -> bool:
        def mutate(conn):
            row = conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            row = self._verified(conn, row, now_us)
            return bool(
                row is not None and row["status"] == "pending"
                and self._transition(
                    conn, row, now_us, status="failed_consumed",
                    terminal_code="ordinary_notice_failed",
                ) is not None
            )
        return self.store._write(mutate, at_us=now_us)

    def claim_approved(self, now_us: int) -> tuple[MvpRequest, str] | None:
        token = secrets.token_urlsafe(24)
        token_digest = self._digest(token)
        def mutate(conn):
            rows = conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests WHERE status='approved' "
                "AND expires_at_us>? ORDER BY created_at_us", (now_us,),
            ).fetchall()
            for row in rows:
                row = self._verified(conn, row, now_us)
                if row is None:
                    continue
                values = self._values(row)
                delivery_id = self._delivery_journal_id(values)
                request_journal_id = self._request_journal_id(values)
                if self._journal.contains("delivery", delivery_id) or self._journal.contains(
                    "delivery", request_journal_id
                ):
                    self._transition(
                        conn, row, now_us, status="failed_consumed", notice_claimed=1,
                        claim_token_digest=None, terminal_code="replay_authority_consumed",
                    )
                    continue
                if not self._journal.append(
                    "delivery", (delivery_id, request_journal_id)
                ):
                    continue
                current = self._transition(
                    conn, row, now_us, status="claimed", claim_token_digest=token_digest,
                )
                if current is not None:
                    return self._row(current), token
            return None
        return self.store._write(mutate, at_us=now_us)

    def finish(self, request_id: str, claim_token: str, *, submitted: bool,
               provider_message_id: str | None, code: str, now_us: int,
               expired: bool = False) -> bool:
        if submitted:
            final = "consumed"
        elif expired:
            final = "expired"
        else:
            final = "failed_consumed"
        def mutate(conn):
            row = conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            row = self._verified(conn, row, now_us)
            if (
                row is None or row["status"] != "claimed"
                or not hmac.compare_digest(row["claim_token_digest"], self._digest(claim_token))
            ):
                return False
            return self._transition(
                conn, row, now_us, status=final, claim_token_digest=None,
                provider_message_id=provider_message_id if submitted else None,
                terminal_code=code,
            ) is not None
        return self.store._write(mutate, at_us=now_us)

    def reconcile_journal(self, now_us: int) -> None:
        """Terminalize actionable SQLite state older than independent evidence."""
        def mutate(conn):
            rows = conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests WHERE status IN "
                "('pending','approved','claimed')"
            ).fetchall()
            for row in rows:
                row = self._verified(conn, row, now_us)
                if row is None:
                    continue
                values = self._values(row)
                request_journal_id = self._request_journal_id(values)
                source_context = MvpEventContext(
                    self._config.requester(row["requester"]), row["source_profile"],
                    row["source_account"], row["source_chat"], row["source_message"],
                    ORDINARY_INBOUND_PROVENANCE,
                )
                invalid = (
                    source_context.requester is None
                    or not self._journal.contains("source", request_journal_id)
                    or not self._journal.contains("source", self._source_journal_id(source_context))
                )
                if row["approval_message"] is not None:
                    approval_context = MvpEventContext(
                        self._config.requester(self._config.owner_sender), row["source_profile"],
                        row["source_account"], row["approval_chat"], row["approval_message"],
                        ORDINARY_INBOUND_PROVENANCE,
                    )
                    invalid = invalid or approval_context.requester is None or not self._journal.contains(
                        "approval", self._approval_journal_id(approval_context)
                    )
                elif self._journal.contains("approval", request_journal_id):
                    invalid = True
                delivery_seen = self._journal.contains("delivery", request_journal_id) or \
                    self._journal.contains("delivery", self._delivery_journal_id(values))
                if row["status"] != "claimed" and delivery_seen:
                    invalid = True
                if invalid:
                    self._transition(
                        conn, row, now_us, status="failed_consumed", notice_claimed=1,
                        claim_token_digest=None, provider_message_id=None,
                        terminal_code="replay_authority_mismatch",
                    )
            return None
        self.store._write(mutate, at_us=now_us)

    def validate_claim(
        self, request: MvpRequest, claim_token: str, now_us: int
    ) -> MvpRequest | None:
        def mutate(conn):
            row = conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests WHERE request_id=?",
                (request.request_id,),
            ).fetchone()
            row = self._verified(conn, row, now_us)
            if (
                row is None or row["status"] != "claimed"
                or now_us >= row["expires_at_us"]
                or not hmac.compare_digest(row["claim_token_digest"], self._digest(claim_token))
            ):
                return None
            current = self._row(row)
            return current if current == request else None
        return self.store._write(mutate, at_us=now_us)

    def get(self, request_id: str) -> MvpRequest | None:
        def mutate(conn):
            row = conn.execute(
                "SELECT rowid,* FROM private_read_mvp_requests WHERE request_id=?", (request_id,)
            ).fetchone()
            row = self._verified(conn, row, self._clock_us())
            return self._row(row) if row is not None else None
        return self.store._write(mutate, at_us=self._clock_us())


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
            SENSITIVE_AUTHORITY: SENSITIVE_AUTHORITY,
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
            with urllib_request.build_opener(
                urllib_request.ProxyHandler({}), _RejectRedirects()
            ).open(
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
        if (
            request.gmail_account != self._config.gmail_account
            or request.openfga_store_id != self._config.openfga_store_id
            or request.openfga_model_id != self._config.openfga_model_id
            or request.provider_authority_digest != _provider_authority_digest(self._config)
        ):
            return False
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
                "owner_sender": request.owner_sender,
                "approval_chat": request.approval_chat,
                "approval_message": request.approval_message,
                "expires_at_us": request.expires_at_us,
                "gmail_account": request.gmail_account,
                "openfga_store_id": request.openfga_store_id,
                "openfga_model_id": request.openfga_model_id,
                "provider_authority_digest": request.provider_authority_digest,
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
        if self.state not in {"submitted", "failed", "unknown", "expired"}:
            raise ValueError("invalid sensitive submission state")

    def __repr__(self) -> str:
        return f"<SensitiveSubmission state={self.state!r}>"


@dataclass(frozen=True, slots=True, repr=False)
class SensitiveRuntimeIdentity:
    registration: str
    account: str
    session: str
    observed_at_us: int
    transport_identity: tuple[tuple[str, str], ...]
    process_generation: str = ""
    topology_identity: tuple[tuple[str, str], ...] = ()

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
    ordinary_fence: Callable[[], bool]

    def __repr__(self) -> str:
        return "<JunoPrivateReadDependencies redacted>"


@dataclass(frozen=True, slots=True)
class ApprovalIntercept:
    matched: bool
    mutated: bool
    response: str | None


class JunoPrivateReadMvpHost:
    def __init__(self, config: JunoPrivateReadMvpConfig, dependencies: JunoPrivateReadDependencies,
                 *, active_profile: str | None = None,
                 _clock_us: Callable[[], int] | None = None):
        self.config = config
        self.dependencies = dependencies
        self.store: AuthorizationTaskStore | None = None
        self.repository: MvpAuthorizationRepository | None = None
        self._journal: JunoReplayAuthority | None = None
        self._context: ContextVar[MvpEventContext | None] = ContextVar(
            "juno-private-read-mvp-event", default=None
        )
        self._lock = None
        self._running = False
        self._healthy = False
        self._task: asyncio.Task | None = None
        self._coordinator: CoordinatorIdentity | None = None
        self._clock_us = _clock_us or (lambda: time.time_ns() // 1000)
        self._active_profile = active_profile

    async def start(self, *, _background_worker: bool = True) -> bool:
        if self._active_profile != self.config.profile:
            return False
        if not self._ordinary_fence_healthy():
            return False
        try:
            # Establish the receiver-owned replay domain before creating any
            # authorization state.  Thereafter its absence is damage and may
            # never be interpreted as a fresh install.
            _prepare_sensitive_receiver_replay_authority(self.config.state_dir)
            master = _load_or_create_state_key(self.config.state_dir)
        except JunoPrivateReadError:
            return False
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
        try:
            journal = JunoReplayAuthority(self.config.state_dir, master)
        except ReplayAuthorityError:
            store.close()
            return False
        self.store = store
        self._journal = journal
        self.repository = MvpAuthorizationRepository(
            store, master, self.config, journal, clock_us=self._clock_us
        )
        try:
            self.repository.quarantine_invalid_active(self._clock_us())
            self.repository.reconcile_journal(self._clock_us())
            self.repository.recover_claimed(self._clock_us())
            self.repository.recover_claimed_notices(self._clock_us())
            self.repository.recover_incomplete_bindings(self._clock_us())
        except BaseException:
            await self.stop()
            return False
        self._lock = lock
        self._coordinator = coordinator
        self._running = True
        self._healthy = True
        if not self.is_healthy():
            await self.stop()
            return False
        from tools.private_read_request_tool import configure_private_read_mvp_handler
        configure_private_read_mvp_handler(self.request_from_tool, health_check=self.is_healthy)
        if _background_worker:
            self._task = asyncio.create_task(self._run(), name="juno-private-read-mvp")
        return True

    async def _run(self) -> None:
        try:
            while self.is_healthy():
                worked = await self.process_once()
                await asyncio.sleep(0 if worked else 0.1)
        except asyncio.CancelledError:
            raise
        except BaseException:
            self._running = False
            self._healthy = False
        finally:
            self._running = False
            self._healthy = False
            from tools.private_read_request_tool import configure_private_read_mvp_handler
            configure_private_read_mvp_handler(None)

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
        if self._journal is not None:
            self._journal.close()
        self.store = None
        self.repository = None
        self._journal = None
        self._lock = None
        self._coordinator = None

    def is_healthy(self) -> bool:
        return bool(
            self._running and self._healthy and self.store is not None
            and self.repository is not None and self._journal is not None
            and self._journal.healthy()
            and self._ordinary_fence_healthy()
        )

    def _ordinary_fence_healthy(self) -> bool:
        try:
            return self.dependencies.ordinary_fence() is True
        except BaseException:
            return False

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
        profile = source.profile if source.profile is not None else self._active_profile
        account = event.metadata.get("whatsapp_account_id") if type(event.metadata) is dict else None
        provenance = event.metadata.get("whatsapp_inbound_provenance") \
            if type(event.metadata) is dict else None
        sender = source.user_id
        requester = self.config.requester(sender) if type(sender) is str else None
        if (
            requester is None
            or profile != self.config.profile
            or account != self.config.ordinary_account
            or provenance != ORDINARY_INBOUND_PROVENANCE
            or source.chat_id != requester.source_chat
            or _event_id(event.message_id) is None
        ):
            return None
        return MvpEventContext(
            requester=requester, source_profile=profile, source_account=account,
            source_chat=source.chat_id, source_message=_event_id(event.message_id),
            source_provenance=provenance,
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
        provenance = event.metadata.get("whatsapp_inbound_provenance") \
            if type(event.metadata) is dict else None
        if (
            not self.is_healthy()
            or source is None
            or source.platform is not Platform.WHATSAPP
            or (source.profile if source.profile is not None else self._active_profile)
                != self.config.profile
            or source.user_id != self.config.owner_sender
            or source.chat_id != self.config.owner_chat
            or account != self.config.ordinary_account
            or provenance != ORDINARY_INBOUND_PROVENANCE
            or _event_id(event.message_id) is None
        ):
            return None
        requester = self.config.requester(self.config.owner_sender)
        if requester is None:
            return None
        return MvpEventContext(
            requester=requester, source_profile=self.config.profile,
            source_account=account, source_chat=source.chat_id,
            source_message=_event_id(event.message_id), source_provenance=provenance,
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
        repository.quarantine_invalid_active(now_us)
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
        deadline_expired = False
        provider_message_id = None
        code = "failed"
        plaintext = None
        try:
            if repository.validate_claim(request, token, self._clock_us()) is None:
                code = "state_integrity_failed"
                return True
            identity = await asyncio.wait_for(
                self.dependencies.sensitive.observe_identity(request=request),
                self.config.request_timeout,
            )
            if not self._identity_matches_request(identity, request):
                code = "identity_unavailable"
                return True
            if repository.validate_claim(request, token, self._clock_us()) is None:
                code = "state_integrity_failed"
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
            if not self._identity_continues(identity, identity_before_read, request):
                code = "identity_drift"
                return True
            if repository.validate_claim(request, token, self._clock_us()) is None:
                code = "state_integrity_failed"
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
            if not self._identity_continues(identity_before_read, identity_at_submit, request):
                code = "identity_drift"
                return True
            if self._clock_us() >= request.expires_at_us:
                code = "expired_before_submit"
                return True
            if repository.validate_claim(request, token, self._clock_us()) is None:
                code = "state_integrity_failed"
                return True
            # Validation performs SQLite/HMAC work and is therefore itself a
            # clock-crossing boundary.  Sample again after it returns, then
            # once more at the final local call boundary.  Exact expiry is
            # stale (>=), never a last-microsecond grace period.
            if self._clock_us() >= request.expires_at_us:
                code = "expired_after_final_validation"
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
            elif type(result) is SensitiveSubmission and result.state == "expired":
                deadline_expired = True
                code = "expired_at_submission_boundary"
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
                expired=deadline_expired,
            )
        return True

    def _identity_matches_request(
        self, identity: SensitiveRuntimeIdentity | None, request: MvpRequest
    ) -> bool:
        now_us = self._clock_us()
        return bool(
            type(identity) is SensitiveRuntimeIdentity
            and identity.account == request.destination_account
            and identity.account == self.config.sensitive_account
            and type(identity.observed_at_us) is int
            and now_us - SENSITIVE_IDENTITY_MAX_AGE_US <= identity.observed_at_us
            and identity.observed_at_us <= now_us + SENSITIVE_IDENTITY_FUTURE_SKEW_US
            and identity.transport_identity
                == tuple(sorted(_SENSITIVE_TRANSPORT_IDENTITY.items()))
        )

    def _identity_continues(
        self, previous: SensitiveRuntimeIdentity | None,
        current: SensitiveRuntimeIdentity | None, request: MvpRequest,
    ) -> bool:
        return bool(
            self._identity_matches_request(current, request)
            and type(previous) is SensitiveRuntimeIdentity
            and current.registration == previous.registration
            and current.account == previous.account
            and current.session == previous.session
            and current.transport_identity == previous.transport_identity
            and current.observed_at_us >= previous.observed_at_us
        )


class _GatewayOrdinaryNotifier:
    def __init__(self, runner: object, config: JunoPrivateReadMvpConfig):
        self._runner = runner
        self._config = config
        self._adapter = self._resolve_adapter()

    def _resolve_adapter(self):
        active_resolver = getattr(self._runner, "_active_profile_name", None)
        active_profile = active_resolver() if callable(active_resolver) else None
        if self._config.profile != active_profile:
            return None
        return getattr(self._runner, "adapters", {}).get(Platform.WHATSAPP)

    def fence_healthy(self) -> bool:
        if bool(getattr(getattr(self._runner, "config", None), "multiplex_profiles", False)):
            return False
        adapter = self._resolve_adapter()
        if adapter is None or adapter is not self._adapter:
            return False
        check = getattr(adapter, "private_read_sender_companion_fence_healthy", None)
        return bool(callable(check) and check(self._config.profile) is True)

    async def send(self, destination: str, text: str) -> str:
        if not hmac.compare_digest(destination, self._config.owner_chat):
            raise JunoPrivateReadError("ordinary transport unavailable")
        adapter = self._resolve_adapter()
        if adapter is None or adapter is not self._adapter:
            raise JunoPrivateReadError("ordinary transport unavailable")
        result = await adapter.send(destination, text)
        message_id = getattr(result, "message_id", None)
        if getattr(result, "success", False) is not True or not message_id:
            raise JunoPrivateReadError("ordinary transport unavailable")
        return str(message_id)


@dataclass(frozen=True, slots=True, repr=False)
class JunoOrdinaryRuntimeTopology:
    adapter: object
    adapter_generation: str
    ordinary_runtime_id: str
    ordinary_socket_generation: int
    ordinary_account_phone: str
    ordinary_account_lid: str
    ordinary_session_path: str
    ordinary_session_identity: str
    ordinary_manifest_sha256: str
    ordinary_source_sha256: str
    ordinary_launcher_sha256: str
    sensitive_session_path: str
    sensitive_session_identity: str
    sensitive_credential_identity: str = ""
    sensitive_device_identity_sha256: str = ""
    sensitive_credential_tree_sha256: str = ""
    sensitive_account_phone: str = ""
    sensitive_account_lid: str = ""

    def __repr__(self) -> str:
        return "<JunoOrdinaryRuntimeTopology redacted>"

    @property
    def generation(self) -> tuple[object, ...]:
        return (
            id(self.adapter), self.adapter_generation, self.ordinary_runtime_id,
            self.ordinary_socket_generation, self.ordinary_account_phone,
            self.ordinary_account_lid, self.ordinary_session_path,
            self.ordinary_session_identity, self.sensitive_session_path,
            self.sensitive_session_identity, self.sensitive_credential_identity,
            self.sensitive_device_identity_sha256,
            self.sensitive_credential_tree_sha256,
            self.sensitive_account_phone, self.sensitive_account_lid,
        )


def _expected_sensitive_session_topology(session_path: Path) -> dict[str, str] | None:
    """Derive content-free sensitive credential authority before child launch."""
    try:
        owner = os.getuid() if hasattr(os, "getuid") else None
        entries: list[tuple[str, str]] = []
        credentials: dict[str, object] | None = None
        credential_identity = ""

        def walk(directory: Path, relative: str = "") -> None:
            nonlocal credentials, credential_identity
            for child in sorted(directory.iterdir(), key=lambda item: item.name):
                child_relative = f"{relative}/{child.name}" if relative else child.name
                info = child.lstat()
                if child.is_symlink() or (owner is not None and info.st_uid != owner):
                    raise ValueError("untrusted sensitive credential tree")
                if child.is_dir():
                    if info.st_mode & 0o7777 != 0o700:
                        raise ValueError("untrusted sensitive credential directory")
                    walk(child, child_relative)
                    continue
                if not child.is_file() or child.suffix != ".json" \
                        or info.st_nlink != 1 or info.st_mode & 0o7777 != 0o600:
                    raise ValueError("untrusted sensitive credential artifact")
                if child.resolve(strict=True) != child:
                    raise ValueError("non-canonical sensitive credential artifact")
                value = child.read_bytes()
                entries.append((child_relative, hashlib.sha256(value).hexdigest()))
                if child_relative == "creds.json":
                    credentials = json.loads(value)
                    credential_identity = f"{info.st_dev}:{info.st_ino}"

        walk(session_path)
        if type(credentials) is not dict or not credential_identity:
            return None
        required = ("registrationId", "noiseKey", "signedIdentityKey", "advSecretKey")
        if any(credentials.get(key) is None for key in required):
            return None
        me = credentials.get("me")
        if credentials.get("registered") is not True or type(me) is not dict:
            return None
        phone = re.sub(r":\d+@", "@", str(me.get("id", "")))
        lid = re.sub(r":\d+@", "@", str(me.get("lid", "")))
        phone = _jid(phone, "sensitive phone")
        lid = _jid(lid, "sensitive lid")
        if not phone.endswith("@s.whatsapp.net") or not lid.endswith("@lid"):
            return None
        device_material = {key: credentials[key] for key in required}
        canonical = lambda value: json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        return {
            "credential_identity": credential_identity,
            "device_identity_sha256": hashlib.sha256(canonical(device_material)).hexdigest(),
            "credential_tree_sha256": hashlib.sha256(canonical(entries)).hexdigest(),
            "account_phone_jid": phone,
            "account_lid_jid": lid,
        }
    except BaseException:
        return None


def resolve_juno_ordinary_runtime_topology(
    runner: object, config: JunoPrivateReadMvpConfig,
) -> JunoOrdinaryRuntimeTopology | None:
    """Resolve exact current ordinary and expected sensitive filesystem authority."""
    if bool(getattr(getattr(runner, "config", None), "multiplex_profiles", False)):
        return None
    adapter = getattr(runner, "adapters", {}).get(Platform.WHATSAPP)
    observe = getattr(adapter, "private_read_runtime_topology", None)
    if adapter is None or not callable(observe):
        return None
    try:
        raw = observe(config.profile)
        fields = {
            "adapter_generation", "ordinary_runtime_id",
            "ordinary_socket_generation", "ordinary_account_phone",
            "ordinary_account_lid", "ordinary_session_path",
            "ordinary_session_identity", "ordinary_manifest_sha256",
            "ordinary_source_sha256", "ordinary_launcher_sha256",
        }
        if type(raw) is not dict or set(raw) != fields:
            return None
        if type(raw["ordinary_socket_generation"]) is not int \
                or raw["ordinary_socket_generation"] < 1:
            return None
        account_aliases = {raw["ordinary_account_phone"], raw["ordinary_account_lid"]}
        if config.ordinary_account not in account_aliases:
            return None
        ordinary_path = Path(_text(raw["ordinary_session_path"], "ordinary session", 2048))
        if not ordinary_path.is_absolute() or ordinary_path.resolve(strict=True) != ordinary_path:
            return None
        ordinary_stat = ordinary_path.stat()
        if raw["ordinary_session_identity"] != f"{ordinary_stat.st_dev}:{ordinary_stat.st_ino}":
            return None
        from hermes_constants import get_hermes_home
        sensitive_path = (
            get_hermes_home() / "sensitive-delivery" / "whatsapp" / "session"
        )
        if sensitive_path.resolve(strict=True) != sensitive_path:
            return None
        sensitive_stat = sensitive_path.stat()
        sensitive_topology = _expected_sensitive_session_topology(sensitive_path)
        if sensitive_topology is None or config.sensitive_account not in {
            sensitive_topology["account_phone_jid"], sensitive_topology["account_lid_jid"],
        }:
            return None
        if ordinary_path == sensitive_path or ordinary_path.is_relative_to(sensitive_path) \
                or sensitive_path.is_relative_to(ordinary_path):
            return None
        if (ordinary_stat.st_dev, ordinary_stat.st_ino) == (
            sensitive_stat.st_dev, sensitive_stat.st_ino,
        ):
            return None
        from gateway.platforms.whatsapp_common import (
            ORDINARY_VERIFIED_LAUNCHER_SHA256,
            ORDINARY_VERIFIED_MANIFEST_SHA256,
            ORDINARY_VERIFIED_SOURCE_SHA256,
        )
        if (
            raw["ordinary_manifest_sha256"] != ORDINARY_VERIFIED_MANIFEST_SHA256
            or raw["ordinary_source_sha256"] != ORDINARY_VERIFIED_SOURCE_SHA256
            or raw["ordinary_launcher_sha256"] != ORDINARY_VERIFIED_LAUNCHER_SHA256
        ):
            return None
        return JunoOrdinaryRuntimeTopology(
            adapter=adapter,
            adapter_generation=_text(raw["adapter_generation"], "adapter generation"),
            ordinary_runtime_id=_text(raw["ordinary_runtime_id"], "ordinary runtime"),
            ordinary_socket_generation=raw["ordinary_socket_generation"],
            ordinary_account_phone=_jid(raw["ordinary_account_phone"], "ordinary phone"),
            ordinary_account_lid=_jid(raw["ordinary_account_lid"], "ordinary lid"),
            ordinary_session_path=str(ordinary_path),
            ordinary_session_identity=raw["ordinary_session_identity"],
            ordinary_manifest_sha256=raw["ordinary_manifest_sha256"],
            ordinary_source_sha256=raw["ordinary_source_sha256"],
            ordinary_launcher_sha256=raw["ordinary_launcher_sha256"],
            sensitive_session_path=str(sensitive_path),
            sensitive_session_identity=f"{sensitive_stat.st_dev}:{sensitive_stat.st_ino}",
            sensitive_credential_identity=sensitive_topology["credential_identity"],
            sensitive_device_identity_sha256=sensitive_topology["device_identity_sha256"],
            sensitive_credential_tree_sha256=sensitive_topology["credential_tree_sha256"],
            sensitive_account_phone=sensitive_topology["account_phone_jid"],
            sensitive_account_lid=sensitive_topology["account_lid_jid"],
        )
    except BaseException:
        return None


_SENSITIVE_RECEIVER_REPLAY_DIRECTORY = "sensitive-receiver-replay"
_SENSITIVE_RECEIVER_REPLAY_ANCHOR = "sensitive-receiver-replay.anchor"
_SENSITIVE_RECEIVER_REPLAY_AUTHORITY = ".authority"


def _prepare_sensitive_receiver_replay_authority(state_dir: Path) -> dict[str, str]:
    """Create once, then strictly validate, the receiver-owned replay domain.

    The sibling anchor makes disappearance of the replay directory fail closed
    instead of looking like a fresh install.  This domain is deliberately not
    part of authorization SQLite and is never rebuilt from authorization rows.
    """
    root = state_dir / _SENSITIVE_RECEIVER_REPLAY_DIRECTORY
    anchor = state_dir / _SENSITIVE_RECEIVER_REPLAY_ANCHOR
    authority = root / _SENSITIVE_RECEIVER_REPLAY_AUTHORITY

    def owner_regular(path: Path) -> os.stat_result:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            or path.resolve(strict=True) != path
        ):
            raise JunoPrivateReadError("sensitive replay authority unavailable")
        return info

    def sync_directory(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def write_all(descriptor: int, value: bytes) -> None:
        offset = 0
        while offset < len(value):
            written = os.write(descriptor, value[offset:])
            if written <= 0:
                raise JunoPrivateReadError("sensitive replay authority unavailable")
            offset += written

    try:
        root_exists, anchor_exists = root.exists(), anchor.exists()
        if root_exists != anchor_exists:
            raise JunoPrivateReadError("sensitive replay authority unavailable")
        if not root_exists:
            # Creation is a one-time pristine-state transition. Once any Juno
            # state exists, disappearance of both replay artifacts is damage,
            # not a new install, and must not make old request IDs reusable.
            if any(state_dir.iterdir()):
                raise JunoPrivateReadError("sensitive replay authority unavailable")
            root.mkdir(mode=0o700, parents=False)
            marker = secrets.token_hex(32).encode("ascii") + b"\n"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(authority, flags, 0o600)
            try:
                write_all(descriptor, marker)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            authority_sha256 = hashlib.sha256(marker).hexdigest()
            descriptor = os.open(anchor, flags, 0o600)
            try:
                write_all(descriptor, authority_sha256.encode("ascii") + b"\n")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            sync_directory(root)
            sync_directory(state_dir)
        if root.resolve(strict=True) != root:
            raise JunoPrivateReadError("sensitive replay authority unavailable")
        root_info = root.lstat()
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or stat.S_ISLNK(root_info.st_mode)
            or stat.S_IMODE(root_info.st_mode) != 0o700
            or (hasattr(os, "getuid") and root_info.st_uid != os.getuid())
        ):
            raise JunoPrivateReadError("sensitive replay authority unavailable")
        owner_regular(anchor)
        owner_regular(authority)
        marker = authority.read_bytes()
        authority_sha256 = hashlib.sha256(marker).hexdigest()
        if (
            len(marker) != 65
            or re.fullmatch(rb"[a-f0-9]{64}\n", marker) is None
            or anchor.read_bytes() != authority_sha256.encode("ascii") + b"\n"
        ):
            raise JunoPrivateReadError("sensitive replay authority unavailable")
        return {
            "root": str(root),
            "root_identity": f"{root_info.st_dev}:{root_info.st_ino}",
            "anchor_path": str(anchor),
            "authority_sha256": authority_sha256,
        }
    except JunoPrivateReadError:
        raise
    except BaseException:
        raise JunoPrivateReadError("sensitive replay authority unavailable") from None


class _SensitiveBridgeSupervisor:
    """Own one reviewed sensitive child and its fresh submission capability."""

    def __init__(self, config: JunoPrivateReadMvpConfig,
                 topology: JunoOrdinaryRuntimeTopology,
                 *, launcher: Path | None = None, port: int = 3011,
                 transport: JsonTransport | None = None):
        self.config = config
        self.topology = topology
        self.launcher = launcher
        self.port = port
        self.transport = transport or FixedHttpJsonTransport()
        self.process: subprocess.Popen | None = None
        self.process_generation = secrets.token_hex(32)
        self.capability = secrets.token_urlsafe(48)
        self.topology_identity: tuple[tuple[str, str], ...] = ()
        self._last_verified_monotonic = 0.0
        self._replay_identity: dict[str, str] | None = None

    def _launch_descriptor(self) -> dict[str, object]:
        topology = self.topology
        return {
            "version": 2,
            "process_generation": self.process_generation,
            "configured_account_jid": self.config.sensitive_account,
            "profile": self.config.profile,
            "mode": "sensitive-outbound-only",
            "replay": dict(self._replay_identity or {}),
            "ordinary": {
                "adapter_generation": topology.adapter_generation,
                "runtime_id": topology.ordinary_runtime_id,
                "socket_generation": topology.ordinary_socket_generation,
                "account_phone_jid": topology.ordinary_account_phone,
                "account_lid_jid": topology.ordinary_account_lid,
                "session_path": topology.ordinary_session_path,
                "session_identity": topology.ordinary_session_identity,
                "manifest_sha256": topology.ordinary_manifest_sha256,
                "source_sha256": topology.ordinary_source_sha256,
                "launcher_sha256": topology.ordinary_launcher_sha256,
            },
            "sensitive": {
                "session_path": topology.sensitive_session_path,
                "session_identity": topology.sensitive_session_identity,
                "credential_identity": topology.sensitive_credential_identity,
                "device_identity_sha256": topology.sensitive_device_identity_sha256,
                "credential_tree_sha256": topology.sensitive_credential_tree_sha256,
                "account_phone_jid": topology.sensitive_account_phone,
                "account_lid_jid": topology.sensitive_account_lid,
            },
        }

    async def start(self) -> bool:
        from gateway.trusted_private_read_host import (
            SENSITIVE_RUNTIME_LAUNCHER_PATH,
            SENSITIVE_VERIFIED_LAUNCHER_SHA256,
        )
        from hermes_constants import find_node_executable, with_hermes_node_path
        from hermes_cli._subprocess_compat import windows_detach_popen_kwargs

        launcher = self.launcher or SENSITIVE_RUNTIME_LAUNCHER_PATH
        node = find_node_executable("node")
        try:
            if node is None or hashlib.sha256(launcher.read_bytes()).hexdigest() \
                    != SENSITIVE_VERIFIED_LAUNCHER_SHA256:
                return False
            self._replay_identity = _prepare_sensitive_receiver_replay_authority(
                self.config.state_dir
            )
            env = with_hermes_node_path()
            env.pop("HERMES_WHATSAPP_SENSITIVE_CAPABILITY", None)
            env.pop("HERMES_INTERNAL_WHATSAPP_SENSITIVE_LAUNCH", None)
            env.pop("HERMES_INTERNAL_JUNO_TEST_PROVIDER_AUTHORITY_FD", None)
            env.pop("HERMES_INTERNAL_JUNO_TEST_PROVIDER_CAPTURE_FD", None)
            env.pop("HERMES_INTERNAL_JUNO_TEST_PROVIDER_AUTHORITY_SHA256", None)
            env["HERMES_WHATSAPP_SENSITIVE_CAPABILITY"] = self.capability
            env["HERMES_INTERNAL_WHATSAPP_SENSITIVE_LAUNCH"] = json.dumps(
                self._launch_descriptor(), sort_keys=True, separators=(",", ":"),
            )
            self.process = subprocess.Popen(
                [node, str(launcher), "--port", str(self.port)],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env=env,
                **windows_detach_popen_kwargs(),
            )
            deadline = time.monotonic() + min(30.0, self.config.request_timeout * 5)
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    return False
                identity = await self._probe_identity()
                if identity is not None and self._identity_matches_launch(identity):
                    self.topology_identity = identity.topology_identity
                    self._last_verified_monotonic = time.monotonic()
                    return True
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            await self.stop()
            raise
        except BaseException:
            pass
        await self.stop()
        return False

    async def _probe_identity(self) -> SensitiveRuntimeIdentity | None:
        request = SimpleNamespace(
            request_id=f"supervisor-{secrets.token_hex(16)}",
            destination_account=self.config.sensitive_account,
            destination_chat=self.config.requesters[0].sensitive_destination,
            expires_at_us=time.time_ns() // 1000 + 5_000_000,
        )
        return await _sealed_sensitive_identity(
            self.config, self.transport, request,
            capability=self.capability,
            expected_process_generation=self.process_generation,
            expected_topology_identity=self.topology_identity or None,
        )

    async def refresh(self) -> bool:
        if self.process is None or self.process.poll() is not None:
            return False
        identity = await self._probe_identity()
        if identity is None or not self._identity_matches_launch(identity):
            self._last_verified_monotonic = 0.0
            return False
        self.topology_identity = identity.topology_identity
        self._last_verified_monotonic = time.monotonic()
        return True

    def _identity_matches_launch(self, identity: SensitiveRuntimeIdentity) -> bool:
        try:
            evidence = dict(identity.topology_identity)
            return bool(
                identity.process_generation == self.process_generation
                and evidence["ordinary_adapter_generation"]
                    == self.topology.adapter_generation
                and evidence["ordinary_runtime_id"] == self.topology.ordinary_runtime_id
                and evidence["ordinary_socket_generation"]
                    == str(self.topology.ordinary_socket_generation)
                and evidence["ordinary_session_identity"]
                    == self.topology.ordinary_session_identity
                and evidence["sensitive_session_identity"]
                    == self.topology.sensitive_session_identity
                and evidence["sensitive_credential_identity"]
                    == self.topology.sensitive_credential_identity
                and evidence["sensitive_device_identity_sha256"]
                    == self.topology.sensitive_device_identity_sha256
                and evidence["sensitive_credential_tree_sha256"]
                    == self.topology.sensitive_credential_tree_sha256
                and evidence["sensitive_account_phone"]
                    == self.topology.sensitive_account_phone
                and evidence["sensitive_account_lid"]
                    == self.topology.sensitive_account_lid
                and self.config.sensitive_account in {
                    evidence["sensitive_account_phone"],
                    evidence["sensitive_account_lid"],
                }
            )
        except BaseException:
            return False

    def healthy(self) -> bool:
        return bool(self.process is not None and self.process.poll() is None
                    and self.topology_identity
                    and time.monotonic() - self._last_verified_monotonic <= 1.0)

    async def stop(self) -> None:
        process, self.process = self.process, None
        self.capability = ""
        self.topology_identity = ()
        self._last_verified_monotonic = 0.0
        self._replay_identity = None
        if process is None:
            return
        control = process.stdin
        if control is not None:
            try:
                control.close()
            except BaseException:
                pass
        if process.poll() is not None:
            try:
                await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=1)
            except BaseException:
                pass
            return
        try:
            process.terminate()
            await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=3)
        except BaseException:
            try:
                process.kill()
            except BaseException:
                pass
            try:
                await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=3)
            except BaseException:
                pass

    async def observe_identity(self, *, request: MvpRequest) -> SensitiveRuntimeIdentity | None:
        if not self.healthy():
            return None
        return await _sealed_sensitive_identity(
            self.config, self.transport, request, capability=self.capability,
            expected_process_generation=self.process_generation,
            expected_topology_identity=self.topology_identity,
        )

    async def submit(self, *, request: MvpRequest, plaintext: str,
                     identity: SensitiveRuntimeIdentity) -> SensitiveSubmission:
        if not self.healthy():
            return SensitiveSubmission("failed", None, "", "")
        return await _sealed_sensitive_submit(
            self.config, self.transport, request, plaintext, identity,
            capability=self.capability,
            expected_process_generation=self.process_generation,
            expected_topology_identity=self.topology_identity,
        )


class _SensitiveHttpSubmitter:
    def __init__(self, config: JunoPrivateReadMvpConfig, transport: JsonTransport,
                 *, _clock_us: Callable[[], int] | None = None):
        self._config = config
        self._transport = transport
        self._clock_us = _clock_us or (lambda: time.time_ns() // 1000)

    async def observe_identity(
        self, *, request: MvpRequest
    ) -> SensitiveRuntimeIdentity | None:
        return await _sealed_sensitive_identity(self._config, self._transport, request)

    async def submit(
        self, *, request: MvpRequest, plaintext: str, identity: SensitiveRuntimeIdentity
    ) -> SensitiveSubmission:
        try:
            entry_now_us = self._clock_us()
        except BaseException:
            return SensitiveSubmission(
                "failed", None, request.destination_account, request.destination_chat
            )
        entry_deadline = _sensitive_deadline_status(
            request.expires_at_us, entry_now_us
        )
        if entry_deadline != "live":
            return SensitiveSubmission(
                "expired" if entry_deadline == "expired" else "failed",
                None, request.destination_account, request.destination_chat,
            )
        return await _sealed_sensitive_submit(
            self._config, self._transport, request, plaintext, identity,
            _clock_us=self._clock_us, _entry_now_us=entry_now_us,
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
    config: JunoPrivateReadMvpConfig, transport: JsonTransport, request: MvpRequest,
    *, capability: str | None = None,
    expected_process_generation: str | None = None,
    expected_topology_identity: tuple[tuple[str, str], ...] | None = None,
) -> SensitiveRuntimeIdentity | None:
    try:
        requested_at_us = time.time_ns() // 1000
        capability = capability or _read_sensitive_capability(config)
        if capability is None:
            return None
        response = await transport.request(
            method="POST", authority=SENSITIVE_AUTHORITY, path="/v1/submit",
            query=(), headers={"x-hermes-sensitive-capability": capability,
                               "content-type": "application/json",
                               "accept": "application/json"},
            body={"contract_version": SENSITIVE_SUBMIT_CONTRACT_VERSION,
                  "operation": "observe_identity",
                  "request_id": request.request_id,
                  "account": request.destination_account,
                  "destination": request.destination_chat,
                  "expires_at_us": request.expires_at_us},
            timeout=config.request_timeout, max_bytes=4096,
        )
        required = {
            "outcome", "submitted", "provider_account_jid", "identity_observed_us",
            "adapter_runtime_id", "process_generation", "connection_epoch",
            "topology_identity", "transport_identity",
        }
        if type(response) is not dict or set(response) != required:
            return None
        completed_at_us = time.time_ns() // 1000
        observed_at_us = response["identity_observed_us"]
        process_generation = response["process_generation"]
        topology = response["topology_identity"]
        topology_flat = _flatten_sensitive_topology(topology)
        if (
            response["outcome"] != "available"
            or response["submitted"] is not False
            or response["provider_account_jid"] != request.destination_account
            or type(observed_at_us) is not int
            or observed_at_us < requested_at_us - SENSITIVE_IDENTITY_FUTURE_SKEW_US
            or observed_at_us > completed_at_us + SENSITIVE_IDENTITY_FUTURE_SKEW_US
            or completed_at_us - observed_at_us > SENSITIVE_IDENTITY_MAX_AGE_US
            or response["transport_identity"] != _SENSITIVE_TRANSPORT_IDENTITY
            or topology_flat is None
            or (expected_process_generation is not None
                and process_generation != expected_process_generation)
            or (expected_topology_identity is not None
                and topology_flat != expected_topology_identity)
        ):
            return None
        registration = _text(response["adapter_runtime_id"], "runtime identity", 512)
        if registration != f"sensitive-{process_generation}":
            return None
        session = _text(response["connection_epoch"], "connection epoch", 512)
        return SensitiveRuntimeIdentity(
            registration, response["provider_account_jid"], session, observed_at_us,
            tuple(sorted(response["transport_identity"].items())),
            process_generation, topology_flat,
        )
    except BaseException:
        return None


async def _sealed_sensitive_submit(
    config: JunoPrivateReadMvpConfig, transport: JsonTransport, request: MvpRequest,
    plaintext: str, identity: SensitiveRuntimeIdentity,
    *, _clock_us: Callable[[], int] | None = None,
    _entry_now_us: int | None = None,
    capability: str | None = None,
    expected_process_generation: str | None = None,
    expected_topology_identity: tuple[tuple[str, str], ...] | None = None,
) -> SensitiveSubmission:
    clock_us = _clock_us or (lambda: time.time_ns() // 1000)
    try:
        entry_now_us = clock_us() if _entry_now_us is None else _entry_now_us
        entry_deadline = _sensitive_deadline_status(request.expires_at_us, entry_now_us)
        if entry_deadline != "live":
            return SensitiveSubmission(
                "expired" if entry_deadline == "expired" else "failed",
                None, request.destination_account, request.destination_chat,
            )
        capability = capability or _read_sensitive_capability(config)
        if capability is None:
            return SensitiveSubmission("failed", None, "", "")
        if (
            expected_process_generation is not None
            and identity.process_generation != expected_process_generation
        ) or (
            expected_topology_identity is not None
            and identity.topology_identity != expected_topology_identity
        ):
            return SensitiveSubmission("failed", None, "", "")
        issue_deadline = _sensitive_deadline_status(
            request.expires_at_us, clock_us(), previous_now_us=entry_now_us
        )
        if issue_deadline != "live":
            return SensitiveSubmission(
                "expired" if issue_deadline == "expired" else "failed",
                None, request.destination_account, request.destination_chat,
            )
        response = await transport.request(
            method="POST", authority=SENSITIVE_AUTHORITY, path="/v1/submit",
            query=(), headers={"x-hermes-sensitive-capability": capability,
                               "content-type": "application/json", "accept": "application/json"},
            body={"contract_version": SENSITIVE_SUBMIT_CONTRACT_VERSION,
                  "request_id": request.request_id,
                  "registration": identity.registration,
                  "process_generation": identity.process_generation,
                  "session": identity.session,
                  "topology_sha256": dict(identity.topology_identity).get(
                      "topology_sha256", ""
                  ),
                  "account": request.destination_account,
                  "destination": request.destination_chat,
                  "expires_at_us": request.expires_at_us,
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


def _flatten_sensitive_topology(value: object) -> tuple[tuple[str, str], ...] | None:
    try:
        if type(value) is not dict or set(value) != {
            "ordinary", "sensitive", "topology_sha256",
        }:
            return None
        ordinary = value["ordinary"]
        sensitive = value["sensitive"]
        if type(ordinary) is not dict or set(ordinary) != {
            "adapter_generation", "runtime_id", "socket_generation",
            "account_phone_jid", "account_lid_jid", "session_path",
            "session_identity", "manifest_sha256", "source_sha256",
            "launcher_sha256",
        } or type(sensitive) is not dict or set(sensitive) != {
            "session_path", "session_identity", "credential_identity",
            "device_identity_sha256", "credential_tree_sha256",
            "account_phone_jid", "account_lid_jid",
        }:
            return None
        flattened = {
            "topology_sha256": _text(value["topology_sha256"], "topology digest", 64),
            "ordinary_adapter_generation": _text(
                ordinary["adapter_generation"], "ordinary adapter generation"
            ),
            "ordinary_runtime_id": _text(ordinary["runtime_id"], "ordinary runtime"),
            "ordinary_socket_generation": str(ordinary["socket_generation"]),
            "ordinary_session_identity": _text(
                ordinary["session_identity"], "ordinary session identity"
            ),
            "sensitive_session_identity": _text(
                sensitive["session_identity"], "sensitive session identity"
            ),
            "sensitive_credential_identity": _text(
                sensitive["credential_identity"], "sensitive credential identity"
            ),
            "sensitive_device_identity_sha256": _text(
                sensitive["device_identity_sha256"], "sensitive device identity", 64
            ),
            "sensitive_credential_tree_sha256": _text(
                sensitive["credential_tree_sha256"], "sensitive credential tree", 64
            ),
            "sensitive_account_phone": _jid(
                sensitive["account_phone_jid"], "sensitive phone"
            ),
            "sensitive_account_lid": _jid(
                sensitive["account_lid_jid"], "sensitive lid"
            ),
        }
        if any(
            re.fullmatch(r"[a-f0-9]{64}", flattened[key]) is None
            for key in (
                "topology_sha256", "sensitive_device_identity_sha256",
                "sensitive_credential_tree_sha256",
            )
        ):
            return None
        expected_digest = hashlib.sha256(json.dumps(
            {"ordinary": ordinary, "sensitive": sensitive}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        if not hmac.compare_digest(flattened["topology_sha256"], expected_digest):
            return None
        return tuple(sorted(flattened.items()))
    except BaseException:
        return None


def _sensitive_deadline_status(
    expires_at_us: object, now_us: object, *, previous_now_us: int | None = None
) -> str:
    if (
        type(expires_at_us) is not int
        or type(now_us) is not int
        or (previous_now_us is not None and type(previous_now_us) is not int)
        or not MIN_TRUSTED_EPOCH_US <= now_us <= MAX_TRUSTED_EPOCH_US
        or not MIN_TRUSTED_EPOCH_US <= expires_at_us <= MAX_TRUSTED_EPOCH_US
        or (previous_now_us is not None and now_us < previous_now_us)
        or expires_at_us - now_us > MAX_SENSITIVE_DEADLINE_AHEAD_US
    ):
        return "invalid"
    return "live" if now_us < expires_at_us else "expired"


def compose_juno_private_read_mvp_services(
    runner: object, config: JunoPrivateReadMvpConfig,
    *, sensitive_supervisor: _SensitiveBridgeSupervisor | None = None,
) -> JunoPrivateReadDependencies:
    """Concrete code-owned production composition; config supplies data only."""
    if type(sensitive_supervisor) is not _SensitiveBridgeSupervisor \
            or not sensitive_supervisor.healthy():
        raise JunoPrivateReadError("sensitive supervisor unavailable")
    transport = FixedHttpJsonTransport()
    ordinary = _GatewayOrdinaryNotifier(runner, config)
    return JunoPrivateReadDependencies(
        openfga=OpenFgaChecker(config, transport),
        gmail=GmailNewestInboxProvider(config, transport),
        ordinary=ordinary,
        sensitive=sensitive_supervisor,
        ordinary_fence=lambda: bool(
            ordinary.fence_healthy() and sensitive_supervisor.healthy()
        ),
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
        # The replay authority validates the complete sealed form.  Returning
        # only the key prefix here lets cycle-0/1/2 raw 32-byte keys migrate
        # without treating the post-migration seal as a new HMAC key.
        return value[:32] if len(value) >= 32 and len(value) <= 256 else None
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
    "ORDINARY_INBOUND_PROVENANCE",
    "OpenFgaChecker", "PrivateReadAuthorizer", "PrivateReadProvider",
    "SENSITIVE_AUTHORITY", "SENSITIVE_SUBMIT_CONTRACT_VERSION",
    "SensitiveRuntimeIdentity", "SensitiveSubmission",
    "compose_juno_private_read_mvp_services", "private_read_tool_surface_is_closed",
    "render_gmail_message",
]
