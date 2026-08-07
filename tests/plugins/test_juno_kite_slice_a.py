"""Slice A audience-authority tests using synthetic opaque transport IDs only."""

from __future__ import annotations

import asyncio
import copy
import json
import sqlite3
from contextvars import copy_context
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.base import MessageEvent
from gateway.session import SessionSource
from gateway.session_context import clear_session_vars, set_session_vars
from plugins.juno_kite_trusted_principal.mapping_store import MappingStore
from plugins.juno_kite_trusted_principal.runtime import (
    REQUEST_PREFIX,
    RESPONSE_PREFIX,
    TrustedPrincipalRuntime,
    canonical_json,
    sign_payload,
)


_PHONE_A = "11111111111@s.whatsapp.net"
_LID_A = "21111111111@lid"
_PHONE_B = "12222222222@s.whatsapp.net"
_LID_B = "22222222222@lid"
_PHONE_UNKNOWN = "13333333333@s.whatsapp.net"
_BOT_PHONE = "19999999999@s.whatsapp.net"
_BOT_LID = "29999999999@lid"
_GROUP = "300000000000000@g.us"


class MutableRoster:
    def __init__(self, participants=None, generation="a" * 64):
        self.participants = participants or [[_PHONE_A, _LID_A], [_PHONE_B, _LID_B]]
        self.generation = generation
        self.missing = False

    def __call__(
        self,
        _profile="juno",
        _chat_id=_GROUP,
        *,
        timeout=2,
        expected_runtime_id=None,
        expected_socket_generation=None,
    ):
        assert timeout <= 2
        assert expected_runtime_id == "a" * 64
        assert expected_socket_generation == 1
        if self.missing:
            raise RuntimeError("synthetic roster unavailable")
        return {
            "group_id": _GROUP,
            "participants": copy.deepcopy(self.participants),
            "bot_identities": [_BOT_PHONE, _BOT_LID],
            "generation": self.generation,
        }


class Clock:
    def __init__(self):
        self.value = 1_900_000_000

    def __call__(self):
        return self.value


def _config(tmp_path: Path, *, mode="juno") -> dict:
    return {
        "a2a_agents": {
            "kite": {
                "url": "http://127.0.0.1:9917",
                "auth": {"type": "bearer", "token": "synthetic-peer-token"},
                "timeout": 5,
            }
        },
        "juno_kite_trusted_principal": {
            "enabled": True,
            "mode": mode,
            "profile": mode,
            "mapping_path": str(tmp_path / "owner" / "mapping.sqlite3"),
            "mapping_key_env": "JK_MAPPING_KEY",
            "request_key_env": "JK_REQUEST_KEY",
            "response_key_env": "JK_RESPONSE_KEY",
            "principal_bindings": [
                {"platform": "whatsapp", "user_id": _PHONE_A, "principal": "owner"},
                {"platform": "whatsapp", "user_id": _LID_A, "principal": "owner"},
                {"platform": "whatsapp", "user_id": _PHONE_B, "principal": "family"},
                {"platform": "whatsapp", "user_id": _LID_B, "principal": "family"},
            ],
            "allowed_group_conversations": [
                {"platform": "whatsapp", "chat_id": _GROUP},
            ],
            "kite_peer": "kite",
            "kite_url": "http://127.0.0.1:9917",
            "kite_plugin": "juno_kite_trusted_principal",
            "policy_generation": "slice-a-policy-v2",
            "limits": {
                "question_chars": 120,
                "context_turns": 2,
                "context_turn_chars": 48,
                "handoff_bytes": 2400,
                "policy_view_chars": 4000,
                "output_chars": 96,
                "response_bytes": 2600,
                "turn_ttl_seconds": 30,
                "roster_timeout_seconds": 2,
            },
            "policy": {
                "principals": {
                    "owner": {
                        "conversation_eligibility": {"dm": True, "group": True},
                        "required_group_co_principals": [],
                        "read_capability_ids": ["private.owner", "private.shared"],
                        "action_capability_ids": ["fixture.write"],
                        "semantic_policy": {
                            "private.owner": {"disclose": ["owner"]},
                            "private.shared": {"disclose": ["shared"]},
                        },
                    },
                    "family": {
                        "conversation_eligibility": {"dm": False, "group": True},
                        "required_group_co_principals": ["owner"],
                        "read_capability_ids": ["private.shared"],
                        "action_capability_ids": [],
                        "semantic_policy": {
                            "private.shared": {"disclose": ["shared"]},
                        },
                    },
                },
                "tool_classes": {"read": ["read_file"], "mutating": ["write_file"]},
                "action_rules": [],
            },
        },
    }


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    monkeypatch.setenv("JK_MAPPING_KEY", "mapping-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_REQUEST_KEY", "request-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_RESPONSE_KEY", "response-key-with-at-least-thirty-two-bytes")


def _runtime(tmp_path, *, mode="juno", transport=None, clock=None):
    return TrustedPrincipalRuntime(
        _config(tmp_path, mode=mode),
        active_profile=mode,
        transport=transport,
        clock=clock,
    )


def _event(*, sender=_PHONE_B, chat_type="group", chat_id=_GROUP):
    return MessageEvent(
        text="synthetic question",
        message_id="opaque-message",
        source=SessionSource(
            platform=Platform.WHATSAPP,
            user_id=sender,
            chat_id=chat_id,
            user_name="untrusted display",
            chat_type=chat_type,
        ),
        metadata={
            "whatsapp_inbound_provenance": "messages.upsert:registered-emitting-socket:v1",
            "whatsapp_inbound_runtime_id": "a" * 64,
            "whatsapp_inbound_socket_generation": 1,
        },
    )


def _session(callback, *, sender=_PHONE_B, chat_type="group", chat_id=_GROUP):
    def run():
        tokens = set_session_vars(
            platform="whatsapp",
            source="whatsapp",
            chat_id=chat_id,
            chat_type=chat_type,
            user_id=sender,
            session_key=f"agent:juno:whatsapp:{chat_type}:opaque",
            session_id="opaque-session",
            profile="juno",
            cron_session="",
        )
        try:
            return callback()
        finally:
            clear_session_vars(tokens)

    return copy_context().run(run)


@pytest.mark.asyncio
async def test_group_only_dm_is_silent_before_auth_session_model_and_store(tmp_path, monkeypatch):
    runtime = _runtime(tmp_path)
    monkeypatch.setattr(
        "plugins.juno_kite_trusted_principal.runtime.runtime_from_host",
        lambda _profile: runtime,
    )
    from plugins.juno_kite_trusted_principal import register

    hooks = {}
    ctx = SimpleNamespace(
        profile_name="juno",
        register_hook=lambda name, callback: hooks.setdefault(name, callback),
        register_tool=lambda **_kwargs: None,
    )
    register(ctx)
    assert "pre_gateway_dispatch" in hooks

    runner = MagicMock()
    runner.config = GatewayConfig(platforms={Platform.WHATSAPP: PlatformConfig(enabled=True)})
    runner._is_user_authorized.side_effect = AssertionError("auth must not run")
    runner.async_session_store.get_or_create_session = AsyncMock(
        side_effect=AssertionError("session must not run")
    )
    runner.adapters = {}

    decision = await hooks["pre_gateway_dispatch"](
        event=_event(chat_type="dm", chat_id=_PHONE_B), gateway=runner
    )
    assert decision == {
        "action": "skip", "reason": "conversation-ineligible", "redact_scope": True
    }
    with runtime.store._database(write=False) as db:
        assert db.execute("SELECT COUNT(*) FROM mappings").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM request_ledger").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_required_co_principal_absent_is_silent(tmp_path):
    runtime = _runtime(tmp_path)
    roster = MutableRoster(participants=[[_PHONE_B, _LID_B]])
    adapter = SimpleNamespace(authenticated_group_roster=roster)
    gateway = SimpleNamespace(adapters={Platform.WHATSAPP: adapter})
    result = await runtime.pre_gateway_dispatch(event=_event(), gateway=gateway)
    assert result == {
        "action": "skip",
        "reason": "required-co-principal-unproved",
        "redact_scope": True,
    }


@pytest.mark.asyncio
async def test_group_only_missing_roster_is_silent(tmp_path):
    runtime = _runtime(tmp_path)
    roster = MutableRoster()
    roster.missing = True
    gateway = SimpleNamespace(
        adapters={Platform.WHATSAPP: SimpleNamespace(authenticated_group_roster=roster)}
    )
    result = await runtime.pre_gateway_dispatch(event=_event(), gateway=gateway)
    assert result == {
        "action": "skip",
        "reason": "audience-authority-unavailable",
        "redact_scope": True,
    }


@pytest.mark.asyncio
async def test_intersection_alias_equivalence_bot_exclusion_and_unknown_public_only(tmp_path):
    runtime = _runtime(tmp_path)
    roster = MutableRoster(
        participants=[[_PHONE_A, _LID_A], [_PHONE_B, _LID_B], [_BOT_PHONE, _BOT_LID]]
    )
    gateway = SimpleNamespace(
        adapters={Platform.WHATSAPP: SimpleNamespace(authenticated_group_roster=roster)}
    )
    assert await runtime.pre_gateway_dispatch(event=_event(), gateway=gateway) is None
    binding = runtime.current_audience_binding()
    assert binding.effective_read_capability_ids == ("private.shared",)
    assert binding.effective_action_capability_ids == ()
    assert binding.private_eligible is True

    roster.participants.append([_PHONE_UNKNOWN])
    assert await runtime.pre_gateway_dispatch(event=_event(), gateway=gateway) is None
    unknown = runtime.current_audience_binding()
    assert unknown.effective_read_capability_ids == ()
    assert unknown.effective_action_capability_ids == ()
    assert unknown.private_eligible is False


@pytest.mark.asyncio
async def test_unknown_public_only_denies_before_mapping_or_request(tmp_path):
    calls = []
    runtime = _runtime(tmp_path, transport=lambda *args: calls.append(args))
    roster = MutableRoster(participants=[[_PHONE_A, _LID_A], [_PHONE_B, _LID_B], [_PHONE_UNKNOWN]])
    gateway = SimpleNamespace(
        adapters={Platform.WHATSAPP: SimpleNamespace(authenticated_group_roster=roster)}
    )
    assert await runtime.pre_gateway_dispatch(event=_event(), gateway=gateway) is None
    result = await asyncio.to_thread(
        _session,
        lambda: runtime.consult_kite({"question_or_goal": "bounded synthetic question"}),
    )
    assert result.startswith("BLOCKED:")
    assert calls == []
    with runtime.store._database(write=False) as db:
        assert db.execute("SELECT COUNT(*) FROM mappings").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM request_ledger").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_concurrent_conversations_keep_task_local_audiences_isolated(tmp_path):
    runtime = _runtime(tmp_path)
    roster = MutableRoster()
    gateway = SimpleNamespace(
        adapters={Platform.WHATSAPP: SimpleNamespace(authenticated_group_roster=roster)}
    )

    async def group_turn():
        assert await runtime.pre_gateway_dispatch(event=_event(), gateway=gateway) is None
        await asyncio.sleep(0)
        return runtime.current_audience_binding().effective_read_capability_ids

    async def dm_turn():
        assert await runtime.pre_gateway_dispatch(
            event=_event(sender=_PHONE_A, chat_type="dm", chat_id=_PHONE_A),
            gateway=gateway,
        ) is None
        await asyncio.sleep(0)
        return runtime.current_audience_binding().effective_read_capability_ids

    group_caps, dm_caps = await asyncio.gather(group_turn(), dm_turn())
    assert group_caps == ("private.shared",)
    assert dm_caps == ("private.owner", "private.shared")


@pytest.mark.asyncio
@pytest.mark.parametrize("change_boundary", ["before_dispatch", "before_release"])
async def test_roster_or_generation_change_aborts_nonreusable_request(
    tmp_path, change_boundary
):
    clock = Clock()
    roster = MutableRoster()
    kite = _runtime(tmp_path, mode="kite", clock=clock)

    def transport(_peer_name, _peer, message, context_id):
        if change_boundary == "before_release":
            roster.generation = "b" * 64

        def kite_turn():
            tokens = set_session_vars(
                platform="a2a",
                source="a2a",
                chat_id=context_id,
                user_id="juno",
                session_key=f"agent:kite:a2a:dm:{context_id}",
                session_id="kite-session",
                profile="kite",
                cron_session="",
            )
            try:
                view = kite.pre_llm_call(
                    user_message=message, session_id="kite-session", turn_id="kite-turn"
                )
                assert "policy view" in view["context"].lower()
                return (
                    kite.transform_llm_output(
                        response_text="bounded private answer", session_id="kite-session"
                    ),
                    context_id,
                    "completed",
                )
            finally:
                clear_session_vars(tokens)

        return copy_context().run(kite_turn)

    juno = _runtime(tmp_path, transport=transport, clock=clock)
    gateway = SimpleNamespace(
        adapters={Platform.WHATSAPP: SimpleNamespace(authenticated_group_roster=roster)}
    )
    assert await juno.pre_gateway_dispatch(event=_event(), gateway=gateway) is None
    if change_boundary == "before_dispatch":
        roster.generation = "b" * 64
    result = await asyncio.to_thread(
        _session,
        lambda: juno.consult_kite({"question_or_goal": "bounded synthetic question"}),
    )
    assert result.startswith("BLOCKED:")
    with juno.store._database(write=False) as db:
        rows = db.execute("SELECT state FROM request_ledger").fetchall()
    if change_boundary == "before_dispatch":
        assert rows == []
    else:
        assert [row[0] for row in rows] == ["aborted"]


def test_v2_envelope_exact_fields_and_cross_audience_binding_denial(tmp_path):
    runtime = _runtime(tmp_path)
    # A deterministic, explicitly eligible owner DM remains usable without a group roster.
    class Capture:
        calls = []

        def __call__(self, peer_name, peer, message, context_id):
            self.calls.append(message)
            return "unsigned", context_id, "completed"

    capture = Capture()
    runtime.transport = capture
    result = _session(
        lambda: runtime.consult_kite({"question_or_goal": "bounded synthetic question"}),
        sender=_PHONE_A,
        chat_type="dm",
        chat_id=_PHONE_A,
    )
    assert result.startswith("BLOCKED:")
    payload = json.loads(capture.calls[0].split(REQUEST_PREFIX, 1)[1])
    assert payload["version"] == 2
    assert set(payload) == {
        "version", "context_id", "correlation_id", "request_id",
        "policy_generation", "expires_at", "question_or_goal", "relevant_context",
        "audience_digest", "conversation_binding", "effective_read_capability_ids",
        "effective_action_capability_ids", "roster_generation", "signature",
    }
    assert _PHONE_A not in json.dumps(payload)
    payload["audience_digest"] = "f" * 64
    payload["signature"] = sign_payload(
        {key: value for key, value in payload.items() if key != "signature"},
        runtime.request_key,
    )
    kite = _runtime(tmp_path, mode="kite")
    tokens = set_session_vars(
        platform="a2a", source="a2a", chat_id=payload["context_id"], user_id="juno",
        session_key="agent:kite:a2a:dm:opaque", session_id="kite-session", profile="kite",
        cron_session="",
    )
    try:
        denied = kite.pre_llm_call(
            user_message=capture.calls[0].split(REQUEST_PREFIX, 1)[0]
            + REQUEST_PREFIX
            + canonical_json(payload),
            session_id="kite-session",
            turn_id="kite-turn",
        )
    finally:
        clear_session_vars(tokens)
    assert "denied" in denied["context"].lower()


def test_v2_response_exact_fields_echo_signed_audience_and_replay_is_terminal(tmp_path):
    clock = Clock()
    kite = _runtime(tmp_path, mode="kite", clock=clock)
    captured = {}

    def transport(_peer_name, _peer, message, context_id):
        def turn():
            tokens = set_session_vars(
                platform="a2a", source="a2a", chat_id=context_id, user_id="juno",
                session_key=f"agent:kite:a2a:dm:{context_id}",
                session_id="kite-session", profile="kite", cron_session="",
            )
            try:
                view = kite.pre_llm_call(
                    user_message=message, session_id="kite-session", turn_id="kite-turn"
                )
                assert _PHONE_A not in view["context"]
                raw = kite.transform_llm_output(
                    response_text="bounded answer", session_id="kite-session"
                )
                captured["raw"] = raw
                return raw, context_id, "completed"
            finally:
                clear_session_vars(tokens)

        return copy_context().run(turn)

    juno = _runtime(tmp_path, transport=transport, clock=clock)
    assert _session(
        lambda: juno.consult_kite({"question_or_goal": "bounded synthetic question"}),
        sender=_PHONE_A,
        chat_type="dm",
        chat_id=_PHONE_A,
    ) == "bounded answer"
    payload = json.loads(captured["raw"].split(RESPONSE_PREFIX, 1)[1])
    assert set(payload) == {
        "version", "context_id", "correlation_id", "request_id",
        "policy_generation", "expires_at", "answer", "denied", "reason",
        "audience_digest", "conversation_binding", "effective_read_capability_ids",
        "effective_action_capability_ids", "roster_generation", "signature",
    }
    assert payload["version"] == 2
    assert _PHONE_A not in json.dumps(payload)
    mapping = juno.store.get_by_context(payload["context_id"])
    reordered = dict(payload)
    reordered["effective_read_capability_ids"] = list(
        reversed(reordered["effective_read_capability_ids"])
    )
    reordered["signature"] = sign_payload(
        {key: value for key, value in reordered.items() if key != "signature"},
        juno.response_key,
    )
    guard = captured["raw"].split(RESPONSE_PREFIX, 1)[0]
    with pytest.raises(ValueError, match="capabilities"):
        juno._validate_response(
            guard + RESPONSE_PREFIX + canonical_json(reordered),
            mapping,
            payload["request_id"],
        )
    with pytest.raises(ValueError, match="replayed"):
        juno._verify_response(captured["raw"], mapping, payload["request_id"])


def test_exact_old_schema_migrates_idempotently_and_aborts_replayable_rows(tmp_path):
    owner = tmp_path / "owner"
    owner.mkdir(mode=0o700)
    path = owner / "mapping.sqlite3"
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE mappings (
            principal TEXT NOT NULL, conversation_digest TEXT NOT NULL,
            context_id TEXT NOT NULL UNIQUE, correlation_id TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL DEFAULT (unixepoch()),
            PRIMARY KEY (principal, conversation_digest));
        CREATE TABLE request_ledger (
            request_id TEXT PRIMARY KEY, context_id TEXT NOT NULL,
            correlation_id TEXT NOT NULL, policy_generation TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('issued','bound','released','consumed')),
            action_fingerprint TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL DEFAULT (unixepoch()),
            FOREIGN KEY (context_id) REFERENCES mappings(context_id));
        INSERT INTO mappings VALUES ('owner','a','ctx-a','corr-a',1);
        INSERT INTO request_ledger VALUES ('req-a','ctx-a','corr-a','old',9999999999,'issued','',1);
        """
    )
    db.commit()
    db.close()
    path.chmod(0o600)

    key = b"mapping-key-with-at-least-thirty-two-bytes"
    first = MappingStore(path, key)
    assert first.get_request("req-a").state == "aborted"
    first.close()
    second = MappingStore(path, key)
    record = second.get_request("req-a")
    assert record.state == "aborted"
    assert record.audience_digest == ""
    second.close()
