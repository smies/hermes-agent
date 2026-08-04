"""Relay Phase 3 interactive tests — prompt op egress, prompt_response
consumption, and the react ack lifecycle.

Covers:
  - send_exec_approval / send_slash_confirm / send_clarify render through ONE
    `prompt` op with the right option sets, honoring op gating (legacy
    connectors get the base/text behaviour or a structured failure that
    triggers run.py's text fallback);
  - the pending-prompt registry: mint → consume-once → expiry;
  - _consume_prompt_response routes answers to the approval / slash-confirm /
    clarify resolvers and CONSUMES the event; unknown/expired ids fall
    through to normal dispatch;
  - the Discord type-3 hp1 decode (structured prompt_response replacing the
    bare-custom_id stub; foreign custom_ids keep the legacy text shape);
  - on_processing_start/complete drive react ops (👀 → ✅/❌), op-gated and
    best-effort.
"""

from __future__ import annotations

import time
from copy import deepcopy
from typing import Any, Dict, Optional

import pytest

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    MessageEvent,
    MessageType,
    ProcessingOutcome,
    build_session_key,
)
from gateway.relay.adapter import RelayAdapter
from gateway.relay.descriptor import CONTRACT_VERSION, CapabilityDescriptor
from gateway.session import SessionSource

from tests.gateway.relay.stub_connector import StubConnector

FULL_OPS = (
    "send",
    "edit",
    "typing",
    "get_chat_info",
    "send_media",
    "prompt",
    "react",
)


def make_desc(**kw) -> CapabilityDescriptor:
    base = dict(
        contract_version=CONTRACT_VERSION,
        platform="telegram",
        label="Telegram",
        max_message_length=4096,
        supports_draft_streaming=False,
        supports_edit=True,
        supports_threads=True,
        markdown_dialect="markdown_v2",
        len_unit="utf16",
        supported_ops=FULL_OPS,
    )
    base.update(kw)
    return CapabilityDescriptor(**base)


def _adapter(**desc_kw) -> tuple[RelayAdapter, StubConnector]:
    stub = StubConnector(make_desc(**desc_kw))
    adapter = RelayAdapter(PlatformConfig(), make_desc(**desc_kw), transport=stub)
    return adapter, stub


def _event(
    prompt_response: Optional[Dict[str, Any]] = None,
    text: str = "/once",
    chat_id: str = "c1",
    user_id: str = "u1",
    platform: Platform = Platform.TELEGRAM,
    chat_type: str = "dm",
    thread_id: Optional[str] = None,
    profile: Optional[str] = None,
) -> MessageEvent:
    return MessageEvent(
        text=text,
        message_type=MessageType.COMMAND,
        source=SessionSource(
            platform=platform,
            chat_id=chat_id,
            chat_type=chat_type,
            user_id=user_id,
            thread_id=thread_id,
            profile=profile,
        ),
        prompt_response=prompt_response,
    )


# ── egress: the three prompt surfaces ────────────────────────────────────


@pytest.mark.asyncio
async def test_exec_approval_renders_full_option_set():
    adapter, stub = _adapter()
    result = await adapter.send_exec_approval(
        "c1", "rm -rf /tmp/x", "sess:1", description="deletes files"
    )
    assert result.success is True
    assert result.message_id == "pm1"
    action = stub.sent[-1]
    assert action["op"] == "prompt"
    assert action["prompt_kind"] == "approval"
    ids = [o["id"] for o in action["options"]]
    assert ids == ["once", "session", "always", "deny"]
    assert "rm -rf /tmp/x" in action["content"]
    assert "deletes files" in action["content"]
    # The registry holds the pending prompt keyed by the wire's prompt_id.
    assert action["prompt_id"] in adapter._pending_prompts
    state = adapter._pending_prompts[action["prompt_id"]]
    assert state["kind"] == "exec_approval"
    assert state["session_key"] == "sess:1"


@pytest.mark.asyncio
async def test_exec_approval_smart_denied_and_flag_gating():
    adapter, stub = _adapter()
    await adapter.send_exec_approval(
        "c1", "cmd", "s", smart_denied=True, allow_permanent=True, allow_session=True
    )
    ids = [o["id"] for o in stub.sent[-1]["options"]]
    assert ids == ["once", "deny"]  # smart-deny: no session/always
    await adapter.send_exec_approval(
        "c1", "cmd", "s", allow_session=True, allow_permanent=False
    )
    ids = [o["id"] for o in stub.sent[-1]["options"]]
    assert ids == ["once", "session", "deny"]


@pytest.mark.asyncio
async def test_slash_confirm_renders_three_options():
    adapter, stub = _adapter()
    result = await adapter.send_slash_confirm(
        "c1", "Reload MCP", "This invalidates the prompt cache.", "sess:1", "cf-9"
    )
    assert result.success is True
    action = stub.sent[-1]
    ids = [o["id"] for o in action["options"]]
    assert ids == ["once", "always", "cancel"]
    assert "Reload MCP" in action["content"]
    state = adapter._pending_prompts[action["prompt_id"]]
    assert state == {
        **state,
        "kind": "slash_confirm",
        "confirm_id": "cf-9",
        "session_key": "sess:1",
    }


@pytest.mark.asyncio
async def test_clarify_renders_choices_plus_other_with_positional_ids():
    adapter, stub = _adapter()
    result = await adapter.send_clarify(
        "c1",
        "Which environment?",
        ["staging — the safe one", "production"],
        "cl-1",
        "sess:1",
    )
    assert result.success is True
    action = stub.sent[-1]
    assert action["prompt_kind"] == "clarify"
    ids = [o["id"] for o in action["options"]]
    # Positional ids (choice text is arbitrary UTF-8; ids must be callback-safe).
    assert ids == ["c0", "c1", "other"]
    labels = [o["label"] for o in action["options"]]
    assert labels[0].startswith("staging")
    state = adapter._pending_prompts[action["prompt_id"]]
    assert state["choices"] == ["staging — the safe one", "production"]


# ── the pending-prompt registry ──────────────────────────────────────────


# ── inbound consumption ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_prompt_response_resolves_clarify_choice_and_other(monkeypatch):
    adapter, stub = _adapter()
    owner = _event(text="start")
    adapter._capture_scope(owner)
    session = build_session_key(owner.source)
    await adapter.send_clarify(
        "c1", "Which?", ["alpha", "beta"], "cl-9", session
    )
    prompt_id = stub.sent[-1]["prompt_id"]

    resolved: list[tuple] = []
    marked: list[str] = []
    monkeypatch.setattr(
        "tools.clarify_gateway.resolve_gateway_clarify",
        lambda cid, resp: resolved.append((cid, resp)) or True,
    )
    monkeypatch.setattr(
        "tools.clarify_gateway.mark_awaiting_text", lambda cid: marked.append(cid)
    )
    # Positional id maps back to the REAL choice text.
    event = _event({"prompt_id": prompt_id, "option_id": "c1"})
    assert await adapter._consume_prompt_response(event) is True
    assert resolved == [("cl-9", "beta")]

    # "Other" flips to text capture.
    await adapter.send_clarify("c1", "Which?", ["a"], "cl-10", session)
    prompt_id2 = stub.sent[-1]["prompt_id"]
    event2 = _event({"prompt_id": prompt_id2, "option_id": "other"})
    assert await adapter._consume_prompt_response(event2) is True
    assert marked == ["cl-10"]


@pytest.mark.asyncio
async def test_cross_principal_structured_clarify_and_slash_are_fenced_before_mutation(
    monkeypatch,
):
    """Review regression: B cannot resolve or consume A's relay prompts."""
    from tools import clarify_gateway, slash_confirm

    adapter, stub = _adapter()
    owner = _event(text="start", user_id="principal-a")
    attacker = _event(text="/c0", user_id="principal-b")
    adapter._capture_scope(owner)
    session = build_session_key(owner.source)
    clarify_entry = clarify_gateway.register(
        "clarify-owner-a", session, "Which?", ["alpha", "beta"]
    )
    slash_calls: list[str] = []

    async def slash_handler(choice: str) -> str:
        slash_calls.append(choice)
        return "ran"

    slash_confirm.register(session, "confirm-owner-a", "reload-mcp", slash_handler)
    gate_calls: list[tuple[MessageEvent, str]] = []
    adapter.set_busy_principal_gate(
        lambda event, key: gate_calls.append((event, key)) or False
    )
    try:
        await adapter.send_clarify(
            "c1", "Which?", ["alpha", "beta"], "clarify-owner-a", session
        )
        clarify_prompt_id = stub.sent[-1]["prompt_id"]
        await adapter.send_slash_confirm(
            "c1", "Reload", "Confirm", session, "confirm-owner-a"
        )
        slash_prompt_id = stub.sent[-1]["prompt_id"]
        before_prompts = deepcopy(adapter._pending_prompts)
        before_slash = slash_confirm.get_pending(session)

        attacker.prompt_response = {
            "prompt_id": clarify_prompt_id,
            "option_id": "c0",
        }
        assert await adapter._consume_prompt_response(attacker) is True
        attacker.prompt_response = {
            "prompt_id": slash_prompt_id,
            "option_id": "once",
        }
        assert await adapter._consume_prompt_response(attacker) is True

        # Structured ownership is decided read-only from the prompt record;
        # the busy gate is not invoked because it may queue ordinary text.
        assert gate_calls == []
        assert adapter._pending_prompts == before_prompts
        assert clarify_entry.event.is_set() is False
        assert clarify_entry.response is None
        assert slash_confirm.get_pending(session) == before_slash
        assert slash_calls == []
    finally:
        clarify_gateway.clear_session(session)
        slash_confirm.clear(session)


# ── Discord type-3 hp1 decode ────────────────────────────────────────────


def test_discord_component_interaction_decodes_prompt_token():
    adapter, _stub = _adapter()
    owner = _event(
        text="start",
        platform=Platform.DISCORD,
        chat_id="ch1",
        chat_type="channel",
        user_id="u1",
    )
    owner.source.scope_id = "g1"
    session = adapter._canonical_session_key(owner.source)
    assert adapter._on_message_accepted(owner, session) is True
    prompt_id = adapter._mint_prompt(
        "clarify", {"session_key": session, "chat_id": "ch1"}
    )

    class Forward:
        platform = "discord"
        authenticated_user_id = "u1"
        method = "POST"
        path = "/interactions/bot1"
        body = (
            b'{"type": 3, "id": "i1", "channel_id": "ch1", "guild_id": "g1",'
            b' "message": {"id": "pm55"},'
            b' "member": {"user": {"id": "u1", "username": "ben"}},'
            + f' "data": {{"custom_id": "hp1:{prompt_id}:deny"}}}}'.encode()
        )

    event = adapter._discord_interaction_to_event(Forward())
    assert event is not None
    assert event.source.platform == Platform.DISCORD
    assert event.prompt_response == {
        "prompt_id": prompt_id,
        "option_id": "deny",
        "prompt_message_id": "pm55",
    }
    assert event.text == "/deny"
    assert event.message_type == MessageType.COMMAND


@pytest.mark.asyncio
async def test_rejected_shared_thread_event_cannot_poison_later_prompt_owner(monkeypatch):
    """A active, B rejected, then A's later prompt remains A-owned."""
    adapter, stub = _adapter(platform="discord", label="Discord")
    owner = _event(
        text="start",
        user_id="principal-a",
        platform=Platform.DISCORD,
        chat_id="thread-1",
        chat_type="thread",
        thread_id="thread-1",
    )
    attacker = _event(
        text="ordinary inbound",
        user_id="principal-b",
        platform=Platform.DISCORD,
        chat_id="thread-1",
        chat_type="thread",
        thread_id="thread-1",
    )
    session = adapter._canonical_session_key(owner.source)
    assert adapter._on_message_accepted(owner, session) is True
    adapter._active_sessions[session] = __import__("asyncio").Event()
    owner_principal = adapter._authenticated_principal(owner)
    assert owner_principal is not None
    adapter._active_principal_by_session[session] = owner_principal
    handled: list[MessageEvent] = []

    async def handler(event):
        handled.append(event)

    adapter.set_message_handler(handler)
    before = deepcopy(
        {
            "principal": adapter._principal_by_session,
            "platform": adapter._platform_by_chat,
            "scope": adapter._scope_by_chat,
            "dm_user": adapter._dm_user_by_chat,
            "chat_type": adapter._chat_type_by_chat,
            "pending": adapter._pending_prompts,
            "active": {key: id(value) for key, value in adapter._active_sessions.items()},
            "active_principal": adapter._active_principal_by_session,
        }
    )
    await adapter._on_inbound(attacker)
    assert handled == []
    assert {
        "principal": adapter._principal_by_session,
        "platform": adapter._platform_by_chat,
        "scope": adapter._scope_by_chat,
        "dm_user": adapter._dm_user_by_chat,
        "chat_type": adapter._chat_type_by_chat,
        "pending": adapter._pending_prompts,
        "active": {key: id(value) for key, value in adapter._active_sessions.items()},
        "active_principal": adapter._active_principal_by_session,
    } == before

    resolved: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "tools.clarify_gateway.resolve_gateway_clarify",
        lambda clarify_id, response: resolved.append((clarify_id, response)) or True,
    )
    await adapter.send_clarify("thread-1", "Which?", ["alpha"], "clarify-a", session)
    prompt_id = stub.sent[-1]["prompt_id"]
    assert adapter._pending_prompts[prompt_id]["owner_principal"] == adapter._authenticated_principal(owner)

    attacker.prompt_response = {"prompt_id": prompt_id, "option_id": "c0"}
    assert await adapter._consume_prompt_response(attacker) is True
    assert prompt_id in adapter._pending_prompts
    owner.prompt_response = {"prompt_id": prompt_id, "option_id": "c0"}
    assert await adapter._consume_prompt_response(owner) is True
    assert resolved == [("clarify-a", "alpha")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("platform", "chat_type", "thread_id"),
    [
        (Platform.TELEGRAM, "dm", None),
        (Platform.DISCORD, "group", None),
        (Platform.DISCORD, "thread", "thread-1"),
    ],
)
async def test_idle_first_turn_captures_owner_after_acceptance(
    monkeypatch, platform, chat_type, thread_id
):
    adapter, _stub = _adapter(platform=platform.value, label=platform.value.title())
    event = _event(
        text="first",
        platform=platform,
        chat_type=chat_type,
        thread_id=thread_id,
        chat_id="thread-1" if thread_id else "c1",
        user_id="owner-a",
    )
    started: list[str] = []

    async def handler(_event):
        return None

    adapter.set_message_handler(handler)
    monkeypatch.setattr(
        adapter,
        "_start_session_processing",
        lambda _event, key: started.append(key) or True,
    )
    await adapter.handle_message(event)
    expected = adapter._canonical_session_key(event.source)
    assert started == [expected]
    assert adapter._principal_by_session[expected] == adapter._authenticated_principal(event)


@pytest.mark.asyncio
async def test_multiplex_profiles_isolate_prompt_owners_and_same_profile_resolves(monkeypatch):
    adapter, stub = _adapter()
    main = _event(text="main", user_id="owner", profile="default")
    coder = _event(text="coder", user_id="owner", profile="coder")
    main_key = adapter._canonical_session_key(main.source)
    coder_key = adapter._canonical_session_key(coder.source)
    assert main_key == "agent:main:telegram:dm:c1"
    assert coder_key == "agent:coder:telegram:dm:c1"
    assert adapter._on_message_accepted(main, main_key) is True
    assert adapter._on_message_accepted(coder, coder_key) is True
    await adapter.send_clarify("c1", "Which?", ["alpha"], "coder-clarify", coder_key)
    prompt_id = stub.sent[-1]["prompt_id"]
    before = deepcopy(adapter._pending_prompts[prompt_id])

    main.prompt_response = {"prompt_id": prompt_id, "option_id": "c0"}
    assert await adapter._consume_prompt_response(main) is True
    assert adapter._pending_prompts[prompt_id] == before

    resolved: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "tools.clarify_gateway.resolve_gateway_clarify",
        lambda clarify_id, response: resolved.append((clarify_id, response)) or True,
    )
    coder.prompt_response = {"prompt_id": prompt_id, "option_id": "c0"}
    assert await adapter._consume_prompt_response(coder) is True
    assert resolved == [("coder-clarify", "alpha")]


@pytest.mark.asyncio
async def test_discord_component_preserves_platform_profile_and_prompt_owner(monkeypatch):
    adapter, stub = _adapter(platform="discord", label="Discord")
    assert await adapter.connect() is True

    class Runner:
        @staticmethod
        def _profile_name_for_source(_source):
            return "coder"

        @staticmethod
        def _session_key_for_source(source):
            return build_session_key(source, profile=source.profile)

    adapter.gateway_runner = Runner()
    owner = _event(
        text="start",
        platform=Platform.DISCORD,
        chat_id="ch1",
        chat_type="channel",
        user_id="u1",
        profile="coder",
    )
    owner.source.scope_id = "g1"
    session = adapter._canonical_session_key(owner.source)
    assert adapter._on_message_accepted(owner, session) is True
    await adapter.send_clarify("ch1", "Which?", ["alpha"], "discord-c", session)
    prompt_id = stub.sent[-1]["prompt_id"]

    class Forward:
        platform = "discord"
        authenticated_user_id = "u1"
        body = (
            b'{"type":3,"platform":"telegram","profile":"main",'
            b'"id":"i1","channel_id":"ch1","guild_id":"g1",'
            b'"member":{"user":{"id":"u1"}},'
            + f'"data":{{"custom_id":"hp1:{prompt_id}:c0"}}}}'.encode()
        )

    response = adapter._discord_interaction_to_event(Forward())
    assert response is not None
    assert response.source.platform == Platform.DISCORD
    assert response.source.profile == "coder"
    response_identity = adapter._canonical_event_identity(response)
    assert response_identity is not None
    assert response_identity[1:] == (
        adapter._authenticated_principal(owner),
        session,
    )
    resolved: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "tools.clarify_gateway.resolve_gateway_clarify",
        lambda clarify_id, answer: resolved.append((clarify_id, answer)) or True,
    )
    attacker_payload = Forward.body.replace(b'"id":"u1"', b'"id":"u2"')

    class AttackerForward:
        platform = "discord"
        authenticated_user_id = "u2"
        body = attacker_payload

    attacker = adapter._discord_interaction_to_event(AttackerForward())
    assert attacker is not None
    before_prompt = deepcopy(adapter._pending_prompts[prompt_id])
    # Exercise the transport-registered passthrough callback, not only the
    # conversion helper: the authenticated envelope identity reaches the same
    # ownership fence used by the live WS transport.
    await stub.push_passthrough(AttackerForward())
    assert adapter._pending_prompts[prompt_id] == before_prompt
    assert resolved == []
    await stub.push_passthrough(Forward())
    assert resolved == [("discord-c", "alpha")]


@pytest.mark.parametrize(
    ("profile", "chat_id", "chat_type", "thread_id", "parent_chat_id", "scope_id"),
    [
        ("main", "channel-1", "channel", None, None, "guild-1"),
        ("coder", "thread-1", "thread", "thread-1", "channel-1", "guild-1"),
        ("coder", "dm-1", "dm", None, None, None),
    ],
)
def test_discord_component_uses_immutable_prompt_scope_and_envelope_responder(
    profile, chat_id, chat_type, thread_id, parent_chat_id, scope_id
):
    adapter, _stub = _adapter(platform="discord", label="Discord")
    owner = _event(
        text="start",
        platform=Platform.DISCORD,
        chat_id=chat_id,
        chat_type=chat_type,
        thread_id=thread_id,
        user_id="owner-a",
        profile=profile,
    )
    owner.source.parent_chat_id = parent_chat_id
    owner.source.scope_id = scope_id
    session = adapter._canonical_session_key(owner.source)
    assert adapter._on_message_accepted(owner, session) is True
    prompt_id = adapter._mint_prompt(
        "clarify", {"session_key": session, "chat_id": chat_id}
    )

    class Forward:
        platform = "discord"
        authenticated_user_id = "owner-a"
        body = (
            b'{"type":3,"profile":"attacker","channel_id":"payload-channel",'
            b'"guild_id":"payload-guild","member":{"user":{"id":"payload-user"}},'
            + f'"data":{{"custom_id":"hp1:{prompt_id}:c0"}}}}'.encode()
        )

    response = adapter._discord_interaction_to_event(Forward())
    assert response is not None
    assert response.source.platform is Platform.DISCORD
    assert response.source.profile == profile
    assert response.source.chat_id == chat_id
    assert response.source.chat_type == chat_type
    assert response.source.thread_id == thread_id
    assert response.source.parent_chat_id == parent_chat_id
    assert response.source.scope_id == scope_id
    assert response.source.user_id == "owner-a"
    identity = adapter._canonical_event_identity(response)
    assert identity is not None
    assert identity[1:] == (adapter._authenticated_principal(owner), session)

    Forward.authenticated_user_id = "owner-b"
    attacker = adapter._discord_interaction_to_event(Forward())
    assert attacker is not None
    attacker_identity = adapter._canonical_event_identity(attacker)
    assert attacker_identity is not None
    assert attacker_identity[1] != identity[1]
    assert attacker_identity[1:] != identity[1:]


def test_unknown_discord_prompt_component_does_not_trust_payload_scope():
    adapter, _stub = _adapter(platform="discord", label="Discord")

    class Forward:
        platform = "discord"
        authenticated_user_id = "owner-a"
        body = (
            b'{"type":3,"channel_id":"nominated","guild_id":"nominated",'
            b'"member":{"user":{"id":"nominated"}},'
            b'"data":{"custom_id":"hp1:deadbeef:c0"}}'
        )

    assert adapter._discord_interaction_to_event(Forward()) is None


def test_passthrough_conversion_preserves_other_authenticated_underlying_platform():
    adapter, _stub = _adapter()

    class Forward:
        platform = "telegram"
        body = (
            b'{"type":3,"platform":"relay","id":"i1","channel_id":"c1",'
            b'"user":{"id":"u1"},"data":{"custom_id":"foreign"}}'
        )

    event = adapter._discord_interaction_to_event(Forward())
    assert event is not None
    assert event.source.platform == Platform.TELEGRAM


# ── react ack lifecycle ──────────────────────────────────────────────────


def _reactable_event() -> MessageEvent:
    return MessageEvent(
        text="do something",
        message_type=MessageType.TEXT,
        source=SessionSource(
            platform="discord",
            chat_id="ch1",
            chat_type="channel",
            user_id="u1",
            message_id="m42",
        ),
        message_id="m42",
    )


@pytest.mark.asyncio
async def test_processing_lifecycle_reacts_eyes_then_check():
    adapter, stub = _adapter()
    event = _reactable_event()
    await adapter.on_processing_start(event)
    await adapter.on_processing_complete(event, ProcessingOutcome.SUCCESS)
    reacts = [a for a in stub.sent if a["op"] == "react"]
    assert [(r["emoji"], r.get("remove", False)) for r in reacts] == [
        ("👀", False),
        ("👀", True),
        ("✅", False),
    ]
    assert all(r["message_id"] == "m42" and r["chat_id"] == "ch1" for r in reacts)
