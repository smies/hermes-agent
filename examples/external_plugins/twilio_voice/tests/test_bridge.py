from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from twilio_voice.bridge import PIN_PATH, VOICE_PATH, WS_PATH, VoiceBridge
from twilio_voice.config import VoiceConfig
from twilio_voice.security import compute_twilio_signature


ACCOUNT = "AC" + "a" * 32
CALL_1 = "CA" + "1" * 32
CALL_2 = "CA" + "2" * 32
SESSION_1 = "VX" + "3" * 32
SESSION_2 = "VX" + "4" * 32
CALLER = "+442000000001"
CALLED = "+442000000002"
TOKEN = "test-auth-token"
BASE = "https://voice.example.test"


def platform_config(**overrides):
    extra = {
        "public_base_url": BASE,
        "allowed_callers": [CALLER],
        "max_frame_bytes": 2048,
        "max_prompt_chars": 128,
        "max_concurrent_calls": 2,
        "setup_timeout_seconds": 2,
        "idle_timeout_seconds": 10,
        "max_duration_seconds": 60,
        "trusted_approval_destination": {
            "platform": "mattermost",
            "account_id": "reviewed-account",
            "chat_id": "reviewed-channel",
            "user_id": "reviewed-owner",
            "thread_id": "reviewed-thread",
        },
    }
    extra.update(overrides)
    return SimpleNamespace(extra=extra)


class FakeHermesAdapter:
    def __init__(self):
        self._message_handler = object()
        self.bridge = None
        self.prompts = []
        self.interrupts = []
        self.disconnects = []

    async def receive_prompt(self, connection, prompt):
        self.prompts.append((connection.call_sid, prompt))
        await self.bridge.send_final(connection.call_sid, f"Reply to **{prompt}** at https://private.example")

    async def interrupt_call(self, connection, *, reason):
        self.interrupts.append((connection.call_sid, reason))

    async def disconnect_call(self, connection, *, reason):
        self.disconnects.append((connection.call_sid, reason))


@pytest.fixture
def bridge(monkeypatch):
    monkeypatch.setenv("TWILIO_VOICE_PIN", "739155")
    adapter = FakeHermesAdapter()
    value = VoiceBridge(
        adapter,
        VoiceConfig.from_platform_config(platform_config()),
        TOKEN,
        ACCOUNT,
        pin="739155",
    )
    adapter.bridge = value
    value._server_started = True
    return value


def signed_http(client, bridge, path, form, *, valid=True):
    signature = compute_twilio_signature(TOKEN, bridge.signature_url(path), form)
    if not valid:
        signature = "invalid"
    return client.post(
        path,
        content=urlencode(form),
        headers={"content-type": "application/x-www-form-urlencoded", "x-twilio-signature": signature},
    )


def inbound_form(call_sid=CALL_1, caller=CALLER):
    return {
        "AccountSid": ACCOUNT,
        "CallSid": call_sid,
        "From": caller,
        "To": CALLED,
        "Direction": "inbound",
    }


def setup(entry, *, call_sid=CALL_1, session_id=SESSION_1, caller=CALLER):
    return {
        "type": "setup",
        "sessionId": session_id,
        "accountSid": ACCOUNT,
        "callSid": call_sid,
        "from": caller,
        "to": CALLED,
        "direction": "inbound",
        "customParameters": {"nonce": entry.nonce},
    }


def ws_headers(bridge):
    url = bridge.signature_url(WS_PATH, websocket=True)
    return {"x-twilio-signature": compute_twilio_signature(TOKEN, url, None)}


def test_http_signature_allowlist_and_twiml_binding(bridge):
    client = TestClient(bridge.create_app())
    wrong_media = client.post(
        VOICE_PATH,
        content="{}",
        headers={"content-type": "application/json", "x-twilio-signature": "invalid"},
    )
    assert wrong_media.status_code == 415
    bad = signed_http(client, bridge, VOICE_PATH, inbound_form(), valid=False)
    assert bad.status_code == 403
    assert len(bridge.pending) == 0

    unknown = signed_http(client, bridge, VOICE_PATH, inbound_form(caller="+442000000099"))
    assert unknown.status_code == 403
    assert len(bridge.pending) == 0

    response = signed_http(client, bridge, VOICE_PATH, inbound_form())
    assert response.status_code == 200
    assert "Gather" in response.text
    authenticated = signed_http(
        client,
        bridge,
        PIN_PATH,
        {**inbound_form(), "Digits": "739155"},
    )
    assert "ConversationRelay" in authenticated.text
    assert "wss://voice.example.test/twilio/voice/relay" in authenticated.text
    assert len(bridge.pending) == 1
    assert bridge.adapter.prompts == []

    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200
    assert client.get("/docs").status_code == 404


def test_websocket_signature_is_required_before_accept(bridge):
    client = TestClient(bridge.create_app())
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            WS_PATH, headers={"x-twilio-signature": "invalid"}
        ) as websocket:
            websocket.receive_json()


def test_required_pin_is_checked_before_relay(monkeypatch):
    monkeypatch.setenv("TWILIO_VOICE_PIN", "739155")
    adapter = FakeHermesAdapter()
    bridge = VoiceBridge(
        adapter,
        VoiceConfig.from_platform_config(platform_config()),
        TOKEN,
        ACCOUNT,
        pin="739155",
    )
    adapter.bridge = bridge
    client = TestClient(bridge.create_app())
    unsolicited_form = {**inbound_form(call_sid=CALL_2), "Digits": "739155"}
    unsolicited = signed_http(client, bridge, PIN_PATH, unsolicited_form)
    assert unsolicited.status_code == 403
    first = signed_http(client, bridge, VOICE_PATH, inbound_form())
    assert "Gather" in first.text and "ConversationRelay" not in first.text
    wrong_form = {**inbound_form(), "Digits": "0000"}
    wrong = signed_http(client, bridge, PIN_PATH, wrong_form)
    assert "Incorrect PIN" in wrong.text
    right_form = {**inbound_form(), "Digits": "739155"}
    right = signed_http(client, bridge, PIN_PATH, right_form)
    assert "ConversationRelay" in right.text
    assert len(bridge.pending) == 1


def test_pin_policy_is_frozen_against_runtime_environment_mutation(monkeypatch):
    monkeypatch.setenv("TWILIO_VOICE_PIN", "739155")
    adapter = FakeHermesAdapter()
    mutable_config = platform_config()
    bridge = VoiceBridge(
        adapter,
        VoiceConfig.from_platform_config(mutable_config),
        TOKEN,
        ACCOUNT,
        pin="739155",
    )
    adapter.bridge = bridge
    monkeypatch.setenv("TWILIO_VOICE_PIN", "")
    mutable_config.extra["allowed_callers"] = ["+442000000099"]

    assert bridge.pin == "739155"
    assert bridge.config.allowed_callers == (CALLER,)
    client = TestClient(bridge.create_app())
    first = signed_http(client, bridge, VOICE_PATH, inbound_form())
    assert "Gather" in first.text and "ConversationRelay" not in first.text


def test_setup_prompt_stream_interrupt_and_disconnect_cleanup(bridge):
    client = TestClient(bridge.create_app())
    entry = bridge.pending.create(
        call_sid=CALL_1, account_sid=ACCOUNT, caller=CALLER, called=CALLED, pin_verified=True
    )
    with client.websocket_connect(WS_PATH, headers=ws_headers(bridge)) as websocket:
        websocket.send_json(setup(entry))
        websocket.send_json({"type": "prompt", "voicePrompt": "hello", "lang": "en-GB", "last": True})
        response = websocket.receive_json()
        assert response["type"] == "text"
        assert response["last"] is True
        assert "**" not in response["token"]
        assert "private.example" not in response["token"]
        websocket.send_json({"type": "interrupt", "utteranceUntilInterrupt": "Reply", "durationUntilInterruptMs": 20})
        websocket.send_json({"type": "dtmf", "digit": "#"})
    assert bridge.adapter.prompts == [(CALL_1, "hello")]
    assert bridge.adapter.interrupts == [(CALL_1, "caller barge-in")]
    assert bridge.adapter.disconnects
    assert bridge.connections == {}


def test_malformed_oversized_and_invalid_setup_fail_closed(bridge):
    client = TestClient(bridge.create_app())
    entry = bridge.pending.create(
        call_sid=CALL_1, account_sid=ACCOUNT, caller=CALLER, called=CALLED, pin_verified=True
    )
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(WS_PATH, headers=ws_headers(bridge)) as websocket:
            bad_setup = setup(entry, caller="+442000000099")
            websocket.send_json(bad_setup)
            websocket.receive_json()
    assert bridge.adapter.prompts == []

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(WS_PATH, headers=ws_headers(bridge)) as websocket:
            websocket.send_text("x" * 3000)
            websocket.receive_json()


def test_concurrent_calls_are_isolated(bridge):
    client = TestClient(bridge.create_app())
    entry_1 = bridge.pending.create(
        call_sid=CALL_1,
        account_sid=ACCOUNT,
        caller=CALLER,
        called=CALLED,
        pin_verified=True,
    )
    entry_2 = bridge.pending.create(
        call_sid=CALL_2,
        account_sid=ACCOUNT,
        caller=CALLER,
        called=CALLED,
        pin_verified=True,
    )
    with client.websocket_connect(WS_PATH, headers=ws_headers(bridge)) as first:
        first.send_json(setup(entry_1))
        with client.websocket_connect(WS_PATH, headers=ws_headers(bridge)) as second:
            second.send_json(setup(entry_2, call_sid=CALL_2, session_id=SESSION_2))
            first.send_json({"type": "prompt", "voicePrompt": "alpha", "last": True})
            second.send_json({"type": "prompt", "voicePrompt": "beta", "last": True})
            first_reply = first.receive_json()["token"]
            second_reply = second.receive_json()["token"]
            assert "alpha" in first_reply and "beta" not in first_reply
            assert "beta" in second_reply and "alpha" not in second_reply
    assert {call for call, _ in bridge.adapter.prompts} == {CALL_1, CALL_2}
    assert bridge.connections == {}


def test_draft_chunks_are_incremental_and_finalized_once(bridge):
    class Sink:
        def __init__(self):
            self.frames = []

        async def send_text(self, value):
            self.frames.append(json.loads(value))

    sink = Sink()
    from twilio_voice.bridge import CallConnection
    import asyncio
    import time

    connection = CallConnection(sink, CALL_1, CALLER, CALLED, SESSION_1, time.monotonic(), time.monotonic())
    bridge.connections[CALL_1] = connection

    async def run():
        await bridge.send_stream_update(CALL_1, "draft-1", "First sentence. Partial", final=False)
        await bridge.send_stream_update(CALL_1, "draft-1", "First sentence. Partial ending", final=True)

    asyncio.run(run())
    assert sink.frames[0]["last"] is False
    assert sink.frames[-1]["last"] is True
    assert "First sentence" in sink.frames[0]["token"]
    assert "First sentence" not in sink.frames[-1]["token"]


def test_edit_fallback_starts_one_talk_cycle_without_replaying_prefix(bridge):
    class Sink:
        def __init__(self):
            self.frames = []

        async def send_text(self, value):
            self.frames.append(json.loads(value))

    sink = Sink()
    from twilio_voice.adapter import TwilioVoiceAdapter
    from twilio_voice.bridge import CallConnection
    import asyncio
    import time

    connection = CallConnection(
        sink, CALL_1, CALLER, CALLED, SESSION_1, time.monotonic(), time.monotonic()
    )
    bridge.connections[CALL_1] = connection
    adapter = object.__new__(TwilioVoiceAdapter)
    adapter.bridge = bridge

    async def run():
        opened = await adapter.send(
            CALL_1,
            "First sentence. Partial",
            metadata={"expect_edits": True},
        )
        assert opened.success and opened.message_id.startswith("edit-")
        await adapter.edit_message(
            CALL_1,
            opened.message_id,
            "First sentence. Partial ending",
            finalize=True,
        )

    asyncio.run(run())
    assert sink.frames[0]["last"] is False
    assert sink.frames[-1]["last"] is True
    assert "First sentence" in sink.frames[0]["token"]
    assert "First sentence" not in sink.frames[-1]["token"]
