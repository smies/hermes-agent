from __future__ import annotations

from types import SimpleNamespace

import pytest

import tools.approval as approval
from twilio_voice.policy import VoiceActionPolicy
from twilio_voice.config import TrustedApprovalDestination


DESTINATION = TrustedApprovalDestination(
    platform="mattermost",
    account_id="reviewed-account",
    chat_id="reviewed-channel",
    user_id="reviewed-owner",
    thread_id="reviewed-thread",
    expires_seconds=120,
)


@pytest.fixture(autouse=True)
def _discard_prepared_trusted_voice_context():
    approval.discard_trusted_voice_approval()
    try:
        yield
    finally:
        approval.discard_trusted_voice_approval()


def test_action_policy_propagates_to_voice_session_only():
    policy = VoiceActionPolicy(
        mode="approval_required",
        safe_tools=frozenset({"read_file"}),
        destination=DESTINATION,
    )
    policy.on_session_start(session_id="voice-session", platform="twilio_voice")
    assert policy.pre_tool_call(tool_name="read_file", session_id="voice-session") is None
    directive = policy.pre_tool_call(
        tool_name="send_message",
        args={"target": "synthetic"},
        session_id="voice-session",
        tool_call_id="tool-call-1",
    )
    assert directive["action"] == "approve"
    assert directive["rule_key"] == "twilio_voice:send_message"
    assert policy.pre_tool_call(tool_name="send_message", session_id="other-session") is None

    # A resumed durable session does not emit on_session_start again, so the
    # per-turn hook must restore the policy scope after a service restart.
    resumed = VoiceActionPolicy(mode="block_external", safe_tools=frozenset())
    resumed.pre_llm_call(session_id="resumed-session", platform="twilio_voice")
    assert resumed.pre_tool_call(tool_name="terminal", session_id="resumed-session")["action"] == "block"


def test_block_policy_and_voice_approval_commands_fail_closed():
    policy = VoiceActionPolicy(mode="block_external", safe_tools=frozenset())
    policy.on_session_start(session_id="voice-session", platform="twilio_voice")
    assert policy.pre_tool_call(tool_name="terminal", session_id="voice-session")["action"] == "block"
    event = SimpleNamespace(
        text="/approve always",
        source=SimpleNamespace(platform=SimpleNamespace(value="twilio_voice")),
    )
    assert policy.pre_gateway_dispatch(event=event)["action"] == "skip"
