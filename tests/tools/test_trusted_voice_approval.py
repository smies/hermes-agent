from __future__ import annotations

import threading
from unittest.mock import patch

import pytest

import tools.approval as approval


DESTINATION = {
    "platform": "mattermost",
    "account_id": "reviewed-account",
    "chat_id": "reviewed-channel",
    "user_id": "reviewed-owner",
    "thread_id": "reviewed-thread",
}


def _identity(**changes):
    value = dict(DESTINATION)
    value.update(changes)
    return value


def _start_request(args=None, expires_seconds=60):
    session_key = "twilio_voice:exact-call"
    notices = []
    approval.register_gateway_notify(session_key, notices.append)
    ready = threading.Event()
    result = {}

    def worker():
        token = approval.set_current_session_key(session_key)
        observability_tokens = approval.set_current_observability_context(
            tool_call_id="tool-call-1"
        )
        try:
            approval.prepare_trusted_voice_approval(
                voice_session_id=session_key,
                tool_call_id="tool-call-1",
                tool_name="terminal",
                args=args if args is not None else {"command": "synthetic"},
                destination=DESTINATION,
                expires_seconds=expires_seconds,
            )
            ready.set()
            result.update(approval.request_tool_approval("terminal", "voice gate"))
        finally:
            approval.reset_current_observability_context(observability_tokens)
            approval.reset_current_session_key(token)

    thread = threading.Thread(target=worker)
    thread.start()
    assert ready.wait(1)
    for _ in range(100):
        if notices:
            break
        threading.Event().wait(0.01)
    assert notices
    return session_key, notices[0], result, thread


@pytest.mark.parametrize("current_session", ["", "twilio_voice:unrelated-call"])
def test_stale_trusted_voice_context_preserves_ordinary_timeout(current_session):
    session_token = approval.set_current_session_key(current_session)
    interactive_token = approval.set_hermes_interactive_context(True)
    try:
        approval.prepare_trusted_voice_approval(
            voice_session_id="twilio_voice:exact-call",
            tool_call_id="tool-call-1",
            tool_name="terminal",
            args={"command": "synthetic"},
            destination=DESTINATION,
            expires_seconds=60,
        )
        config = {"approvals": {"mode": "manual"}}
        with patch("hermes_cli.config.load_config_readonly", return_value=config):
            result = approval.request_tool_approval(
                "terminal",
                "unrelated ordinary gate",
                approval_callback=lambda *_args, **_kwargs: "timeout",
            )
    finally:
        approval.reset_hermes_interactive_context(interactive_token)
        approval.reset_current_session_key(session_token)

    assert result["approved"] is False
    assert result["outcome"] == "timeout"
    assert result["user_consent"] is False
    assert "timed out without user response" in result["message"]


@pytest.mark.parametrize("current_tool_call_id", ["", "tool-call-other"])
def test_same_voice_session_requires_exact_current_tool_call_without_notice(
    current_tool_call_id, monkeypatch
):
    session_key = "twilio_voice:exact-call"
    notices = []
    approval.register_gateway_notify(session_key, notices.append)
    session_token = approval.set_current_session_key(session_key)
    observability_tokens = approval.set_current_observability_context(
        tool_call_id=current_tool_call_id
    )
    monkeypatch.setattr(approval, "_get_approval_timeout", lambda: 0)
    try:
        approval.prepare_trusted_voice_approval(
            voice_session_id=session_key,
            tool_call_id="tool-call-1",
            tool_name="terminal",
            args={"command": "synthetic"},
            destination=DESTINATION,
            expires_seconds=60,
        )
        result = approval.request_tool_approval("terminal", "voice gate")
    finally:
        approval.reset_current_observability_context(observability_tokens)
        approval.reset_current_session_key(session_token)
        approval.unregister_gateway_notify(session_key)

    assert result["approved"] is False
    assert "correlation" in result["message"].lower()
    assert notices == []


@pytest.mark.parametrize(
    "wrong_identity",
    [
        {"platform": "twilio_voice"},
        {"account_id": "wrong"},
        {"chat_id": "wrong"},
        {"user_id": "wrong"},
        {"thread_id": "wrong"},
    ],
)
def test_trusted_voice_approval_is_exact_one_use_and_once_only(wrong_identity):
    session_key, notice, result, thread = _start_request()
    approval_id = notice["trusted_approval"]["approval_id"]

    assert approval.resolve_trusted_gateway_approval(
        approval_id, _identity(**wrong_identity), "once"
    ) == 0
    assert approval.resolve_trusted_gateway_approval(
        approval_id, _identity(), "session"
    ) == 0
    assert thread.is_alive()
    assert approval.resolve_trusted_gateway_approval(
        approval_id, _identity(), "once"
    ) == 1
    thread.join(1)
    assert result["approved"] is True
    assert approval.resolve_trusted_gateway_approval(
        approval_id, _identity(), "once"
    ) == 0
    approval.unregister_gateway_notify(session_key)


def test_trusted_voice_approval_binds_arguments_and_restart_fails_closed():
    args = {"command": "before"}
    session_key, notice, result, thread = _start_request(args=args)
    approval_id = notice["trusted_approval"]["approval_id"]
    args["command"] = "after"
    assert approval.resolve_trusted_gateway_approval(
        approval_id, _identity(), "once"
    ) == 1
    thread.join(1)
    assert result["approved"] is False
    assert "changed" in result["message"].lower()

    session_key, _notice, result, thread = _start_request()
    approval.unregister_gateway_notify(session_key)
    thread.join(1)
    assert result["approved"] is False


def test_trusted_voice_approval_rejects_stale_decision():
    session_key, notice, result, thread = _start_request(expires_seconds=1)
    trusted = notice["trusted_approval"]
    assert approval.resolve_trusted_gateway_approval(
        trusted["approval_id"], _identity(), "once", now=trusted["expires_at"] + 1
    ) == 0
    thread.join(2)
    assert result["approved"] is False
    approval.unregister_gateway_notify(session_key)
