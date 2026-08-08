"""Protected message text must not reach plaintext logs.

Hermes logs a preview of each inbound user message at turn start for
observability. On a messaging surface carrying private family/personal
content (Juno on WhatsApp), that preview wrote real message bodies —
"Show me Lucy's passport" — into ``agent.log`` in the clear.

``security.log_message_text: false`` suppresses the body while keeping the
turn line itself, so operators keep session/model/platform observability
without the content.

These tests patch the module-level flag rather than reloading the module:
``agent.redact`` is imported by many other modules, and reloading it
rebinds objects they already hold, which corrupts unrelated tests.
"""

from __future__ import annotations

import pytest

from agent.redact import message_log_preview
import agent.redact as redact_module


@pytest.fixture
def logging_disabled(monkeypatch):
    monkeypatch.setattr(redact_module, "_LOG_MESSAGE_TEXT", False)


@pytest.fixture
def logging_enabled(monkeypatch):
    monkeypatch.setattr(redact_module, "_LOG_MESSAGE_TEXT", True)


def test_message_text_logged_by_default(logging_enabled):
    """Default is unchanged: existing debugging workflows keep working."""
    assert message_log_preview("Show me Lucy's passport") == "Show me Lucy's passport"


def test_message_text_suppressed_when_disabled(logging_disabled):
    preview = message_log_preview("Show me Lucy's passport")
    assert "passport" not in preview
    assert "Lucy" not in preview
    # The turn is still observable, and the length is a coarse hint only.
    assert "23 chars" in preview


@pytest.mark.parametrize(
    "text",
    [
        "I want you to send me Lucy's passport image as a file",
        "Send me the nacho engagement letter",
        "passport number 123456789",
        "",
    ],
)
def test_suppressed_preview_leaks_nothing_for_any_input(logging_disabled, text):
    preview = message_log_preview(text)
    for token in text.split():
        if len(token) > 3:
            assert token not in preview


def test_non_string_input_is_safe(logging_disabled):
    assert isinstance(message_log_preview(None), str)
    assert isinstance(message_log_preview(42), str)


def test_default_flag_is_enabled():
    """Fail closed on the *behaviour*, not the literal: default must log."""
    assert redact_module._LOG_MESSAGE_TEXT is True
