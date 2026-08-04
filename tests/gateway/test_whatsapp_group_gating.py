import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import GatewayConfig, Platform, PlatformConfig, load_gateway_config


def _make_adapter(require_mention=None, mention_patterns=None, free_response_chats=None,
                  dm_policy=None, allow_from=None, group_policy=None, group_allow_from=None,
                  group_sessions_per_user=None):
    from plugins.platforms.whatsapp.adapter import WhatsAppAdapter

    extra = {}
    if require_mention is not None:
        extra["require_mention"] = require_mention
    if mention_patterns is not None:
        extra["mention_patterns"] = mention_patterns
    if free_response_chats is not None:
        extra["free_response_chats"] = free_response_chats
    if dm_policy is not None:
        extra["dm_policy"] = dm_policy
    if allow_from is not None:
        extra["allow_from"] = allow_from
    if group_policy is not None:
        extra["group_policy"] = group_policy
    if group_allow_from is not None:
        extra["group_allow_from"] = group_allow_from
    if group_sessions_per_user is not None:
        extra["group_sessions_per_user"] = group_sessions_per_user

    adapter = object.__new__(WhatsAppAdapter)
    adapter.platform = Platform.WHATSAPP
    adapter.config = PlatformConfig(enabled=True, extra=extra)
    adapter._message_handler = AsyncMock()
    adapter._dm_policy = str(extra.get("dm_policy", "pairing")).strip().lower()
    adapter._allow_from = WhatsAppAdapter._coerce_allow_list(extra.get("allow_from"))
    adapter._dm_allowlist_source = "config" if allow_from is not None else None
    adapter._group_policy = str(extra.get("group_policy", "pairing")).strip().lower()
    adapter._group_allow_from = WhatsAppAdapter._coerce_allow_list(extra.get("group_allow_from"))
    adapter._mention_patterns = adapter._compile_mention_patterns()
    adapter._free_response_chats = adapter._whatsapp_free_response_chats()
    return adapter


def _group_message(body="hello", **overrides):
    data = {
        "isGroup": True,
        "body": body,
        "chatId": "120363001234567890@g.us",
        "mentionedIds": [],
        "botIds": ["15551230000@s.whatsapp.net", "15551230000@lid"],
        "quotedParticipant": "",
    }
    data.update(overrides)
    return data


def _dm_message(body="hello", **overrides):
    data = {
        "isGroup": False,
        "body": body,
        "senderId": "6281234567890@s.whatsapp.net",
        "from": "6281234567890@s.whatsapp.net",
        "botIds": [],
        "mentionedIds": [],
    }
    data.update(overrides)
    return data


# --- Existing tests (unchanged logic, updated helper) ---


def test_group_messages_can_require_direct_trigger_via_config():
    adapter = _make_adapter(require_mention=True, group_policy="open")

    assert adapter._should_process_message(_group_message("hello everyone")) is False
    assert adapter._should_process_message(
        _group_message(
            "hi there",
            mentionedIds=["15551230000@s.whatsapp.net"],
        )
    ) is True
    assert adapter._should_process_message(
        _group_message(
            "replying",
            quotedParticipant="15551230000@lid",
        )
    ) is True
    assert adapter._should_process_message(_group_message("/status")) is True


def test_regex_mention_patterns_allow_custom_wake_words():
    adapter = _make_adapter(
        require_mention=True,
        mention_patterns=[r"^\s*chompy\b"],
        group_policy="open",
    )

    assert adapter._should_process_message(_group_message("chompy status")) is True
    assert adapter._should_process_message(_group_message("   chompy help")) is True
    assert adapter._should_process_message(_group_message("hey chompy")) is False


def test_invalid_regex_patterns_are_ignored():
    adapter = _make_adapter(
        require_mention=True,
        mention_patterns=[r"(", r"^\s*chompy\b"],
        group_policy="open",
    )

    assert adapter._should_process_message(_group_message("chompy status")) is True
    assert adapter._should_process_message(_group_message("hello everyone")) is False


def test_free_response_chats_bypass_mention_gating():
    adapter = _make_adapter(
        require_mention=True,
        free_response_chats=["120363001234567890@g.us"],
        group_policy="open",
    )

    assert adapter._should_process_message(_group_message("hello everyone")) is True


def test_free_response_chats_does_not_bypass_other_groups():
    adapter = _make_adapter(
        require_mention=True,
        free_response_chats=["999999999999@g.us"],
        group_policy="open",
    )

    assert adapter._should_process_message(_group_message("hello everyone")) is False


def test_mention_stripping_removes_bot_phone_from_body():
    adapter = _make_adapter(require_mention=True)

    data = _group_message("@15551230000 what is the weather?")
    cleaned = adapter._clean_bot_mention_text(data["body"], data)
    assert "15551230000" not in cleaned
    assert "weather" in cleaned


# --- New dm_policy tests ---


def test_dm_policy_disabled_still_allows_groups():
    adapter = _make_adapter(
        dm_policy="disabled",
        require_mention=False,
        group_policy="open",
    )

    assert adapter._should_process_message(_group_message("hello")) is True


# --- Sender + group double-gate regression ---


_TRUSTED_SENDER = "15550101001@s.whatsapp.net"
_TRUSTED_GROUP = "120363000000000001@g.us"
_BOT_ID = "15550101999@s.whatsapp.net"


def _trusted_group_payload(**overrides):
    payload = _group_message(
        body="ordinary synthetic group message",
        chatId=_TRUSTED_GROUP,
        senderId=_TRUSTED_SENDER,
        senderName="Synthetic sender",
        chatName="Synthetic group",
        botIds=[_BOT_ID, "15550101999@lid"],
        messageId="provider-message-001",
        hasMedia=False,
        mediaUrls=[],
    )
    payload.update(overrides)
    return payload


def _make_authorization_runner(adapter):
    from gateway.run import GatewayRunner

    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig(platforms={Platform.WHATSAPP: adapter.config})
    runner.adapters = {Platform.WHATSAPP: adapter}
    runner.pairing_store = MagicMock()
    runner.pairing_store.is_approved.return_value = False
    adapter.gateway_runner = runner
    return runner


async def _deliver_through_double_gate(adapter, runner, payload, agent_turn):
    """Exercise the real adapter intake and gateway sender authorization gates."""
    event = await adapter._build_message_event(payload)
    if event is not None and runner._is_user_authorized(event.source):
        await agent_turn(event)
    return event


@pytest.mark.asyncio
async def test_whatsapp_group_ingress_requires_exact_sender_and_group(
    monkeypatch, tmp_path
):
    """Only the configured sender in the configured group reaches an agent turn."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "synthetic-hermes"))
    monkeypatch.setenv("WHATSAPP_ALLOWED_USERS", _TRUSTED_SENDER)
    for name in (
        "GATEWAY_ALLOWED_USERS",
        "GATEWAY_ALLOW_ALL_USERS",
        "WHATSAPP_ALLOW_ALL_USERS",
    ):
        monkeypatch.delenv(name, raising=False)

    adapter = _make_adapter(
        dm_policy="disabled",
        allow_from=[_TRUSTED_SENDER],
        group_policy="allowlist",
        group_allow_from=[_TRUSTED_GROUP],
        require_mention=True,
        free_response_chats=[_TRUSTED_GROUP],
        group_sessions_per_user=True,
    )
    runner = _make_authorization_runner(adapter)
    agent_turn = AsyncMock()

    accepted = await _deliver_through_double_gate(
        adapter, runner, _trusted_group_payload(), agent_turn
    )
    assert accepted is not None
    agent_turn.assert_awaited_once_with(accepted)

    other_sender_event = await adapter._build_message_event(
        _trusted_group_payload(senderId="15550101002@s.whatsapp.net")
    )
    assert other_sender_event is not None
    assert adapter._text_batch_key(accepted) != adapter._text_batch_key(other_sender_event)

    rejected_payloads = [
        # Allowed group, wrong actual sender.
        _trusted_group_payload(senderId="15550101002@s.whatsapp.net"),
        # Allowed sender, wrong group.
        _trusted_group_payload(chatId="120363000000000002@g.us"),
        # DMs remain disabled even for the allowlisted sender.
        _dm_message(
            senderId=_TRUSTED_SENDER,
            chatId=_TRUSTED_SENDER,
            messageId="provider-message-dm",
            hasMedia=False,
            mediaUrls=[],
        ),
        # Malformed, unrelated LID, and unrelated PN aliases have no mapping
        # in the isolated synthetic Hermes home and cannot match the sender.
        _trusted_group_payload(senderId="../../15550101001@s.whatsapp.net"),
        _trusted_group_payload(senderId="777000000000001@lid"),
        _trusted_group_payload(senderId="15550101003@s.whatsapp.net"),
        # Quoted authorship is reply context, never the current sender's
        # authorization identity.
        _trusted_group_payload(
            senderId="15550101004@s.whatsapp.net",
            hasQuotedMessage=True,
            quotedParticipant=_TRUSTED_SENDER,
            quotedMessageId="quoted-provider-message",
        ),
    ]

    for payload in rejected_payloads:
        await _deliver_through_double_gate(adapter, runner, payload, agent_turn)

    assert agent_turn.await_count == 1


# --- New group_policy tests ---


# --- Config bridging tests ---

def test_config_bridges_whatsapp_dm_and_group_policy(monkeypatch, tmp_path):
    hermes_home = tmp_path / ".hermes"
    hermes_home.mkdir()
    (hermes_home / "config.yaml").write_text(
        "whatsapp:\n"
        "  dm_policy: disabled\n"
        "  group_policy: allowlist\n"
        "  group_allow_from:\n"
        "    - \"120363001234567890@g.us\"\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.delenv("WHATSAPP_DM_POLICY", raising=False)
    monkeypatch.delenv("WHATSAPP_GROUP_POLICY", raising=False)
    monkeypatch.delenv("WHATSAPP_GROUP_ALLOWED_USERS", raising=False)

    config = load_gateway_config()

    assert config is not None
    assert config.platforms[Platform.WHATSAPP].extra["dm_policy"] == "disabled"
    assert config.platforms[Platform.WHATSAPP].extra["group_policy"] == "allowlist"
    assert config.platforms[Platform.WHATSAPP].extra["group_allow_from"] == ["120363001234567890@g.us"]
    assert __import__("os").environ["WHATSAPP_DM_POLICY"] == "disabled"
    assert __import__("os").environ["WHATSAPP_GROUP_POLICY"] == "allowlist"
    assert __import__("os").environ["WHATSAPP_GROUP_ALLOWED_USERS"] == "120363001234567890@g.us"


# --- Broadcast / status / newsletter pseudo-chats are always dropped ---


def test_status_broadcast_chats_are_always_dropped():
    """Felipe's gateway.log showed the agent replying to status@broadcast
    (a contact's WhatsApp Story update). These pseudo-chats aren't real
    conversations and the adapter must drop them regardless of dm_policy.
    """

    # Even on the most permissive config — open DMs, no allowlist — Stories
    # and Channel posts must not reach the agent.
    adapter = _make_adapter(dm_policy="open")

    # Classic Story update — what Felipe was seeing in production.
    status_msg = _dm_message(
        body="[video received]",
        chatId="status@broadcast",
        senderId="34612345678@s.whatsapp.net",
    )
    assert adapter._should_process_message(status_msg) is False

    # Channel / Newsletter broadcast posts.
    newsletter_msg = _dm_message(
        body="check out our latest post",
        chatId="120363999999999999@newsletter",
        senderId="120363999999999999@newsletter",
    )
    assert adapter._should_process_message(newsletter_msg) is False


def test_broadcast_filter_runs_before_allowlist():
    """A status@broadcast message from an allowlisted sender still drops —
    we never want to reply to Stories, even from authorized contacts.
    """
    adapter = _make_adapter(
        dm_policy="allowlist",
        allow_from=["34612345678@s.whatsapp.net"],
    )

    msg = _dm_message(
        body="[image received]",
        chatId="status@broadcast",
        senderId="34612345678@s.whatsapp.net",
    )
    assert adapter._should_process_message(msg) is False
