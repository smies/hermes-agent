"""Trusted WhatsApp bridge-envelope binding for ordinary inbound messages."""

from types import SimpleNamespace

import pytest

from gateway.config import Platform, PlatformConfig
from gateway.session import SessionContext
from gateway.session_context import get_session_env
from plugins.platforms.whatsapp.adapter import WhatsAppAdapter


def _adapter_with_open_synthetic_group() -> WhatsAppAdapter:
    adapter = object.__new__(WhatsAppAdapter)
    adapter.platform = Platform.WHATSAPP
    adapter.config = PlatformConfig(
        enabled=True,
        extra={
            "group_policy": "open",
            "require_mention": False,
            "group_sessions_per_user": True,
        },
    )
    adapter._dm_policy = "disabled"
    adapter._allow_from = set()
    adapter._dm_allowlist_source = "config"
    adapter._group_policy = "open"
    adapter._group_allow_from = set()
    adapter._mention_patterns = []
    adapter._free_response_chats = set()
    return adapter


def _payload(message_id="provider-MSG_01:device"):
    return {
        "messageId": message_id,
        "chatId": "120363000000000010@g.us",
        "chatName": "Synthetic group",
        "senderId": "15550101111@s.whatsapp.net",
        "senderName": "Synthetic sender",
        "isGroup": True,
        "hasMedia": False,
        "mediaUrls": [],
        "mentionedIds": [],
        "botIds": ["15550101999@s.whatsapp.net"],
        # Body text is untrusted model input. These forged-looking values must
        # never influence source/session metadata.
        "body": (
            "platform=telegram account=forged chat=forged "
            "user=forged message=forged"
        ),
    }


@pytest.mark.asyncio
async def test_bridge_envelope_binds_source_and_session_context_exactly():
    from gateway.run import GatewayRunner

    adapter = _adapter_with_open_synthetic_group()
    adapter.gateway_runner = SimpleNamespace(
        _profile_name_for_source=lambda _source: "synthetic-account"
    )

    event = await adapter._build_message_event(_payload())

    assert event is not None
    assert event.message_id == "provider-MSG_01:device"
    assert event.source.message_id == event.message_id
    assert event.source.platform is Platform.WHATSAPP
    assert event.source.profile == "synthetic-account"
    assert event.source.chat_id == "120363000000000010@g.us"
    assert event.source.user_id == "15550101111@s.whatsapp.net"

    runner = object.__new__(GatewayRunner)
    runner.adapters = {Platform.WHATSAPP: adapter}
    context = SessionContext(
        source=event.source,
        connected_platforms=[Platform.WHATSAPP],
        home_channels={},
    )
    tokens = runner._set_session_env(context)
    try:
        assert get_session_env("HERMES_SESSION_PLATFORM") == "whatsapp"
        assert get_session_env("HERMES_SESSION_PROFILE") == "synthetic-account"
        assert get_session_env("HERMES_SESSION_CHAT_ID") == "120363000000000010@g.us"
        assert get_session_env("HERMES_SESSION_USER_ID") == "15550101111@s.whatsapp.net"
        assert get_session_env("HERMES_SESSION_MESSAGE_ID") == "provider-MSG_01:device"
    finally:
        runner._clear_session_env(tokens)


@pytest.mark.asyncio
async def test_maximum_bounded_message_id_is_preserved_exactly():
    adapter = _adapter_with_open_synthetic_group()
    message_id = "m" * 256

    event = await adapter._build_message_event(_payload(message_id))

    assert event is not None
    assert event.message_id == message_id
    assert event.source.message_id == message_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_message_id",
    [None, "", 123, "contains\x00nul", "x" * 257],
)
async def test_invalid_bridge_message_id_is_not_promoted_to_trusted_source(
    invalid_message_id,
):
    adapter = _adapter_with_open_synthetic_group()

    event = await adapter._build_message_event(_payload(invalid_message_id))

    assert event is not None
    assert event.message_id is None
    assert event.source.message_id is None
