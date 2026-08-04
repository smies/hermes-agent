"""Text-debounce batching for the WhatsApp adapter (issue #35301).

WhatsApp delivers rapid multi-message bursts (forwarded batches, paste-splits)
individually.  Without debounce each fragment triggers a separate agent
invocation, wasting tokens and flooding the user with reply fragments.  This
mirrors the Telegram/WeCom/Feishu pattern.

Batch delays are read from ``config.extra`` (config.yaml), not env vars.
"""

import asyncio
from unittest.mock import AsyncMock

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import MessageEvent, MessageType
from plugins.platforms.whatsapp.adapter import WhatsAppAdapter
from gateway.session import SessionSource


def _make_adapter(**extra):
    base = {"session_name": "test"}
    base.update(extra)
    return WhatsAppAdapter(PlatformConfig(enabled=True, extra=base))


def _event(text, *, message_id=None):
    src = SessionSource(
        platform=Platform.WHATSAPP,
        chat_id="chat123",
        chat_type="dm",
        user_id="user1",
        user_name="tester",
        message_id=message_id,
    )
    return MessageEvent(
        text=text,
        message_type=MessageType.TEXT,
        source=src,
        raw_message={"messageId": message_id} if message_id else {},
        message_id=message_id,
    )


def test_batch_delays_overridden_via_config_extra():
    adapter = _make_adapter(
        text_batch_delay_seconds="2.5",
        text_batch_split_delay_seconds=7,
    )
    assert adapter._text_batch_delay_seconds == 2.5
    assert adapter._text_batch_split_delay_seconds == 7.0


def test_invalid_config_value_falls_back_to_default():
    adapter = _make_adapter(
        text_batch_delay_seconds="garbage",
        text_batch_split_delay_seconds=-3,
    )
    assert adapter._text_batch_delay_seconds == 5.0
    assert adapter._text_batch_split_delay_seconds == 10.0


def test_batched_event_retains_final_provider_message_id():
    adapter = _make_adapter(
        text_batch_delay_seconds=0.01,
        text_batch_split_delay_seconds=0.01,
        group_sessions_per_user=True,
    )
    adapter.handle_message = AsyncMock()

    async def _drive():
        adapter._enqueue_text_event(_event("first", message_id="provider-msg-1"))
        adapter._enqueue_text_event(_event("second", message_id="provider-msg-2"))
        await asyncio.sleep(0.05)

    asyncio.run(_drive())

    adapter.handle_message.assert_awaited_once()
    retained = adapter.handle_message.await_args.args[0]
    assert retained.text == "first\nsecond"
    assert retained.message_id == "provider-msg-2"
    assert retained.source.message_id == "provider-msg-2"
    assert retained.raw_message["messageId"] == "provider-msg-2"

