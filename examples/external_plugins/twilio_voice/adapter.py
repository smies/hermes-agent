"""Hermes gateway platform adapter for Twilio ConversationRelay."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Any

from gateway.config import Platform
from gateway.platforms.base import BasePlatformAdapter, MessageEvent, MessageType, SendResult
from gateway.session import build_session_key

from .bridge import CallConnection, VoiceBridge
from .config import VoiceConfig
from .security import caller_subject, valid_sid

logger = logging.getLogger(__name__)


class TwilioVoiceAdapter(BasePlatformAdapter):
    """Inbound-only voice adapter.  It intentionally has no outbound API."""

    supports_async_delivery = False
    REQUIRES_EDIT_FINALIZE = True
    MAX_MESSAGE_LENGTH = 16_000

    def __init__(self, platform_config: Any, *, pin: str | None = None):
        super().__init__(config=platform_config, platform=Platform("twilio_voice"))
        self.voice_config = VoiceConfig.from_platform_config(platform_config)
        self.bridge = VoiceBridge(
            self,
            self.voice_config,
            auth_token=os.environ.get("TWILIO_AUTH_TOKEN", ""),
            account_sid=os.environ.get("TWILIO_ACCOUNT_SID", ""),
            pin=str(pin if pin is not None else os.environ.get("TWILIO_VOICE_PIN", "")),
        )
        self._uvicorn_server = None
        self._server_task: asyncio.Task | None = None

    @property
    def name(self) -> str:
        return "Twilio Voice"

    @property
    def authorization_is_upstream(self) -> bool:
        """Transport signature, exact caller policy, and required PIN authorize intake."""
        return True

    async def connect(self, **_kwargs) -> bool:
        if not self.bridge.auth_token or not valid_sid(self.bridge.account_sid, "AC"):
            self._set_fatal_error("missing_credentials", "Twilio credentials unavailable", retryable=False)
            return False
        pin = self.bridge.pin
        if not pin.isdigit() or not 6 <= len(pin) <= 12:
            self._set_fatal_error(
                "invalid_pin",
                "TWILIO_VOICE_PIN must contain 6 to 12 digits",
                retryable=False,
            )
            return False
        try:
            import uvicorn
        except ImportError:
            self._set_fatal_error("missing_dependency", "uvicorn is required", retryable=False)
            return False
        app = self.bridge.create_app()
        uv_config = uvicorn.Config(
            app,
            host=self.voice_config.bind_host,
            port=self.voice_config.bind_port,
            log_level="warning",
            access_log=False,
            ws_max_size=self.voice_config.max_frame_bytes,
            timeout_keep_alive=5,
            server_header=False,
        )
        self._uvicorn_server = uvicorn.Server(uv_config)
        self._server_task = asyncio.create_task(self._uvicorn_server.serve())
        for _ in range(100):
            if self._uvicorn_server.started:
                break
            if self._server_task.done():
                break
            await asyncio.sleep(0.02)
        if not self._uvicorn_server.started:
            self._set_fatal_error("bind_failed", "voice listener did not start", retryable=True)
            return False
        self.bridge._server_started = True
        self._mark_connected()
        logger.info("Twilio Voice bridge listening on loopback port %d", self.voice_config.bind_port)
        return True

    async def disconnect(self) -> None:
        self._mark_disconnected()
        self.bridge._server_started = False
        for connection in list(self.bridge.connections.values()):
            try:
                await connection.send({"type": "end", "handoffData": '{"reason":"service_shutdown"}'})
            except Exception:
                pass
            await self.bridge._cleanup(connection, "service shutdown")
        if self._uvicorn_server is not None:
            self._uvicorn_server.should_exit = True
        if self._server_task is not None:
            try:
                await asyncio.wait_for(self._server_task, timeout=5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._server_task.cancel()
            self._server_task = None
        await self.cancel_background_tasks()

    def _source(self, connection: CallConnection):
        return self.build_source(
            chat_id=connection.call_sid,
            chat_name="Twilio voice call",
            chat_type="dm",
            user_id=caller_subject(connection.caller),
            user_name="Allowlisted phone caller",
            message_id=connection.session_id,
            role_authorized=True,
        )

    async def receive_prompt(self, connection: CallConnection, prompt: str) -> None:
        event = MessageEvent(
            text=prompt,
            message_type=MessageType.TEXT,
            source=self._source(connection),
            raw_message={"transport": "conversation-relay", "type": "prompt"},
            message_id=f"voice-{uuid.uuid4().hex}",
        )
        await self.handle_message(event)

    def _session_key(self, connection: CallConnection) -> str:
        return build_session_key(
            self._source(connection),
            group_sessions_per_user=self.config.extra.get("group_sessions_per_user", True),
            thread_sessions_per_user=self.config.extra.get("thread_sessions_per_user", False),
        )

    async def interrupt_call(self, connection: CallConnection, *, reason: str) -> None:
        """Best-effort soft interrupt that preserves the cached agent instance."""
        runner = getattr(self, "gateway_runner", None)
        if runner is None:
            return
        try:
            state = runner._peek_session_state(self._session_key(connection))
            agent = state.turn.agent if state is not None else None
            if agent is not None and hasattr(agent, "interrupt"):
                agent.interrupt(reason)
        except Exception:
            logger.debug("Voice turn interrupt could not reach active agent", exc_info=True)

    async def disconnect_call(self, connection: CallConnection, *, reason: str) -> None:
        await self.interrupt_call(connection, reason=reason)
        key = self._session_key(connection)
        try:
            await self.cancel_session_processing(key, discard_pending=True)
        except Exception:
            logger.debug("Voice call task cleanup failed", exc_info=True)

    def supports_draft_streaming(self, chat_type=None, metadata=None) -> bool:
        return True

    async def send_draft(self, chat_id: str, draft_id: int, content: str, metadata=None) -> SendResult:
        stream_id = f"draft-{draft_id}"
        try:
            sent = await self.bridge.send_stream_update(chat_id, stream_id, content, final=False)
            return SendResult(success=sent, message_id=stream_id, error=None if sent else "call unavailable")
        except Exception:
            return SendResult(success=False, error="voice stream unavailable")

    async def send(self, chat_id: str, content: str, reply_to=None, metadata=None) -> SendResult:
        try:
            connection = self.bridge.connections.get(str(chat_id))
            if (
                connection is not None
                and not connection.active_stream_id
                and isinstance(metadata, dict)
                and metadata.get("expect_edits") is True
            ):
                stream_id = f"edit-{uuid.uuid4().hex}"
                sent = await self.bridge.send_stream_update(
                    chat_id, stream_id, content, final=False
                )
                return SendResult(
                    success=sent,
                    message_id=stream_id if sent else None,
                    error=None if sent else "call unavailable",
                )
            sent = await self.bridge.send_final(chat_id, content)
            return SendResult(
                success=sent,
                message_id=f"speech-{uuid.uuid4().hex}",
                error=None if sent else "call unavailable",
            )
        except Exception:
            return SendResult(success=False, error="voice delivery unavailable")

    async def edit_message(self, chat_id: str, message_id: str, content: str, *, finalize: bool = False) -> SendResult:
        try:
            sent = await self.bridge.send_stream_update(
                chat_id, message_id, content, final=finalize
            )
            return SendResult(success=sent, message_id=message_id, error=None if sent else "call unavailable")
        except Exception:
            return SendResult(success=False, error="voice delivery unavailable")

    async def send_typing(self, chat_id: str) -> None:
        return None

    async def send_image(self, chat_id: str, image_url: str, caption: str = "") -> SendResult:
        return SendResult(success=False, error="voice is text-only")

    async def get_chat_info(self, chat_id: str) -> dict[str, Any]:
        return {"name": "Twilio voice call", "type": "dm", "chat_id": chat_id}
