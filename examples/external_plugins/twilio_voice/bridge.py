"""Fail-closed HTTP and ConversationRelay WebSocket application."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs
from xml.sax.saxutils import quoteattr

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse, Response

from .config import VoiceConfig
from .security import (
    PendingCall,
    PendingCallStore,
    allowlisted,
    http_to_wss,
    normalize_phone,
    public_endpoint,
    redact_phone,
    valid_sid,
    validate_twilio_signature,
)
from .speech import StreamingSpeech, phone_friendly_text

logger = logging.getLogger(__name__)

VOICE_PATH = "/twilio/voice"
PIN_PATH = "/twilio/voice/pin"
WS_PATH = "/twilio/voice/relay"


def _xml_response(body: str) -> str:
    return '<?xml version="1.0" encoding="UTF-8"?><Response>' + body + "</Response>"


def _reject_twiml() -> str:
    return _xml_response('<Reject reason="rejected"/>')


@dataclass
class CallConnection:
    websocket: Any
    call_sid: str
    caller: str
    called: str
    session_id: str
    started_at: float
    last_activity: float
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    speech: dict[str, StreamingSpeech] = field(default_factory=dict)
    active_stream_id: str | None = None
    suppress_output: bool = False
    closed: bool = False

    async def send(self, payload: dict[str, Any]) -> None:
        if self.closed:
            raise ConnectionError("call is closed")
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        async with self.send_lock:
            sender = getattr(self.websocket, "send_text", None)
            if callable(sender):
                await sender(encoded)
            else:
                await self.websocket.send_json(payload)


class VoiceBridge:
    """Protocol server owned by :class:`TwilioVoiceAdapter`."""

    def __init__(
        self,
        adapter: Any,
        config: VoiceConfig,
        auth_token: str,
        account_sid: str,
        *,
        pin: str,
    ):
        self.adapter = adapter
        self.config = config
        self.auth_token = str(auth_token or "")
        self.account_sid = str(account_sid or "")
        pin = str(pin or "")
        if not pin.isdigit() or not 6 <= len(pin) <= 12:
            raise ValueError("voice PIN must contain 6 to 12 digits")
        self._pin = pin
        self.pending = PendingCallStore(
            ttl_seconds=max(30, config.setup_timeout_seconds * 4),
            max_entries=max(8, config.max_concurrent_calls * 4),
        )
        self.connections: dict[str, CallConnection] = {}
        self._connection_lock = asyncio.Lock()
        self._pin_challenges: dict[str, dict[str, Any]] = {}
        self._max_pin_challenges = max(8, config.max_concurrent_calls * 4)
        self._server_started = False

    @property
    def pin(self) -> str:
        return self._pin

    def public_base_url(self) -> str:
        return self.config.current_public_base_url()

    def signature_url(self, path: str, *, websocket: bool = False) -> str:
        base = self.public_base_url()
        return http_to_wss(base, path) if websocket else public_endpoint(base, path)

    def ready(self) -> bool:
        try:
            self.signature_url(VOICE_PATH)
            self.signature_url(WS_PATH, websocket=True)
        except ValueError:
            return False
        return bool(
            self._server_started
            and self.auth_token
            and valid_sid(self.account_sid, "AC")
            and self.config.allowed_callers
            and self.pin
            and self.adapter._message_handler is not None
        )

    def create_app(self):
        app = FastAPI(
            title="Hermes Twilio Voice Bridge",
            docs_url=None,
            redoc_url=None,
            openapi_url=None,
        )

        @app.get("/healthz")
        async def healthz():
            return {"status": "ok"}

        @app.get("/readyz")
        async def readyz():
            return JSONResponse(
                {"status": "ready" if self.ready() else "not_ready"},
                status_code=200 if self.ready() else 503,
            )

        @app.post(VOICE_PATH)
        async def inbound_voice(request: Request):
            status, body = await self.handle_voice_http(request, pin_callback=False)
            return Response(body, status_code=status, media_type="application/xml")

        @app.post(PIN_PATH)
        async def inbound_pin(request: Request):
            status, body = await self.handle_voice_http(request, pin_callback=True)
            return Response(body, status_code=status, media_type="application/xml")

        @app.websocket(WS_PATH)
        async def relay(websocket: WebSocket):
            await self.handle_websocket(websocket)

        return app

    async def _read_signed_form(self, request: Any, path: str) -> tuple[int, dict[str, list[str]]]:
        content_type = str(request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            return 415, {}
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.config.max_frame_bytes:
                    return 413, {}
            except ValueError:
                return 400, {}
        raw = await request.body()
        if len(raw) > self.config.max_frame_bytes:
            return 413, {}
        try:
            form = parse_qs(
                raw.decode("utf-8"),
                keep_blank_values=True,
                strict_parsing=False,
                max_num_fields=64,
            )
        except (UnicodeDecodeError, ValueError):
            return 400, {}
        signature = str(request.headers.get("x-twilio-signature") or "")
        params: dict[str, object] = {
            key: values if len(values) > 1 else values[0]
            for key, values in form.items()
        }
        try:
            url = self.signature_url(path)
        except ValueError:
            return 503, {}
        if not validate_twilio_signature(self.auth_token, url, params, signature):
            logger.warning("Twilio voice HTTP request rejected: invalid signature")
            return 403, {}
        return 200, form

    async def handle_voice_http(self, request: Any, *, pin_callback: bool) -> tuple[int, str]:
        path = PIN_PATH if pin_callback else VOICE_PATH
        status, form = await self._read_signed_form(request, path)
        if status != 200:
            return status, _reject_twiml()

        first = lambda key: str((form.get(key) or [""])[0]).strip()
        account_sid = first("AccountSid")
        call_sid = first("CallSid")
        caller = normalize_phone(first("From"))
        called = normalize_phone(first("To"))
        direction = first("Direction").lower()
        if (
            not hmac.compare_digest(account_sid, self.account_sid)
            or not valid_sid(call_sid, "CA")
            or direction not in {"inbound", "inbound-api"}
            or not caller
            or not called
        ):
            logger.warning("Twilio voice request rejected: invalid call binding")
            return 403, _reject_twiml()
        if not allowlisted(caller, self.config.allowed_callers):
            logger.warning("Twilio voice request rejected: caller not allowlisted (%s)", redact_phone(caller))
            return 403, _reject_twiml()

        if self.pin and not pin_callback:
            self._expire_pin_challenges()
            if len(self._pin_challenges) >= self._max_pin_challenges:
                oldest_sid = min(
                    self._pin_challenges,
                    key=lambda sid: self._pin_challenges[sid]["created_at"],
                )
                self._pin_challenges.pop(oldest_sid, None)
            self._pin_challenges[call_sid] = {
                "account_sid": account_sid,
                "caller": caller,
                "called": called,
                "attempts": 0,
                "created_at": time.monotonic(),
            }
            return 200, self._pin_gather_twiml(retry=False)

        pin_verified = not bool(self.pin)
        if pin_callback:
            if not self.pin:
                return 403, _reject_twiml()
            self._expire_pin_challenges()
            challenge = self._pin_challenges.get(call_sid)
            if challenge is None or not (
                hmac.compare_digest(account_sid, challenge["account_sid"])
                and hmac.compare_digest(caller, challenge["caller"])
                and hmac.compare_digest(called, challenge["called"])
            ):
                return 403, _reject_twiml()
            attempts = int(challenge["attempts"]) + 1
            challenge["attempts"] = attempts
            digits = first("Digits")
            if not hmac.compare_digest(digits.encode(), self.pin.encode()):
                if attempts >= self.config.pin_max_attempts:
                    self._pin_challenges.pop(call_sid, None)
                    logger.warning("Twilio voice PIN rejected after maximum attempts (%s)", redact_phone(caller))
                    return 200, _xml_response("<Say>Authentication failed.</Say><Hangup/>")
                return 200, self._pin_gather_twiml(retry=True)
            pin_verified = True
            self._pin_challenges.pop(call_sid, None)

        entry = self.pending.create(
            call_sid=call_sid,
            account_sid=account_sid,
            caller=caller,
            called=called,
            pin_verified=pin_verified,
        )
        return 200, self._relay_twiml(entry)

    def _expire_pin_challenges(self) -> None:
        cutoff = time.monotonic() - max(30, self.config.setup_timeout_seconds * 4)
        for call_sid, challenge in list(self._pin_challenges.items()):
            if float(challenge.get("created_at", 0)) < cutoff:
                self._pin_challenges.pop(call_sid, None)

    def _pin_gather_twiml(self, *, retry: bool) -> str:
        action = quoteattr(self.signature_url(PIN_PATH))
        words = "Incorrect PIN. Try again." if retry else "Enter your voice access PIN."
        gather = (
            f'<Gather action={action} method="POST" input="dtmf" '
            f'numDigits="{len(self.pin)}" timeout="8">'
            f"<Say>{words}</Say></Gather><Hangup/>"
        )
        return _xml_response(gather)

    def _relay_twiml(self, entry: PendingCall) -> str:
        attrs = {
            "url": self.signature_url(WS_PATH, websocket=True),
            "welcomeGreeting": self.config.greeting,
            "welcomeGreetingInterruptible": "any",
            "language": self.config.language,
            "ttsProvider": self.config.tts_provider,
            "transcriptionProvider": self.config.transcription_provider,
            "speechModel": self.config.speech_model,
            "interruptible": "any",
            "preemptible": "true",
            "dtmfDetection": "true",
            "reportInputDuringAgentSpeech": "any",
        }
        if self.config.voice:
            attrs["voice"] = self.config.voice
        rendered = " ".join(f"{key}={quoteattr(value)}" for key, value in attrs.items())
        relay = (
            f"<Connect><ConversationRelay {rendered}>"
            f'<Parameter name="nonce" value={quoteattr(entry.nonce)}/>'
            "</ConversationRelay></Connect><Hangup/>"
        )
        return _xml_response(relay)

    async def handle_websocket(self, websocket: Any) -> None:
        signature = str(websocket.headers.get("x-twilio-signature") or "")
        try:
            url = self.signature_url(WS_PATH, websocket=True)
        except ValueError:
            await websocket.close(code=1008, reason="not ready")
            return
        if not validate_twilio_signature(self.auth_token, url, None, signature):
            logger.warning("ConversationRelay WebSocket rejected: invalid signature")
            await websocket.close(code=1008, reason="invalid signature")
            return

        async with self._connection_lock:
            if len(self.connections) >= self.config.max_concurrent_calls:
                await websocket.close(code=1013, reason="capacity")
                return
        await websocket.accept()
        connection: CallConnection | None = None
        try:
            setup = await asyncio.wait_for(
                self._receive_json(websocket), timeout=self.config.setup_timeout_seconds
            )
            connection = await self._accept_setup(websocket, setup)
            if connection is None:
                await websocket.close(code=1008, reason="invalid setup")
                return
            while True:
                elapsed = time.monotonic() - connection.started_at
                if elapsed >= self.config.max_duration_seconds:
                    await connection.send({"type": "end", "handoffData": '{"reason":"duration_limit"}'})
                    await websocket.close(code=1000, reason="duration limit")
                    return
                timeout = min(
                    self.config.idle_timeout_seconds,
                    self.config.max_duration_seconds - elapsed,
                )
                message = await asyncio.wait_for(self._receive_json(websocket), timeout=timeout)
                connection.last_activity = time.monotonic()
                should_close = await self._handle_frame(connection, message)
                if should_close:
                    await websocket.close(code=1000, reason="session ended")
                    return
        except asyncio.TimeoutError:
            if connection is not None:
                try:
                    await connection.send({"type": "end", "handoffData": '{"reason":"timeout"}'})
                except Exception:
                    pass
            try:
                await websocket.close(code=1000, reason="timeout")
            except Exception:
                pass
        except (ValueError, json.JSONDecodeError):
            try:
                await websocket.close(code=1007, reason="malformed frame")
            except Exception:
                pass
        except Exception as exc:
            # Starlette raises WebSocketDisconnect here; do not log payloads.
            logger.debug("ConversationRelay connection ended: %s", type(exc).__name__)
        finally:
            if connection is not None:
                await self._cleanup(connection, "disconnect")

    async def _receive_json(self, websocket: Any) -> dict[str, Any]:
        raw = await websocket.receive_text()
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > self.config.max_frame_bytes:
            raise ValueError("oversized frame")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("frame must be an object")
        return value

    async def _accept_setup(self, websocket: Any, message: dict[str, Any]) -> CallConnection | None:
        if message.get("type") != "setup":
            return None
        nonce = str((message.get("customParameters") or {}).get("nonce") or "")
        entry = self.pending.consume(nonce)
        if entry is None:
            return None
        values = {
            "session": str(message.get("sessionId") or ""),
            "account": str(message.get("accountSid") or ""),
            "call": str(message.get("callSid") or ""),
            "caller": normalize_phone(str(message.get("from") or "")),
            "called": normalize_phone(str(message.get("to") or "")),
            "direction": str(message.get("direction") or "").lower(),
        }
        valid = (
            valid_sid(values["session"], "VX")
            and hmac.compare_digest(values["account"], entry.account_sid)
            and hmac.compare_digest(values["call"], entry.call_sid)
            and hmac.compare_digest(values["caller"], entry.caller)
            and hmac.compare_digest(values["called"], entry.called)
            and values["direction"] == "inbound"
            and (entry.pin_verified or not self.pin)
            and allowlisted(values["caller"], self.config.allowed_callers)
        )
        if not valid:
            return None
        connection = CallConnection(
            websocket=websocket,
            call_sid=entry.call_sid,
            caller=entry.caller,
            called=entry.called,
            session_id=values["session"],
            started_at=time.monotonic(),
            last_activity=time.monotonic(),
        )
        async with self._connection_lock:
            if entry.call_sid in self.connections or len(self.connections) >= self.config.max_concurrent_calls:
                return None
            self.connections[entry.call_sid] = connection
        logger.info("ConversationRelay call accepted (%s)", redact_phone(entry.caller))
        return connection

    async def _handle_frame(self, connection: CallConnection, message: dict[str, Any]) -> bool:
        kind = str(message.get("type") or "")
        if kind == "prompt":
            prompt = str(message.get("voicePrompt") or "")
            if len(prompt) > self.config.max_prompt_chars:
                raise ValueError("oversized prompt")
            if message.get("last") is not True:
                return False
            prompt = prompt.strip()
            if not prompt:
                return False
            connection.suppress_output = False
            await self.adapter.receive_prompt(connection, prompt)
            return False
        if kind == "interrupt":
            connection.suppress_output = True
            connection.speech.clear()
            connection.active_stream_id = None
            await self.adapter.interrupt_call(connection, reason="caller barge-in")
            return False
        if kind == "dtmf":
            digit = str(message.get("digit") or "")
            if digit == self.config.hangup_digit:
                return True
            return False
        if kind in {"disconnect", "end"}:
            return True
        if kind == "error":
            logger.warning("ConversationRelay reported a protocol error")
            return True
        # Unknown client frames are rejected rather than reflected to the agent.
        raise ValueError("unknown frame type")

    async def _cleanup(self, connection: CallConnection, reason: str) -> None:
        if connection.closed:
            return
        connection.closed = True
        connection.speech.clear()
        async with self._connection_lock:
            if self.connections.get(connection.call_sid) is connection:
                self.connections.pop(connection.call_sid, None)
        self.pending.discard_call(connection.call_sid)
        self._pin_challenges.pop(connection.call_sid, None)
        await self.adapter.disconnect_call(connection, reason=reason)

    async def send_stream_update(
        self,
        call_sid: str,
        stream_id: str,
        accumulated: str,
        *,
        final: bool,
    ) -> bool:
        connection = self.connections.get(str(call_sid))
        if connection is None or connection.closed or connection.suppress_output:
            return False
        speech = connection.speech.setdefault(str(stream_id), StreamingSpeech())
        connection.active_stream_id = str(stream_id)
        chunks = speech.update(accumulated, final=final)
        if final and not chunks:
            chunks = [" "]
        for index, token in enumerate(chunks):
            is_last = final and index == len(chunks) - 1
            await connection.send(
                {
                    "type": "text",
                    "token": token,
                    "last": is_last,
                    "interruptible": True,
                    "preemptible": True,
                    "lang": self.config.language,
                }
            )
        if final:
            connection.speech.pop(str(stream_id), None)
            if connection.active_stream_id == str(stream_id):
                connection.active_stream_id = None
        return True

    async def send_final(self, call_sid: str, content: str) -> bool:
        connection = self.connections.get(str(call_sid))
        if connection is None or connection.closed or connection.suppress_output:
            return False
        if connection.active_stream_id:
            return await self.send_stream_update(
                call_sid,
                connection.active_stream_id,
                content,
                final=True,
            )
        text = phone_friendly_text(content)
        await connection.send(
            {
                "type": "text",
                "token": text or " ",
                "last": True,
                "interruptible": True,
                "preemptible": True,
                "lang": self.config.language,
            }
        )
        return True
