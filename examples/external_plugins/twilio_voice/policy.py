"""Low-assurance voice action policy, enforced through Hermes approvals."""

from __future__ import annotations

from collections import OrderedDict
from threading import RLock
from typing import Any


class VoiceActionPolicy:
    def __init__(self, *, mode: str, safe_tools: frozenset[str], destination=None, max_sessions: int = 1024):
        self.mode = mode
        self.safe_tools = safe_tools
        self.max_sessions = max_sessions
        self.destination = destination
        self._sessions: OrderedDict[str, None] = OrderedDict()
        self._lock = RLock()

    def on_session_start(self, *, session_id: str = "", platform: str = "", **_kwargs):
        if platform != "twilio_voice" or not session_id:
            return None
        with self._lock:
            self._sessions[session_id] = None
            self._sessions.move_to_end(session_id)
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)
        return None

    def pre_llm_call(self, *, session_id: str = "", platform: str = "", **_kwargs):
        """Reassert scope on every turn, including durable session resumes."""
        return self.on_session_start(session_id=session_id, platform=platform)

    def pre_tool_call(
        self,
        *,
        tool_name: str,
        args: dict | None = None,
        session_id: str = "",
        tool_call_id: str = "",
        **_kwargs,
    ):
        if not self._is_voice(session_id):
            return None
        if tool_name in self.safe_tools:
            return None
        message = (
            "This request originated from a low-assurance phone voice session. "
            "Externally side-effecting or unclassified tools require approval "
            "through the existing Hermes/Juno authorization path. Voice input "
            "cannot approve its own action."
        )
        if self.mode == "block_external":
            return {"action": "block", "message": "BLOCKED: " + message}
        try:
            from tools.approval import prepare_trusted_voice_approval

            if self.destination is None:
                raise ValueError("trusted destination unavailable")
            prepare_trusted_voice_approval(
                voice_session_id=session_id,
                tool_call_id=tool_call_id,
                tool_name=tool_name,
                args=args or {},
                destination=self.destination.identity(),
                expires_seconds=self.destination.expires_seconds,
            )
        except Exception:
            return {
                "action": "block",
                "message": "BLOCKED: exact trusted non-voice approval correlation is unavailable.",
            }
        return {
            "action": "approve",
            "message": message,
            "rule_key": f"twilio_voice:{tool_name}",
        }

    def pre_gateway_dispatch(self, *, event: Any, **_kwargs):
        source = getattr(event, "source", None)
        platform = getattr(getattr(source, "platform", None), "value", "")
        if platform != "twilio_voice":
            return None
        text = str(getattr(event, "text", "") or "").strip().lower()
        if text.startswith(("/approve", "/deny", "/yolo", "/approvals")):
            return {
                "action": "skip",
                "reason": "voice sessions cannot resolve authorization decisions",
            }
        # Plain yes/no approval interception is only dangerous while an approval
        # is actually pending for this session key.
        if text in {"yes", "approve", "always", "no", "deny"}:
            try:
                from gateway.session import build_session_key
                from tools.approval import has_blocking_approval

                key = build_session_key(source)
                if has_blocking_approval(key):
                    return {
                        "action": "skip",
                        "reason": "voice sessions cannot resolve authorization decisions",
                    }
            except Exception:
                # If the pending-state check fails, do not reinterpret ordinary
                # conversation as an approval command. The approval gate itself
                # remains fail-closed on timeout.
                pass
        return None

    def _is_voice(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self._sessions
