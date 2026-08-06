"""Strict behavioral configuration for the voice platform plugin."""

from __future__ import annotations

import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .security import normalize_phone


def _bounded_int(raw: Any, *, name: str, minimum: int, maximum: int, default: int) -> int:
    if raw in (None, ""):
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class TrustedApprovalDestination:
    platform: str
    account_id: str
    chat_id: str
    user_id: str
    thread_id: str
    expires_seconds: int

    def identity(self) -> dict[str, str]:
        return {
            "platform": self.platform,
            "account_id": self.account_id,
            "chat_id": self.chat_id,
            "user_id": self.user_id,
            "thread_id": self.thread_id,
        }


@dataclass(frozen=True)
class VoiceConfig:
    bind_host: str
    bind_port: int
    public_base_url: str
    runtime_public_url_file: Path | None
    allowed_callers: tuple[str, ...]
    greeting: str
    language: str
    voice: str
    tts_provider: str
    transcription_provider: str
    speech_model: str
    max_duration_seconds: int
    idle_timeout_seconds: int
    setup_timeout_seconds: int
    max_frame_bytes: int
    max_prompt_chars: int
    max_concurrent_calls: int
    pin_max_attempts: int
    action_policy: str
    safe_tools: frozenset[str]
    hangup_digit: str
    trusted_approval_destination: TrustedApprovalDestination

    @classmethod
    def from_platform_config(cls, platform_config: Any) -> "VoiceConfig":
        extra = dict(getattr(platform_config, "extra", {}) or {})
        allowed_raw = extra.get("allowed_callers") or []
        if isinstance(allowed_raw, str):
            allowed_raw = [item.strip() for item in allowed_raw.split(",")]
        if not isinstance(allowed_raw, list):
            raise ValueError("allowed_callers must be a list of E.164 strings")
        allowed: list[str] = []
        for item in allowed_raw:
            normalized = normalize_phone(str(item))
            if not normalized or str(item) != normalized:
                raise ValueError("allowed_callers must contain exactly one canonical E.164 caller")
            allowed.append(normalized)
        if len(allowed) != 1:
            raise ValueError("allowed_callers must contain exactly one canonical E.164 caller")

        runtime_path = str(extra.get("runtime_public_url_file") or "").strip()
        action_policy = str(extra.get("action_policy") or "approval_required").strip()
        if action_policy not in {"approval_required", "block_external"}:
            raise ValueError("action_policy must be approval_required or block_external")
        destination_raw = extra.get("trusted_approval_destination")
        if not isinstance(destination_raw, dict):
            raise ValueError("trusted_approval_destination must be an explicit mapping")
        destination_values = {
            key: str(destination_raw.get(key) or "").strip()
            for key in ("platform", "account_id", "chat_id", "user_id", "thread_id")
        }
        if destination_values["platform"] == "twilio_voice" or any(
            not value for value in destination_values.values()
        ):
            raise ValueError("trusted_approval_destination must identify an exact non-voice owner route")
        trusted_destination = TrustedApprovalDestination(
            **destination_values,
            expires_seconds=_bounded_int(
                destination_raw.get("expires_seconds"),
                name="trusted_approval_destination.expires_seconds",
                minimum=15,
                maximum=600,
                default=120,
            ),
        )
        safe_tools = extra.get("safe_tools") or [
            "clarify",
            "web_search",
            "web_extract",
        ]
        if not isinstance(safe_tools, list) or not all(isinstance(x, str) for x in safe_tools):
            raise ValueError("safe_tools must be a list of tool names")

        hangup_digit = str(extra.get("hangup_digit") or "#")
        if hangup_digit not in set("0123456789*#"):
            raise ValueError("hangup_digit must be one DTMF digit")

        bind_host = str(extra.get("bind_host") or "127.0.0.1").strip()
        if bind_host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("bind_host must be a loopback address")

        return cls(
            bind_host=bind_host,
            bind_port=_bounded_int(
                extra.get("bind_port"),
                name="bind_port",
                minimum=1024,
                maximum=65535,
                default=8091,
            ),
            public_base_url=str(extra.get("public_base_url") or "").rstrip("/"),
            runtime_public_url_file=Path(runtime_path).expanduser() if runtime_path else None,
            allowed_callers=tuple(allowed),
            greeting=str(extra.get("greeting") or "Hello. You are securely connected to Hermes."),
            language=str(extra.get("language") or "en-GB"),
            voice=str(extra.get("voice") or ""),
            tts_provider=str(extra.get("tts_provider") or "Google"),
            transcription_provider=str(extra.get("transcription_provider") or "Deepgram"),
            speech_model=str(extra.get("speech_model") or "nova-3-general"),
            max_duration_seconds=_bounded_int(
                extra.get("max_duration_seconds"),
                name="max_duration_seconds",
                minimum=30,
                maximum=3600,
                default=900,
            ),
            idle_timeout_seconds=_bounded_int(
                extra.get("idle_timeout_seconds"),
                name="idle_timeout_seconds",
                minimum=10,
                maximum=600,
                default=90,
            ),
            setup_timeout_seconds=_bounded_int(
                extra.get("setup_timeout_seconds"),
                name="setup_timeout_seconds",
                minimum=2,
                maximum=30,
                default=8,
            ),
            max_frame_bytes=_bounded_int(
                extra.get("max_frame_bytes"),
                name="max_frame_bytes",
                minimum=1024,
                maximum=65536,
                default=16384,
            ),
            max_prompt_chars=_bounded_int(
                extra.get("max_prompt_chars"),
                name="max_prompt_chars",
                minimum=64,
                maximum=8192,
                default=4096,
            ),
            max_concurrent_calls=_bounded_int(
                extra.get("max_concurrent_calls"),
                name="max_concurrent_calls",
                minimum=1,
                maximum=16,
                default=2,
            ),
            pin_max_attempts=_bounded_int(
                extra.get("pin_max_attempts"),
                name="pin_max_attempts",
                minimum=1,
                maximum=5,
                default=3,
            ),
            action_policy=action_policy,
            safe_tools=frozenset(item.strip() for item in safe_tools if item.strip()),
            hangup_digit=hangup_digit,
            trusted_approval_destination=trusted_destination,
        )

    def current_public_base_url(self) -> str:
        if self.runtime_public_url_file:
            try:
                info = self.runtime_public_url_file.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise ValueError("runtime public URL state is not a regular file")
                if info.st_mode & 0o077:
                    raise ValueError("runtime public URL state is not owner-only")
                payload = json.loads(self.runtime_public_url_file.read_text(encoding="utf-8"))
                value = str(payload.get("public_base_url") or "").rstrip("/")
                if value:
                    return value
            except (OSError, ValueError, TypeError):
                pass
        return self.public_base_url
