from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from twilio_voice import validate_config
from twilio_voice.config import VoiceConfig


CALLER = "+442000000001"


def test_plugin_installer_masks_every_required_secret():
    manifest_path = Path(__file__).resolve().parents[1] / "plugin.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))

    required = {entry["name"]: entry for entry in manifest["requires_env"]}
    assert required["TWILIO_ACCOUNT_SID"]["secret"] is True
    assert required["TWILIO_AUTH_TOKEN"]["secret"] is True
    assert required["TWILIO_VOICE_PIN"]["secret"] is True


def platform_config(allowed_callers):
    return SimpleNamespace(
        extra={
            "public_base_url": "https://voice.example.test",
            "allowed_callers": allowed_callers,
            "trusted_approval_destination": {
                "platform": "mattermost",
                "account_id": "reviewed-account",
                "chat_id": "reviewed-channel",
                "user_id": "reviewed-owner",
                "thread_id": "reviewed-thread",
            },
        }
    )


@pytest.mark.parametrize(
    "callers",
    [
        [],
        [CALLER, "+442000000002"],
        ["not-e164"],
        [CALLER, CALLER],
    ],
)
def test_startup_requires_exactly_one_canonical_e164_caller(callers):
    with pytest.raises(ValueError, match="exactly one canonical E.164"):
        VoiceConfig.from_platform_config(platform_config(callers))


@pytest.mark.parametrize(
    "pin",
    [None, "", "12345", "1234567890123", "12345x", " 123456"],
)
def test_startup_rejects_missing_weak_or_malformed_pin(monkeypatch, pin):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC" + "a" * 32)
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "synthetic-token")
    if pin is None:
        monkeypatch.delenv("TWILIO_VOICE_PIN", raising=False)
    else:
        monkeypatch.setenv("TWILIO_VOICE_PIN", pin)

    assert validate_config(platform_config([CALLER])) is False


def test_startup_accepts_six_to_twelve_digit_pin(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC" + "a" * 32)
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "synthetic-token")
    for pin in ("123456", "123456789012"):
        monkeypatch.setenv("TWILIO_VOICE_PIN", pin)
        assert validate_config(platform_config([CALLER])) is True
