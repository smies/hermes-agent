"""Host-attested ordinary WhatsApp sender-companion fence tests."""

from __future__ import annotations

import hashlib
import hmac
import time
from pathlib import Path

import pytest

from gateway.config import Platform, PlatformConfig
from gateway.platforms.whatsapp_common import (
    ORDINARY_VERIFIED_LAUNCHER_SHA256,
    ORDINARY_VERIFIED_MANIFEST_SHA256,
    ORDINARY_VERIFIED_SOURCE_SHA256,
)
from plugins.platforms.whatsapp.adapter import WhatsAppAdapter


BRIDGE_ROOT = Path(__file__).resolve().parents[2] / "scripts" / "whatsapp-bridge"


def _adapter() -> WhatsAppAdapter:
    adapter = WhatsAppAdapter(PlatformConfig(enabled=True, extra={
        "bridge_script": str(BRIDGE_ROOT / "launcher.js"),
    }))
    adapter.configure_private_read_sender_companion_fence("juno")
    return adapter


def _health(
    adapter: WhatsAppAdapter,
    *,
    observed_at_us: int | None = None,
    runtime_id: str = "a" * 64,
) -> dict:
    observed = time.time_ns() // 1000 if observed_at_us is None else observed_at_us
    script_hash = hashlib.sha256((BRIDGE_ROOT / "bridge.js").read_bytes()).hexdigest()[:16]
    material = "\0".join((
        "juno-sender-companion-fence-v1",
        "juno",
        runtime_id,
        str(observed),
        ORDINARY_VERIFIED_MANIFEST_SHA256,
        ORDINARY_VERIFIED_SOURCE_SHA256,
        script_hash,
    ))
    proof = hmac.new(
        bytes.fromhex(adapter._private_read_fence_key),
        material.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "status": "connected",
        "scriptHash": script_hash,
        "launcherHash": ORDINARY_VERIFIED_LAUNCHER_SHA256,
        "transportManifestHash": ORDINARY_VERIFIED_MANIFEST_SHA256,
        "senderCompanionFence": {
            "version": 1,
            "active": True,
            "profile": "juno",
            "runtimeId": runtime_id,
            "observedAtUs": observed,
            "manifestSha256": ORDINARY_VERIFIED_MANIFEST_SHA256,
            "sourceSha256": ORDINARY_VERIFIED_SOURCE_SHA256,
            "scriptHash": script_hash,
            "proof": proof,
        },
    }


def test_fence_bootstrap_cannot_be_borrowed_from_ambient_environment() -> None:
    inherited = {
        "HERMES_INTERNAL_WHATSAPP_FENCE_PROFILE": "juno",
        "HERMES_INTERNAL_WHATSAPP_FENCE_KEY": "0" * 64,
        "KEPT": "yes",
    }
    generic = WhatsAppAdapter(PlatformConfig(enabled=True))
    generic._apply_private_read_fence_environment(inherited)
    assert inherited == {"KEPT": "yes"}

    fenced = _adapter()
    fenced._apply_private_read_fence_environment(inherited)
    assert inherited["KEPT"] == "yes"
    assert inherited["HERMES_INTERNAL_WHATSAPP_FENCE_PROFILE"] == "juno"
    assert inherited["HERMES_INTERNAL_WHATSAPP_FENCE_KEY"] == fenced._private_read_fence_key
    assert inherited["HERMES_INTERNAL_WHATSAPP_FENCE_KEY"] != "0" * 64


@pytest.mark.parametrize(
    "mutation", ("absent", "false", "malformed", "stale", "drifted"),
)
def test_private_read_fence_refuses_unattested_health(mutation: str) -> None:
    adapter = _adapter()
    health = _health(adapter)
    if mutation == "absent":
        health.pop("senderCompanionFence")
    elif mutation == "false":
        health["senderCompanionFence"]["active"] = False
    elif mutation == "malformed":
        health["senderCompanionFence"].pop("proof")
    elif mutation == "stale":
        health = _health(
            adapter,
            observed_at_us=time.time_ns() // 1000 - 10_000_000,
        )
    else:
        health["senderCompanionFence"]["profile"] = "another-profile"
    assert adapter._observe_private_read_fence_health(health) is False
    assert adapter.private_read_sender_companion_fence_healthy("juno") is False


def test_private_read_fence_accepts_fresh_exact_evidence_then_expires() -> None:
    adapter = _adapter()
    assert adapter._observe_private_read_fence_health(_health(adapter)) is True
    assert adapter.private_read_sender_companion_fence_healthy("juno") is True

    adapter._private_read_fence_received_monotonic -= 10
    assert adapter.private_read_sender_companion_fence_healthy("juno") is False


def test_private_read_fence_authority_is_adapter_and_profile_scoped() -> None:
    first = _adapter()
    second = _adapter()
    evidence = _health(first)
    assert first._observe_private_read_fence_health(evidence) is True
    assert second._observe_private_read_fence_health(evidence) is False
    assert first.private_read_sender_companion_fence_healthy("default") is False
    assert second.private_read_sender_companion_fence_healthy("juno") is False


def test_private_read_fence_runtime_drift_depublishes() -> None:
    adapter = _adapter()
    assert adapter._observe_private_read_fence_health(_health(adapter)) is True
    drifted = _health(adapter, runtime_id="b" * 64)
    assert adapter._observe_private_read_fence_health(drifted) is False
    assert adapter.private_read_sender_companion_fence_healthy("juno") is False
