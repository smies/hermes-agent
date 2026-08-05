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


def _adapter(tmp_path: Path) -> WhatsAppAdapter:
    session = tmp_path / "ordinary-session"
    session.mkdir(mode=0o700, parents=True)
    adapter = WhatsAppAdapter(PlatformConfig(enabled=True, extra={
        "bridge_script": str(BRIDGE_ROOT / "launcher.js"),
        "session_path": str(session),
    }))
    adapter.configure_private_read_sender_companion_fence("juno")
    return adapter


def _health(
    adapter: WhatsAppAdapter,
    *,
    observed_at_us: int | None = None,
    runtime_id: str = "a" * 64,
    socket_generation: int = 1,
    session_path: Path | None = None,
    account_phone: str = "33333333333@s.whatsapp.net",
    account_lid: str = "44444444444@lid",
) -> dict:
    observed = time.time_ns() // 1000 if observed_at_us is None else observed_at_us
    session_path = adapter._session_path if session_path is None else session_path
    script_hash = hashlib.sha256((BRIDGE_ROOT / "bridge.js").read_bytes()).hexdigest()[:16]
    material = "\0".join((
        "juno-sender-companion-fence-v2",
        "juno",
        runtime_id,
        str(socket_generation),
        account_phone,
        account_lid,
        str(session_path),
        f"{session_path.stat().st_dev}:{session_path.stat().st_ino}",
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
            "version": 2,
            "active": True,
            "profile": "juno",
            "runtimeId": runtime_id,
            "socketGeneration": socket_generation,
            "accountPhoneJid": account_phone,
            "accountLidJid": account_lid,
            "sessionPath": str(session_path),
            "sessionIdentity": (
                f"{session_path.stat().st_dev}:"
                f"{session_path.stat().st_ino}"
            ),
            "observedAtUs": observed,
            "manifestSha256": ORDINARY_VERIFIED_MANIFEST_SHA256,
            "sourceSha256": ORDINARY_VERIFIED_SOURCE_SHA256,
            "scriptHash": script_hash,
            "proof": proof,
        },
    }


def test_fence_bootstrap_cannot_be_borrowed_from_ambient_environment(tmp_path: Path) -> None:
    inherited = {
        "HERMES_INTERNAL_WHATSAPP_FENCE_PROFILE": "juno",
        "HERMES_INTERNAL_WHATSAPP_FENCE_KEY": "0" * 64,
        "KEPT": "yes",
    }
    generic = WhatsAppAdapter(PlatformConfig(enabled=True))
    generic._apply_private_read_fence_environment(inherited)
    assert inherited == {"KEPT": "yes"}

    fenced = _adapter(tmp_path)
    fenced._apply_private_read_fence_environment(inherited)
    assert inherited["KEPT"] == "yes"
    assert inherited["HERMES_INTERNAL_WHATSAPP_FENCE_PROFILE"] == "juno"
    assert inherited["HERMES_INTERNAL_WHATSAPP_FENCE_KEY"] == fenced._private_read_fence_key
    assert inherited["HERMES_INTERNAL_WHATSAPP_FENCE_KEY"] != "0" * 64


@pytest.mark.parametrize(
    "mutation", ("absent", "false", "malformed", "stale", "drifted"),
)
def test_private_read_fence_refuses_unattested_health(mutation: str, tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
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


def test_private_read_fence_accepts_fresh_exact_evidence_then_expires(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    assert adapter._observe_private_read_fence_health(_health(adapter)) is True
    assert adapter.private_read_sender_companion_fence_healthy("juno") is True

    adapter._private_read_fence_received_monotonic -= 10
    assert adapter.private_read_sender_companion_fence_healthy("juno") is False


def test_private_read_fence_authority_is_adapter_and_profile_scoped(tmp_path: Path) -> None:
    first = _adapter(tmp_path / "first")
    second = _adapter(tmp_path / "second")
    evidence = _health(first)
    assert first._observe_private_read_fence_health(evidence) is True
    assert second._observe_private_read_fence_health(evidence) is False
    assert first.private_read_sender_companion_fence_healthy("default") is False
    assert second.private_read_sender_companion_fence_healthy("juno") is False


def test_private_read_fence_runtime_drift_depublishes(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    assert adapter._observe_private_read_fence_health(_health(adapter)) is True
    drifted = _health(adapter, runtime_id="b" * 64)
    assert adapter._observe_private_read_fence_health(drifted) is False
    assert adapter.private_read_sender_companion_fence_healthy("juno") is False


def test_runtime_topology_is_exact_and_socket_generation_is_not_transferable(
    tmp_path: Path,
) -> None:
    adapter = _adapter(tmp_path)
    assert adapter._observe_private_read_fence_health(_health(adapter)) is True
    topology = adapter.private_read_runtime_topology("juno")
    assert topology["adapter_generation"] == adapter._private_read_adapter_generation
    assert topology["ordinary_session_path"] == str(adapter._session_path)
    assert topology["ordinary_socket_generation"] == 1

    assert adapter._observe_private_read_fence_health(
        _health(adapter, socket_generation=2)
    ) is True
    replacement = adapter.private_read_runtime_topology("juno")
    assert replacement["ordinary_socket_generation"] == 2
    assert replacement != topology


def test_active_adapter_session_a_rejects_signed_claim_for_session_b(
    tmp_path: Path,
) -> None:
    adapter = _adapter(tmp_path / "active")
    other = tmp_path / "other" / "ordinary-session"
    other.mkdir(mode=0o700, parents=True)
    assert adapter._observe_private_read_fence_health(
        _health(adapter, session_path=other)
    ) is False
    assert adapter.private_read_runtime_topology("juno") is None
