"""Host-attested ordinary WhatsApp sender-companion fence tests."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.whatsapp_common import (
    ORDINARY_VERIFIED_LAUNCHER_SHA256,
    ORDINARY_VERIFIED_MANIFEST_SHA256,
    ORDINARY_VERIFIED_SOURCE_SHA256,
)
from plugins.platforms.whatsapp.adapter import WhatsAppAdapter


BRIDGE_ROOT = Path(__file__).resolve().parents[2] / "scripts" / "whatsapp-bridge"


def _trusted_principal_activation() -> dict:
    return {
        "version": 2,
        "enabled": True,
        "mode": "juno",
        "profile": "juno",
        "kite_plugin": "juno_kite_trusted_principal",
        "mapping_path": "/private/tmp/synthetic-juno-activation.sqlite3",
        "mapping_key_env": "SYNTHETIC_MAPPING_KEY",
        "request_key_env": "SYNTHETIC_REQUEST_KEY",
        "response_key_env": "SYNTHETIC_RESPONSE_KEY",
        "kite_peer": "kite",
        "kite_url": "http://127.0.0.1:9917",
        "policy_generation": "synthetic-v2",
        "allowed_group_conversations": [
            {"platform": "whatsapp", "chat_id": "300000000000000@g.us"}
        ],
        "principal_bindings": [
            {
                "platform": "whatsapp",
                "user_id": "11111111111@s.whatsapp.net",
                "principal": "owner",
            }
        ],
        "policy": {
            "principals": {
                "owner": {
                    "conversation_eligibility": {"dm": True, "group": True},
                    "required_group_co_principals": [],
                    "read_capability_ids": ["private.owner"],
                    "action_capability_ids": [],
                    "semantic_policy": {"private.owner": {"disclose": ["own"]}},
                }
            },
            "tool_classes": {"read": ["read_file"], "mutating": []},
            "action_rules": [],
        },
        "limits": {
            "question_chars": 120,
            "context_turns": 2,
            "context_turn_chars": 48,
            "handoff_bytes": 2400,
            "policy_view_chars": 3000,
            "output_chars": 64,
            "response_bytes": 1800,
            "turn_ttl_seconds": 30,
            "roster_timeout_seconds": 2,
        },
    }


def _activation_runner(raw=None, *, profile="juno", multiplex=False):
    from gateway.run import GatewayRunner

    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig(
        platforms={Platform.WHATSAPP: PlatformConfig(enabled=True)},
        multiplex_profiles=multiplex,
        trusted_private_read={"version": 2, "enabled": False},
        enabled_plugins=("juno_kite_trusted_principal",),
        juno_kite_trusted_principal=(
            _trusted_principal_activation() if raw is None else raw
        ),
    )
    runner._active_profile_name = lambda: profile
    return runner


def _unconfigured_adapter(tmp_path: Path, *, mode: str = "bot") -> WhatsAppAdapter:
    session = tmp_path / "ordinary-session"
    session.mkdir(mode=0o700, parents=True)
    return WhatsAppAdapter(
        PlatformConfig(
            enabled=True,
            extra={
                "bridge_script": str(BRIDGE_ROOT / "launcher.js"),
                "session_path": str(session),
                "mode": mode,
            },
        )
    )


def _adapter(tmp_path: Path) -> WhatsAppAdapter:
    session = tmp_path / "ordinary-session"
    session.mkdir(mode=0o700, parents=True)
    adapter = WhatsAppAdapter(PlatformConfig(enabled=True, extra={
        "bridge_script": str(BRIDGE_ROOT / "launcher.js"),
        "session_path": str(session),
        "mode": "bot",
    }))
    adapter.configure_private_read_sender_companion_fence("juno")
    return adapter


def test_legacy_juno_self_chat_can_configure_sender_companion_fence(
    tmp_path: Path,
) -> None:
    adapter = _unconfigured_adapter(tmp_path, mode="self-chat")

    adapter.configure_private_read_sender_companion_fence("juno")

    assert adapter._private_read_fence_profile == "juno"


def test_exact_trusted_principal_v2_configures_fence_without_legacy_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _trusted_principal_activation()
    raw["principal_bindings"].append(
        {"platform": "telegram", "user_id": "synthetic-owner", "principal": "owner"}
    )
    runner = _activation_runner(raw)
    adapter = _unconfigured_adapter(tmp_path)
    configured_before_connect = False
    configure = adapter.configure_trusted_principal_v2_sender_companion_fence

    def observe_preconnect(profile: str) -> None:
        nonlocal configured_before_connect
        configured_before_connect = (
            adapter._bridge_process is None and not adapter._running
        )
        configure(profile)

    monkeypatch.setattr(
        adapter,
        "configure_trusted_principal_v2_sender_companion_fence",
        observe_preconnect,
    )

    runner._configure_juno_private_read_sender_fence(Platform.WHATSAPP, adapter)

    assert configured_before_connect is True
    assert adapter._private_read_fence_profile == "juno"
    assert runner.config.trusted_private_read == {"version": 2, "enabled": False}
    assert not hasattr(runner, "_trusted_private_read_host")


@pytest.mark.parametrize(
    "case",
    (
        "missing",
        "disabled",
        "wrong_version",
        "wrong_profile",
        "wrong_mode",
        "self_chat",
        "multiplex",
        "wrong_platform",
        "no_groups",
        "bad_policy",
        "plugin_disabled",
        "adapter_capability_missing",
    ),
)
def test_trusted_principal_fence_activation_requires_exact_scope(
    case: str, tmp_path: Path
) -> None:
    raw = _trusted_principal_activation()
    profile = "juno"
    multiplex = False
    platform = Platform.WHATSAPP
    if case == "missing":
        raw = _trusted_principal_activation()
    elif case == "disabled":
        raw["enabled"] = False
    elif case == "wrong_version":
        raw["version"] = 1
    elif case == "wrong_profile":
        profile = "default"
    elif case == "wrong_mode":
        raw["mode"] = "kite"
    elif case == "multiplex":
        multiplex = True
    elif case == "wrong_platform":
        platform = Platform.TELEGRAM
    elif case == "no_groups":
        raw["allowed_group_conversations"] = []
    elif case == "bad_policy":
        raw["policy"]["principals"]["owner"]["semantic_policy"] = {}
    runner = _activation_runner(raw, profile=profile, multiplex=multiplex)
    if case == "missing":
        runner.config.juno_kite_trusted_principal = None
    elif case == "plugin_disabled":
        runner.config.enabled_plugins = ()
    adapter = (
        SimpleNamespace(_private_read_fence_profile=None)
        if case == "adapter_capability_missing"
        else _unconfigured_adapter(
            tmp_path, mode="self-chat" if case == "self_chat" else "bot"
        )
    )

    runner._configure_juno_private_read_sender_fence(platform, adapter)

    assert adapter._private_read_fence_profile is None


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


def _roster_response(
    adapter: WhatsAppAdapter,
    *,
    challenge: str,
    group_id: str = "300000000000000@g.us",
    runtime_id: str = "a" * 64,
    socket_generation: int = 1,
    participants=None,
) -> dict:
    unsigned = {
        "version": 1,
        "groupId": group_id,
        "isGroup": True,
        "complete": True,
        "participants": participants or [
            ["11111111111@s.whatsapp.net", "21111111111@lid"],
            ["12222222222@s.whatsapp.net", "22222222222@lid"],
        ],
        "botIdentities": ["33333333333@s.whatsapp.net", "44444444444@lid"],
        "runtimeId": runtime_id,
        "socketGeneration": socket_generation,
        "observedAtUs": time.time_ns() // 1000,
        "challenge": challenge,
    }
    material = json.dumps(
        unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return {
        **unsigned,
        "proof": hmac.new(
            bytes.fromhex(adapter._private_read_fence_key), material, hashlib.sha256
        ).hexdigest(),
    }


def _resign_roster_response(adapter: WhatsAppAdapter, response: dict) -> None:
    unsigned = {key: value for key, value in response.items() if key != "proof"}
    material = json.dumps(
        unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    response["proof"] = hmac.new(
        bytes.fromhex(adapter._private_read_fence_key), material, hashlib.sha256
    ).hexdigest()


@pytest.mark.parametrize(
    "mutation",
    (
        "stopped",
        "stale_health",
        "non_group",
        "empty",
        "malformed",
        "duplicate",
        "uncanonical",
        "wrong_group",
        "fallback_chat",
        "inbound_generation",
        "wrong_generation",
        "wrong_proof",
    ),
)
def test_authenticated_managed_roster_strict_rejection_table(
    mutation: str, tmp_path: Path
) -> None:
    adapter = _adapter(tmp_path)
    adapter._running = True
    adapter._bridge_process = SimpleNamespace(poll=lambda: None, pid=12345)
    health = _health(adapter)

    def request(path, payload, timeout):
        assert timeout <= 2
        if path == "/health":
            return health
        response = _roster_response(adapter, challenge=payload["challenge"])
        if mutation == "non_group":
            response["isGroup"] = False
        elif mutation == "empty":
            response["participants"] = []
        elif mutation == "malformed":
            response["participants"] = "not-a-roster"
        elif mutation == "duplicate":
            response["participants"].append(response["participants"][0])
        elif mutation == "uncanonical":
            response["participants"][0] = ["11111111111:4@s.whatsapp.net"]
        elif mutation == "wrong_group":
            response["groupId"] = "300000000000001@g.us"
        elif mutation == "fallback_chat":
            return {"name": "fallback", "isGroup": True, "participants": []}
        elif mutation == "wrong_generation":
            response["socketGeneration"] = 2
        if mutation == "wrong_proof":
            response["proof"] = "0" * 64
        else:
            _resign_roster_response(adapter, response)
        return response

    if mutation == "stopped":
        adapter._bridge_process = SimpleNamespace(poll=lambda: 1, pid=12345)
    elif mutation == "stale_health":
        health = _health(adapter, observed_at_us=time.time_ns() // 1000 - 10_000_000)
    adapter._private_read_bridge_request = request

    with pytest.raises(RuntimeError):
        adapter.authenticated_group_roster(
            "juno",
            "300000000000000@g.us",
            timeout=2,
            expected_runtime_id="a" * 64,
            expected_socket_generation=2 if mutation == "inbound_generation" else 1,
        )


def test_authenticated_managed_roster_accepts_exact_signed_socket_generation(
    tmp_path: Path,
) -> None:
    adapter = _adapter(tmp_path)
    adapter._running = True
    adapter._bridge_process = SimpleNamespace(poll=lambda: None, pid=12345)
    health = _health(adapter)

    def request(path, payload, _timeout):
        if path == "/health":
            return health
        return _roster_response(adapter, challenge=payload["challenge"])

    adapter._private_read_bridge_request = request
    roster = adapter.authenticated_group_roster(
        "juno",
        "300000000000000@g.us",
        timeout=2,
        expected_runtime_id="a" * 64,
        expected_socket_generation=1,
    )
    assert roster == {
        "group_id": "300000000000000@g.us",
        "participants": [
            ["11111111111@s.whatsapp.net", "21111111111@lid"],
            ["12222222222@s.whatsapp.net", "22222222222@lid"],
        ],
        "bot_identities": ["33333333333@s.whatsapp.net", "44444444444@lid"],
        "generation": roster["generation"],
    }
    assert len(roster["generation"]) == 64
