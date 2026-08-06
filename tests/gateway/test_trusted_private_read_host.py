from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.config import GatewayConfig
from gateway.run import GatewayRunner
from gateway.trusted_private_read_host import (
    SENSITIVE_RUNTIME_LAUNCHER_PATH,
    SENSITIVE_VERIFIED_LAUNCHER_SHA256,
    TrustedPrivateReadConfigurationError,
    TrustedPrivateReadGatewayHost,
    TrustedPrivateReadHostConfig,
    TrustedPrivateReadHostServices,
    _sensitive_launcher_seal,
)
from tools.private_read_request_tool import (
    check_private_read_request_runtime,
    configure_private_read_request_runtime,
)


def _write_owner_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def _config(root: Path) -> dict:
    root.mkdir(mode=0o700, exist_ok=True)
    state = root / "state"
    state.mkdir(mode=0o700)
    key_file = root / "keys.json"
    allowlist_file = root / "allowlist.json"
    keys = {
        "version": 1,
        "key_version": "fixture-v1",
        "audit_hmac": "11" * 32,
        "request_hmac": "22" * 32,
        "request_id_hmac": "33" * 32,
        "authorization_hmac": "44" * 32,
        "receipt_hmac": "55" * 32,
    }
    identity = {
        "manifest_sha256": "a" * 64,
        "verifier_sha256": "f" * 64,
        "patcher_sha256": "9" * 64,
        "launcher_sha256": SENSITIVE_VERIFIED_LAUNCHER_SHA256,
        "source_sha256": "b" * 64,
        "node_modules_tree_sha256": "1" * 64,
        "package_sha256": "c" * 64,
        "lock_sha256": "d" * 64,
        "package_name": "fixture-package",
        "package_version": "fixture-version",
        "submit_contract_version": "fixture-submit-contract",
        "baileys_spec": "fixture-spec",
        "baileys_lock_version": "fixture-lock-version",
        "baileys_lock_resolved": "fixture-lock-resolved",
        "baileys_version": "fixture-provider-version",
        "baileys_lock_integrity": "fixture-lock-integrity",
        "baileys_installed_name": "fixture-installed-name",
        "baileys_package_sha256": "f" * 64,
        "baileys_preimage_tree_sha256": "7" * 64,
        "baileys_tree_sha256": "e" * 64,
        "baileys_reviewed_release_git_head": "fixture-reviewed-head",
        "baileys_patch_contract": "fixture-patch-contract",
        "baileys_patch_upstream_commit": "fixture-patch-head",
        "baileys_patch_target": "fixture-patch-target",
        "baileys_patch_preimage_sha256": "6" * 64,
        "baileys_patch_postimage_sha256": "5" * 64,
        "baileys_patch_postimage_contract_sha256": "8" * 64,
    }
    _write_owner_json(key_file, keys)
    _write_owner_json(
        allowlist_file,
        {"version": 1, "transport_identity": identity},
    )
    return {
        "version": 1,
        "enabled": True,
        "state_dir": str(state),
        "key_file": str(key_file),
        "allowlist_file": str(allowlist_file),
        "openfga_version": "1.18.2",
        "capabilities": [
            {
                "id": "fixture-capability",
                "operation": "fixture-operation",
                "resource_type": "fixture-resource",
                "fields": ["fixture-field"],
            }
        ],
        "poll_seconds": 0.1,
        "lease_seconds": 5,
    }


@pytest.fixture(autouse=True)
def _remove_runtime():
    configure_private_read_request_runtime(None)
    yield
    configure_private_read_request_runtime(None)


def test_default_config_has_no_block_and_schema_is_unavailable() -> None:
    config = GatewayConfig()
    assert config.trusted_private_read is None
    assert "trusted_private_read" not in config.to_dict()
    assert check_private_read_request_runtime() is False


@pytest.mark.asyncio
async def test_enabled_config_cannot_activate_unavailable_production_composition(
    tmp_path: Path,
) -> None:
    runner = object.__new__(GatewayRunner)
    runner.config = SimpleNamespace(trusted_private_read=_config(tmp_path))
    runner._trusted_private_read_host = None

    assert await GatewayRunner._start_trusted_private_read_host(runner) is False
    assert runner._trusted_private_read_host is None
    assert check_private_read_request_runtime() is False


def test_arbitrary_services_module_is_not_a_configuration_surface(tmp_path: Path) -> None:
    raw = _config(tmp_path)
    raw["services_module"] = "fixture.untrusted"
    with pytest.raises(TrustedPrivateReadConfigurationError):
        TrustedPrivateReadHostConfig.parse(raw)

@pytest.mark.asyncio
async def test_gateway_rejects_external_service_factory_and_keeps_runtime_unavailable(
    tmp_path: Path,
) -> None:
    called = False

    def untrusted_factory(*_args):
        nonlocal called
        called = True
        raise AssertionError("configuration must not select executable composition")

    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig.from_dict({"trusted_private_read": _config(tmp_path)})
    runner._trusted_private_read_services_factory = untrusted_factory
    assert await runner._start_trusted_private_read_host() is False
    assert called is False
    assert check_private_read_request_runtime() is False


def test_explicit_versioned_config_round_trips_and_authenticates_files(tmp_path: Path) -> None:
    raw = _config(tmp_path)
    parsed = TrustedPrivateReadHostConfig.parse(raw)
    assert type(parsed) is TrustedPrivateReadHostConfig
    config = GatewayConfig.from_dict({"trusted_private_read": raw})
    assert config.to_dict()["trusted_private_read"] == raw

    Path(raw["key_file"]).chmod(0o644)
    with pytest.raises(TrustedPrivateReadConfigurationError):
        TrustedPrivateReadHostConfig.parse(raw)


def test_symlinked_key_and_transport_allowlist_drift_are_rejected(tmp_path: Path) -> None:
    raw = _config(tmp_path)
    key = Path(raw["key_file"])
    alias = tmp_path / "alias.json"
    alias.symlink_to(key)
    raw["key_file"] = str(alias)
    with pytest.raises(TrustedPrivateReadConfigurationError):
        TrustedPrivateReadHostConfig.parse(raw)

    raw = _config(tmp_path / "third")
    allowlist = Path(raw["allowlist_file"])
    payload = json.loads(allowlist.read_text(encoding="utf-8"))
    payload["transport_identity"]["launcher_sha256"] = "0" * 64
    _write_owner_json(allowlist, payload)
    with pytest.raises(TrustedPrivateReadConfigurationError):
        TrustedPrivateReadHostConfig.parse(raw)

    raw = _config(tmp_path / "second")
    allowlist = Path(raw["allowlist_file"])
    payload = json.loads(allowlist.read_text(encoding="utf-8"))
    payload["transport_identity"]["source_sha256"] = "not-a-digest"
    _write_owner_json(allowlist, payload)
    with pytest.raises(TrustedPrivateReadConfigurationError):
        TrustedPrivateReadHostConfig.parse(raw)


def _copy_sensitive_launcher(target: Path) -> Path:
    target.write_bytes(SENSITIVE_RUNTIME_LAUNCHER_PATH.read_bytes())
    target.chmod(0o600)
    return target


def test_actual_sensitive_launcher_positive_and_tampered_marker_rejected(
    tmp_path: Path,
) -> None:
    launcher = _copy_sensitive_launcher(tmp_path / "launcher.js")
    seal = _sensitive_launcher_seal(launcher)
    assert seal[-1] == SENSITIVE_VERIFIED_LAUNCHER_SHA256

    marker = tmp_path / "tampered-launcher-executed"
    launcher.write_text(
        launcher.read_text(encoding="utf-8")
        + f"\nprocess.getBuiltinModule('node:fs').writeFileSync({str(marker)!r}, 'x');\n",
        encoding="utf-8",
    )
    with pytest.raises(TrustedPrivateReadConfigurationError) as raised:
        _sensitive_launcher_seal(launcher)
    assert not marker.exists()
    assert str(tmp_path) not in str(raised.value)


def test_sensitive_launcher_symlink_and_symlinked_ancestor_rejected(
    tmp_path: Path,
) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir(mode=0o700)
    launcher = _copy_sensitive_launcher(real_dir / "launcher.js")
    alias = tmp_path / "launcher-alias.js"
    alias.symlink_to(launcher)
    with pytest.raises(TrustedPrivateReadConfigurationError):
        _sensitive_launcher_seal(alias)

    directory_alias = tmp_path / "directory-alias"
    directory_alias.symlink_to(real_dir, target_is_directory=True)
    with pytest.raises(TrustedPrivateReadConfigurationError):
        _sensitive_launcher_seal(directory_alias / "launcher.js")


def test_sensitive_launcher_inode_swap_during_hash_is_rejected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    launcher = _copy_sensitive_launcher(tmp_path / "launcher.js")
    replacement = _copy_sensitive_launcher(tmp_path / "replacement.js")
    real_read = os.read
    swapped = False

    def swap_after_first_read(descriptor: int, size: int) -> bytes:
        nonlocal swapped
        chunk = real_read(descriptor, size)
        if chunk and not swapped:
            swapped = True
            os.replace(replacement, launcher)
        return chunk

    monkeypatch.setattr(os, "read", swap_after_first_read)
    with pytest.raises(TrustedPrivateReadConfigurationError):
        _sensitive_launcher_seal(launcher)
    assert swapped is True

@pytest.mark.asyncio
async def test_gateway_host_installs_only_while_healthy_and_reconciles_restart(
    tmp_path: Path,
) -> None:
    config = TrustedPrivateReadHostConfig.parse(_config(tmp_path))
    assert config is not None
    health = {"ok": True}

    async def unused(*_args):
        raise AssertionError("no provider action is expected without authorized work")

    async def close() -> None:
        return None

    services = TrustedPrivateReadHostServices(
        healthy=lambda: health["ok"],
        context_for_current_event=lambda: None,
        pdp_check=unused,
        transport_registration=unused,
        private_read=unused,
        deliver_notification=unused,
        decision_for_event=lambda _event: None,
        close=close,
        transport_identity=lambda: dict(config.transport_identity),
        account_state=lambda: (
            "juno@fixture",
            "juno@fixture",
            "fixture",
            True,
        ),
    )
    first = TrustedPrivateReadGatewayHost(config, services)
    assert await first.start() is True
    assert check_private_read_request_runtime() is True
    assert first.health() == {
        "enabled": True,
        "ready": True,
        "worker_running": True,
    }

    # A handler planned before this drift rechecks the same health closure.
    health["ok"] = False
    assert check_private_read_request_runtime() is False
    await first.stop()
    assert check_private_read_request_runtime() is False

    health["ok"] = True
    restarted = TrustedPrivateReadGatewayHost(config, services)
    assert await restarted.start() is True
    await restarted.stop()


@pytest.mark.asyncio
async def test_gateway_host_accepts_same_account_distinct_session_topology(
    tmp_path: Path,
) -> None:
    config = TrustedPrivateReadHostConfig.parse(_config(tmp_path))
    assert config is not None

    async def unused(*_args):
        raise AssertionError

    async def close() -> None:
        return None

    services = TrustedPrivateReadHostServices(
        healthy=lambda: True,
        context_for_current_event=lambda: None,
        pdp_check=unused,
        transport_registration=unused,
        private_read=unused,
        deliver_notification=unused,
        decision_for_event=lambda _event: None,
        close=close,
        transport_identity=lambda: dict(config.transport_identity),
        account_state=lambda: (
            "juno@fixture",
            "juno@fixture",
            "fixture",
            True,
        ),
    )
    host = TrustedPrivateReadGatewayHost(config, services)
    assert await host.start() is True
    await host.stop()


@pytest.mark.asyncio
async def test_baseexception_in_worker_revokes_schema(tmp_path: Path) -> None:
    config = TrustedPrivateReadHostConfig.parse(_config(tmp_path))
    assert config is not None
    healthy_calls = 0

    def healthy() -> bool:
        nonlocal healthy_calls
        healthy_calls += 1
        if healthy_calls > 3:
            raise SystemExit
        return True

    async def unused(*_args):
        raise AssertionError

    async def close() -> None:
        return None

    host = TrustedPrivateReadGatewayHost(
        config,
        TrustedPrivateReadHostServices(
            healthy=healthy,
            context_for_current_event=lambda: None,
            pdp_check=unused,
            transport_registration=unused,
            private_read=unused,
            deliver_notification=unused,
            decision_for_event=lambda _event: None,
            close=close,
            transport_identity=lambda: dict(config.transport_identity),
            account_state=lambda: (
                "juno@fixture",
                "juno@fixture",
                "fixture",
                True,
            ),
        ),
    )
    await host.start()
    await asyncio.sleep(0.2)
    assert check_private_read_request_runtime() is False
    await host.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "account_state",
    [
        ("ordinary@fixture", "sensitive@other", "fixture", True),
        ("ordinary@fixture", "sensitive@fixture", "fixture", True),
        ("ordinary@fixture", "sensitive@fixture", "fixture", False),
        ("juno@fixture", "juno@fixture", "fixture", False),
    ],
)
async def test_account_mismatch_namespace_and_lid_readiness_fail_closed(
    tmp_path: Path, account_state: tuple[str, str, str, bool]
) -> None:
    config = TrustedPrivateReadHostConfig.parse(_config(tmp_path))
    assert config is not None

    async def unused(*_args):
        raise AssertionError

    async def close() -> None:
        return None

    host = TrustedPrivateReadGatewayHost(
        config,
        TrustedPrivateReadHostServices(
            healthy=lambda: True,
            context_for_current_event=lambda: None,
            pdp_check=unused,
            transport_registration=unused,
            private_read=unused,
            deliver_notification=unused,
            decision_for_event=lambda _event: None,
            close=close,
            transport_identity=lambda: dict(config.transport_identity),
            account_state=lambda: account_state,
        ),
    )
    assert await host.start() is False
    assert check_private_read_request_runtime() is False
    await host.stop()
