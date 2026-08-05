from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.config import Platform
from gateway.run import GatewayRunner
from gateway.juno_private_read_mvp import (
    JunoOrdinaryRuntimeTopology,
    JunoPrivateReadMvpConfig,
    _SENSITIVE_TRANSPORT_IDENTITY,
    _SensitiveBridgeSupervisor,
    resolve_juno_ordinary_runtime_topology,
)
from tests.gateway.test_juno_private_read_mvp_e2e import _raw_config


class _Host:
    def __init__(self, generation: str) -> None:
        self.generation = generation
        self.stopped = 0
        self.healthy = True

    def is_healthy(self) -> bool:
        return self.healthy

    async def stop(self) -> None:
        self.stopped += 1


class _Adapter:
    def __init__(self, topology=None) -> None:
        self.topology = topology

    def private_read_sender_companion_fence_healthy(self, profile: str) -> bool:
        return profile == "juno" and self.topology is not None

    def private_read_runtime_topology(self, profile: str):
        return self.topology if profile == "juno" else None


class _Topology:
    def __init__(self, adapter: _Adapter, label: str) -> None:
        self.adapter = adapter
        self.label = label

    @property
    def generation(self):
        return id(self.adapter), self.label


class _Supervisor:
    def __init__(self) -> None:
        self.stopped = 0
        self.refresh_ok = True

    def healthy(self) -> bool:
        return True

    async def refresh(self) -> bool:
        return self.refresh_ok

    async def stop(self) -> None:
        self.stopped += 1


def _runner(tmp_path):
    runner = object.__new__(GatewayRunner)
    runner.config = SimpleNamespace(
        trusted_private_read=_raw_config(tmp_path),
        multiplex_profiles=False,
    )
    runner._active_profile_name = lambda: "juno"
    runner.adapters = {}
    runner._profile_adapters = {}
    runner._trusted_private_read_host = None
    runner._trusted_private_read_generation = None
    runner._trusted_private_read_supervisor = None
    runner._trusted_private_read_config = None
    return runner


def _write_sensitive_credentials(session: Path, *, registration_id: int = 47) -> None:
    session.mkdir(parents=True, mode=0o700, exist_ok=True)
    session.chmod(0o700)
    creds = {
        "registered": True,
        "me": {
            "id": "33333333333:4@s.whatsapp.net",
            "lid": "44444444444:7@lid",
        },
        "registrationId": registration_id,
        "noiseKey": {"private": "synthetic-a", "public": "synthetic-b"},
        "signedIdentityKey": {"private": "synthetic-c", "public": "synthetic-d"},
        "advSecretKey": f"synthetic-device-{registration_id}",
    }
    target = session / "creds.json"
    target.write_text(json.dumps(creds), encoding="utf-8")
    target.chmod(0o600)


def test_topology_resolver_binds_exact_sensitive_credential_generation(
    tmp_path, monkeypatch,
) -> None:
    from gateway.platforms.whatsapp_common import (
        ORDINARY_VERIFIED_LAUNCHER_SHA256,
        ORDINARY_VERIFIED_MANIFEST_SHA256,
        ORDINARY_VERIFIED_SOURCE_SHA256,
    )

    home = tmp_path / "profile"
    sensitive = home / "sensitive-delivery" / "whatsapp" / "session"
    ordinary = tmp_path / "ordinary"
    ordinary.mkdir(mode=0o700)
    _write_sensitive_credentials(sensitive)
    monkeypatch.setenv("HERMES_HOME", str(home))
    config = JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path))
    adapter = _Adapter({
        "adapter_generation": "b" * 64,
        "ordinary_runtime_id": "ordinary-runtime",
        "ordinary_socket_generation": 7,
        "ordinary_account_phone": config.ordinary_account,
        "ordinary_account_lid": "44444444444@lid",
        "ordinary_session_path": str(ordinary),
        "ordinary_session_identity": f"{ordinary.stat().st_dev}:{ordinary.stat().st_ino}",
        "ordinary_manifest_sha256": ORDINARY_VERIFIED_MANIFEST_SHA256,
        "ordinary_source_sha256": ORDINARY_VERIFIED_SOURCE_SHA256,
        "ordinary_launcher_sha256": ORDINARY_VERIFIED_LAUNCHER_SHA256,
    })
    runner = SimpleNamespace(
        config=SimpleNamespace(multiplex_profiles=False),
        adapters={Platform.WHATSAPP: adapter},
    )

    first = resolve_juno_ordinary_runtime_topology(runner, config)
    assert first is not None
    assert first.sensitive_account_phone == config.sensitive_account
    assert first.sensitive_account_lid == "44444444444@lid"
    assert len(first.sensitive_device_identity_sha256) == 64
    assert len(first.sensitive_credential_tree_sha256) == 64

    _write_sensitive_credentials(sensitive, registration_id=88)
    second = resolve_juno_ordinary_runtime_topology(runner, config)
    assert second is not None
    assert second.generation != first.generation


@pytest.mark.asyncio
async def test_fence_only_adapter_cannot_become_sensitive_authority(
    tmp_path,
) -> None:
    runner = _runner(tmp_path)

    class FenceOnly:
        def private_read_sender_companion_fence_healthy(self, profile):
            return profile == "juno"

    runner.adapters[Platform.WHATSAPP] = FenceOnly()
    assert await GatewayRunner._start_trusted_private_read_host(runner) is False
    assert runner._trusted_private_read_host is None


@pytest.mark.asyncio
async def test_reconciler_publishes_once_after_delayed_topology_and_recovery(
    tmp_path, monkeypatch,
) -> None:
    runner = _runner(tmp_path)
    adapter = _Adapter()
    runner.adapters[Platform.WHATSAPP] = adapter
    runner._current_juno_private_read_topology = lambda: adapter.topology
    activated = []

    async def activate(topology):
        host = _Host(topology.label)
        activated.append(host)
        return host, _Supervisor()

    monkeypatch.setattr(runner, "_activate_juno_private_read_generation", activate)
    assert not await runner._reconcile_juno_private_read_host_once()
    assert runner._trusted_private_read_host is None

    adapter.topology = _Topology(adapter, "ordinary-a")
    assert await runner._reconcile_juno_private_read_host_once()
    first = runner._trusted_private_read_host
    assert first is activated[0]
    assert await runner._reconcile_juno_private_read_host_once()
    assert runner._trusted_private_read_host is first
    assert len(activated) == 1

    adapter.topology = None
    assert not await runner._reconcile_juno_private_read_host_once()
    assert first.stopped == 1
    assert runner._trusted_private_read_host is None

    adapter.topology = _Topology(adapter, "ordinary-a")
    assert await runner._reconcile_juno_private_read_host_once()
    assert runner._trusted_private_read_host is activated[1]
    assert activated[1] is not first


@pytest.mark.asyncio
async def test_reconciler_burns_old_handler_on_adapter_or_runtime_replacement(
    tmp_path, monkeypatch,
) -> None:
    runner = _runner(tmp_path)
    first_adapter = _Adapter()
    first_adapter.topology = _Topology(first_adapter, "ordinary-a")
    runner.adapters[Platform.WHATSAPP] = first_adapter
    runner._current_juno_private_read_topology = lambda: (
        runner.adapters[Platform.WHATSAPP].topology
    )
    activated = []

    async def activate(topology):
        host = _Host(topology.label)
        activated.append(host)
        return host, _Supervisor()

    monkeypatch.setattr(runner, "_activate_juno_private_read_generation", activate)
    assert await runner._reconcile_juno_private_read_host_once()
    first_host = runner._trusted_private_read_host

    replacement = _Adapter()
    replacement.topology = _Topology(replacement, "ordinary-a")
    runner.adapters[Platform.WHATSAPP] = replacement
    assert await runner._reconcile_juno_private_read_host_once()
    assert first_host.stopped == 1
    assert runner._trusted_private_read_host is not first_host

    second_host = runner._trusted_private_read_host
    runner.adapters[Platform.WHATSAPP].topology = _Topology(replacement, "ordinary-b")
    assert await runner._reconcile_juno_private_read_host_once()
    assert second_host.stopped == 1
    assert runner._trusted_private_read_host.generation == "ordinary-b"


@pytest.mark.asyncio
async def test_reconciler_replaces_host_after_sensitive_runtime_evidence_loss(
    tmp_path, monkeypatch,
) -> None:
    runner = _runner(tmp_path)
    adapter = _Adapter()
    adapter.topology = _Topology(adapter, "ordinary-a")
    runner._current_juno_private_read_topology = lambda: adapter.topology
    activated = []

    async def activate(topology):
        pair = (_Host(topology.label), _Supervisor())
        activated.append(pair)
        return pair

    monkeypatch.setattr(runner, "_activate_juno_private_read_generation", activate)
    assert await runner._reconcile_juno_private_read_host_once()
    first_host, first_supervisor = activated[0]
    first_supervisor.refresh_ok = False

    assert await runner._reconcile_juno_private_read_host_once()
    assert first_host.stopped == 1
    assert first_supervisor.stopped == 1
    assert runner._trusted_private_read_host is activated[1][0]
    assert runner._trusted_private_read_host is not first_host


@pytest.mark.asyncio
async def test_reconciler_shutdown_cleans_host_and_child_once(
    tmp_path, monkeypatch,
) -> None:
    runner = _runner(tmp_path)
    adapter = _Adapter()
    adapter.topology = _Topology(adapter, "ordinary-a")
    runner._current_juno_private_read_topology = lambda: adapter.topology
    runner._shutdown_event = asyncio.Event()
    host = _Host("ordinary-a")
    supervisor = _Supervisor()

    async def activate(_topology):
        return host, supervisor

    monkeypatch.setattr(runner, "_activate_juno_private_read_generation", activate)
    task = asyncio.create_task(runner._juno_private_read_reconciler())
    for _ in range(20):
        if runner._trusted_private_read_host is host:
            break
        await asyncio.sleep(0)
    runner._shutdown_event.set()
    await task
    assert host.stopped == 1
    assert supervisor.stopped == 1
    assert runner._trusted_private_read_host is None


@pytest.mark.asyncio
async def test_supervisor_never_adopts_stale_port_owner_generation(
    tmp_path, monkeypatch,
) -> None:
    raw = _raw_config(tmp_path)
    config = replace(JunoPrivateReadMvpConfig.parse(raw), request_timeout=0.1)
    ordinary = tmp_path / "ordinary-session"
    sensitive = tmp_path / "sensitive-session"
    ordinary.mkdir(mode=0o700)
    sensitive.mkdir(mode=0o700)
    ordinary_stat = ordinary.stat()
    sensitive_stat = sensitive.stat()
    adapter = object()
    topology = JunoOrdinaryRuntimeTopology(
        adapter=adapter,
        adapter_generation="b" * 64,
        ordinary_runtime_id="ordinary-runtime",
        ordinary_socket_generation=1,
        ordinary_account_phone=config.ordinary_account,
        ordinary_account_lid="44444444444@lid",
        ordinary_session_path=str(ordinary),
        ordinary_session_identity=f"{ordinary_stat.st_dev}:{ordinary_stat.st_ino}",
        ordinary_manifest_sha256="c" * 64,
        ordinary_source_sha256="d" * 64,
        ordinary_launcher_sha256="e" * 64,
        sensitive_session_path=str(sensitive),
        sensitive_session_identity=f"{sensitive_stat.st_dev}:{sensitive_stat.st_ino}",
    )

    class Process:
        stopped = False

        def poll(self):
            return 0 if self.stopped else None

        def terminate(self):
            self.stopped = True

        def kill(self):
            self.stopped = True

        def wait(self):
            return 0

    process = Process()
    monkeypatch.setattr("gateway.juno_private_read_mvp.subprocess.Popen", lambda *_a, **_k: process)

    class StalePortTransport:
        async def request(self, **_call):
            topology_identity = {
                "ordinary": {
                    "adapter_generation": topology.adapter_generation,
                    "runtime_id": topology.ordinary_runtime_id,
                    "socket_generation": 1,
                    "account_phone_jid": config.ordinary_account,
                    "account_lid_jid": topology.ordinary_account_lid,
                    "session_path": str(ordinary),
                    "session_identity": topology.ordinary_session_identity,
                    "manifest_sha256": "c" * 64,
                    "source_sha256": "d" * 64,
                    "launcher_sha256": "e" * 64,
                },
                "sensitive": {
                    "session_path": str(sensitive),
                    "session_identity": topology.sensitive_session_identity,
                    "credential_identity": "1:4",
                    "device_identity_sha256": "f" * 64,
                    "credential_tree_sha256": "0" * 64,
                    "account_phone_jid": config.sensitive_account,
                    "account_lid_jid": topology.ordinary_account_lid,
                },
            }
            topology_identity["topology_sha256"] = hashlib.sha256(json.dumps(
                topology_identity, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False,
            ).encode()).hexdigest()
            return {
                "outcome": "available",
                "submitted": False,
                "provider_account_jid": config.sensitive_account,
                "identity_observed_us": __import__("time").time_ns() // 1000,
                "adapter_runtime_id": f"sensitive-{'9' * 64}",
                "process_generation": "9" * 64,
                "connection_epoch": "stale-epoch",
                "topology_identity": topology_identity,
                "transport_identity": _SENSITIVE_TRANSPORT_IDENTITY,
            }

    supervisor = _SensitiveBridgeSupervisor(
        config, topology, transport=StalePortTransport(),
    )
    assert not await supervisor.start()
    assert process.stopped
    assert supervisor.process is None
