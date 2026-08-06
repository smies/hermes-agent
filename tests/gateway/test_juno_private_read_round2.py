from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import select
import signal
import socket
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from gateway.config import Platform
from gateway.run import GatewayRunner
from gateway.juno_private_read_mvp import (
    JunoOrdinaryRuntimeTopology,
    JunoPrivateReadError,
    JunoPrivateReadMvpConfig,
    _SENSITIVE_TRANSPORT_IDENTITY,
    _SensitiveBridgeSupervisor,
    _prepare_sensitive_receiver_replay_authority,
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


def _parent_death_supervisor(child: Path, port: int) -> subprocess.Popen:
    source = """
import json, subprocess, sys, time
child, port = sys.argv[1], sys.argv[2]
process = subprocess.Popen(
    ['node', child, port], stdin=subprocess.PIPE,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
)
line = process.stdout.readline()
if not line:
    raise SystemExit(process.wait())
ready = json.loads(line)
print(json.dumps({'parent_pid': __import__('os').getpid(), 'child_pid': process.pid,
                  'child_ready': ready}), flush=True)
while True:
    time.sleep(60)
"""
    return subprocess.Popen(
        [sys.executable, "-c", source, str(child), str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _readline_bounded(process: subprocess.Popen, timeout: float = 5.0) -> str:
    ready, _, _ = select.select([process.stdout], [], [], timeout)
    if not ready:
        raise AssertionError(f"parent process {process.pid} produced no readiness evidence")
    return process.stdout.readline()


def _wait_port_released(port: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", port))
            return True
        except OSError:
            time.sleep(0.05)
        finally:
            probe.close()
    return False


def test_receiver_replay_authority_cannot_be_recreated_after_state_exists(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    identity = _prepare_sensitive_receiver_replay_authority(state_dir)
    (state_dir / "authorization.db").write_bytes(b"rolled-back-valid-snapshot")

    shutil.rmtree(identity["root"])
    Path(identity["anchor_path"]).unlink()

    with pytest.raises(JunoPrivateReadError):
        _prepare_sensitive_receiver_replay_authority(state_dir)


def test_parent_death_pipe_reaps_exact_signal_ignoring_child_and_releases_3011() -> None:
    child = Path(__file__).parents[1] / "fixtures" / "juno_parent_death_child.mjs"
    port = 3011
    preflight = socket.socket()
    try:
        preflight.bind(("127.0.0.1", port))
    except PermissionError:
        pytest.skip("execution sandbox denied parent-death loopback gate")
    except OSError as exc:
        pytest.fail(f"stale unknown listener owns sensitive port 3011: {exc}")
    finally:
        preflight.close()

    parent = _parent_death_supervisor(child, port)
    replacement = None
    child_pid = None
    replacement_child_pid = None
    try:
        line = _readline_bounded(parent)
        if not line:
            stderr = parent.stderr.read()
            if "operation not permitted" in stderr.lower():
                pytest.skip("execution sandbox denied parent-death child listen")
            pytest.fail(f"parent-death child failed to start: {stderr[:512]}")
        ready = json.loads(line)
        child_pid = ready["child_pid"]
        assert ready["child_ready"] == {"pid": child_pid, "live": True}
        os.kill(parent.pid, signal.SIGKILL)
        parent.wait(timeout=3)
        assert _wait_port_released(port)
        deadline = time.monotonic() + 5
        while _pid_exists(child_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _pid_exists(child_pid), "exact orphaned sensitive child survived parent death"

        replacement = _parent_death_supervisor(child, port)
        replacement_line = _readline_bounded(replacement)
        assert replacement_line
        replacement_ready = json.loads(replacement_line)
        replacement_child_pid = replacement_ready["child_pid"]
        assert replacement_child_pid != child_pid
        assert replacement_ready["child_ready"]["live"] is True
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=3)
        if replacement is not None and replacement.poll() is None:
            replacement.kill()
            replacement.wait(timeout=3)
        if replacement_child_pid is not None:
            deadline = time.monotonic() + 5
            while _pid_exists(replacement_child_pid) and time.monotonic() < deadline:
                time.sleep(0.05)
            if _pid_exists(replacement_child_pid):
                os.kill(replacement_child_pid, signal.SIGKILL)
                pytest.fail("replacement parent left a descendant after control EOF")
        if child_pid is not None:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


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
async def test_three_stale_starts_reap_then_valid_start_survives_slow_surface_check(
    tmp_path, monkeypatch,
) -> None:
    """Cold tool discovery must not starve the ordinary fence refresh task."""
    import gateway.juno_private_read_mvp as mvp
    from tools.private_read_request_tool import check_private_read_request_runtime

    runner = _runner(tmp_path)
    runner._shutdown_event = asyncio.Event()
    runner._background_tasks = set()
    runner._trusted_private_read_reconcile_lock = asyncio.Lock()

    class RefreshingAdapter:
        def __init__(self) -> None:
            self.last_refresh = time.monotonic()

        def private_read_sender_companion_fence_healthy(self, profile: str) -> bool:
            return profile == "juno" and time.monotonic() - self.last_refresh < 0.5

        async def send(self, _destination: str, _text: str):
            return SimpleNamespace(success=True, message_id="ordinary-notice")

    adapter = RefreshingAdapter()
    topology = _Topology(adapter, "ordinary-live")
    runner.adapters[Platform.WHATSAPP] = adapter
    runner._current_juno_private_read_topology = lambda: (
        topology
        if adapter.private_read_sender_companion_fence_healthy("juno")
        else None
    )

    supervisors = []

    class Supervisor:
        def __init__(self, _config, _topology) -> None:
            self.process = SimpleNamespace(
                pid=10_000 + len(supervisors), state="running", control_open=True,
            )
            self.reaped = None
            self.stop_count = 0
            supervisors.append(self)

        async def start(self) -> bool:
            return not any(
                os.environ.get(name) == "1"
                for name in (
                    "JUNO_TEST_SENSITIVE_STALE_CAPABILITY",
                    "JUNO_TEST_SENSITIVE_STALE_TOPOLOGY",
                    "JUNO_TEST_SENSITIVE_STALE_PROCESS_GENERATION",
                )
            )

        async def stop(self) -> None:
            self.stop_count += 1
            process, self.process = self.process, None
            if process is not None:
                process.control_open = False
                process.state = "reaped"
                self.reaped = process

        def healthy(self) -> bool:
            return self.process is not None and self.process.state == "running"

        async def refresh(self) -> bool:
            return self.healthy()

        async def observe_identity(self, *, request):
            del request
            return None

        async def submit(self, *, request, plaintext, identity):
            del request, plaintext, identity
            raise AssertionError("startup recovery must not submit")

    monkeypatch.setattr(mvp, "_SensitiveBridgeSupervisor", Supervisor)

    def slow_private_tool_surface_check() -> bool:
        time.sleep(0.75)
        return check_private_read_request_runtime()

    monkeypatch.setattr(
        mvp, "private_read_tool_surface_is_closed", slow_private_tool_surface_check,
    )

    async def refresh_fence() -> None:
        while True:
            adapter.last_refresh = time.monotonic()
            await asyncio.sleep(0.005)

    refresh_task = asyncio.create_task(refresh_fence())
    try:
        for stale_environment in (
            "JUNO_TEST_SENSITIVE_STALE_CAPABILITY",
            "JUNO_TEST_SENSITIVE_STALE_TOPOLOGY",
            "JUNO_TEST_SENSITIVE_STALE_PROCESS_GENERATION",
        ):
            monkeypatch.setenv(stale_environment, "1")
            await asyncio.sleep(0.01)
            assert not await runner._start_trusted_private_read_host()
            assert runner._trusted_private_read_host is None
            rejected = supervisors[-1]
            assert rejected.process is None
            assert rejected.reaped is not None
            assert rejected.reaped.state == "reaped"
            assert rejected.reaped.control_open is False
            reconcile_task = runner._trusted_private_read_reconciler_task
            assert reconcile_task is not None
            assert await runner._stop_juno_private_read_reconciler()
            assert reconcile_task.done()
            monkeypatch.delenv(stale_environment)

        await asyncio.sleep(0.01)
        assert await runner._start_trusted_private_read_host()
        assert runner._trusted_private_read_host is not None
        assert len(supervisors) == 4
        assert all(item.stop_count == 1 for item in supervisors[:3])
        assert supervisors[3].healthy()
    finally:
        await runner._stop_juno_private_read_reconciler()
        await runner._depublish_juno_private_read_generation()
        refresh_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await refresh_task


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
async def test_reconciler_cancellation_joins_bounded_then_caller_depublishes(
    tmp_path, monkeypatch,
) -> None:
    runner = _runner(tmp_path)
    adapter = _Adapter()
    adapter.topology = _Topology(adapter, "ordinary-a")
    runner._current_juno_private_read_topology = lambda: adapter.topology
    runner._shutdown_event = asyncio.Event()
    runner._background_tasks = set()
    runner._trusted_private_read_reconciler_task = None
    host = _Host("ordinary-a")
    supervisor = _Supervisor()

    async def activate(_topology):
        return host, supervisor

    monkeypatch.setattr(runner, "_activate_juno_private_read_generation", activate)
    runner._ensure_juno_private_read_reconciler()
    task = runner._trusted_private_read_reconciler_task
    for _ in range(50):
        if runner._trusted_private_read_host is host:
            break
        await asyncio.sleep(0)
    assert runner._trusted_private_read_host is host
    assert await asyncio.wait_for(
        runner._stop_juno_private_read_reconciler(), timeout=2.5
    )
    assert task.done()
    assert all(item.get_name() != "juno-private-read-reconciler"
               for item in asyncio.all_tasks() if not item.done())
    await runner._depublish_juno_private_read_generation()
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

        class Control:
            closed = False

            def close(self):
                self.closed = True

        stdin = Control()

        def poll(self):
            return 0 if self.stopped else None

        def terminate(self):
            self.stopped = True

        def kill(self):
            self.stopped = True

        def wait(self):
            return 0

    process = Process()
    popen_calls = []

    def popen(*args, **kwargs):
        popen_calls.append((args, kwargs))
        return process

    monkeypatch.setattr("gateway.juno_private_read_mvp.subprocess.Popen", popen)

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
    replay_identity = _prepare_sensitive_receiver_replay_authority(config.state_dir)
    assert replay_identity["root"].endswith("sensitive-receiver-replay")
    assert not await supervisor.start()
    assert len(popen_calls) == 1
    assert popen_calls[0][1]["stdin"] == subprocess.PIPE
    assert process.stopped
    assert supervisor.process is None


@pytest.mark.asyncio
async def test_supervisor_start_cancellation_propagates_after_bounded_child_reap(
    tmp_path, monkeypatch,
) -> None:
    config = replace(
        JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path)), request_timeout=2,
    )
    ordinary = tmp_path / "cancel-ordinary-session"
    sensitive = tmp_path / "cancel-sensitive-session"
    ordinary.mkdir(mode=0o700)
    sensitive.mkdir(mode=0o700)
    topology = JunoOrdinaryRuntimeTopology(
        adapter=object(), adapter_generation="b" * 64,
        ordinary_runtime_id="ordinary-runtime", ordinary_socket_generation=1,
        ordinary_account_phone=config.ordinary_account,
        ordinary_account_lid="44444444444@lid",
        ordinary_session_path=str(ordinary),
        ordinary_session_identity=(
            f"{ordinary.stat().st_dev}:{ordinary.stat().st_ino}"
        ),
        ordinary_manifest_sha256="c" * 64,
        ordinary_source_sha256="d" * 64,
        ordinary_launcher_sha256="e" * 64,
        sensitive_session_path=str(sensitive),
        sensitive_session_identity=(
            f"{sensitive.stat().st_dev}:{sensitive.stat().st_ino}"
        ),
    )

    class Process:
        stopped = False

        class Control:
            closed = False

            def close(self):
                self.closed = True

        stdin = Control()

        def poll(self):
            return 0 if self.stopped else None

        def terminate(self):
            self.stopped = True

        def kill(self):
            self.stopped = True

        def wait(self):
            return 0

    process = Process()
    monkeypatch.setattr(
        "gateway.juno_private_read_mvp.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )
    supervisor = _SensitiveBridgeSupervisor(config, topology)
    probing = asyncio.Event()

    async def blocked_probe():
        probing.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(supervisor, "_probe_identity", blocked_probe)
    task = asyncio.create_task(supervisor.start())
    await asyncio.wait_for(probing.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=2)
    assert task.done()
    assert process.stdin.closed
    assert process.stopped
    assert supervisor.process is None
