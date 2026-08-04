"""Behavior and adversarial process tests for sensitive delivery."""

from __future__ import annotations

import asyncio
import builtins
import copy
from contextvars import ContextVar
from dataclasses import asdict, astuple, fields, is_dataclass, replace
import fcntl
import gc
import hashlib
import hmac
import inspect
import json
import logging
import os
from pathlib import Path
import pickle
import secrets
import signal
import sqlite3
import socket
import subprocess
import sys
import tempfile
import threading
import time
import weakref

import pytest

import gateway.sensitive_delivery as sensitive_delivery
from gateway.config import Platform
from gateway.authorization_contracts import (
    ClaimIdentity,
    CoordinatorIdentity,
    ExternalPdpDecisionResult,
    NotificationAttemptSpec,
    OwnerDecision,
    ProviderAcceptanceEvidence,
    TrustedAuthorizationBinding,
)
from gateway.authorization_tasks import AuthorizationTaskStore
from gateway.authorization_sensitive_delivery import (
    AuthorizationSensitiveDeliveryBridge,
)
from gateway.platforms.base import BasePlatformAdapter, SendResult
from gateway.platforms.base import MessageEvent
from gateway.private_read_authorization import TrustedPrivateReadHostContext
from gateway.session import SessionSource
from gateway.sensitive_delivery import (
    MAX_SENSITIVE_EVIDENCE_BYTES,
    MAX_SENSITIVE_PLAINTEXT_BYTES,
    MAX_SENSITIVE_STDIN_BYTES,
    PreparedSensitiveDelivery,
    SensitiveDeliveryAcceptanceStatus,
    SensitiveDeliveryAccountBinder,
    SensitiveDeliveryAuthorizationProvenance,
    SensitiveDeliveryDestinationEvidenceVerifier,
    SensitiveDeliveryDestination,
    SensitiveDeliveryErrorCode,
    SensitiveDeliveryHostAuthority,
    SensitiveDeliveryOutcome,
    SensitiveDeliveryProcessLease,
    SensitiveDeliveryReceipt,
    SensitiveDeliveryRouter,
    SensitiveDeliveryRuntimeIdentity,
    SensitiveDeliveryLoopbackAccountProbe,
    SensitiveDeliverySendGrant,
    SensitiveDeliveryTransportCommand,
    SensitiveDeliveryTransportRegistration,
    SensitiveDeliveryTransportRegistry,
)
from gateway.trusted_private_read_host import (
    TrustedPrivateReadGatewayHost,
    TrustedPrivateReadHostConfig,
    TrustedPrivateReadHostServices,
)
from tools.private_read_request_tool import (
    PRIVATE_READ_REQUEST_TOOL_NAME,
    configure_private_read_request_runtime,
)
from tools.registry import registry


SECRET = "private-content-sentinel-9f2d6n"
ACCOUNT = "sensitive-account@example.test"
AUTH_KEY = b"authorization-key-material-" + b"a" * 32
RECEIPT_KEY = b"receipt-key-material-" + b"r" * 32
BIND_KEY = b"binding-key-material-" + b"b" * 32
PROBE_KEY = b"probe-key-material-" + b"p" * 32
AUDIT_KEY = b"audit-key-material-" + b"a" * 32
REQUEST_KEY = b"request-key-material-" + b"q" * 32
NOW_US = 1_786_363_200_000_000
COORDINATOR = CoordinatorIdentity("gateway-host", "c" * 32)
RECEIPT_FIELDS = (
    "outcome",
    "error_code",
    "provenance",
    "destination",
    "attempt",
    "provider_message_id",
    "non_acceptance_provider_message_id",
    "submission_id",
    "evidence_id",
    "acceptance_status",
    "acceptance_signal",
    "non_acceptance_signal",
    "acceptance_observed_us",
    "provider_observed_us",
    "_seal",
)

# Every subprocess in this file is a freshly-created executable under
# ``tmp_path``.  The production contract intentionally creates a new session,
# so the repository's broad live-system guard must allow these exact killpg
# lifecycle tests to exercise the real process group.
pytestmark = pytest.mark.live_system_guard_bypass


_CHILD = r'''#!/usr/bin/env python3
import json
import os
import signal
import sys
import time

mode = sys.argv[1]
pid_path = sys.argv[2]
marker_path = sys.argv[3]
with open(pid_path + ".tmp", "w", encoding="ascii") as handle:
    handle.write(str(os.getpid()))
os.replace(pid_path + ".tmp", pid_path)
if mode == "early_exit":
    os._exit(7)
header = json.loads(sys.stdin.buffer.readline().decode("utf-8"))
payload = sys.stdin.buffer.read(header["payload_bytes"])
correlation_fields = (
    "attempt_id", "authorization_task_id", "correlation_id", "operation_id",
    "authorization_binding_digest", "request_digest", "request_key_version",
    "worker_profile", "worker_agent", "worker_account", "claim_nonce",
    "claim_generation", "destination_profile", "destination_platform",
    "transport_implementation_id", "destination_chat_id",
    "destination_thread_id", "destination_account_binding_token",
    "connection_epoch", "runtime_instance_token", "process_identity",
    "session_identity", "account_observation_id", "account_observed_at_us",
)

def make_evidence(signal_name):
    evidence = {"version": 1}
    evidence.update({name: header[name] for name in correlation_fields})
    evidence.update({
        "origin": "destination",
        "signal": signal_name,
        "provider_message_id": "provider-message-1",
        "submission_id": "submission-1",
        "evidence_id": "evidence-1",
        "provider_observed_us": 1786363200000000,
    })
    return evidence

if mode == "hostile":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    retained_plaintext = payload
    time.sleep(3.0)
    with open(marker_path, "wb") as handle:
        handle.write(b"delayed-send:" + retained_plaintext)
    time.sleep(30)
elif mode in ("forking", "forking_hostile"):
    descendant = os.fork()
    if descendant == 0:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(2.0 if mode == "forking_hostile" else 1.0)
        with open(marker_path, "wb") as handle:
            handle.write(b"detached-send:" + payload)
        time.sleep(30)
        os._exit(0)
    with open(pid_path + ".descendant.tmp", "w", encoding="ascii") as handle:
        handle.write(str(descendant))
    os.replace(pid_path + ".descendant.tmp", pid_path + ".descendant")
    if mode == "forking_hostile":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(30)
    signal_name = "baileys.delivery_ack"
    evidence = make_evidence(signal_name)
    sys.stdout.write(json.dumps(evidence, separators=(",", ":")))
elif mode == "malformed":
    sys.stdout.write("not-json")
elif mode == "overflow":
    sys.stdout.write("x" * 20000)
else:
    signal_name = mode
    evidence = make_evidence(signal_name)
    # A malicious independent transport status is intentionally ignored.
    if signal_name == "baileys.server_ack":
        evidence["status"] = "accepted"
    sys.stdout.write(json.dumps(evidence, separators=(",", ":")))
'''


_SIDECAR = r'''#!/usr/bin/env python3
import os
import signal
import sys
import time

descendant_path = sys.argv[1]
descendant = os.fork()
if descendant == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(30)
    os._exit(0)
with open(descendant_path + ".tmp", "w", encoding="ascii") as handle:
    handle.write(str(descendant))
os.replace(descendant_path + ".tmp", descendant_path)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(30)
'''


_PROBE_FAKES = []


@pytest.fixture(autouse=True)
def _close_probe_fakes():
    yield
    while _PROBE_FAKES:
        probe, sidecar_socket, thread = _PROBE_FAKES.pop()
        probe.close()
        sidecar_socket.close()
        thread.join(timeout=1)
        assert not thread.is_alive()


def _live_probe(binder, **state_overrides):
    raw_response_transform = state_overrides.pop("raw_response_transform", None)
    host_socket, sidecar_socket = socket.socketpair()
    probe = SensitiveDeliveryLoopbackAccountProbe(
        connected_socket=host_socket,
        probe_hmac_key=PROBE_KEY,
        account_binder=binder,
        timeout_seconds=1.0,
    )
    state = {
        "account_identity": ACCOUNT,
        "runtime_instance_token": "runtime-registration-1",
        "process_identity": "provider-sidecar-process-1",
        "session_identity": "provider-session-1",
        "connection_epoch": 1,
        "observed_at_us": NOW_US,
    }
    state.update(state_overrides)

    def serve_probe():
        buffered = bytearray()
        try:
            while True:
                while b"\n" not in buffered:
                    chunk = sidecar_socket.recv(4096)
                    if not chunk:
                        return
                    buffered.extend(chunk)
                raw, _, remainder = buffered.partition(b"\n")
                buffered = bytearray(remainder)
                request = json.loads(raw.decode("ascii"))
                response = {
                    "version": 1,
                    "challenge": request["challenge"],
                    **state,
                }
                signed = tuple(response[name] for name in (
                    "challenge", "account_identity", "runtime_instance_token",
                    "process_identity", "session_identity", "connection_epoch",
                    "observed_at_us",
                ))
                response["signature"] = probe._signature(signed)
                encoded = json.dumps(
                    response, sort_keys=True, separators=(",", ":")
                ).encode("ascii")
                if raw_response_transform is not None:
                    encoded = raw_response_transform(encoded)
                sidecar_socket.sendall(encoded + b"\n")
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    thread = threading.Thread(target=serve_probe, daemon=False)
    thread.start()
    _PROBE_FAKES.append((probe, sidecar_socket, thread))
    return probe


def _stalled_probe(binder, *, timeout_seconds):
    host_socket, sidecar_socket = socket.socketpair()
    probe = SensitiveDeliveryLoopbackAccountProbe(
        connected_socket=host_socket,
        probe_hmac_key=PROBE_KEY,
        account_binder=binder,
        timeout_seconds=timeout_seconds,
    )
    request_seen = threading.Event()

    def serve_stalled_probe():
        buffered = bytearray()
        try:
            while b"\n" not in buffered:
                chunk = sidecar_socket.recv(4096)
                if not chunk:
                    return
                buffered.extend(chunk)
            request_seen.set()
            while sidecar_socket.recv(4096):
                pass
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    thread = threading.Thread(target=serve_stalled_probe, daemon=False)
    thread.start()
    _PROBE_FAKES.append((probe, sidecar_socket, thread))
    return probe, request_seen, thread


def _write_child(tmp_path):
    child = tmp_path / "sensitive-child.py"
    child.write_text(_CHILD)
    child.chmod(0o700)
    return child


def _spawn_sidecar(tmp_path):
    child = tmp_path / f"sidecar-{secrets.token_hex(4)}.py"
    descendant_path = child.with_suffix(".descendant")
    child.write_text(_SIDECAR)
    child.chmod(0o700)
    process = subprocess.Popen(
        [str(child), str(descendant_path)],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return process, descendant_path


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _authority():
    return SensitiveDeliveryHostAuthority(AUTH_KEY, RECEIPT_KEY)


def _destination(binder=None, **overrides):
    binder = binder or SensitiveDeliveryAccountBinder(BIND_KEY)
    values = {
        "authorization_task_id": "authorization-task-1",
        "operation_id": "operation-1",
        "profile": "default",
        "platform": Platform.WHATSAPP,
        "account_binding_token": binder.bind_sensitive_account(Platform.WHATSAPP, ACCOUNT),
        "chat_id": "447700900001@s.whatsapp.net",
        "thread_id": "delivery-thread-1",
    }
    values.update(overrides)
    return SensitiveDeliveryDestination(**values)


def _registration(tmp_path, *, mode="baileys.delivery_ack", child=None, **overrides):
    child = child or _write_child(tmp_path)
    binder = SensitiveDeliveryAccountBinder(BIND_KEY)
    destination = _destination(binder)
    pid_path = tmp_path / f"{mode.replace('.', '-')}.pid"
    marker_path = tmp_path / f"{mode.replace('.', '-')}.marker"
    command = SensitiveDeliveryTransportCommand(
        str(child.resolve()),
        _digest(child),
        (mode, str(pid_path), str(marker_path)),
    )
    identity = SensitiveDeliveryRuntimeIdentity(
        "default",
        Platform.WHATSAPP,
        "tests.audited-baileys:v1",
        "runtime-registration-1",
        "provider-sidecar-process-1",
        "provider-session-1",
        destination.account_binding_token,
        1,
    )
    verifier = SensitiveDeliveryDestinationEvidenceVerifier(
        identity="tests.destination-evidence:v1",
        accepted_signals=(
            "baileys.delivery_ack",
            "baileys.read",
            "baileys.played",
        ),
        rejected_signals=("baileys.rejected",),
    )
    values = {
        "command": command,
        "identity": identity,
        "verifier": verifier,
        "verifier_type": SensitiveDeliveryDestinationEvidenceVerifier,
        "verifier_identity": verifier.identity,
        "account_probe": _live_probe(binder),
        "max_sensitive_payload_bytes": MAX_SENSITIVE_PLAINTEXT_BYTES,
        "max_stdout_bytes": MAX_SENSITIVE_EVIDENCE_BYTES,
        "max_stderr_bytes": 4096,
    }
    values.update(overrides)
    return SensitiveDeliveryTransportRegistration(**values), pid_path, marker_path


def _authorization_binding(registration, destination, **overrides):
    identity = registration.identity
    values = {
        "task_id": destination.authorization_task_id,
        "correlation_id": "correlation-1",
        "tool_call_id": "tool-call-1",
        "requester_profile": "requester-profile",
        "requester_agent": "requester-agent",
        "source_platform": "authenticated-api",
        "source_account": "source-account",
        "source_user": "source-user",
        "source_chat": "source-chat",
        "source_thread": "source-thread",
        "source_message": "source-message",
        "source_provenance": "authenticated_internal",
        "operation": destination.operation_id,
        "resource_type": "private-record",
        "resource_id": "resource-1",
        "fields": ("private-field",),
        "parameter_fingerprint": "a" * 64,
        "approval_profile": "owner-profile",
        "approval_account": "owner-account",
        "approval_user": "owner-user",
        "approval_chat": "owner-chat",
        "approval_thread": "owner-thread",
        "delivery_profile": destination.profile,
        "delivery_account": ACCOUNT,
        "delivery_chat": destination.chat_id,
        "delivery_thread": destination.thread_id,
        "created_at_us": NOW_US - 2_000_000,
        "expires_at_us": NOW_US + 60_000_000,
        "pdp_identity": "pdp-1",
        "policy_identity": "tests.sensitive",
        "model_identity": "decision-model-1",
        "delivery_platform": destination.platform.value,
        "delivery_transport_implementation": identity.transport_implementation_id,
        "delivery_runtime_identity": identity.runtime_instance_token,
        "delivery_account_binding": destination.account_binding_token,
        "delivery_connection_epoch": identity.connection_epoch,
        "policy_version": "policy-v1",
        "policy_hash": "b" * 64,
    }
    values.update(overrides)
    return TrustedAuthorizationBinding(**values)


def _notification_claim(nonce):
    return ClaimIdentity("owner-profile", "notification-worker", "owner-account", nonce, 1)


def _claimed_bridge(tmp_path, registration, authority, destination=None):
    destination = destination or _destination()
    binding = _authorization_binding(registration, destination)
    root = tmp_path / f"authorization-{secrets.token_hex(5)}"
    root.mkdir(mode=0o700)
    store = AuthorizationTaskStore(
        db_path=(root / "authorization.db").absolute(),
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="key-v1",
    )
    lock = store.acquire_coordinator_lock()
    assert lock is not None
    assert store.acquire_coordinator(
        COORDINATOR,
        now_us=NOW_US - 3_000_000,
        lease_expires_at_us=NOW_US + 120_000_000,
        lock_session=lock,
    ) is not None
    challenge_id = "challenge-" + binding.task_id
    challenge_nonce = challenge_id + "-" + "n" * 32
    challenge = NotificationAttemptSpec(
        attempt_id=challenge_id,
        challenge_generation=1,
        kind="approval_challenge",
        destination_profile=binding.approval_profile,
        destination_account=binding.approval_account,
        destination_chat=binding.approval_chat,
        destination_thread=binding.approval_thread,
        created_at_us=NOW_US - 1_900_000,
        due_at_us=NOW_US - 1_800_000,
        challenge_nonce=challenge_nonce,
    )
    store.create_pending(binding, request_key="request-key", notification=challenge)
    notification_worker = _notification_claim("notification-claim-" + "n" * 32)
    store.claim_notification(
        challenge_id,
        notification_worker,
        now_us=NOW_US - 1_700_000,
        lease_expires_at_us=NOW_US - 1_400_000,
    )
    store.record_notification_send_started(
        challenge_id, notification_worker, now_us=NOW_US - 1_600_000
    )
    store.finish_notification(
        challenge_id,
        notification_worker,
        now_us=NOW_US - 1_500_000,
        outcome="provider_accepted",
        receipt_code="provider_accepted",
        evidence=ProviderAcceptanceEvidence(
            task_id=binding.task_id,
            correlation_id=binding.correlation_id,
            attempt_id=challenge_id,
            challenge_generation=1,
            worker_claim_generation=1,
            status="provider_accepted",
            provider_message_id="provider-" + challenge_id,
            accepted_at_us=NOW_US - 1_550_000,
            adapter_instance_id="approval-adapter-1",
            account_binding=binding.approval_account,
            connection_epoch=1,
            destination_profile=binding.approval_profile,
            destination_account=binding.approval_account,
            destination_chat=binding.approval_chat,
            destination_thread=binding.approval_thread,
        ),
    )
    decision = OwnerDecision(
        decision_id="decision-" + binding.task_id,
        task_id=binding.task_id,
        correlation_id=binding.correlation_id,
        owner_profile=binding.approval_profile,
        owner_account=binding.approval_account,
        owner_user=binding.approval_user,
        owner_chat=binding.approval_chat,
        owner_thread=binding.approval_thread,
        source_message="owner-message",
        provenance="authenticated_reply",
        challenge_attempt_id=challenge_id,
        challenge_generation=1,
        challenge_nonce=challenge_nonce,
        challenge_provider_message_id="provider-" + challenge_id,
        reply_to_provider_message_id="provider-" + challenge_id,
        adapter_instance_id="approval-adapter-1",
        account_binding=binding.approval_account,
        connection_epoch=1,
    )
    resolution = NotificationAttemptSpec(
        attempt_id="resolution-" + binding.task_id,
        challenge_generation=1,
        kind="approval_resolution",
        destination_profile=binding.approval_profile,
        destination_account=binding.approval_account,
        destination_chat=binding.approval_chat,
        destination_thread=binding.approval_thread,
        created_at_us=NOW_US - 1_300_000,
        due_at_us=NOW_US - 1_300_000,
        challenge_nonce="resolution-" + binding.task_id,
    )
    assert store.approve(
        binding.task_id,
        binding,
        decision,
        resolution_notification=resolution,
        now_us=NOW_US - 1_300_000,
    ).applied
    claim = ClaimIdentity("default", "delivery-worker", ACCOUNT, "claim-" + "c" * 32, 1)
    assert store.claim(
        binding.task_id,
        binding,
        claim,
        now_us=NOW_US - 1_200_000,
        lease_expires_at_us=NOW_US + 30_000_000,
        pdp_evidence=_pdp_evidence(store, binding, claim, "pre_claim", NOW_US - 1_200_000),
    ).applied
    return AuthorizationSensitiveDeliveryBridge(
        store=store,
        binding=binding,
        claim=claim,
        host_authority=authority,
        wall_clock_us=lambda: NOW_US,
    )


def _pdp_evidence(store, binding, claim, stage, now_us):
    context = store.create_pdp_check_context(
        binding.task_id,
        claim,
        stage=stage,
        now_us=now_us,
    )
    result = ExternalPdpDecisionResult(
        context_id=context.context_id,
        pdp_call_id=context.pdp_call_id,
        decision="allow",
        checked_at_us=now_us,
        consistency="strongest",
        cache_used=False,
    )
    return store.create_pdp_decision_evidence(context, claim, result)


def _router(tmp_path, *, registration=None, authority=None, bridge=None, destination=None, **kwargs):
    authority = authority or _authority()
    if registration is None:
        registration, _, _ = _registration(tmp_path)
    registry = SensitiveDeliveryTransportRegistry([registration], max_registrations=1)
    bridge = bridge or _claimed_bridge(tmp_path, registration, authority, destination)
    return SensitiveDeliveryRouter(
        transport_registry=registry,
        authorization_bridge=bridge,
        **kwargs,
    )


async def _prepare(router):
    prepared = await router.prepare()
    if type(prepared) is PreparedSensitiveDelivery:
        bridge = router._bridge
        evidence = _pdp_evidence(
            bridge._store,
            bridge.binding,
            bridge.claim,
            "pre_private_read",
            NOW_US - 100_000,
        )
        assert prepared.authorize_private_read(evidence, now_us=NOW_US - 100_000)
    return prepared


async def _deliver(router, plaintext=SECRET):
    prepared = await _prepare(router)
    assert type(prepared) is PreparedSensitiveDelivery
    return await prepared.deliver(plaintext)


def _pid_exists(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _process_group_exists(process_group_id):
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _is_direct_child_or_zombie(pid):
    try:
        waited_pid, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return False
    return waited_pid in (0, pid)


@pytest.mark.asyncio
async def test_raw_child_cleanup_does_not_require_waitid(
    tmp_path,
    monkeypatch,
):
    # This is already absent on the supported macOS Python 3.11 runtime.  On
    # runtimes that expose it, remove it so the same portable path is tested.
    monkeypatch.delattr(os, "waitid", raising=False)
    assert not hasattr(os, "waitid")
    baseline_fds = _open_fds()
    before_launches = _staged_launch_paths()

    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            time.sleep(30)
        finally:
            os._exit(0)
    raw_child = sensitive_delivery._DirectChildOwnership(pid)
    sensitive_delivery._cleanup_raw_fork_child(
        raw_child,
        time.monotonic() + 0.5,
        0.01,
        time.monotonic,
    )
    assert raw_child.state == "reaped"
    assert not _is_direct_child_or_zombie(pid)
    assert not _process_group_exists(pid)

    def forbidden_signal(*args, **kwargs):
        raise AssertionError("completed ownership must never signal its numeric PID")

    with monkeypatch.context() as repeated_cleanup:
        repeated_cleanup.setattr(os, "kill", forbidden_signal)
        repeated_cleanup.setattr(os, "killpg", forbidden_signal)
        sensitive_delivery._cleanup_raw_fork_child(
            raw_child,
            time.monotonic() + 0.5,
            0.01,
            time.monotonic,
        )

    assert _open_fds() == baseline_fds
    assert _staged_launch_paths() == before_launches
    assert not _sensitive_delivery_tasks()


async def _read_pid(path, timeout=5.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        try:
            value = path.read_text()
            if value:
                return int(value)
        except (FileNotFoundError, ValueError):
            pass
        if asyncio.get_running_loop().time() >= deadline:
            raise AssertionError(f"timed out reading PID from {path}")
        await asyncio.sleep(0.005)


def _spawn_aware_clock(pid_path):
    frozen = time.monotonic()
    running_started = None

    def monotonic():
        nonlocal running_started
        now = time.monotonic()
        if not pid_path.exists():
            return frozen
        if running_started is None:
            running_started = now
        return frozen + (now - running_started)

    return monotonic


def _sensitive_delivery_tasks():
    return {
        task
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task()
        and not task.done()
        and task.get_name().startswith("sensitive-delivery")
    }


def _open_fds():
    descriptors = set()
    for descriptor in range(256):
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError:
            continue
        descriptors.add(descriptor)
    return descriptors


def _open_fd_count():
    return len(_open_fds())


def _open_fd_targets():
    targets = []
    for descriptor in _open_fds():
        try:
            targets.append(os.readlink(f"/dev/fd/{descriptor}"))
        except OSError:
            pass
    return targets


def _staged_launch_paths():
    return set(Path(tempfile.gettempdir()).glob("hermes-sensitive-delivery-*"))


async def _wait_for_owned_spawn(pids, timeout=0.5):
    deadline = time.monotonic() + timeout
    while not pids:
        if time.monotonic() >= deadline:
            raise AssertionError("router never published ownership of the fork child")
        await asyncio.sleep(0)


def _stall_exec_after_owned_fork(monkeypatch, marker_path, pids):
    real_spawn = SensitiveDeliveryRouter._spawn

    def track_spawn(
        self,
        attempt_id,
        executable,
        arguments,
        deadline,
        cleanup_deadline,
    ):
        process = real_spawn(
            self,
            attempt_id,
            executable,
            arguments,
            deadline,
            cleanup_deadline,
        )
        pids.append(process.pid)
        return process

    def cancellation_ignoring_exec(executable, arguments, environment):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(1.0)
        marker_path.write_text("late-exec-work", encoding="ascii")
        time.sleep(30)

    monkeypatch.setattr(SensitiveDeliveryRouter, "_spawn", track_spawn)
    monkeypatch.setattr(os, "execve", cancellation_ignoring_exec)


def _receipt_values(receipt):
    return {
        name: getattr(receipt, name)
        for name in RECEIPT_FIELDS
        if name != "_seal"
    }


def _task_frames_contain(secret):
    for task in asyncio.all_tasks():
        if task is asyncio.current_task() or task.done():
            continue
        stack = task.get_stack(limit=100)
        for frame in stack:
            for name, value in frame.f_locals.items():
                if name in {"secret", "plaintext", "payload"} and secret in repr(value):
                    return True
    return False


def test_default_inert_and_no_ordinary_gateway_surface():
    assert not hasattr(BasePlatformAdapter, "sensitive_delivery_capability")
    registry = SensitiveDeliveryTransportRegistry([], max_registrations=0)
    registration, code = registry.resolve(_destination())
    assert registration is None
    assert code is SensitiveDeliveryErrorCode.UNSUPPORTED


def test_registry_requires_finite_bounded_sequence(tmp_path):
    registration, _, _ = _registration(tmp_path)
    with pytest.raises(TypeError, match="finite sequence"):
        SensitiveDeliveryTransportRegistry(iter([registration]), max_registrations=1)
    with pytest.raises(ValueError, match="cap exceeded"):
        SensitiveDeliveryTransportRegistry([registration], max_registrations=0)


def test_registry_never_trusts_custom_length_or_iteration_and_rejects_duplicates(tmp_path):
    registration, _, _ = _registration(tmp_path)

    class DishonestSequence:
        iterated = False

        def __len__(self):
            return 0

        def __iter__(self):
            self.iterated = True
            while True:
                yield registration

    dishonest = DishonestSequence()
    with pytest.raises(TypeError, match="exact finite sequence"):
        SensitiveDeliveryTransportRegistry(dishonest, max_registrations=1)
    assert not dishonest.iterated
    with pytest.raises(ValueError, match="duplicate registration"):
        SensitiveDeliveryTransportRegistry(
            [registration, registration],
            max_registrations=2,
        )
    second_account = SensitiveDeliveryAccountBinder(BIND_KEY).bind_sensitive_account(
        Platform.WHATSAPP,
        "second-account@example.test",
    )
    second_identity = replace(
        registration.identity,
        runtime_instance_token="runtime-registration-2",
        account_binding_token=second_account,
    )
    second_registration = replace(registration, identity=second_identity)
    with pytest.raises(ValueError, match="process identities must be unique"):
        SensitiveDeliveryTransportRegistry(
            [registration, second_registration],
            max_registrations=2,
        )
    registry = SensitiveDeliveryTransportRegistry(
        (registration,),
        max_registrations=1,
    )
    assert registry.resolve(_destination())[0] is registration


def test_registry_cap_applies_to_exact_bounded_snapshot_under_append_race(
    tmp_path,
    monkeypatch,
):
    first, _, _ = _registration(tmp_path)
    second = replace(
        first,
        identity=replace(
            first.identity,
            runtime_instance_token="runtime-registration-2",
            process_identity="provider-sidecar-process-2",
            session_identity="provider-session-2",
            account_binding_token=SensitiveDeliveryAccountBinder(BIND_KEY).bind_sensitive_account(
                Platform.WHATSAPP,
                "second-account@example.test",
            ),
        ),
    )
    registrations = [first]
    raced = False

    def append_on_first_length(value):
        nonlocal raced
        original_length = builtins.len(value)
        if not raced:
            raced = True
            registrations.append(second)
        return original_length

    monkeypatch.setattr(
        sensitive_delivery,
        "len",
        append_on_first_length,
        raising=False,
    )
    registry = SensitiveDeliveryTransportRegistry(
        registrations,
        max_registrations=1,
    )
    assert raced and builtins.len(registrations) == 2
    assert registry._registrations == (first,)
    assert builtins.len(registry._registrations) <= registry._max_registrations


def test_registration_binds_exact_verifier_type_identity_and_digest(tmp_path):
    registration, _, _ = _registration(tmp_path)

    class ForgedVerifier(SensitiveDeliveryDestinationEvidenceVerifier):
        pass

    with pytest.raises(TypeError, match="exact host evidence verifier"):
        _registration(
            tmp_path,
            child=Path(registration.command.executable),
            verifier=ForgedVerifier(
                identity=registration.verifier.identity,
                accepted_signals=registration.verifier.accepted_signals,
                rejected_signals=registration.verifier.rejected_signals,
            ),
            verifier_type=SensitiveDeliveryDestinationEvidenceVerifier,
        )
    with pytest.raises(TypeError, match="exact host evidence verifier"):
        _registration(
            tmp_path,
            child=Path(registration.command.executable),
            verifier_identity="attacker-policy:v1",
        )


@pytest.mark.asyncio
async def test_host_verifies_request_hmac_before_claim_or_spawn(tmp_path):
    authority = _authority()
    registration, pid_path, _ = _registration(tmp_path)
    bridge = _claimed_bridge(tmp_path, registration, authority)
    forged = replace(
        bridge.provenance,
        request_hmac="hmac-sha256:v1:" + "0" * 64,
    )
    bridge.provenance = forged
    router = _router(
        tmp_path,
        registration=registration,
        authority=authority,
        bridge=bridge,
    )
    result = await _prepare(router)
    assert result.error_code is SensitiveDeliveryErrorCode.PROVENANCE_MISMATCH
    assert bridge._store.load_task(bridge.binding.task_id, bridge.binding).status == "failed_consumed"
    assert not pid_path.exists()
    await router.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("signal_name", "outcome", "code"),
    [
        ("baileys.delivery_ack", SensitiveDeliveryOutcome.ACCEPTED, None),
        ("baileys.read", SensitiveDeliveryOutcome.ACCEPTED, None),
        ("baileys.played", SensitiveDeliveryOutcome.ACCEPTED, None),
        ("baileys.server_ack", SensitiveDeliveryOutcome.AMBIGUOUS, SensitiveDeliveryErrorCode.ACCEPTANCE_UNCONFIRMED),
        ("baileys.sender_companion", SensitiveDeliveryOutcome.AMBIGUOUS, SensitiveDeliveryErrorCode.ACCEPTANCE_UNCONFIRMED),
        ("baileys.unknown", SensitiveDeliveryOutcome.AMBIGUOUS, SensitiveDeliveryErrorCode.ACCEPTANCE_UNCONFIRMED),
        ("baileys.rejected", SensitiveDeliveryOutcome.REJECTED, SensitiveDeliveryErrorCode.TRANSPORT_REJECTED),
    ],
)
async def test_exact_configured_destination_acceptance_policy(
    tmp_path, signal_name, outcome, code
):
    registration, _, _ = _registration(tmp_path, mode=signal_name)
    authority = _authority()
    router = _router(tmp_path, registration=registration, authority=authority)
    receipt = await _deliver(router)
    assert receipt.outcome is outcome
    assert receipt.error_code is code
    if outcome is SensitiveDeliveryOutcome.ACCEPTED:
        assert receipt.acceptance_signal == signal_name
        assert receipt.non_acceptance_signal is None
        assert authority.verify_receipt(receipt)
    else:
        assert receipt.acceptance_signal is None
        assert receipt.non_acceptance_signal == signal_name
        assert receipt.provider_message_id is None
        assert receipt.non_acceptance_provider_message_id == "provider-message-1"
    await router.aclose()


@pytest.mark.asyncio
async def test_forged_accepted_status_with_server_ack_cannot_accept(tmp_path):
    registration, _, _ = _registration(tmp_path, mode="baileys.server_ack")
    router = _router(tmp_path, registration=registration)
    receipt = await _deliver(router)
    assert receipt.outcome is SensitiveDeliveryOutcome.AMBIGUOUS
    assert receipt.error_code is SensitiveDeliveryErrorCode.ACCEPTANCE_UNCONFIRMED
    assert receipt.acceptance_status is SensitiveDeliveryAcceptanceStatus.UNKNOWN
    await router.aclose()


@pytest.mark.asyncio
async def test_duplicate_signal_evidence_is_malformed_before_acceptance(tmp_path):
    child = _write_child(tmp_path)
    source = child.read_text()
    replacement = (
        'encoded = json.dumps(evidence, separators=(",", ":"))\n'
        '    sys.stdout.write(encoded[:-1] + '
        '\',"signal":"baileys.delivery_ack"}\')'
    )
    child.write_text(
        source.replace(
            'sys.stdout.write(json.dumps(evidence, separators=(",", ":")))',
            replacement,
        )
    )
    child.chmod(0o700)
    registration, _, _ = _registration(
        tmp_path,
        mode="baileys.server_ack",
        child=child,
    )
    authority = _authority()
    router = _router(tmp_path, registration=registration, authority=authority)
    receipt = await _deliver(router)
    assert receipt.error_code is SensitiveDeliveryErrorCode.INVALID_EVIDENCE
    assert receipt.outcome is SensitiveDeliveryOutcome.AMBIGUOUS
    assert receipt.acceptance_status is SensitiveDeliveryAcceptanceStatus.UNKNOWN
    assert receipt.acceptance_signal is None
    assert not receipt.success
    assert authority.verify_receipt(receipt)
    await router.aclose()


def test_duplicate_evidence_keys_are_rejected_at_every_object_level():
    for raw in (
        b'{"signal":"baileys.server_ack","signal":"baileys.delivery_ack"}',
        b'{"outer":{"key":1,"key":2}}',
        b'{"outer":1,"outer":2}',
    ):
        with pytest.raises(ValueError, match="duplicate key"):
            sensitive_delivery._decode_closed_evidence(raw)


@pytest.mark.asyncio
async def test_success_receipt_has_host_time_full_seal_and_cannot_be_publicly_minted(tmp_path):
    authority = _authority()
    registration, _, _ = _registration(tmp_path)
    router = _router(tmp_path, registration=registration, authority=authority)
    receipt = await _deliver(router)
    assert receipt.success
    assert receipt.acceptance_observed_us == NOW_US
    assert receipt.provider_observed_us == NOW_US
    assert receipt.attempt.send_started_us <= receipt.acceptance_observed_us
    assert authority.verify_receipt(receipt)
    object.__setattr__(receipt, "evidence_id", "forged-evidence")
    assert not authority.verify_receipt(receipt)
    with pytest.raises(TypeError, match="minted only"):
        SensitiveDeliveryReceipt()
    assert not hasattr(SensitiveDeliveryReceipt, "_from_host")
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(receipt)
    await router.aclose()


@pytest.mark.asyncio
async def test_receipt_authority_accepts_only_the_exact_live_minted_object(tmp_path):
    authority = _authority()
    registration, _, _ = _registration(tmp_path)
    router = _router(tmp_path, registration=registration, authority=authority)
    receipt = await _deliver(router)
    assert authority.verify_receipt(receipt)

    clone = object.__new__(SensitiveDeliveryReceipt)
    for name in RECEIPT_FIELDS:
        object.__setattr__(clone, name, getattr(receipt, name))
    assert clone is not receipt
    assert clone.seal == receipt.seal
    assert not authority.verify_receipt(clone)
    assert authority.verify_receipt(receipt)
    assert not _authority().verify_receipt(receipt)

    issued = authority._SensitiveDeliveryHostAuthority__issued_receipts
    receipt_id = id(receipt)
    receipt_ref = weakref.ref(receipt)
    assert issued[receipt_id]() is receipt
    del receipt
    await asyncio.sleep(0)
    for _ in range(3):
        if receipt_ref() is None:
            break
        gc.collect()
    assert receipt_ref() is None
    assert receipt_id not in issued
    await router.aclose()


@pytest.mark.parametrize(
    "foreign_receipt",
    ({"success": True}, SendResult(success=True, message_id="ordinary-message")),
)
def test_bridge_maps_dict_and_ordinary_send_result_to_failed_consumed(
    tmp_path,
    foreign_receipt,
):
    registration, _, _ = _registration(tmp_path)
    bridge = _claimed_bridge(tmp_path, registration, _authority())
    assert bridge.finish_receipt(foreign_receipt, now_us=NOW_US)
    task = bridge._store.load_task(bridge.binding.task_id, bridge.binding)
    assert task.status == "failed_consumed"
    assert task.receipt_code == "internal_failure"


@pytest.mark.asyncio
async def test_bridge_rejects_a_cloned_live_receipt_before_evidence_conversion(
    tmp_path,
    monkeypatch,
):
    registration, _, _ = _registration(tmp_path)
    router = _router(tmp_path, registration=registration)
    bridge = router._bridge
    real_finish = AuthorizationSensitiveDeliveryBridge.finish_receipt
    monkeypatch.setattr(
        AuthorizationSensitiveDeliveryBridge,
        "finish_receipt",
        lambda self, receipt, *, now_us: True,
    )
    receipt = await _deliver(router)
    assert receipt.success
    monkeypatch.setattr(
        AuthorizationSensitiveDeliveryBridge,
        "finish_receipt",
        real_finish,
    )
    clone = object.__new__(SensitiveDeliveryReceipt)
    for name in RECEIPT_FIELDS:
        object.__setattr__(clone, name, getattr(receipt, name))
    assert not bridge.authority.verify_receipt(clone)
    assert bridge.finish_receipt(clone, now_us=NOW_US)
    task = bridge._store.load_task(bridge.binding.task_id, bridge.binding)
    assert task.status == "failed_consumed"
    assert task.receipt_code == "internal_failure"
    await router.aclose()


@pytest.mark.asyncio
async def test_receipt_rejects_generic_traversal_serialization_and_reconstruction(
    tmp_path,
):
    registration, _, _ = _registration(tmp_path)
    router = _router(tmp_path, registration=registration)
    receipt = await _deliver(router)
    assert not is_dataclass(receipt)
    for operation in (
        asdict,
        astuple,
        lambda value: replace(value, outcome=value.outcome),
        copy.copy,
        copy.deepcopy,
        pickle.dumps,
        vars,
        iter,
        tuple,
        json.dumps,
        lambda value: json.dumps(value, default=vars),
    ):
        with pytest.raises((TypeError, AttributeError)):
            operation(receipt)
    with pytest.raises(TypeError, match="minted only"):
        SensitiveDeliveryReceipt.__new__(SensitiveDeliveryReceipt)
    with pytest.raises(TypeError, match="immutable"):
        receipt.evidence_id = "replacement"
    assert weakref.ref(receipt)() is receipt
    await router.aclose()


@pytest.mark.asyncio
async def test_receipt_verifier_rejects_subclasses_ducks_reused_bindings_and_all_tampering(
    tmp_path,
):
    authority = _authority()
    registration, _, _ = _registration(tmp_path)
    router = _router(tmp_path, registration=registration, authority=authority)
    receipt = await _deliver(router)
    assert authority.verify_receipt(receipt)
    values = _receipt_values(receipt)

    class ForgedReceipt(SensitiveDeliveryReceipt):
        pass

    class DuckReceipt:
        def _seal_values(self):
            return receipt._seal_values()

        _seal = receipt.seal

    assert not authority.verify_receipt(object.__new__(ForgedReceipt))
    assert not authority.verify_receipt(DuckReceipt())

    class ForgedDestination(SensitiveDeliveryDestination):
        def binding_tuple(self):
            return receipt.destination.binding_tuple()

    forged_destination = ForgedDestination(
        receipt.destination.authorization_task_id,
        receipt.destination.operation_id,
        receipt.destination.profile,
        receipt.destination.platform,
        receipt.destination.account_binding_token,
        "forged-outward-chat",
        receipt.destination.thread_id,
    )
    forged = authority._mint_receipt(**values)
    object.__setattr__(forged, "destination", forged_destination)
    assert not authority.verify_receipt(forged)

    class TextSubclass(str):
        pass

    typed_forgery = authority._mint_receipt(**values)
    object.__setattr__(typed_forgery, "provider_message_id", TextSubclass("provider-message-1"))
    assert not authority.verify_receipt(typed_forgery)

    altered_provenance = {
        "correlation_id": "correlation-2",
        "authorization_task_id": "authorization-task-2",
        "operation_id": "operation-2",
        "request_hmac": "hmac-sha256:v1:" + "0" * 64,
        "request_key_version": "key-v2",
        "policy_namespace": "tests.other-policy",
        "policy_version": "policy-v2",
        "decision_model_id": "decision-model-2",
    }
    altered_destination = {
        "authorization_task_id": "authorization-task-2",
        "operation_id": "operation-2",
        "profile": "other",
        "platform": Platform.TELEGRAM,
        "account_binding_token": "hmac-sha256:v1:" + "1" * 64,
        "chat_id": "other-chat",
        "thread_id": "other-thread",
    }
    altered_attempt = {
        "attempt_id": "attempt-2",
        "claim_generation": 2,
        "profile": "other",
        "platform": Platform.TELEGRAM,
        "transport_implementation_id": "tests.other-transport:v1",
        "runtime_instance_token": "runtime-registration-2",
        "process_identity": "provider-sidecar-process-2",
        "session_identity": "provider-session-2",
        "account_binding_token": "hmac-sha256:v1:" + "2" * 64,
            "connection_epoch": 2,
        "chat_id": "other-chat",
        "thread_id": "other-thread",
        "send_started_us": NOW_US - 1,
    }
    tampered_bindings = []
    for name, value in altered_provenance.items():
        tampered_bindings.append(
            ("provenance", replace(receipt.provenance, **{name: value}))
        )
    for name, value in altered_destination.items():
        tampered_bindings.append(
            ("destination", replace(receipt.destination, **{name: value}))
        )
    for name, value in altered_attempt.items():
        tampered_bindings.append(
            ("attempt", replace(receipt.attempt, **{name: value}))
        )
    for field_name, altered_value in tampered_bindings:
        forged = authority._mint_receipt(**values)
        object.__setattr__(forged, field_name, altered_value)
        assert not authority.verify_receipt(forged), field_name

    for field_name, altered_value in (
        ("acceptance_status", SensitiveDeliveryAcceptanceStatus.UNKNOWN),
        ("acceptance_observed_us", NOW_US + 1),
        ("provider_observed_us", NOW_US + 1),
        ("evidence_id", "evidence-2"),
        ("_seal", "hmac-sha256:v1:" + "f" * 64),
    ):
        forged = authority._mint_receipt(**values)
        object.__setattr__(forged, field_name, altered_value)
        assert not authority.verify_receipt(forged), field_name

    contradictory = dict(values)
    contradictory["destination"] = replace(
        receipt.destination,
        chat_id="contradictory-chat",
    )
    with pytest.raises(ValueError, match="destination and attempt contradict"):
        authority._mint_receipt(**contradictory)
    await router.aclose()


@pytest.mark.asyncio
async def test_wrong_destination_account_epoch_message_and_time_do_not_accept(tmp_path):
    child = _write_child(tmp_path)
    source = child.read_text()
    mutations = {
        "destination": 'evidence["destination_chat_id"] = "wrong-chat"',
        "account": 'evidence["destination_account_binding_token"] = "hmac-sha256:v1:" + "0" * 64',
        "epoch": 'evidence["connection_epoch"] = 2',
        "message": 'evidence["provider_message_id"] = ""',
        "time": 'evidence["provider_observed_us"] = 1786363199999999',
    }
    marker = "    # A malicious independent transport status is intentionally ignored."
    for name, mutation in mutations.items():
        altered = tmp_path / f"altered-{name}.py"
        altered.write_text(source.replace(marker, f"    {mutation}\n{marker}"))
        altered.chmod(0o700)
        registration, _, _ = _registration(tmp_path, child=altered)
        router = _router(
            tmp_path,
            registration=registration,
        )
        receipt = await _deliver(router)
        assert not receipt.success
        assert receipt.outcome is SensitiveDeliveryOutcome.AMBIGUOUS
        await router.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["wrong", "missing", "extra"])
async def test_destination_thread_evidence_is_required_exact_and_canonical(
    tmp_path,
    mutation,
):
    child = _write_child(tmp_path)
    source = child.read_text()
    marker = "    # A malicious independent transport status is intentionally ignored."
    if mutation == "wrong":
        replacement = '    evidence["destination_thread_id"] = "wrong-thread"\n'
    elif mutation == "missing":
        replacement = '    evidence.pop("destination_thread_id")\n'
    else:
        replacement = '    evidence["thread_id"] = None\n'
    altered = tmp_path / f"thread-{mutation}.py"
    altered.write_text(source.replace(marker, replacement + marker))
    altered.chmod(0o700)
    registration, _, _ = _registration(tmp_path, child=altered)
    router = _router(tmp_path, registration=registration)
    receipt = await _deliver(router)
    assert receipt.error_code is SensitiveDeliveryErrorCode.CORRELATION_MISMATCH
    assert not receipt.success
    await router.aclose()


@pytest.mark.asyncio
async def test_aggregate_stdin_cap_rejects_before_spawn_without_truncation(tmp_path):
    registration, pid_path, _ = _registration(tmp_path)
    destination = _destination(
        chat_id="c" * 256,
        thread_id="t" * 256,
    )
    router = _router(tmp_path, registration=registration, destination=destination)
    prepared = await _prepare(router)
    assert type(prepared) is PreparedSensitiveDelivery
    receipt = await prepared.deliver("p" * MAX_SENSITIVE_PLAINTEXT_BYTES)
    assert receipt.error_code is SensitiveDeliveryErrorCode.INPUT_LIMIT
    assert receipt.attempt is not None
    assert not pid_path.exists()
    assert router._bridge._store.load_task(
        router._bridge.binding.task_id, router._bridge.binding
    ).status == "failed_consumed"
    normal_header_budget = MAX_SENSITIVE_STDIN_BYTES - MAX_SENSITIVE_PLAINTEXT_BYTES
    assert normal_header_budget > 0
    assert not _sensitive_delivery_tasks()
    await router.aclose()


def test_send_grants_cannot_be_publicly_constructed():
    with pytest.raises(TypeError, match="minted only"):
        SensitiveDeliverySendGrant()


@pytest.mark.asyncio
async def test_pre_send_executable_identity_failure_never_claims_reveals_or_spawns(tmp_path):
    child = _write_child(tmp_path)
    registration, pid_path, marker_path = _registration(tmp_path, child=child)
    router = _router(tmp_path, registration=registration)
    prepared = await _prepare(router)
    child.write_text(child.read_text() + "\n# changed after registration\n")
    receipt = await prepared.deliver(SECRET)
    assert receipt.error_code is SensitiveDeliveryErrorCode.EXECUTABLE_INVALID
    assert receipt.attempt is None
    assert router._bridge._store.load_task(
        router._bridge.binding.task_id, router._bridge.binding
    ).status == "failed_consumed"
    assert not pid_path.exists()
    assert not marker_path.exists()
    assert not _task_frames_contain(SECRET)
    await router.aclose()


@pytest.mark.asyncio
async def test_real_process_deadline_sigkills_reaps_and_prevents_delayed_send(tmp_path, caplog):
    registration, pid_path, marker_path = _registration(tmp_path, mode="hostile")
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=2.0,
        termination_grace_seconds=0.05,
        monotonic_clock=_spawn_aware_clock(pid_path),
    )
    caplog.set_level(logging.DEBUG)
    started = time.monotonic()
    receipt = await _deliver(router)
    elapsed = time.monotonic() - started
    assert receipt.error_code is SensitiveDeliveryErrorCode.TIMEOUT
    assert receipt.outcome is SensitiveDeliveryOutcome.AMBIGUOUS
    assert elapsed >= 2.0
    assert pid_path.exists()
    pid = await _read_pid(pid_path)
    assert not _pid_exists(pid)
    await asyncio.sleep(1.05)
    assert not marker_path.exists()
    assert router._bridge._store.load_task(
        router._bridge.binding.task_id, router._bridge.binding
    ).status == "failed_consumed"
    assert SECRET not in repr(router)
    assert SECRET not in repr(receipt)
    assert SECRET not in caplog.text
    assert not _task_frames_contain(SECRET)
    await router.aclose()
    assert not router._active and not router._attempt_tasks


@pytest.mark.asyncio
@pytest.mark.parametrize("iteration", range(3))
async def test_stalled_pre_exec_is_owned_timed_out_and_cannot_work_later(
    tmp_path,
    monkeypatch,
    iteration,
):
    registration, _, _ = _registration(tmp_path)
    marker_path = tmp_path / f"late-spawn-{iteration}.marker"
    pids = []
    _stall_exec_after_owned_fork(monkeypatch, marker_path, pids)
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=0.1,
        termination_grace_seconds=0.01,
    )

    started = time.monotonic()
    documented_ceiling = 0.1 + sensitive_delivery._cleanup_budget_seconds(0.01)
    receipt = await asyncio.wait_for(
        _deliver(router),
        documented_ceiling + 0.1,
    )
    elapsed = time.monotonic() - started
    assert receipt.error_code is SensitiveDeliveryErrorCode.TIMEOUT
    assert elapsed < documented_ceiling + 0.1
    assert len(pids) == 1
    assert not _pid_exists(pids[0])
    assert not _process_group_exists(pids[0])
    assert not router._spawning and not router._active and not router._attempt_tasks
    assert not _sensitive_delivery_tasks()
    await asyncio.sleep(0.15)
    assert not marker_path.exists()
    await asyncio.wait_for(router.aclose(), 0.5)


@pytest.mark.asyncio
async def test_repeated_cancellation_and_close_race_during_pre_exec_join_bounded(
    tmp_path,
    monkeypatch,
):
    registration, _, _ = _registration(tmp_path)
    marker_path = tmp_path / "cancelled-pre-exec.marker"
    pids = []
    _stall_exec_after_owned_fork(monkeypatch, marker_path, pids)
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=0.1,
        termination_grace_seconds=0.01,
    )
    delivery_task = asyncio.create_task(_deliver(router))
    await _wait_for_owned_spawn(pids)
    close_task = asyncio.create_task(router.aclose())
    await asyncio.sleep(0)
    for _ in range(8):
        delivery_task.cancel()
        close_task.cancel()
        await asyncio.sleep(0)

    started = time.monotonic()
    documented_ceiling = 0.1 + sensitive_delivery._cleanup_budget_seconds(0.01)
    receipt = await asyncio.wait_for(
        delivery_task,
        documented_ceiling + 0.1,
    )
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(close_task, documented_ceiling + 0.1)
    assert time.monotonic() - started < documented_ceiling + 0.1
    assert receipt.error_code is SensitiveDeliveryErrorCode.CANCELLED
    assert not _pid_exists(pids[0])
    assert not _process_group_exists(pids[0])
    assert not marker_path.exists()
    assert not router._spawning and not router._active and not router._attempt_tasks
    assert not _sensitive_delivery_tasks()
    await asyncio.wait_for(router.aclose(), 0.5)


@pytest.mark.asyncio
async def test_baseexception_after_owned_fork_reaps_pre_exec_child(tmp_path, monkeypatch):
    registration, _, _ = _registration(tmp_path)
    marker_path = tmp_path / "baseexception-pre-exec.marker"
    pids = []
    _stall_exec_after_owned_fork(monkeypatch, marker_path, pids)
    tracked_spawn = SensitiveDeliveryRouter._spawn

    class InjectedBaseException(BaseException):
        pass

    def fail_after_fork(
        self,
        attempt_id,
        executable,
        arguments,
        deadline,
        cleanup_deadline,
    ):
        tracked_spawn(
            self,
            attempt_id,
            executable,
            arguments,
            deadline,
            cleanup_deadline,
        )
        raise InjectedBaseException("failure after PID ownership")

    monkeypatch.setattr(SensitiveDeliveryRouter, "_spawn", fail_after_fork)
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=0.1,
        termination_grace_seconds=0.01,
    )
    with pytest.raises(InjectedBaseException, match="PID ownership"):
        await asyncio.wait_for(_deliver(router), 0.8)
    assert len(pids) == 1
    assert not _pid_exists(pids[0])
    assert not _process_group_exists(pids[0])
    assert not marker_path.exists()
    assert not router._spawning and not router._active and not router._attempt_tasks
    assert not _sensitive_delivery_tasks()
    await asyncio.wait_for(router.aclose(), 0.5)


@pytest.mark.asyncio
async def test_real_process_caller_cancellation_waits_for_sigkill_and_reap(tmp_path):
    registration, pid_path, marker_path = _registration(tmp_path, mode="hostile")
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=5,
        termination_grace_seconds=0.05,
    )
    prepared = await _prepare(router)
    task = asyncio.create_task(prepared.deliver(SECRET))
    pid = await _read_pid(pid_path)
    task.cancel()
    receipt = await asyncio.wait_for(task, 1)
    assert receipt.error_code is SensitiveDeliveryErrorCode.CANCELLED
    assert receipt.outcome is SensitiveDeliveryOutcome.AMBIGUOUS
    assert not _pid_exists(pid)
    await asyncio.sleep(3.05)
    assert not marker_path.exists()
    assert router._bridge._store.load_task(
        router._bridge.binding.task_id, router._bridge.binding
    ).status == "failed_consumed"
    assert not _task_frames_contain(SECRET)
    await router.aclose()
    assert not router._active and not router._attempt_tasks


@pytest.mark.asyncio
async def test_repeated_cancellation_during_grace_cannot_detach_descendant_cleanup(tmp_path):
    registration, pid_path, marker_path = _registration(
        tmp_path,
        mode="forking",
    )
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=5,
        termination_grace_seconds=0.2,
    )
    delivery_task = asyncio.create_task(_deliver(router))
    direct_pid = await _read_pid(pid_path)
    descendant_pid = await _read_pid(Path(str(pid_path) + ".descendant"))
    await asyncio.sleep(0.02)
    for _ in range(12):
        delivery_task.cancel()
        await asyncio.sleep(0.01)
    receipt = await asyncio.wait_for(delivery_task, 1)
    assert receipt.error_code is SensitiveDeliveryErrorCode.CANCELLED
    assert not _pid_exists(direct_pid)
    assert not _pid_exists(descendant_pid)
    assert not _process_group_exists(direct_pid)
    await asyncio.sleep(1.05)
    assert not marker_path.exists()
    assert router._bridge._store.load_task(
        router._bridge.binding.task_id, router._bridge.binding
    ).status == "failed_consumed"
    assert not router._active and not router._attempt_tasks
    assert not _sensitive_delivery_tasks()
    await router.aclose()


@pytest.mark.asyncio
async def test_timeout_reaps_direct_child_and_descendant_under_one_budget(tmp_path):
    registration, pid_path, marker_path = _registration(
        tmp_path,
        mode="forking_hostile",
    )
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=1.5,
        termination_grace_seconds=0.05,
        monotonic_clock=_spawn_aware_clock(pid_path),
    )
    receipt = await _deliver(router)
    direct_pid = await _read_pid(pid_path)
    descendant_pid = await _read_pid(Path(str(pid_path) + ".descendant"))
    assert receipt.error_code is SensitiveDeliveryErrorCode.TIMEOUT
    assert not _pid_exists(direct_pid)
    assert not _pid_exists(descendant_pid)
    assert not _process_group_exists(direct_pid)
    await asyncio.sleep(0.65)
    assert not marker_path.exists()
    assert router._bridge._store.load_task(
        router._bridge.binding.task_id, router._bridge.binding
    ).status == "failed_consumed"
    assert not _sensitive_delivery_tasks()
    await router.aclose()


@pytest.mark.asyncio
async def test_baseexception_after_spawn_reaps_descendant_before_propagating(
    tmp_path,
    monkeypatch,
):
    registration, pid_path, marker_path = _registration(
        tmp_path,
        mode="forking_hostile",
    )
    descendant_path = Path(str(pid_path) + ".descendant")
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=5,
        termination_grace_seconds=0.05,
    )

    class InjectedBaseException(BaseException):
        pass

    async def raise_after_descendant(process, deadline, monotonic_clock):
        await _read_pid(descendant_path)
        raise InjectedBaseException("injected host failure")

    monkeypatch.setattr(
        sensitive_delivery,
        "_wait_for_async_process_exit",
        raise_after_descendant,
    )
    with pytest.raises(InjectedBaseException, match="injected host failure"):
        await _deliver(router)
    direct_pid = await _read_pid(pid_path)
    descendant_pid = await _read_pid(descendant_path)
    assert not _pid_exists(direct_pid)
    assert not _pid_exists(descendant_pid)
    assert not _process_group_exists(direct_pid)
    await asyncio.sleep(2.05)
    assert not marker_path.exists()
    assert router._bridge._store.load_task(
        router._bridge.binding.task_id, router._bridge.binding
    ).status == "failed_consumed"
    assert not _sensitive_delivery_tasks()
    await router.aclose()


@pytest.mark.asyncio
async def test_unproven_cleanup_is_bounded_and_never_reports_success(tmp_path, monkeypatch):
    registration, pid_path, _ = _registration(tmp_path)
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=5,
        termination_grace_seconds=0.05,
    )
    real_group_exists = sensitive_delivery._process_group_exists
    prepared = await _prepare(router)
    monkeypatch.setattr(
        sensitive_delivery,
        "_process_group_exists",
        lambda process_group_id: True,
    )
    started = time.monotonic()
    receipt = await prepared.deliver(SECRET)
    elapsed = time.monotonic() - started
    assert receipt.error_code is SensitiveDeliveryErrorCode.CLEANUP_FAILED
    assert not receipt.success
    assert elapsed < 7.0
    direct_pid = await _read_pid(pid_path)
    assert not real_group_exists(direct_pid)
    assert router._bridge._store.load_task(
        router._bridge.binding.task_id, router._bridge.binding
    ).status == "failed_consumed"
    assert not router._active and not router._attempt_tasks
    assert not _sensitive_delivery_tasks()
    monkeypatch.setattr(
        sensitive_delivery,
        "_process_group_exists",
        real_group_exists,
    )
    await router.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "code"),
    [
        ("malformed", SensitiveDeliveryErrorCode.INVALID_EVIDENCE),
        ("overflow", SensitiveDeliveryErrorCode.OUTPUT_LIMIT),
        ("early_exit", SensitiveDeliveryErrorCode.TRANSPORT_FAILED),
    ],
)
async def test_parse_and_output_failures_are_closed_and_reaped(tmp_path, mode, code):
    registration, pid_path, marker_path = _registration(tmp_path, mode=mode)
    router = _router(tmp_path, registration=registration)
    receipt = await _deliver(router)
    assert receipt.error_code is code
    assert not _pid_exists(await _read_pid(pid_path))
    assert not marker_path.exists()
    assert not _sensitive_delivery_tasks()
    await router.aclose()


@pytest.mark.asyncio
async def test_pipe_reader_failure_still_completes_process_cleanup(tmp_path, monkeypatch):
    registration, pid_path, marker_path = _registration(tmp_path, mode="hostile")

    async def fail_reader(stream, cap, output):
        raise RuntimeError("injected pipe reader failure")

    async def fail_after_spawn(process, deadline, monotonic_clock):
        await _read_pid(pid_path)
        raise RuntimeError("injected process observation failure")

    monkeypatch.setattr(sensitive_delivery, "_read_bounded_status", fail_reader)
    monkeypatch.setattr(
        sensitive_delivery,
        "_wait_for_async_process_exit",
        fail_after_spawn,
    )
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=5,
        termination_grace_seconds=0.05,
    )
    receipt = await _deliver(router)
    direct_pid = await _read_pid(pid_path)
    assert receipt.error_code is SensitiveDeliveryErrorCode.CLEANUP_FAILED
    assert not _pid_exists(direct_pid)
    assert not _process_group_exists(direct_pid)
    assert not marker_path.exists()
    assert not router._active and not router._attempt_tasks
    assert not _sensitive_delivery_tasks()
    await router.aclose()


@pytest.mark.asyncio
async def test_success_kills_process_group_descendant_before_return(tmp_path):
    registration, pid_path, marker_path = _registration(tmp_path, mode="forking")
    router = _router(tmp_path, registration=registration, deadline_seconds=5)
    receipt = await _deliver(router)
    assert receipt.success
    direct_pid = await _read_pid(pid_path)
    descendant_pid = await _read_pid(Path(str(pid_path) + ".descendant"))
    assert not _pid_exists(direct_pid)
    assert not _pid_exists(descendant_pid)
    assert not _process_group_exists(direct_pid)
    assert not _sensitive_delivery_tasks()
    await asyncio.sleep(1.05)
    assert not marker_path.exists()
    await router.aclose()


@pytest.mark.asyncio
async def test_registered_sidecar_lease_is_invalidated_killed_and_reaped(tmp_path):
    sidecar = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)",
        ],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    lease = SensitiveDeliveryProcessLease(sidecar, "provider-sidecar-process-1")
    registration, _, _ = _registration(tmp_path, sidecar_lease=lease)
    router = _router(
        tmp_path,
        registration=registration,
        termination_grace_seconds=0.05,
    )
    receipt = await _deliver(router)
    assert receipt.success
    assert sidecar.poll() is not None
    assert not _pid_exists(sidecar.pid)
    assert not lease.is_live("provider-sidecar-process-1")
    await router.aclose()


def test_process_lease_rejects_live_child_that_is_not_process_group_leader():
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        with pytest.raises(ValueError, match="dedicated process group"):
            SensitiveDeliveryProcessLease(child, "non-dedicated-process")
    finally:
        child.terminate()
        child.wait(timeout=2)


@pytest.mark.asyncio
async def test_duplicate_lease_registration_is_rejected_and_original_can_reap(tmp_path):
    sidecar, descendant_path = _spawn_sidecar(tmp_path)
    lease = SensitiveDeliveryProcessLease(sidecar, "provider-sidecar-process-1")
    with pytest.raises(ValueError, match="already has a lifecycle lease"):
        SensitiveDeliveryProcessLease(sidecar, "provider-sidecar-process-1")
    registration, _, _ = _registration(tmp_path, sidecar_lease=lease)
    with pytest.raises(ValueError, match="cap exceeded"):
        SensitiveDeliveryTransportRegistry([registration], max_registrations=0)
    registry = SensitiveDeliveryTransportRegistry([registration], max_registrations=1)
    with pytest.raises(ValueError, match="already registered"):
        SensitiveDeliveryTransportRegistry([registration], max_registrations=1)
    authority = _authority()
    bridge = _claimed_bridge(tmp_path, registration, authority)
    router = SensitiveDeliveryRouter(
        transport_registry=registry,
        authorization_bridge=bridge,
        termination_grace_seconds=0.05,
    )
    with pytest.raises(ValueError, match="lifecycle authority"):
        SensitiveDeliveryRouter(
            transport_registry=registry,
            authorization_bridge=_claimed_bridge(tmp_path, registration, authority),
        )
    descendant_pid = await _read_pid(descendant_path)
    await router.aclose()
    assert sidecar.poll() is not None
    assert not _pid_exists(descendant_pid)
    assert not _process_group_exists(sidecar.pid)
    assert not _sensitive_delivery_tasks()


@pytest.mark.asyncio
async def test_router_close_reaps_unused_lease_descendants_and_is_idempotent(tmp_path):
    sidecar, descendant_path = _spawn_sidecar(tmp_path)
    lease = SensitiveDeliveryProcessLease(sidecar, "provider-sidecar-process-1")
    registration, _, _ = _registration(tmp_path, sidecar_lease=lease)
    router = _router(
        tmp_path,
        registration=registration,
        termination_grace_seconds=0.05,
    )
    descendant_pid = await _read_pid(descendant_path)
    await router.aclose()
    await router.aclose()
    assert sidecar.poll() is not None
    assert not _pid_exists(descendant_pid)
    assert not _process_group_exists(sidecar.pid)
    assert not lease.is_live("provider-sidecar-process-1")
    assert not router._active and not router._attempt_tasks
    assert not _sensitive_delivery_tasks()


@pytest.mark.asyncio
async def test_repeated_cancellation_cannot_detach_direct_lease_reap(tmp_path):
    sidecar, descendant_path = _spawn_sidecar(tmp_path)
    lease = SensitiveDeliveryProcessLease(sidecar, "provider-sidecar-process-1")
    descendant_pid = await _read_pid(descendant_path)
    reap_task = asyncio.create_task(lease.invalidate_and_reap(0.2))
    await asyncio.sleep(0)
    for _ in range(8):
        reap_task.cancel()
        await asyncio.sleep(0.01)
    with pytest.raises(asyncio.CancelledError):
        await reap_task
    assert sidecar.poll() is not None
    assert not _pid_exists(descendant_pid)
    assert not _process_group_exists(sidecar.pid)
    assert not _sensitive_delivery_tasks()


@pytest.mark.asyncio
async def test_repeated_cancellation_cannot_detach_router_close_cleanup(tmp_path):
    sidecar, descendant_path = _spawn_sidecar(tmp_path)
    lease = SensitiveDeliveryProcessLease(sidecar, "provider-sidecar-process-1")
    registration, _, _ = _registration(tmp_path, sidecar_lease=lease)
    router = _router(
        tmp_path,
        registration=registration,
        termination_grace_seconds=0.2,
    )
    descendant_pid = await _read_pid(descendant_path)
    close_task = asyncio.create_task(router.aclose())
    await asyncio.sleep(0)
    for _ in range(8):
        close_task.cancel()
        await asyncio.sleep(0.01)
    with pytest.raises(asyncio.CancelledError):
        await close_task
    assert sidecar.poll() is not None
    assert not _pid_exists(descendant_pid)
    assert not _process_group_exists(sidecar.pid)
    assert not _sensitive_delivery_tasks()
    await router.aclose()


@pytest.mark.asyncio
async def test_router_close_finishes_inflight_one_shot_cleanup_before_return(tmp_path):
    registration, pid_path, marker_path = _registration(tmp_path, mode="hostile")
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=5,
        termination_grace_seconds=0.05,
    )
    delivery_task = asyncio.create_task(_deliver(router))
    direct_pid = await _read_pid(pid_path)
    await router.aclose()
    receipt = await delivery_task
    assert receipt.error_code is SensitiveDeliveryErrorCode.CANCELLED
    assert not _pid_exists(direct_pid)
    assert not _process_group_exists(direct_pid)
    assert router._bridge._store.load_task(
        router._bridge.binding.task_id, router._bridge.binding
    ).status == "failed_consumed"
    assert not marker_path.exists()
    assert not router._active and not router._attempt_tasks
    assert not _sensitive_delivery_tasks()


@pytest.mark.asyncio
async def test_router_enforces_loop_thread_ownership(tmp_path):
    router = _router(tmp_path)
    prepared = await _prepare(router)
    errors = []

    def other_loop():
        async def use():
            with pytest.raises(RuntimeError, match="one event loop and thread"):
                prepared.discard()

        try:
            asyncio.run(use())
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    thread = threading.Thread(target=other_loop)
    thread.start()
    thread.join(timeout=2)
    assert not errors and not thread.is_alive()
    prepared.discard()
    await router.aclose()


def test_secret_bearing_host_objects_reject_copy_pickle_and_redact(tmp_path):
    key_sentinel = b"pickle-key-sentinel-5f4f"
    binder = SensitiveDeliveryAccountBinder(key_sentinel + b"b" * 32)
    authority = SensitiveDeliveryHostAuthority(
        key_sentinel + b"a" * 32,
        key_sentinel + b"r" * 32,
    )
    registration, _, _ = _registration(tmp_path)
    registry = SensitiveDeliveryTransportRegistry([registration], max_registrations=1)
    bridge = _claimed_bridge(tmp_path, registration, authority)
    router = SensitiveDeliveryRouter(
        transport_registry=registry,
        authorization_bridge=bridge,
    )
    objects = [
        binder, authority, registration.command, registration,
        registration.account_probe, registry, bridge, router,
    ]
    for value in objects:
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                operation(value)
        rendered = repr(value)
        assert SECRET not in rendered
        assert str(registration.command.executable) not in rendered
        assert ACCOUNT not in rendered
    captured = None
    try:
        pickle.dumps(authority)
    except TypeError as exc:
        captured = pickle.dumps(exc)
    assert key_sentinel not in captured


@pytest.mark.asyncio
async def test_payload_utf8_caps_prepared_and_inflight_caps_and_shutdown(tmp_path):
    registration, _, _ = _registration(
        tmp_path,
        max_sensitive_payload_bytes=4,
    )
    router = _router(
        tmp_path,
        registration=registration,
        max_prepared_handles=1,
        max_in_flight_attempts=1,
    )
    prepared = await _prepare(router)
    limited = await _prepare(router)
    assert limited.error_code is SensitiveDeliveryErrorCode.PREPARED_LIMIT
    receipt = await prepared.deliver("\ud800")
    assert receipt.error_code is SensitiveDeliveryErrorCode.INPUT_LIMIT
    assert receipt.attempt is None
    # Validation failure consumes the one-shot handle, so create a fresh router
    # to verify clean shutdown of all bounded collections.
    await router.aclose()
    assert router._prepared == 0
    assert not router._attempt_tasks and not router._active


@pytest.mark.asyncio
async def test_invalid_plaintext_is_content_free_without_exception_retention(
    tmp_path,
    caplog,
):
    sentinel = "private-invalid-plaintext-sentinel-41c7"

    class InvalidPlaintext:
        def __repr__(self):
            return sentinel

    registration, pid_path, _ = _registration(
        tmp_path,
        max_sensitive_payload_bytes=32,
    )
    invalid_values = (
        InvalidPlaintext(),
        "",
        sentinel + "\ud800",
        sentinel * 4,
    )
    receipts = []
    captured_exceptions = []
    routers = []
    for invalid in invalid_values:
        router = _router(tmp_path, registration=registration)
        routers.append(router)
        prepared = await _prepare(router)
        try:
            receipts.append(await prepared.deliver(invalid))
        except BaseException as exc:  # pragma: no cover - asserted empty below
            captured_exceptions.append(exc)
        invalid = None
    assert captured_exceptions == []
    assert all(
        receipt.error_code is SensitiveDeliveryErrorCode.INPUT_LIMIT
        and receipt.outcome is SensitiveDeliveryOutcome.REJECTED
        and receipt.attempt is None
        for receipt in receipts
    )
    for router in routers:
        assert router._bridge._store.load_task(
            router._bridge.binding.task_id, router._bridge.binding
        ).status == "failed_consumed"
        await router.aclose()
    assert not pid_path.exists()
    assert sentinel not in caplog.text
    assert all(sentinel not in repr(receipt) for receipt in receipts)
    assert not _task_frames_contain(sentinel)
    await router.aclose()


def test_module_has_no_rejected_async_client_or_detached_deadline_api():
    import gateway.sensitive_delivery as module

    source = inspect.getsource(module)
    assert "SensitiveDeliveryTransportClient" not in source
    assert "_hard_deadline" not in source
    assert "add_done_callback" not in source
    assert "submit_sensitive" not in source
    assert "confirm_sensitive_submission" not in source
    assert "SendResult" in module.__doc__


class InjectedLifecycleBaseException(BaseException):
    pass


@pytest.mark.asyncio
async def test_postfork_ownership_allocation_memoryerror_uses_raw_cleanup(
    tmp_path,
    monkeypatch,
):
    registration, _, _ = _registration(tmp_path)
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=0.1,
        termination_grace_seconds=0.01,
    )
    baseline_fds = _open_fds()
    before_launches = _staged_launch_paths()
    forked_pids = []
    raw_pipe_fds = []
    real_fork = os.fork
    real_pipe = sensitive_delivery._pipe_above_stdio

    def tracking_fork():
        pid = real_fork()
        if pid > 0:
            forked_pids.append(pid)
        return pid

    def allocation_failure(*args, **kwargs):
        raise MemoryError("injected ownership allocation failure")

    def tracking_pipe():
        descriptors = real_pipe()
        raw_pipe_fds.extend(descriptors)
        return descriptors

    monkeypatch.setattr(os, "fork", tracking_fork)
    monkeypatch.setattr(sensitive_delivery, "_pipe_above_stdio", tracking_pipe)
    monkeypatch.setattr(
        sensitive_delivery,
        "_DirectChildOwnership",
        allocation_failure,
    )
    with pytest.raises(MemoryError, match="ownership allocation failure"):
        router._spawn(
            "attempt-memoryerror",
            registration.command.executable,
            registration.command.arguments,
            time.monotonic() + 0.1,
            time.monotonic() + 0.36,
        )

    # These proofs precede aclose: rollback cannot depend on publication or
    # any later owner to recover the raw post-fork resources.
    assert len(forked_pids) == 1
    assert raw_pipe_fds
    for descriptor in raw_pipe_fds:
        with pytest.raises(OSError):
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
    extra_fds = _open_fds() - baseline_fds
    assert not extra_fds, (
        extra_fds,
        [(descriptor, os.fstat(descriptor)) for descriptor in extra_fds],
    )
    assert _staged_launch_paths() == before_launches
    assert not router._spawning and not router._active
    for pid in forked_pids:
        assert not _is_direct_child_or_zombie(pid)
        assert not _process_group_exists(pid)
    assert not _sensitive_delivery_tasks()
    await router.aclose()


@pytest.mark.parametrize("terminal_state", ("reaped", "lost", "closed"))
def test_terminal_owned_process_never_signals_reused_numeric_pid(
    monkeypatch,
    terminal_state,
):
    ownership = sensitive_delivery._DirectChildOwnership(
        424242,
        terminal_state,
    )
    process = sensitive_delivery._OwnedProcess(
        424242,
        None,
        None,
        None,
        returncode=0,
        child_ownership=ownership,
    )
    signals = []

    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(
        os,
        "killpg",
        lambda pid, sig: (_ for _ in ()).throw(ProcessLookupError()),
    )
    monkeypatch.setattr(os, "kill", lambda pid, sig: signals.append((pid, sig)))
    assert not sensitive_delivery._signal_owned_process(process, signal.SIGKILL)
    assert signals == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "checkpoint",
    (
        "spawn.after_fork",
        "spawn.process_construction",
        "spawn.after_process_construction",
        "spawn.publication",
        "spawn.after_publication",
        "spawn.parent_end_close",
    ),
)
@pytest.mark.parametrize("failure_type", (SystemExit, InjectedLifecycleBaseException))
async def test_every_postfork_publication_failure_owns_raw_pid_fds_and_group(
    tmp_path,
    monkeypatch,
    checkpoint,
    failure_type,
):
    registration, _, _ = _registration(tmp_path)
    marker_path = tmp_path / "postfork-late.marker"
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=0.1,
        termination_grace_seconds=0.01,
    )
    baseline_fds = _open_fds()
    forked_pids = []
    real_fork = os.fork

    def tracking_fork():
        pid = real_fork()
        if pid > 0:
            forked_pids.append(pid)
        return pid

    def delayed_pre_exec(executable, arguments, environment):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(0.2)
        marker_path.write_text("late", encoding="ascii")
        time.sleep(30)

    def inject(name):
        if name == checkpoint:
            raise failure_type("injected lifecycle failure")

    monkeypatch.setattr(os, "fork", tracking_fork)
    monkeypatch.setattr(os, "execve", delayed_pre_exec)
    monkeypatch.setattr(sensitive_delivery, "_lifecycle_checkpoint", inject)
    started = time.monotonic()
    with pytest.raises(failure_type, match="injected lifecycle failure"):
        router._spawn(
            "attempt-injected",
            registration.command.executable,
            registration.command.arguments,
            time.monotonic() + 0.1,
            time.monotonic() + 0.36,
        )
    assert time.monotonic() - started < 1.0
    assert not (_open_fds() - baseline_fds)
    await router.aclose()
    assert len(forked_pids) == 1
    for pid in forked_pids:
        assert not _is_direct_child_or_zombie(pid), forked_pids
        assert not _process_group_exists(pid)
    await asyncio.sleep(0.25)
    assert not marker_path.exists()
    assert not (_open_fds() - baseline_fds)
    assert not router._spawning and not router._active
    assert not _sensitive_delivery_tasks()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "checkpoint",
    (
        "launch.after_mkdir",
        "launch.after_source_open",
        "launch.after_target_open",
        "launch.copy",
        "launch.after_chmod",
        "launch.after_verification",
        "launch.publication",
    ),
)
@pytest.mark.parametrize("failure_type", (SystemExit, InjectedLifecycleBaseException))
async def test_launch_staging_baseexceptions_close_and_remove_private_tree(
    tmp_path,
    monkeypatch,
    checkpoint,
    failure_type,
):
    registration, _, _ = _registration(tmp_path)
    before = _staged_launch_paths()
    router = _router(
        tmp_path,
        registration=registration,
        deadline_seconds=0.1,
        termination_grace_seconds=0.01,
    )

    def inject(name):
        if name == checkpoint:
            raise failure_type("injected staging failure")

    monkeypatch.setattr(sensitive_delivery, "_lifecycle_checkpoint", inject)
    with pytest.raises(failure_type, match="injected staging failure"):
        await _deliver(router)
    await router.aclose()
    assert _staged_launch_paths() == before
    assert all(
        "hermes-sensitive-delivery-" not in target
        for target in _open_fd_targets()
    )
    assert not _sensitive_delivery_tasks()


@pytest.mark.asyncio
async def test_launch_deletion_failure_is_recovered_reported_and_not_leaked(
    tmp_path,
    monkeypatch,
):
    registration, _, _ = _registration(tmp_path)
    before = _staged_launch_paths()
    router = _router(tmp_path, registration=registration)

    def inject(name):
        if name == "launch.deletion":
            raise InjectedLifecycleBaseException("injected deletion failure")

    monkeypatch.setattr(sensitive_delivery, "_lifecycle_checkpoint", inject)
    receipt = await _deliver(router)
    assert receipt.error_code is SensitiveDeliveryErrorCode.CLEANUP_FAILED
    assert _staged_launch_paths() == before
    await router.aclose()


@pytest.mark.asyncio
async def test_two_workers_share_one_store_send_start_and_only_one_spawns(tmp_path):
    registration, _, _ = _registration(tmp_path)
    authority = _authority()
    first_bridge = _claimed_bridge(tmp_path, registration, authority)
    second_bridge = AuthorizationSensitiveDeliveryBridge(
        store=first_bridge._store,
        binding=first_bridge.binding,
        claim=first_bridge.claim,
        host_authority=authority,
        wall_clock_us=lambda: NOW_US,
    )
    routers = (
        _router(tmp_path, registration=registration, bridge=first_bridge),
        _router(tmp_path, registration=registration, bridge=second_bridge),
    )
    prepared = await asyncio.gather(*(_prepare(router) for router in routers))
    spawn_count = 0
    real_spawn = SensitiveDeliveryRouter._spawn

    def count_spawn(self, *args, **kwargs):
        nonlocal spawn_count
        spawn_count += 1
        return real_spawn(self, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(SensitiveDeliveryRouter, "_spawn", count_spawn)
        receipts = await asyncio.gather(
            *(item.deliver(f"worker-{index}") for index, item in enumerate(prepared))
        )
    assert spawn_count == 1
    assert sum(receipt.success for receipt in receipts) == 1
    assert sum(
        receipt.error_code is SensitiveDeliveryErrorCode.SEND_START_UNCERTAIN
        for receipt in receipts
    ) == 1
    task = first_bridge._store.load_task(first_bridge.binding.task_id, first_bridge.binding)
    assert task.status == "consumed" and task.send_started_at_us == NOW_US
    for router in routers:
        await router.aclose()


@pytest.mark.asyncio
async def test_send_grant_replay_copy_pickle_forgery_and_collision_fail_closed(
    tmp_path,
    monkeypatch,
):
    registration, _, _ = _registration(tmp_path)
    router = _router(tmp_path, registration=registration)
    real_consume = AuthorizationSensitiveDeliveryBridge.consume_send_grant
    attacked = False

    def attack(self, grant, observation, attempt):
        nonlocal attacked
        attacked = True
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                operation(grant)
        forged = object.__new__(SensitiveDeliverySendGrant)
        for name in SensitiveDeliverySendGrant.__slots__:
            if name != "__weakref__":
                object.__setattr__(forged, name, getattr(grant, name))
        assert not real_consume(self, forged, observation, attempt)
        assert real_consume(self, grant, observation, attempt)
        assert not real_consume(self, grant, observation, attempt)
        return True

    monkeypatch.setattr(
        AuthorizationSensitiveDeliveryBridge,
        "consume_send_grant",
        attack,
    )
    receipt = await _deliver(router)
    assert attacked and receipt.success
    await router.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("fault_step", ("transition.before", "transition.after"))
async def test_send_start_uncertainty_never_spawns_and_closes_failed_consumed(
    tmp_path,
    fault_step,
):
    registration, pid_path, _ = _registration(tmp_path)
    router = _router(tmp_path, registration=registration)
    prepared = await _prepare(router)
    fired = False

    def fault(step):
        nonlocal fired
        if step == fault_step and not fired:
            fired = True
            raise SystemExit("send-start uncertainty")

    router._bridge._store._fault_hook = fault
    receipt = await prepared.deliver(SECRET)
    assert fired
    assert receipt.error_code is SensitiveDeliveryErrorCode.SEND_START_UNCERTAIN
    assert not pid_path.exists()
    task = router._bridge._store.load_task(
        router._bridge.binding.task_id, router._bridge.binding
    )
    assert task.status == "failed_consumed"
    await router.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fault_step", "durable_status"),
    (("transition.before", "claimed"), ("commit.after", "consumed")),
)
async def test_finish_boundary_uncertainty_never_reopens(
    tmp_path,
    fault_step,
    durable_status,
):
    registration, _, _ = _registration(tmp_path)
    router = _router(tmp_path, registration=registration)
    prepared = await _prepare(router)
    seen = 0

    def fault(step):
        nonlocal seen
        if step == fault_step:
            seen += 1
            if seen == 2:
                raise SystemExit("finish uncertainty")

    router._bridge._store._fault_hook = fault
    receipt = await prepared.deliver(SECRET)
    assert receipt.error_code is SensitiveDeliveryErrorCode.AUTHORIZATION_FINISH_UNCERTAIN
    task = router._bridge._store.load_task(
        router._bridge.binding.task_id, router._bridge.binding
    )
    assert task.status == durable_status
    assert task.send_started_at_us == NOW_US
    await router.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("state_change", "fresh"),
    (
        ({}, True),
        ({"observed_at_us": NOW_US - 2_000_000}, False),
        ({"account_identity": "wrong@example.test"}, False),
        ({"connection_epoch": 2}, False),
        ({"process_identity": "other-process"}, False),
        ({"session_identity": "other-session"}, False),
    ),
)
async def test_live_probe_precedes_private_read_and_rejects_drift(
    tmp_path,
    state_change,
    fresh,
):
    binder = SensitiveDeliveryAccountBinder(BIND_KEY)
    probe = _live_probe(binder, **state_change)
    registration, pid_path, _ = _registration(tmp_path, account_probe=probe)
    router = _router(
        tmp_path,
        registration=registration,
        provider_evidence_max_age_seconds=1.0,
    )
    result = await router.prepare()
    task = router._bridge._store.load_task(
        router._bridge.binding.task_id, router._bridge.binding
    )
    assert task.send_started_at_us is None and not pid_path.exists()
    if fresh:
        assert type(result) is PreparedSensitiveDelivery
        assert task.status == "claimed"
        result.discard()
    else:
        assert type(result) is SensitiveDeliveryReceipt
        assert result.error_code in {
            SensitiveDeliveryErrorCode.ACCOUNT_MISMATCH,
            SensitiveDeliveryErrorCode.RUNTIME_UNAVAILABLE,
        }
    await router.aclose()


@pytest.mark.asyncio
async def test_probe_duplicate_json_key_is_rejected_before_private_read(tmp_path):
    binder = SensitiveDeliveryAccountBinder(BIND_KEY)

    def duplicate(encoded):
        return encoded[:-1] + b',"connection_epoch":1}'

    probe = _live_probe(binder, raw_response_transform=duplicate)
    registration, pid_path, _ = _registration(tmp_path, account_probe=probe)
    router = _router(tmp_path, registration=registration)
    receipt = await router.prepare()
    assert type(receipt) is SensitiveDeliveryReceipt
    assert receipt.error_code is SensitiveDeliveryErrorCode.RUNTIME_UNAVAILABLE
    assert not pid_path.exists()
    await router.aclose()


@pytest.mark.asyncio
async def test_live_probe_timeout_closes_channel_and_joins_local_fake():
    probe, request_seen, thread = _stalled_probe(
        SensitiveDeliveryAccountBinder(BIND_KEY),
        timeout_seconds=0.05,
    )
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        await probe.observe(
            platform=Platform.WHATSAPP,
            deadline=started + 1.0,
            monotonic_clock=time.monotonic,
        )
    assert request_seen.is_set()
    thread.join(timeout=0.5)
    assert not thread.is_alive()
    assert time.monotonic() - started < 0.75


@pytest.mark.asyncio
async def test_live_probe_cancellation_closes_channel_and_joins_local_fake():
    probe, request_seen, thread = _stalled_probe(
        SensitiveDeliveryAccountBinder(BIND_KEY),
        timeout_seconds=1.0,
    )
    task = asyncio.create_task(
        probe.observe(
            platform=Platform.WHATSAPP,
            deadline=time.monotonic() + 2.0,
            monotonic_clock=time.monotonic,
        )
    )
    while not request_seen.is_set():
        await asyncio.sleep(0.005)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    thread.join(timeout=0.5)
    assert not thread.is_alive()


@pytest.mark.asyncio
async def test_live_probe_baseexception_closes_exact_real_channel(monkeypatch):
    probe = _live_probe(SensitiveDeliveryAccountBinder(BIND_KEY))

    class InjectedProbeBaseException(BaseException):
        pass

    def fail_decode(raw):
        raise InjectedProbeBaseException("probe parser host failure")

    monkeypatch.setattr(sensitive_delivery, "_decode_closed_evidence", fail_decode)
    with pytest.raises(InjectedProbeBaseException):
        await probe.observe(
            platform=Platform.WHATSAPP,
            deadline=time.monotonic() + 1.0,
            monotonic_clock=time.monotonic,
        )
    assert probe._failed
    _, _, thread = _PROBE_FAKES[-1]
    thread.join(timeout=0.5)
    assert not thread.is_alive()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("authorization_task_id", "other-task"),
        ("correlation_id", "other-correlation"),
        ("operation_id", "other-operation"),
        ("authorization_binding_digest", "other-binding"),
        ("request_digest", "other-request"),
        ("request_key_version", "other-key"),
        ("claim_nonce", "other-claim"),
        ("claim_generation", 2),
    ),
)
async def test_transport_evidence_cannot_replay_across_authorization_binding(
    tmp_path,
    field,
    value,
):
    child = _write_child(tmp_path)
    source = child.read_text()
    marker = "    # A malicious independent transport status is intentionally ignored."
    mutation = f"    evidence[{field!r}] = {value!r}\n"
    child.write_text(source.replace(marker, mutation + marker))
    child.chmod(0o700)
    registration, _, _ = _registration(tmp_path, child=child)
    router = _router(tmp_path, registration=registration)
    receipt = await _deliver(router)
    assert receipt.error_code is SensitiveDeliveryErrorCode.CORRELATION_MISMATCH
    assert router._bridge._store.load_task(
        router._bridge.binding.task_id, router._bridge.binding
    ).status == "failed_consumed"
    await router.aclose()


@pytest.mark.asyncio
async def test_plaintext_echo_then_host_baseexception_leaves_no_traceback_graph(
    tmp_path,
    monkeypatch,
    caplog,
):
    child = _write_child(tmp_path)
    source = child.read_text().replace(
        'elif mode == "malformed":\n    sys.stdout.write("not-json")',
        'elif mode == "echo_then_exit":\n'
        '    sys.stdout.buffer.write(payload)\n'
        '    sys.stdout.buffer.flush()\n'
        '    sys.stderr.buffer.write(payload)\n'
        '    sys.stderr.buffer.flush()\n'
        'elif mode == "malformed":\n    sys.stdout.write("not-json")',
    )
    child.write_text(source)
    child.chmod(0o700)
    registration, _, _ = _registration(tmp_path, child=child, mode="echo_then_exit")
    router = _router(tmp_path, registration=registration)
    real_wait = sensitive_delivery._wait_for_async_process_exit

    class InjectedAfterExit(BaseException):
        pass

    async def fail_after_exit(process, deadline, monotonic_clock):
        await real_wait(process, deadline, monotonic_clock)
        raise InjectedAfterExit("after transport exit")

    monkeypatch.setattr(
        sensitive_delivery,
        "_wait_for_async_process_exit",
        fail_after_exit,
    )
    prepared = await _prepare(router)
    with pytest.raises(InjectedAfterExit) as raised:
        await prepared.deliver(SECRET)
    pending = [raised.value]
    seen = set()
    while pending:
        failure = pending.pop()
        if failure is None or id(failure) in seen:
            continue
        seen.add(id(failure))
        assert SECRET not in str(failure)
        traceback_node = failure.__traceback__
        while traceback_node is not None:
            for value in traceback_node.tb_frame.f_locals.values():
                if type(value) is str:
                    assert SECRET not in value
                elif type(value) in (bytes, bytearray):
                    assert SECRET.encode() not in value
            traceback_node = traceback_node.tb_next
        pending.extend((failure.__cause__, failure.__context__))
    assert SECRET not in caplog.text
    assert not _task_frames_contain(SECRET)
    assert not router._active and not router._attempt_tasks
    await router.aclose()


def _synthetic_host_config(root: Path) -> TrustedPrivateReadHostConfig:
    root.mkdir(mode=0o700)
    state = root / "state"
    state.mkdir(mode=0o700)
    keys = root / "keys.json"
    allowlist = root / "allowlist.json"
    keys.write_text(json.dumps({
        "version": 1,
        "key_version": "synthetic-v1",
        "audit_hmac": "11" * 32,
        "request_hmac": "22" * 32,
        "request_id_hmac": "33" * 32,
        "authorization_hmac": "44" * 32,
        "receipt_hmac": "55" * 32,
    }), encoding="utf-8")
    identity = {
        "manifest_sha256": "a" * 64,
        "source_sha256": "b" * 64,
        "package_sha256": "c" * 64,
        "lock_sha256": "d" * 64,
        "package_name": "synthetic-package",
        "package_version": "synthetic-version",
        "baileys_commit": "synthetic-commit",
        "baileys_version": "synthetic-provider-version",
        "baileys_lock_integrity": "synthetic-lock-integrity",
        "baileys_tree_sha256": "e" * 64,
    }
    allowlist.write_text(json.dumps({
        "version": 1,
        "transport_identity": identity,
    }), encoding="utf-8")
    keys.chmod(0o600)
    allowlist.chmod(0o600)
    parsed = TrustedPrivateReadHostConfig.parse({
        "version": 1,
        "enabled": True,
        "state_dir": str(state),
        "key_file": str(keys),
        "allowlist_file": str(allowlist),
        "openfga_version": "1.18.2",
        "capabilities": [{
            "id": "synthetic-capability",
            "operation": "synthetic-operation",
            "resource_type": "synthetic-resource",
            "fields": ["synthetic-field"],
        }],
        "poll_seconds": 0.1,
        "lease_seconds": 5,
    })
    assert parsed is not None
    return parsed


@pytest.mark.asyncio
async def test_synthetic_authenticated_private_read_e2e_never_persists_plaintext(
    tmp_path: Path,
    caplog,
) -> None:
    """Exercise the exact durable protocol without a live provider or PDP."""
    config = _synthetic_host_config(tmp_path / "synthetic-private-host")
    now_us = time.time_ns() // 1000
    binder = SensitiveDeliveryAccountBinder(BIND_KEY)
    destination = _destination(binder)
    child = _write_child(tmp_path)
    # The general delivery suite uses a fixed clock. This E2E runs the real
    # host clock, so make the fake child's provider event use the current one.
    child.write_text(child.read_text().replace(
        "provider_observed_us\": 1786363200000000",
        "provider_observed_us\": int(time.time() * 1000000)",
    ))
    child.chmod(0o700)
    live_probe = _live_probe(binder, observed_at_us=now_us)
    registration, _, marker = _registration(
        tmp_path,
        child=child,
        account_probe=live_probe,
    )
    current_context: ContextVar[TrustedPrivateReadHostContext | None] = ContextVar(
        "synthetic-private-context", default=None
    )
    notification_seen = asyncio.Event()
    notifications: dict[str, tuple[object, str]] = {}
    pdp_stages: list[tuple[str, str, bool]] = []
    private_reads: list[str] = []
    task_id: str | None = None
    challenge_nonce: str | None = None

    request_event = MessageEvent(
        text="request configured capability",
        message_id="authenticated-request-message",
        source=SessionSource(
            platform=Platform.SLACK,
            profile="ordinary-account@example.test",
            scope_id="authenticated-workspace",
            chat_id="authenticated-source-chat",
            chat_type="thread",
            thread_id="authenticated-source-thread",
            user_id="authenticated-source-user",
        ),
    )
    approval_event = MessageEvent(
        text="approve",
        message_id="authenticated-owner-reply",
        reply_to_message_id="placeholder-until-notified",
        source=SessionSource(
            platform=Platform.WHATSAPP,
            profile="owner-account",
            chat_id="owner-chat",
            chat_type="thread",
            thread_id="owner-thread",
            user_id="owner-user",
        ),
    )

    def context_from_event(event: object) -> TrustedPrivateReadHostContext | None:
        if event is not request_event or type(event) is not MessageEvent:
            return None
        source = event.source
        # Identity comes only from the exact normalized authenticated event;
        # message text and display names do not participate.
        if (
            source.platform is not Platform.SLACK
            or source.profile != "ordinary-account@example.test"
            or source.scope_id != "authenticated-workspace"
            or source.user_id != "authenticated-source-user"
            or source.chat_id != "authenticated-source-chat"
            or source.thread_id != "authenticated-source-thread"
            or event.message_id != "authenticated-request-message"
        ):
            return None
        return TrustedPrivateReadHostContext(
            requester_profile=source.profile,
            requester_agent="gateway-agent",
            source_platform=source.platform.value,
            source_account=source.profile,
            source_user=source.user_id,
            source_chat=source.chat_id,
            source_thread=source.thread_id,
            source_message=event.message_id,
            source_provenance="authenticated_inbound",
            resource_id="host-configured-resource",
            approval_profile="owner-profile",
            approval_account="owner-account",
            approval_user="owner-user",
            approval_chat="owner-chat",
            approval_thread="owner-thread",
            delivery_profile=destination.profile,
            delivery_platform=destination.platform.value,
            delivery_account=ACCOUNT,
            delivery_chat=destination.chat_id,
            delivery_thread=destination.thread_id,
            delivery_transport_implementation=registration.identity.transport_implementation_id,
            delivery_runtime_identity=registration.identity.runtime_instance_token,
            delivery_account_binding=destination.account_binding_token,
            delivery_connection_epoch=registration.identity.connection_epoch,
            created_at_us=now_us,
            expires_at_us=now_us + 60_000_000,
            pdp_identity="synthetic-openfga-1.18.2",
            policy_identity="synthetic-policy",
            policy_version="synthetic-policy-v1",
            policy_hash="f" * 64,
            model_identity="synthetic-model-attestation",
        )

    def bind_event(event: object):
        return current_context.set(context_from_event(event))

    async def pdp_check(context):
        pdp_stages.append(
            (context.stage, context.consistency_preference, False)
        )
        return ExternalPdpDecisionResult(
            context_id=context.context_id,
            pdp_call_id=context.pdp_call_id,
            decision="allow",
            checked_at_us=max(time.time_ns() // 1000, context.created_at_us),
            consistency="strongest",
            cache_used=False,
        )

    async def deliver_notification(item, claim):
        accepted_at = max(time.time_ns() // 1000, item.notification.created_at_us)
        provider_message = "provider-" + item.attempt_id
        notifications[item.notification.kind] = (item, provider_message)
        notification_seen.set()
        return ProviderAcceptanceEvidence(
            task_id=item.task_id,
            correlation_id=item.correlation_id,
            attempt_id=item.attempt_id,
            challenge_generation=item.challenge_generation,
            worker_claim_generation=claim.generation,
            status="provider_accepted",
            provider_message_id=provider_message,
            accepted_at_us=accepted_at,
            adapter_instance_id="synthetic-approval-adapter",
            account_binding=item.destination_account,
            connection_epoch=1,
            destination_profile=item.destination_profile,
            destination_account=item.destination_account,
            destination_chat=item.destination_chat,
            destination_thread=item.destination_thread,
        )

    def decision_for_event(event: object):
        if event is not approval_event or task_id is None or challenge_nonce is None:
            return None
        challenge = notifications.get("approval_challenge")
        if challenge is None:
            return None
        item, provider_message = challenge
        created_at = time.time_ns() // 1000
        decision = OwnerDecision(
            decision_id="synthetic-decision-" + task_id,
            task_id=task_id,
            correlation_id=item.correlation_id,
            owner_profile="owner-profile",
            owner_account="owner-account",
            owner_user="owner-user",
            owner_chat="owner-chat",
            owner_thread="owner-thread",
            source_message=approval_event.message_id,
            provenance="authenticated_reply",
            challenge_attempt_id=item.attempt_id,
            challenge_generation=item.challenge_generation,
            challenge_nonce=challenge_nonce,
            challenge_provider_message_id=provider_message,
            reply_to_provider_message_id=provider_message,
            adapter_instance_id="synthetic-approval-adapter",
            account_binding=item.destination_account,
            connection_epoch=1,
        )
        resolution = NotificationAttemptSpec(
            attempt_id="synthetic-resolution-" + task_id,
            challenge_generation=item.challenge_generation,
            kind="approval_resolution",
            destination_profile="owner-profile",
            destination_account="owner-account",
            destination_chat="owner-chat",
            destination_thread="owner-thread",
            created_at_us=created_at,
            due_at_us=created_at,
            challenge_nonce="resolution-" + task_id,
        )
        return "approve", decision, resolution

    async def private_read(item):
        private_reads.append(item.task_id)
        return SECRET

    async def close_services() -> None:
        return None

    services = TrustedPrivateReadHostServices(
        healthy=lambda: True,
        context_for_current_event=current_context.get,
        pdp_check=pdp_check,
        transport_registration=lambda _item: asyncio.sleep(0, result=registration),
        private_read=private_read,
        deliver_notification=deliver_notification,
        decision_for_event=decision_for_event,
        close=close_services,
        transport_identity=lambda: dict(config.transport_identity),
        account_state=lambda: (
            "ordinary-account@example.test",
            ACCOUNT,
            "example.test",
            True,
        ),
        bind_event=bind_event,
        unbind_event=current_context.reset,
    )
    host = TrustedPrivateReadGatewayHost(config, services)
    try:
        assert await host.start() is True
        token = host.bind_event(request_event)
        try:
            capability = config.capabilities.capabilities[0]
            material = b"\0".join((
                capability.canonical_bytes(),
                current_context.get().canonical_bytes(),
                b"synthetic-tool-call",
            ))
            challenge_nonce = hmac.new(
                config.request_id_key,
                b"private-read-request-challenge-v1\0" + material,
                hashlib.sha256,
            ).hexdigest()[:64]
            entry = registry.get_entry(PRIVATE_READ_REQUEST_TOOL_NAME)
            assert entry is not None and entry.check_fn() is True
            visible = entry.handler(
                {"capability_id": "synthetic-capability"},
                tool_call_id="synthetic-tool-call",
            )
        finally:
            host.unbind_event(token)
        assert SECRET not in repr(visible)
        assert visible.terminal is not None
        task_id = dict(visible.terminal.metadata)["task_id"]
        assert host.store is not None
        pending = host.store.load_task_work_item(
            task_id, now_us=time.time_ns() // 1000
        )
        assert pending.task.status == "approval_required"
        await asyncio.wait_for(notification_seen.wait(), timeout=3)
        approval_event.reply_to_message_id = notifications["approval_challenge"][1]
        approval_token = host.bind_event(approval_event)
        host.unbind_event(approval_token)

        deadline = time.monotonic() + 5
        terminal = None
        while time.monotonic() < deadline:
            terminal = host.store.load_task(task_id, pending.binding)
            if terminal.status == "consumed":
                break
            await asyncio.sleep(0.05)
        assert terminal is not None and terminal.status == "consumed"
        assert terminal.receipt_code == "provider_accepted"
        assert private_reads == [task_id]
        assert pdp_stages == [
            ("pre_claim", "HIGHER_CONSISTENCY", False),
            ("pre_private_read", "HIGHER_CONSISTENCY", False),
        ]
        audit = host.store.list_audit_events(task_id=task_id)
        assert {event.kind for event in audit} >= {
            "task_created",
            "task_approved",
            "task_claimed",
            "pdp_check_allowed",
            "send_started",
            "task_consumed",
        }
        state_bytes = b"".join(
            path.read_bytes()
            for path in config.state_dir.iterdir()
            if path.is_file()
        )
        assert SECRET.encode() not in state_bytes
        assert SECRET not in caplog.text
        assert SECRET not in repr(registration.command)
        assert all(SECRET not in value for value in os.environ.values())
        assert not marker.exists()
        assert not _task_frames_contain(SECRET)
    finally:
        await host.stop()
        configure_private_read_request_runtime(None)
