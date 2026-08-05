from __future__ import annotations

import base64
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import io
import json
import logging
import os
import selectors
import shutil
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sqlite3
import subprocess
from threading import Thread
import time
import traceback
from types import SimpleNamespace

import pytest

from gateway.config import Platform, PlatformConfig
from gateway.juno_private_read_mvp import (
    CAPABILITY_ID,
    GMAIL_AUTHORITY,
    GMAIL_SCOPE,
    OPENFGA_AUTHORITY,
    ORDINARY_INBOUND_PROVENANCE,
    FixedHttpJsonTransport,
    GmailNewestInboxProvider,
    JunoPrivateReadDependencies,
    JunoPrivateReadError,
    JunoPrivateReadMvpConfig,
    JunoPrivateReadMvpHost,
    OpenFgaChecker,
    SensitiveRuntimeIdentity,
    SensitiveSubmission,
    _SENSITIVE_TRANSPORT_IDENTITY,
    compose_juno_private_read_mvp_services,
    render_gmail_message,
)
from gateway.juno_replay_journal import JOURNAL_NAME, MARKER_NAME, _KEY_MAGIC
from tests.gateway.test_juno_private_read_mvp_e2e import (
    FakeJsonTransport, FakeOrdinary, FakeSensitive, ORDINARY_ACCOUNT,
    OWNER, OWNER_CHAT, PRIVATE_SENTINEL, SENSITIVE_ACCOUNT,
    TRUSTED, TRUSTED_CHAT, _event, _host, _raw_config, _tool,
)
from tools.private_read_request_tool import check_private_read_request_runtime


CREDENTIAL_SENTINEL = "SYNTHETIC-CREDENTIAL-SENTINEL-74a1"


def _runtime_identity(
    runtime: str = "runtime", account: str = SENSITIVE_ACCOUNT,
    epoch: str = "epoch", observed_at_us: int | None = None,
    transport_identity: dict[str, str] | None = None,
) -> SensitiveRuntimeIdentity:
    return SensitiveRuntimeIdentity(
        runtime, account, epoch,
        time.time_ns() // 1000 if observed_at_us is None else observed_at_us,
        tuple(sorted((transport_identity or _SENSITIVE_TRANSPORT_IDENTITY).items())),
    )


def _node_forwarded_event(*, sender: str, text: str, message_id: str) -> dict:
    source = r"""
import { pathToFileURL } from 'node:url';
const helper = await import(pathToFileURL(process.env.JUNO_BRIDGE_HELPER));
const producer = await import(pathToFileURL(process.env.JUNO_BRIDGE_PRODUCER));
const input = JSON.parse(process.env.JUNO_BRIDGE_INPUT);
const msg = {
  key: { id: input.messageId, remoteJid: input.sender,
    participant: input.sender, fromMe: false },
  pushName: 'Synthetic User', messageTimestamp: 1786000000,
  message: { conversation: input.text },
};
const queue = [];
const store = helper.createBoundedMessageStore();
const handlers = new Map();
const socket = {
  user: { id: '33333333333:19@s.whatsapp.net', lid: '44444444444@lid' },
  ev: { on: (name, handler) => handlers.set(name, handler) },
};
producer.registerInboundMessageHandler({
  emittingSocket: socket, isActiveSocket: candidate => candidate === socket,
  producerDependencies: {
    mode: 'bot', dmPolicy: 'allowlist', forwardOwnerMessages: true,
    recentlySentIds: new Set(),
    allowlistMatches: id => [input.sender, '11111111111@s.whatsapp.net'].includes(id),
    extractEvent: helper.extractBridgeEvent, cacheDirs: {}, replyPrefix: '',
    messageStore: store, messageQueue: queue, maxQueueSize: 100,
  },
});
const outcome = await handlers.get('messages.upsert')({ type: 'notify', messages: [msg] });
if (outcome.action !== 'queued' || queue.length !== 1) throw new Error('producer rejected');
process.stdout.write(JSON.stringify(queue[0]));
"""
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", source],
        check=True, capture_output=True, text=True, timeout=10,
        env={
            **os.environ,
            "JUNO_BRIDGE_HELPER": str(
                os.environ.get("JUNO_ISOLATED_BRIDGE_HELPER")
                or Path(__file__).parents[2] / "scripts/whatsapp-bridge/bridge_helpers.js"
            ),
            "JUNO_BRIDGE_PRODUCER": str(
                os.environ.get("JUNO_ISOLATED_BRIDGE_PRODUCER")
                or Path(__file__).parents[2] / "scripts/whatsapp-bridge/inbound_producer.js"
            ),
            "JUNO_BRIDGE_INPUT": json.dumps({
                "sender": sender, "text": text, "messageId": message_id,
            }),
        },
    )
    return json.loads(completed.stdout)


def _loopback_server(handler) -> HTTPServer:
    try:
        return HTTPServer(("127.0.0.1", 0), handler)
    except PermissionError:
        pytest.skip("execution sandbox denies loopback socket binding")


def _node_harness_failure(stderr: str, returncode: int | None) -> str:
    value = stderr[:4096]
    if returncode == 73 and value.strip() in {
        "JUNO_SOCKET_BIND_DENIED:EACCES:listen",
        "JUNO_SOCKET_BIND_DENIED:EPERM:listen",
    }:
        return "socket_bind_denied"
    if "ERR_MODULE_NOT_FOUND" in value or "Cannot find module" in value:
        return "module_not_found"
    if "SyntaxError" in value:
        return "syntax_error"
    if returncode == 74 and value.strip() == "JUNO_HARNESS_STARTUP_FAILURE":
        return "startup_failure"
    return "unexpected_node_failure"


def _assert_sealed_source_provenance(host, context) -> None:
    assert context.source_provenance == ORDINARY_INBOUND_PROVENANCE
    source_id = host.repository._source_journal_id(context)
    journal_path = host.config.state_dir / JOURNAL_NAME
    marker_path = host.config.state_dir / MARKER_NAME
    records = [json.loads(line) for line in journal_path.read_text().splitlines()]
    assert records[0]["kind"] == "genesis"
    assert any(
        record["kind"] == "source" and source_id in record["ids"]
        for record in records
    )
    assert all(
        set(record) == {"v", "seq", "prev", "kind", "ids", "mac"}
        and len(record["mac"]) == 64
        for record in records
    )
    marker = json.loads(marker_path.read_text())
    assert marker["seq"] == len(records)
    assert marker["head"] == hashlib.sha256(
        journal_path.read_bytes().splitlines()[-1]
    ).hexdigest()
    assert len(marker["mac"]) == 64
    assert len((host.config.state_dir / "mvp-store.key").read_bytes()) \
        == 32 + len(_KEY_MAGIC) + 32


def test_node_harness_failure_classification_skips_only_exact_bind_denial() -> None:
    assert _node_harness_failure(
        "JUNO_SOCKET_BIND_DENIED:EPERM:listen\n", 73
    ) == "socket_bind_denied"
    assert _node_harness_failure(
        "Error [ERR_MODULE_NOT_FOUND]: synthetic", 1
    ) == "module_not_found"
    assert _node_harness_failure("SyntaxError: synthetic", 1) == "syntax_error"
    assert _node_harness_failure("", 1) == "unexpected_node_failure"


class _SensitiveHandler(BaseHTTPRequestHandler):
    observed: list[tuple[str, dict | None]] = []

    def _json(self, value):
        encoded = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        self.observed.append((self.path, None))
        self._json({
            "outcome": "available", "submitted": False,
            "provider_account_jid": SENSITIVE_ACCOUNT,
            "identity_observed_us": time.time_ns() // 1000,
            "adapter_runtime_id": "runtime-fresh", "connection_epoch": "epoch-fresh",
            "transport_identity": _SENSITIVE_TRANSPORT_IDENTITY,
        })

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        self.observed.append((self.path, body))
        self._json({
            "state": "submitted", "message_id": "3EB0ABCDEF0123456789AB",
            "account": SENSITIVE_ACCOUNT, "destination": body["destination"],
        })

    def log_message(self, *_args):
        pass


class _VerticalProviderHandler(BaseHTTPRequestHandler):
    observed: list[str] = []

    def _json(self, value):
        encoded = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):
        self.observed.append(self.path)
        self.rfile.read(int(self.headers.get("content-length", "0")))
        self._json({"allowed": True})

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        self.observed.append(path)
        if path.endswith("/profile"):
            self._json({"emailAddress": "juno@example.test"})
        elif path.endswith("/messages"):
            self._json({"messages": [{"id": "vertical-message"}]})
        else:
            encoded = base64.urlsafe_b64encode(PRIVATE_SENTINEL.encode()).decode().rstrip("=")
            self._json({"id": "vertical-message", "payload": {
                "mimeType": "text/plain", "headers": [
                    {"name": "From", "value": "sender@example.test"},
                    {"name": "To", "value": "juno@example.test"},
                    {"name": "Cc", "value": "copy@example.test"},
                    {"name": "Subject", "value": "Synthetic vertical"},
                    {"name": "Date", "value": "Wed, 5 Aug 2026 12:00:00 +0000"},
                ], "body": {"data": encoded, "size": len(PRIVATE_SENTINEL)},
            }})

    def log_message(self, *_args):
        pass


def _exception_surface(exc: BaseException) -> str:
    values: list[str] = []
    seen: set[int] = set()
    pending: list[BaseException] = [exc]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        values.extend((repr(current), str(current)))
        values.extend(traceback.format_exception(type(current), current, current.__traceback__))
        tb = current.__traceback__
        while tb is not None:
            values.extend(repr(value) for value in tb.tb_frame.f_locals.values())
            tb = tb.tb_next
        pending.extend(value for value in (current.__cause__, current.__context__) if value)
    return "\n".join(values)


def _capture_renderer_failure() -> BaseException:
    private_input = {"id": "id", "payload": {
        "mimeType": PRIVATE_SENTINEL, "headers": [], "body": {},
    }}
    try:
        render_gmail_message(private_input, expected_id="id")
    except BaseException as exc:
        private_input = None
        return exc
    raise AssertionError("renderer unexpectedly accepted malformed input")


@pytest.mark.asyncio
async def test_distinct_real_dm_source_and_owner_approval_chat_are_exact(tmp_path: Path) -> None:
    host, _transport, ordinary, sensitive = await _host(tmp_path)
    try:
        pending = _tool(_event(TRUSTED, "request", message="trusted-dm-message"), host)
        request_id = dict(pending.terminal.metadata)["request_id"]
        request = host.repository.get(request_id)
        assert request.source_chat == TRUSTED_CHAT == TRUSTED
        assert request.source_message == "trusted-dm-message"
        assert request.approval_chat == OWNER_CHAT == OWNER
        assert await host.process_once()
        assert len(ordinary.messages) == 1
        assert ordinary.destinations == [OWNER_CHAT]

        wrong_events = (
            _event(OWNER, f"/approve {request_id}", chat=TRUSTED_CHAT, message="wrong-chat"),
            _event(OWNER, f"/approve {request_id}", account="99999999999@s.whatsapp.net"),
            _event(TRUSTED, f"/approve {request_id}", chat=OWNER_CHAT),
        )
        assert all(not host.intercept_approval(event).mutated for event in wrong_events)
        assert host.intercept_approval(
            _event(OWNER, f"/approve {request_id}", message="owner-dm-decision")
        ).mutated
        assert await host.process_once()
        assert len(sensitive.calls) == 1
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_exact_owner_decision_event_is_one_time_across_requests_and_restart(
    tmp_path: Path,
) -> None:
    host, _transport, _ordinary, sensitive = await _host(tmp_path)
    config, dependencies = host.config, host.dependencies
    first = _tool(_event(TRUSTED, "request", message="approval-replay-request-1"), host)
    second = _tool(_event(TRUSTED, "request", message="approval-replay-request-2"), host)
    first_id = dict(first.terminal.metadata)["request_id"]
    second_id = dict(second.terminal.metadata)["request_id"]
    exact_message_id = "owner-provider-decision-once"
    try:
        assert host.intercept_approval(_event(
            OWNER, f"/approve {first_id}", message=exact_message_id,
        )).mutated
        assert not host.intercept_approval(_event(
            OWNER, f"/deny {first_id}", message=exact_message_id,
        )).mutated
        assert not host.intercept_approval(_event(
            OWNER, f"/approve {second_id}", message=exact_message_id,
        )).mutated
        assert await host.process_once()
        assert await host.process_once()
        assert len(sensitive.calls) == 1
    finally:
        await host.stop()

    restarted = JunoPrivateReadMvpHost(
        config, dependencies, active_profile="juno"
    )
    assert await restarted.start(_background_worker=False)
    try:
        assert not restarted.intercept_approval(_event(
            OWNER, f"/approve {second_id}", message=exact_message_id,
        )).mutated
        assert await restarted.process_once() is False
        assert len(sensitive.calls) == 1
    finally:
        await restarted.stop()


@pytest.mark.asyncio
async def test_group_source_is_possible_only_when_exactly_configured(tmp_path: Path) -> None:
    raw = _raw_config(tmp_path)
    raw["requesters"][1]["source_chat"] = "1234567890@g.us"
    config = JunoPrivateReadMvpConfig.parse(raw)
    host = JunoPrivateReadMvpHost(
        config,
        JunoPrivateReadDependencies(
            OpenFgaChecker(config, FakeJsonTransport()),
            GmailNewestInboxProvider(config, FakeJsonTransport()),
            FakeOrdinary(), FakeSensitive(),
        ),
        active_profile="juno",
    )
    assert await host.start(_background_worker=False)
    try:
        allowed = host.context_for_event(
            _event(TRUSTED, "request", chat="1234567890@g.us", message="group-message")
        )
        rejected = host.context_for_event(
            _event(TRUSTED, "request", chat="9999999999@g.us", message="group-message")
        )
        assert allowed is not None
        assert rejected is None
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_exact_source_event_replay_is_durable_across_restart(tmp_path: Path) -> None:
    host, _transport, _ordinary, sensitive = await _host(tmp_path)
    config, dependencies = host.config, host.dependencies
    event = _event(OWNER, "request", message="provider-message-replayed")
    first = _tool(event, host)
    second = _tool(event, host)
    assert dict(first.terminal.metadata)["request_id"] == dict(second.terminal.metadata)["request_id"]
    assert await host.process_once()
    assert len(sensitive.calls) == 1
    await host.stop()

    restarted = JunoPrivateReadMvpHost(config, dependencies, active_profile="juno")
    assert await restarted.start(_background_worker=False)
    try:
        assert _tool(event, restarted).terminal.status == "safe_failure"
        assert await restarted.process_once() is False
        assert len(sensitive.calls) == 1
        conn = restarted.store._connect()
        try:
            assert conn.execute("SELECT count(*) FROM private_read_mvp_requests").fetchone()[0] == 1
        finally:
            conn.close()
    finally:
        await restarted.stop()


def _sqlite_snapshot(source: Path, destination: Path) -> None:
    source_conn = sqlite3.connect(source)
    destination_conn = sqlite3.connect(destination)
    try:
        source_conn.backup(destination_conn)
    finally:
        destination_conn.close()
        source_conn.close()
    destination.chmod(0o600)


@pytest.mark.asyncio
async def test_restored_valid_hmac_pre_delivery_sqlite_cannot_disclose_twice(
    tmp_path: Path,
) -> None:
    host, transport, ordinary, sensitive = await _host(tmp_path)
    config, dependencies = host.config, host.dependencies
    result = _tool(_event(OWNER, "request", message="sqlite-rollback-source"), host)
    request_id = dict(result.terminal.metadata)["request_id"]
    snapshot = tmp_path / "pre-delivery.db"
    _sqlite_snapshot(host.store.db_path, snapshot)
    assert await host.process_once()
    assert len(sensitive.calls) == 1
    await host.stop()

    shutil.copyfile(snapshot, config.state_dir / "authorization.db")
    (config.state_dir / "authorization.db").chmod(0o600)
    for suffix in ("-wal", "-shm"):
        path = config.state_dir / ("authorization.db" + suffix)
        if path.exists():
            path.unlink()
    restarted = JunoPrivateReadMvpHost(config, dependencies, active_profile="juno")
    assert await restarted.start(_background_worker=False)
    try:
        row = restarted.repository.get(request_id)
        assert row.status == "failed_consumed"
        assert row.terminal_code == "replay_authority_mismatch"
        assert await restarted.process_once() is False
        assert len(sensitive.calls) == 1
        assert transport.calls
        assert ordinary.messages == []
    finally:
        await restarted.stop()


@pytest.mark.asyncio
async def test_deleted_row_does_not_free_consumed_owner_provider_message(
    tmp_path: Path,
) -> None:
    host, _transport, _ordinary, sensitive = await _host(tmp_path)
    config, dependencies = host.config, host.dependencies
    first = _tool(_event(TRUSTED, "request", message="deleted-row-source-1"), host)
    first_id = dict(first.terminal.metadata)["request_id"]
    decision_id = "deleted-row-owner-decision"
    assert host.intercept_approval(_event(
        OWNER, f"/approve {first_id}", message=decision_id,
    )).mutated
    assert await host.process_once()
    assert len(sensitive.calls) == 1
    conn = host.store._connect()
    try:
        conn.execute("DELETE FROM private_read_mvp_requests WHERE request_id=?", (first_id,))
        conn.commit()
    finally:
        conn.close()
    await host.stop()

    restarted = JunoPrivateReadMvpHost(config, dependencies, active_profile="juno")
    assert await restarted.start(_background_worker=False)
    try:
        second = _tool(_event(
            TRUSTED, "request", message="deleted-row-source-2"
        ), restarted)
        second_id = dict(second.terminal.metadata)["request_id"]
        replay = restarted.intercept_approval(_event(
            OWNER, f"/approve {second_id}", message=decision_id,
        ))
        assert replay.matched and not replay.mutated
        assert await restarted.process_once()
        assert await restarted.process_once() is False
        assert len(sensitive.calls) == 1
    finally:
        await restarted.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["journal_missing", "journal_truncated", "journal_corrupt",
                                    "marker_missing", "marker_corrupt", "both_missing"])
async def test_required_replay_authority_damage_keeps_host_unpublished_and_offline(
    tmp_path: Path, damage: str,
) -> None:
    host, transport, ordinary, sensitive = await _host(tmp_path)
    config, dependencies = host.config, host.dependencies
    _tool(_event(OWNER, "request", message="journal-damage-source"), host)
    await host.stop()
    journal = config.state_dir / JOURNAL_NAME
    marker = config.state_dir / MARKER_NAME
    if damage == "journal_missing":
        journal.unlink()
    elif damage == "both_missing":
        journal.unlink()
        marker.unlink()
    elif damage == "journal_truncated":
        value = journal.read_bytes()
        journal.write_bytes(value.splitlines(keepends=True)[0])
    elif damage == "journal_corrupt":
        value = bytearray(journal.read_bytes())
        value[min(10, len(value) - 1)] ^= 1
        journal.write_bytes(value)
    elif damage == "marker_missing":
        marker.unlink()
    else:
        marker.write_text("corrupt\n", encoding="utf-8")
    for path in (journal, marker):
        if path.exists():
            path.chmod(0o600)
    restarted = JunoPrivateReadMvpHost(config, dependencies, active_profile="juno")
    assert not await restarted.start(_background_worker=False)
    assert not restarted.is_healthy()
    assert not check_private_read_request_runtime()
    assert transport.calls == []
    assert ordinary.messages == []
    assert sensitive.calls == []


_KEY_DAMAGE_CASES = (
    "deleted", "truncate-0", "truncate-1", "truncate-31",
    "truncate-33", "truncate-mid-seal", "truncate-complete-minus-1",
    "complete-plus-extra", "corrupt-key", "corrupt-magic",
    "corrupt-version", "corrupt-seal-mac", "mode", "hardlink",
    "symlink", "replaceable-parent", "owner",
)


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", _KEY_DAMAGE_CASES)
async def test_used_sealed_state_key_damage_fails_real_host_startup_offline(
    tmp_path: Path, damage: str,
) -> None:
    """Durable regression evidence for already-correct sealed-key rejection.

    The 32-byte raw-key checkpoint is intentionally not included: it is the
    exact historical migration input. Every listed case starts from a key
    whose seal has been created and whose replay authority has been appended.
    """
    host, transport, ordinary, sensitive = await _host(tmp_path)
    config, dependencies = host.config, host.dependencies
    result = _tool(_event(
        TRUSTED, "request", message=f"sealed-key-source-{damage}"
    ), host)
    assert result.terminal.status == "deferred"
    await host.stop()

    key = config.state_dir / "mvp-store.key"
    complete = key.read_bytes()
    assert len(complete) == 32 + len(_KEY_MAGIC) + 32
    assert (config.state_dir / JOURNAL_NAME).stat().st_size > 0
    assert (config.state_dir / MARKER_NAME).stat().st_size > 0
    transport.calls.clear()
    ordinary.messages.clear()
    sensitive.calls.clear()

    if damage == "deleted":
        key.unlink()
    elif damage.startswith("truncate-"):
        boundary = {
            "truncate-0": 0,
            "truncate-1": 1,
            "truncate-31": 31,
            "truncate-33": 33,
            "truncate-mid-seal": 32 + max(1, len(_KEY_MAGIC) // 2),
            "truncate-complete-minus-1": len(complete) - 1,
        }[damage]
        key.write_bytes(complete[:boundary])
        key.chmod(0o600)
    elif damage == "complete-plus-extra":
        key.write_bytes(complete + b"x")
        key.chmod(0o600)
    elif damage.startswith("corrupt-"):
        changed = bytearray(complete)
        index = {
            "corrupt-key": 0,
            "corrupt-magic": 32,
            "corrupt-version": 32 + _KEY_MAGIC.index(b"1"),
            "corrupt-seal-mac": len(changed) - 1,
        }[damage]
        changed[index] ^= 1
        key.write_bytes(changed)
        key.chmod(0o600)
    elif damage == "mode":
        key.chmod(0o640)
    elif damage == "hardlink":
        os.link(key, config.state_dir / "mvp-store.key.link")
    elif damage == "symlink":
        original = config.state_dir / "mvp-store.key.original"
        key.rename(original)
        key.symlink_to(original.name)
    elif damage == "replaceable-parent":
        config.state_dir.chmod(0o777)
    elif damage == "owner":
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            pytest.skip("file ownership damage is not constructible without privilege")
        os.chown(key, 1, -1)

    restarted = JunoPrivateReadMvpHost(config, dependencies, active_profile="juno")
    exposed: list[str] = []
    try:
        started = await restarted.start(_background_worker=False)
    except BaseException as exc:  # assertion records any accidental exposure
        exposed.extend((str(exc), repr(exc), traceback.format_exc()))
        started = False
    assert not started
    assert not restarted.is_healthy()
    assert not check_private_read_request_runtime()
    assert transport.calls == []
    assert ordinary.messages == []
    assert sensitive.calls == []
    assert all(len(value) <= 4096 for value in exposed)
    assert all(PRIVATE_SENTINEL not in value for value in exposed)
    assert all(CREDENTIAL_SENTINEL not in value for value in exposed)


@pytest.mark.asyncio
async def test_journal_fsync_before_marker_failure_depublishes_without_db_transition(
    tmp_path: Path, monkeypatch,
) -> None:
    host, transport, ordinary, sensitive = await _host(tmp_path)
    original = host._journal._replace_marker

    def fail_marker(*_args, **_kwargs):
        raise OSError("synthetic marker failure")

    monkeypatch.setattr(host._journal, "_replace_marker", fail_marker)
    result = _tool(_event(OWNER, "request", message="journal-marker-crash"), host)
    assert result.terminal.status == "safe_failure"
    assert not host.is_healthy()
    assert not check_private_read_request_runtime()
    assert transport.calls == [] and ordinary.messages == [] and sensitive.calls == []
    monkeypatch.setattr(host._journal, "_replace_marker", original)
    await host.stop()


@pytest.mark.asyncio
async def test_journal_delivery_tombstone_survives_db_commit_failure_without_disclosure(
    tmp_path: Path,
) -> None:
    host, transport, ordinary, sensitive = await _host(tmp_path)
    config, dependencies = host.config, host.dependencies
    result = _tool(_event(OWNER, "request", message="delivery-db-crash"), host)
    request_id = dict(result.terminal.metadata)["request_id"]
    fired = [False]
    conn = host.store._connect()
    try:
        values = host.repository._values(conn.execute(
            "SELECT * FROM private_read_mvp_requests WHERE request_id=?", (request_id,)
        ).fetchone())
    finally:
        conn.close()
    request_journal_id = host.repository._request_journal_id(values)

    def fail_commit(step):
        if (
            step == "commit.before" and not fired[0]
            and host._journal.contains("delivery", request_journal_id)
        ):
            fired[0] = True
            raise RuntimeError("synthetic commit failure")

    host.store._fault_hook = fail_commit
    with pytest.raises(RuntimeError, match="synthetic commit failure"):
        await host.process_once()
    host.store._fault_hook = None
    assert sensitive.calls == [] and transport.calls == []
    await host.stop()
    restarted = JunoPrivateReadMvpHost(config, dependencies, active_profile="juno")
    assert await restarted.start(_background_worker=False)
    try:
        row = restarted.repository.get(request_id)
        assert row.status == "failed_consumed"
        assert await restarted.process_once() is False
        assert sensitive.calls == [] and transport.calls == [] and ordinary.messages == []
    finally:
        await restarted.stop()


@pytest.mark.asyncio
async def test_concurrent_exact_event_creates_one_durable_request(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    host, _transport, _ordinary, _sensitive = await _host(tmp_path)
    try:
        context = host.context_for_event(_event(
            OWNER, "request", message="concurrent-provider-message"
        ))
        with ThreadPoolExecutor(max_workers=8) as pool:
            requests = list(pool.map(
                lambda _: host.repository.create(context, host.config), range(16)
            ))
        assert len({request.request_id for request in requests}) == 1
        conn = host.store._connect()
        try:
            assert conn.execute("SELECT count(*) FROM private_read_mvp_requests").fetchone()[0] == 1
        finally:
            conn.close()
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_claimed_notice_is_terminally_consumed_on_restart(tmp_path: Path) -> None:
    host, _transport, ordinary, sensitive = await _host(tmp_path)
    config, dependencies = host.config, host.dependencies
    result = _tool(_event(TRUSTED, "request", message="notice-crash-boundary"), host)
    request_id = dict(result.terminal.metadata)["request_id"]
    assert host.repository.claim_notice(host._clock_us()) is not None
    await host.stop()

    restarted = JunoPrivateReadMvpHost(config, dependencies, active_profile="juno")
    assert await restarted.start(_background_worker=False)
    try:
        request = restarted.repository.get(request_id)
        assert request.status == "failed_consumed"
        assert request.notice_claimed is True
        assert await restarted.process_once() is False
        assert ordinary.messages == []
        assert sensitive.calls == []
    finally:
        await restarted.stop()


@pytest.mark.asyncio
async def test_read_crossing_expiry_never_reaches_sensitive_submit(tmp_path: Path) -> None:
    clock = [time.time_ns() // 1000]
    config = JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path))
    transport = FakeJsonTransport()
    sensitive = FakeSensitive()

    class CrossingGmail:
        async def read(self) -> str:
            clock[0] += 61_000_000
            return PRIVATE_SENTINEL

    host = JunoPrivateReadMvpHost(
        config,
        JunoPrivateReadDependencies(
            OpenFgaChecker(config, transport), CrossingGmail(), FakeOrdinary(), sensitive,
        ),
        active_profile="juno",
        _clock_us=lambda: clock[0],
    )
    assert await host.start(_background_worker=False)
    try:
        result = _tool(_event(OWNER, "request", message="expiry-crossing-read"), host)
        request_id = dict(result.terminal.metadata)["request_id"]
        assert await host.process_once()
        request = host.repository.get(request_id)
        assert request.status == "failed_consumed"
        assert sensitive.calls == []
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_clock_reaches_exact_expiry_during_final_validation_and_never_submits(
    tmp_path: Path,
) -> None:
    clock = [time.time_ns() // 1000]
    config = JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path))

    class ClockSensitive(FakeSensitive):
        async def observe_identity(self, *, request):
            return _runtime_identity(observed_at_us=clock[0])

    sensitive = ClockSensitive()
    host = JunoPrivateReadMvpHost(
        config,
        JunoPrivateReadDependencies(
            OpenFgaChecker(config, FakeJsonTransport()),
            GmailNewestInboxProvider(config, FakeJsonTransport()),
            FakeOrdinary(), sensitive,
        ),
        active_profile="juno", _clock_us=lambda: clock[0],
    )
    assert await host.start(_background_worker=False)
    try:
        result = _tool(_event(OWNER, "request", message="exact-expiry-final-validation"), host)
        request_id = dict(result.terminal.metadata)["request_id"]
        request = host.repository.get(request_id)
        original = host.repository.validate_claim
        validations = [0]

        def crossing_validate(candidate, token, now_us):
            validations[0] += 1
            validated = original(candidate, token, now_us)
            if validations[0] == 4:
                clock[0] = candidate.expires_at_us
            return validated

        host.repository.validate_claim = crossing_validate
        assert await host.process_once()
        terminal = host.repository.get(request_id)
        assert terminal.status == "failed_consumed"
        assert terminal.terminal_code == "expired_after_final_validation"
        assert sensitive.calls == []
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_validate_claim_rejects_exact_expiry(tmp_path: Path) -> None:
    host, _transport, _ordinary, _sensitive = await _host(tmp_path)
    try:
        result = _tool(_event(OWNER, "request", message="exact-expiry-claim"), host)
        request_id = dict(result.terminal.metadata)["request_id"]
        request, token = host.repository.claim_approved(host._clock_us())
        assert request.request_id == request_id
        assert host.repository.validate_claim(request, token, request.expires_at_us) is None
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_sensitive_identity_drift_fails_before_gmail(tmp_path: Path) -> None:
    config = JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path))
    transport = FakeJsonTransport()

    class DriftingSensitive(FakeSensitive):
        def __init__(self):
            super().__init__()
            self.observations = 0

        async def observe_identity(self, *, request):
            self.observations += 1
            epoch = "epoch-one" if self.observations == 1 else "epoch-two"
            return _runtime_identity("runtime-one", epoch=epoch)

    sensitive = DriftingSensitive()
    host = JunoPrivateReadMvpHost(
        config,
        JunoPrivateReadDependencies(
            OpenFgaChecker(config, transport), GmailNewestInboxProvider(config, transport),
            FakeOrdinary(), sensitive,
        ),
        active_profile="juno",
    )
    assert await host.start(_background_worker=False)
    try:
        _tool(_event(OWNER, "request", message="identity-drift"), host)
        assert await host.process_once()
        assert not any(call["authority"] == GMAIL_AUTHORITY for call in transport.calls)
        assert sensitive.calls == []
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_sensitive_runtime_restart_after_read_prevents_submission(tmp_path: Path) -> None:
    config = JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path))
    transport = FakeJsonTransport()

    class RestartingSensitive(FakeSensitive):
        def __init__(self):
            super().__init__()
            self.observations = 0

        async def observe_identity(self, *, request):
            self.observations += 1
            runtime = "runtime-one" if self.observations < 3 else "runtime-restarted"
            return _runtime_identity(runtime, epoch="epoch-one")

    sensitive = RestartingSensitive()
    host = JunoPrivateReadMvpHost(
        config,
        JunoPrivateReadDependencies(
            OpenFgaChecker(config, transport), GmailNewestInboxProvider(config, transport),
            FakeOrdinary(), sensitive,
        ),
        active_profile="juno",
    )
    assert await host.start(_background_worker=False)
    try:
        _tool(_event(OWNER, "request", message="runtime-restart"), host)
        assert await host.process_once()
        assert any(call["authority"] == GMAIL_AUTHORITY for call in transport.calls)
        assert sensitive.calls == []
    finally:
        await host.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(("mode", "accepted"), [
    ("exact", True),
    ("stale", False),
    ("future", False),
    ("malformed", False),
    ("arbitrary_transport", False),
])
async def test_sensitive_identity_requires_fresh_exact_reviewed_transport(
    tmp_path: Path, mode: str, accepted: bool,
) -> None:
    host, _transport, _ordinary, _sensitive = await _host(tmp_path)
    try:
        result = _tool(_event(OWNER, "request", message="identity-" + mode), host)
        request = host.repository.get(dict(result.terminal.metadata)["request_id"])

        class IdentityTransport:
            async def request(self, **_call):
                observed: object = time.time_ns() // 1000
                if mode == "stale":
                    observed -= 6_000_000
                elif mode == "future":
                    observed += 1_000_000
                elif mode == "malformed":
                    observed = "not-an-integer"
                proof = _SENSITIVE_TRANSPORT_IDENTITY
                if mode == "arbitrary_transport":
                    proof = {"manifest_sha256": "a" * 64}
                return {
                    "outcome": "available", "submitted": False,
                    "provider_account_jid": SENSITIVE_ACCOUNT,
                    "identity_observed_us": observed,
                    "adapter_runtime_id": "reviewed-runtime",
                    "connection_epoch": "reviewed-epoch",
                    "transport_identity": proof,
                }

        from gateway.juno_private_read_mvp import _sealed_sensitive_identity
        identity = await _sealed_sensitive_identity(host.config, IdentityTransport(), request)
        assert (identity is not None) is accepted
        if identity is not None:
            assert identity.transport_identity == tuple(
                sorted(_SENSITIVE_TRANSPORT_IDENTITY.items())
            )
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_non_monotonic_sensitive_identity_fails_before_private_read(
    tmp_path: Path,
) -> None:
    config = JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path))
    transport = FakeJsonTransport()
    observed = time.time_ns() // 1000

    class NonMonotonicSensitive(FakeSensitive):
        def __init__(self):
            super().__init__()
            self.count = 0

        async def observe_identity(self, *, request):
            self.count += 1
            return _runtime_identity(
                "monotonic-runtime", epoch="monotonic-epoch",
                observed_at_us=observed if self.count == 1 else observed - 1,
            )

    sensitive = NonMonotonicSensitive()
    host = JunoPrivateReadMvpHost(
        config,
        JunoPrivateReadDependencies(
            OpenFgaChecker(config, transport), GmailNewestInboxProvider(config, transport),
            FakeOrdinary(), sensitive,
        ),
        active_profile="juno",
    )
    assert await host.start(_background_worker=False)
    try:
        _tool(_event(OWNER, "request", message="non-monotonic-identity"), host)
        assert await host.process_once()
        assert not any(call["authority"] == GMAIL_AUTHORITY for call in transport.calls)
        assert sensitive.calls == []
    finally:
        await host.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("observed", [
    None,
    _runtime_identity(account=ORDINARY_ACCOUNT),
    _runtime_identity(account="99999999999@s.whatsapp.net"),
])
async def test_unavailable_or_wrong_sensitive_identity_fails_before_gmail(
    tmp_path: Path, observed,
) -> None:
    config = JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path))
    transport = FakeJsonTransport()

    class Sensitive(FakeSensitive):
        async def observe_identity(self, *, request):
            return observed

    sensitive = Sensitive()
    host = JunoPrivateReadMvpHost(
        config,
        JunoPrivateReadDependencies(
            OpenFgaChecker(config, transport), GmailNewestInboxProvider(config, transport),
            FakeOrdinary(), sensitive,
        ),
        active_profile="juno",
    )
    assert await host.start(_background_worker=False)
    try:
        _tool(_event(OWNER, "request", message="bad-identity" + repr(observed)), host)
        assert await host.process_once()
        assert not any(call["authority"] == GMAIL_AUTHORITY for call in transport.calls)
        assert sensitive.calls == []
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_runner_cleanup_failure_depublishes_mvp_tool(tmp_path: Path, monkeypatch) -> None:
    from gateway.run import GatewayRunner

    host, _transport, _ordinary, _sensitive = await _host(tmp_path)
    runner = object.__new__(GatewayRunner)
    runner.config = SimpleNamespace(multiplex_profiles=False)
    runner._trusted_private_read_host = host
    runner._private_read_active_principals = {}
    runner._private_read_principal = lambda _event: ("juno", ORDINARY_ACCOUNT, OWNER)

    async def inner(*_args, **_kwargs):
        return {"final_response": "ok"}

    runner._run_agent_inner = inner
    original_unbind = host.unbind_event

    def broken_unbind(binding):
        original_unbind(binding)
        raise RuntimeError("synthetic cleanup failure")

    monkeypatch.setattr(host, "unbind_event", broken_unbind)
    try:
        result = await GatewayRunner._run_agent(
            runner, "request", "context", [], _event(OWNER, "request").source,
            "session-id", session_key="session-key",
            logical_event=_event(OWNER, "request", message="runner-event"),
        )
        assert result == {"final_response": "ok"}
        assert host._running is True
        assert host.is_healthy() is False
        assert host.health()["ready"] is False
        assert check_private_read_request_runtime() is False
        assert await host.process_once() is False
    finally:
        monkeypatch.setattr(host, "unbind_event", original_unbind)
        await host.stop()


def test_yaml_merge_override_is_valid_but_explicit_duplicates_are_rejected() -> None:
    from gateway.config import _load_gateway_yaml

    merged = _load_gateway_yaml(io.StringIO(
        "defaults: &defaults\n  enabled: false\n  nested:\n    value: one\n"
        "gateway:\n  <<: *defaults\n  enabled: true\n"
    ))
    assert merged["gateway"] == {"enabled": True, "nested": {"value": "one"}}
    with pytest.raises(Exception, match="duplicate mapping key"):
        _load_gateway_yaml(io.StringIO("outer:\n  nested:\n    key: one\n    key: two\n"))


def test_invalid_primary_yaml_cannot_resurrect_legacy_private_read(
    tmp_path: Path, monkeypatch,
) -> None:
    import gateway.config as gateway_config

    raw = _raw_config(tmp_path)
    (tmp_path / "gateway.json").write_text(
        json.dumps({"trusted_private_read": raw}), encoding="utf-8"
    )
    (tmp_path / "config.yaml").write_text(
        "gateway:\n  trusted_private_read:\n    enabled: true\n    enabled: false\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gateway_config, "get_hermes_home", lambda: tmp_path)
    assert gateway_config.load_gateway_config().trusted_private_read is None


def test_legacy_private_read_is_used_only_when_primary_is_absent(
    tmp_path: Path, monkeypatch,
) -> None:
    import gateway.config as gateway_config

    raw = _raw_config(tmp_path)
    (tmp_path / "gateway.json").write_text(
        json.dumps({"trusted_private_read": raw}), encoding="utf-8"
    )
    monkeypatch.setattr(gateway_config, "get_hermes_home", lambda: tmp_path)
    assert gateway_config.load_gateway_config().trusted_private_read == raw
    (tmp_path / "config.yaml").write_text("{}\n", encoding="utf-8")
    assert gateway_config.load_gateway_config().trusted_private_read is None


def _body(value: str) -> dict:
    encoded = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    return {"data": encoded, "size": len(value.encode())}


def test_gmail_renderer_accepts_one_plain_leaf_and_marks_missing_headers() -> None:
    message = {
        "id": "message-1",
        "payload": {
            "mimeType": "multipart/alternative",
            "headers": [{"name": "From", "value": "sender@example.test"}],
            "body": {},
            "parts": [
                {"mimeType": "text/plain", "headers": [], "body": _body("plain body")},
                {"mimeType": "text/html", "headers": [], "body": _body("<b>ignored</b>")},
            ],
        },
    }
    assert render_gmail_message(message, expected_id="message-1") == (
        "From: sender@example.test\nTo: (not present)\nCc: (not present)\n"
        "Subject: (not present)\nDate: (not present)\nBody:\nplain body"
    )


@pytest.mark.parametrize("parts", [
    [{"mimeType": "text/html", "headers": [], "body": _body("html only")}],
    [
        {"mimeType": "text/plain", "headers": [], "body": _body("one")},
        {"mimeType": "text/plain", "headers": [], "body": _body("two")},
    ],
    [{"mimeType": "text/plain", "headers": [],
      "body": {"attachmentId": "remote", "size": 4}}],
])
def test_gmail_renderer_rejects_html_ambiguous_and_remote_bodies(parts) -> None:
    message = {"id": "message-1", "payload": {
        "mimeType": "multipart/alternative", "headers": [], "body": {}, "parts": parts,
    }}
    with pytest.raises(JunoPrivateReadError):
        render_gmail_message(message, expected_id="message-1")


def test_gmail_renderer_rejects_attachments_malformed_base64_and_limits() -> None:
    attachment = {"id": "message-1", "payload": {
        "mimeType": "text/plain",
        "headers": [{"name": "Content-Disposition", "value": "attachment; filename=x.txt"}],
        "body": _body("private attachment"),
    }}
    malformed = {"id": "message-1", "payload": {
        "mimeType": "text/plain", "headers": [],
        "body": {"data": "not+base64%%%", "size": 4},
    }}
    excessive = {"id": "message-1", "payload": {
        "mimeType": "multipart/mixed", "headers": [], "body": {},
        "parts": [
            {"mimeType": "text/html", "headers": [], "body": _body("ignored")}
            for _ in range(65)
        ] + [{"mimeType": "text/plain", "headers": [], "body": _body("plain")}],
    }}
    for message in (attachment, malformed, excessive):
        with pytest.raises(JunoPrivateReadError):
            render_gmail_message(message, expected_id="message-1")


@pytest.mark.asyncio
async def test_gmail_profile_full_shape_and_exact_production_queries(tmp_path: Path) -> None:
    config = JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path))
    transport = FakeJsonTransport()
    original = transport.request

    async def request(**call):
        if call["path"].endswith("/profile"):
            transport.calls.append(call)
            return {"emailAddress": "juno@example.test", "messagesTotal": 2,
                    "threadsTotal": 1, "historyId": "12345"}
        return await original(**call)

    transport.request = request
    rendered = await GmailNewestInboxProvider(config, transport).read()
    assert rendered.endswith(PRIVATE_SENTINEL)
    profile_call = next(call for call in transport.calls if call["path"].endswith("/profile"))
    list_call = next(call for call in transport.calls if call["path"].endswith("/messages"))
    assert profile_call["query"] == (("fields", "emailAddress"),)
    assert ("includeSpamTrash", "false") in list_call["query"]


def test_renderer_exception_graph_has_no_private_value() -> None:
    failure = _capture_renderer_failure()
    assert type(failure) is JunoPrivateReadError
    assert PRIVATE_SENTINEL not in _exception_surface(failure)


@pytest.mark.asyncio
async def test_credential_and_transport_exception_graphs_are_sealed(tmp_path: Path) -> None:
    raw = _raw_config(tmp_path)
    token_path = Path(raw["gmail"]["token_file"])
    token_path.write_text("{invalid-" + CREDENTIAL_SENTINEL, encoding="utf-8")
    config = JunoPrivateReadMvpConfig.parse(raw)
    with pytest.raises(JunoPrivateReadError) as credential_failure:
        await GmailNewestInboxProvider(config, FakeJsonTransport()).read()
    assert CREDENTIAL_SENTINEL not in _exception_surface(credential_failure.value)

    token_path.write_text(json.dumps({
        "access_token": CREDENTIAL_SENTINEL,
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
        "account": "juno@example.test",
        "expires_at_us": 9_000_000_000_000_000,
    }), encoding="utf-8")

    class RaisingTransport:
        async def request(self, **_call):
            raise RuntimeError(PRIVATE_SENTINEL + CREDENTIAL_SENTINEL)

    with pytest.raises(JunoPrivateReadError) as raised:
        await GmailNewestInboxProvider(config, RaisingTransport()).read()
    surface = _exception_surface(raised.value)
    assert PRIVATE_SENTINEL not in surface
    assert CREDENTIAL_SENTINEL not in surface

    request_root = tmp_path / "request"
    request_root.mkdir()
    checker_host, _transport, _ordinary, _sensitive = await _host(request_root)
    try:
        result = _tool(
            _event(OWNER, "request", message="exception-request"), checker_host
        )
        request = checker_host.repository.get(
            dict(result.terminal.metadata)["request_id"]
        )
        assert await OpenFgaChecker(config, RaisingTransport()).check(request) is False

        from gateway.juno_private_read_mvp import _SensitiveHttpSubmitter
        submitter = _SensitiveHttpSubmitter(config, RaisingTransport())
        submission = await submitter.submit(
            request=request,
            plaintext=PRIVATE_SENTINEL,
            identity=_runtime_identity(),
        )
        assert submission.state == "unknown"
        assert PRIVATE_SENTINEL not in repr(submission)
        assert CREDENTIAL_SENTINEL not in repr(submission)
    finally:
        await checker_host.stop()


@pytest.mark.asyncio
async def test_fixed_transport_refuses_redirect_without_forwarding_secrets() -> None:
    redirected: list[bytes] = []

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            redirected.append(self.rfile.read(int(self.headers.get("content-length", "0"))))
            self.send_response(200)
            self.end_headers()

        do_POST = do_GET

        def log_message(self, *_args):
            pass

    target = _loopback_server(Target)
    target_url = f"http://127.0.0.1:{target.server_port}/capture"

    class Redirect(BaseHTTPRequestHandler):
        def redirect(self):
            length = int(self.headers.get("content-length", "0"))
            if length:
                self.rfile.read(length)
            self.send_response(307)
            self.send_header("location", target_url)
            self.end_headers()

        do_GET = redirect
        do_POST = redirect

        def log_message(self, *_args):
            pass

    source = _loopback_server(Redirect)
    threads = [Thread(target=server.serve_forever, daemon=True) for server in (target, source)]
    for thread in threads:
        thread.start()
    source_url = f"http://127.0.0.1:{source.server_port}"
    transport = FixedHttpJsonTransport(_test_authorities={
        GMAIL_AUTHORITY: source_url, "http://127.0.0.1:3011": source_url,
    })
    try:
        gmail = await transport.request(
            method="GET", authority=GMAIL_AUTHORITY, path="/gmail",
            query=(), headers={"authorization": "Bearer " + CREDENTIAL_SENTINEL},
            body=None, timeout=2, max_bytes=1024,
        )
        sensitive = await transport.request(
            method="POST", authority="http://127.0.0.1:3011", path="/v1/submit",
            query=(), headers={"x-hermes-sensitive-capability": CREDENTIAL_SENTINEL,
                               "content-type": "application/json"},
            body={"private_value": PRIVATE_SENTINEL}, timeout=2, max_bytes=1024,
        )
        assert repr(gmail) == "<private transport failure>"
        assert repr(sensitive) == "<private transport failure>"
        assert redirected == []
    finally:
        source.shutdown()
        target.shutdown()
        source.server_close()
        target.server_close()
        for thread in threads:
            thread.join(timeout=2)


@pytest.mark.asyncio
async def test_fixed_authority_transport_ignores_all_ambient_proxy_variables(
    monkeypatch,
) -> None:
    target_calls: list[tuple[str, bytes]] = []
    proxy_calls: list[tuple[str, bytes]] = []

    def handler_for(capture):
        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
                capture.append((self.path, body))
                encoded = b'{"ok":true}'
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            do_GET = _handle
            do_POST = _handle

            def log_message(self, *_args):
                pass
        return Handler

    target = _loopback_server(handler_for(target_calls))
    proxy = _loopback_server(handler_for(proxy_calls))
    threads = [Thread(target=item.serve_forever, daemon=True) for item in (target, proxy)]
    for thread in threads:
        thread.start()
    proxy_url = f"http://127.0.0.1:{proxy.server_port}"
    for name in (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
    ):
        monkeypatch.setenv(name, proxy_url)
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    fixed = f"http://127.0.0.1:{target.server_port}"
    transport = FixedHttpJsonTransport(_test_authorities={
        GMAIL_AUTHORITY: fixed, OPENFGA_AUTHORITY: fixed,
        "http://127.0.0.1:3011": fixed,
    })
    try:
        calls = (
            ("GET", GMAIL_AUTHORITY, "/gmail", None,
             {"authorization": "Bearer " + CREDENTIAL_SENTINEL}),
            ("POST", OPENFGA_AUTHORITY, "/fga", {"request": "authority-only"},
             {"authorization": "Bearer " + CREDENTIAL_SENTINEL,
              "content-type": "application/json"}),
            ("POST", "http://127.0.0.1:3011", "/sensitive",
             {"private_value": PRIVATE_SENTINEL},
             {"x-hermes-sensitive-capability": CREDENTIAL_SENTINEL,
              "content-type": "application/json"}),
        )
        for method, authority, path, body, headers in calls:
            result = await transport.request(
                method=method, authority=authority, path=path, query=(), headers=headers,
                body=body, timeout=2, max_bytes=1024,
            )
            assert result == {"ok": True}
        assert [path for path, _body_value in target_calls] == [
            "/gmail", "/fga", "/sensitive",
        ]
        assert proxy_calls == []
        assert PRIVATE_SENTINEL.encode() in target_calls[-1][1]
    finally:
        for server in (target, proxy):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


@pytest.mark.asyncio
async def test_redirect_refusal_is_content_free_without_socket(monkeypatch) -> None:
    import gateway.juno_private_read_mvp as mvp
    handlers = []

    class Opener:
        def open(self, request, timeout):
            assert request.headers["Authorization"] == "Bearer " + CREDENTIAL_SENTINEL
            assert mvp._RejectRedirects().redirect_request(
                request, None, 307, "redirect", {}, "http://attacker.test/capture"
            ) is None
            raise OSError(PRIVATE_SENTINEL + CREDENTIAL_SENTINEL)

    def build_opener(*values):
        handlers.extend(values)
        return Opener()

    monkeypatch.setattr(mvp.urllib_request, "build_opener", build_opener)
    result = await FixedHttpJsonTransport().request(
        method="POST", authority=GMAIL_AUTHORITY, path="/fixed",
        query=(), headers={"authorization": "Bearer " + CREDENTIAL_SENTINEL},
        body={"private_value": PRIVATE_SENTINEL}, timeout=1, max_bytes=1024,
    )
    assert repr(result) == "<private transport failure>"
    proxy_handlers = [
        item for item in handlers if isinstance(item, mvp.urllib_request.ProxyHandler)
    ]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}
    assert any(isinstance(item, mvp._RejectRedirects) for item in handlers)
    assert PRIVATE_SENTINEL not in repr(result)
    assert CREDENTIAL_SENTINEL not in repr(result)


@pytest.mark.asyncio
async def test_python_submitter_real_http_route_uses_fresh_identity(tmp_path: Path) -> None:
    _SensitiveHandler.observed = []
    server = _loopback_server(_SensitiveHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, _transport, _ordinary, _sensitive = await _host(tmp_path)
    try:
        result = _tool(_event(OWNER, "request", message="http-seam"), host)
        request = host.repository.get(dict(result.terminal.metadata)["request_id"])
        from gateway.juno_private_read_mvp import _SensitiveHttpSubmitter
        transport = FixedHttpJsonTransport(_test_authorities={
            "http://127.0.0.1:3011": f"http://127.0.0.1:{server.server_port}",
        })
        submitter = _SensitiveHttpSubmitter(host.config, transport)
        identity = await submitter.observe_identity(request=request)
        assert identity is not None
        assert identity.registration == "runtime-fresh"
        assert identity.account == SENSITIVE_ACCOUNT
        assert identity.session == "epoch-fresh"
        assert identity.transport_identity == tuple(
            sorted(_SENSITIVE_TRANSPORT_IDENTITY.items())
        )
        submitted = await submitter.submit(
            request=request, plaintext=PRIVATE_SENTINEL, identity=identity,
        )
        assert submitted.state == "submitted"
        assert _SensitiveHandler.observed[0] == ("/v1/identity", None)
        path, body = _SensitiveHandler.observed[1]
        assert path == "/v1/submit"
        assert set(body) == {
            "request_id", "registration", "session", "account", "destination", "private_value",
        }
        assert (body["registration"], body["session"]) == ("runtime-fresh", "epoch-fresh")
    finally:
        await host.stop()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_gateway_runner_v2_production_composition_publishes_only_when_ready(
    tmp_path: Path,
) -> None:
    from gateway.run import GatewayRunner

    runner = object.__new__(GatewayRunner)
    runner.config = SimpleNamespace(trusted_private_read=_raw_config(tmp_path))
    runner._trusted_private_read_host = None
    runner._active_profile_name = lambda: "juno"
    runner.adapters = {}
    runner._profile_adapters = {}
    assert await GatewayRunner._start_trusted_private_read_host(runner) is True
    host = runner._trusted_private_read_host
    try:
        assert type(host) is JunoPrivateReadMvpHost
        assert host.is_healthy()
        assert check_private_read_request_runtime()
        binding = host.bind_event(_event(OWNER, "request", message="startup-event"))
        try:
            assert binding.private_context is True
        finally:
            host.unbind_event(binding)
    finally:
        await host.stop()
    assert check_private_read_request_runtime() is False


@pytest.mark.asyncio
async def test_real_gateway_runner_startup_dispatch_registry_and_cleanup_seam(
    tmp_path: Path, monkeypatch,
) -> None:
    import gateway.juno_private_read_mvp as mvp
    from gateway.config import GatewayConfig
    from gateway.run import GatewayRunner
    from tools.private_read_request_tool import PRIVATE_READ_REQUEST_TOOL_NAME
    from tools.registry import registry

    home = tmp_path / "home"
    profile_home = home / ".hermes" / "profiles" / "juno"
    profile_home.mkdir(parents=True, mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(profile_home))
    monkeypatch.setenv("WHATSAPP_ALLOWED_USERS", f"{OWNER},{TRUSTED}")
    authority_root = tmp_path / "authority"
    authority_root.mkdir(mode=0o700)
    raw = _raw_config(authority_root)

    class RunnerTransport(FakeJsonTransport):
        async def request(self, **call):
            if call["authority"] == "http://127.0.0.1:3011":
                if call["path"] == "/v1/identity":
                    return {
                        "outcome": "available", "submitted": False,
                        "provider_account_jid": SENSITIVE_ACCOUNT,
                        "identity_observed_us": time.time_ns() // 1000,
                        "adapter_runtime_id": "runner-runtime",
                        "connection_epoch": "runner-epoch",
                        "transport_identity": _SENSITIVE_TRANSPORT_IDENTITY,
                    }
                return {
                    "state": "submitted", "message_id": "3EB0ABCDEF0123456789AB",
                    "account": SENSITIVE_ACCOUNT,
                    "destination": call["body"]["destination"],
                }
            return await super().request(**call)

    fake_transport = RunnerTransport()
    monkeypatch.setattr(mvp, "FixedHttpJsonTransport", lambda: fake_transport)

    class Adapter:
        def __init__(self):
            self.sent = []

        async def send(self, destination, text):
            self.sent.append((destination, text))
            return SimpleNamespace(success=True, message_id="runner-notice")

    config = GatewayConfig(
        sessions_dir=tmp_path / "sessions",
        trusted_private_read=raw,
        platforms={Platform.WHATSAPP: PlatformConfig(
            enabled=True,
            extra={"allow_from": [OWNER, TRUSTED], "dm_policy": "allowlist"},
        )},
    )
    runner = GatewayRunner(config)
    adapter = Adapter()
    runner.adapters[Platform.WHATSAPP] = adapter
    runner.delivery_router.adapters = runner.adapters
    assert runner._active_profile_name() == "juno"
    assert await runner._start_trusted_private_read_host()
    host = runner._trusted_private_read_host
    observed_results: list[object] = []

    async def fake_model(*_args, **_kwargs):
        entry = registry.get_entry(PRIVATE_READ_REQUEST_TOOL_NAME)
        result = entry.handler({"capability_id": CAPABILITY_ID}, tool_call_id="runner-tool")
        observed_results.append(result)
        return {"final_response": result.terminal.final_response, "messages": [],
                "api_calls": 0, "tools": [PRIVATE_READ_REQUEST_TOOL_NAME]}

    monkeypatch.setattr(runner, "_run_agent_inner", fake_model)
    trusted = _event(
        TRUSTED, "read newest inbox", profile=None, message="runner-trusted-provider-message",
    )
    wrong_events = (
        _event(TRUSTED, "x", profile="default", message="runner-wrong-profile"),
        _event(TRUSTED, "x", account="99999999999@s.whatsapp.net",
               profile=None, message="runner-wrong-account"),
        _event(TRUSTED, "x", chat=OWNER_CHAT, profile=None,
               message="runner-wrong-chat"),
        _event(TRUSTED, "x", profile=None, message=""),
    )
    try:
        dispatched = await runner._run_agent(
            trusted.text, "", [], trusted.source, "runner-session",
            session_key="runner-session-key", logical_event=trusted,
        )
        assert observed_results[-1].terminal.status == "deferred"
        request_id = dict(observed_results[-1].terminal.metadata)["request_id"]
        durable = host.repository.get(request_id)
        assert durable.gmail_account == "juno@example.test"
        assert durable.openfga_store_id == "store-juno"
        assert durable.openfga_model_id == "model-juno"
        assert durable.provider_authority_digest == mvp._provider_authority_digest(
            host.config
        )
        trusted_context = host.context_for_event(trusted)
        assert trusted_context is not None
        _assert_sealed_source_provenance(host, trusted_context)
        for wrong in wrong_events:
            await runner._run_agent(
                wrong.text, "", [], wrong.source, "wrong-session",
                session_key="wrong-session-key", logical_event=wrong,
            )
            assert observed_results[-1].terminal.status == "safe_failure"
        for _ in range(100):
            if adapter.sent:
                break
            await asyncio.sleep(0.01)
        assert adapter.sent and adapter.sent[0][0] == OWNER_CHAT
        owner = _event(
            OWNER, f"/approve {request_id}", profile=None,
            message="runner-owner-provider-message",
        )
        response = await runner._handle_message(owner)
        assert response == "Private-read request approved."
        for _ in range(100):
            row = host.repository.get(request_id)
            if row.status in {"consumed", "failed_consumed"}:
                break
            await asyncio.sleep(0.01)
        assert host.repository.get(request_id).status == "consumed"
        serialized = json.dumps({"dispatch": dispatched, "results": [repr(x) for x in observed_results]})
        assert PRIVATE_SENTINEL not in serialized
        assert CREDENTIAL_SENTINEL not in serialized
        with pytest.raises(JunoPrivateReadError):
            host.request_from_tool(CAPABILITY_ID)
    finally:
        await host.stop()
        runner._trusted_private_read_host = None
    assert not check_private_read_request_runtime()


@pytest.mark.asyncio
async def test_dedicated_juno_profile_binds_profileless_events_and_real_adapter_map(
    tmp_path: Path,
) -> None:
    config = JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path))

    class Adapter:
        def __init__(self):
            self.sent = []

        async def send(self, destination, text):
            self.sent.append((destination, text))
            return SimpleNamespace(success=True, message_id="ordinary-provider-notice")

    adapter = Adapter()
    runner = SimpleNamespace(
        _active_profile_name=lambda: "juno",
        adapters={Platform.WHATSAPP: adapter},
        _profile_adapters={"secondary": {}},
    )
    dependencies = compose_juno_private_read_mvp_services(runner, config)
    host = JunoPrivateReadMvpHost(
        config, dependencies, active_profile=runner._active_profile_name()
    )
    assert await host.start(_background_worker=False)
    try:
        inbound = _event(
            TRUSTED, "request", profile=None, message="profileless-trusted-request"
        )
        context = host.context_for_event(inbound)
        assert context is not None and context.source_profile == "juno"
        result = _tool(inbound, host)
        request_id = dict(result.terminal.metadata)["request_id"]
        assert await host.process_once()
        assert len(adapter.sent) == 1
        assert adapter.sent[0][0] == OWNER_CHAT
        decision = _event(
            OWNER, f"/approve {request_id}", profile=None,
            message="profileless-owner-decision",
        )
        assert host.intercept_approval(decision).mutated
        approved = host.repository.get(request_id)
        assert approved.status == "approved"
        assert approved.approval_message == "profileless-owner-decision"
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_offline_cross_runtime_producer_to_private_delivery_vertical(
    tmp_path: Path, caplog, monkeypatch,
) -> None:
    import gateway.juno_private_read_mvp as mvp
    from gateway.config import GatewayConfig
    from hermes_state import SessionDB
    from plugins.platforms.whatsapp.adapter import WhatsAppAdapter
    from gateway.run import GatewayRunner
    from tools.private_read_request_tool import PRIVATE_READ_REQUEST_TOOL_NAME
    from tools.registry import registry

    caplog.set_level(logging.DEBUG)
    home = tmp_path / "home"
    profile_home = home / ".hermes" / "profiles" / "juno"
    profile_home.mkdir(parents=True, mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(profile_home))
    monkeypatch.setenv("WHATSAPP_ALLOWED_USERS", f"{OWNER},{TRUSTED}")
    _VerticalProviderHandler.observed = []
    raw = _raw_config(tmp_path)
    Path(raw["openfga"]["api_credential_file"]).write_text(
        CREDENTIAL_SENTINEL, encoding="utf-8"
    )
    token_path = Path(raw["gmail"]["token_file"])
    token_data = json.loads(token_path.read_text(encoding="utf-8"))
    token_data["access_token"] = CREDENTIAL_SENTINEL
    token_path.write_text(json.dumps(token_data), encoding="utf-8")
    config = JunoPrivateReadMvpConfig.parse(raw)

    capture = tmp_path / "private-delivery-capture.jsonl"
    capture.touch(mode=0o600)
    harness = Path(os.environ.get("JUNO_ISOLATED_SENSITIVE_HARNESS") or (
        Path(__file__).parents[1] / "fixtures/juno_sensitive_http_harness.mjs"
    ))
    sensitive_process = subprocess.Popen(
        ["node", str(harness)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env={
            **os.environ,
            "JUNO_TEST_TRANSPORT_IDENTITY": json.dumps(_SENSITIVE_TRANSPORT_IDENTITY),
            "JUNO_TEST_DELIVERY_CAPTURE": str(capture),
            "JUNO_TEST_SENSITIVE_CAPABILITY": "s" * 48,
        },
    )
    selector = selectors.DefaultSelector()
    selector.register(sensitive_process.stdout, selectors.EVENT_READ)
    # Cold imports from an isolated npm tree can be slow on encrypted/remote
    # filesystems; this is startup, not a provider deadline.
    ready = selector.select(timeout=60)
    selector.close()
    if not ready:
        if sensitive_process.poll() is None:
            sensitive_process.terminate()
            sensitive_process.wait(timeout=5)
        classification = _node_harness_failure(
            sensitive_process.stderr.read(), sensitive_process.returncode,
        )
        pytest.fail(f"Node vertical harness timed out: {classification}")
    first_line = sensitive_process.stdout.readline()
    if not first_line:
        returncode = sensitive_process.wait(timeout=5)
        classification = _node_harness_failure(
            sensitive_process.stderr.read(), returncode,
        )
        if classification == "socket_bind_denied":
            pytest.skip("execution sandbox positively denied Node loopback listen")
        pytest.fail(f"Node vertical harness failed: {classification}")
    sensitive_port = json.loads(first_line)["port"]
    try:
        provider = HTTPServer(("127.0.0.1", 0), _VerticalProviderHandler)
    except PermissionError:
        sensitive_process.terminate()
        sensitive_process.wait(timeout=5)
        pytest.skip("execution sandbox positively denied Python provider loopback listen")
    provider_thread = Thread(target=provider.serve_forever, daemon=True)
    provider_thread.start()

    class OrdinaryAdapter:
        def __init__(self):
            self.sent = []

        async def send(self, destination, text):
            self.sent.append((destination, text))
            return SimpleNamespace(success=True, message_id="ordinary-vertical-notice")

    authority = f"http://127.0.0.1:{provider.server_port}"
    transport = FixedHttpJsonTransport(_test_authorities={
        OPENFGA_AUTHORITY: authority,
        GMAIL_AUTHORITY: authority,
        "http://127.0.0.1:3011": f"http://127.0.0.1:{sensitive_port}",
    })
    monkeypatch.setattr(mvp, "FixedHttpJsonTransport", lambda: transport)
    runner_config = GatewayConfig(
        sessions_dir=tmp_path / "runner-sessions",
        trusted_private_read=raw,
        platforms={Platform.WHATSAPP: PlatformConfig(
            enabled=True,
            extra={"allow_from": [OWNER, TRUSTED], "dm_policy": "allowlist"},
        )},
    )
    runner = GatewayRunner(runner_config)
    ordinary_adapter = OrdinaryAdapter()
    runner.adapters[Platform.WHATSAPP] = ordinary_adapter
    runner.delivery_router.adapters = runner.adapters
    assert runner._active_profile_name() == "juno"
    assert await runner._start_trusted_private_read_host()
    host = runner._trusted_private_read_host
    tool_results: list[object] = []

    async def fake_model(*_args, **_kwargs):
        entry = registry.get_entry(PRIVATE_READ_REQUEST_TOOL_NAME)
        tool_result = entry.handler(
            {"capability_id": CAPABILITY_ID}, tool_call_id="vertical-tool"
        )
        tool_results.append(tool_result)
        return {
            "final_response": tool_result.terminal.final_response,
            "messages": [], "api_calls": 0,
            "tools": [PRIVATE_READ_REQUEST_TOOL_NAME],
        }

    monkeypatch.setattr(runner, "_run_agent_inner", fake_model)
    session_db = None
    try:
        bridge_data = _node_forwarded_event(
            sender=TRUSTED, text="read newest inbox message",
            message_id="VERTICAL-TRUSTED-PROVIDER-MESSAGE",
        )
        inbound_adapter = WhatsAppAdapter(PlatformConfig(
            enabled=True, extra={"allow_from": [TRUSTED, OWNER], "dm_policy": "allowlist"},
        ))
        inbound = await inbound_adapter._build_message_event(bridge_data)
        assert inbound is not None
        assert inbound.message_id == "VERTICAL-TRUSTED-PROVIDER-MESSAGE"
        assert inbound.metadata["whatsapp_account_id"] == ORDINARY_ACCOUNT
        assert inbound.metadata["whatsapp_inbound_provenance"] \
            == ORDINARY_INBOUND_PROVENANCE
        assert inbound.source.profile is None

        dispatch = await runner._run_agent(
            inbound.text, "", [], inbound.source, "vertical-session",
            session_key="vertical-session-key", logical_event=inbound,
        )
        result = tool_results[-1]
        request_id = dict(result.terminal.metadata)["request_id"]
        durable = host.repository.get(request_id)
        assert durable.gmail_account == "juno@example.test"
        assert durable.openfga_store_id == "store-juno"
        assert durable.openfga_model_id == "model-juno"
        assert durable.provider_authority_digest == mvp._provider_authority_digest(
            host.config
        )
        inbound_context = host.context_for_event(inbound)
        assert inbound_context is not None
        _assert_sealed_source_provenance(host, inbound_context)
        assert json.loads(result.content) == {
            "status": "deferred", "reason": "approval_required"
        }
        for _ in range(200):
            if ordinary_adapter.sent:
                break
            await asyncio.sleep(0.01)
        assert len(ordinary_adapter.sent) == 1

        approval_data = _node_forwarded_event(
            sender=OWNER, text=f"/approve {request_id}",
            message_id="VERTICAL-OWNER-PROVIDER-DECISION",
        )
        approval = await inbound_adapter._build_message_event(approval_data)
        assert approval.source.profile is None
        assert await runner._handle_message(approval) == "Private-read request approved."
        for _ in range(300):
            if host.repository.get(request_id).status in {"consumed", "failed_consumed"}:
                break
            await asyncio.sleep(0.01)
        assert host.repository.get(request_id).status == "consumed"
        replay_approval = await runner._handle_message(approval)
        assert replay_approval != "Private-read request approved."
        await runner._run_agent(
            inbound.text, "", [], inbound.source, "vertical-replay-session",
            session_key="vertical-replay-session-key", logical_event=inbound,
        )
        assert tool_results[-1].terminal.status == "safe_failure"

        deliveries = [json.loads(line) for line in capture.read_text().splitlines()]
        assert len(deliveries) == 1
        assert deliveries[0]["chat"] == "77777777777@s.whatsapp.net"
        assert deliveries[0]["messageId"] == "3EB0ABCDEF0123456789AB"
        assert deliveries[0]["text"].endswith(PRIVATE_SENTINEL)
        assert len(_VerticalProviderHandler.observed) == 4

        session_path = tmp_path / "ordinary-session.db"
        session_db = SessionDB(db_path=session_path)
        session_db.create_session("juno-vertical", "gateway")
        session_db.append_message("juno-vertical", "user", "private read requested")
        session_db.append_message("juno-vertical", "tool", result.content)
        session_db.append_message(
            "juno-vertical", "assistant", result.terminal.final_response
        )
        session_db.close()
        session_db = None
        trajectory = tmp_path / "trajectory.json"
        trajectory.write_text(json.dumps({
            "tool_result": result.content, "dispatch": dispatch,
        }), encoding="utf-8")
        gateway_log = tmp_path / "gateway.log"
        gateway_log.write_text(caplog.text, encoding="utf-8")

        await host.stop()
        runner._trusted_private_read_host = None
        ordinary_surfaces = [
            session_path, trajectory, gateway_log,
        ]
        ordinary_surfaces.extend(config.state_dir.iterdir())
        for base in tuple(ordinary_surfaces):
            ordinary_surfaces.extend(base.parent.glob(base.name + "-*"))
        scanned = b"\n".join(
            path.read_bytes() for path in ordinary_surfaces if path.exists()
        )
        assert PRIVATE_SENTINEL.encode() not in scanned
        assert CREDENTIAL_SENTINEL.encode() not in scanned
        assert PRIVATE_SENTINEL not in repr(ordinary_adapter.sent)
        assert CREDENTIAL_SENTINEL not in repr(ordinary_adapter.sent)
        assert PRIVATE_SENTINEL not in caplog.text
        assert CREDENTIAL_SENTINEL not in caplog.text
    finally:
        if session_db is not None:
            session_db.close()
        if host is not None and host.is_healthy():
            await host.stop()
        runner._trusted_private_read_host = None
        sensitive_process.terminate()
        sensitive_process.wait(timeout=5)
        provider.shutdown()
        provider.server_close()
        provider_thread.join(timeout=2)


@pytest.mark.asyncio
async def test_no_socket_vertical_preserves_producer_adapter_and_replay_contract(
    tmp_path: Path,
) -> None:
    from plugins.platforms.whatsapp.adapter import WhatsAppAdapter

    host, transport, ordinary, sensitive = await _host(tmp_path)
    adapter = WhatsAppAdapter(PlatformConfig(
        enabled=True, extra={"allow_from": [TRUSTED, OWNER], "dm_policy": "allowlist"},
    ))
    try:
        inbound = await adapter._build_message_event(_node_forwarded_event(
            sender=TRUSTED, text="read newest inbox message",
            message_id="NO-SOCKET-TRUSTED-PROVIDER-MESSAGE",
        ))
        assert inbound.source.profile is None
        result = _tool(inbound, host)
        request_id = dict(result.terminal.metadata)["request_id"]
        assert await host.process_once()
        approval = await adapter._build_message_event(_node_forwarded_event(
            sender=OWNER, text=f"/approve {request_id}",
            message_id="NO-SOCKET-OWNER-PROVIDER-DECISION",
        ))
        assert host.intercept_approval(approval).mutated
        assert await host.process_once()
        assert len(sensitive.calls) == 1
        assert not host.intercept_approval(approval).mutated
        assert _tool(inbound, host).terminal.status == "safe_failure"
        assert await host.process_once() is False
        assert len(sensitive.calls) == 1
        assert PRIVATE_SENTINEL not in repr(ordinary.messages)
        assert PRIVATE_SENTINEL not in (config_bytes := (
            host.config.state_dir / "authorization.db"
        ).read_bytes()).decode("latin1")
        assert CREDENTIAL_SENTINEL.encode() not in config_bytes
        assert transport.calls[0]["authority"] == OPENFGA_AUTHORITY
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_non_juno_active_profile_cannot_start_or_bind_v2_host(tmp_path: Path) -> None:
    config = JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path))
    dependencies = JunoPrivateReadDependencies(
        OpenFgaChecker(config, FakeJsonTransport()),
        GmailNewestInboxProvider(config, FakeJsonTransport()),
        FakeOrdinary(), FakeSensitive(),
    )
    host = JunoPrivateReadMvpHost(config, dependencies, active_profile="default")
    assert not await host.start(_background_worker=False)
    assert host.context_for_event(
        _event(OWNER, "request", profile=None, message="wrong-active-profile")
    ) is None

    from gateway.run import GatewayRunner
    runner = object.__new__(GatewayRunner)
    runner_root = tmp_path / "runner"
    runner_root.mkdir()
    runner.config = SimpleNamespace(trusted_private_read=_raw_config(runner_root))
    runner._trusted_private_read_host = None
    runner._active_profile_name = lambda: "default"
    assert not await GatewayRunner._start_trusted_private_read_host(runner)
    assert runner._trusted_private_read_host is None


def _checkpoint_metadata(checkpoint: int):
    columns = [
        ("request_id", "TEXT", 0, None, 1),
        ("requester", "TEXT", 1, None, 0),
        ("source_profile", "TEXT", 1, None, 0),
        ("source_account", "TEXT", 1, None, 0),
        ("source_chat", "TEXT", 1, None, 0),
    ]
    if checkpoint >= 1:
        columns.extend([
            ("source_message", "TEXT", 1, None, 0),
        ])
    columns.extend([
        ("capability_id", "TEXT", 1, None, 0),
        ("destination_account", "TEXT", 1, None, 0),
        ("destination_chat", "TEXT", 1, None, 0),
        ("owner_sender", "TEXT", 1, None, 0),
    ])
    if checkpoint >= 1:
        columns.append(("approval_chat", "TEXT", 1, None, 0))
    if checkpoint >= 2:
        columns.append(("approval_message", "TEXT", 0, None, 0))
    columns.extend([
        ("descriptor_digest", "TEXT", 1, None, 0),
        ("created_at_us", "INTEGER", 1, None, 0),
        ("expires_at_us", "INTEGER", 1, None, 0),
        ("status", "TEXT", 1, None, 0),
        ("notice_claimed", "INTEGER", 1, "0", 0),
        ("claim_token_digest", "TEXT", 0, None, 0),
        ("provider_message_id", "TEXT", 0, None, 0),
        ("terminal_code", "TEXT", 0, None, 0),
        ("updated_at_us", "INTEGER", 1, None, 0),
        ("version", "INTEGER", 1, "1", 0),
    ])
    if checkpoint >= 2:
        columns.append(("state_hmac", "TEXT", 1, None, 0))
    return [
        (cid, name, kind, notnull, default, primary)
        for cid, (name, kind, notnull, default, primary) in enumerate(columns)
    ]


def _install_legacy_mvp_table(db_path: Path, *, checkpoint: int) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DROP INDEX IF EXISTS idx_private_read_mvp_state")
        conn.execute("DROP INDEX IF EXISTS idx_private_read_mvp_source_event")
        conn.execute("DROP INDEX IF EXISTS idx_private_read_mvp_approval_event")
        conn.execute("DROP TABLE IF EXISTS private_read_mvp_requests")
        source_column = "source_message TEXT NOT NULL," if checkpoint >= 1 else ""
        approval_columns = "approval_chat TEXT NOT NULL," if checkpoint >= 1 else ""
        if checkpoint >= 2:
            approval_columns += "approval_message TEXT,"
        state_column = ",state_hmac TEXT NOT NULL" if checkpoint >= 2 else ""
        conn.execute(
            "CREATE TABLE private_read_mvp_requests ("
            "request_id TEXT PRIMARY KEY,requester TEXT NOT NULL,"
            "source_profile TEXT NOT NULL,source_account TEXT NOT NULL,"
            "source_chat TEXT NOT NULL," + source_column +
            "capability_id TEXT NOT NULL,destination_account TEXT NOT NULL,"
            "destination_chat TEXT NOT NULL,owner_sender TEXT NOT NULL,"
            + approval_columns +
            "descriptor_digest TEXT NOT NULL,created_at_us INTEGER NOT NULL,"
            "expires_at_us INTEGER NOT NULL,status TEXT NOT NULL CHECK (status IN ("
            "'pending','approved','denied','expired','claimed','consumed','failed_consumed'"
            ")),notice_claimed INTEGER NOT NULL DEFAULT 0 CHECK (notice_claimed IN (0,1)),"
            "claim_token_digest TEXT,provider_message_id TEXT,terminal_code TEXT,"
            "updated_at_us INTEGER NOT NULL,version INTEGER NOT NULL DEFAULT 1"
            + state_column + ")"
        )
        conn.execute(
            "CREATE INDEX idx_private_read_mvp_state ON private_read_mvp_requests("
            "status,expires_at_us,created_at_us)"
        )
        if checkpoint >= 1:
            conn.execute(
                "CREATE UNIQUE INDEX idx_private_read_mvp_source_event "
                "ON private_read_mvp_requests(source_profile,source_account,source_chat,"
                "requester,source_message,capability_id) WHERE source_message <> ''"
            )
        if checkpoint >= 2:
            conn.execute(
                "CREATE UNIQUE INDEX idx_private_read_mvp_approval_event "
                "ON private_read_mvp_requests(source_profile,source_account,owner_sender,"
                "approval_chat,approval_message,capability_id) "
                "WHERE approval_message IS NOT NULL"
            )
        # All three source checkpoints used authorization schema version 7;
        # the MVP table was an additive table outside that version number.
        conn.execute("PRAGMA user_version=7")
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 7
        assert [tuple(row) for row in conn.execute(
            "PRAGMA table_info(private_read_mvp_requests)"
        )] == _checkpoint_metadata(checkpoint)
        expected_indexes = {
            "sqlite_autoindex_private_read_mvp_requests_1": (
                1, "pk", 0, ("request_id",),
            ),
            "idx_private_read_mvp_state": (
                0, "c", 0, ("status", "expires_at_us", "created_at_us"),
            ),
        }
        if checkpoint >= 1:
            expected_indexes["idx_private_read_mvp_source_event"] = (
                1, "c", 1,
                ("source_profile", "source_account", "source_chat", "requester",
                 "source_message", "capability_id"),
            )
        if checkpoint >= 2:
            expected_indexes["idx_private_read_mvp_approval_event"] = (
                1, "c", 1,
                ("source_profile", "source_account", "owner_sender", "approval_chat",
                 "approval_message", "capability_id"),
            )
        observed_indexes = {}
        for row in conn.execute("PRAGMA index_list(private_read_mvp_requests)"):
            observed_indexes[row[1]] = (
                row[2], row[3], row[4], tuple(
                    item[2] for item in conn.execute(f"PRAGMA index_info('{row[1]}')")
                ),
            )
        assert observed_indexes == expected_indexes
        columns = ["request_id", "requester", "source_profile", "source_account", "source_chat"]
        if checkpoint >= 1:
            columns.append("source_message")
        columns.extend((
            "capability_id", "destination_account", "destination_chat", "owner_sender",
        ))
        if checkpoint >= 1:
            columns.append("approval_chat")
        if checkpoint >= 2:
            columns.append("approval_message")
        columns.extend((
            "descriptor_digest", "created_at_us", "expires_at_us", "status",
            "notice_claimed", "claim_token_digest", "provider_message_id", "terminal_code",
            "updated_at_us", "version",
        ))
        if checkpoint >= 2:
            columns.append("state_hmac")
        for index, status in enumerate(("pending", "approved", "claimed")):
            values = [f"legacy-{index}", TRUSTED, "juno", ORDINARY_ACCOUNT, TRUSTED_CHAT]
            if checkpoint >= 1:
                values.append(f"legacy-source-{index}")
            values.extend((
                CAPABILITY_ID, SENSITIVE_ACCOUNT, "77777777777@s.whatsapp.net", OWNER,
            ))
            if checkpoint >= 1:
                values.append(OWNER_CHAT)
            if checkpoint >= 2:
                values.append(None)
            values.extend((
                "0" * 64, 1_000_000 + index, 9_000_000_000_000_000, status, 0,
                "legacy-claim" if status == "claimed" else None,
                None, None, 1_000_000 + index, 1,
            ))
            if checkpoint >= 2:
                values.append("")
            conn.execute(
                "INSERT INTO private_read_mvp_requests (" + ",".join(columns) + ") VALUES ("
                + ",".join("?" for _ in columns) + ")", values,
            )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("checkpoint", [0, 1, 2])
async def test_exact_checkpoint_schema_migrates_legacy_rows_fail_closed(
    tmp_path: Path, checkpoint: int,
) -> None:
    from gateway.authorization_tasks import AuthorizationTaskStore

    config = JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path))
    transport = FakeJsonTransport()
    ordinary = FakeOrdinary()
    sensitive = FakeSensitive()
    dependencies = JunoPrivateReadDependencies(
        OpenFgaChecker(config, transport), GmailNewestInboxProvider(config, transport),
        ordinary, sensitive,
    )
    db_path = config.state_dir / "authorization.db"
    key_path = config.state_dir / "mvp-store.key"
    key_path.write_bytes(b"k" * 32)
    key_path.chmod(0o600)
    assert not (config.state_dir / JOURNAL_NAME).exists()
    assert not (config.state_dir / MARKER_NAME).exists()
    bootstrap = AuthorizationTaskStore(
        db_path=db_path, audit_hmac_key=b"a" * 32,
        request_hmac_key=b"r" * 32, key_version="checkpoint-fixture",
    )
    bootstrap.close()
    _install_legacy_mvp_table(db_path, checkpoint=checkpoint)

    migrated = JunoPrivateReadMvpHost(config, dependencies, active_profile="juno")
    assert await migrated.start(_background_worker=False)
    try:
        assert (config.state_dir / JOURNAL_NAME).is_file()
        assert (config.state_dir / MARKER_NAME).is_file()
        assert len(key_path.read_bytes()) > 32
        conn = migrated.store._connect()
        try:
            columns = {row[1] for row in conn.execute(
                "PRAGMA table_info(private_read_mvp_requests)"
            )}
            assert {"source_message", "approval_chat", "approval_message", "state_hmac"} <= columns
            assert conn.execute(
                "SELECT count(*) FROM private_read_mvp_requests "
                "WHERE status='failed_consumed' AND terminal_code='state_integrity_failed'"
            ).fetchone()[0] == 3
            indexes = {row[1] for row in conn.execute(
                "PRAGMA index_list(private_read_mvp_requests)"
            )}
            assert {
                "idx_private_read_mvp_state", "idx_private_read_mvp_source_event",
                "idx_private_read_mvp_approval_event",
            } <= indexes
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        finally:
            conn.close()
        assert await migrated.process_once() is False
        fresh = _tool(_event(
            TRUSTED, "request", message=f"authenticated-after-migration-{checkpoint}"
        ), migrated)
        fresh_id = dict(fresh.terminal.metadata)["request_id"]
        assert migrated.intercept_approval(_event(
            OWNER, f"/deny {fresh_id}", message=f"deny-after-migration-{checkpoint}"
        )).mutated
        authenticated = migrated.repository.get(fresh_id)
        assert authenticated.status == "denied"
        assert len(authenticated.state_hmac) == 64
    finally:
        await migrated.stop()

    clean = JunoPrivateReadMvpHost(config, dependencies, active_profile="juno")
    assert await clean.start(_background_worker=False)
    try:
        assert await clean.process_once() is False
        assert transport.calls == []
        assert ordinary.messages == []
        assert sensitive.calls == []
    finally:
        await clean.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(("column", "value"), [
    ("status", "approved"),
    ("destination_account", "88888888888@s.whatsapp.net"),
    ("destination_chat", "88888888888@s.whatsapp.net"),
    ("requester", OWNER),
    ("source_profile", "default"),
    ("source_account", "88888888888@s.whatsapp.net"),
    ("source_chat", OWNER_CHAT),
    ("source_message", "tampered-source-message"),
    ("owner_sender", TRUSTED),
    ("approval_chat", TRUSTED_CHAT),
    ("approval_message", "forged-approval-message"),
    ("gmail_account", "forged@example.test"),
    ("openfga_store_id", "forged-store"),
    ("openfga_model_id", "forged-model"),
    ("provider_authority_digest", "f" * 64),
    ("created_at_us", 1),
    ("expires_at_us", 9_000_000_000_000_000),
    ("notice_claimed", 1),
    ("claim_token_digest", "0" * 64),
    ("provider_message_id", "3EB0FFFFFFFFFFFFFFFFFF"),
    ("terminal_code", "submitted"),
    ("version", 999),
    ("descriptor_digest", "0" * 64),
    ("state_hmac", "0" * 64),
])
async def test_authenticated_row_tamper_is_terminal_before_any_external_access(
    tmp_path: Path, column: str, value: object,
) -> None:
    host, transport, ordinary, sensitive = await _host(tmp_path)
    try:
        result = _tool(
            _event(TRUSTED, "request", message="tamper-" + column), host
        )
        request_id = dict(result.terminal.metadata)["request_id"]
        conn = host.store._connect()
        try:
            conn.execute(
                f"UPDATE private_read_mvp_requests SET {column}=? WHERE request_id=?",
                (value, request_id),
            )
            conn.commit()
        finally:
            conn.close()

        assert host.repository.get(request_id) is None
        assert await host.process_once() is False
        conn = host.store._connect()
        try:
            terminal = conn.execute(
                "SELECT status,terminal_code,provider_message_id "
                "FROM private_read_mvp_requests WHERE request_id=?", (request_id,),
            ).fetchone()
        finally:
            conn.close()
        assert tuple(terminal) == ("failed_consumed", "state_integrity_failed", None)
        assert transport.calls == []
        assert ordinary.messages == []
        assert sensitive.calls == []
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_authenticated_state_hmac_rotates_on_every_lifecycle_transition(
    tmp_path: Path,
) -> None:
    host, _transport, _ordinary, _sensitive = await _host(tmp_path)
    try:
        result = _tool(_event(TRUSTED, "request", message="state-hmac-lifecycle"), host)
        request_id = dict(result.terminal.metadata)["request_id"]
        created = host.repository.get(request_id)
        notice = host.repository.claim_notice(host._clock_us())
        assert notice.request_id == request_id
        assert notice.state_hmac != created.state_hmac
        decision = _event(
            OWNER, f"/approve {request_id}", message="state-hmac-owner-decision"
        )
        assert host.intercept_approval(decision).mutated
        approved = host.repository.get(request_id)
        assert approved.state_hmac != notice.state_hmac
        assert approved.approval_message == "state-hmac-owner-decision"
        assert approved.descriptor_digest != notice.descriptor_digest
        claimed, token = host.repository.claim_approved(host._clock_us())
        assert claimed.state_hmac != approved.state_hmac
        assert host.repository.finish(
            request_id, token, submitted=False, provider_message_id=None,
            code="synthetic_terminal", now_us=host._clock_us(),
        )
        terminal = host.repository.get(request_id)
        assert terminal.state_hmac != claimed.state_hmac
        assert terminal.claim_token_digest is None
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_historical_authenticated_row_fails_when_sealed_requester_mapping_changes(
    tmp_path: Path,
) -> None:
    host, transport, ordinary, sensitive = await _host(tmp_path)
    result = _tool(_event(
        TRUSTED, "request", message="historical-config-binding"
    ), host)
    request_id = dict(result.terminal.metadata)["request_id"]
    old_config, dependencies = host.config, host.dependencies
    await host.stop()

    changed_requesters = tuple(
        replace(item, sensitive_destination="88888888888@s.whatsapp.net")
        if item.sender == TRUSTED else item
        for item in old_config.requesters
    )
    changed = replace(old_config, requesters=changed_requesters)
    restarted = JunoPrivateReadMvpHost(
        changed, dependencies, active_profile="juno"
    )
    assert await restarted.start(_background_worker=False)
    try:
        assert restarted.repository.get(request_id) is None
        assert await restarted.process_once() is False
        assert transport.calls == []
        assert ordinary.messages == []
        assert sensitive.calls == []
    finally:
        await restarted.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(("field", "changed_value"), [
    ("gmail_account", "other@example.test"),
    ("openfga_store_id", "store-other"),
    ("openfga_model_id", "model-other"),
])
async def test_approved_request_is_terminalized_on_exact_provider_authority_drift(
    tmp_path: Path, field: str, changed_value: str,
) -> None:
    host, transport, ordinary, sensitive = await _host(tmp_path)
    result = _tool(_event(OWNER, "request", message="provider-drift-" + field), host)
    request_id = dict(result.terminal.metadata)["request_id"]
    old_config, dependencies = host.config, host.dependencies
    await host.stop()
    changed = replace(old_config, **{field: changed_value})
    restarted = JunoPrivateReadMvpHost(changed, dependencies, active_profile="juno")
    assert await restarted.start(_background_worker=False)
    try:
        assert restarted.repository.get(request_id) is None
        assert await restarted.process_once() is False
        assert transport.calls == []
        assert ordinary.messages == []
        assert sensitive.calls == []
    finally:
        await restarted.stop()


@pytest.mark.asyncio
async def test_unchanged_exact_provider_authority_survives_restart_and_submits(
    tmp_path: Path,
) -> None:
    host, transport, ordinary, sensitive = await _host(tmp_path)
    result = _tool(_event(OWNER, "request", message="provider-authority-stable"), host)
    request_id = dict(result.terminal.metadata)["request_id"]
    config, dependencies = host.config, host.dependencies
    await host.stop()
    restarted = JunoPrivateReadMvpHost(config, dependencies, active_profile="juno")
    assert await restarted.start(_background_worker=False)
    try:
        request = restarted.repository.get(request_id)
        assert request.status == "approved"
        assert request.gmail_account == "juno@example.test"
        assert request.openfga_store_id == "store-juno"
        assert request.openfga_model_id == "model-juno"
        assert await restarted.process_once()
        assert restarted.repository.get(request_id).status == "consumed"
        assert len(sensitive.calls) == 1
        assert transport.calls
        assert ordinary.messages == []
    finally:
        await restarted.stop()


@pytest.mark.asyncio
async def test_concurrent_reuse_of_one_owner_decision_message_mutates_exactly_one(
    tmp_path: Path,
) -> None:
    host, _transport, _ordinary, sensitive = await _host(tmp_path)
    try:
        ids = []
        for index in range(2):
            result = _tool(_event(
                TRUSTED, "request", message=f"concurrent-decision-request-{index}"
            ), host)
            ids.append(dict(result.terminal.metadata)["request_id"])
        events = [
            _event(OWNER, f"/approve {ids[0]}", message="one-concurrent-decision"),
            _event(OWNER, f"/deny {ids[1]}", message="one-concurrent-decision"),
        ]
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(host.intercept_approval, events))
        assert sum(outcome.mutated for outcome in outcomes) == 1
        assert await host.process_once()
        assert len(sensitive.calls) in (0, 1)
        conn = host.store._connect()
        try:
            assert conn.execute(
                "SELECT count(*) FROM private_read_mvp_requests "
                "WHERE approval_message='one-concurrent-decision'"
            ).fetchone()[0] == 1
        finally:
            conn.close()
    finally:
        await host.stop()
