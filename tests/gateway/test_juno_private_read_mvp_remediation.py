from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import io
import json
import logging
import os
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
import { readFileSync } from 'node:fs';
const helper = await import(pathToFileURL(process.env.JUNO_BRIDGE_HELPER));
const input = JSON.parse(process.env.JUNO_BRIDGE_INPUT);
const msg = {
  key: { id: input.messageId, remoteJid: input.sender,
    participant: input.sender, fromMe: false },
  pushName: 'Synthetic User', messageTimestamp: 1786000000,
  message: { conversation: input.text },
};
const event = await helper.extractBridgeEvent({
  msg, chatId: input.sender, senderId: input.sender,
  senderNumber: input.sender.split('@')[0], isGroup: false,
});
const production = readFileSync(process.env.JUNO_BRIDGE_SOURCE, 'utf8');
if (!/event\.fromOwner = fromOwner;[\s\S]*?event\.accountId = normalizeWhatsAppId\(sock\.user\?\.id\);[\s\S]*?messageQueue\.push\(event\);/.test(production)) {
  throw new Error('production inbound authority forwarding path is missing');
}
event.fromOwner = false;
event.accountId = helper.normalizeWhatsAppId('33333333333:19@s.whatsapp.net');
process.stdout.write(JSON.stringify(event));
"""
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", source],
        check=True, capture_output=True, text=True, timeout=10,
        env={
            **os.environ,
            "JUNO_BRIDGE_HELPER": str(
                Path(__file__).parents[2] / "scripts/whatsapp-bridge/bridge_helpers.js"
            ),
            "JUNO_BRIDGE_SOURCE": str(
                Path(__file__).parents[2] / "scripts/whatsapp-bridge/bridge.js"
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
async def test_redirect_refusal_is_content_free_without_socket(monkeypatch) -> None:
    import gateway.juno_private_read_mvp as mvp

    class Opener:
        def open(self, request, timeout):
            assert request.headers["Authorization"] == "Bearer " + CREDENTIAL_SENTINEL
            assert mvp._RejectRedirects().redirect_request(
                request, None, 307, "redirect", {}, "http://attacker.test/capture"
            ) is None
            raise OSError(PRIVATE_SENTINEL + CREDENTIAL_SENTINEL)

    monkeypatch.setattr(mvp.urllib_request, "build_opener", lambda *_: Opener())
    result = await FixedHttpJsonTransport().request(
        method="POST", authority=GMAIL_AUTHORITY, path="/fixed",
        query=(), headers={"authorization": "Bearer " + CREDENTIAL_SENTINEL},
        body={"private_value": PRIVATE_SENTINEL}, timeout=1, max_bytes=1024,
    )
    assert repr(result) == "<private transport failure>"
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
    tmp_path: Path, caplog,
) -> None:
    from hermes_state import SessionDB
    from plugins.platforms.whatsapp.adapter import WhatsAppAdapter
    from gateway.juno_private_read_mvp import _SensitiveHttpSubmitter
    from gateway.run import GatewayRunner

    caplog.set_level(logging.DEBUG)
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

    provider = _loopback_server(_VerticalProviderHandler)
    provider_thread = Thread(target=provider.serve_forever, daemon=True)
    provider_thread.start()
    capture = tmp_path / "private-delivery-capture.jsonl"
    capture.touch(mode=0o600)
    harness = Path(__file__).parents[1] / "fixtures/juno_sensitive_http_harness.mjs"
    sensitive_process = subprocess.Popen(
        ["node", str(harness)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env={
            **os.environ,
            "JUNO_TEST_TRANSPORT_IDENTITY": json.dumps(_SENSITIVE_TRANSPORT_IDENTITY),
            "JUNO_TEST_DELIVERY_CAPTURE": str(capture),
            "JUNO_TEST_SENSITIVE_CAPABILITY": "s" * 48,
        },
    )
    first_line = sensitive_process.stdout.readline()
    if not first_line:
        sensitive_process.terminate()
        pytest.skip("Node loopback harness could not bind")
    sensitive_port = json.loads(first_line)["port"]

    class OrdinaryAdapter:
        def __init__(self):
            self.sent = []

        async def send(self, destination, text):
            self.sent.append((destination, text))
            return SimpleNamespace(success=True, message_id="ordinary-vertical-notice")

    ordinary_adapter = OrdinaryAdapter()
    runner = object.__new__(GatewayRunner)
    runner._active_profile_name = lambda: "juno"
    runner.adapters = {Platform.WHATSAPP: ordinary_adapter}
    runner._profile_adapters = {}
    production = compose_juno_private_read_mvp_services(runner, config)
    authority = f"http://127.0.0.1:{provider.server_port}"
    transport = FixedHttpJsonTransport(_test_authorities={
        OPENFGA_AUTHORITY: authority,
        GMAIL_AUTHORITY: authority,
        "http://127.0.0.1:3011": f"http://127.0.0.1:{sensitive_port}",
    })
    dependencies = JunoPrivateReadDependencies(
        OpenFgaChecker(config, transport), GmailNewestInboxProvider(config, transport),
        production.ordinary, _SensitiveHttpSubmitter(config, transport),
    )
    host = JunoPrivateReadMvpHost(config, dependencies, active_profile="juno")
    assert await host.start(_background_worker=False)
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
        assert inbound.source.profile is None

        result = _tool(inbound, host)
        request_id = dict(result.terminal.metadata)["request_id"]
        assert json.loads(result.content) == {
            "status": "deferred", "reason": "approval_required"
        }
        assert await host.process_once()
        assert len(ordinary_adapter.sent) == 1

        approval_data = _node_forwarded_event(
            sender=OWNER, text=f"/approve {request_id}",
            message_id="VERTICAL-OWNER-PROVIDER-DECISION",
        )
        approval = await inbound_adapter._build_message_event(approval_data)
        assert approval.source.profile is None
        assert host.intercept_approval(approval).mutated
        assert await host.process_once()
        assert not host.intercept_approval(approval).mutated
        assert _tool(inbound, host).terminal.status == "safe_failure"
        assert await host.process_once() is False

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
        trajectory.write_text(json.dumps({"tool_result": result.content}), encoding="utf-8")
        gateway_log = tmp_path / "gateway.log"
        gateway_log.write_text(caplog.text, encoding="utf-8")

        await host.stop()
        ordinary_surfaces = [
            config.state_dir / "authorization.db", session_path, trajectory, gateway_log,
        ]
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
        if host.is_healthy():
            await host.stop()
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


def _install_legacy_mvp_table(db_path: Path, *, cycle1: bool) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DROP INDEX IF EXISTS idx_private_read_mvp_state")
        conn.execute("DROP INDEX IF EXISTS idx_private_read_mvp_source_event")
        conn.execute("DROP INDEX IF EXISTS idx_private_read_mvp_approval_event")
        conn.execute("DROP TABLE private_read_mvp_requests")
        binding_columns = (
            "source_message TEXT NOT NULL,approval_chat TEXT NOT NULL,"
            if cycle1 else ""
        )
        conn.execute(
            "CREATE TABLE private_read_mvp_requests ("
            "request_id TEXT PRIMARY KEY,requester TEXT NOT NULL,"
            "source_profile TEXT NOT NULL,source_account TEXT NOT NULL,"
            "source_chat TEXT NOT NULL," + binding_columns +
            "capability_id TEXT NOT NULL,destination_account TEXT NOT NULL,"
            "destination_chat TEXT NOT NULL,owner_sender TEXT NOT NULL,"
            "descriptor_digest TEXT NOT NULL,created_at_us INTEGER NOT NULL,"
            "expires_at_us INTEGER NOT NULL,status TEXT NOT NULL CHECK (status IN ("
            "'pending','approved','denied','expired','claimed','consumed','failed_consumed'"
            ")),notice_claimed INTEGER NOT NULL DEFAULT 0 CHECK (notice_claimed IN (0,1)),"
            "claim_token_digest TEXT,provider_message_id TEXT,terminal_code TEXT,"
            "updated_at_us INTEGER NOT NULL,version INTEGER NOT NULL DEFAULT 1)"
        )
        conn.execute(
            "CREATE INDEX idx_private_read_mvp_state ON private_read_mvp_requests("
            "status,expires_at_us,created_at_us)"
        )
        if cycle1:
            conn.execute(
                "CREATE UNIQUE INDEX idx_private_read_mvp_source_event "
                "ON private_read_mvp_requests(source_profile,source_account,source_chat,"
                "requester,source_message,capability_id) WHERE source_message <> ''"
            )
        columns = ["request_id", "requester", "source_profile", "source_account", "source_chat"]
        if cycle1:
            columns.extend(("source_message", "approval_chat"))
        columns.extend((
            "capability_id", "destination_account", "destination_chat", "owner_sender",
            "descriptor_digest", "created_at_us", "expires_at_us", "status",
            "notice_claimed", "claim_token_digest", "provider_message_id", "terminal_code",
            "updated_at_us", "version",
        ))
        for index, status in enumerate(("pending", "approved", "claimed")):
            values = [f"legacy-{index}", TRUSTED, "juno", ORDINARY_ACCOUNT, TRUSTED_CHAT]
            if cycle1:
                values.extend((f"legacy-source-{index}", OWNER_CHAT))
            values.extend((
                CAPABILITY_ID, SENSITIVE_ACCOUNT, "77777777777@s.whatsapp.net", OWNER,
                "0" * 64, 1_000_000 + index, 9_000_000_000_000_000, status, 0,
                "legacy-claim" if status == "claimed" else None,
                None, None, 1_000_000 + index, 1,
            ))
            conn.execute(
                "INSERT INTO private_read_mvp_requests (" + ",".join(columns) + ") VALUES ("
                + ",".join("?" for _ in columns) + ")", values,
            )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("cycle1", [False, True])
async def test_exact_checkpoint_schema_migrates_legacy_rows_fail_closed(
    tmp_path: Path, cycle1: bool,
) -> None:
    host, transport, ordinary, sensitive = await _host(tmp_path)
    config, dependencies = host.config, host.dependencies
    db_path = config.state_dir / "authorization.db"
    await host.stop()
    _install_legacy_mvp_table(db_path, cycle1=cycle1)

    migrated = JunoPrivateReadMvpHost(config, dependencies, active_profile="juno")
    assert await migrated.start(_background_worker=False)
    try:
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
            TRUSTED, "request", message=f"authenticated-after-migration-{cycle1}"
        ), migrated)
        fresh_id = dict(fresh.terminal.metadata)["request_id"]
        assert migrated.intercept_approval(_event(
            OWNER, f"/deny {fresh_id}", message=f"deny-after-migration-{cycle1}"
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
