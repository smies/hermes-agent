from __future__ import annotations

import base64
import io
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
import traceback
from types import SimpleNamespace

import pytest

from gateway.juno_private_read_mvp import (
    CAPABILITY_ID,
    GMAIL_AUTHORITY,
    FixedHttpJsonTransport,
    GmailNewestInboxProvider,
    JunoPrivateReadDependencies,
    JunoPrivateReadError,
    JunoPrivateReadMvpConfig,
    JunoPrivateReadMvpHost,
    OpenFgaChecker,
    SensitiveRuntimeIdentity,
    SensitiveSubmission,
    render_gmail_message,
)
from tests.gateway.test_juno_private_read_mvp_e2e import (
    FakeJsonTransport, FakeOrdinary, FakeSensitive, ORDINARY_ACCOUNT,
    OWNER, OWNER_CHAT, PRIVATE_SENTINEL, SENSITIVE_ACCOUNT,
    TRUSTED, TRUSTED_CHAT, _event, _host, _raw_config, _tool,
)
from tools.private_read_request_tool import check_private_read_request_runtime


CREDENTIAL_SENTINEL = "SYNTHETIC-CREDENTIAL-SENTINEL-74a1"


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
            "provider_account_jid": SENSITIVE_ACCOUNT, "identity_observed_us": 123,
            "adapter_runtime_id": "runtime-fresh", "connection_epoch": "epoch-fresh",
            "transport_identity": {"synthetic": True},
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

    restarted = JunoPrivateReadMvpHost(config, dependencies)
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
    assert host.repository.claim_notice(0) is not None
    await host.stop()

    restarted = JunoPrivateReadMvpHost(config, dependencies)
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
    clock = [1_000_000]
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
            return SensitiveRuntimeIdentity("runtime-one", SENSITIVE_ACCOUNT, epoch)

    sensitive = DriftingSensitive()
    host = JunoPrivateReadMvpHost(
        config,
        JunoPrivateReadDependencies(
            OpenFgaChecker(config, transport), GmailNewestInboxProvider(config, transport),
            FakeOrdinary(), sensitive,
        ),
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
            return SensitiveRuntimeIdentity(runtime, SENSITIVE_ACCOUNT, "epoch-one")

    sensitive = RestartingSensitive()
    host = JunoPrivateReadMvpHost(
        config,
        JunoPrivateReadDependencies(
            OpenFgaChecker(config, transport), GmailNewestInboxProvider(config, transport),
            FakeOrdinary(), sensitive,
        ),
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
@pytest.mark.parametrize("observed", [
    None,
    SensitiveRuntimeIdentity("runtime", ORDINARY_ACCOUNT, "epoch"),
    SensitiveRuntimeIdentity("runtime", "99999999999@s.whatsapp.net", "epoch"),
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
            identity=SensitiveRuntimeIdentity("runtime", SENSITIVE_ACCOUNT, "epoch"),
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
        assert identity == SensitiveRuntimeIdentity(
            "runtime-fresh", SENSITIVE_ACCOUNT, "epoch-fresh"
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
    runner.profile = "juno"
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
