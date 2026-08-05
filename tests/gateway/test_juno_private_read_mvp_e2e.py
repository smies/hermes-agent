from __future__ import annotations

import base64
import io
import json
import logging
from pathlib import Path
import traceback

import pytest

from gateway.config import Platform
from gateway.juno_private_read_mvp import (
    CAPABILITY_ID,
    GMAIL_AUTHORITY,
    GMAIL_CONTRACT_VERSION,
    GMAIL_SCOPE,
    OPENFGA_AUTHORITY,
    OPENFGA_CLIENT_CONTRACT_VERSION,
    GmailNewestInboxProvider,
    JunoPrivateReadDependencies,
    JunoPrivateReadError,
    JunoPrivateReadMvpConfig,
    JunoPrivateReadMvpHost,
    OpenFgaChecker,
    SensitiveRuntimeIdentity,
    SensitiveSubmission,
    private_read_tool_surface_is_closed,
    render_gmail_message,
)
from gateway.platforms.base import MessageEvent
from gateway.session import SessionSource
from tools.private_read_request_tool import (
    PRIVATE_READ_REQUEST_TOOL_NAME,
    configure_private_read_mvp_handler,
)
from tools.registry import registry


PRIVATE_SENTINEL = "JUNO-PRIVATE-SENTINEL-DO-NOT-PERSIST"
OWNER = "11111111111@s.whatsapp.net"
TRUSTED = "22222222222@s.whatsapp.net"
ORDINARY_ACCOUNT = "33333333333@s.whatsapp.net"
OWNER_CHAT = OWNER
TRUSTED_CHAT = TRUSTED
SENSITIVE_ACCOUNT = "55555555555@s.whatsapp.net"
OWNER_DESTINATION = "66666666666@s.whatsapp.net"
TRUSTED_DESTINATION = "77777777777@s.whatsapp.net"


def _write(path: Path, value: object) -> Path:
    if isinstance(value, str):
        path.write_text(value, encoding="utf-8")
    else:
        path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return path


def _raw_config(tmp_path: Path) -> dict:
    root = tmp_path / "juno"
    root.mkdir(mode=0o700)
    state = root / "state"
    state.mkdir(mode=0o700)
    future = 9_000_000_000_000_000
    openfga = _write(root / "openfga.token", "synthetic-openfga-token-value")
    client = _write(root / "gmail-client.json", {
        "client_id": "synthetic-client", "client_secret": "synthetic-secret"
    })
    token = _write(root / "gmail-token.json", {
        "access_token": "synthetic-access-token", "scope": GMAIL_SCOPE,
        "account": "juno@example.test", "expires_at_us": future,
    })
    sensitive = _write(root / "sensitive.capability", "s" * 48)
    return {
        "version": 2,
        "enabled": True,
        "state_dir": str(state),
        "profile": "juno",
        "ordinary": {
            "account": ORDINARY_ACCOUNT,
            "owner_sender": OWNER,
            "owner_chat": OWNER_CHAT,
        },
        "requesters": [
            {"sender": OWNER, "source_chat": OWNER_CHAT, "label": "James",
             "sensitive_destination": OWNER_DESTINATION},
            {"sender": TRUSTED, "source_chat": TRUSTED_CHAT, "label": "Trusted Person",
             "sensitive_destination": TRUSTED_DESTINATION},
        ],
        "capability_id": CAPABILITY_ID,
        "gmail_contract_version": GMAIL_CONTRACT_VERSION,
        "openfga": {
            "store_id": "store-juno", "model_id": "model-juno",
            "api_credential_file": str(openfga),
        },
        "gmail": {
            "oauth_client_file": str(client), "token_file": str(token),
            "account": "juno@example.test",
        },
        "sensitive": {
            "account": SENSITIVE_ACCOUNT, "capability_file": str(sensitive),
        },
        "timeouts": {"request": 2, "approval": 60, "read": 2, "submission": 2},
    }


def _event(sender: str, text: str, *, account: str = ORDINARY_ACCOUNT,
           chat: str | None = None, profile: str = "juno", message: str = "inbound-1"):
    chat = sender if chat is None else chat
    return MessageEvent(
        text=text,
        message_id=message,
        metadata={"whatsapp_account_id": account},
        source=SessionSource(
            platform=Platform.WHATSAPP, profile=profile, chat_id=chat,
            chat_type="dm", user_id=sender,
        ),
    )


class FakeJsonTransport:
    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.fga = "allow"
        self.gmail = "ok"

    async def request(self, **call):
        self.calls.append(call)
        if call["authority"] == OPENFGA_AUTHORITY:
            if self.fga == "error":
                raise RuntimeError(PRIVATE_SENTINEL)
            return {"allowed": self.fga == "allow"}
        assert call["authority"] == GMAIL_AUTHORITY
        if self.gmail == "error":
            raise RuntimeError(PRIVATE_SENTINEL)
        if call["path"].endswith("/profile"):
            return {"emailAddress": "juno@example.test"}
        if call["path"].endswith("/messages"):
            return {"messages": [{"id": "message-1"}]}
        encoded = base64.urlsafe_b64encode(PRIVATE_SENTINEL.encode()).decode().rstrip("=")
        if self.gmail == "oversize":
            return {"id": "message-1", "payload": {
                "mimeType": "text/plain", "headers": [],
                "body": {"data": encoded, "size": 99_999},
            }}
        if self.gmail == "mime":
            return {"id": "message-1", "payload": {
                "mimeType": "text/html", "headers": [],
                "body": {"data": encoded, "size": len(PRIVATE_SENTINEL)},
            }}
        if self.gmail == "parts":
            return {"id": "message-1", "payload": {
                "mimeType": "multipart/alternative", "headers": [], "body": {}, "parts": [],
            }}
        return {"id": "message-1", "payload": {
            "mimeType": "text/plain",
            "headers": [
                {"name": "From", "value": "sender@example.test"},
                {"name": "To", "value": "juno@example.test"},
                {"name": "Cc", "value": "copy@example.test"},
                {"name": "Subject", "value": "Synthetic subject"},
                {"name": "Date", "value": "Wed, 5 Aug 2026 12:00:00 +0000"},
            ],
            "body": {"data": encoded, "size": len(PRIVATE_SENTINEL)},
        }}


class FakeOrdinary:
    def __init__(self) -> None:
        self.messages: list[str] = []
        self.destinations: list[str] = []

    async def send(self, destination: str, text: str) -> str:
        self.destinations.append(destination)
        self.messages.append(text)
        return "ordinary-message-1"


class FakeSensitive:
    def __init__(self) -> None:
        self.calls: list[tuple[object, str]] = []
        self.mode = "submitted"
        self.identity = SensitiveRuntimeIdentity(
            "sensitive-runtime-test", SENSITIVE_ACCOUNT, "epoch-test"
        )

    async def observe_identity(self, *, request):
        if self.mode == "identity-unavailable":
            return None
        return self.identity

    async def submit(self, *, request, plaintext: str, identity) -> SensitiveSubmission:
        self.calls.append((request, plaintext))
        if self.mode == "mismatch":
            return SensitiveSubmission(
                "submitted", "3EB0FFFFFFFFFFFFFFFFFF", request.destination_account, "wrong"
            )
        if self.mode == "unknown":
            return SensitiveSubmission("unknown", None, request.destination_account, request.destination_chat)
        if self.mode == "failure":
            raise RuntimeError(PRIVATE_SENTINEL)
        return SensitiveSubmission(
            "submitted", "3EB0ABCDEF0123456789AB",
            request.destination_account, request.destination_chat,
        )


@pytest.fixture(autouse=True)
def _clear_tool():
    configure_private_read_mvp_handler(None)
    yield
    configure_private_read_mvp_handler(None)


async def _host(tmp_path: Path):
    config = JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path))
    assert config is not None
    transport = FakeJsonTransport()
    ordinary = FakeOrdinary()
    sensitive = FakeSensitive()
    host = JunoPrivateReadMvpHost(
        config,
        JunoPrivateReadDependencies(
            OpenFgaChecker(config, transport),
            GmailNewestInboxProvider(config, transport),
            ordinary,
            sensitive,
        ),
    )
    assert await host.start(_background_worker=False)
    return host, transport, ordinary, sensitive


def _tool(event: MessageEvent, host: JunoPrivateReadMvpHost):
    binding = host.bind_event(event)
    try:
        entry = registry.get_entry(PRIVATE_READ_REQUEST_TOOL_NAME)
        assert entry is not None
        return entry.handler({"capability_id": CAPABILITY_ID}, tool_call_id="tool-call-1")
    finally:
        host.unbind_event(binding)


def _tool_names() -> set[str]:
    from model_tools import get_tool_definitions

    definitions = get_tool_definitions(
        enabled_toolsets=["private-read-request"],
        quiet_mode=True,
        skip_tool_search_assembly=True,
    )
    return {item["function"]["name"] for item in definitions}


@pytest.mark.asyncio
async def test_james_full_private_read_is_submitted_with_content_free_model_status(
    tmp_path: Path, caplog,
) -> None:
    host, transport, ordinary, sensitive = await _host(tmp_path)
    caplog.set_level(logging.DEBUG)
    try:
        result = _tool(_event(OWNER, "read my newest inbox message"), host)
        request_id = dict(result.terminal.metadata)["request_id"]
        assert json.loads(result.content) == {"status": "accepted"}
        assert _tool_names() == {PRIVATE_READ_REQUEST_TOOL_NAME}
        assert private_read_tool_surface_is_closed()
        assert PRIVATE_SENTINEL not in repr(result)
        assert ordinary.messages == []
        model_messages = [
            {"role": "user", "content": "read my newest inbox message"},
            {"role": "tool", "content": result.content},
            {"role": "assistant", "content": result.terminal.final_response},
        ]
        session_record = {"messages": model_messages}
        trajectory_record = {"tool_result": result.content}
        assert PRIVATE_SENTINEL not in json.dumps(session_record)
        assert PRIVATE_SENTINEL not in json.dumps(trajectory_record)

        assert await host.process_once() is True
        request = host.repository.get(request_id)
        assert request is not None and request.status == "consumed"
        assert request.destination_chat == OWNER_DESTINATION
        assert sensitive.calls[0][1].endswith(PRIVATE_SENTINEL)
        assert request_id in json.dumps(transport.calls[0]["body"])
        assert PRIVATE_SENTINEL not in json.dumps(transport.calls[0]["body"])
        assert transport.calls[0]["body"]["consistency"] == "HIGHER_CONSISTENCY"
        assert OPENFGA_CLIENT_CONTRACT_VERSION == "1.18.2"
        assert transport.calls[0]["body"] == {
            "authorization_model_id": "model-juno",
            "consistency": "HIGHER_CONSISTENCY",
            "tuple_key": {
                "user": f"requester:{OWNER}",
                "relation": "read",
                "object": f"capability:{CAPABILITY_ID}",
            },
            "context": {
                "request_id": request_id,
                "requester": OWNER,
                "capability": CAPABILITY_ID,
                "destination_account": SENSITIVE_ACCOUNT,
                "destination_chat": OWNER_DESTINATION,
                "source_profile": "juno",
                "source_account": ORDINARY_ACCOUNT,
                "source_chat": OWNER_CHAT,
                "source_message": "inbound-1",
                "expires_at_us": request.expires_at_us,
                "descriptor_digest": request.descriptor_digest,
            },
        }
        assert [call["path"] for call in transport.calls].count(
            "/gmail/v1/users/me/messages"
        ) == 1
        assert sum("/messages/message-1" in call["path"] for call in transport.calls) == 1

        for state_file in host.config.state_dir.iterdir():
            if state_file.is_file():
                assert PRIVATE_SENTINEL.encode() not in state_file.read_bytes()
        assert PRIVATE_SENTINEL not in caplog.text
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_trusted_request_notice_wrong_sender_then_owner_approval_once(
    tmp_path: Path,
) -> None:
    host, _transport, ordinary, sensitive = await _host(tmp_path)
    try:
        result = _tool(_event(TRUSTED, "please read it", message="trusted-request"), host)
        request_id = dict(result.terminal.metadata)["request_id"]
        assert json.loads(result.content) == {"reason": "approval_required", "status": "deferred"}
        assert await host.process_once() is True
        assert len(ordinary.messages) == 1
        assert request_id in ordinary.messages[0]
        assert PRIVATE_SENTINEL not in ordinary.messages[0]

        wrong = host.intercept_approval(
            _event(TRUSTED, f"/approve {request_id}", message="copied-command")
        )
        assert wrong.matched and not wrong.mutated
        accepted = host.intercept_approval(
            _event(OWNER, f"/approve {request_id}", message="owner-command")
        )
        assert accepted.mutated
        replay = host.intercept_approval(
            _event(OWNER, f"/approve {request_id}", message="owner-replay")
        )
        assert replay.matched and not replay.mutated

        assert await host.process_once() is True
        request = host.repository.get(request_id)
        assert request is not None and request.status == "consumed"
        assert sensitive.calls[0][0].destination_chat == TRUSTED_DESTINATION
    finally:
        await host.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [
    "deny", "fga-deny", "fga-error", "gmail-error", "oversize", "mime", "parts",
    "sensitive-mismatch", "sensitive-failure", "sensitive-unknown",
])
async def test_fail_closed_matrix_is_consumed_without_private_ordinary_output(
    tmp_path: Path, mode: str,
) -> None:
    host, transport, ordinary, sensitive = await _host(tmp_path)
    try:
        sender = TRUSTED if mode == "deny" else OWNER
        result = _tool(_event(sender, "request", message="matrix-" + mode), host)
        request_id = dict(result.terminal.metadata)["request_id"]
        if mode == "deny":
            await host.process_once()
            decision = host.intercept_approval(_event(OWNER, f"/deny {request_id}"))
            assert decision.mutated
            assert host.repository.get(request_id).status == "denied"
            assert sensitive.calls == []
            return
        if mode == "fga-deny":
            transport.fga = "deny"
        elif mode == "fga-error":
            transport.fga = "error"
        elif mode in {"gmail-error", "oversize", "mime", "parts"}:
            transport.gmail = mode.removeprefix("gmail-")
        elif mode.startswith("sensitive-"):
            sensitive.mode = mode.removeprefix("sensitive-")
        await host.process_once()
        request = host.repository.get(request_id)
        assert request is not None and request.status == "failed_consumed"
        assert PRIVATE_SENTINEL not in "".join(ordinary.messages)
        assert PRIVATE_SENTINEL.encode() not in host.store.db_path.read_bytes()
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_wrong_account_profile_chat_destination_expiry_and_malformed_commands(
    tmp_path: Path,
) -> None:
    host, _transport, _ordinary, _sensitive = await _host(tmp_path)
    try:
        for event in (
            _event(OWNER, "x", account="wrong"),
            _event(OWNER, "x", profile="default"),
            _event(OWNER, "x", chat="99999999999@s.whatsapp.net"),
            _event("99999999999@s.whatsapp.net", "x"),
        ):
            binding = host.bind_event(event)
            try:
                with pytest.raises(JunoPrivateReadError):
                    host.request_from_tool(CAPABILITY_ID)
            finally:
                host.unbind_event(binding)
        for command in ("/approve", "/approve  short", "/approve unknown-request-id", "/deny id extra"):
            result = host.intercept_approval(_event(OWNER, command))
            assert result.matched and not result.mutated

        pending = _tool(_event(TRUSTED, "x", message="expiry"), host)
        request_id = dict(pending.terminal.metadata)["request_id"]
        request = host.repository.get(request_id)
        host.repository.expire_due(request.expires_at_us)
        assert host.repository.get(request_id).status == "expired"
        assert not host.intercept_approval(_event(OWNER, f"/approve {request_id}")).mutated
    finally:
        await host.stop()


def test_config_is_default_off_closed_and_rejects_unknown_duplicate_semantics(tmp_path: Path) -> None:
    from gateway.config import _load_gateway_yaml

    assert JunoPrivateReadMvpConfig.parse(None) is None
    assert JunoPrivateReadMvpConfig.parse({"enabled": False}) is None
    with pytest.raises(JunoPrivateReadError):
        JunoPrivateReadMvpConfig.parse({"enabled": False, "surprise": True})
    raw = _raw_config(tmp_path)
    raw["unexpected"] = "value"
    with pytest.raises(JunoPrivateReadError):
        JunoPrivateReadMvpConfig.parse(raw)
    with pytest.raises(Exception, match="duplicate mapping key"):
        _load_gateway_yaml(io.StringIO(
            "gateway:\n  trusted_private_read:\n    enabled: true\n    enabled: false\n"
        ))


def test_renderer_is_exact_six_fields_and_content_free_failures() -> None:
    encoded = base64.urlsafe_b64encode(b"body").decode().rstrip("=")
    message = {"id": "id", "payload": {"mimeType": "text/plain", "headers": [
        {"name": "From", "value": "a"}, {"name": "To", "value": "b"},
        {"name": "Cc", "value": "c"}, {"name": "Subject", "value": "d"},
        {"name": "Date", "value": "e"},
    ], "body": {"data": encoded, "size": 4}}}
    assert render_gmail_message(message, expected_id="id") == (
        "From: a\nTo: b\nCc: c\nSubject: d\nDate: e\nBody:\nbody"
    )
    bad = {**message, "payload": {**message["payload"], "mimeType": PRIVATE_SENTINEL}}
    with pytest.raises(JunoPrivateReadError) as raised:
        render_gmail_message(bad, expected_id="id")
    assert PRIVATE_SENTINEL not in repr(raised.value)
    assert PRIVATE_SENTINEL not in "".join(
        traceback.format_exception(raised.type, raised.value, raised.tb)
    )


@pytest.mark.asyncio
async def test_interrupted_claim_is_consumed_on_restart_without_retry(tmp_path: Path) -> None:
    host, transport, ordinary, sensitive = await _host(tmp_path)
    config = host.config
    dependencies = host.dependencies
    result = _tool(_event(OWNER, "request", message="before-restart"), host)
    request_id = dict(result.terminal.metadata)["request_id"]
    claimed = host.repository.claim_approved(0)
    assert claimed is not None
    await host.stop()

    restarted = JunoPrivateReadMvpHost(config, dependencies)
    assert await restarted.start(_background_worker=False)
    try:
        assert restarted.repository.get(request_id).status == "failed_consumed"
        assert await restarted.process_once() is False
        assert transport.calls == []
        assert ordinary.messages == []
        assert sensitive.calls == []
    finally:
        await restarted.stop()


@pytest.mark.asyncio
async def test_gateway_consumes_private_decision_before_session_or_queue(monkeypatch) -> None:
    from gateway.juno_private_read_mvp import ApprovalIntercept
    from gateway.run import GatewayRunner
    import hermes_cli.lifecycle

    class Host:
        def intercept_approval(self, event):
            assert event.text == "/approve opaque-request-1234"
            return ApprovalIntercept(True, True, "Private-read request approved.")

    runner = object.__new__(GatewayRunner)
    runner._startup_restore_in_progress = False
    runner._trusted_private_read_host = Host()
    runner._scale_to_zero_note_real_inbound = lambda: None
    runner._is_user_authorized = lambda _source: True
    runner._session_key_for_source = lambda _source: (_ for _ in ()).throw(
        AssertionError("decision reached session/queue handling")
    )
    monkeypatch.setattr(hermes_cli.lifecycle, "invoke_hook", lambda *args, **kwargs: [])

    response = await runner._handle_message(
        _event(OWNER, "/approve opaque-request-1234", message="decision-message")
    )
    assert response == "Private-read request approved."
