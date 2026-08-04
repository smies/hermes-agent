from __future__ import annotations

from contextvars import ContextVar
from types import MethodType, SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import Platform
from gateway.platforms.base import BasePlatformAdapter, MessageEvent, MessageType, SendResult
from gateway.config import PlatformConfig
from gateway.run import GatewayRunner
from gateway.session import SessionSource, build_session_key
from gateway.trusted_private_read_host import TrustedPrivateReadEventBinding


def _event(user: str, message: str) -> MessageEvent:
    return MessageEvent(
        text=message,
        message_id=f"message-{user}",
        source=SessionSource(
            platform=Platform.SLACK,
            profile="fixture-profile",
            scope_id="workspace-1",
            chat_id="shared-channel",
            chat_type="thread",
            thread_id="shared-thread",
            user_id=user,
        ),
    )


class _EventBoundHost:
    def __init__(self) -> None:
        self.current: ContextVar[dict | None] = ContextVar("private-event", default=None)
        self.unbound: list[object] = []

    def bind_event(self, event: MessageEvent):
        if event is None:
            return TrustedPrivateReadEventBinding(self.current.set(None), False)
        user = event.source.user_id
        token = self.current.set({
            "source": (event.source.platform.value, event.source.scope_id, user),
            "pdp_subject": f"subject-{user}",
            "approval": f"approval-{user}",
            "resource": f"resource-{user}",
            "delivery": f"delivery-{user}",
        })
        return TrustedPrivateReadEventBinding(token, True)

    def unbind_event(self, token) -> None:
        self.unbound.append(token)
        self.current.reset(token.token)


class _FenceAdapter(BasePlatformAdapter):
    def __init__(self) -> None:
        super().__init__(PlatformConfig(enabled=True, token="fixture"), Platform.SLACK)

    async def connect(self):
        return True

    async def disconnect(self):
        return None

    async def send(self, chat_id, content, **kwargs):
        return SendResult(success=True, message_id="fixture")

    async def get_chat_info(self, chat_id):
        return {"id": chat_id}


def _runner(host: _EventBoundHost) -> GatewayRunner:
    runner = object.__new__(GatewayRunner)
    runner.config = SimpleNamespace(multiplex_profiles=False)
    runner._trusted_private_read_host = host
    runner._private_read_active_principals = {}
    return runner


@pytest.mark.asyncio
async def test_shared_thread_recursive_followup_rebinds_every_private_authority() -> None:
    event_a = _event("user-a", "first")
    event_b = _event("user-b", "second")
    session_a = build_session_key(event_a.source, thread_sessions_per_user=False)
    session_b = build_session_key(event_b.source, thread_sessions_per_user=False)
    assert session_a == session_b

    host = _EventBoundHost()
    runner = _runner(host)
    observed: list[dict] = []

    async def inner(self, message, context_prompt, history, source, session_id, **kwargs):
        observed.append(dict(host.current.get() or {}))
        if message == "first":
            await self._run_agent(
                message="second",
                context_prompt="",
                history=[],
                source=event_b.source,
                session_id=session_id,
                session_key=session_b,
                logical_event=event_b,
            )
            # Nested cleanup must restore A while A is still unwinding.
            observed.append(dict(host.current.get() or {}))
        return {"final_response": message, "messages": []}

    runner._run_agent_inner = MethodType(inner, runner)
    await runner._run_agent(
        message="first",
        context_prompt="",
        history=[],
        source=event_a.source,
        session_id="shared-session",
        session_key=session_a,
        logical_event=event_a,
    )

    assert observed == [
        {
            "source": ("slack", "workspace-1", "user-a"),
            "pdp_subject": "subject-user-a",
            "approval": "approval-user-a",
            "resource": "resource-user-a",
            "delivery": "delivery-user-a",
        },
        {
            "source": ("slack", "workspace-1", "user-b"),
            "pdp_subject": "subject-user-b",
            "approval": "approval-user-b",
            "resource": "resource-user-b",
            "delivery": "delivery-user-b",
        },
        {
            "source": ("slack", "workspace-1", "user-a"),
            "pdp_subject": "subject-user-a",
            "approval": "approval-user-a",
            "resource": "resource-user-a",
            "delivery": "delivery-user-a",
        },
    ]
    assert host.current.get() is None
    assert runner._private_read_active_principals == {}
    assert len(host.unbound) == 2


def test_shared_thread_cross_principal_steer_redirect_is_rejected() -> None:
    event_a = _event("user-a", "active")
    event_a_followup = _event("user-a", "correction")
    event_b = _event("user-b", "confused deputy")
    session = build_session_key(event_a.source, thread_sessions_per_user=False)
    runner = _runner(_EventBoundHost())
    runner._private_read_active_principals[session] = runner._private_read_principal(event_a)

    assert runner._private_read_live_injection_allowed(session, event_a_followup) is True
    assert runner._private_read_live_injection_allowed(session, event_b) is False


@pytest.mark.asyncio
async def test_baseexception_clears_event_context_and_active_principal() -> None:
    event = _event("user-a", "explode")
    session = build_session_key(event.source, thread_sessions_per_user=False)
    host = _EventBoundHost()
    runner = _runner(host)

    async def inner(*_args, **_kwargs):
        raise SystemExit

    runner._run_agent_inner = inner
    with pytest.raises(SystemExit):
        await runner._run_agent(
            message="explode",
            context_prompt="",
            history=[],
            source=event.source,
            session_id="shared-session",
            session_key=session,
            logical_event=event,
        )
    assert host.current.get() is None
    assert runner._private_read_active_principals == {}
    assert len(host.unbound) == 1


@pytest.mark.asyncio
async def test_nested_internal_run_receives_explicit_empty_private_context() -> None:
    event = _event("user-a", "authenticated")
    session = build_session_key(event.source, thread_sessions_per_user=False)
    host = _EventBoundHost()
    runner = _runner(host)
    observed: list[dict | None] = []

    async def inner(self, message, context_prompt, history, source, session_id, **kwargs):
        observed.append(host.current.get())
        if message == "authenticated":
            await self._run_agent(
                message="internal",
                context_prompt="",
                history=[],
                source=source,
                session_id=session_id,
                session_key=session,
                logical_event=None,
            )
            observed.append(host.current.get())
        return {"final_response": message, "messages": []}

    runner._run_agent_inner = MethodType(inner, runner)
    await runner._run_agent(
        message="authenticated",
        context_prompt="",
        history=[],
        source=event.source,
        session_id="shared-session",
        session_key=session,
        logical_event=event,
    )
    assert observed[0]["source"] == ("slack", "workspace-1", "user-a")
    assert observed[1] is None
    assert observed[2]["source"] == ("slack", "workspace-1", "user-a")
    assert host.current.get() is None


@pytest.mark.asyncio
async def test_untyped_binding_aborts_and_attempts_cleanup_before_agent_execution() -> None:
    event = _event("user-a", "active")
    cleaned: list[object] = []

    class _AmbiguousHost:
        _healthy = True

        def bind_event(self, _event):
            return None

        def unbind_event(self, token):
            cleaned.append(token)

    runner = _runner(_EventBoundHost())
    runner._trusted_private_read_host = _AmbiguousHost()
    runner._run_agent_inner = AsyncMock(side_effect=AssertionError("agent must not run"))

    with pytest.raises(RuntimeError, match="did not prove event binding"):
        await runner._run_agent(
            "message",
            "context",
            [],
            event.source,
            "session",
            session_key=build_session_key(event.source, thread_sessions_per_user=False),
            logical_event=event,
        )

    assert cleaned == [None]
    runner._run_agent_inner.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("text", ["2", "/approve", "/stop", "redirect me"])
async def test_base_adapter_principal_gate_precedes_every_busy_direct_dispatch(
    text: str,
) -> None:
    from tools import clarify_gateway

    event_a = _event("user-a", "active")
    event_b = _event("user-b", text)
    event_b.message_type = MessageType.TEXT
    session = build_session_key(event_a.source, thread_sessions_per_user=False)
    runner = _runner(_EventBoundHost())
    runner._private_read_active_principals[session] = runner._private_read_principal(event_a)
    queued: list[MessageEvent] = []
    runner._queue_or_replace_pending_event = lambda _key, event: queued.append(event)

    adapter = _FenceAdapter()
    adapter._message_handler = AsyncMock(return_value="")
    adapter._busy_session_handler = AsyncMock(return_value=True)
    adapter.set_busy_principal_gate(runner._guard_private_read_busy_principal)
    adapter._active_sessions[session] = __import__("asyncio").Event()
    clarify_gateway.clear_session(session)
    clarify_gateway.register("clarify-fence", session, "Pick", ["A", "B"])
    try:
        await adapter.handle_message(event_b)
        assert queued == [event_b]
        adapter._message_handler.assert_not_awaited()
        adapter._busy_session_handler.assert_not_awaited()
        assert clarify_gateway.get_pending_for_session(
            session, include_choice_prompts=True
        ) is not None
    finally:
        clarify_gateway.clear_session(session)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "route_text",
    ["yes", "clarify answer", "/approve", "redirect", "/stop", "/steer guidance"],
)
async def test_runner_earliest_gate_queues_cross_principal_before_early_routes(
    route_text: str,
) -> None:
    event_a = _event("user-a", "active")
    event_b = _event("user-b", route_text)
    session = build_session_key(event_a.source, thread_sessions_per_user=False)
    runner = _runner(_EventBoundHost())
    runner.config = SimpleNamespace(
        multiplex_profiles=False,
        group_sessions_per_user=True,
        thread_sessions_per_user=False,
    )
    runner.session_store = None
    runner._running_agents = {session: MagicMock()}
    runner._running_agents_ts = {session: 1.0}
    runner._private_read_active_principals[session] = runner._private_read_principal(event_a)
    runner._is_user_authorized = lambda _source: True
    runner._startup_restore_in_progress = False
    runner._scale_to_zero_note_real_inbound = lambda: None
    queued: list[MessageEvent] = []
    runner._queue_or_replace_pending_event = lambda _key, event: queued.append(event)

    result = await GatewayRunner._handle_message(runner, event_b)

    assert result is None
    assert queued == [event_b]
    runner._running_agents[session].interrupt.assert_not_called()
    runner._running_agents[session].redirect.assert_not_called()
    runner._running_agents[session].steer.assert_not_called()
