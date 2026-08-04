from __future__ import annotations

from contextvars import ContextVar
from types import MethodType, SimpleNamespace

import pytest

from gateway.config import Platform
from gateway.platforms.base import MessageEvent
from gateway.run import GatewayRunner
from gateway.session import SessionSource, build_session_key


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
            return self.current.set(None)
        user = event.source.user_id
        return self.current.set({
            "source": (event.source.platform.value, event.source.scope_id, user),
            "pdp_subject": f"subject-{user}",
            "approval": f"approval-{user}",
            "resource": f"resource-{user}",
            "delivery": f"delivery-{user}",
        })

    def unbind_event(self, token) -> None:
        self.unbound.append(token)
        if token is not None:
            self.current.reset(token)


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
