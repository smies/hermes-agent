"""Transactional active-session principal lifecycle regressions."""

from __future__ import annotations

import asyncio

import pytest

import gateway.platforms.base as base_module
from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, MessageEvent
from gateway.session import SessionSource


class _Adapter(BasePlatformAdapter):
    async def connect(self, *, is_reconnect: bool = False):
        return None

    async def disconnect(self):
        return None

    async def send(self, chat_id, text, **kwargs):
        return None

    async def get_chat_info(self, chat_id):
        return {}


def _adapter() -> _Adapter:
    return _Adapter(PlatformConfig(enabled=True, token="synthetic"), Platform.DISCORD)


def _event() -> MessageEvent:
    return MessageEvent(
        text="synthetic",
        source=SessionSource(
            platform=Platform.DISCORD,
            profile="coder",
            chat_id="thread-1",
            chat_type="thread",
            thread_id="thread-1",
            scope_id="guild-1",
            user_id="owner-1",
        ),
    )


def test_create_task_failure_rolls_back_guard_task_and_principal(monkeypatch):
    adapter = _adapter()
    event = _event()
    session_key = adapter._canonical_session_key(event.source)

    def fail_create_task(_coroutine, *args, **kwargs):
        raise RuntimeError("synthetic task creation failure")

    monkeypatch.setattr(asyncio, "create_task", fail_create_task)
    assert adapter._start_session_processing(event, session_key) is False
    assert adapter._active_sessions == {}
    assert adapter._session_tasks == {}
    assert adapter._active_principal_by_session == {}
    assert adapter._background_tasks == set()


def test_task_registration_failure_rolls_back_every_owner_map(monkeypatch):
    adapter = _adapter()
    event = _event()
    session_key = adapter._canonical_session_key(event.source)

    class RegistrationFailure:
        cancelled = False

        def add_done_callback(self, _callback):
            raise RuntimeError("synthetic callback registration failure")

        def cancel(self):
            self.cancelled = True

    sentinel = RegistrationFailure()
    monkeypatch.setattr(asyncio, "create_task", lambda _coroutine: sentinel)
    assert adapter._start_session_processing(event, session_key) is False
    assert sentinel.cancelled is True
    assert adapter._active_sessions == {}
    assert adapter._session_tasks == {}
    assert adapter._active_principal_by_session == {}
    assert adapter._background_tasks == set()


@pytest.mark.asyncio
async def test_bounded_shutdown_forgets_cancellation_suppressor_without_stale_owner(
    monkeypatch,
):
    adapter = _adapter()
    event = _event()
    session_key = adapter._canonical_session_key(event.source)
    started = asyncio.Event()
    release = asyncio.Event()

    async def suppress_one_cancellation(_event):
        started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await release.wait()
        return None

    adapter.set_message_handler(suppress_one_cancellation)
    monkeypatch.setattr(base_module, "_BACKGROUND_TASK_CANCEL_TIMEOUT_S", 0.01)
    assert adapter._start_session_processing(event, session_key) is True
    straggler = adapter._session_tasks[session_key]
    await asyncio.wait_for(started.wait(), timeout=1)

    await adapter.cancel_background_tasks()
    assert not straggler.done()
    assert adapter._active_sessions == {}
    assert adapter._session_tasks == {}
    assert adapter._active_principal_by_session == {}
    assert adapter._background_tasks == set()

    # The stale generation exits later and must not resurrect or clear a
    # replacement owner installed after forced bookkeeping cleanup.
    replacement_guard = asyncio.Event()
    replacement_principal = ("replacement",)
    adapter._active_sessions[session_key] = replacement_guard
    adapter._active_principal_by_session[session_key] = replacement_principal
    release.set()
    await asyncio.wait_for(straggler, timeout=1)
    assert adapter._active_sessions[session_key] is replacement_guard
    assert adapter._active_principal_by_session[session_key] == replacement_principal
