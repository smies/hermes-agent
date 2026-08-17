"""Delivery must run on the loop that owns the adapter's HTTP session.

The live symptom was a cron job reporting:

    Plugin platform send failed: Timeout context manager should be used
    inside a task

An adapter's aiohttp session belongs to the loop it was created on. Awaiting
a request from a *different* loop arms the request timer against a loop with
no current task, and aiohttp raises that error. Reproduced on aiohttp 3.14.1:
same-loop calls driven by run_coroutine_threadsafe are fine, cross-loop calls
fail every time.

Worth stating because the obvious remedy is wrong: swapping ClientTimeout for
asyncio.wait_for leaves the error exactly as it was. The loop is the fault,
not the timeout style.
"""
from __future__ import annotations

import asyncio
import threading

import pytest


@pytest.fixture
def foreign_loop():
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    yield loop
    loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=5)
    loop.close()


def _bridge():
    from tools.send_message_tool import _await_on_gateway_loop
    return _await_on_gateway_loop


@pytest.mark.asyncio
async def test_the_call_runs_on_the_gateway_loop_not_the_callers(foreign_loop):
    """The whole point: execution moves to the loop owning the session."""
    ran_on = []

    async def work():
        ran_on.append(asyncio.get_running_loop())
        return "done"

    runner = type("R", (), {"_gateway_loop": foreign_loop})()
    caller = asyncio.get_running_loop()

    assert await _bridge()(runner, work()) == "done"
    assert ran_on == [foreign_loop]
    assert ran_on[0] is not caller


@pytest.mark.asyncio
async def test_same_loop_is_awaited_directly(foreign_loop):
    ran_on = []

    async def work():
        ran_on.append(asyncio.get_running_loop())
        return "done"

    caller = asyncio.get_running_loop()
    runner = type("R", (), {"_gateway_loop": caller})()

    assert await _bridge()(runner, work()) == "done"
    assert ran_on == [caller]


@pytest.mark.asyncio
async def test_a_runner_without_a_loop_still_delivers():
    """Older runners, or none at all, must not break delivery."""
    async def work():
        return "done"

    assert await _bridge()(object(), work()) == "done"


@pytest.mark.asyncio
async def test_a_closed_gateway_loop_does_not_strand_the_message():
    """A stopped gateway must fail loudly, not hang on a dead loop."""
    dead = asyncio.new_event_loop()
    dead.close()

    async def work():
        return "done"

    runner = type("R", (), {"_gateway_loop": dead})()
    assert await _bridge()(runner, work()) == "done"


@pytest.mark.asyncio
async def test_an_exception_crosses_back_to_the_caller(foreign_loop):
    """A send failure on the gateway loop must surface here, not vanish."""
    async def work():
        raise RuntimeError("upstream refused")

    runner = type("R", (), {"_gateway_loop": foreign_loop})()
    with pytest.raises(RuntimeError, match="upstream refused"):
        await _bridge()(runner, work())


def test_delivery_actually_routes_through_the_bridge():
    import inspect
    from tools import send_message_tool

    source = inspect.getsource(send_message_tool._send_via_adapter)
    assert "_await_on_gateway_loop(" in source, (
        "adapter sends no longer go through the owning-loop bridge"
    )
