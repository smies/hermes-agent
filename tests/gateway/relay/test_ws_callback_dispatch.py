"""Socket-free lifecycle proofs for relay callback dispatch.

The companion real-loopback tests exercise the same paths on a host that may
bind loopback.  These tests keep cancellation, overload, and ordering coverage
available in restricted sandboxes where local listen sockets are forbidden.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from gateway.relay.ws_transport import WebSocketRelayTransport


def _event_frame(text: str) -> dict:
    return {
        "type": "inbound",
        "event": {
            "text": text,
            "message_type": "text",
            "source": {
                "platform": "discord",
                "chat_id": "thread-1",
                "chat_type": "thread",
                "thread_id": "thread-1",
                "user_id": "owner-a",
            },
        },
    }


class _LoopbackSocket:
    def __init__(self) -> None:
        self.incoming: asyncio.Queue[str | None] = asyncio.Queue()
        self.closed = False
        self.sent: list[dict] = []

    def __aiter__(self):
        return self

    async def __anext__(self):
        item = await self.incoming.get()
        if item is None:
            raise StopAsyncIteration
        return item

    async def send(self, raw: str) -> None:
        frame = json.loads(raw)
        self.sent.append(frame)
        if frame.get("type") == "outbound":
            response = {
                "type": "outbound_result",
                "requestId": frame["requestId"],
                "result": {"success": True, "message_id": "ack-1"},
            }
            await self.push(response)

    async def push(self, *frames: dict) -> None:
        await self.incoming.put("".join(json.dumps(frame) + "\n" for frame in frames))

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            await self.incoming.put(None)


def _running_transport(queue_max: int = 128):
    transport = WebSocketRelayTransport(
        "ws://synthetic.invalid", "discord", "synthetic"
    )
    socket = _LoopbackSocket()
    transport._ws = socket
    transport._closing = False
    transport._connection_generation = 1
    transport._callback_queue_max = queue_max
    transport._callback_queue = asyncio.Queue(maxsize=queue_max)
    transport._callback_worker = asyncio.create_task(
        transport._callback_loop(1), name="test-relay-callbacks"
    )
    transport._reader = asyncio.create_task(
        transport._read_loop(socket, 1), name="test-relay-reader"
    )
    return transport, socket


@pytest.mark.asyncio
async def test_reentrant_ack_future_completes_and_sentinel_stays_ordered():
    transport, socket = _running_transport()
    order: list[str] = []
    complete = asyncio.Event()

    async def callback(event):
        order.append(event.text)
        if event.text == "prompt":
            result = await transport.send_outbound({"op": "send", "content": "ack"})
            assert result["message_id"] == "ack-1"
            await socket.push(_event_frame("sentinel"))
        else:
            complete.set()

    transport.set_inbound_handler(callback)
    await socket.push(_event_frame("prompt"))
    await asyncio.wait_for(complete.wait(), timeout=1)
    assert order == ["prompt", "sentinel"]
    assert transport._pending == {}
    assert transport._reader is not None and not transport._reader.done()
    await transport.disconnect()


@pytest.mark.asyncio
async def test_interrupt_typing_cleanup_egress_and_callback_failure_are_serial():
    transport, socket = _running_transport()
    order: list[str] = []
    done = asyncio.Event()

    async def interrupt(_event, _session, _chat):
        order.append("interrupt")
        result = await transport.send_outbound({"op": "typing", "active": False})
        assert result["success"] is True

    async def callback(event):
        order.append(event.text)
        if event.text == "boom":
            raise RuntimeError("synthetic callback failure")
        done.set()

    transport.set_interrupt_inbound_handler(interrupt)
    transport.set_inbound_handler(callback)
    await socket.push(
        {
            "type": "interrupt_inbound",
            "event": _event_frame("ignored")["event"],
            "session_key": "session-1",
            "chat_id": "thread-1",
        },
        _event_frame("boom"),
        _event_frame("after"),
    )
    await asyncio.wait_for(done.wait(), timeout=1)
    assert order == ["interrupt", "boom", "after"]
    assert transport._reader is not None and not transport._reader.done()
    await transport.disconnect()


@pytest.mark.asyncio
async def test_callback_queue_overload_closes_and_drains_generation():
    transport, socket = _running_transport(queue_max=1)
    entered = asyncio.Event()

    async def callback(_event):
        entered.set()
        await asyncio.Future()

    transport.set_inbound_handler(callback)
    await socket.push(_event_frame("first"))
    await asyncio.wait_for(entered.wait(), timeout=1)
    await socket.push(_event_frame("queued"), _event_frame("overload"))
    reader = transport._reader
    assert reader is not None
    await asyncio.wait_for(asyncio.shield(reader), timeout=2)
    assert socket.closed is True
    assert transport._pending == {}
    assert transport._callback_worker is None
    assert transport._callback_queue is None


@pytest.mark.asyncio
async def test_disconnect_from_callback_never_awaits_or_cancels_itself():
    transport, socket = _running_transport()
    returned = asyncio.Event()

    async def callback(_event):
        await transport.disconnect()
        returned.set()

    transport.set_inbound_handler(callback)
    await socket.push(_event_frame("disconnect"))
    await asyncio.wait_for(returned.wait(), timeout=1)
    for _ in range(100):
        if transport._callback_worker is None:
            break
        await asyncio.sleep(0)
    assert transport._callback_worker is None
    assert transport._callback_queue is None
    assert transport._pending == {}
    assert socket.closed is True


@pytest.mark.asyncio
async def test_reconnect_generation_has_no_old_callbacks_or_late_markers():
    transport, first_socket = _running_transport()
    seen: list[str] = []
    old_entered = asyncio.Event()

    async def old_callback(event):
        seen.append(event.text)
        old_entered.set()
        await asyncio.Future()

    transport.set_inbound_handler(old_callback)
    await first_socket.push(_event_frame("old"))
    await asyncio.wait_for(old_entered.wait(), timeout=1)
    await transport.disconnect()
    assert transport._callback_worker is None
    assert transport._callback_queue is None

    second_socket = _LoopbackSocket()
    transport._closing = False
    transport._ws = second_socket
    transport._connection_generation += 1
    generation = transport._connection_generation
    transport._callback_queue = asyncio.Queue(maxsize=128)
    transport._callback_worker = asyncio.create_task(
        transport._callback_loop(generation), name="test-relay-callbacks-reconnected"
    )
    transport._reader = asyncio.create_task(
        transport._read_loop(second_socket, generation),
        name="test-relay-reader-reconnected",
    )
    delivered = asyncio.Event()

    async def new_callback(event):
        seen.append(event.text)
        delivered.set()

    transport.set_inbound_handler(new_callback)
    await second_socket.push(_event_frame("new"))
    await asyncio.wait_for(delivered.wait(), timeout=1)
    assert seen == ["old", "new"]
    assert transport._pending == {}
    await transport.disconnect()
    assert transport._reader is None
    assert transport._callback_worker is None
    assert transport._callback_queue is None
