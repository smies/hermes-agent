"""Relay /stop interrupt routing (relay Phase 1, Task 1.4).

Proves a connector-delivered mid-turn interrupt reaches the existing per-session
interrupt mechanism and cancels exactly the targeted session_key's turn — never
a sibling's. Mirrors the isolation discipline of test_stop_thread_sibling.py.
"""

from __future__ import annotations

import asyncio

import pytest

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import MessageEvent, MessageType
from gateway.relay.adapter import RelayAdapter
from gateway.relay.descriptor import CONTRACT_VERSION, CapabilityDescriptor
from gateway.session import SessionSource, build_session_key

from tests.gateway.relay.stub_connector import StubConnector


def _desc() -> CapabilityDescriptor:
    return CapabilityDescriptor(
        contract_version=CONTRACT_VERSION,
        platform="discord",
        label="Discord",
        max_message_length=2000,
        supports_draft_streaming=False,
        supports_edit=True,
        supports_threads=True,
        markdown_dialect="discord",
        len_unit="chars",
    )


@pytest.fixture
def adapter():
    return RelayAdapter(PlatformConfig(), _desc(), transport=StubConnector(_desc()))


@pytest.mark.asyncio
async def test_interrupt_sets_only_target_session_event(adapter):
    event = MessageEvent(
        text="/stop",
        message_type=MessageType.COMMAND,
        source=SessionSource(
            platform=Platform.DISCORD,
            chat_id="chanA",
            chat_type="group",
            user_id="userX",
        ),
    )
    key_a = build_session_key(event.source)
    key_b = "agent:main:discord:group:chanB:userY"
    ev_a = asyncio.Event()
    ev_b = asyncio.Event()
    adapter._active_sessions[key_a] = ev_a
    adapter._active_sessions[key_b] = ev_b

    await adapter.on_interrupt(event, key_a, chat_id="chanA")

    assert ev_a.is_set() is True, "target session's interrupt Event must be set"
    assert ev_b.is_set() is False, "sibling session must be untouched"


@pytest.mark.asyncio
async def test_interrupt_without_authenticated_event_or_rejected_principal_is_noop(adapter):
    event = MessageEvent(
        text="/stop",
        message_type=MessageType.COMMAND,
        source=SessionSource(
            platform=Platform.DISCORD,
            chat_id="chanA",
            chat_type="group",
            user_id="userX",
        ),
    )
    key = build_session_key(event.source)
    active = asyncio.Event()
    adapter._active_sessions[key] = active
    calls = []
    adapter.set_busy_principal_gate(lambda inbound, session: calls.append((inbound, session)) or False)

    await adapter.on_interrupt(None, key, "chanA")
    await adapter.on_interrupt(event, key, "chanA")

    assert calls == [(event, key)]
    assert active.is_set() is False
