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
    adapter._active_principal_by_session[key_a] = adapter._authenticated_principal(event)

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
    adapter._active_principal_by_session[key] = adapter._authenticated_principal(event)
    calls = []
    adapter.set_busy_principal_gate(lambda inbound, session: calls.append((inbound, session)) or False)

    await adapter.on_interrupt(None, key, "chanA")
    await adapter.on_interrupt(event, key, "chanA")

    assert calls == [(event, key)]
    assert active.is_set() is False


@pytest.mark.asyncio
@pytest.mark.parametrize("host_present", [False, True])
async def test_interrupt_missing_active_owner_fails_closed_with_or_without_host(
    adapter, host_present
):
    """Reviewer reproductions: neither missing-owner case may mutate active state."""
    event = MessageEvent(
        text="/stop",
        message_type=MessageType.COMMAND,
        source=SessionSource(
            platform=Platform.DISCORD,
            chat_id="shared-thread",
            chat_type="thread",
            thread_id="shared-thread",
            user_id="principal-b",
        ),
    )
    key = adapter._canonical_session_key(event.source)
    active = asyncio.Event()
    adapter._active_sessions[key] = active
    gate_calls = []
    if host_present:
        # Models the old trusted-host gate's missing-owner fail-open result.
        adapter.set_busy_principal_gate(
            lambda inbound, session: gate_calls.append((inbound, session)) or True
        )
    await adapter.on_interrupt(event, key, "shared-thread")
    assert active.is_set() is False
    assert gate_calls == []


@pytest.mark.asyncio
async def test_interrupt_exact_owner_works_without_private_host(adapter):
    event = MessageEvent(
        text="/stop",
        message_type=MessageType.COMMAND,
        source=SessionSource(
            platform=Platform.DISCORD,
            chat_id="shared-thread",
            chat_type="thread",
            thread_id="shared-thread",
            user_id="principal-a",
            profile="coder",
        ),
    )
    key = adapter._canonical_session_key(event.source)
    active = asyncio.Event()
    adapter._active_sessions[key] = active
    adapter._active_principal_by_session[key] = adapter._authenticated_principal(event)
    await adapter.on_interrupt(event, key, "shared-thread")
    assert active.is_set() is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("platform", "profile", "user_id", "chat_id"),
    [
        (Platform.DISCORD, "coder", "principal-b", "shared-thread"),
        (Platform.DISCORD, "main", "principal-a", "shared-thread"),
        (Platform.TELEGRAM, "coder", "principal-a", "shared-thread"),
        (Platform.DISCORD, "coder", "principal-a", "other-thread"),
    ],
)
async def test_interrupt_rejects_principal_profile_platform_and_session_mismatch(
    adapter, platform, profile, user_id, chat_id
):
    owner = MessageEvent(
        text="start",
        source=SessionSource(
            platform=Platform.DISCORD,
            chat_id="shared-thread",
            chat_type="thread",
            thread_id="shared-thread",
            user_id="principal-a",
            profile="coder",
        ),
    )
    key = adapter._canonical_session_key(owner.source)
    active = asyncio.Event()
    adapter._active_sessions[key] = active
    adapter._active_principal_by_session[key] = adapter._authenticated_principal(owner)
    incoming = MessageEvent(
        text="/stop",
        message_type=MessageType.COMMAND,
        source=SessionSource(
            platform=platform,
            chat_id=chat_id,
            chat_type="thread",
            thread_id=chat_id,
            user_id=user_id,
            profile=profile,
        ),
    )
    await adapter.on_interrupt(incoming, key, chat_id)
    assert active.is_set() is False
