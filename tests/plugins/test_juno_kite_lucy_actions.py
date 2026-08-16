"""Whether Lucy can actually act, driven as Lucy.

The action slice shipped with her policy granting `juno.action.todo`, her
action rule in place, and her arguments validating -- and she still could not
add a task, because a group conversation resolved every action capability to
the empty set regardless of what anyone held. Reading the rules said yes.
Driving the flow said no, and only the second one is the system.

So these tests establish a real group binding from a real roster, with Lucy
as the initiating principal, and ask the binding rather than the policy.
"""
from __future__ import annotations

import copy

import pytest
from gateway.config import Platform
from types import SimpleNamespace

from tests.plugins.test_juno_kite_slice_a import (
    _GROUP,
    _LID_A,
    _LID_B,
    _PHONE_A,
    _PHONE_B,
    _PHONE_UNKNOWN,
    Clock,
    MutableRoster,
    _config,
    _event,
)
from plugins.juno_kite_trusted_principal.runtime import TrustedPrincipalRuntime

# `owner` is the James-shaped principal: reachable in a DM or the group.
# `family` is the Lucy-shaped one: group only, and only alongside owner.
ACTION = "fixture.write"


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    monkeypatch.setenv("JK_MAPPING_KEY", "mapping-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_REQUEST_KEY", "request-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_RESPONSE_KEY", "response-key-with-at-least-thirty-two-bytes")


def _runtime(tmp_path, *, family_actions, clock=None):
    config = copy.deepcopy(_config(tmp_path, mode="juno"))
    principals = config["juno_kite_trusted_principal"]["policy"]["principals"]
    principals["family"]["action_capability_ids"] = list(family_actions)
    return TrustedPrincipalRuntime(
        config, active_profile="juno", clock=clock or Clock()
    )


async def _dispatch(runtime, roster, *, sender=_PHONE_B):
    gateway = SimpleNamespace(
        adapters={Platform.WHATSAPP: SimpleNamespace(authenticated_group_roster=roster)}
    )
    return await runtime.pre_gateway_dispatch(event=_event(sender=sender),
                                              gateway=gateway)


async def _bind(runtime, roster, *, sender=_PHONE_B):
    """Bind a real group audience, as Lucy unless told otherwise."""
    result = await _dispatch(runtime, roster, sender=sender)
    return result, runtime.current_audience_binding()


@pytest.mark.asyncio
async def test_lucy_holds_in_the_group_the_action_she_was_granted(tmp_path):
    """The bug: this was () no matter what her policy said."""
    runtime = _runtime(tmp_path, family_actions=[ACTION])
    result, binding = await _bind(runtime, MutableRoster())

    assert result["action"] == "critical_allow"
    assert binding.principal == "family"
    assert binding.effective_action_capability_ids == (ACTION,)


@pytest.mark.asyncio
async def test_james_can_also_act_in_the_family_group_not_only_in_a_dm(tmp_path):
    runtime = _runtime(tmp_path, family_actions=[ACTION])
    _result, binding = await _bind(runtime, MutableRoster(), sender=_PHONE_A)

    assert binding.principal == "owner"
    assert binding.effective_action_capability_ids == (ACTION,)


@pytest.mark.asyncio
async def test_an_action_one_member_lacks_does_not_survive_the_room(tmp_path):
    """Intersection, exactly as reads work: everyone present must hold it."""
    runtime = _runtime(tmp_path, family_actions=[])
    _result, binding = await _bind(runtime, MutableRoster())

    # Lucy holds nothing, so James's own action does not reach this room.
    assert binding.effective_read_capability_ids == ("private.shared",)
    assert binding.effective_action_capability_ids == ()


@pytest.mark.asyncio
async def test_james_does_not_keep_his_own_action_in_a_room_lucy_cannot_act_in(tmp_path):
    """The case that separates intersection from "whoever is asking".

    Lucy holds no action here. If the room resolved to the initiator's own
    capabilities, James asking in the family group would still act -- and the
    change would have been taken in front of an audience that was never
    entitled to it. Reads have always worked this way; actions now do too.
    """
    runtime = _runtime(tmp_path, family_actions=[])
    _result, binding = await _bind(runtime, MutableRoster(), sender=_PHONE_A)

    assert binding.principal == "owner"
    assert binding.effective_action_capability_ids == ()


@pytest.mark.asyncio
async def test_a_stranger_in_the_room_removes_every_action(tmp_path):
    runtime = _runtime(tmp_path, family_actions=[ACTION])
    roster = MutableRoster(
        participants=[[_PHONE_A, _LID_A], [_PHONE_B, _LID_B], [_PHONE_UNKNOWN]]
    )
    _result, binding = await _bind(runtime, roster)

    # An unproved member makes the audience unknown, and an unknown audience
    # gets no reads and no actions -- the stricter of the two rules wins.
    assert binding.effective_read_capability_ids == ()
    assert binding.effective_action_capability_ids == ()
    assert binding.private_eligible is False


@pytest.mark.asyncio
async def test_lucy_cannot_act_with_her_co_principal_absent(tmp_path):
    """Her whole authority to act is that she never does it alone."""
    runtime = _runtime(tmp_path, family_actions=[ACTION])
    roster = MutableRoster(participants=[[_PHONE_B, _LID_B]])
    result = await _dispatch(runtime, roster)

    assert result["action"] != "critical_allow"
    # No audience is bound at all, so there is nothing to hold an action.
    with pytest.raises(ValueError, match="no active authenticated audience"):
        runtime.current_audience_binding()


@pytest.mark.asyncio
async def test_the_action_fingerprint_follows_the_room_not_the_policy(tmp_path):
    """A room that changes underneath a bound turn must not keep its actions.

    This is the seam that had to exist before a group could hold an action at
    all: the capability set is fingerprinted into the request and rechecked at
    both gates, so gaining a member invalidates the turn rather than silently
    acting for a wider audience.
    """
    runtime = _runtime(tmp_path, family_actions=[ACTION])
    roster = MutableRoster()
    _result, before = await _bind(runtime, roster)
    assert before.effective_action_capability_ids == (ACTION,)

    roster.participants.append([_PHONE_UNKNOWN])
    _result, after = await _bind(runtime, roster)

    assert after.effective_action_capability_ids == ()
    # The two turns cannot be confused for one another.
    assert after.audience_digest != before.audience_digest
