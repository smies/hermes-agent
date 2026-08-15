"""The first action: adding a task to the household's list.

Reading was built first and taught one lesson repeatedly -- a refusal that
names nothing costs a real answer. These tests hold an action to the same
standard, and add the one thing reading never needed: a change that fails
must be distinguishable from a change that was not allowed, because "try
again in a minute" and "you may not do this" are opposite instructions.
"""
from __future__ import annotations

import copy
import json
import subprocess
from types import SimpleNamespace

import pytest

from plugins.juno_kite_trusted_principal.actions import (
    ACTION_TOOL_NAMES,
    ActionService,
    action_handlers_for,
)
from plugins.juno_kite_trusted_principal.private_reads import (
    THINGS_PROJECT_TITLE,
    THINGS_PROJECT_UUID,
)
from plugins.juno_kite_trusted_principal.runtime import TrustedPrincipalRuntime
from tests.plugins.test_juno_kite_trusted_principal import _base_config

THINGS_CONFIG = {
    "things": {"client": "/opt/things/client", "endpoint": "http://127.0.0.1:9999"}
}


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    monkeypatch.setenv("JK_MAPPING_KEY", "mapping-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_REQUEST_KEY", "request-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_RESPONSE_KEY", "response-key-with-at-least-thirty-two-bytes")


def _service(*, returncode=0, stdout="ok", stderr="", record=None,
             lookup=None, lookup_rc=0):
    """A stand-in list. `lookup` is what a search finds after a failed add."""
    def runner(argv, **kwargs):
        if record is not None:
            record.append((argv, kwargs))
        if "search" in argv:
            if lookup is None:
                raise AssertionError("the list was searched unexpectedly")
            return SimpleNamespace(
                returncode=lookup_rc, stdout=json.dumps(lookup), stderr="")
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    return ActionService(THINGS_CONFIG, command_runner=runner)


def _add(service, **args):
    return json.loads(service.execute("kite_things_add_task", args))


def _payload(calls):
    """The JSON the client was called with, found rather than indexed."""
    argv = calls[0][0]
    return json.loads(argv[argv.index("add_todo") + 1])


# --------------------------------------------------------------------------
# What the action does
# --------------------------------------------------------------------------


def test_a_task_is_filed_on_the_one_list_the_action_is_pinned_to():
    calls: list = []
    result = _add(_service(record=calls), title="Book the ferry")

    assert result["status"] == "ok"
    argv = calls[0][0]
    assert argv[:3] == ["/opt/things/client", "--url", "http://127.0.0.1:9999"]
    assert "add_todo" in argv
    payload = _payload(calls)
    # The list is not an argument, so no caller -- model or person -- can file
    # a household task somewhere nobody looks.
    assert payload["list_id"] == THINGS_PROJECT_UUID
    assert payload["title"] == "Book the ferry"
    assert result["list"] == THINGS_PROJECT_TITLE


def test_the_action_takes_no_lease_because_it_is_not_reconciling():
    calls: list = []
    _add(_service(record=calls), title="Renew the parking permit")

    payload = _payload(calls)
    # The lease is mutual exclusion between reconciliation workers, not a
    # write gate. A one-off add that invented a run_id would be claiming to
    # be a reconciliation run, which is a different and much larger promise.
    assert "run_id" not in payload and "lease_token" not in payload


def test_a_shell_is_never_involved():
    calls: list = []
    _add(_service(record=calls), title="Pay the window cleaner; rm -rf /")

    assert calls[0][1]["shell"] is False
    assert calls[0][1]["stdin"] is subprocess.DEVNULL


def test_optional_notes_travel_and_omitted_ones_do_not():
    calls: list = []
    _add(_service(record=calls), title="Call the plumber",
         notes="The upstairs radiator is cold")
    assert _payload(calls)["notes"] == "The upstairs radiator is cold"

    calls.clear()
    _add(_service(record=calls), title="Call the plumber")
    assert "notes" not in _payload(calls)


def test_no_scheduling_is_offered_while_the_date_it_lands_on_is_wrong():
    """`when` asked for today and stored yesterday, so it is not offered.

    Filing a household task on the wrong day is worse than filing it on no
    day: the person stops trusting the dates on the whole list.
    """
    schema = _service().schema_for("kite_things_add_task")
    assert "when" not in schema["parameters"]["properties"]
    result = _add(_service(), title="Call the plumber", when="today")
    assert result["error"]["code"] == "invalid_arguments"


def test_the_confirmation_says_what_changed_in_the_words_it_was_asked_in():
    result = _add(_service(), title="Order Nacho's birthday cake")
    # A turn that reports "the action completed" tells the person nothing they
    # can check. Naming the task and the list is what makes it verifiable.
    assert "Order Nacho's birthday cake" in result["say"]
    assert THINGS_PROJECT_TITLE in result["say"]


# --------------------------------------------------------------------------
# How it fails
# --------------------------------------------------------------------------


def test_a_reconciliation_lease_is_a_wait_and_says_so():
    service = _service(
        returncode=1,
        stdout="",
        stderr="PermissionError: active reconciliation lease is owned by another worker",
    )
    result = _add(service, title="Book the dentist")

    assert result["status"] == "error"
    assert result["error"]["code"] == "list_busy"
    # The whole point: this must not read as a refusal.
    assert result["error"]["retryable"] is True
    assert "shortly" in result["error"]["message"]


def test_a_real_failure_is_not_dressed_up_as_a_retry():
    result = _add(_service(returncode=1, stdout="", stderr="database is corrupt",
                           lookup=[]),
                  title="Book the dentist")

    assert result["error"]["code"] == "action_failed"
    assert result["error"]["retryable"] is False
    # And it must not imply the task landed.
    assert "not added" in result["error"]["message"]


@pytest.mark.parametrize(
    "args, expected",
    [
        ({"title": ""}, "title"),
        ({"title": "   "}, "title"),
        ({"title": "x" * 201}, "title"),
        ({"title": "ok", "notes": "n" * 2001}, "notes"),
    ],
)
def test_a_rejected_argument_names_itself_and_what_it_wanted(args, expected):
    result = _add(_service(), **args)

    assert result["status"] == "error"
    assert result["error"]["code"] == "invalid_arguments"
    # Every reader learned this the hard way: a refusal that does not say what
    # to write instead sends the model round the loop again.
    assert expected in result["error"]["message"]


def test_a_task_written_before_the_client_failed_is_reported_as_added():
    """The bug the first live run found.

    The client created the task, checked its own postcondition, disagreed with
    what it read back, and exited non-zero. Reporting "not added" there is
    false, and the person who believes it adds the task a second time.
    """
    service = _service(
        returncode=1,
        stdout="",
        stderr='Things mutation postcondition mismatch: {"start_date": ...}',
        lookup=[{"title": "Book the ferry"}],
    )
    result = _add(service, title="Book the ferry")

    assert result["status"] == "ok"
    assert result["outcome"] == "added"
    assert result["confirmed_by"] == "lookup"


def test_a_failure_that_wrote_nothing_still_says_it_wrote_nothing():
    service = _service(returncode=1, stdout="", stderr="disk full",
                       lookup=[{"title": "Something else entirely"}])
    result = _add(service, title="Book the ferry")

    assert result["error"]["code"] == "action_failed"
    assert "not added" in result["error"]["message"]


def test_uncertainty_is_admitted_rather_than_guessed_either_way():
    service = _service(returncode=1, stdout="", stderr="disk full",
                       lookup=[], lookup_rc=1)
    result = _add(service, title="Book the ferry")

    assert result["error"]["code"] == "action_uncertain"
    # It must not claim either outcome, and must not invite a blind retry.
    assert "may or may not" in result["error"]["message"]
    assert result["error"]["retryable"] is False


def test_a_busy_list_is_not_searched_because_nothing_was_written():
    # The fake raises if searched. The lease is taken before any change, so
    # there is nothing to look for and no reason to pay for a lookup.
    service = _service(
        returncode=1, stdout="",
        stderr="active reconciliation lease is owned by another worker")
    assert _add(service, title="Book the ferry")["error"]["code"] == "list_busy"


def test_nothing_is_sent_to_the_list_when_arguments_are_rejected():
    calls: list = []
    _add(_service(record=calls), title="")
    assert calls == []


def test_an_unknown_action_is_refused_rather_than_dispatched():
    result = json.loads(_service().execute("kite_things_delete_everything", {}))
    assert result["error"]["code"] == "operation_denied"


# --------------------------------------------------------------------------
# What is available at all
# --------------------------------------------------------------------------


def test_the_service_is_absent_rather_than_broken_without_a_client():
    service = ActionService({})
    assert service.enabled is False
    assert service.tool_names == ()
    assert action_handlers_for(service) == {}


def test_every_named_action_has_a_schema_and_a_handler():
    service = _service()
    handlers = action_handlers_for(service)
    assert sorted(handlers) == sorted(ACTION_TOOL_NAMES)
    for name in ACTION_TOOL_NAMES:
        schema = service.schema_for(name)
        assert schema["description"].strip()
        assert schema["parameters"]["additionalProperties"] is False


def test_this_system_implements_no_way_to_send_anything():
    """James's rule for mail, as a property rather than a habit.

    Kite may draft and never send. The durable form of that is not an
    instruction anyone has to remember -- it is that no sending action exists
    here to authorise, so no policy file can grant one.
    """
    assert not [name for name in ACTION_TOOL_NAMES if "send" in name.lower()]


# --------------------------------------------------------------------------
# Who may act
# --------------------------------------------------------------------------


def _policy_runtime(tmp_path, mutate):
    config = copy.deepcopy(_base_config(tmp_path))
    mutate(config["juno_kite_trusted_principal"]["policy"])
    return TrustedPrincipalRuntime(config, active_profile="juno")


def test_a_group_only_principal_may_act_alongside_a_required_co_principal(tmp_path):
    def grant(policy):
        policy["principals"]["lucy"]["action_capability_ids"] = ["fixture.write"]
        policy["action_rules"].append({
            "principal": "lucy",
            "tool": "write_file",
            "arguments": {"path": str(tmp_path / "x.txt"), "content": "c",
                          "encoding": "utf-8"},
        })

    runtime = _policy_runtime(tmp_path, grant)
    # Lucy is reachable only in the group, and that group requires James. Who
    # sent a group message is established by the sender fence -- the same
    # identification her every read already relies on.
    assert ("lucy", "write_file") in runtime.action_schemas


def test_a_group_only_principal_may_not_act_alone(tmp_path):
    def grant(policy):
        policy["principals"]["lucy"]["action_capability_ids"] = ["fixture.write"]
        policy["principals"]["lucy"]["required_group_co_principals"] = []

    with pytest.raises(ValueError, match="required co-principal"):
        _policy_runtime(tmp_path, grant)


def test_an_action_rule_needs_a_principal_who_may_act_at_all(tmp_path):
    def grant(policy):
        policy["action_rules"].append({
            "principal": "lucy",
            "tool": "write_file",
            "arguments": {"path": str(tmp_path / "x.txt"), "content": "c",
                          "encoding": "utf-8"},
        })

    with pytest.raises(ValueError, match="semantic action capability"):
        _policy_runtime(tmp_path, grant)
