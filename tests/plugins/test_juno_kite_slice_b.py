"""Slice B semantic disclosure and exact private-read connector tests.

All connector data and identities are synthetic. No test contacts a private
provider, starts a listener, or reads an operator source.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from contextvars import copy_context
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.session_context import clear_session_vars, set_session_vars
from plugins.juno_kite_trusted_principal.disclosure import (
    BOUNDED_EXCERPT,
    BULK_RAW,
    DOCUMENT_DESCRIPTOR,
    MINIMIZED,
    classify_output_tier,
    disclosure_decision,
    generated_semantic_guidance,
)
from plugins.juno_kite_trusted_principal.private_reads import (
    KITE_GMAIL,
    PERSONAL_GMAIL,
    PRIVATE_READ_TOOLSET,
    THINGS_CLIENT,
    THINGS_ENDPOINT,
    THINGS_PROJECT_TITLE,
    THINGS_PROJECT_UUID,
    TOOL_NAMES,
    TOOL_SCHEMAS,
    WHATSAPP_QUERY,
    PrivateReadService,
)
from plugins.juno_kite_trusted_principal.runtime import (
    RESPONSE_PREFIX,
    TrustedPrincipalRuntime,
)
from tests.plugins.test_juno_kite_trusted_principal import (
    _base_config,
    _run_in_session,
)


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    monkeypatch.setenv("JK_MAPPING_KEY", "mapping-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_REQUEST_KEY", "request-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_RESPONSE_KEY", "response-key-with-at-least-thirty-two-bytes")


@pytest.fixture(autouse=True)
def _fresh_preview_cache():
    """No test inherits another's extraction.

    The document preview cache is process-global on purpose -- it exists so a
    later turn does not pay the recogniser again -- which means a test that
    stubs the reader would otherwise be answered by whatever an earlier test
    stubbed for the same bytes.
    """
    from plugins.juno_kite_trusted_principal import private_reads as pr

    pr._reset_document_preview_cache()
    yield
    pr._reset_document_preview_cache()


class RecordingBackend:
    def __init__(self, results=None, failure=None):
        self.results = dict(results or {})
        self.failure = failure
        self.calls = []

    def execute(self, operation, args):
        self.calls.append((operation, copy.deepcopy(args)))
        if self.failure:
            raise self.failure
        value = self.results.get(operation, [])
        return copy.deepcopy(value(args) if callable(value) else value)


def _slice_b_config(tmp_path: Path, *, mode="juno") -> dict:
    config = _base_config(tmp_path)
    section = config["juno_kite_trusted_principal"]
    section.update(
        mode=mode,
        profile=mode,
        policy_generation="slice-b-policy-v1",
        private_reads={
            "enabled": True,
            "timeout_seconds": 5,
            "output_bytes": 65_536,
        },
    )
    section["limits"].update(
        question_chars=512,
        policy_view_chars=20_000,
        output_chars=4_000,
        response_bytes=12_000,
    )
    principals = section["policy"]["principals"]
    shared = [
        "juno.public",
        "juno.shared.children",
        "juno.shared.family",
        "juno.shared.mauritius",
        "juno.shared.property_intel",
        "juno.shared.villa_lena",
    ]
    james_caps = ["juno.private.james", *shared]
    principals["james"].update(
        read_capability_ids=james_caps,
        action_capability_ids=[],
        semantic_policy={name: {"domain": name} for name in james_caps},
    )
    principals["lucy"].update(
        conversation_eligibility={"dm": True, "group": True},
        read_capability_ids=shared,
        action_capability_ids=[],
        semantic_policy={name: {"domain": name} for name in shared},
    )
    section["policy"]["tool_classes"] = {"read": [], "mutating": []}
    section["policy"]["action_rules"] = []
    return config


def _runtime(tmp_path: Path, *, mode="juno", backends=None):
    return TrustedPrincipalRuntime(
        _slice_b_config(tmp_path, mode=mode),
        active_profile=mode,
        private_read_backends=backends,
    )


def _bound_turn(
    tmp_path: Path,
    backends,
    callback,
    question="What is the current status?",
    *,
    principal="james",
):
    juno = _runtime(tmp_path, mode="juno", backends=backends)
    user_id = "fixture-user-101" if principal == "james" else "fixture-user-202"
    prepared = _run_in_session(
        lambda: juno._prepare_request({"question_or_goal": question}),
        platform="telegram",
        user_id=user_id,
        session_key=f"conversation-slice-b-{principal}",
        profile="juno",
    )
    call = {
        "message": prepared.message,
        "context_id": prepared.mapping.context_id,
    }
    kite = _runtime(tmp_path, mode="kite", backends=backends)

    def turn():
        policy = kite.pre_llm_call(
            user_message=call["message"],
            session_id="kite-session",
            turn_id="kite-turn",
        )
        assert "source-agnostic policy view" in policy["context"]
        return callback(kite)

    return _run_in_session(
        turn,
        platform="a2a",
        user_id="juno",
        session_key=f"agent:kite:a2a:dm:{call['context_id']}",
        profile="kite",
        chat_id=call["context_id"],
    )


def _invoke(kite, name, args):
    assert (
        kite.pre_tool_call(
            name,
            args,
            session_id="kite-session",
            turn_id="kite-turn",
            tool_call_id="call-1",
        )
        is None
    )
    assert (
        kite.pre_tool_dispatch(
            name,
            args,
            session_id="kite-session",
            turn_id="kite-turn",
            tool_call_id="call-1",
        )
        is None
    )
    return json.loads(kite.execute_private_read(name, args, session_id="kite-session"))


def test_kite_registers_only_exact_private_read_surface(tmp_path, monkeypatch):
    import plugins.juno_kite_trusted_principal as plugin

    kite = _runtime(tmp_path, mode="kite", backends={})
    monkeypatch.setattr(plugin, "runtime_from_host", lambda _profile: kite)
    context = SimpleNamespace(
        profile_name="kite",
        tools=[],
        hooks=[],
        register_tool=lambda **kwargs: context.tools.append(kwargs),
        register_hook=lambda name, callback: context.hooks.append((name, callback)),
    )
    plugin.register(context)
    assert {item["name"] for item in context.tools} == set(TOOL_NAMES)
    assert {item["toolset"] for item in context.tools} == {"juno_kite_private_reads"}
    assert all(item["check_fn"]() is True for item in context.tools)
    assert not {
        "terminal",
        "execute_code",
        "read_file",
        "search_files",
        "write_file",
        "patch",
        "a2a_call",
        "mcp_call",
        "homeassistant",
        "cron",
        "send_message",
    }.intersection(item["name"] for item in context.tools)


def test_juno_registers_no_private_read_tools(tmp_path, monkeypatch):
    import plugins.juno_kite_trusted_principal as plugin

    juno = _runtime(tmp_path)
    monkeypatch.setattr(plugin, "runtime_from_host", lambda _profile: juno)
    tools = []
    context = SimpleNamespace(
        profile_name="juno",
        register_tool=lambda **kwargs: tools.append(kwargs),
        register_hook=lambda *_args: None,
    )
    plugin.register(context)
    assert [item["name"] for item in tools] == ["consult_kite"]


def test_direct_kite_read_denies_before_backend(tmp_path):
    backend = RecordingBackend({"search": [{"id": "m1"}]})
    kite = _runtime(tmp_path, mode="kite", backends={"gmail": backend})
    result = _run_in_session(
        lambda: json.loads(
            kite.execute_private_read(
                "kite_gmail_search",
                {"account": "personal", "query": "trip", "max_results": 5},
                session_id="direct-session",
            )
        ),
        platform="cli",
        user_id="local",
        session_key="direct-kite",
        profile="kite",
    )
    assert result["error"]["code"] == "authority_denied"
    assert backend.calls == []


@pytest.mark.parametrize(
    "tool",
    [
        "terminal",
        "execute_code",
        "read_file",
        "search_files",
        "write_file",
        "patch",
        "mcp_call",
        "ha_get_state",
        "a2a_call",
        "memory_add",
        "cron_create",
    ],
)
def test_generic_and_mutating_tools_remain_denied_under_claim(tmp_path, tool):
    def check(kite):
        decision = kite.pre_tool_call(
            tool, {}, session_id="kite-session", turn_id="kite-turn"
        )
        assert decision["action"] == "block"

    _bound_turn(tmp_path, {}, check)


def test_deferred_broker_gates_are_exact_and_same_turn_bound(tmp_path):
    calendar_args = {
        "account": "personal",
        "start": "2026-08-08T00:00:00+01:00",
        "end": "2026-08-09T00:00:00+01:00",
        "max_results": 5,
    }

    def check(kite):
        assert kite.pre_tool_call(
            "tool_describe",
            {"name": "kite_calendar_read"},
            session_id="kite-session",
            turn_id="kite-turn",
        ) is None
        for malformed in (
            {},
            {"name": "kite_calendar_read", "extra": True},
            {"name": "read_file"},
            {"name": " kite_calendar_read"},
        ):
            assert kite.pre_tool_call(
                "tool_describe",
                malformed,
                session_id="kite-session",
                turn_id="kite-turn",
            )["action"] == "block"
        assert kite.pre_tool_call(
            "tool_describe",
            {"name": "kite_calendar_read"},
            session_id="other-session",
            turn_id="kite-turn",
        )["action"] == "block"

        broker_call = {"name": "kite_calendar_read", "arguments": calendar_args}
        assert kite.pre_tool_call(
            "tool_call",
            broker_call,
            session_id="kite-session",
            turn_id="kite-turn",
        ) is None
        assert kite.pre_tool_dispatch(
            "kite_calendar_read",
            {**calendar_args, "max_results": 6},
            session_id="kite-session",
            turn_id="kite-turn",
        )["action"] == "block"
        for malformed in (
            {"name": "read_file", "arguments": {}},
            {"name": "kite_calendar_read", "arguments": {}},
            {
                "name": "kite_calendar_read",
                "arguments": {**calendar_args, "max_results": 51},
            },
            {**broker_call, "extra": True},
        ):
            assert kite.pre_tool_call(
                "tool_call",
                malformed,
                session_id="kite-session",
                turn_id="kite-turn",
            )["action"] == "block"

    _bound_turn(tmp_path, {}, check)


def test_an_unrelated_deferred_tool_is_not_this_plugins_business(tmp_path):
    """James could not reach his own Granola connector on his own profile.

    The broker fronts every deferred tool. This hook treated any
    tool_describe/tool_call in kite mode as a possible private read and
    demanded a Juno binding before looking at what was being brokered, so an
    ordinary Mattermost turn -- no A2A, no delegation, nothing to do with
    Juno -- came back as "Juno--Kite policy blocked tool call: internal or
    missing policy binding": a policy decision about a tool this plugin does
    not own, in the name of a lane that was not involved.
    """
    kite = _runtime(tmp_path, mode="kite", backends={})
    unrelated = "mcp__granola__list_meetings"

    def ordinary_turn():
        assert kite.pre_tool_call(
            "tool_describe", {"name": unrelated},
            session_id="mm-session", turn_id="mm-turn",
        ) is None
        assert kite.pre_tool_call(
            "tool_call", {"name": unrelated, "arguments": {"limit": 5}},
            session_id="mm-session", turn_id="mm-turn",
        ) is None
        # The final-dispatch gate is the parallel path and must agree.
        assert kite.pre_tool_dispatch(
            "tool_call", {"name": unrelated, "arguments": {"limit": 5}},
            session_id="mm-session", turn_id="mm-turn",
        ) is None
        # A broker request this plugin cannot read as naming one of its own
        # readers is equally not its business; the registry validates it.
        for shape in ({}, {"name": 123}, {"arguments": {}}, None, "not-a-dict"):
            assert kite.pre_tool_call(
                "tool_describe", shape,
                session_id="mm-session", turn_id="mm-turn",
            ) is None, shape
        # ...but naming a protected reader off the lane still fails closed,
        # which is the whole point of reading the target rather than the mode.
        assert kite.pre_tool_call(
            "tool_describe", {"name": "kite_calendar_read"},
            session_id="mm-session", turn_id="mm-turn",
        )["action"] == "block"

    _run_in_session(
        ordinary_turn,
        platform="mattermost",
        user_id="james-mattermost",
        session_key="ordinary-conversation",
        profile="kite",
    )


def test_deferred_brokers_are_blocked_outside_authenticated_a2a_turn(tmp_path):
    kite = _runtime(tmp_path, mode="kite", backends={})

    def direct():
        assert kite.pre_tool_call(
            "tool_describe",
            {"name": "kite_calendar_read"},
            session_id="direct-session",
            turn_id="direct-turn",
        )["action"] == "block"
        assert kite.pre_tool_call(
            "tool_call",
            {
                "name": "kite_gmail_search",
                "arguments": {
                    "account": "personal",
                    "query": "synthetic",
                    "max_results": 2,
                },
            },
            session_id="direct-session",
            turn_id="direct-turn",
        )["action"] == "block"

    _run_in_session(
        direct,
        platform="cli",
        user_id="local",
        session_key="direct-broker",
        profile="kite",
    )


def test_real_plugin_deferred_broker_describes_and_dispatches_once(
    tmp_path, monkeypatch
):
    """Production registry + deferred broker regression for B-ACTIVE-1/4/6."""
    import hermes_cli.plugins as plugins_module
    import model_tools
    import plugins.juno_kite_trusted_principal as plugin
    from hermes_cli.plugins import (
        PluginContext,
        PluginManager,
        PluginManifest,
        resolve_pre_tool_block,
    )
    from agent.tool_executor import plan_tool_batch
    from tools.registry import registry

    gmail = RecordingBackend({"search": [{"id": "synthetic-message-1"}]})
    calendar = RecordingBackend({"list": []})

    def check(kite):
        manager = PluginManager()
        monkeypatch.setattr(plugin, "runtime_from_host", lambda _profile: kite)
        monkeypatch.setattr(plugins_module, "_plugin_manager", manager)
        context = PluginContext(
            PluginManifest(
                name="juno_kite_trusted_principal", source="bundled"
            ),
            manager,
        )
        plugin.register(context)
        try:
            definitions = model_tools.get_tool_definitions(
                enabled_toolsets=[PRIVATE_READ_TOOLSET], quiet_mode=True
            )
            visible_names = {
                item["function"]["name"] for item in definitions
            }
            assert {"tool_search", "tool_describe", "tool_call"} <= visible_names
            assert not set(TOOL_NAMES).intersection(visible_names)

            for name in ("kite_calendar_read", "kite_gmail_search"):
                assert resolve_pre_tool_block(
                    "tool_describe",
                    {"name": name},
                    session_id="kite-session",
                    turn_id="kite-turn",
                ) is None
                described = json.loads(model_tools.handle_function_call(
                    "tool_describe",
                    {"name": name},
                    session_id="kite-session",
                    turn_id="kite-turn",
                    enabled_toolsets=[PRIVATE_READ_TOOLSET],
                    skip_pre_tool_call_hook=True,
                ))
                assert described["name"] == name
                assert described["parameters"] == TOOL_SCHEMAS[name]["parameters"]

            calls = (
                (
                    "kite_calendar_read",
                    {
                        "account": "personal",
                        "start": "2026-08-08T00:00:00+01:00",
                        "end": "2026-08-09T00:00:00+01:00",
                        "max_results": 5,
                    },
                ),
                (
                    "kite_gmail_search",
                    {
                        "account": "personal",
                        "query": "synthetic",
                        "max_results": 2,
                    },
                ),
            )
            for name, nested_args in calls:
                broker_args = {"name": name, "arguments": nested_args}
                model_call = SimpleNamespace(
                    id=f"call-{name}",
                    function=SimpleNamespace(
                        name="tool_call", arguments=json.dumps(broker_args)
                    ),
                )
                agent = SimpleNamespace(
                    enabled_toolsets=[PRIVATE_READ_TOOLSET],
                    disabled_toolsets=None,
                    valid_tool_names=visible_names,
                )
                planned = plan_tool_batch(agent, [model_call]).calls[0]
                assert planned.original_name == "tool_call"
                assert planned.effective_name == name
                assert planned.args == nested_args
                assert planned.scope_block is None
                assert resolve_pre_tool_block(
                    planned.effective_name,
                    planned.args,
                    session_id="kite-session",
                    turn_id="kite-turn",
                ) is None
                result = json.loads(model_tools.handle_function_call(
                    planned.effective_name,
                    planned.args,
                    session_id="kite-session",
                    turn_id="kite-turn",
                    enabled_toolsets=[PRIVATE_READ_TOOLSET],
                    skip_pre_tool_call_hook=True,
                ))
                assert result["status"] == "ok"

            assert len(calendar.calls) == 1
            assert len(gmail.calls) == 1

            mutated = {
                "account": "personal",
                "query": "synthetic",
                "max_results": 3,
            }
            assert resolve_pre_tool_block(
                "kite_gmail_search",
                {**mutated, "max_results": 2},
                session_id="kite-session",
                turn_id="kite-turn",
            ) is None
            blocked = json.loads(model_tools.handle_function_call(
                "kite_gmail_search",
                mutated,
                session_id="kite-session",
                turn_id="kite-turn",
                enabled_toolsets=[PRIVATE_READ_TOOLSET],
                skip_pre_tool_call_hook=True,
            ))
            assert "blocked" in blocked["error"].lower()
            assert len(gmail.calls) == 1

            assert resolve_pre_tool_block(
                "tool_describe",
                {"name": "read_file"},
                session_id="kite-session",
                turn_id="kite-turn",
            ) is not None
            assert resolve_pre_tool_block(
                "read_file",
                {},
                session_id="kite-session",
                turn_id="kite-turn",
            ) is not None
        finally:
            for name in TOOL_NAMES:
                registry.deregister(name)

    _bound_turn(
        tmp_path,
        {"gmail": gmail, "calendar": calendar},
        check,
    )


def test_read_argument_change_denies_before_backend(tmp_path):
    backend = RecordingBackend({"search": []})

    def check(kite):
        original = {"account": "personal", "query": "Mauritius", "max_results": 5}
        changed = {**original, "max_results": 6}
        assert (
            kite.pre_tool_call(
                "kite_gmail_search",
                original,
                session_id="kite-session",
                turn_id="kite-turn",
            )
            is None
        )
        denied = kite.pre_tool_dispatch(
            "kite_gmail_search",
            changed,
            session_id="kite-session",
            turn_id="kite-turn",
        )
        assert denied["action"] == "block"
        assert backend.calls == []

    _bound_turn(tmp_path, {"gmail": backend}, check)


def test_a_date_argument_is_read_the_way_it_is_written(tmp_path):
    """"after must be an ISO date" said what was wrong and not what to write.

    The forms it refused are the ones anyone writing a mail query reaches for
    first -- Gmail's own 2026/08/01, or "30d" for the last month -- and every
    one of them names a window unambiguously. The retry after a refusal is a
    guess, and each guess costs a round trip that the question may not survive.

    The old regex also let 2026-13-45 through to the source, where it matched
    nothing and looked like an absence of mail.
    """
    gmail = RecordingBackend({"search": []})
    calendar = RecordingBackend({"list": []})

    def check(kite):
        def search(**extra):
            _invoke(kite, "kite_gmail_search", {
                "account": "personal", "query": "Ibiza", "max_results": 5, **extra,
            })
            return gmail.calls[-1][1]["query"]

        assert search(after="2026-08-01").endswith("after:2026/08/01")
        assert search(after="2026/08/01").endswith("after:2026/08/01")
        assert search(before="2026.08.01").endswith("before:2026/08/01")

        today = datetime.now(timezone.utc).date()
        assert search(after="7d").endswith(
            (today - timedelta(days=7)).strftime(" after:%Y/%m/%d")
        )
        assert search(after="3w").endswith(
            (today - timedelta(days=21)).strftime(" after:%Y/%m/%d")
        )
        assert search(before="today").endswith(today.strftime(" before:%Y/%m/%d"))

        # A day that does not exist is caught here rather than becoming a
        # search nothing can match.
        failed = _invoke(kite, "kite_gmail_search", {
            "account": "personal", "query": "Ibiza",
            "max_results": 5, "after": "2026-13-45",
        })
        assert failed["status"] == "error"
        assert failed["error"]["code"] == "invalid_arguments"
        # And the refusal says what to write instead.
        assert "2026-08-01" in failed["error"]["message"]
        assert "7d" in failed["error"]["message"]

        # The same forms open a calendar window. The schema used to require ten
        # characters, which ruled out the short ones before the reader saw them.
        _invoke(kite, "kite_calendar_read", {
            "account": "personal", "start": "30d", "end": "today", "max_results": 5,
        })
        window = calendar.calls[-1][1]
        assert window["start"].startswith(
            (today - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00")
        )
        assert window["end"].startswith(today.strftime("%Y-%m-%dT23:59:59"))

        # A day is a window. The backend wants a moment and answers Bad
        # Request to a bare date -- which arrives as "source command failed"
        # and reads as the calendar being down.
        _invoke(kite, "kite_calendar_read", {
            "account": "personal", "start": "2026-08-01", "end": "2026-08-31",
            "max_results": 5,
        })
        window = calendar.calls[-1][1]
        assert window["start"].startswith("2026-08-01T00:00:00")
        assert window["end"].startswith("2026-08-31T23:59:59")

        # And so one day at each end is one whole day -- what "what's on
        # today" means, and what the window check used to reject as empty.
        _invoke(kite, "kite_calendar_read", {
            "account": "personal", "start": "today", "end": "today",
            "max_results": 5,
        })
        window = calendar.calls[-1][1]
        assert window["start"].startswith(today.strftime("%Y-%m-%dT00:00:00"))
        assert window["end"].startswith(today.strftime("%Y-%m-%dT23:59:59"))

        # A bare span reaches back, which is what a mail search means by it --
        # but "the next month" is the ordinary calendar question and has to be
        # sayable. The sign is how it is said.
        _invoke(kite, "kite_calendar_read", {
            "account": "personal", "start": "today", "end": "+30d",
            "max_results": 5,
        })
        window = calendar.calls[-1][1]
        assert window["start"].startswith(today.strftime("%Y-%m-%dT00:00:00"))
        assert window["end"].startswith(
            (today + timedelta(days=30)).strftime("%Y-%m-%dT23:59:59")
        )

        # And asking for it the other way says how to say it, rather than
        # reporting an empty window and leaving the model to guess.
        backwards = _invoke(kite, "kite_calendar_read", {
            "account": "personal", "start": "today", "end": "30d",
            "max_results": 5,
        })
        assert backwards["status"] == "error"
        assert "+30d" in backwards["error"]["message"]

        # An hour is still an hour: a full timestamp is not rounded to the day.
        _invoke(kite, "kite_calendar_read", {
            "account": "personal",
            "start": "2026-08-01T09:00:00Z",
            "end": "2026-08-01T17:00:00Z",
            "max_results": 5,
        })
        assert calendar.calls[-1][1]["start"] == "2026-08-01T09:00:00Z"

    _bound_turn(tmp_path, {"gmail": gmail, "calendar": calendar}, check)


def test_a_requested_result_cap_bounds_the_read_instead_of_failing_it(tmp_path):
    """max_results is how many are wanted, not how many there had better be.

    Three readers treated a source that overshot the cap as a malformed read
    and returned nothing. The caller had asked for five; five were available;
    the answer was an error.
    """
    def check(kite):
        mail = _invoke(kite, "kite_gmail_search", {
            "account": "personal", "query": "Ibiza", "max_results": 2,
        })["data"]
        assert [item["id"] for item in mail] == ["message-1", "message-2"]

        events = _invoke(kite, "kite_calendar_read", {
            "account": "personal",
            "start": "2026-08-01",
            "end": "2026-08-31",
            "max_results": 1,
        })["data"]
        assert [event["summary"] for event in events] == ["Flight"]

        messages = _invoke(kite, "kite_whatsapp_archive_read", {
            "operation": "search", "query": "Ibiza",
            "max_results": 2, "since": "30d",
        })["data"]
        assert [item["message_id"] for item in messages] == ["m-1", "m-2"]

    _bound_turn(
        tmp_path,
        {
            "gmail": RecordingBackend({"search": [
                {"id": f"message-{n}"} for n in range(1, 6)
            ]}),
            "calendar": RecordingBackend({"list": [
                {"summary": "Flight", "start": "2026-08-02", "end": "2026-08-03"},
                {"summary": "Hotel", "start": "2026-08-03", "end": "2026-08-09"},
            ]}),
            "whatsapp": RecordingBackend({"search": [
                {"message_id": f"m-{n}"} for n in range(1, 6)
            ]}),
        },
        check,
    )


def _pdf_with_text(text: str) -> bytes:
    """A minimal but structurally valid PDF: pdftotext needs a real xref."""
    body = f"BT /F1 12 Tf 20 700 Td ({text}) Tj ET".encode("latin-1")
    objs = [
        b"<</Type/Catalog/Pages 2 0 R>>",
        b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
        b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]"
        b"/Resources<</Font<</F1<</Type/Font/Subtype/Type1"
        b"/BaseFont/Helvetica>>>>>>/Contents 4 0 R>>",
        b"<</Length " + str(len(body)).encode("ascii")
        + b">>\nstream\n" + body + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for n, obj in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{n} 0 obj".encode("ascii") + obj + b"endobj\n"
    xref = len(out)
    out += b"xref\n0 " + str(len(objs) + 1).encode("ascii")
    out += b"\n0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode("ascii")
    out += (b"trailer<</Size " + str(len(objs) + 1).encode("ascii")
            + b"/Root 1 0 R>>\nstartxref\n" + str(xref).encode("ascii")
            + b"\n%%EOF\n")
    return bytes(out)


def test_a_pdf_attachment_is_read_not_returned_empty(tmp_path):
    """"Text extraction returned empty", live, for a PDF this module reads.

    The source command decodes only genuinely textual formats and returns ""
    for everything else, and the read path passed that through -- so every PDF
    attachment read as empty while the same bytes staged for release extracted
    fine. The engagement letter was the live case: retrieved, authorised, and
    reported unreadable.
    """
    import base64 as _b64

    pdf = _pdf_with_text("Engagement letter: Villa purchase at 3.2m EUR")
    gmail = RecordingBackend({
        "search": [{"id": "message-1", "subject": "engagement letter"}],
        "get": {
            "id": "message-1",
            "body": "engagement letter attached",
            "attachments": [
                {"attachment_id": "attachment-1", "filename": "EL MS 07 08 2026.pdf"}
            ],
        },
        "attachment_extract": {
            "filename": "EL MS 07 08 2026.pdf",
            "mime_type": "application/pdf",
            "size_bytes": len(pdf),
            "text": "",
            "artifact_base64": _b64.b64encode(pdf).decode("ascii"),
        },
    })

    def check(kite):
        _invoke(kite, "kite_gmail_search",
                {"account": "personal", "query": "engagement", "max_results": 3})
        _invoke(kite, "kite_gmail_get",
                {"account": "personal", "message_id": "message-1"})
        result = _invoke(kite, "kite_gmail_attachment_extract", {
            "account": "personal", "message_id": "message-1",
            "attachment_id": "attachment-1",
        })
        assert result["status"] == "ok", result
        assert "Villa purchase at 3.2m EUR" in result["data"]["text"]
        # The binary itself never reaches the model.
        assert "artifact_base64" not in result["data"]

    _bound_turn(tmp_path, {"gmail": gmail}, check)


def test_an_attachment_larger_than_the_answer_is_still_readable(tmp_path):
    """The answer allowance is not a file-size limit.

    A read returns the bounded extraction, never the bytes -- but the read
    path capped the attachment's size at output_bytes while the release path
    allowed 8MB, so a large scan was releasable and unreadable at once.
    """
    import base64 as _b64

    pdf = _pdf_with_text("Large but perfectly readable")
    padded_size = 300_000  # past output_bytes, well under the extraction cap
    gmail = RecordingBackend({
        "search": [{"id": "message-1", "subject": "engagement letter"}],
        "get": {
            "id": "message-1",
            "body": "attached",
            "attachments": [
                {"attachment_id": "attachment-1", "filename": "big-scan.pdf"}
            ],
        },
        "attachment_extract": {
            "filename": "big-scan.pdf",
            "mime_type": "application/pdf",
            "size_bytes": padded_size,
            "text": "",
            "artifact_base64": _b64.b64encode(pdf).decode("ascii"),
        },
    })

    def check(kite):
        _invoke(kite, "kite_gmail_search",
                {"account": "personal", "query": "engagement", "max_results": 3})
        _invoke(kite, "kite_gmail_get",
                {"account": "personal", "message_id": "message-1"})
        result = _invoke(kite, "kite_gmail_attachment_extract", {
            "account": "personal", "message_id": "message-1",
            "attachment_id": "attachment-1",
        })
        assert result["status"] == "ok", result
        assert "perfectly readable" in result["data"]["text"]

    _bound_turn(tmp_path, {"gmail": gmail}, check)


def test_an_unextractable_attachment_still_reads_as_empty_not_an_error(tmp_path):
    """Failing to extract must not be worse than the old behaviour."""
    gmail = RecordingBackend({
        "search": [{"id": "message-1", "subject": "engagement letter"}],
        "get": {
            "id": "message-1",
            "body": "attached",
            "attachments": [
                {"attachment_id": "attachment-1", "filename": "corrupt.pdf"}
            ],
        },
        "attachment_extract": {
            "filename": "corrupt.pdf",
            "mime_type": "application/pdf",
            "size_bytes": 40,
            "text": "",
            "artifact_base64": "not-valid-base64!!!",
        },
    })

    def check(kite):
        _invoke(kite, "kite_gmail_search",
                {"account": "personal", "query": "engagement", "max_results": 3})
        _invoke(kite, "kite_gmail_get",
                {"account": "personal", "message_id": "message-1"})
        result = _invoke(kite, "kite_gmail_attachment_extract", {
            "account": "personal", "message_id": "message-1",
            "attachment_id": "attachment-1",
        })
        assert result["status"] == "ok", result
        assert result["data"]["text"] == ""

    _bound_turn(tmp_path, {"gmail": gmail}, check)


def test_gmail_accounts_and_exact_id_chain(tmp_path):
    gmail = RecordingBackend({
        "search": [{"id": "message-1", "subject": "Synthetic trip"}],
        "get": {
            "id": "message-1",
            "body": "synthetic permitted body",
            "attachments": [{"attachment_id": "attachment-1", "filename": "trip.pdf"}],
        },
        "attachment_extract": {
            "filename": "trip.pdf",
            "mime_type": "application/pdf",
            "size_bytes": 120,
            "text": "synthetic extracted itinerary",
        },
    })

    def check(kite):
        search = _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "Mauritius", "max_results": 5},
        )
        assert search["status"] == "ok"
        message = _invoke(
            kite,
            "kite_gmail_get",
            {"account": "personal", "message_id": "message-1"},
        )
        assert message["status"] == "ok"
        attachment = _invoke(
            kite,
            "kite_gmail_attachment_extract",
            {
                "account": "personal",
                "message_id": "message-1",
                "attachment_id": "attachment-1",
            },
        )
        assert attachment["data"]["text"] == "synthetic extracted itinerary"
        denied = kite.pre_tool_call(
            "kite_gmail_get",
            {"account": "personal", "message_id": "not-returned"},
            session_id="kite-session",
            turn_id="kite-turn",
        )
        assert denied["action"] == "block"

    _bound_turn(tmp_path, {"gmail": gmail}, check)
    assert gmail.calls[0][1]["account_identity"] == PERSONAL_GMAIL
    assert (
        "work"
        not in TOOL_SCHEMAS["kite_gmail_search"]["parameters"]["properties"]["account"][
            "enum"
        ]
    )
    assert not any(
        word in TOOL_NAMES
        for word in ("gmail_send", "gmail_reply", "gmail_draft", "gmail_modify")
    )


def test_gmail_kite_identity_and_unsafe_attachment_denied(tmp_path):
    gmail = RecordingBackend({
        "search": [{"id": "m2"}],
        "get": {"id": "m2", "attachments": [{"attachmentId": "a2"}]},
        "attachment_extract": {
            "filename": "macro.docm",
            "mime_type": "application/vnd.ms-word.document.macroEnabled.12",
            "size_bytes": 20,
            "text": "never execute",
        },
    })

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "kite", "query": "ops", "max_results": 2},
        )
        _invoke(kite, "kite_gmail_get", {"account": "kite", "message_id": "m2"})
        result = _invoke(
            kite,
            "kite_gmail_attachment_extract",
            {"account": "kite", "message_id": "m2", "attachment_id": "a2"},
        )
        assert result["error"]["code"] == "unsupported_content"

    _bound_turn(tmp_path, {"gmail": gmail}, check)
    assert gmail.calls[0][1]["account_identity"] == KITE_GMAIL


def test_gmail_config_cannot_alias_personal_to_work_account():
    with pytest.raises(ValueError, match="personal and Kite"):
        PrivateReadService({
            "enabled": True,
            "gmail": {
                "executable": "/synthetic/google-wrapper",
                "account_aliases": {"personal": "work", "kite": "kite"},
            },
        })


def test_work_calendar_is_deterministically_projected(tmp_path):
    calendar = RecordingBackend({
        "list": [
            {
                "id": "secret-event-id",
                "title": "Acquisition at Company",
                "summary": "Secret",
                "attendees": ["private@example.test"],
                "description": "confidential body",
                "location": "office",
                "htmlLink": "https://calendar.invalid/secret",
                "organizer": {"email": "boss@example.test"},
                "conferenceData": {"url": "https://meet.invalid"},
                "attachments": [{"title": "board.pdf"}],
                "constraints": ["Meet Secret Company directors"],
                "start": {"dateTime": "2026-08-08T09:00:00+01:00"},
                "end": {"dateTime": "2026-08-08T10:00:00+01:00"},
                "timeZone": "Europe/London",
            }
        ]
    })

    def check(kite):
        result = _invoke(
            kite,
            "kite_calendar_read",
            {
                "account": "work_free_busy",
                "start": "2026-08-08T00:00:00+01:00",
                "end": "2026-08-09T00:00:00+01:00",
                "max_results": 5,
            },
        )
        interval = result["data"][0]
        assert set(interval) == {"status", "start", "end", "timezone", "constraints"}
        assert interval["status"] == "busy"
        rendered = json.dumps(interval)
        assert not any(
            value in rendered
            for value in ("Company", "Secret", "boss", "secret-event-id", "board.pdf")
        )

    _bound_turn(tmp_path, {"calendar": calendar}, check)


def test_things_is_pinned_to_exact_personal_project(tmp_path):
    things = RecordingBackend({"snapshot": [{"uuid": "task-1", "title": "Synthetic"}]})

    def check(kite):
        result = _invoke(kite, "kite_things_read", {"operation": "snapshot"})
        assert result["status"] == "ok"

    _bound_turn(tmp_path, {"things": things}, check)
    assert things.calls == [
        (
            "snapshot",
            {
                "operation": "snapshot",
                "project_title": THINGS_PROJECT_TITLE,
                "project_uuid": THINGS_PROJECT_UUID,
            },
        )
    ]
    with pytest.raises(ValueError):
        PrivateReadService({
            "enabled": True,
            "things": {
                "client": THINGS_CLIENT,
                "endpoint": THINGS_ENDPOINT,
                "project_uuid": "another-list",
                "project_title": THINGS_PROJECT_TITLE,
            },
        })


def test_property_and_whatsapp_use_typed_read_operations(tmp_path):
    prop = RecordingBackend({
        "property": {"id": "synthetic", "publicUrl": "https://property.invalid/p/1"}
    })
    whatsapp = RecordingBackend({"search": [{"message_id": "synthetic-message"}]})

    def check(kite):
        property_result = _invoke(
            kite,
            "kite_property_read",
            {
                "operation": "property",
                "property_id": "123e4567-e89b-12d3-a456-426614174000",
            },
        )
        archive_result = _invoke(
            kite,
            "kite_whatsapp_archive_read",
            {"operation": "search", "query": "Mauritius", "max_results": 5},
        )
        assert property_result["status"] == archive_result["status"] == "ok"

    _bound_turn(tmp_path, {"property_intel": prop, "whatsapp": whatsapp}, check)
    assert prop.calls[0][0] == "property"
    assert whatsapp.calls[0][0] == "search"
    assert not any(
        "sql" in json.dumps(schema).lower() for schema in TOOL_SCHEMAS.values()
    )


def test_property_payload_preserves_unknown_nested_fields_and_sanitizes_once(
    monkeypatch,
):
    property_id = "123e4567-e89b-12d3-a456-426614174000"
    monkeypatch.setenv("PROPERTY_AUTH_TOKEN", "configured-connector-token")
    backend = RecordingBackend({
        "property": {
            "id": property_id,
            "futureField": {
                "heritageScore": 97,
                "history": [
                    {
                        "eventId": "ordinary-history-id-44",
                        "note": (
                            "Survey complete. Authorization: Bearer escaped-secret; "
                            "retain this note."
                        ),
                    }
                ],
            },
            "documents": [
                {
                    "documentId": "doc-ordinary-9",
                    "url": "https://property.example.test/documents/doc-ordinary-9",
                    "metadata": {"pages": 14, "mimeType": "application/pdf"},
                }
            ],
            "auditNote": (
                r'keep this context {\"authorization\":\"Bearer serialized-secret\",'
                r'\"ordinary\":\"preserved\"}'
            ),
            "debugMessage": "prefix configured-connector-token suffix",
            "PROPERTY_AUTH_TOKEN": "configured-connector-token",
            "connector": {
                "headers": {"Authorization": "Bearer nested-secret"},
                "environment": {"PROPERTY_TOKEN": "environment-secret"},
                "auth": {"password": "password-secret"},
            },
            "refresh\u005ftoken": "escaped-key-secret",
            "privateKey": "-----BEGIN PRIVATE KEY----- secret material",
        }
    })
    service = PrivateReadService(
        {
            "enabled": True,
            "output_bytes": 65_536,
            "property_intel": {
                "base_url": "https://property.example.test",
                "auth_env": "PROPERTY_AUTH_TOKEN",
            },
        },
        backends={"property_intel": backend},
    )

    result = json.loads(service.execute(
        "kite_property_read",
        {"operation": "property", "property_id": property_id},
    ))

    assert result["status"] == "ok"
    data = result["data"]
    assert data["id"] == property_id
    assert data["futureField"]["heritageScore"] == 97
    assert data["futureField"]["history"][0]["eventId"] == "ordinary-history-id-44"
    assert data["documents"][0]["metadata"] == {
        "mimeType": "application/pdf",
        "pages": 14,
    }
    assert data["documents"][0]["url"].endswith("/doc-ordinary-9")
    assert "retain this note" in data["futureField"]["history"][0]["note"]
    rendered = json.dumps(data)
    for secret in (
        "escaped-secret",
        "nested-secret",
        "environment-secret",
        "password-secret",
        "escaped-key-secret",
        "PRIVATE KEY",
        "PROPERTY_TOKEN",
        "Authorization",
        "serialized-secret",
        "configured-connector-token",
    ):
        assert secret not in rendered


def test_property_payload_fails_closed_on_deep_or_oversized_data():
    property_id = "123e4567-e89b-12d3-a456-426614174000"
    deep: object = "leaf"
    for _ in range(20):
        deep = {"ordinary": deep}
    deep_service = PrivateReadService(
        {"enabled": True, "output_bytes": 65_536},
        backends={"property_intel": RecordingBackend({"property": deep})},
    )
    deep_result = json.loads(deep_service.execute(
        "kite_property_read",
        {"operation": "property", "property_id": property_id},
    ))
    assert deep_result["status"] == "error"
    assert deep_result["error"]["code"] == "depth_exceeded"
    assert deep_result["complete"] is False

    oversized_service = PrivateReadService(
        {"enabled": True, "output_bytes": 4096},
        backends={
            "property_intel": RecordingBackend({
                "property": {"futureOrdinaryField": "x" * 5000}
            })
        },
    )
    oversized_result = json.loads(oversized_service.execute(
        "kite_property_read",
        {"operation": "property", "property_id": property_id},
    ))
    assert oversized_result["status"] == "error"
    assert oversized_result["error"]["code"] == "cap_exceeded"
    assert oversized_result["complete"] is False


def test_property_mode_releases_arbitrary_sanitized_facts_as_bounded_prose(tmp_path):
    property_id = "123e4567-e89b-12d3-a456-426614174000"
    prop = RecordingBackend({
        "property": {
            "id": property_id,
            "futureField": {"heritageScore": 97},
        }
    })

    def check(kite):
        _invoke(
            kite,
            "kite_property_read",
            {"operation": "property", "property_id": property_id},
        )
        answer = (
            f"- Property ID: {property_id}\n"
            "- client_id: ordinary-buyer-record-7\n"
            "- The future heritage score is 97.\n"
            "- Contact: property-agent@example.test\n"
            "- Portal link: https://property.example.test/properties/record-44"
        )
        envelope_text = kite.transform_llm_output(
            response_text=answer, session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert envelope["denied"] is False
        assert envelope["answer"] == answer

    _bound_turn(tmp_path, {"property_intel": prop}, check)


@pytest.mark.parametrize(
    "answer",
    [
        '{"id":"123e4567-e89b-12d3-a456-426614174000","futureField":97}',
        "```json\n[{\"id\":\"record-1\"}]\n```",
        "Authorization: Bearer output-secret",
    ],
)
def test_property_mode_denies_container_dumps_and_credentials(tmp_path, answer):
    prop = RecordingBackend({"property": {"futureField": 97}})

    def check(kite):
        _invoke(
            kite,
            "kite_property_read",
            {
                "operation": "property",
                "property_id": "123e4567-e89b-12d3-a456-426614174000",
            },
        )
        envelope_text = kite.transform_llm_output(
            response_text=answer, session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert envelope["denied"] is True
        assert answer not in envelope_text

    _bound_turn(tmp_path, {"property_intel": prop}, check)


def test_the_turn_that_could_not_find_nachos_letter(tmp_path):
    """Lucy asked for the lawyer's latest letter. Four readers refused at once.

    2026-08-13 19:38, source_failures: gmail:cap_exceeded,
    property:cap_exceeded, property:invalid_arguments, personal:path_denied.
    Three were the reader's own caps and shapes, not policy:

    - a Gmail search that returned a lot of mail was refused outright, because
      what a source command prints was measured against the answer allowance;
    - research_notes returns whole markdown bodies -- five notes is 213,728
      characters -- when the operation exists to tell notes apart;
    - research_notes would not take the query that narrows the list, so the
      model asked twice and was refused twice.
    """
    notes = [
        {"id": f"123e4567-e89b-12d3-a456-42661417400{n}", "kind": "research",
         "status": "open", "author": "Hermes", "entryCount": 4,
         "bodyMd": "# Position\n\n" + ("nacho says the target holds. " * 400)}
        for n in range(4)
    ]

    def check(kite):
        # An index, not four whole notes.
        listed = _invoke(kite, "kite_property_read", {
            "operation": "research_notes",
            "property_id": "123e4567-e89b-12d3-a456-426614174000",
            "max_results": 10,
        })
        assert listed["status"] == "ok", listed
        rows = listed["data"]["matches"] if isinstance(listed["data"], dict) else listed["data"]
        assert len(rows) == 4
        assert "bodyMd" not in rows[0]
        assert rows[0]["bodyExcerpt"].startswith("# Position")
        assert len(json.dumps(listed["data"])) < 6000

        # And it narrows the same way the property list does.
        narrowed = _invoke(kite, "kite_property_read", {
            "operation": "research_notes",
            "property_id": "123e4567-e89b-12d3-a456-426614174000",
            "max_results": 10, "query": "nacho",
        })
        assert narrowed["status"] == "ok", narrowed

    _bound_turn(
        tmp_path,
        {"property_intel": RecordingBackend({"research_notes": notes})},
        check,
    )


def test_a_guessed_file_path_is_told_what_to_do_instead(tmp_path):
    """"path is unavailable or escapes its configured root" -- so, what now?

    A guessed relative_path is the ordinary way to arrive here and the answer
    is always the same: search first, read what the search returned.
    """
    root = tmp_path / "personal"
    root.mkdir()
    (root / "real.md").write_text("here", encoding="utf-8")
    service = PrivateReadService({
        "enabled": True, "output_bytes": 65536,
        "files": {"roots": [{"name": "obsidian", "path": str(root)}],
                  "allowed_bases": [str(tmp_path)]},
    })
    failed = json.loads(service.execute("kite_personal_files_read", {
        "operation": "read", "root": "obsidian",
        "relative_path": "Letters/nacho-latest.pdf",
    }))
    assert failed["status"] == "error"
    message = failed["error"]["message"]
    assert "Search this root first" in message
    assert "guessing" in message


def test_a_purchase_transaction_answers_without_its_whole_history(tmp_path):
    """Lucy asked what the house being bought was, and got nothing.

    A transaction carries its whole history: for the live one that is 59
    documents, 100 audit events and 23 tasks -- 140,321 characters, past the
    100,000 the host holds inline. It was truncated mid-JSON and the model
    reported the result incomplete rather than guess. The answer she wanted --
    price, stage, the seller's possession summary -- is about 1,200 characters
    of it, near the top.
    """
    payload = {
        "transaction": {
            "agreedPrice": "3200000.00", "currency": "EUR",
            "stage": "due_diligence", "propertyTitle": "Villa Lena",
            "sellerPossessionSummary": "Seller confirmed the October move-out.",
        },
        "parties": [{"name": f"party-{n}", "role": "buyer"} for n in range(3)],
        "documents": [
            {"id": f"doc-{n}", "documentType": "planning", "blocking": True,
             "notes": "x" * 900}
            for n in range(40)
        ],
        "events": [
            {"id": f"ev-{n}", "createdAt": "2026-08-10", "actor": "Hermes agent",
             "action": "update-item", "entityType": "decision",
             "detail": {"changedFields": ["title"], "padding": "y" * 300}}
            for n in range(60)
        ],
        "readiness": {
            "arras": {"ready": False, "blockers": [
                {"title": f"blocker-{n}", "severity": "high", "gate": True,
                 "reason": "Task is in progress.", "padding": "z" * 400}
                for n in range(20)
            ]},
        },
    }

    def check(kite):
        result = _invoke(kite, "kite_property_read", {
            "operation": "transaction",
            "property_id": "123e4567-e89b-12d3-a456-426614174000",
        })
        assert result["status"] == "ok", result
        data = result["data"]

        # The answer is whole.
        assert data["transaction"]["agreedPrice"] == "3200000.00"
        assert "October move-out" in data["transaction"]["sellerPossessionSummary"]
        # Small collections are untouched.
        assert len(data["parties"]) == 3

        # The long ones are bounded, and say by how much.
        assert len(data["documents"]) == 12
        assert len(data["events"]) == 12
        assert data["omitted_for_size"]["counts"] == {"documents": 28, "events": 48}
        assert "max_results" in data["omitted_for_size"]["note"]

        # A document keeps what identifies it and loses the essay.
        assert data["documents"][0]["documentType"] == "planning"
        assert "notes" not in data["documents"][0]
        # The audit trail keeps only what identifies an entry.
        assert set(data["events"][0]) == {
            "createdAt", "actor", "action", "entityType"
        }
        # Blockers are bounded and projected too.
        blockers = data["readiness"]["arras"]["blockers"]
        assert len(blockers) == 12
        assert "padding" not in blockers[0]
        assert data["readiness"]["arras"]["ready"] is False

        assert len(json.dumps(data)) < 20_000

        # And more can be asked for.
        wider = _invoke(kite, "kite_property_read", {
            "operation": "transaction",
            "property_id": "123e4567-e89b-12d3-a456-426614174000",
            "max_results": 30,
        })["data"]
        assert len(wider["documents"]) == 30
        assert wider["omitted_for_size"]["counts"] == {"documents": 10, "events": 30}

    _bound_turn(
        tmp_path,
        {"property_intel": RecordingBackend({"transaction": payload})},
        check,
    )


def test_a_property_list_is_an_index_not_the_whole_file(tmp_path):
    """"What's the latest on the property purchase?" could not be answered.

    Every call failed: an empty result, then "result exceeded the requested
    cap", then "response exceeded its cap". The list returned whole records --
    description, amenities, legal text, geometry, 4KB each and 170KB for
    thirty-nine of them -- and max_results, asked for five, refused the call
    rather than returning five.

    A list is for telling properties apart and finding the one that matters.
    Depth is what the detail operations are for.
    """
    fat = [
        {
            "id": f"123e4567-e89b-12d3-a456-42661417400{n}",
            "canonicalTitle": f"Villa {n}",
            "status": "offer_candidate" if n == 0 else "watchlist",
            "displayArea": "Cala Llenya",
            "priceAmount": "3400000",
            "priceCurrency": "EUR",
            "nextAction": "Confirm the timetable",
            "description": "x" * 4000,
            "amenities": ["y"] * 200,
            "legal": {"notes": "z" * 2000},
            "geom": {"coordinates": [[1.0, 2.0]] * 200},
        }
        for n in range(3)
    ]

    def check(kite):
        result = _invoke(
            kite, "kite_property_read", {"operation": "list", "max_results": 2}
        )
        data = result["data"]

        # Bounded, not refused, and honest about what it left out.
        assert data["truncated"] is True
        assert data["total"] == 3
        assert len(data["matches"]) == 2
        assert "3 matched; showing 2" in data["note"]

        # An index: what identifies and triages a property, and nothing whose
        # only job is to be long.
        row = data["matches"][0]
        assert row["canonicalTitle"] == "Villa 0"
        assert row["status"] == "offer_candidate"
        assert row["nextAction"] == "Confirm the timetable"
        for fat_field in ("description", "amenities", "legal", "geom"):
            assert fat_field not in row, fat_field
        assert len(json.dumps(data)) < 2000

        # A query still narrows, and the one that matters is findable.
        found = _invoke(kite, "kite_property_read", {
            "operation": "list", "query": "offer_candidate", "max_results": 10,
        })["data"]
        assert found["total"] == 1
        assert found["truncated"] is False
        assert found["matches"][0]["canonicalTitle"] == "Villa 0"

        # Depth is still available, by id, in full.
        detail = _invoke(kite, "kite_property_read", {
            "operation": "property",
            "property_id": "123e4567-e89b-12d3-a456-426614174000",
        })["data"]
        assert detail["description"] == "x" * 4000

    _bound_turn(
        tmp_path,
        {"property_intel": RecordingBackend({
            "list": fat,
            "property": fat[0],
        })},
        check,
    )


def test_a_heuristic_match_costs_the_span_not_the_answer(tmp_path):
    """James's calibration: this is his wife, not an adversary.

    The identifier heuristics refused dozens of answers in two days and never
    caught one real disclosure; each refusal read as "you may not know this"
    about something she was entitled to. So a heuristic match now costs
    exactly the matched span -- [redacted] -- and the answer survives. Hard
    evidence is different: a configured secret or credential-shaped content
    still withholds the whole answer, because there is nothing partial about
    a password.
    """
    gmail = RecordingBackend({"search": [{"id": "message-1", "subject": "trip"}]})

    def answer_with(kite, text):
        _invoke(kite, "kite_gmail_search",
                {"account": "personal", "query": "trip", "max_results": 2})
        return json.loads(
            kite.transform_llm_output(
                response_text=text, session_id="kite-session"
            ).split(RESPONSE_PREFIX, 1)[1]
        )

    def run(text):
        verdicts = {}
        _bound_turn(tmp_path, {"gmail": gmail},
                    lambda kite: verdicts.update(v=answer_with(kite, text)))
        return verdicts["v"]

    # A UUID-shaped span is blanked; everything she asked for still arrives.
    mixed = run(
        "The villa holding record is 123e4567-e89b-12d3-a456-426614174000 "
        "and completion is set for 8 October."
    )
    assert mixed["denied"] is False
    assert "completion is set for 8 October" in mixed["answer"]
    assert "123e4567" not in mixed["answer"]
    assert "[redacted]" in mixed["answer"]

    # A labelled identifier likewise.
    labelled = run("Booking reference: 987654321 confirmed for the family.")
    assert labelled["denied"] is False
    assert "confirmed for the family" in labelled["answer"]

    # Hard evidence still withholds everything.
    hard = run("The wifi admin password=synthetic-credential-value if you need it.")
    assert hard["denied"] is True
    assert hard["answer"] == ""


def test_reading_something_alongside_property_does_not_withhold_the_answer(tmp_path):
    """Lucy asked what the house being bought was and the answer was withheld.

    The expanded Property prose mode is for a turn whose only source was
    Property Intel. Kite read the transaction and then checked one other
    source, which turned the mode off -- and provenance without the mode
    refused the whole turn rather than checking it more carefully.

    Both gates apply now. The Property gate bounds the form its data would be
    dumped in; the ordinary gate catches the identifiers the Property one
    deliberately does not inspect. Passing both is stricter than either, so
    this releases nothing the authorized path would not.
    """
    property_id = "123e4567-e89b-12d3-a456-426614174000"
    verdicts = {}

    def turn(label, text):
        def check(kite):
            _invoke(kite, "kite_property_read",
                    {"operation": "property", "property_id": property_id})
            _invoke(kite, "kite_whatsapp_archive_read",
                    {"operation": "search", "query": "villa", "max_results": 2})
            verdicts[label] = json.loads(
                kite.transform_llm_output(
                    response_text=text, session_id="kite-session"
                ).split(RESPONSE_PREFIX, 1)[1]
            )

        _bound_turn(
            tmp_path,
            {
                "property_intel": RecordingBackend({"property": {"id": property_id}}),
                "whatsapp": RecordingBackend({"search": [{"message": "ordinary"}]}),
            },
            check,
        )

    turn("prose", "The purchase is Villa Lena at 3.2m EUR, in due diligence. "
                  "The seller confirmed an 8 October move-out.")
    turn("identifier", f"Property ID: {property_id}")
    turn("table", "\n".join([
        "| field | value |", "| --- | --- |",
        "| price | 3200000 |", "| stage | due_diligence |",
    ]))

    # An ordinary prose answer, from two sources, is released.
    assert verdicts["prose"]["denied"] is False, verdicts["prose"]
    assert "Villa Lena" in verdicts["prose"]["answer"]
    # The ordinary gate still applies to the span: the identifier is redacted
    # and the answer survives, rather than the whole turn being withheld.
    assert verdicts["identifier"]["denied"] is False
    assert "123e4567" not in verdicts["identifier"]["answer"]
    assert "[redacted]" in verdicts["identifier"]["answer"]
    # And so does the Property form gate, which the ordinary one has no
    # opinion about: a table dump of its data is still refused.
    assert verdicts["table"]["denied"] is True


def test_property_mode_denies_over_limit_mixed_source_and_non_james(tmp_path):
    property_id = "123e4567-e89b-12d3-a456-426614174000"

    def over_limit(kite):
        _invoke(
            kite,
            "kite_property_read",
            {"operation": "property", "property_id": property_id},
        )
        answer = "Property fact. " * 500
        envelope = json.loads(
            kite.transform_llm_output(
                response_text=answer, session_id="kite-session"
            ).split(RESPONSE_PREFIX, 1)[1]
        )
        assert envelope["denied"] is True
        assert envelope["answer"] == ""

    _bound_turn(
        tmp_path,
        {"property_intel": RecordingBackend({"property": {"id": property_id}})},
        over_limit,
    )

    def mixed(kite):
        _invoke(
            kite,
            "kite_property_read",
            {"operation": "property", "property_id": property_id},
        )
        _invoke(
            kite,
            "kite_whatsapp_archive_read",
            {"operation": "search", "query": "property", "max_results": 2},
        )
        envelope = json.loads(
            kite.transform_llm_output(
                response_text=f"Property ID: {property_id}",
                session_id="kite-session",
            ).split(RESPONSE_PREFIX, 1)[1]
        )
        # The identifier is redacted rather than the answer withheld.
        assert envelope["denied"] is False
        assert property_id not in envelope["answer"]
        assert "[redacted]" in envelope["answer"]

    _bound_turn(
        tmp_path,
        {
            "property_intel": RecordingBackend({"property": {"id": property_id}}),
            "whatsapp": RecordingBackend({"search": [{"message": "ordinary"}]}),
        },
        mixed,
    )

    # A second principal holding the property capability gets the same
    # property answer he does. Gating the fuller mode on his name meant his
    # wife got the thin one for a purchase they are making together.
    outcomes = {}

    def record(principal):
        def check(kite):
            _invoke(
                kite,
                "kite_property_read",
                {"operation": "property", "property_id": property_id},
            )
            envelope = json.loads(
                kite.transform_llm_output(
                    response_text="The future heritage score is 97.",
                    session_id="kite-session",
                ).split(RESPONSE_PREFIX, 1)[1]
            )
            outcomes[principal] = envelope["denied"]

        return check

    for principal in ("james", "lucy"):
        _bound_turn(
            tmp_path,
            {"property_intel": RecordingBackend({"property": {"futureField": 97}})},
            record(principal),
            principal=principal,
        )
    assert outcomes["lucy"] == outcomes["james"], outcomes


def test_property_mode_denies_wrong_final_turn_binding(tmp_path):
    prop = RecordingBackend({"property": {"futureField": 97}})

    def check(kite):
        _invoke(
            kite,
            "kite_property_read",
            {
                "operation": "property",
                "property_id": "123e4567-e89b-12d3-a456-426614174000",
            },
        )
        envelope = json.loads(
            kite.transform_llm_output(
                response_text="The future heritage score is 97.",
                session_id="kite-session",
                turn_id="different-turn",
            ).split(RESPONSE_PREFIX, 1)[1]
        )
        assert envelope["denied"] is True
        assert envelope["answer"] == ""

    _bound_turn(tmp_path, {"property_intel": prop}, check)


def test_only_configured_property_public_links_may_preserve_uuid(tmp_path):
    config = _slice_b_config(tmp_path, mode="kite")
    config["juno_kite_trusted_principal"]["private_reads"]["property_intel"] = {
        "base_url": "http://127.0.0.1:3917",
        "public_base_url": "https://property.example.test",
    }
    runtime = TrustedPrincipalRuntime(config, active_profile="kite")
    identifier = "123e4567-e89b-12d3-a456-426614174000"

    assert (
        runtime._leak_reason(
            f"Property: https://property.example.test/properties/{identifier}",
            output=True,
        )
        == ""
    )
    assert (
        runtime._leak_reason(f"Internal record {identifier}", output=True)
        == "UUID-shaped private identifier"
    )


def test_whatsapp_real_boundary_uses_argv_without_shell(tmp_path):
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="[]", stderr="")

    service = PrivateReadService(
        {
            "enabled": True,
            "whatsapp": {
                "executable": "/usr/bin/node",
                "script": WHATSAPP_QUERY,
                "state_dir": str(tmp_path / "archive"),
            },
        },
        command_runner=runner,
    )
    result = json.loads(
        service.execute(
            "kite_whatsapp_archive_read",
            {
                "operation": "search",
                "name": "Synthetic Family",
                "query": "trip",
                "since": "2026-08-01",
                "max_results": 5,
            },
        )
    )
    assert result["status"] == "ok"
    argv, kwargs = calls[0]
    assert argv[:2] == ["/usr/bin/node", WHATSAPP_QUERY]
    assert kwargs["shell"] is False
    assert kwargs["env"]["WHATSAPP_READONLY_STATE_DIR"] == str(tmp_path / "archive")
    assert not {"--send", "--reply", "--react", "--mark-read"}.intersection(argv)


def test_every_candidate_producer_returns_the_transport_contract(tmp_path):
    """The new producer returned a dict and the tool layer refused it.

    "Tool handler returned unsupported result type: dict" -- so a document
    that locate had found, in a folder James named, came back to him as a
    malformed lookup. Every other branch serialises before returning and
    this one did not, which no test noticed because none of them checked
    the type the transport actually requires.
    """
    base = tmp_path / "docs"
    (base / "Elsewhere").mkdir(parents=True)
    (base / "Hermes Documents").mkdir(parents=True)
    (base / "Elsewhere" / "statement.pdf").write_bytes(b"%PDF-1.4 located")
    (base / "Hermes Documents" / "in-root.pdf").write_bytes(b"%PDF-1.4 in root")

    service = PrivateReadService({
        "enabled": True,
        "output_bytes": 262_144,
        "files": {
            "roots": [{"name": "documents", "path": str(base / "Hermes Documents")}],
            "allowed_bases": [str(base)],
        },
    })

    produced = service.resolve_document_candidate(
        "kite_personal_files_release_located",
        {"directory": str(base / "Elsewhere"), "file_name": "statement.pdf"},
    )
    result, internal = produced
    assert isinstance(result, str), (
        "the transport requires an encoded result, not a dict"
    )
    parsed = json.loads(result)
    assert parsed["status"] == "ok"
    assert parsed["data"]["outcome"] == "release_candidate"
    assert parsed["data"]["requires_owner_approval"] is True
    assert internal["requires_owner_approval"] is True
    assert internal["path"].name == "statement.pdf"

    # The in-root producer answers the same contract, which is the point.
    in_root, _internal = service.resolve_document_candidate(
        "kite_personal_files_read",
        {"operation": "read", "root": "documents", "relative_path": "in-root.pdf"},
    )
    assert isinstance(in_root, str)
    assert json.loads(in_root)["status"] == "ok"


def test_locate_says_where_a_document_is_without_being_able_to_open_it(tmp_path):
    """A document outside the three roots could not be found at all.

    A configured root is a standing grant -- everything beneath it is
    readable and releasable -- which is why there are only three. The cost
    was that a file sitting in plain view somewhere else got the honest but
    useless answer "I cannot find it". Locate separates the two: it reports
    names and whereabouts, and grants nothing. What it returns cannot be
    handed to a reader, because the readers key off (root, relative_path)
    and locate deliberately returns neither.
    """
    base = tmp_path / "docs"
    (base / "Hermes Documents").mkdir(parents=True)
    (base / "Elsewhere" / "Scans").mkdir(parents=True)
    (base / "Hermes Documents" / "alex passport.pdf").write_bytes(b"%PDF-1.4 in")
    (base / "Elsewhere" / "Scans" / "robin passport.pdf").write_bytes(b"%PDF-1.4 out")
    (base / "Elsewhere" / "id_rsa_private_key.pem").write_text("x", encoding="utf-8")
    (base / "Elsewhere" / "passport_helper.sh").write_text("echo", encoding="utf-8")
    (base / "Elsewhere" / ".hidden passport.pdf").write_bytes(b"%PDF-1.4 hidden")

    service = PrivateReadService({
        "enabled": True,
        "output_bytes": 262_144,
        "files": {
            "roots": [{"name": "documents", "path": str(base / "Hermes Documents")}],
            "allowed_bases": [str(base)],
        },
    })

    def locate(query, **extra):
        return json.loads(service.execute(
            "kite_personal_files_locate", {"query": query, **extra}
        ))

    found = locate("passport", max_results=10)["data"]
    by_name = {m["file_name"]: m for m in found["matches"]}
    assert set(by_name) == {"alex passport.pdf", "robin passport.pdf"}

    # The one inside a root is already releasable; the one outside is not,
    # and saying which is the entire point.
    assert by_name["alex passport.pdf"]["releasable_now"] is True
    assert by_name["alex passport.pdf"]["release_root"] == "documents"
    assert by_name["robin passport.pdf"]["releasable_now"] is False
    assert by_name["robin passport.pdf"]["release_root"] is None

    # Locations only: nothing here is content, and nothing here is a
    # relative_path that a reader would accept.
    for match in found["matches"]:
        assert set(match) == {
            "document_name", "file_name", "directory", "size_bytes",
            "modified", "release_root", "releasable_now",
        }
        assert "relative_path" not in match

    # A location is a disclosure too: key material stays invisible, as do
    # executables and dotfiles.
    assert locate("id_rsa", max_results=10)["data"]["matches"] == []
    assert locate("passport_helper", max_results=10)["data"]["matches"] == []
    assert all(
        not m["file_name"].startswith(".") for m in locate("hidden")["data"]["matches"]
    )

    # Bounded: a result cap truncates rather than walking everything.
    capped = locate("passport", max_results=1)["data"]
    assert len(capped["matches"]) == 1 and capped["truncated"] is True

    for malformed in ({}, {"query": "x" * 300}, {"query": "ok", "extra": 1}):
        assert json.loads(
            service.execute("kite_personal_files_locate", malformed)
        )["status"] == "error", malformed


def test_a_file_search_finds_a_document_the_way_it_is_asked_for(tmp_path):
    """Search matched the query as one literal substring of the path.

    Nobody names a document the way they ask for it. "holiday itinerary" found
    nothing in a folder holding Ibiza-Trip-Itinerary-2026.pdf, and on the turn
    where Lucy asked about the trip five searches in a row came back empty on a
    question the documents could answer.

    Words are matched separately and punctuation is not something the asker has
    to guess. Everything-in-the-name ranks first, everything-somewhere next, and
    a file matching only some of the words is still shown and labelled, because
    a half-remembered name is the ordinary case.
    """
    root = tmp_path / "personal"
    (root / "Travel").mkdir(parents=True)
    (root / "Travel" / "Ibiza-Trip-Itinerary-2026.pdf").write_bytes(b"%PDF-1.4 ")
    (root / "Travel" / "hotel-booking.md").write_text(
        "Confirmation for the holiday itinerary", encoding="utf-8"
    )
    (root / "insurance.md").write_text("Travel cover", encoding="utf-8")
    (root / "20.11.25_180-Strand-Report.pdf").write_bytes(b"%PDF-1.4 ")
    (root / "Passports-Renewal.pdf").write_bytes(b"%PDF-1.4 ")
    service = PrivateReadService({
        "enabled": True,
        "output_bytes": 65536,
        "files": {"roots": [{"name": "documents", "path": str(root)}],
                  "allowed_bases": [str(tmp_path)]},
    })

    def search(query, limit=10):
        return json.loads(service.execute("kite_personal_files_read", {
            "operation": "search", "root": "documents",
            "query": query, "max_results": limit,
        }))["data"]

    # Word order, case and punctuation do not decide whether it is found.
    hits = search("holiday itinerary")
    assert [item["relative_path"] for item in hits] == [
        "Travel/hotel-booking.md",       # every word, in the contents
        "Travel/Ibiza-Trip-Itinerary-2026.pdf",   # one word, in the name
    ]
    assert hits[0]["matched_on"] == "contents"
    assert hits[1]["matched_on"] == "partial"

    assert [item["relative_path"] for item in search("itinerary ibiza")] == [
        "Travel/Ibiza-Trip-Itinerary-2026.pdf",
        "Travel/hotel-booking.md",
    ]
    assert search("ibiza trip 2026")[0]["matched_on"] == "name"

    # A document whose name is punctuated one way, asked for another way. This
    # is not hypothetical: it is how the name was typed when it was asked for.
    named = search("20-11-25 180 Strand")
    assert named[0]["relative_path"] == "20.11.25_180-Strand-Report.pdf"
    assert named[0]["matched_on"] == "name"
    assert search("20/11/25_180 strand")[0]["matched_on"] == "name"

    # A word matches where a word starts, so a plural is not a different
    # document -- and the middle of an unrelated word is not a match at all.
    assert [item["relative_path"] for item in search("passport")] == [
        "Passports-Renewal.pdf"
    ]
    assert search("port") == []

    # More matches than asked for is a shortlist, not a failed read.
    limited = search("travel", limit=1)
    assert len(limited) == 1

    _ = search("Mauritius")
    assert search("Mauritius") == []


def test_a_long_note_is_partly_read_not_refused(tmp_path):
    """max_lines defaulted to 400, so a 401-line note was unreadable.

    It is how much was asked for, not how much there had better be. Refusing
    returned nothing at all from a file the answer was probably in -- and a
    long note is exactly where a long answer lives.
    """
    root = tmp_path / "personal"
    root.mkdir()
    note = root / "ibiza-purchase.md"
    note.write_text(
        "\n".join([f"line {n}" for n in range(600)] + ["completion is 8 October"]),
        encoding="utf-8",
    )
    service = PrivateReadService({
        "enabled": True,
        "output_bytes": 65536,
        "files": {"roots": [{"name": "obsidian", "path": str(root)}],
                  "allowed_bases": [str(tmp_path)]},
    })

    def read(**extra):
        return json.loads(service.execute("kite_personal_files_read", {
            "operation": "read", "root": "obsidian",
            "relative_path": "ibiza-purchase.md", **extra,
        }))

    # The default no longer refuses a file merely for being long.
    default = read()
    assert default["status"] == "ok", default
    assert default["data"]["truncated"] is True
    assert default["data"]["line_count"] == 400
    assert default["data"]["text"].startswith("line 0")

    # A smaller ask is honoured exactly, and still says it was cut.
    fewer = read(max_lines=10)
    assert fewer["data"]["line_count"] == 10
    assert fewer["data"]["truncated"] is True

    # And the tail is now reachable, which it was not: 400 lines was the
    # ceiling and there was no way to ask for line 401.
    first = read(max_lines=400)["data"]
    assert first["start_line"] == 1
    assert first["total_lines"] == 601
    assert first["truncated"] is True
    assert first["next_start_line"] == 401
    assert "completion is 8 October" not in first["text"]

    rest = read(max_lines=400, start_line=first["next_start_line"])["data"]
    assert rest["start_line"] == 401
    assert rest["truncated"] is False
    assert rest["next_start_line"] is None
    assert "completion is 8 October" in rest["text"]

    # A start past the end is an empty window, not an error.
    beyond = read(start_line=5000)["data"]
    assert beyond["line_count"] == 0
    assert beyond["truncated"] is False

    # A note larger than the answer allowance is still readable, because only
    # max_lines of it ever comes back. The same file as a PDF was always fine;
    # measuring text against the answer allowance was the leftover of the two
    # kinds of cap being one number.
    big = root / "long-research.md"
    big.write_text("\n".join(f"para {n} " + "w" * 300 for n in range(400)),
                   encoding="utf-8")
    assert big.stat().st_size > 65536
    spilled = json.loads(service.execute("kite_personal_files_read", {
        "operation": "read", "root": "obsidian",
        "relative_path": "long-research.md", "max_lines": 5,
    }))
    assert spilled["status"] == "ok", spilled
    assert spilled["data"]["line_count"] == 5
    assert spilled["data"]["truncated"] is True

    # A file that fits says so plainly.
    short = root / "short.md"
    short.write_text("one\ntwo\n", encoding="utf-8")
    fitted = json.loads(service.execute("kite_personal_files_read", {
        "operation": "read", "root": "obsidian", "relative_path": "short.md",
    }))
    assert fitted["data"]["truncated"] is False
    assert fitted["data"]["line_count"] == 2


def test_a_refused_argument_is_named(tmp_path):
    """"file search requires query and max_results" -- to a call passing both.

    What it objected to was max_lines: advertised on the same tool, for the
    other operation, and never named. A refusal that does not say which
    argument it refused costs a round trip to guess at, and the guess is often
    wrong twice.
    """
    root = tmp_path / "personal"
    root.mkdir()
    (root / "trip.md").write_text("Ibiza", encoding="utf-8")
    service = PrivateReadService({
        "enabled": True,
        "output_bytes": 4096,
        "files": {"roots": [{"name": "obsidian", "path": str(root)}],
                  "allowed_bases": [str(tmp_path)]},
        "property_intel": {"base_url": "https://example.invalid"},
    })

    def why(tool, args):
        result = json.loads(service.execute(tool, args))
        assert result["status"] == "error", result
        return result["error"]["message"]

    said = why("kite_personal_files_read", {
        "operation": "search", "root": "obsidian",
        "query": "Ibiza", "max_results": 5, "max_lines": 20,
    })
    assert "max_lines" in said
    assert "does not take" in said
    assert "query" not in said

    said = why("kite_personal_files_read", {"operation": "read", "root": "obsidian"})
    assert "needs relative_path" in said

    said = why("kite_property_read", {
        "operation": "list", "max_results": 5, "property_id": "nope",
    })
    assert "property_id" in said and "does not take" in said

    said = why("kite_things_read", {"operation": "search", "query": "nacho"})
    assert "needs max_results" in said

    # And a call that is right still gets through.
    ok = json.loads(service.execute("kite_personal_files_read", {
        "operation": "search", "root": "obsidian", "query": "Ibiza",
        "max_results": 5,
    }))
    assert ok["status"] == "ok"


def test_personal_file_containment_and_bounds(tmp_path):
    root = tmp_path / "personal"
    root.mkdir()
    (root / "trip.md").write_text("Synthetic Mauritius itinerary", encoding="utf-8")
    (root / ".hidden.md").write_text("hidden", encoding="utf-8")
    (root / "api_token.json").write_text("{}", encoding="utf-8")
    (root / "program.sh").write_text("echo no", encoding="utf-8")
    (root / "id_rsa.pem").write_text("synthetic key material", encoding="utf-8")
    # A format nobody anticipated is still a document: releasing a phone photo
    # while being unable to read or list it is how the allow-list failed.
    (root / "scan.heic").write_bytes(b"\x00\x00\x00\x18ftypheic")
    outside = tmp_path / "outside.md"
    outside.write_text("outside", encoding="utf-8")
    (root / "escape.md").symlink_to(outside)
    service = PrivateReadService({
        "enabled": True,
        "output_bytes": 4096,
        "files": {"roots": [{"name": "obsidian", "path": str(root)}],
                  "allowed_bases": [str(tmp_path)]},
    })
    found = json.loads(
        service.execute(
            "kite_personal_files_read",
            {
                "operation": "search",
                "root": "obsidian",
                "query": "Mauritius",
                "max_results": 5,
            },
        )
    )
    assert found["data"] == [
        {
            "relative_path": "trip.md",
            "root": "obsidian",
            "size_bytes": 29,
            "matched_on": "contents",
        }
    ]
    read = json.loads(
        service.execute(
            "kite_personal_files_read",
            {
                "operation": "read",
                "root": "obsidian",
                "relative_path": "trip.md",
                "max_lines": 10,
            },
        )
    )
    assert read["data"]["text"] == "Synthetic Mauritius itinerary"
    for relative in (
        "../outside.md",
        "/etc/passwd",
        "escape.md",
        ".hidden.md",
        "api_token.json",
        "program.sh",
        "id_rsa.pem",
    ):
        denied = json.loads(
            service.execute(
                "kite_personal_files_read",
                {
                    "operation": "read",
                    "root": "obsidian",
                    "relative_path": relative,
                    "max_lines": 10,
                },
            )
        )
        assert denied["status"] == "error"
    allowed = json.loads(
        service.execute(
            "kite_personal_files_read",
            {
                "operation": "read",
                "root": "obsidian",
                "relative_path": "scan.heic",
                "max_lines": 10,
            },
        )
    )
    assert allowed["status"] != "error", allowed


def test_contact_details_are_not_withheld_but_credentials_still_are(tmp_path):
    """Contact details are James's to share; a credential is not his to leak.

    A phone rule and an email rule used to sit in this filter. Between them
    they refused, in one day, a dated document title, four of the household's
    own passport numbers, and a filename James typed himself -- each reported
    back to him as an authorization problem for a document he was entitled
    to. What they defended against was his own contact details reaching his
    own conversation. He does not count that as a leak, so they are gone.

    What is left is the part that defends something a recipient could use.
    """
    runtime = _runtime(tmp_path, mode="kite")
    runtime.secret_values = {"super-secret-token-value"}

    for allowed in (
        "Send me 20-11-25_180-Strand_10818.pdf from iCloud Drive",
        "Call me on 07700 900123",
        "Reach him at +44 7700 900123",
        "adviser@example.com sent the engagement letter",
        "Alex Morgan Reed - 900000001 - 4 March 2032",
        "Filed on 2026-08-10 at 15:37",
        "invoice_2024_01_15_final.pdf",
    ):
        assert runtime._leak_reason(allowed, output=True) == "", allowed

    for refused in (
        "my api_key is sk-abc123def456ghi789",
        "pass**word**: hunter2000000",
        "AKIAIOSFODNN7EXAMPLE",
    ):
        assert runtime._leak_reason(refused, output=True) == (
            "credential-shaped content"
        ), refused
    assert runtime._leak_reason(
        "the value is super-secret-token-value", output=True
    ) == "configured credential value"
    assert runtime._leak_reason("account_id: 12345", output=True) == (
        "labelled private identifier"
    )


def test_formatting_does_not_decide_whether_an_answer_leaks(tmp_path):
    """Emphasis inside a token must not slip a credential past the scan.

    cred**ential** reads as prose to a pattern and as a credential to a
    human, so the scan sees the flattened form too and a match on either is
    enough. An underscore is left alone inside a word: removing it joined
    the parts of a filename into digits that were never there.
    """
    runtime = _runtime(tmp_path, mode="kite")
    assert runtime._leak_reason("pass**word**: hunter2000000", output=True) == (
        "credential-shaped content"
    )
    assert runtime._leak_reason("my ap*i_ke*y is sk-abc123def456", output=True) == (
        "credential-shaped content"
    )
    for untouched in (
        "20-11-25_180-Strand_10818.pdf",
        "scan_20260810_143022.jpg",
        "_italic emphasis_ around words",
    ):
        assert runtime._leak_reason(untouched, output=True) == "", untouched


def test_a_read_of_a_scan_is_bounded_by_the_read_not_by_the_preview(monkeypatch):
    """The number was returned and the expiry was cut off.

    Every local reader imposed the 600-character preview length, whatever the
    caller asked for, so a read of a passport stopped mid-page: enough to show
    the number, not enough to reach the expiry date. The model reported that
    it could not verify the passport -- which is what a truncated document
    looks like from the inside -- and declined to give either.
    """
    import plugins.juno_kite_trusted_principal.private_reads as pr

    page = "Passport No 900000001 " + ("official observations " * 200) + "Expiry 14 MAR 2031"
    assert len(page) > 4000

    monkeypatch.setattr(pr, "_normalise_artifact", lambda data, mime: (data, mime))
    monkeypatch.setattr(pr.Path, "exists", lambda self: True)
    monkeypatch.setattr(
        pr.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=page),
    )

    preview = pr._document_preview(b"synthetic", "image/jpeg")
    assert len(preview) == 600
    assert "14 MAR 2031" not in preview  # a preview only has to tell them apart

    read = pr._document_preview(b"synthetic", "image/jpeg", limit=6000)
    assert "900000001" in read
    assert "14 MAR 2031" in read, "a read must reach the end of the page"

    # And the same for a PDF with a text layer, which uses the other reader.
    pdf = pr._document_preview(b"%PDF-1.4", "application/pdf", limit=6000)
    assert "14 MAR 2031" in pdf


def test_preview_converts_what_a_phone_produces_before_trying_to_read_it(monkeypatch):
    """A HEIC photo of a document read as blank, not as unreadable.

    The release path converts HEIC and TIFF locally before inspecting them;
    the preview path dispatched straight on MIME, so the formats a family
    actually photographs documents in fell to the "" branch -- which the
    model cannot tell apart from a genuinely unidentifiable file.
    """
    import plugins.juno_kite_trusted_principal.private_reads as pr

    converted: list[str] = []

    def _fake_normalise(data, mime_type):
        if mime_type in {"image/heic", "image/tiff"}:
            converted.append(mime_type)
            return data, "image/jpeg"
        return data, mime_type

    monkeypatch.setattr(pr, "_normalise_artifact", _fake_normalise)
    monkeypatch.setattr(
        pr, "_run_preview_reader", lambda argv, limit=600: "PASSPORT 533812947"
    )
    monkeypatch.setattr(pr.Path, "exists", lambda self: True)

    for mime in ("image/heic", "image/tiff", "image/jpeg"):
        assert pr._document_preview(b"synthetic", mime) == "PASSPORT 533812947", mime
    assert converted == ["image/heic", "image/tiff"]


def test_read_caps_a_document_on_what_it_loads_not_on_what_a_text_file_returns(
    tmp_path, monkeypatch
):
    """A scan is megabytes of image behind a few hundred characters of text.

    output_bytes caps what a tool returns, and for a text file that is also
    its size on disk, so one gate served for both. Charging an extracted
    document for the size of its image data made every passport unreadable
    -- "what is Lucy's passport number" could only be answered by sending
    Lucy's passport -- while the same file previewed and released fine.
    """
    root = tmp_path / "personal"
    root.mkdir()
    filler = b"0" * 23_000
    (root / "scan.pdf").write_bytes(b"%PDF-1.4\n" + filler)
    (root / "notes.md").write_text("x" * 23_000, encoding="utf-8")
    # Derived from the cap, not a number that happened to match it once: this
    # asserted 8MB was refused, and stayed asserting it after the ceiling was
    # raised for a solicitor's 10.97MB scan. Patched small so the test does not
    # write tens of megabytes to say one thing.
    monkeypatch.setattr(
        "plugins.juno_kite_trusted_principal.private_reads"
        "._EXTRACT_MAX_INPUT_BYTES",
        50_000,
    )
    (root / "huge.pdf").write_bytes(b"%PDF-1.4\n" + b"0" * 60_000)

    seen: list[int] = []

    def _stub(data, mime_type, *, limit=600, pages=2):
        seen.append(len(data))
        return ("Synthetic passport. Number 000000000. Expiry 01 JAN 2030. " * 400)[
            :limit
        ]

    monkeypatch.setattr(
        "plugins.juno_kite_trusted_principal.private_reads._document_preview", _stub
    )
    service = PrivateReadService({
        "enabled": True,
        "output_bytes": 20_000,
        "files": {"roots": [{"name": "obsidian", "path": str(root)}],
                  "allowed_bases": [str(tmp_path)]},
    })

    def read(relative):
        return json.loads(
            service.execute(
                "kite_personal_files_read",
                {
                    "operation": "read",
                    "root": "obsidian",
                    "relative_path": relative,
                    "max_lines": 10,
                },
            )
        )

    extracted = read("scan.pdf")
    assert extracted["status"] != "error", extracted
    assert extracted["data"]["outcome"] == "extracted"
    assert "000000000" in extracted["data"]["text"]
    # The extractor was handed the whole document, well past output_bytes...
    assert seen == [23_009]
    # ...and what came back is bounded by what a read returns, shortened to
    # fit the configured cap rather than failing against it: half of the
    # 20_000-byte envelope here, well under the 40_000 a read may ask for.
    assert len(extracted["data"]["text"]) == 10_000

    # A text file still answers for its own size: there the two are the same.
    assert read("notes.md")["status"] == "error"
    # And the new gate is a gate, not an opening.
    assert read("huge.pdf")["status"] == "error"
    assert seen == [23_009]


@pytest.mark.parametrize(
    "text",
    [
        "password: synthetic-password",
        "api_key=synthetic-key",
        "refresh_token: synthetic-refresh",
        "cookie: synthetic-session-cookie",
        "OTP code: 123456",
        "recovery code: ABCD-1234",
        "pairing code: 987654",
        "QR payload: synthetic-qr-material",
        "cvv: 123",
        "-----BEGIN PRIVATE KEY-----",
        "https://login.invalid/magic?token=synthetic-token",
    ],
)
def test_authentication_material_is_detected(tmp_path, text):
    runtime = _runtime(tmp_path, mode="kite")
    assert runtime._leak_reason(text, output=True)


def test_passport_identifier_is_not_globally_a_credential(tmp_path):
    runtime = _runtime(tmp_path, mode="kite")
    assert runtime._leak_reason("Child passport number 123456789", output=True) == ""
    assert runtime._leak_reason("Child passport no. 123 456 789", output=True) == ""


@pytest.mark.parametrize(
    "question,tier",
    [
        ("What are the next steps?", MINIMIZED),
        ("Quote the exact wording needed", BOUNDED_EXCERPT),
        ("Send me the actual passport scan", DOCUMENT_DESCRIPTOR),
        ("Export the whole raw mailbox and headers", BULK_RAW),
        ("Export all Property Intel records", BULK_RAW),
    ],
)
def test_output_tiers(question, tier):
    assert classify_output_tier(question) == tier


@pytest.mark.parametrize(
    "question",
    [
        # Named real-world documents: people do not say "PDF" or "file".
        "Send me the nacho engagement letter",
        "attach the engagement letter",
        "email me the file",
        "forward me the birth certificate",
        "can you send me the tenancy agreement",
        "whatsapp me Albie's boarding pass",
        "I need the survey report",
        "share my driving licence",
        "send me the signed engagement letter PDF from Nacho",
        # Existing artifact-noun phrasings must keep working.
        "send me the passport scan",
        "send me the document",
        # Plural and polite forms.
        "send over the boarding passes",
        "can you send me the engagement letter",
        # Viewing verbs are delivery requests too: a passport cannot be
        # "shown" in a chat without releasing the actual image.
        "Show me Lucy's passport",
        "show me the engagement letter",
        "let me see Albie's boarding pass",
        "pull up the tenancy agreement",
        "I want you to send me Lucy's passport image as a file",
    ],
)
def test_named_document_requests_select_the_document_tier(question):
    assert classify_output_tier(question) == DOCUMENT_DESCRIPTOR


@pytest.mark.parametrize(
    "question",
    [
        # Informational intent wins even next to a delivery verb, so an
        # ordinary question never escalates into a file-release proposal.
        "what did nacho say",
        "send me a summary of the engagement letter",
        "tell me about the engagement letter",
        "what's in the terms of business",
        "when did nacho email",
        "send me an update on the villa",
        "send me a note about the letter",
        "remind me about the tenancy agreement",
        # A question about a document is not a request to be sent one.
        "did nacho send the agreement",
        "has the certificate arrived",
        "is the tenancy agreement signed",
        "have you got the invoice",
        "send Lucy a note",
        # Viewing verbs must not escalate informational questions either.
        "show me what nacho said",
        "show me a summary of the letter",
        "tell me about the passport",
        # A field printed on a document is not the document. This asked for
        # four numbers and was answered with four passport scans, which is
        # both wrong and irreversible -- and it needs no question word, so
        # nothing above catches it.
        "give me the whole family's passport numbers and expiries",
        "give me the passport numbers",
        "i need the passport expiry dates",
        "give me the expiry dates on the family's passports",
        "when do the kids' passports expire",
    ],
)
def test_informational_requests_stay_minimized(question):
    assert classify_output_tier(question) == MINIMIZED


@pytest.mark.parametrize(
    "question",
    [
        # Plurals count. "Send me the passports" classified as a minimized
        # answer because the word boundary would not close after "passport",
        # so asking for several documents quietly asked for none.
        "send me the passports",
        "send me the whole family's passports",
        "send me the documents",
        "forward the scans",
        # A details *page* is the document itself, not a field printed on it.
        "give me the passport details page",
        "send me the passport photo page",
        "send me a copy of the passport",
    ],
)
def test_asking_for_several_documents_still_asks_for_documents(question):
    assert classify_output_tier(question) == DOCUMENT_DESCRIPTOR


def test_james_may_release_his_own_private_documents():
    """James asking for his own emailed document is a permitted release."""
    decision = disclosure_decision(
        principal="james",
        effective_capability_ids=["juno.private.james"],
        capability_id="juno.private.james",
        output_tier=DOCUMENT_DESCRIPTOR,
    )
    assert decision.allowed is True
    assert decision.outcome == DOCUMENT_DESCRIPTOR


def test_lucy_may_not_release_james_private_documents():
    decision = disclosure_decision(
        principal="lucy",
        effective_capability_ids=["juno.private.james"],
        capability_id="juno.private.james",
        output_tier=DOCUMENT_DESCRIPTOR,
    )
    assert decision.allowed is False


@pytest.mark.parametrize("principal", ["lucy", "someone_else"])
def test_a_second_principal_releases_shared_classes_but_never_his_own(principal):
    """Name decided this; the capability decides it now.

    A shared class is shared -- refusing a family document to family was the
    old rule doing the wrong thing for the right reason. His private class
    stays his, and not because of a check on names: it is only ever in an
    effective set that belongs to him alone, because a group's set is the
    intersection of everyone in it.
    """
    for capability_id in ("juno.shared.family", "juno.shared.children"):
        assert disclosure_decision(
            principal=principal,
            effective_capability_ids=[capability_id],
            capability_id=capability_id,
            output_tier=DOCUMENT_DESCRIPTOR,
        ).allowed is True

    # Asked for outside what the audience holds, it is refused for anyone.
    assert disclosure_decision(
        principal=principal,
        effective_capability_ids=["juno.shared.family"],
        capability_id="juno.private.james",
        output_tier=DOCUMENT_DESCRIPTOR,
    ).allowed is False


def test_guidance_names_releasable_document_classes_for_james():
    """The model must be told which documents are releasable.

    Without this it invents privacy-sounding refusals for requests the
    policy actually permits, which is indistinguishable from a real denial.
    """
    guidance = generated_semantic_guidance(
        principal="james",
        effective_capability_ids=[
            "juno.private.james",
            "juno.shared.children",
            "juno.shared.family",
        ],
        configured_policy={
            "juno.private.james": "personal",
            "juno.shared.children": "children",
            "juno.shared.family": "family",
        },
        output_tier=DOCUMENT_DESCRIPTOR,
    )
    release = guidance["document_release_mode"]
    assert release["available"] is True
    assert "juno.shared.children" in release["releasable_capability_ids"]
    assert "juno.private.james" in release["releasable_capability_ids"]
    # It must instruct deferral to the host gates rather than self-refusal.
    assert "refuse" in release["self_refusal"].lower()


def test_guidance_offers_a_second_principal_the_classes_they_hold():
    """The model has to be told what it may release, for whoever is asking."""
    guidance = generated_semantic_guidance(
        principal="lucy",
        effective_capability_ids=["juno.shared.family"],
        configured_policy={"juno.shared.family": "family"},
        output_tier=DOCUMENT_DESCRIPTOR,
    )
    assert guidance["document_release_mode"]["available"] is True
    assert guidance["document_release_mode"]["releasable_capability_ids"] == [
        "juno.shared.family"
    ]

    # Nothing releasable in the set, nothing offered.
    public_only = generated_semantic_guidance(
        principal="lucy",
        effective_capability_ids=["juno.public"],
        configured_policy={"juno.public": "public"},
        output_tier=DOCUMENT_DESCRIPTOR,
    )
    assert public_only["document_release_mode"]["available"] is False
    assert public_only["document_release_mode"]["releasable_capability_ids"] == []


def test_semantic_james_lucy_domain_matrix():
    shared = {
        "juno.shared.children",
        "juno.shared.mauritius",
        "juno.shared.property_intel",
        "juno.shared.villa_lena",
    }
    for capability in shared:
        assert disclosure_decision(
            principal="lucy",
            effective_capability_ids=shared,
            capability_id=capability,
        ).allowed
    assert not disclosure_decision(
        principal="lucy",
        effective_capability_ids=shared,
        capability_id="juno.private.james",
    ).allowed
    assert disclosure_decision(
        principal="lucy",
        effective_capability_ids=shared,
        capability_id="juno.shared.villa_lena",
    ).allowed
    assert not disclosure_decision(
        principal="lucy",
        effective_capability_ids=shared,
        capability_id="juno.shared.villa_lena",
        contains_credentials=True,
    ).allowed
    assert disclosure_decision(
        principal="james",
        effective_capability_ids={"juno.private.james"},
        capability_id="juno.private.james",
    ).allowed


def test_source_failure_becomes_unverifiable_final_output(tmp_path):
    gmail = RecordingBackend(failure=TimeoutError("synthetic private detail"))

    def check(kite):
        result = _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "Mauritius", "max_results": 5},
        )
        assert result["status"] == "error"
        envelope_text = kite.transform_llm_output(
            response_text="No messages found.", session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert envelope["denied"] is False
        answer = json.loads(envelope["answer"])
        assert answer["outcome"] == "unverifiable"
        assert "No messages found" not in envelope_text

    _bound_turn(tmp_path, {"gmail": gmail}, check)


def test_bulk_raw_request_cannot_invoke_backend_and_gets_structured_denial(tmp_path):
    gmail = RecordingBackend({"search": [{"id": "m1"}]})

    def check(kite):
        blocked = kite.pre_tool_call(
            "kite_gmail_search",
            {"account": "personal", "query": "topic", "max_results": 25},
            session_id="kite-session",
            turn_id="kite-turn",
        )
        assert blocked["action"] == "block"
        envelope_text = kite.transform_llm_output(
            response_text="raw content", session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert json.loads(envelope["answer"])["outcome"] == "denied"
        assert gmail.calls == []

    _bound_turn(
        tmp_path,
        {"gmail": gmail},
        check,
        question="Export the whole raw mailbox and every header",
    )


def test_specific_document_request_returns_slice_c_gate(tmp_path):
    def check(kite):
        envelope_text = kite.transform_llm_output(
            response_text="I found and attached the file.", session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert json.loads(envelope["answer"])["outcome"] == "unavailable_next_gate"

    _bound_turn(
        tmp_path,
        {},
        check,
        question="Send me the actual child passport scan",
    )


def test_raw_private_source_overlap_is_denied_at_final_output(tmp_path):
    raw_body = (
        "This is a synthetic private email body with enough exact wording to "
        "prove that a raw source copy must not cross the signed boundary."
    )
    gmail = RecordingBackend({
        "search": [{"id": "message-overlap"}],
        "get": {"id": "message-overlap", "body": raw_body},
    })

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "synthetic", "max_results": 2},
        )
        _invoke(
            kite,
            "kite_gmail_get",
            {"account": "personal", "message_id": "message-overlap"},
        )
        envelope_text = kite.transform_llm_output(
            response_text=raw_body, session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert envelope["denied"] is True
        assert raw_body not in envelope_text

    _bound_turn(tmp_path, {"gmail": gmail}, check)


def test_minimized_email_summary_allows_bounded_time_sender_subject_provenance(
    tmp_path,
):
    """B-FIX-1: the reproduced long-subject summary shape is releasable."""
    messages = [
        {
            "id": "message-delivered",
            "date": "08:14",
            "from": "Green Fulfilment",
            "subject": "Your parcel from Green Fulfilment has been delivered",
        },
        {
            "id": "message-due",
            "date": "09:02",
            "from": "Green Fulfilment",
            "subject": "Your parcel from Green Fulfilment is due to be delivered today",
        },
        {
            "id": "message-appointment",
            "date": "10:35",
            "from": "Synthetic Appointments",
            "subject": (
                "Your synthetic appointment booking has been confirmed for "
                "Tuesday afternoon"
            ),
        },
        {
            "id": "message-membership",
            "date": "11:48",
            "from": "Household Memberships",
            "subject": (
                "A household membership renewal notice is ready for your review"
            ),
        },
        {
            "id": "message-travel",
            "date": "13:20",
            "from": "Synthetic Travel",
            "subject": (
                "Updated travel itinerary and check-in details for the family journey"
            ),
        },
        {
            "id": "message-receipt",
            "date": "15:41",
            "from": "Synthetic Receipts",
            "subject": (
                "Receipt for your recent synthetic household purchase is now available"
            ),
        },
    ]
    gmail = RecordingBackend({"search": messages})
    answer = "New emails today:\n" + "\n".join(
        f"- {item['date']} — {item['from']} — {item['subject']}"
        for item in messages
    )
    assert len(answer) > 400

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "after:today", "max_results": 10},
        )
        envelope_text = kite.transform_llm_output(
            response_text=answer, session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert envelope["denied"] is False
        assert envelope["answer"] == answer

    _bound_turn(
        tmp_path,
        {"gmail": gmail},
        check,
        question="Any new emails today?",
    )


@pytest.mark.parametrize("content_field", ["body", "snippet"])
def test_minimized_email_content_overlap_remains_denied(tmp_path, content_field):
    """B-FIX-2: provenance does not relax body or snippet overlap."""
    raw_content = (
        "This synthetic message content is deliberately longer than forty-eight "
        "characters and must remain inside Kite."
    )
    gmail = RecordingBackend({
        "search": [{"id": "message-content"}],
        "get": {"id": "message-content", content_field: raw_content},
    })

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "synthetic", "max_results": 2},
        )
        _invoke(
            kite,
            "kite_gmail_get",
            {"account": "personal", "message_id": "message-content"},
        )
        envelope_text = kite.transform_llm_output(
            response_text=raw_content, session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert envelope["denied"] is True
        assert raw_content not in envelope_text

    _bound_turn(tmp_path, {"gmail": gmail}, check)


@pytest.mark.parametrize("message_count", [11, 13])
def test_minimized_email_bulk_subject_harvest_exceeds_provenance_bounds(
    tmp_path, message_count
):
    """B-FIX-3: total-character and distinct-fragment bounds block harvesting."""
    labels = (
        "alpha",
        "bravo",
        "charlie",
        "delta",
        "echo",
        "foxtrot",
        "golf",
        "hotel",
        "india",
        "juliet",
        "kilo",
        "lima",
        "mike",
    )
    messages = [
        {
            "id": f"message-{label}",
            "subject": (
                f"Synthetic provenance {label}: household update ready for review"
            ),
        }
        for label in labels[:message_count]
    ]
    gmail = RecordingBackend({"search": messages})
    answer = "\n".join(f"- {item['subject']}" for item in messages)

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "synthetic", "max_results": 25},
        )
        envelope = json.loads(
            kite.transform_llm_output(
                response_text=answer, session_id="kite-session"
            ).split(RESPONSE_PREFIX, 1)[1]
        )
        assert envelope["denied"] is True
        assert envelope["answer"] == ""

    _bound_turn(tmp_path, {"gmail": gmail}, check)


@pytest.mark.parametrize(
    "subject,answer,withheld",
    [
        (
            "Security notice: password=synthetic-credential-value must never be exposed",
            "Security notice: password=synthetic-credential-value must never be exposed",
            True,
        ),
        # Identifier-shaped content is redacted, not withheld: the span costs
        # itself, the answer survives. James's calibration, 2026-08-12.
        (
            "Synthetic private record 123e4567-e89b-12d3-a456-426614174000 is ready",
            "Synthetic private record 123e4567-e89b-12d3-a456-426614174000 is ready",
            False,
        ),
        (
            "Synthetic household update with enough provenance text for overlap",
            json.dumps({
                "subject": (
                    "Synthetic household update with enough provenance text for overlap"
                )
            }),
            True,
        ),
    ],
)
def test_minimized_provenance_does_not_relax_absolute_output_denials(
    tmp_path, subject, answer, withheld
):
    """B-FIX-4: credentials and containers stay denied; identifiers redact."""
    gmail = RecordingBackend({
        "search": [{"id": "message-absolute-denial", "subject": subject}]
    })

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "synthetic", "max_results": 2},
        )
        envelope = json.loads(
            kite.transform_llm_output(
                response_text=answer, session_id="kite-session"
            ).split(RESPONSE_PREFIX, 1)[1]
        )
        assert envelope["denied"] is withheld
        if withheld:
            assert envelope["answer"] == ""
        else:
            assert "123e4567" not in envelope["answer"]
            assert "[redacted]" in envelope["answer"]
            assert "is ready" in envelope["answer"]

    _bound_turn(tmp_path, {"gmail": gmail}, check)


def test_unrelated_tool_content_cannot_ride_on_matching_provenance(tmp_path):
    """B-FIX-5: a content-field tag wins even when provenance has the same text."""
    shared_text = (
        "Synthetic household update with enough exact wording to test source scope"
    )
    gmail = RecordingBackend({
        "search": [{"id": "message-shared", "subject": shared_text}]
    })
    whatsapp = RecordingBackend({"search": [{"text": shared_text}]})

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "synthetic", "max_results": 2},
        )
        _invoke(
            kite,
            "kite_whatsapp_archive_read",
            {"operation": "search", "query": "synthetic", "max_results": 2},
        )
        envelope = json.loads(
            kite.transform_llm_output(
                response_text=shared_text, session_id="kite-session"
            ).split(RESPONSE_PREFIX, 1)[1]
        )
        assert envelope["denied"] is True
        assert envelope["answer"] == ""

    _bound_turn(
        tmp_path,
        {"gmail": gmail, "whatsapp": whatsapp},
        check,
    )


def test_private_read_config_rejects_generic_read_authority(tmp_path):
    config = _slice_b_config(tmp_path, mode="kite")
    config["juno_kite_trusted_principal"]["policy"]["tool_classes"]["read"] = [
        "read_file"
    ]
    with pytest.raises(ValueError, match="generic or non-plugin"):
        TrustedPrincipalRuntime(config, active_profile="kite")


def test_contextvar_isolation_does_not_transfer_private_read_authority(tmp_path):
    backend = RecordingBackend({"search": []})

    def check(kite):
        args = {"account": "personal", "query": "trip", "max_results": 2}
        assert (
            kite.pre_tool_call(
                "kite_gmail_search",
                args,
                session_id="kite-session",
                turn_id="kite-turn",
            )
            is None
        )

        def isolated():
            tokens = set_session_vars(
                platform="a2a",
                source="a2a",
                chat_id="different-context",
                user_id="juno",
                session_key="agent:kite:a2a:dm:different",
                session_id="other-session",
                profile="kite",
                cron_session="",
            )
            try:
                denied = kite.pre_tool_dispatch(
                    "kite_gmail_search",
                    args,
                    session_id="other-session",
                    turn_id="kite-turn",
                )
                assert denied["action"] == "block"
            finally:
                clear_session_vars(tokens)

        copy_context().run(isolated)
        assert backend.calls == []

    _bound_turn(tmp_path, {"gmail": backend}, check)


# ---------------------------------------------------------------------------
# The reader contract.
#
# Two days of defects fell into a handful of shapes that kept recurring in
# whichever reader had not been touched yet: a caller's own cap refusing the
# call instead of bounding it, a refusal that would not name what it objected
# to, an oversized-but-legal payload turned away rather than trimmed. Each was
# fixed where it was found, one bespoke test at a time.
#
# These run the same invariants over every reader that takes a bound, so the
# next reader cannot reintroduce them quietly. A new reader with a max_results
# belongs in READER_CONTRACT.
# ---------------------------------------------------------------------------

# (tool, arguments, backend operation, the key the bound arrives under)
READER_CONTRACT = [
    (
        "kite_gmail_search",
        {"account": "personal", "query": "anything", "max_results": 3},
        "gmail", "search",
        lambda n: [{"id": f"message-{i}", "subject": "s"} for i in range(n)],
    ),
    (
        "kite_calendar_read",
        {"account": "personal", "start": "2026-08-01", "end": "2026-08-31",
         "max_results": 3},
        "calendar", "list",
        lambda n: [
            {"summary": f"event-{i}", "start": "2026-08-02", "end": "2026-08-03"}
            for i in range(n)
        ],
    ),
    (
        "kite_whatsapp_archive_read",
        {"operation": "search", "query": "anything", "max_results": 3},
        "whatsapp", "search",
        lambda n: [{"message_id": f"m-{i}", "text": "t"} for i in range(n)],
    ),
    (
        "kite_things_read",
        {"operation": "search", "query": "anything", "max_results": 3},
        "things", "search",
        lambda n: [{"id": f"t-{i}", "title": "task"} for i in range(n)],
    ),
    (
        "kite_property_read",
        {"operation": "list", "max_results": 3},
        "property_intel", "list",
        lambda n: [
            {"id": f"123e4567-e89b-12d3-a456-4266141740{i:02d}",
             "canonicalTitle": f"Villa {i}", "status": "watchlist"}
            for i in range(n)
        ],
    ),
]


@pytest.mark.parametrize(
    "tool,args,backend_name,operation,make",
    READER_CONTRACT,
    ids=[row[0] for row in READER_CONTRACT],
)
def test_reader_contract_a_requested_bound_trims_and_never_refuses(
    tmp_path, tool, args, backend_name, operation, make
):
    """max_results says how many are wanted, not how many there had better be.

    Gmail, the calendar, the WhatsApp archive and Property Intel each treated
    a source that returned more than the cap as a malformed read and returned
    nothing. The caller asked for three; three were available; the answer was
    an error.
    """
    wanted = args["max_results"]

    def check(kite):
        result = _invoke(kite, tool, dict(args))
        assert result["status"] == "ok", result
        data = result["data"]
        rows = data["matches"] if isinstance(data, dict) and "matches" in data else data
        assert isinstance(rows, list), data
        assert len(rows) == wanted, f"{tool} returned {len(rows)} for cap {wanted}"

    _bound_turn(
        tmp_path,
        {backend_name: RecordingBackend({operation: make(wanted * 4)})},
        check,
    )


@pytest.mark.parametrize(
    "tool,args,backend_name,operation,make",
    READER_CONTRACT,
    ids=[row[0] for row in READER_CONTRACT],
)
def test_reader_contract_a_refusal_names_the_argument(
    tmp_path, tool, args, backend_name, operation, make
):
    """"file search requires query and max_results", to a call passing both.

    A refusal that does not name what it objected to costs a round trip to
    guess at, and the guess is often wrong twice.
    """
    def check(kite):
        stray = {**args, "not_an_argument": "x"}
        blocked = kite.pre_tool_call(
            tool, stray, session_id="kite-session", turn_id="kite-turn",
        )
        # Either the schema gate or the reader may refuse it, but whichever
        # does has to say which argument it means.
        if blocked is not None:
            assert "not_an_argument" in blocked["message"] or "schema" in (
                blocked["message"].lower()
            ), blocked
            return
        result = _invoke(kite, tool, stray)
        assert result["status"] == "error", result
        assert "not_an_argument" in result["error"]["message"], result

    _bound_turn(
        tmp_path,
        {backend_name: RecordingBackend({operation: make(1)})},
        check,
    )
