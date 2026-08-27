"""Deterministic coverage for bounded background-review replay (#93057)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from run_agent import AIAgent


def _tool_call() -> SimpleNamespace:
    return SimpleNamespace(
        id="call_1",
        type="function",
        function=SimpleNamespace(name="web_search", arguments='{"query":"x"}'),
    )


def _response(*, prompt_tokens: int, tool: bool) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content=None if tool else "done",
                    reasoning_content=None,
                    reasoning=None,
                    tool_calls=[_tool_call()] if tool else None,
                ),
                finish_reason="tool_calls" if tool else "stop",
            )
        ],
        model="test/model",
        usage=SimpleNamespace(
            prompt_tokens=prompt_tokens,
            completion_tokens=1,
            total_tokens=prompt_tokens + 1,
        ),
    )


def _make_loop_agent() -> AIAgent:
    tool_definition = {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search",
            "parameters": {"type": "object", "properties": {}},
        },
    }
    with (
        patch("run_agent.get_tool_definitions", return_value=[tool_definition]),
        patch("run_agent.check_toolset_requirements", return_value={}),
        patch("run_agent.OpenAI"),
        patch(
            "agent.model_metadata.get_model_context_length",
            return_value=256_000,
        ),
        patch(
            "agent.context_compressor.get_model_context_length",
            return_value=256_000,
        ),
    ):
        agent = AIAgent(
            api_key="test-key-1234567890",
            base_url="https://example.invalid/v1",
            model="test/model",
            quiet_mode=True,
            skip_context_files=True,
            skip_memory=True,
            max_iterations=10,
        )
    agent.client = MagicMock()
    agent._cached_system_prompt = "stable prompt"
    agent._use_prompt_caching = False
    agent._disable_streaming = True
    agent.tool_delay = 0
    agent.save_trajectories = False
    agent.max_compression_attempts = 1

    compressor = MagicMock()
    compressor.protect_first_n = 3
    compressor.protect_last_n = 20
    compressor.threshold_tokens = 999_999_999
    compressor.context_length = 1_000_000_000
    compressor.last_prompt_tokens = -1
    compressor.awaiting_real_usage_after_compression = False
    compressor.should_compress.return_value = False
    compressor.should_compress_info.return_value = (False, None)
    compressor.should_compress_preflight.return_value = False
    compressor.should_defer_preflight_to_real_usage.return_value = False
    compressor.get_active_compression_failure_cooldown.return_value = None
    compressor.select_context.return_value = None
    compressor.get_automatic_compaction_status_message.return_value = ""
    agent.context_compressor = compressor
    agent.compression_enabled = False

    def _execute(assistant_message, messages, *_args):
        call = assistant_message.tool_calls[0]
        messages.append(
            {
                "role": "tool",
                "name": call.function.name,
                "tool_call_id": call.id,
                "content": "ok",
            }
        )

    agent._execute_tool_calls = _execute
    return agent


def _run(agent: AIAgent, responses: list[SimpleNamespace], **kwargs):
    agent.client.chat.completions.create.side_effect = responses
    with (
        patch.object(agent, "_flush_messages_to_session_db", return_value=True),
        patch.object(agent, "_persist_session"),
        patch.object(agent, "_save_trajectory"),
        patch.object(agent, "_cleanup_task_resources"),
    ):
        return agent.run_conversation("review", **kwargs)


def test_review_input_budget_stops_before_next_provider_call():
    agent = _make_loop_agent()
    agent._review_input_token_budget = 100_000
    result = _run(
        agent,
        [
            _response(prompt_tokens=50_000, tool=True),
            _response(prompt_tokens=50_000, tool=True),
            _response(prompt_tokens=50_000, tool=True),
        ],
    )

    assert agent.client.chat.completions.create.call_count == 2
    assert agent.session_input_tokens == 100_000
    assert result["completed"] is False


def test_same_model_review_first_request_is_warm_then_followup_compacts():
    agent = _make_loop_agent()
    agent.compression_enabled = True
    agent._review_warm_snapshot_pending = True
    agent.context_compressor.threshold_tokens = 1
    agent.context_compressor.last_prompt_tokens = 100
    agent.context_compressor.should_compress.return_value = True
    agent._compress_context = MagicMock(
        return_value=(
            [
                {"role": "system", "content": "stable prompt"},
                {"role": "user", "content": "detached compacted summary"},
            ],
            "stable prompt",
        )
    )
    history = [
        {"role": "user", "content": "WARM_FULL_SNAPSHOT_MARKER"},
        {"role": "assistant", "content": "old reply"},
    ]
    _run(
        agent,
        [
            _response(prompt_tokens=100, tool=True),
            _response(prompt_tokens=10, tool=False),
        ],
        conversation_history=history,
    )

    calls = agent.client.chat.completions.create.call_args_list
    assert len(calls) == 2
    first_messages = calls[0].kwargs["messages"]
    second_messages = calls[1].kwargs["messages"]
    assert any(
        "WARM_FULL_SNAPSHOT_MARKER" in str(message.get("content", ""))
        for message in first_messages
    )
    assert not any(
        "WARM_FULL_SNAPSHOT_MARKER" in str(message.get("content", ""))
        for message in second_messages
    )
    assert agent._compress_context.call_count == 1


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({}, 600_000),
        ({"max_input_tokens": 1_000_000}, 1_000_000),
        ({"max_input_tokens": 0}, None),
        ({"max_input_tokens": -1}, None),
        ({"max_input_tokens": "bad"}, 600_000),
    ],
)
def test_review_input_budget_config(value, expected):
    from agent.background_review import _review_input_token_budget

    assert _review_input_token_budget(value) == expected


def test_review_input_budget_predicate_type_edges():
    from agent.conversation_loop import _review_input_budget_exhausted

    agent = SimpleNamespace(session_input_tokens=100)
    assert _review_input_budget_exhausted(agent) is False
    agent._review_input_token_budget = True
    assert _review_input_budget_exhausted(agent) is False
    agent._review_input_token_budget = 101
    assert _review_input_budget_exhausted(agent) is False
    agent._review_input_token_budget = 100
    assert _review_input_budget_exhausted(agent) is True
