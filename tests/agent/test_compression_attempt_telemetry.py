import json
import logging
from concurrent.futures import Future
from types import SimpleNamespace
from unittest.mock import patch

from agent.conversation_compression import (
    compress_context,
    run_compress_context_with_progress_timeout,
)
from agent.context_compressor import ContextCompressor


class _TodoStore:
    def format_for_injection(self):
        return ""


class _Agent:
    def __init__(self, compressor):
        self.context_compressor = compressor
        self.session_id = "session-telemetry-test"
        self.platform = "cli"
        self.model = "test/main-model"
        self.provider = "test-provider"
        self.tools = []
        self._compression_feasibility_checked = True
        self.compression_in_place = False
        self._memory_manager = None
        self._session_db = None
        self._todo_store = _TodoStore()
        self._cached_system_prompt = None

    def _emit_status(self, _message):
        pass

    def _emit_warning(self, _message):
        pass

    def _invalidate_system_prompt(self):
        self._cached_system_prompt = None

    def _build_system_prompt(self, system_message):
        return system_message

    def commit_memory_session(self, _messages):
        pass


def _messages(secret_text="TOPSECRET_TRANSCRIPT_TEXT"):
    msgs = [{"role": "system", "content": "system prompt"}]
    for idx in range(10):
        msgs.append({"role": "user", "content": f"user message {idx} {secret_text}"})
        msgs.append({"role": "assistant", "content": f"assistant reply {idx} {secret_text}"})
    return msgs


def _extract_telemetry(caplog):
    records = [
        record.getMessage()
        for record in caplog.records
        if "context compression attempt telemetry:" in record.getMessage()
    ]
    assert len(records) == 1
    return json.loads(records[0].split("context compression attempt telemetry: ", 1)[1])


def test_compression_attempt_telemetry_is_metadata_only(caplog):
    with patch("agent.context_compressor.get_model_context_length", return_value=100_000):
        compressor = ContextCompressor(
            model="test/main-model",
            provider="test-provider",
            threshold_percent=0.50,
            quiet_mode=True,
            config_context_length=100_000,
        )
    compressor.tail_token_budget = 10
    agent = _Agent(compressor)

    with patch.object(compressor, "_generate_summary", return_value="SANITIZED SUMMARY"):
        with caplog.at_level(logging.INFO, logger="agent.conversation_compression"):
            compressed, system_prompt = compress_context(
                agent,
                _messages(),
                "system prompt",
                approx_tokens=75_000,
                force=True,
            )

    assert system_prompt == "system prompt"
    assert compressed is not None
    payload = _extract_telemetry(caplog)

    assert payload["event"] == "compression_attempt"
    assert payload["attempt_id"]
    assert payload["session_id"] == "session-telemetry-test"
    assert payload["trigger_source"] == "manual"
    assert payload["main_model"] == "test/main-model"
    assert payload["main_context_limit"] == 100_000
    assert payload["current_estimated_tokens"] == 75_000
    assert payload["effective_threshold"] == compressor.threshold_tokens
    assert payload["protected_head_tokens"] is not None
    assert payload["protected_tail_tokens"] is not None
    assert payload["middle_window_tokens"] is not None
    assert payload["chunking"] is False
    assert payload["chunk_count"] in {0, 1}
    assert payload["commit_status"] == "committed"
    assert payload["split_status"] == "not_applicable"
    assert payload["fallback_used"] is False
    assert isinstance(payload["total_duration_ms"], int)
    assert payload["timing_schema"] == "compression_phase_v1"
    assert payload["queue_admission_ms"] == 0
    assert payload["provider_ttft_ms"] is None
    assert payload["summary_generation_ms"] is None
    assert payload["database_commit_ms"] is None
    assert payload["phase_status"]["queue_admission"] == "inline"
    assert payload["phase_status"]["provider"] == "no_provider_call"
    assert payload["phase_status"]["database_commit"] == "no_database"
    assert payload["phase_unavailable_reason"]["database_commit"] == "no_database"

    raw_log = json.dumps(payload)
    assert "TOPSECRET_TRANSCRIPT_TEXT" not in raw_log
    assert "SANITIZED SUMMARY" not in raw_log
    assert "user message" not in raw_log
    assert "assistant reply" not in raw_log


def test_aux_call_telemetry_records_durations_without_content(caplog):
    with patch("agent.context_compressor.get_model_context_length", return_value=100_000):
        compressor = ContextCompressor(
            model="test/main-model",
            provider="test-provider",
            threshold_percent=0.50,
            quiet_mode=True,
            config_context_length=100_000,
        )
    compressor.tail_token_budget = 10
    agent = _Agent(compressor)
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="SANITIZED SUMMARY"))]
    )

    with patch("agent.context_compressor.call_llm", return_value=response):
        with caplog.at_level(logging.INFO, logger="agent.conversation_compression"):
            compress_context(
                agent,
                _messages(),
                "system prompt",
                approx_tokens=75_000,
            )

    payload = _extract_telemetry(caplog)
    assert payload["aux_prompt_tokens"] is not None
    # Current main intentionally omits max_tokens from the aux summary call
    # (the summary budget is prompt-level guidance only), so no output
    # reservation is recorded.
    assert payload["aux_output_reservation"] is None
    assert isinstance(payload["aux_call_duration_ms"], int)
    assert payload["aux_provider"]
    assert payload["aux_model"]
    assert payload["provider_call_count"] == 1
    assert payload["provider_total_ms"] >= 0
    assert payload["provider_ttft_ms"] is None
    assert payload["summary_generation_ms"] is None
    assert (
        payload["phase_unavailable_reason"]["provider_ttft"]
        == "non_streaming_or_no_token_observable"
    )

    raw_log = json.dumps(payload)
    assert "TOPSECRET_TRANSCRIPT_TEXT" not in raw_log
    assert "SANITIZED SUMMARY" not in raw_log


def test_meaningful_stream_token_not_bookkeeping_event_defines_ttft():
    from agent.auxiliary_client import (
        _create_with_progress,
        _relay_sync_completion,
        aux_progress_hook,
        aux_timing_hook,
    )

    bookkeeping = SimpleNamespace(id="r1", model="test", usage=None, choices=[])
    meaningful = SimpleNamespace(
        id="r1",
        model="test",
        usage=None,
        choices=[
            SimpleNamespace(
                finish_reason=None,
                delta=SimpleNamespace(
                    content="first token", reasoning=None, tool_calls=None
                ),
            )
        ],
    )
    completed = SimpleNamespace(
        id="r1",
        model="test",
        usage=None,
        choices=[
            SimpleNamespace(
                finish_reason="stop",
                delta=SimpleNamespace(content=None, reasoning=None, tool_calls=None),
            )
        ],
    )

    class _Client:
        def __init__(self):
            self.chat = SimpleNamespace(completions=self)

        def create(self, **kwargs):
            assert kwargs["stream"] is True
            return iter([bookkeeping, meaningful, completed])

    edges = []
    client = _Client()
    with aux_timing_hook(edges.append), aux_progress_hook(lambda: None):
        _relay_sync_completion(
            client,
            {"model": "test/model", "messages": []},
            create=lambda request: _create_with_progress(
                client, request, task="compression"
            ),
        )

    assert [edge["event"] for edge in edges] == [
        "dispatch",
        "meaningful_token",
        "complete",
    ]

    with patch("agent.context_compressor.get_model_context_length", return_value=100_000):
        compressor = ContextCompressor(
            model="test/main-model",
            provider="test-provider",
            config_context_length=100_000,
        )
    telemetry = compressor._begin_compression_telemetry(current_tokens=75_000)
    compressor._record_aux_provider_timing(
        {
            "event": "dispatch",
            "at": 10.0,
            "call_id": "call",
            "provider": "test-provider",
            "model": "test/model",
            "api_mode": "chat_completions",
        }
    )
    compressor._record_aux_provider_timing(
        {"event": "meaningful_token", "at": 10.125, "call_id": "call"}
    )
    compressor._record_aux_provider_timing(
        {
            "event": "complete",
            "at": 10.500,
            "call_id": "call",
            "status": "completed",
        }
    )
    assert telemetry["provider_ttft_ms"] == 125
    assert telemetry["summary_generation_ms"] == 375
    assert telemetry["provider_total_ms"] == 500


def test_database_commit_phase_covers_in_place_mutation(caplog, tmp_path):
    from hermes_state import SessionDB

    with patch("agent.context_compressor.get_model_context_length", return_value=100_000):
        compressor = ContextCompressor(
            model="test/main-model",
            provider="test-provider",
            threshold_percent=0.50,
            quiet_mode=True,
            config_context_length=100_000,
        )
    compressor.tail_token_budget = 10
    agent = _Agent(compressor)
    agent.compression_in_place = True
    agent._session_db = SessionDB(db_path=tmp_path / "state.db")
    agent._session_db.create_session(agent.session_id, source="cli")
    agent._last_flushed_db_idx = 0

    with patch.object(compressor, "_generate_summary", return_value="summary"):
        with caplog.at_level(logging.INFO, logger="agent.conversation_compression"):
            compress_context(
                agent,
                _messages(),
                "system prompt",
                approx_tokens=75_000,
                force=True,
            )

    payload = _extract_telemetry(caplog)
    assert isinstance(payload["database_commit_ms"], int)
    assert payload["database_commit_ms"] >= 0
    assert payload["phase_status"]["database_commit"] == "committed"
    assert payload["phase_unavailable_reason"]["database_commit"] is None
    assert agent._session_db.get_session(agent.session_id) is not None
    agent._session_db.close()


def test_queue_phase_is_measured_at_actual_worker_start(monkeypatch):
    with patch("agent.context_compressor.get_model_context_length", return_value=100_000):
        compressor = ContextCompressor(
            model="test/main-model",
            provider="test-provider",
            config_context_length=100_000,
        )
    agent = _Agent(compressor)
    captured = {}

    class _ImmediateExecutor:
        def submit(self, fn, *args):
            future = Future()
            future.set_result(fn(*args))
            return future

    monkeypatch.setattr(
        "agent.conversation_compression._get_compress_timeout_executor",
        lambda: _ImmediateExecutor(),
    )
    monkeypatch.setattr(
        "agent.conversation_compression._try_admit_compression_job", lambda: True
    )
    monkeypatch.setattr(
        "agent.conversation_compression._release_compression_admission",
        lambda *_args: None,
    )

    def _worker(_fence):
        seed = compressor._compression_queue_phase_seed
        captured.update(seed)
        return [], "prompt"

    run_compress_context_with_progress_timeout(
        worker=_worker,
        messages=[],
        system_prompt_fallback="prompt",
        idle_timeout_seconds=1,
        total_ceiling_seconds=2,
        telemetry_agent=agent,
    )
    assert captured["queue_admission_status"] == "worker_started"
    assert isinstance(captured["queue_admission_ms"], int)
    assert captured["queue_admission_ms"] >= 0


def test_pool_saturation_emits_one_terminal_phase_record(caplog, monkeypatch):
    with patch("agent.context_compressor.get_model_context_length", return_value=100_000):
        compressor = ContextCompressor(
            model="test/main-model",
            provider="test-provider",
            config_context_length=100_000,
        )
    agent = _Agent(compressor)
    monkeypatch.setattr(
        "agent.conversation_compression._try_admit_compression_job", lambda: False
    )

    with caplog.at_level(logging.INFO, logger="agent.conversation_compression"):
        run_compress_context_with_progress_timeout(
            worker=lambda _fence: ([], "prompt"),
            messages=[],
            system_prompt_fallback="prompt",
            idle_timeout_seconds=1,
            total_ceiling_seconds=2,
            telemetry_agent=agent,
        )

    payload = _extract_telemetry(caplog)
    assert payload["failure_class"] == "pool_saturated"
    assert payload["queue_admission_ms"] is None
    assert payload["phase_status"]["queue_admission"] == "saturated"
    assert payload["phase_status"]["provider"] == "no_provider_call"
    assert payload["phase_status"]["database_commit"] == "aborted"


def test_progress_timeout_emits_one_terminal_phase_record(caplog, monkeypatch):
    with patch("agent.context_compressor.get_model_context_length", return_value=100_000):
        compressor = ContextCompressor(
            model="test/main-model",
            provider="test-provider",
            config_context_length=100_000,
        )
    agent = _Agent(compressor)

    class _NeverStartsExecutor:
        def submit(self, _fn, *_args):
            return Future()

    monkeypatch.setattr(
        "agent.conversation_compression._get_compress_timeout_executor",
        lambda: _NeverStartsExecutor(),
    )
    monkeypatch.setattr(
        "agent.conversation_compression._try_admit_compression_job", lambda: True
    )
    monkeypatch.setattr(
        "agent.conversation_compression._release_compression_admission",
        lambda *_args: None,
    )

    with caplog.at_level(logging.INFO, logger="agent.conversation_compression"):
        run_compress_context_with_progress_timeout(
            worker=lambda _fence: ([], "prompt"),
            messages=[],
            system_prompt_fallback="prompt",
            idle_timeout_seconds=0.01,
            total_ceiling_seconds=0.02,
            telemetry_agent=agent,
        )

    payload = _extract_telemetry(caplog)
    assert payload["failure_class"] == "progress_timeout"
    assert payload["phase_status"]["queue_admission"] == "admitted"
    assert payload["phase_status"]["provider"] == "no_provider_call"
    assert payload["phase_unavailable_reason"]["database_commit"] == (
        "aborted_before_commit"
    )


def test_fallback_provider_calls_are_all_accounted_for(caplog):
    with patch("agent.context_compressor.get_model_context_length", return_value=100_000):
        compressor = ContextCompressor(
            model="test/main-model",
            provider="test-provider",
            summary_model_override="test/aux-model",
            threshold_percent=0.50,
            quiet_mode=True,
            config_context_length=100_000,
        )
    compressor.tail_token_budget = 10
    agent = _Agent(compressor)
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="summary"))]
    )

    with patch(
        "agent.context_compressor.call_llm",
        side_effect=[RuntimeError("model_not_found"), response],
    ):
        with caplog.at_level(logging.INFO, logger="agent.conversation_compression"):
            compress_context(
                agent,
                _messages(),
                "system prompt",
                approx_tokens=75_000,
                force=True,
            )

    payload = _extract_telemetry(caplog)
    assert payload["provider_call_count"] == 2
    assert [call["status"] for call in payload["provider_calls"]] == [
        "failed",
        "completed",
    ]
    assert payload["fallback_used"] is True
    assert payload["provider_total_ms"] >= 0
