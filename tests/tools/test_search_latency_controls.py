"""Latency, admission, and broad-root exclusion contracts for search_files."""

from __future__ import annotations

import json
import subprocess
import threading
import time
from unittest.mock import MagicMock

import pytest

import tools.file_tools as file_tools
from agent.concurrency_gate import ConcurrencyWaitCancelled, FairConcurrencyGate
from tools.file_operations import SearchResult, ShellFileOperations
from tools.interrupt import set_interrupt


class SubprocessEnvironment:
    def __init__(self, cwd: str):
        self.cwd = cwd

    def execute(self, command, cwd=None, timeout=None, **_kwargs):
        try:
            result = subprocess.run(
                ["bash", "-c", command],
                cwd=cwd or self.cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or "") + (exc.stderr or "")
            return {
                "output": f"{output}\n[Command timed out after {timeout}s]",
                "returncode": 124,
            }
        return {
            "output": result.stdout + result.stderr,
            "returncode": result.returncode,
        }


def _configure(
    monkeypatch,
    *,
    max_concurrency=2,
    timeout_seconds=15,
    queue_timeout_seconds=45,
):
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {
            "tools": {
                "search_files": {
                    "max_concurrency": max_concurrency,
                    "timeout_seconds": timeout_seconds,
                    "queue_timeout_seconds": queue_timeout_seconds,
                }
            }
        },
    )


@pytest.fixture(autouse=True)
def _isolated_search_gate(monkeypatch):
    monkeypatch.setattr(file_tools, "_SEARCH_FILES_GATE", FairConcurrencyGate())


def _wait_for_waiter_count(gate: FairConcurrencyGate, expected: int) -> None:
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        with gate._condition:
            if len(gate._waiters) == expected:
                return
        time.sleep(0.005)
    raise AssertionError(f"gate did not reach {expected} queued waiter(s)")


def test_search_capacity_waits_then_admits_and_releases(monkeypatch):
    _configure(monkeypatch, max_concurrency=1, queue_timeout_seconds=2)
    entered = threading.Event()
    release = threading.Event()
    second_finished = threading.Event()
    calls = []

    class BlockingOps:
        def search(self, **kwargs):
            calls.append(kwargs["pattern"])
            if kwargs["pattern"] == "first":
                entered.set()
                release.wait(2)
            return SearchResult()

    monkeypatch.setattr(file_tools, "_get_file_ops", lambda _task_id: BlockingOps())
    worker = threading.Thread(
        target=file_tools.search_tool,
        kwargs={"pattern": "first", "task_id": "capacity-first"},
        daemon=True,
    )
    worker.start()
    assert entered.wait(1)

    result = {}

    def run_second():
        result.update(json.loads(file_tools.search_tool("second", task_id="capacity-second")))
        second_finished.set()

    second = threading.Thread(target=run_second, daemon=True)
    second.start()
    _wait_for_waiter_count(file_tools._SEARCH_FILES_GATE, 1)
    assert not second_finished.is_set()

    release.set()
    worker.join(1)
    second.join(1)
    assert not worker.is_alive()
    assert not second.is_alive()
    assert "error" not in result
    assert calls == ["first", "second"]


def test_fair_gate_admits_waiters_fifo():
    gate = FairConcurrencyGate()
    initial = gate.acquire(1, timeout_seconds=1)
    assert initial is not None
    admitted = []
    threads = []

    def wait_for_capacity(index):
        lease = gate.acquire(1, timeout_seconds=2)
        assert lease is not None
        admitted.append(index)
        lease.release()

    for index in range(3):
        thread = threading.Thread(target=wait_for_capacity, args=(index,), daemon=True)
        thread.start()
        threads.append(thread)
        _wait_for_waiter_count(gate, index + 1)

    initial.release()
    for thread in threads:
        thread.join(1)
        assert not thread.is_alive()
    assert admitted == [0, 1, 2]


def test_fair_gate_timeout_removes_head_ticket():
    gate = FairConcurrencyGate()
    initial = gate.acquire(1, timeout_seconds=1)
    assert initial is not None
    results = {}

    def wait(name, timeout):
        started = time.monotonic()
        results[name] = gate.acquire(1, timeout_seconds=timeout)
        results[f"{name}_elapsed"] = time.monotonic() - started

    timed_out = threading.Thread(target=wait, args=("timed_out", 0.1), daemon=True)
    follower = threading.Thread(target=wait, args=("follower", 1), daemon=True)
    timed_out.start()
    _wait_for_waiter_count(gate, 1)
    follower.start()
    _wait_for_waiter_count(gate, 2)

    timed_out.join(1)
    assert not timed_out.is_alive()
    assert results["timed_out"] is None
    assert results["timed_out_elapsed"] >= 0.08
    initial.release()
    follower.join(1)
    assert not follower.is_alive()
    assert results["follower"] is not None
    results["follower"].release()


def test_fair_gate_cancellation_removes_head_ticket():
    gate = FairConcurrencyGate()
    initial = gate.acquire(1, timeout_seconds=1)
    assert initial is not None
    cancelled = threading.Event()
    results = {}

    def wait_cancelled():
        try:
            gate.acquire(1, timeout_seconds=2, cancel_check=cancelled.is_set)
        except ConcurrencyWaitCancelled:
            results["cancelled"] = True

    def wait_follower():
        results["follower"] = gate.acquire(1, timeout_seconds=1)

    cancelled_thread = threading.Thread(target=wait_cancelled, daemon=True)
    follower = threading.Thread(target=wait_follower, daemon=True)
    cancelled_thread.start()
    _wait_for_waiter_count(gate, 1)
    follower.start()
    _wait_for_waiter_count(gate, 2)

    cancelled.set()
    cancelled_thread.join(1)
    assert not cancelled_thread.is_alive()
    assert results["cancelled"] is True
    initial.release()
    follower.join(1)
    assert not follower.is_alive()
    assert results["follower"] is not None
    results["follower"].release()


def test_search_queue_timeout_is_model_actionable(monkeypatch):
    _configure(monkeypatch, max_concurrency=1, queue_timeout_seconds=7)

    class ExhaustedGate:
        def acquire(self, limit, timeout_seconds, cancel_check):
            assert limit == 1
            assert timeout_seconds == 7
            assert cancel_check is file_tools.is_interrupted
            return None

    monkeypatch.setattr(file_tools, "_SEARCH_FILES_GATE", ExhaustedGate())
    result = json.loads(file_tools.search_tool("needle", task_id="queue-timeout"))

    assert result["error_type"] == "search_queue_timeout"
    assert result["queue_timeout_seconds"] == 7
    assert result["retryable"] is True
    assert "narrow" in result["error"].lower()
    assert "retry" in result["error"].lower()


def test_search_queue_interrupt_cleans_up_without_timeout_error(monkeypatch):
    _configure(monkeypatch, max_concurrency=1, queue_timeout_seconds=2)
    initial = file_tools._SEARCH_FILES_GATE.acquire(1, timeout_seconds=1)
    assert initial is not None
    result = {}

    worker = threading.Thread(
        target=lambda: result.update(
            json.loads(file_tools.search_tool("needle", task_id="queue-cancel"))
        ),
        daemon=True,
    )
    worker.start()
    _wait_for_waiter_count(file_tools._SEARCH_FILES_GATE, 1)
    set_interrupt(True, worker.ident)
    worker.join(1)
    set_interrupt(False, worker.ident)

    assert not worker.is_alive()
    assert result["status"] == "cancelled"
    assert "error_type" not in result

    initial.release()
    monkeypatch.setattr(
        file_tools,
        "_get_file_ops",
        lambda _task_id: MagicMock(search=MagicMock(return_value=SearchResult())),
    )
    followup = json.loads(file_tools.search_tool("needle", task_id="queue-cancel-followup"))
    assert "error" not in followup


def test_search_capacity_is_released_after_error(monkeypatch):
    _configure(monkeypatch, max_concurrency=1)
    calls = 0

    class Ops:
        def search(self, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("boom")
            return SearchResult()

    monkeypatch.setattr(file_tools, "_get_file_ops", lambda _task_id: Ops())

    first = json.loads(file_tools.search_tool("one", task_id="error-release-1"))
    second = json.loads(file_tools.search_tool("two", task_id="error-release-2"))

    assert "boom" in first["error"]
    assert "error" not in second
    assert calls == 2


def test_configured_budget_is_forwarded_without_changing_tool_schema(monkeypatch):
    _configure(monkeypatch, timeout_seconds=7)
    ops = MagicMock()
    ops.search.return_value = SearchResult()
    monkeypatch.setattr(file_tools, "_get_file_ops", lambda _task_id: ops)

    file_tools.search_tool("needle", task_id="budget-forward")

    assert ops.search.call_args.kwargs["timeout_seconds"] == 7
    assert "timeout_seconds" not in file_tools.SEARCH_FILES_SCHEMA["parameters"]["properties"]
    assert "max_concurrency" not in file_tools.SEARCH_FILES_SCHEMA["parameters"]["properties"]
    assert "queue_timeout_seconds" not in file_tools.SEARCH_FILES_SCHEMA["parameters"]["properties"]


def test_queue_wait_does_not_reduce_execution_budget(monkeypatch):
    _configure(
        monkeypatch,
        max_concurrency=1,
        timeout_seconds=7,
        queue_timeout_seconds=2,
    )
    initial = file_tools._SEARCH_FILES_GATE.acquire(1, timeout_seconds=1)
    assert initial is not None
    called = threading.Event()
    result = {}

    class Ops:
        def search(self, **kwargs):
            assert kwargs["timeout_seconds"] == 7
            called.set()
            return SearchResult()

    monkeypatch.setattr(file_tools, "_get_file_ops", lambda _task_id: Ops())

    worker = threading.Thread(
        target=lambda: result.update(
            json.loads(file_tools.search_tool("needle", task_id="budget-separation"))
        ),
        daemon=True,
    )
    worker.start()
    _wait_for_waiter_count(file_tools._SEARCH_FILES_GATE, 1)
    assert not called.is_set()
    initial.release()
    worker.join(1)

    assert not worker.is_alive()
    assert called.is_set()
    assert "error" not in result


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({}, (2, 15, 45)),
        ({"tools": {"search_files": {"max_concurrency": 5}}}, (5, 15, 45)),
        (
            {
                "tools": {
                    "search_files": {
                        "max_concurrency": "bad",
                        "timeout_seconds": None,
                        "queue_timeout_seconds": [],
                    }
                }
            },
            (2, 15, 45),
        ),
    ],
)
def test_search_latency_config_resolves_old_and_invalid_configs(monkeypatch, config, expected):
    monkeypatch.setattr("hermes_cli.config.load_config_readonly", lambda: config)
    assert file_tools._load_search_latency_controls() == expected


@pytest.fixture
def generated_tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "visible.txt").write_text("needle\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "vendor.txt").write_text("needle\n", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "environment.txt").write_text("needle\n", encoding="utf-8")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "cached.txt").write_text("needle\n", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("target,pattern", [("content", "needle"), ("files", "*.txt")])
def test_broad_search_excludes_generated_trees_and_discloses_it(generated_tree, target, pattern):
    ops = ShellFileOperations(SubprocessEnvironment(str(generated_tree)), cwd=str(generated_tree))

    result = ops.search(pattern, path=str(generated_tree), target=target, timeout_seconds=5)
    payload = result.to_dict()
    rendered = json.dumps(payload)

    assert "visible.txt" in rendered
    assert "vendor.txt" not in rendered
    assert "environment.txt" not in rendered
    assert "cached.txt" not in rendered
    assert "excluded_directories" in payload
    assert "node_modules" in payload["excluded_directories"]


@pytest.mark.parametrize("target,pattern", [("content", "needle"), ("files", "*.txt")])
@pytest.mark.parametrize(
    ("root_name", "expected_file"),
    [("node_modules", "vendor.txt"), (".venv", "environment.txt")],
)
def test_explicit_generated_root_remains_searchable(
    generated_tree, target, pattern, root_name, expected_file
):
    root = generated_tree / root_name
    ops = ShellFileOperations(SubprocessEnvironment(str(root)), cwd=str(root))

    result = ops.search(pattern, path=str(root), target=target, timeout_seconds=5)
    payload = result.to_dict()

    assert expected_file in json.dumps(payload)
    assert payload["default_exclusions"] == "disabled for explicitly targeted generated/vendor root"


def test_timeout_returns_partial_results_with_narrowing_disclosure(monkeypatch):
    env = MagicMock(cwd="/big")

    def execute(command, **kwargs):
        if "test -e" in command:
            return {"output": "exists", "returncode": 0}
        assert kwargs["timeout"] <= 3
        return {
            "output": "src/a.py:10:needle\n[Command timed out after 3s]",
            "returncode": 124,
        }

    env.execute.side_effect = execute
    ops = ShellFileOperations(env)
    monkeypatch.setattr(ops, "_has_command", lambda command: command == "rg")

    result = ops.search("needle", path="/big", target="content", timeout_seconds=3)
    payload = result.to_dict()

    assert payload["truncated"] is True
    assert payload["limit_reason"] == "search_timeout"
    assert payload["matches"][0]["path"] == "src/a.py"
    assert "narrow" in payload["warning"].lower()


def test_latency_defaults_are_canonical():
    from hermes_cli.config_defaults import DEFAULT_CONFIG

    assert DEFAULT_CONFIG["auxiliary"]["background_review"]["max_concurrency"] == 1
    assert DEFAULT_CONFIG["tools"]["search_files"]["max_concurrency"] <= 2
    assert DEFAULT_CONFIG["tools"]["search_files"]["timeout_seconds"] == 15
    assert DEFAULT_CONFIG["tools"]["search_files"]["queue_timeout_seconds"] == 45
