"""Latency, admission, and broad-root exclusion contracts for search_files."""

from __future__ import annotations

import json
import subprocess
import threading
import time
from unittest.mock import MagicMock

import pytest

import tools.file_tools as file_tools
from tools.file_operations import SearchResult, ShellFileOperations


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


def _configure(monkeypatch, *, max_concurrency=2, timeout_seconds=15):
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {
            "tools": {
                "search_files": {
                    "max_concurrency": max_concurrency,
                    "timeout_seconds": timeout_seconds,
                }
            }
        },
    )


def test_search_capacity_exhaustion_fails_fast_and_releases(monkeypatch):
    _configure(monkeypatch, max_concurrency=1)
    entered = threading.Event()
    release = threading.Event()

    class BlockingOps:
        def search(self, **_kwargs):
            entered.set()
            release.wait(2)
            return SearchResult()

    monkeypatch.setattr(file_tools, "_get_file_ops", lambda _task_id: BlockingOps())
    worker = threading.Thread(
        target=file_tools.search_tool,
        kwargs={"pattern": "needle", "task_id": "capacity-first"},
        daemon=True,
    )
    worker.start()
    assert entered.wait(1)

    started = time.monotonic()
    rejected = json.loads(file_tools.search_tool("needle", task_id="capacity-second"))
    assert time.monotonic() - started < 0.2
    assert "capacity" in rejected["error"].lower()
    assert "narrow" in rejected["error"].lower()
    assert "retry" in rejected["error"].lower()

    release.set()
    worker.join(1)
    assert not worker.is_alive()


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
