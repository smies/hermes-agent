"""Process-wide admission tests for automatic background reviews."""

from __future__ import annotations

import threading
import time

import agent.background_review as background_review
import run_agent as run_agent_module
from run_agent import AIAgent


def _agent() -> AIAgent:
    agent = object.__new__(AIAgent)
    agent._MEMORY_REVIEW_PROMPT = "review memory"
    agent._SKILL_REVIEW_PROMPT = "review skills"
    agent._COMBINED_REVIEW_PROMPT = "review both"
    return agent


def _configure_limit(monkeypatch, limit: int) -> None:
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"auxiliary": {"background_review": {"max_concurrency": limit}}},
    )


def test_overlapping_reviews_are_skipped_without_queueing(monkeypatch, caplog):
    _configure_limit(monkeypatch, 1)
    real_thread = threading.Thread
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    calls = []
    threads = []

    class TrackingThread:
        def __init__(self, *, target, daemon=None, name=None):
            self._thread = real_thread(target=target, daemon=daemon, name=name)
            threads.append(self._thread)

        def start(self):
            self._thread.start()

    def blocking_review(*_args, **_kwargs):
        calls.append("started")
        entered.set()
        release.wait(2)
        finished.set()

    monkeypatch.setattr(background_review, "_run_review_in_thread", blocking_review)
    monkeypatch.setattr(run_agent_module.threading, "Thread", TrackingThread)

    agent = _agent()
    agent._spawn_background_review([], review_memory=True)
    assert entered.wait(1)

    started = time.monotonic()
    agent._spawn_background_review([], review_skills=True)
    agent._spawn_background_review([], review_skills=True)
    assert time.monotonic() - started < 0.2
    assert calls == ["started"]
    assert "capacity" in caplog.text.lower()
    assert caplog.text.lower().count("capacity occupied") == 1

    release.set()
    assert finished.wait(1)
    threads[0].join(1)
    assert not threads[0].is_alive()


def test_review_capacity_is_released_after_worker_exception(monkeypatch):
    _configure_limit(monkeypatch, 1)
    real_thread = threading.Thread
    first_finished = threading.Event()
    second_finished = threading.Event()
    calls = []
    threads = []

    def raising_then_succeeding(*_args, **_kwargs):
        calls.append("started")
        if len(calls) == 1:
            first_finished.set()
            raise RuntimeError("review failed")
        second_finished.set()

    class SwallowingThread:
        def __init__(self, *, target, daemon=None, name=None):
            def run():
                try:
                    target()
                except RuntimeError:
                    pass

            self._thread = real_thread(target=run, daemon=daemon, name=name)
            threads.append(self._thread)

        def start(self):
            self._thread.start()

    monkeypatch.setattr(background_review, "_run_review_in_thread", raising_then_succeeding)
    monkeypatch.setattr(run_agent_module.threading, "Thread", SwallowingThread)

    agent = _agent()
    agent._spawn_background_review([], review_memory=True)
    assert first_finished.wait(1)
    threads[0].join(1)
    assert not threads[0].is_alive()
    agent._spawn_background_review([], review_memory=True)

    assert second_finished.wait(1)
    assert calls == ["started", "started"]
