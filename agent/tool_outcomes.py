"""Host-only control values for terminal-capable local tool calls.

Nothing in this module is a wire format.  Model, MCP, middleware, hook, log,
and persistence surfaces receive only the separate ``content`` value.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable


MAX_TERMINAL_CONTENT_CHARS = 2_048
MAX_TERMINAL_FINAL_RESPONSE_CHARS = 4_096
MAX_TERMINAL_STATUS_CHARS = 64
MAX_TERMINAL_REASON_CHARS = 96
MAX_TERMINAL_METADATA_ITEMS = 16
MAX_TERMINAL_METADATA_KEY_CHARS = 64
MAX_TERMINAL_METADATA_VALUE_CHARS = 256
MAX_TERMINAL_ERROR_CHARS = 512

TERMINAL_SAFE_FAILURE_FINAL_RESPONSE = (
    "The action may have completed, but Hermes could not verify its terminal "
    "outcome. The turn was stopped safely."
)

_MACHINE_VALUE_RE = re.compile(r"^[a-z][a-z0-9_.:-]*$")
_ACTIVE_TOOL_BATCH_PLAN: ContextVar[ToolBatchPlan | None] = ContextVar(
    "hermes_active_tool_batch_plan", default=None
)


def _bounded_text(value: Any, field_name: str, limit: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    if len(value) > limit:
        raise ValueError(f"{field_name} exceeds {limit} characters")
    if "\x00" in value:
        raise ValueError(f"{field_name} must not contain NUL")
    return value


def _machine_value(value: Any, field_name: str, limit: int) -> str:
    text = _bounded_text(value, field_name, limit)
    if not _MACHINE_VALUE_RE.fullmatch(text):
        raise ValueError(f"{field_name} is not a valid machine value")
    return text


def _immutable_metadata(value: Any) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if isinstance(value, Mapping):
        items = list(value.items())
    elif isinstance(value, tuple):
        items = list(value)
    else:
        raise TypeError("terminal metadata must be a mapping or tuple of pairs")
    if len(items) > MAX_TERMINAL_METADATA_ITEMS:
        raise ValueError(
            f"terminal metadata exceeds {MAX_TERMINAL_METADATA_ITEMS} items"
        )
    normalized: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise TypeError("terminal metadata entries must be key/value pairs")
        key = _machine_value(
            item[0], "terminal metadata key", MAX_TERMINAL_METADATA_KEY_CHARS
        )
        val = _bounded_text(
            item[1], "terminal metadata value", MAX_TERMINAL_METADATA_VALUE_CHARS
        )
        if key in seen:
            raise ValueError(f"duplicate terminal metadata key: {key}")
        seen.add(key)
        normalized.append((key, val))
    return tuple(sorted(normalized))


@dataclass(frozen=True, slots=True)
class TerminalToolDirective:
    """Bounded host instruction to finish the current turn."""

    final_response: str
    status: str
    reason: str
    metadata: tuple[tuple[str, str], ...] | Mapping[str, str] = ()

    def __post_init__(self) -> None:
        _bounded_text(
            self.final_response,
            "terminal final_response",
            MAX_TERMINAL_FINAL_RESPONSE_CHARS,
        )
        _machine_value(self.status, "terminal status", MAX_TERMINAL_STATUS_CHARS)
        _machine_value(self.reason, "terminal reason", MAX_TERMINAL_REASON_CHARS)
        object.__setattr__(self, "metadata", _immutable_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class ToolExecutionResult:
    """Model-visible content paired with optional host-only control."""

    content: str
    terminal: TerminalToolDirective | None = None

    def __post_init__(self) -> None:
        _bounded_text(self.content, "terminal tool content", MAX_TERMINAL_CONTENT_CHARS)
        if self.terminal is not None and not isinstance(
            self.terminal, TerminalToolDirective
        ):
            raise TypeError("terminal must be a TerminalToolDirective or None")


@dataclass(frozen=True, slots=True)
class TerminalToolCapability:
    """Authority snapshot bound to one exact current local registration."""

    name: str
    handler: Callable[..., Any]
    registration_token: object
    is_async: bool
    terminal_handler: Callable[..., Any]
    toolset: str
    check_fn: Callable[..., Any] | None
    availability_generation: int
    enabled_toolsets: frozenset[str] | None = None
    disabled_toolsets: frozenset[str] = frozenset()
    session_scope: frozenset[str] | None = None
    tool_search_scope: frozenset[str] | None = None

    def __post_init__(self) -> None:
        _bounded_text(self.name, "terminal capability name", 128)
        if not callable(self.handler):
            raise TypeError("terminal capability handler must be callable")
        if self.terminal_handler is not self.handler:
            raise ValueError("terminal capability handler metadata must match")
        _bounded_text(self.toolset, "terminal capability toolset", 128)
        if self.check_fn is not None and not callable(self.check_fn):
            raise TypeError("terminal capability check_fn must be callable or None")
        if not isinstance(self.availability_generation, int):
            raise TypeError("terminal capability availability generation must be an int")


@dataclass(slots=True)
class TerminalToolInvocation:
    """Single-use invocation-local authority, never exposed to middleware."""

    capability: TerminalToolCapability
    handler_entered: bool = False
    _handler_result: Any = field(default=None, repr=False)
    _handler_exited: bool = field(default=False, repr=False)
    _post_entry_error: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.capability, TerminalToolCapability):
            raise TypeError("terminal invocation requires a capability snapshot")

    def enter(self, handler: Callable[..., Any], registration_token: object) -> None:
        if self.handler_entered:
            raise RuntimeError("terminal handler invocation is single-use")
        if (
            handler is not self.capability.handler
            or registration_token is not self.capability.registration_token
        ):
            raise RuntimeError("terminal handler identity does not match snapshot")
        self.handler_entered = True

    def record_result(self, result: Any) -> None:
        if not self.handler_entered or self._handler_exited:
            raise RuntimeError("terminal handler result is out of sequence")
        self._handler_result = result
        self._handler_exited = True

    def record_error(self, _error: BaseException | None = None) -> None:
        if not self.handler_entered:
            raise RuntimeError("terminal handler error recorded before entry")
        self._post_entry_error = True
        self._handler_exited = True

    def seal(self, candidate: Any) -> Any:
        """Restore host control after middleware, or produce safe failure."""

        if not self.handler_entered:
            if isinstance(candidate, ToolExecutionResult):
                return bounded_terminal_error(
                    "terminal control was returned before trusted handler entry"
                )
            return candidate

        raw = self._handler_result
        raw_error = (
            validate_tool_execution_result(raw)
            if isinstance(raw, ToolExecutionResult)
            else None
        )
        if self._post_entry_error:
            return terminal_safe_failure("terminal_handler_error")
        if raw_error is not None:
            return terminal_safe_failure("terminal_result_invalid")
        if not (
            self._handler_exited
            and isinstance(raw, ToolExecutionResult)
            and raw.terminal is not None
        ):
            return terminal_safe_failure("terminal_result_missing")

        if isinstance(candidate, ToolExecutionResult):
            candidate_error = validate_tool_execution_result(candidate)
            visible = candidate.content if candidate_error is None else raw.content
        elif isinstance(candidate, str):
            visible = candidate
        else:
            visible = raw.content
        try:
            return ToolExecutionResult(content=visible, terminal=raw.terminal)
        except (TypeError, ValueError):
            return ToolExecutionResult(content=raw.content, terminal=raw.terminal)


@dataclass(frozen=True, slots=True)
class PlannedToolCall:
    """One pre-dispatch resolution, including Tool Search indirection."""

    tool_call_id: str
    original_name: str
    effective_name: str
    args: dict[str, Any]
    parse_error: str | None = None
    scope_block: str | None = None
    terminal_capability: TerminalToolCapability | None = None


@dataclass(frozen=True, slots=True)
class ToolBatchPlan:
    calls: tuple[PlannedToolCall, ...]
    reject_for_terminal_exclusivity: bool = False

    def for_id(self, tool_call_id: str) -> PlannedToolCall | None:
        return next((call for call in self.calls if call.tool_call_id == tool_call_id), None)


@contextmanager
def bind_tool_batch_plan(plan: ToolBatchPlan):
    """Bind one immutable plan to the current conversation execution context."""
    if not isinstance(plan, ToolBatchPlan):
        raise TypeError("active tool batch plan must be a ToolBatchPlan")
    token = _ACTIVE_TOOL_BATCH_PLAN.set(plan)
    try:
        yield
    finally:
        _ACTIVE_TOOL_BATCH_PLAN.reset(token)


def get_active_tool_batch_plan() -> ToolBatchPlan | None:
    return _ACTIVE_TOOL_BATCH_PLAN.get()


@dataclass(frozen=True, slots=True)
class ToolBatchOutcome:
    terminal: TerminalToolDirective | None = None
    tool_name: str | None = None
    tool_call_id: str | None = None

    def __post_init__(self) -> None:
        if self.terminal is None:
            if self.tool_name is not None or self.tool_call_id is not None:
                raise ValueError("terminal identity requires a terminal directive")
            return
        _bounded_text(self.tool_name, "terminal tool name", 128)
        _bounded_text(self.tool_call_id, "terminal tool call id", 256)


def validate_tool_execution_result(value: Any) -> str | None:
    """Return a bounded validation error for a forged/malformed envelope."""

    if not isinstance(value, ToolExecutionResult):
        return None
    try:
        _bounded_text(value.content, "terminal tool content", MAX_TERMINAL_CONTENT_CHARS)
        if value.terminal is not None:
            if not isinstance(value.terminal, TerminalToolDirective):
                raise TypeError("terminal must be a TerminalToolDirective")
            _bounded_text(
                value.terminal.final_response,
                "terminal final_response",
                MAX_TERMINAL_FINAL_RESPONSE_CHARS,
            )
            _machine_value(
                value.terminal.status, "terminal status", MAX_TERMINAL_STATUS_CHARS
            )
            _machine_value(
                value.terminal.reason, "terminal reason", MAX_TERMINAL_REASON_CHARS
            )
            if _immutable_metadata(value.terminal.metadata) != value.terminal.metadata:
                raise ValueError("terminal metadata is not canonical")
    except (AttributeError, TypeError, ValueError) as exc:
        return bounded_terminal_error(f"invalid terminal tool result: {exc}")
    return None


def terminal_safe_failure(
    reason: str,
    *,
    metadata: tuple[tuple[str, str], ...] | Mapping[str, str] = (),
) -> ToolExecutionResult:
    detail = {
        "terminal_handler_error": "terminal-capable handler failed after it started",
        "terminal_processing_error": "terminal tool processing failed after handler entry",
        "terminal_persistence_error": "terminal outcome persistence failed after handler entry",
        "terminal_result_invalid": "terminal-capable handler returned an invalid result",
        "terminal_result_missing": "terminal-capable handler returned no terminal control",
    }.get(reason, "terminal-capable handler could not be verified")
    return ToolExecutionResult(
        content=bounded_terminal_error(detail),
        terminal=TerminalToolDirective(
            final_response=TERMINAL_SAFE_FAILURE_FINAL_RESPONSE,
            status="safe_failure",
            reason=reason,
            metadata=metadata,
        ),
    )


def bounded_terminal_error(message: str) -> str:
    text = " ".join(str(message).split())[:MAX_TERMINAL_ERROR_CHARS]
    while True:
        result = json.dumps({"error": text}, ensure_ascii=False)
        if len(result) <= MAX_TERMINAL_ERROR_CHARS:
            return result
        text = text[: max(0, len(text) - (len(result) - MAX_TERMINAL_ERROR_CHARS))]


def split_tool_execution_result(
    value: Any,
) -> tuple[Any, TerminalToolDirective | None]:
    if not isinstance(value, ToolExecutionResult):
        return value, None
    error = validate_tool_execution_result(value)
    if error is not None:
        return error, None
    return value.content, value.terminal


__all__ = [
    "MAX_TERMINAL_CONTENT_CHARS",
    "MAX_TERMINAL_ERROR_CHARS",
    "MAX_TERMINAL_FINAL_RESPONSE_CHARS",
    "MAX_TERMINAL_METADATA_ITEMS",
    "MAX_TERMINAL_REASON_CHARS",
    "MAX_TERMINAL_STATUS_CHARS",
    "PlannedToolCall",
    "TerminalToolCapability",
    "TerminalToolDirective",
    "TerminalToolInvocation",
    "ToolBatchOutcome",
    "ToolBatchPlan",
    "ToolExecutionResult",
    "bind_tool_batch_plan",
    "bounded_terminal_error",
    "get_active_tool_batch_plan",
    "split_tool_execution_result",
    "terminal_safe_failure",
    "validate_tool_execution_result",
]
