"""Dormant terminal tool for host-configured private-read requests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from agent.tool_outcomes import (
    TerminalToolDirective,
    ToolExecutionResult,
    terminal_safe_failure,
)
from gateway.private_read_authorization import (
    MAX_CAPABILITY_ID_BYTES,
    PrivateReadAuthorizationOrchestrator,
    PrivateReadProposal,
    PrivateReadRequestRuntime,
    TrustedPrivateReadHostContext,
)
from tools.registry import registry


PRIVATE_READ_REQUEST_TOOL_NAME = "private_read_request"
_GENERIC_DEFERRED_CONTENT = json.dumps(
    {"status": "deferred", "reason": "approval_required"},
    sort_keys=True,
    separators=(",", ":"),
)
_GENERIC_DEFERRED_FINAL = (
    "The private read request requires approval and was deferred safely."
)
_GENERIC_ACCEPTED_CONTENT = json.dumps(
    {"status": "accepted"}, sort_keys=True, separators=(",", ":")
)
_GENERIC_ACCEPTED_FINAL = "The private read request was accepted safely."


def configure_private_read_request_runtime(
    runtime: PrivateReadRequestRuntime | None,
    *,
    health_check=None,
) -> None:
    """Atomically install or remove complete trusted host configuration."""
    if runtime is not None and type(runtime) is not PrivateReadRequestRuntime:
        raise TypeError("private read request runtime has an invalid type")
    if health_check is not None and not callable(health_check):
        raise TypeError("private read request health check must be callable")
    _register_runtime(runtime, health_check=health_check)


def configure_private_read_mvp_handler(handler, *, health_check=None) -> None:
    """Install the code-owned MVP handler without exposing config callbacks."""
    if handler is not None and not callable(handler):
        raise TypeError("private read MVP handler must be callable")
    if health_check is not None and not callable(health_check):
        raise TypeError("private read MVP health check must be callable")
    if handler is None:
        _register_runtime(None)
        return
    bound = _RuntimeBoundMvpHandler(handler, health_check)
    registry._register_host_terminal_tool(
        name=PRIVATE_READ_REQUEST_TOOL_NAME,
        toolset="private-read-request",
        schema=PRIVATE_READ_REQUEST_SCHEMA,
        handler=bound,
        check_fn=bound.available,
        description="Create a payload-free private-read request",
        emoji="🔐",
    )


def check_private_read_request_runtime() -> bool:
    entry = registry.get_entry(PRIVATE_READ_REQUEST_TOOL_NAME)
    if entry is None or not (
        entry.terminal_eligible and entry.terminal_handler is entry.handler
    ):
        return False
    check_fn = entry.check_fn
    return bool(check_fn is not None and check_fn())


def _private_read_request_for_runtime(
    runtime: PrivateReadRequestRuntime | None,
    args: object,
    *,
    tool_call_id: str | None,
) -> ToolExecutionResult:
    """Create pending state using one immutable registration-time runtime."""
    try:
        if runtime is None or not runtime.enabled:
            return terminal_safe_failure("terminal_handler_error")
        proposal = PrivateReadProposal.from_model_args(args)
        capability = runtime.capabilities.resolve(proposal.capability_id)
        context = runtime.host_contexts.current()
        if type(context) is not TrustedPrivateReadHostContext:
            return terminal_safe_failure("terminal_handler_error")
        pending = PrivateReadAuthorizationOrchestrator(
            runtime.store,
            id_hmac_key=runtime.id_hmac_key,
        ).create_pending(
            capability,
            host_context=context,
            tool_call_id=tool_call_id,
        )
        return ToolExecutionResult(
            content=_GENERIC_DEFERRED_CONTENT,
            terminal=TerminalToolDirective(
                final_response=_GENERIC_DEFERRED_FINAL,
                status="deferred",
                reason="approval_required",
                metadata={
                    "task_id": pending.task_id,
                    "correlation_id": pending.correlation_id,
                },
            ),
        )
    except BaseException:
        # Do not format or log context/store exceptions. They may contain
        # sensitive provider material; the terminal seal receives fixed text.
        return terminal_safe_failure("terminal_handler_error")


@dataclass(frozen=True, slots=True, eq=False)
class _RuntimeBoundPrivateReadHandler:
    """Exact runtime and handler identity committed in one registry entry."""

    runtime: PrivateReadRequestRuntime | None = field(repr=False)
    health_check: object = field(default=None, repr=False)

    def healthy(self) -> bool:
        if self.health_check is None:
            return True
        try:
            return self.health_check() is True
        except BaseException:
            return False

    def available(self) -> bool:
        runtime = self.runtime
        return bool(
            runtime is not None
            and runtime.enabled
            and self.healthy()
            and len(runtime.capabilities.capabilities) > 0
        )

    def __call__(
        self,
        args: object,
        *,
        tool_call_id: str | None = None,
        **_host_kwargs: object,
    ) -> ToolExecutionResult:
        if not self.healthy():
            return terminal_safe_failure("terminal_handler_error")
        return _private_read_request_for_runtime(
            self.runtime,
            args,
            tool_call_id=tool_call_id,
        )


@dataclass(frozen=True, slots=True, eq=False)
class _RuntimeBoundMvpHandler:
    handler: object = field(repr=False)
    health_check: object = field(default=None, repr=False)

    def available(self) -> bool:
        try:
            return self.health_check is None or self.health_check() is True
        except BaseException:
            return False

    def __call__(self, args: object, *, tool_call_id: str | None = None,
                 **_host_kwargs: object) -> ToolExecutionResult:
        del tool_call_id
        try:
            proposal = PrivateReadProposal.from_model_args(args)
            if not self.available():
                return terminal_safe_failure("terminal_handler_error")
            outcome = self.handler(proposal.capability_id)
            if type(outcome) is not tuple or len(outcome) != 2:
                return terminal_safe_failure("terminal_handler_error")
            status, request_id = outcome
            if type(status) is not str or type(request_id) is not str or not request_id:
                return terminal_safe_failure("terminal_handler_error")
            if status == "approved":
                return ToolExecutionResult(
                    content=_GENERIC_ACCEPTED_CONTENT,
                    terminal=TerminalToolDirective(
                        final_response=_GENERIC_ACCEPTED_FINAL,
                        status="accepted",
                        reason="queued",
                        metadata={"request_id": request_id},
                    ),
                )
            if status == "pending":
                return ToolExecutionResult(
                    content=_GENERIC_DEFERRED_CONTENT,
                    terminal=TerminalToolDirective(
                        final_response=_GENERIC_DEFERRED_FINAL,
                        status="deferred",
                        reason="approval_required",
                        metadata={"request_id": request_id},
                    ),
                )
            return terminal_safe_failure("terminal_handler_error")
        except BaseException:
            return terminal_safe_failure("terminal_handler_error")

PRIVATE_READ_REQUEST_SCHEMA = {
    "name": PRIVATE_READ_REQUEST_TOOL_NAME,
    "description": (
        "Request approval for one host-configured private-read capability. "
        "The trusted host selects every request detail."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "capability_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_CAPABILITY_ID_BYTES,
            },
        },
        "required": ["capability_id"],
    },
}


def _register_runtime(runtime: PrivateReadRequestRuntime | None, *, health_check=None) -> None:
    """Commit a runtime-bound handler and its generation under registry authority."""
    handler = _RuntimeBoundPrivateReadHandler(runtime, health_check)
    registry._register_host_terminal_tool(
        name=PRIVATE_READ_REQUEST_TOOL_NAME,
        toolset="private-read-request",
        schema=PRIVATE_READ_REQUEST_SCHEMA,
        handler=handler,
        check_fn=handler.available,
        description="Create a payload-free pending private-read authorization task",
        emoji="🔐",
    )


_DORMANT_HANDLER = _RuntimeBoundPrivateReadHandler(None)
registry._register_host_terminal_tool(
    name=PRIVATE_READ_REQUEST_TOOL_NAME,
    toolset="private-read-request",
    schema=PRIVATE_READ_REQUEST_SCHEMA,
    handler=_DORMANT_HANDLER,
    check_fn=_DORMANT_HANDLER.available,
    description="Create a payload-free pending private-read authorization task",
    emoji="🔐",
)


__all__ = [
    "PRIVATE_READ_REQUEST_SCHEMA",
    "PRIVATE_READ_REQUEST_TOOL_NAME",
    "check_private_read_request_runtime",
    "configure_private_read_mvp_handler",
    "configure_private_read_request_runtime",
]
