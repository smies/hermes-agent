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


def configure_private_read_request_runtime(
    runtime: PrivateReadRequestRuntime | None,
) -> None:
    """Atomically install or remove complete trusted host configuration."""
    if runtime is not None and type(runtime) is not PrivateReadRequestRuntime:
        raise TypeError("private read request runtime has an invalid type")
    _register_runtime(runtime)


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

    def available(self) -> bool:
        runtime = self.runtime
        return bool(
            runtime is not None
            and runtime.enabled
            and len(runtime.capabilities.capabilities) > 0
        )

    def __call__(
        self,
        args: object,
        *,
        tool_call_id: str | None = None,
        **_host_kwargs: object,
    ) -> ToolExecutionResult:
        return _private_read_request_for_runtime(
            self.runtime,
            args,
            tool_call_id=tool_call_id,
        )


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


def _register_runtime(runtime: PrivateReadRequestRuntime | None) -> None:
    """Commit a runtime-bound handler and its generation under registry authority."""
    handler = _RuntimeBoundPrivateReadHandler(runtime)
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
    "configure_private_read_request_runtime",
]
