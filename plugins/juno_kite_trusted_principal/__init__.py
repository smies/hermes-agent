"""Generic Juno--Kite trusted-principal Hermes plugin."""

from __future__ import annotations

from .runtime import TrustedPrincipalRuntime, runtime_from_host


TOOL_DESCRIPTION = (
    "Consult Kite only after using the current principal-isolated Juno session, "
    "Juno's safe local context, and direct public tools first. Use this bounded "
    "surface only when those are insufficient or Kite's private authority is "
    "required. Authority, identity, peer, URL, and conversation mapping are "
    "host-bound and cannot be supplied in tool arguments."
)


def _schema(runtime) -> dict:
    limits = runtime.limits
    return {
        "description": TOOL_DESCRIPTION,
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "question_or_goal": {
                    "type": "string",
                    "maxLength": limits.question_chars,
                    "description": "The bounded question or goal that specifically requires Kite.",
                },
                "relevant_context": {
                    "type": "array",
                    "maxItems": limits.context_turns,
                    "description": "Optional minimal relevant Juno turns; never a whole transcript.",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "role": {"type": "string", "enum": ["user", "assistant"]},
                            "text": {"type": "string", "maxLength": limits.context_turn_chars},
                        },
                        "required": ["role", "text"],
                    },
                },
            },
            "required": ["question_or_goal"],
        },
    }


def register(ctx) -> None:
    runtime = runtime_from_host(ctx.profile_name)

    # Register all policy hooks in either mode.  They are no-ops on ordinary
    # human turns, but keep an accidentally received A2A turn fail-closed when
    # a profile/mode/configuration mismatch occurs.
    ctx.register_hook("pre_llm_call", runtime.pre_llm_call)
    ctx.register_hook("pre_gateway_dispatch", runtime.pre_gateway_dispatch)
    ctx.register_hook("pre_tool_call", runtime.pre_tool_call)
    ctx.register_hook("pre_tool_dispatch", runtime.pre_tool_dispatch)
    ctx.register_hook("transform_llm_output", runtime.transform_llm_output)

    if runtime.mode == "juno":
        schema = _schema(runtime)
        ctx.register_tool(
            name="consult_kite",
            toolset="juno_kite",
            schema=schema,
            handler=runtime.consult_kite,
            check_fn=runtime.juno_available,
            description=TOOL_DESCRIPTION,
            emoji="🪁",
        )


__all__ = ["TrustedPrincipalRuntime", "register", "runtime_from_host"]
