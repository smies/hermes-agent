"""The things Juno may do, as opposed to the things it may read.

Reading and acting are separate authorities. A reader answers a question and
costs an answer when it refuses; an action changes the world and cannot be
taken back by asking again. So the rules are different in one specific way:
what may be done is described in policy as a shape, checked against the
capability the turn actually holds, and claimed once so the same approval
cannot be spent twice.

What is *not* different: an action that fails should say why, and a refusal
should say what to do instead. The same lesson the readers learned all week.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any, Callable

from .private_reads import (
    THINGS_PROJECT_TITLE,
    THINGS_PROJECT_UUID,
    SourceFailure,
    canonical_json,
)

# Only what is registered here can ever be classified mutating, so a tool that
# sends rather than drafts, or deletes rather than adds, is not refused by
# instruction -- it simply is not here.
ACTION_TOOL_NAMES: tuple[str, ...] = ("kite_things_add_task",)
ACTION_TOOLSET = "juno_kite_actions"

_TITLE_MAX = 200
_NOTES_MAX = 2000

# Scheduling is deliberately absent. `when` works through the client, but the
# date it lands on is a day early -- asking for "today" on 2026-08-15 stored a
# start date of 2026-08-14, and the client's own postcondition caught the
# disagreement. A task filed on the wrong day is worse than one filed on no
# day, so this adds to the list and leaves scheduling to the person until the
# date handling upstream is fixed.

ACTION_SCHEMAS: dict[str, dict[str, Any]] = {
    "kite_things_add_task": {
        "description": (
            "Add one task to the household's Personal Action List. The list is "
            "fixed: a task cannot be filed anywhere else. Adding a task is "
            "undoable in a second, so it needs no approval -- but it is a real "
            "change, so say what was added."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["title"],
            "properties": {
                "title": {
                    "type": "string", "minLength": 1, "maxLength": _TITLE_MAX,
                    "description": "What the task is, in the words it was asked for.",
                },
                "notes": {
                    "type": "string", "maxLength": _NOTES_MAX,
                    "description": "Anything needed to act on it later.",
                },
            },
        },
    },
}


class ActionService:
    """Runs the small set of changes Juno is allowed to make."""

    def __init__(self, config: Any, *, command_runner: Callable[..., Any] | None = None,
                 timeout_seconds: int = 30) -> None:
        self.config = config if isinstance(config, dict) else {}
        self.command_runner = command_runner or subprocess.run
        self.timeout = int(timeout_seconds)

    @property
    def enabled(self) -> bool:
        things = self.config.get("things")
        return isinstance(things, dict) and bool(things.get("client"))

    @property
    def tool_names(self) -> tuple[str, ...]:
        return ACTION_TOOL_NAMES if self.enabled else ()

    def schema_for(self, tool_name: str) -> dict[str, Any]:
        return ACTION_SCHEMAS[tool_name]

    def execute(self, tool_name: str, args: dict[str, Any]) -> str:
        if tool_name != "kite_things_add_task":
            return canonical_json(
                {"status": "error", "error": {
                    "code": "operation_denied",
                    "message": f"{tool_name} is not an action this host performs",
                    "retryable": False}})
        try:
            return canonical_json(self._add_task(dict(args)))
        except SourceFailure as exc:
            return canonical_json({"status": "error", "error": {
                "code": exc.code, "message": exc.message,
                "retryable": exc.retryable}})

    def _add_task(self, args: dict[str, Any]) -> dict[str, Any]:
        # An argument this action does not implement must be refused, not
        # dropped. Quietly ignoring `when` would answer "Added" to someone who
        # asked for it tomorrow, and they would believe the date took.
        allowed = set(ACTION_SCHEMAS["kite_things_add_task"]["parameters"]
                      ["properties"])
        unexpected = sorted(set(args) - allowed)
        if unexpected:
            raise SourceFailure(
                "invalid_arguments",
                f"this action does not take {', '.join(unexpected)}; it takes "
                f"{', '.join(sorted(allowed))}")
        title = str(args.get("title") or "").strip()
        if not title or len(title) > _TITLE_MAX:
            raise SourceFailure(
                "invalid_arguments",
                f"a task needs a title of 1 to {_TITLE_MAX} characters")
        payload: dict[str, Any] = {"title": title, "list_id": THINGS_PROJECT_UUID}
        notes = str(args.get("notes") or "").strip()
        if notes:
            if len(notes) > _NOTES_MAX:
                raise SourceFailure(
                    "invalid_arguments",
                    f"notes are longer than the {_NOTES_MAX} characters allowed")
            payload["notes"] = notes

        completed = self._call("add_todo", payload)
        output = f"{completed.stdout or ''}\n{completed.stderr or ''}"
        if completed.returncode != 0:
            # The list has its own mutual exclusion: while a reconciliation run
            # is in flight, nobody else may write. That is a wait, not a
            # refusal, and saying so is the difference between "ask again in a
            # minute" and "you may not do this".
            if "reconciliation lease" in output or "another worker" in output:
                # Nothing was written: the lease is taken before any change.
                raise SourceFailure(
                    "list_busy",
                    "the action list is being reconciled right now, so it did "
                    "not take the task; asking again shortly will work",
                    True)
            # A non-zero exit does not mean nothing happened. The first live
            # run of this action proved it: the client wrote the task, checked
            # its own postcondition, disagreed, and exited non-zero -- and the
            # action told the caller it "was not added". A person reading that
            # adds it again, and now the list has it twice.
            #
            # So do not guess from an exit code what only the list can say.
            return self._outcome_after_failure(title, output)
        return {
            "status": "ok",
            "outcome": "added",
            "list": THINGS_PROJECT_TITLE,
            "title": title,
            # Said plainly so the turn can report a real change in the words
            # the person used, rather than announcing that something happened.
            "say": f'Added "{title}" to the {THINGS_PROJECT_TITLE}.',
        }

    def _outcome_after_failure(self, title: str, output: str) -> dict[str, Any]:
        """Ask the list what is actually there, rather than assuming."""
        try:
            found = self._task_exists(title)
        except Exception:
            found = None
        if found is True:
            return {
                "status": "ok",
                "outcome": "added",
                "list": THINGS_PROJECT_TITLE,
                "title": title,
                "confirmed_by": "lookup",
                "say": f'Added "{title}" to the {THINGS_PROJECT_TITLE}.',
            }
        if found is False:
            raise SourceFailure(
                "action_failed",
                "the action list refused the task and it was not added", False)
        raise SourceFailure(
            "action_uncertain",
            # The one case where uncertainty is the honest answer. Say which
            # way to check, and do not invite a blind retry that duplicates.
            f'the list did not confirm "{title}" and could not be checked; it '
            "may or may not have been added, so look at the list before adding "
            "it again",
            False)

    def _task_exists(self, title: str) -> bool:
        completed = self._call_search(title)
        if completed.returncode != 0:
            raise SourceFailure("lookup_failed", "the list could not be read")
        rows = json.loads(completed.stdout or "[]")
        return any(str(row.get("title") or "") == title for row in rows)

    def _client_argv(self, *rest: str) -> list[str]:
        things = self.config.get("things") or {}
        return [str(things["client"]), "--url", str(things["endpoint"]),
                "--timeout", str(self.timeout), *rest]

    def _call(self, operation: str, payload: dict[str, Any]) -> Any:
        return self._run(self._client_argv(
            "call", operation, json.dumps(payload, sort_keys=True)))

    def _call_search(self, title: str) -> Any:
        return self._run(self._client_argv(
            "search", "--query", title, "--project", THINGS_PROJECT_TITLE,
            "--json"))

    def _run(self, argv: list[str]) -> Any:
        return self.command_runner(
            argv, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=self.timeout)


def action_handlers_for(service: ActionService) -> dict[str, Callable[..., str]]:
    handlers: dict[str, Callable[..., str]] = {}
    for tool_name in service.tool_names:
        def handler(args: dict[str, Any], *, _name: str = tool_name, **_: Any) -> str:
            return service.execute(_name, args)
        handler.__name__ = f"handle_{tool_name}"
        handlers[tool_name] = handler
    return handlers


__all__ = ["ACTION_TOOLSET", "ACTION_TOOL_NAMES", "ACTION_SCHEMAS", "ActionService",
           "action_handlers_for"]
