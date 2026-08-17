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
import re
import subprocess
from datetime import datetime, timedelta
from typing import Any, Callable

from .private_reads import (
    _DATE_HELP,
    THINGS_PROJECT_TITLE,
    THINGS_PROJECT_UUID,
    SourceFailure,
    _normalise_date,
    canonical_json,
)

# Only what is registered here can ever be classified mutating, so a tool that
# sends rather than drafts, or deletes rather than adds, is not refused by
# instruction -- it simply is not here.
ACTION_TOOL_NAMES: tuple[str, ...] = (
    "kite_things_add_task",
    "kite_calendar_add_event",
    "kite_gmail_create_draft",
)
ACTION_TOOLSET = "juno_kite_actions"

_TITLE_MAX = 200
_NOTES_MAX = 2000
_SUBJECT_MAX = 300
_BODY_MAX = 20000
_RECIPIENTS_MAX = 10
_DEFAULT_EVENT_MINUTES = 60
# A syntactic check only. Whether an address is the *right* one is a question
# no regex answers, which is exactly why a draft is never sent from here.
_EMAIL_RE = re.compile(r"[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+")

# Scheduling was held back while two upstream faults made it unsafe: the MCP
# server reported every scheduled item a day early under BST (a UTC timestamp
# sliced instead of converted), and the client then asserted a Today-list
# membership the server never reports at all. Both are fixed, so a task can
# carry a day again. Verified end to end on 2026-08-17: "today" stores today,
# and the call now exits clean rather than through failure recovery.
_WHEN_LISTS = ("today", "tomorrow", "evening", "anytime", "someday")

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
                "when": {
                    "type": "string", "maxLength": 40,
                    "description": (
                        "When to put it on the list: "
                        + ", ".join(_WHEN_LISTS)
                        + ", or a specific day. " + _DATE_HELP
                        + " Omit to leave it unscheduled in the project."
                    ),
                },
            },
        },
    },
    "kite_calendar_add_event": {
        "description": (
            "Put one event on the household calendar. It goes on the calendar "
            "and nowhere else: this cannot invite anyone, because inviting "
            "people is sending mail on someone's behalf. Give a start time; "
            "an event with no end runs for an hour."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["title", "start"],
            "properties": {
                "title": {
                    "type": "string", "minLength": 1, "maxLength": _TITLE_MAX,
                    "description": "What the event is.",
                },
                "start": {
                    "type": "string",
                    "description": "When it starts. " + _DATE_HELP,
                },
                "end": {
                    "type": "string",
                    "description": "When it ends. Omit for one hour.",
                },
                "location": {
                    "type": "string", "maxLength": _TITLE_MAX,
                    "description": "Where it is.",
                },
                "notes": {
                    "type": "string", "maxLength": _NOTES_MAX,
                    "description": "Anything else worth having to hand.",
                },
            },
        },
    },
    "kite_gmail_create_draft": {
        "description": (
            "Write an email draft and leave it in Drafts. This never sends: "
            "James presses Send himself, in Gmail. Say that the draft is "
            "waiting rather than implying the mail has gone."
        ),
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["to", "subject", "body"],
            "properties": {
                "to": {
                    "type": "string",
                    "description": "Recipient address, or several separated by commas.",
                },
                "subject": {
                    "type": "string", "minLength": 1, "maxLength": _SUBJECT_MAX,
                    "description": "Subject line.",
                },
                "body": {
                    "type": "string", "minLength": 1, "maxLength": _BODY_MAX,
                    "description": "The message, as plain text.",
                },
                "cc": {
                    "type": "string",
                    "description": "Anyone to copy, separated by commas.",
                },
                "account": {
                    "type": "string", "enum": ["personal", "kite"],
                    "description": "Which mailbox to draft in. Defaults to personal.",
                },
            },
        },
    },
}


def _instant(value: str) -> datetime:
    """Compare a day and a timestamp on the same footing."""
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise SourceFailure("invalid_arguments", f"{value} is not a time") from None
    return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed


def _plus_default(start: str) -> str:
    """An event with no end runs an hour, or covers the whole day given a day.

    Google ends an all-day event on an *exclusive* date, so a single day ends
    on the following one. Getting this wrong produces a zero-length event that
    shows up nowhere -- an action that reports success and changes nothing.
    """
    if "T" not in start:
        return (_instant(start) + timedelta(days=1)).date().isoformat()
    ended = _instant(start) + timedelta(minutes=_DEFAULT_EVENT_MINUTES)
    return ended.isoformat(timespec="seconds")


def _local_offset(value: str) -> str:
    """Attach this machine's offset to a bare time.

    Google refuses a timed event with no zone ("Missing time zone definition
    for start time"). Someone asking for 10am means 10am where they are, so
    the host supplies what it knows rather than making the caller state it.
    Dates are left alone: an all-day event has no zone.
    """
    if "T" not in value:
        return value
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        return parsed.isoformat(timespec="seconds")
    return parsed.astimezone().isoformat(timespec="seconds")


def _schedule(raw: Any) -> str:
    """A named list, or any day the readers would have understood.

    The list names are checked first: "today" has to reach Things as the word,
    so it lands in the Today list rather than merely carrying today's date.
    Anything else goes through the same date vocabulary every reader accepts,
    so "the 25th", "+30d" and an ISO date all work here exactly as they do
    when asking a question. Offering a narrower language in the half that acts
    than in the half that reads is the kind of small inconsistency that costs
    a turn.
    """
    text = str(raw or "").strip()
    if not text:
        return ""
    if text.casefold() in _WHEN_LISTS:
        return text.casefold()
    # Not a list name, so it has to be a day. _normalise_date names what is
    # wrong with it if it is not.
    return _normalise_date(text, "when")


def _addresses(raw: Any, key: str, *, required: bool = True) -> list[str]:
    """Split and check recipients, naming the one that is wrong."""
    text = str(raw or "").strip()
    if not text:
        if required:
            raise SourceFailure("invalid_arguments", f"a draft needs a {key} address")
        return []
    found = [part.strip() for part in re.split(r"[,;]", text) if part.strip()]
    if len(found) > _RECIPIENTS_MAX:
        raise SourceFailure(
            "invalid_arguments",
            f"{key} has more than the {_RECIPIENTS_MAX} recipients allowed")
    for address in found:
        if _EMAIL_RE.fullmatch(address) is None:
            raise SourceFailure(
                "invalid_arguments",
                f"{address} in {key} is not an email address")
    return found


class ActionService:
    """Runs the small set of changes Juno is allowed to make."""

    def __init__(self, config: Any, *, command_runner: Callable[..., Any] | None = None,
                 timeout_seconds: int = 30) -> None:
        self.config = config if isinstance(config, dict) else {}
        self.command_runner = command_runner or subprocess.run
        self.timeout = int(timeout_seconds)

    _BACKENDS = {
        "kite_things_add_task": ("things", "client"),
        "kite_calendar_add_event": ("calendar", "executable"),
        "kite_gmail_create_draft": ("gmail", "executable"),
    }

    def _configured(self, source: str, key: str) -> bool:
        cfg = self.config.get(source)
        return isinstance(cfg, dict) and bool(cfg.get(key))

    @property
    def enabled(self) -> bool:
        return bool(self.tool_names)

    @property
    def tool_names(self) -> tuple[str, ...]:
        # Per backend, not all-or-nothing: a host with a calendar and no
        # Things client should offer the calendar action rather than nothing,
        # and must not offer an action whose backend it cannot reach.
        return tuple(
            name for name in ACTION_TOOL_NAMES
            if self._configured(*self._BACKENDS[name])
        )

    def schema_for(self, tool_name: str) -> dict[str, Any]:
        return ACTION_SCHEMAS[tool_name]

    def execute(self, tool_name: str, args: dict[str, Any]) -> str:
        handlers = {
            "kite_things_add_task": self._add_task,
            "kite_calendar_add_event": self._add_event,
            "kite_gmail_create_draft": self._create_draft,
        }
        handler = handlers.get(tool_name)
        if handler is None or tool_name not in self.tool_names:
            return canonical_json(
                {"status": "error", "error": {
                    "code": "operation_denied",
                    "message": f"{tool_name} is not an action this host performs",
                    "retryable": False}})
        try:
            self._reject_unknown(tool_name, args)
            return canonical_json(handler(dict(args)))
        except SourceFailure as exc:
            return canonical_json({"status": "error", "error": {
                "code": exc.code, "message": exc.message,
                "retryable": exc.retryable}})

    def _reject_unknown(self, tool_name: str, args: dict[str, Any]) -> None:
        """An argument this action does not implement is refused, not dropped.

        Quietly ignoring one answers "done" to someone who asked for something
        that did not happen -- a schedule that never took, a recipient never
        copied.
        """
        allowed = set(ACTION_SCHEMAS[tool_name]["parameters"]["properties"])
        unexpected = sorted(set(args) - allowed)
        if unexpected:
            raise SourceFailure(
                "invalid_arguments",
                f"this action does not take {', '.join(unexpected)}; it takes "
                f"{', '.join(sorted(allowed))}")

    def _google(self, source: str, alias: str) -> tuple[str, str]:
        cfg = self.config.get(source)
        if not isinstance(cfg, dict):
            raise SourceFailure(
                "backend_unavailable", f"{source} is not configured", True)
        executable = str(cfg.get("executable") or "")
        aliases = cfg.get("account_aliases")
        if not executable.startswith("/") or not isinstance(aliases, dict):
            raise SourceFailure(
                "backend_unavailable", f"the {source} command boundary is invalid")
        fixed = str(aliases.get(alias) or "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", fixed):
            raise SourceFailure(
                "account_denied", f"{alias} is not a configured {source} account")
        return executable, fixed

    def _add_event(self, args: dict[str, Any]) -> dict[str, Any]:
        title = str(args.get("title") or "").strip()
        if not title or len(title) > _TITLE_MAX:
            raise SourceFailure(
                "invalid_arguments",
                f"an event needs a title of 1 to {_TITLE_MAX} characters")
        start = _normalise_date(str(args.get("start") or ""), "start",
                                allow_time=True)
        end_raw = str(args.get("end") or "").strip()
        if end_raw:
            end = _normalise_date(end_raw, "end", allow_time=True)
        else:
            end = _plus_default(start)
        if _instant(end) <= _instant(start):
            raise SourceFailure(
                "invalid_arguments", "an event has to end after it starts")
        # An end date the caller named is the last day they mean, but Google
        # reads it as the first day they do not.
        if end_raw and "T" not in end:
            end = (_instant(end) + timedelta(days=1)).date().isoformat()
        start, end = _local_offset(start), _local_offset(end)

        executable, alias = self._google("calendar", "personal")
        calendar_ids = (self.config.get("calendar") or {}).get("calendar_ids") or {}
        calendar_id = str(calendar_ids.get("personal") or "primary")
        argv = [executable, alias, "api", "calendar", "create",
                "--summary", title, "--start", start, "--end", end,
                "--calendar", calendar_id]
        location = str(args.get("location") or "").strip()
        if location:
            argv += ["--location", location]
        notes = str(args.get("notes") or "").strip()
        if notes:
            if len(notes) > _NOTES_MAX:
                raise SourceFailure(
                    "invalid_arguments",
                    f"notes are longer than the {_NOTES_MAX} characters allowed")
            argv += ["--description", notes]
        # No --attendees, ever. The flag exists on the underlying command and
        # using it would email an invitation, which is sending mail on James's
        # behalf under another name. An event lands on the calendar; telling
        # anyone about it stays a human act.
        completed = self._run(argv)
        if completed.returncode != 0:
            raise SourceFailure(
                "action_failed",
                "the calendar refused the event and it was not created", False)
        return {
            "status": "ok",
            "outcome": "created",
            "title": title,
            "start": start,
            "end": end,
            "invited": [],
            "say": f'Put "{title}" on the calendar for {start}.',
        }

    def _create_draft(self, args: dict[str, Any]) -> dict[str, Any]:
        to = _addresses(args.get("to"), "to")
        cc = _addresses(args.get("cc"), "cc", required=False)
        subject = str(args.get("subject") or "").strip()
        if not subject or len(subject) > _SUBJECT_MAX:
            raise SourceFailure(
                "invalid_arguments",
                f"a draft needs a subject of 1 to {_SUBJECT_MAX} characters")
        body = str(args.get("body") or "").strip()
        if not body or len(body) > _BODY_MAX:
            raise SourceFailure(
                "invalid_arguments",
                f"a draft needs a body of 1 to {_BODY_MAX} characters")
        account = str(args.get("account") or "personal").strip() or "personal"
        executable, alias = self._google("gmail", account)

        argv = [executable, alias, "api", "gmail", "draft",
                "--to", ", ".join(to), "--subject", subject, "--body", body]
        if cc:
            argv += ["--cc", ", ".join(cc)]
        completed = self._run(argv)
        if completed.returncode != 0:
            raise SourceFailure(
                "action_failed",
                "the mailbox refused the draft and nothing was written", False)
        return {
            "status": "ok",
            "outcome": "drafted",
            "sent": False,
            "to": to,
            "cc": cc,
            "subject": subject,
            # Said so a turn cannot imply the mail has gone. It has not, and
            # the difference matters more here than anywhere else.
            "say": f'Left a draft to {", ".join(to)} in {account} Drafts, '
                   f'subject "{subject}". It has not been sent -- '
                   "press Send in Gmail when you are happy with it.",
        }

    def _add_task(self, args: dict[str, Any]) -> dict[str, Any]:
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
        when = _schedule(args.get("when"))
        if when:
            payload["when"] = when

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
            "when": when or None,
            # Said plainly so the turn can report a real change in the words
            # the person used, rather than announcing that something happened.
            "say": f'Added "{title}" to the {THINGS_PROJECT_TITLE}'
                   + (f" for {when}." if when else "."),
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
