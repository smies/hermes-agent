#!/usr/bin/env python3
"""Quick Tunnel supervisor and transactional Twilio Voice URL updater.

No mutation occurs unless ``supervise --apply`` is explicit.  Credentials are
read from the process environment or an owner-selected dotenv file and are
never placed in argv, state, or logs.  The updater only writes VoiceUrl and
VoiceMethod on the exact discovered voice-capable IncomingPhoneNumber SIDs.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import queue
import re
import signal
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from .security import atomic_owner_only_write, public_endpoint, redact_url, valid_sid

logger = logging.getLogger("twilio_voice_supervisor")
API_ROOT = "https://api.twilio.com"
VOICE_PATH = "/twilio/voice"
_TUNNEL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com", re.IGNORECASE)


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _load_dotenv(path: Path) -> dict[str, str]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeError("dotenv file is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("dotenv path is not a regular file")
    if info.st_mode & 0o077:
        raise RuntimeError("dotenv file is not owner-only")
    try:
        from dotenv import dotenv_values

        return {str(k): str(v) for k, v in dotenv_values(path).items() if v is not None}
    except ImportError:
        values: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip("'\"")
        return values


def _credentials(env_file: Path | None) -> tuple[str, str]:
    values: dict[str, str] = {}
    if env_file:
        values.update(_load_dotenv(env_file.expanduser()))
    account = os.environ.get("TWILIO_ACCOUNT_SID") or values.get("TWILIO_ACCOUNT_SID", "")
    token = os.environ.get("TWILIO_AUTH_TOKEN") or values.get("TWILIO_AUTH_TOKEN", "")
    if not valid_sid(account, "AC") or not token:
        raise RuntimeError("Twilio credentials are unavailable")
    return account, token


@dataclass(frozen=True)
class VoiceNumber:
    sid: str
    voice_url: str
    voice_method: str
    voice_application_sid: str


class TwilioApi:
    def __init__(self, account_sid: str, auth_token: str, opener: Callable | None = None):
        self.account_sid = account_sid
        self._auth_token = auth_token
        self._opener = opener or build_opener(_RejectRedirects()).open

    def request(self, method: str, path_or_url: str, form: dict[str, str] | None = None) -> dict:
        url = path_or_url if path_or_url.startswith("https://") else API_ROOT + path_or_url
        if not url.startswith(API_ROOT + "/"):
            raise RuntimeError("Twilio pagination left the API origin")
        data = urlencode(form).encode("utf-8") if form is not None else None
        request = Request(url, data=data, method=method)
        basic = base64.b64encode(f"{self.account_sid}:{self._auth_token}".encode()).decode()
        request.add_header("Authorization", "Basic " + basic)
        if data is not None:
            request.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with self._opener(request, timeout=15) as response:
                raw = response.read()
        except (HTTPError, URLError, TimeoutError) as exc:
            raise RuntimeError(f"Twilio API request failed ({type(exc).__name__})") from exc
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError("Twilio API returned an invalid response") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Twilio API returned an unexpected response")
        return payload

    def voice_numbers(self) -> list[VoiceNumber]:
        path = f"/2010-04-01/Accounts/{self.account_sid}/IncomingPhoneNumbers.json?PageSize=1000"
        found: list[VoiceNumber] = []
        for _ in range(10):
            payload = self.request("GET", path)
            rows = payload.get("incoming_phone_numbers") or []
            if not isinstance(rows, list):
                raise RuntimeError("Twilio number list is malformed")
            for row in rows:
                if not isinstance(row, dict):
                    continue
                capabilities = row.get("capabilities") or {}
                voice_capable = capabilities.get("voice") is True or capabilities.get("voice") == "true"
                if not voice_capable:
                    continue
                sid = str(row.get("sid") or "")
                if not valid_sid(sid, "PN"):
                    raise RuntimeError("Twilio returned an invalid number SID")
                found.append(
                    VoiceNumber(
                        sid=sid,
                        voice_url=str(row.get("voice_url") or ""),
                        voice_method=str(row.get("voice_method") or "POST").upper(),
                        voice_application_sid=str(row.get("voice_application_sid") or ""),
                    )
                )
            next_uri = payload.get("next_page_uri")
            if not next_uri:
                if len({number.sid for number in found}) != len(found):
                    raise RuntimeError("Twilio returned duplicate number resources")
                return found
            path = str(next_uri)
        raise RuntimeError("Twilio number pagination exceeded its bound")

    def update_voice(self, sid: str, *, voice_url: str, voice_method: str) -> None:
        if not valid_sid(sid, "PN"):
            raise RuntimeError("refusing invalid number SID")
        payload = self.request(
            "POST",
            f"/2010-04-01/Accounts/{self.account_sid}/IncomingPhoneNumbers/{sid}.json",
            {"VoiceUrl": voice_url, "VoiceMethod": voice_method},
        )
        if (
            str(payload.get("sid") or "") != sid
            or str(payload.get("voice_url") or "") != voice_url
            or str(payload.get("voice_method") or "").upper() != voice_method.upper()
        ):
            raise RuntimeError("Twilio API returned an invalid update response")


class VoiceWebhookTransaction:
    def __init__(
        self,
        api: TwilioApi,
        *,
        state_path: Path,
        runtime_url_path: Path,
        expected_count: int = 2,
        managed_sids: list[str] | tuple[str, ...] | set[str] | None = None,
    ):
        self.api = api
        self.state_path = state_path.expanduser()
        self.runtime_url_path = runtime_url_path.expanduser()
        self.expected_count = int(expected_count)
        self.managed_sids = tuple(managed_sids or ())

    def targets(self, *, require_exact_authority: bool = False) -> list[VoiceNumber]:
        if any(not valid_sid(sid, "PN") for sid in self.managed_sids):
            raise RuntimeError("managed_number_sids contains an invalid SID")
        if len(set(self.managed_sids)) != len(self.managed_sids):
            raise RuntimeError("managed_number_sids contains a duplicate SID")
        if require_exact_authority and not self.managed_sids:
            raise RuntimeError("apply requires non-empty exact managed_number_sids authority")
        if require_exact_authority and len(self.managed_sids) != self.expected_count:
            raise RuntimeError(
                "managed_number_sids did not match exactly the expected target count"
            )
        numbers = self.api.voice_numbers()
        if self.managed_sids:
            authorized = set(self.managed_sids)
            numbers = [number for number in numbers if number.sid in authorized]
            if {number.sid for number in numbers} != authorized:
                raise RuntimeError("configured managed number SIDs did not match exactly")
        elif len(numbers) != self.expected_count:
            raise RuntimeError("voice-capable number count did not match the configured expectation")
        if any(number.voice_application_sid for number in numbers):
            raise RuntimeError("a target is controlled by a TwiML Application; refusing number-level update")
        return sorted(numbers, key=lambda number: number.sid)

    def plan(
        self, public_base_url: str, *, require_exact_authority: bool = False
    ) -> dict[str, Any]:
        target_url = public_endpoint(public_base_url, VOICE_PATH)
        targets = self.targets(require_exact_authority=require_exact_authority)
        return {
            "target_url": target_url,
            "targets": targets,
            "changes": sum(
                number.voice_url != target_url or number.voice_method != "POST"
                for number in targets
            ),
        }

    def apply(
        self,
        public_base_url: str,
        *,
        pre_update_check: Callable[[], None] | None = None,
    ) -> int:
        plan = self.plan(public_base_url, require_exact_authority=True)
        target_url = plan["target_url"]
        targets: list[VoiceNumber] = plan["targets"]
        snapshot = self._load_snapshot(optional=True)
        target_sids = [number.sid for number in targets]
        if snapshot and snapshot.get("status") in {
            "applying",
            "rolling_back",
            "uncertain",
        }:
            raise RuntimeError(
                "unresolved transaction state requires verified restore before apply"
            )
        if snapshot and snapshot.get("status") == "active":
            if snapshot.get("account_sid") != self.api.account_sid or snapshot.get("target_sids") != target_sids:
                raise RuntimeError("active rollback state belongs to different targets")
            original = self._validated_rows(snapshot.get("original"), target_sids)
            original_runtime = snapshot.get("original_runtime")
            return_status = "active"
            prior_applied_voice_url = snapshot.get("applied_voice_url")
        else:
            original = [
                {"sid": number.sid, "voice_url": number.voice_url, "voice_method": number.voice_method}
                for number in targets
            ]
            original_runtime = self._capture_runtime_state()
            return_status = "rolled_back"
            prior_applied_voice_url = None
        preflight_rows = [
            {"sid": number.sid, "voice_url": number.voice_url, "voice_method": number.voice_method}
            for number in targets
        ]
        preflight_runtime = self._capture_runtime_state()
        snapshot = dict(snapshot or {})
        snapshot.update(
            {
                "version": 2,
                "status": "applying",
                "account_sid": self.api.account_sid,
                "target_sids": target_sids,
                "original": original,
                "original_runtime": original_runtime,
                "applied_voice_url": target_url,
                "updated_at": int(time.time()),
                "intent": None,
                "transaction": {
                    "operation": "apply",
                    "preflight_rows": preflight_rows,
                    "preflight_runtime": preflight_runtime,
                    "return_status": return_status,
                    "prior_applied_voice_url": prior_applied_voice_url,
                },
            }
        )
        self._write_snapshot(snapshot)
        # Signature validation must switch before Twilio can call the new URL.
        atomic_owner_only_write(
            self.runtime_url_path,
            json.dumps({"public_base_url": public_base_url, "updated_at": int(time.time())}, sort_keys=True) + "\n",
        )
        changed: list[str] = []
        try:
            if pre_update_check is not None:
                pre_update_check()
        except Exception:
            try:
                self._restore_runtime_state(preflight_runtime)
                snapshot["rolled_back_at"] = int(time.time())
                settled = self._finished_apply_transaction(snapshot, return_status)
                self._write_snapshot(settled)
            except Exception:
                self._mark_uncertain(snapshot)
            raise
        try:
            for number in targets:
                if number.voice_url == target_url and number.voice_method == "POST":
                    continue
                self._provider_write(
                    snapshot,
                    phase="apply",
                    sid=number.sid,
                    voice_url=target_url,
                    voice_method="POST",
                )
                changed.append(number.sid)
            desired = {
                number.sid: (target_url, "POST")
                for number in targets
            }
            self._verify_remote(desired)
        except Exception:
            self._rollback_failed_transaction(
                snapshot,
                preflight_rows,
                preflight_runtime,
                return_status,
            )
            raise AssertionError("unreachable")
        snapshot["status"] = "active"
        snapshot["intent"] = None
        snapshot["verified_at"] = int(time.time())
        snapshot.pop("transaction", None)
        self._write_snapshot(snapshot)
        logger.info(
            "Applied Twilio Voice URL transaction to %d exact target(s) (%s)",
            len(changed),
            redact_url(target_url),
        )
        return len(changed)

    def restore(self) -> int:
        snapshot = self._load_snapshot(optional=False)
        if snapshot.get("status") not in {
            "active",
            "applying",
            "rolling_back",
            "uncertain",
        }:
            raise RuntimeError("rollback state is not recoverable")
        if snapshot.get("account_sid") != self.api.account_sid:
            raise RuntimeError("rollback state belongs to a different account")
        current_target_sids = [
            number.sid for number in self.targets(require_exact_authority=True)
        ]
        if current_target_sids != snapshot.get("target_sids"):
            raise RuntimeError("current exact targets do not match rollback state")
        target_sids = snapshot.get("target_sids")
        original = self._validated_rows(snapshot.get("original"), target_sids)
        rows = original
        runtime_state = snapshot.get("original_runtime")
        return_status = "restored"
        recovering_apply = False
        transaction = snapshot.get("transaction")
        if snapshot.get("status") in {"applying", "rolling_back", "uncertain"} and transaction is not None:
            if (
                not isinstance(transaction, dict)
                or transaction.get("operation") != "apply"
                or transaction.get("return_status") not in {"active", "rolled_back"}
                or not self._valid_runtime_state(transaction.get("preflight_runtime"))
            ):
                raise RuntimeError("rollback state failed integrity checks")
            rows = self._validated_rows(
                transaction.get("preflight_rows"), target_sids
            )
            runtime_state = transaction["preflight_runtime"]
            return_status = transaction["return_status"]
            recovering_apply = True
        expected = self._expected_rows(rows)
        try:
            observed = self._read_remote_state()
            rollback_sids = {
                sid for sid, prior in expected.items() if observed.get(sid) != prior
            }
        except Exception:
            # A failed classification makes every exact target ambiguous. Each
            # rollback intent is still durable and final readback remains the
            # only authority for declaring convergence.
            rollback_sids = set(expected)
        try:
            restored = self._restore_rows(
                rows,
                only=rollback_sids,
                snapshot=snapshot,
                allow_ambiguous_completion=True,
            )
            self._verify_remote(expected)
        except Exception:
            self._mark_uncertain(snapshot)
            raise RuntimeError("remote rollback convergence could not be verified") from None
        try:
            self._restore_runtime_state(runtime_state)
        except Exception:
            self._mark_uncertain(snapshot)
            raise RuntimeError("local rollback convergence could not be verified") from None
        snapshot["intent"] = None
        if recovering_apply:
            snapshot["recovered_at"] = int(time.time())
            snapshot = self._finished_apply_transaction(snapshot, return_status)
        else:
            snapshot["status"] = "restored"
            snapshot["restored_at"] = int(time.time())
        self._write_snapshot(snapshot)
        logger.info("Restored prior Twilio Voice webhook values for %d exact target(s)", restored)
        return restored

    def _capture_runtime_state(self) -> dict[str, Any]:
        try:
            info = self.runtime_url_path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise RuntimeError("runtime URL state is not a regular file")
            if info.st_mode & 0o077:
                raise RuntimeError("runtime URL state is not owner-only")
            return {
                "present": True,
                "content": self.runtime_url_path.read_text(encoding="utf-8"),
            }
        except FileNotFoundError:
            return {"present": False}
        except OSError as exc:
            raise RuntimeError("runtime URL state is unreadable") from exc

    def _restore_runtime_state(self, state: Any) -> None:
        if not isinstance(state, dict) or state.get("present") is not True:
            try:
                info = self.runtime_url_path.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise RuntimeError("runtime URL state is not a regular file")
                self.runtime_url_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise RuntimeError("runtime URL state could not be removed") from exc
            return
        content = state.get("content")
        if not isinstance(content, str):
            raise RuntimeError("saved runtime URL state is invalid")
        atomic_owner_only_write(self.runtime_url_path, content)

    def _restore_rows(
        self,
        rows: list[dict],
        only: set[str] | None = None,
        *,
        snapshot: dict | None = None,
        allow_ambiguous_completion: bool = False,
    ) -> int:
        attempted = 0
        failures = 0
        for row in rows:
            sid = str(row.get("sid") or "")
            if only is not None and sid not in only:
                continue
            attempted += 1
            try:
                if snapshot is None:
                    self.api.update_voice(
                        sid,
                        voice_url=str(row.get("voice_url") or ""),
                        voice_method=str(row.get("voice_method") or "POST"),
                    )
                else:
                    self._provider_write(
                        snapshot,
                        phase="rollback",
                        sid=sid,
                        voice_url=str(row.get("voice_url") or ""),
                        voice_method=str(row.get("voice_method") or "POST"),
                    )
            except Exception:
                failures += 1
        if failures and not allow_ambiguous_completion:
            raise RuntimeError("one or more rollback writes failed")
        return attempted

    def _write_snapshot(self, snapshot: dict) -> None:
        atomic_owner_only_write(
            self.state_path,
            json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
        )

    def _provider_write(
        self,
        snapshot: dict,
        *,
        phase: str,
        sid: str,
        voice_url: str,
        voice_method: str,
    ) -> None:
        """Durably record sanitized intent before every provider mutation."""
        snapshot["status"] = "applying" if phase == "apply" else "rolling_back"
        snapshot["intent"] = {
            "phase": phase,
            "sid": sid,
            "recorded_at": int(time.time()),
        }
        self._write_snapshot(snapshot)
        self.api.update_voice(sid, voice_url=voice_url, voice_method=voice_method)

    @staticmethod
    def _expected_rows(rows: list[dict]) -> dict[str, tuple[str, str]]:
        return {
            str(row.get("sid") or ""): (
                str(row.get("voice_url") or ""),
                str(row.get("voice_method") or "POST").upper(),
            )
            for row in rows
        }

    @staticmethod
    def _validated_rows(rows: Any, target_sids: Any) -> list[dict]:
        if (
            not isinstance(rows, list)
            or not isinstance(target_sids, list)
            or any(not isinstance(row, dict) for row in rows)
            or [row.get("sid") for row in rows] != target_sids
        ):
            raise RuntimeError("rollback state failed integrity checks")
        return rows

    @staticmethod
    def _valid_runtime_state(state: Any) -> bool:
        return isinstance(state, dict) and (
            state.get("present") is False
            or (state.get("present") is True and isinstance(state.get("content"), str))
        )

    @staticmethod
    def _finished_apply_transaction(snapshot: dict, return_status: str) -> dict:
        settled = dict(snapshot)
        transaction = snapshot.get("transaction") or {}
        settled["status"] = return_status
        settled["intent"] = None
        if return_status == "active":
            settled["applied_voice_url"] = transaction.get(
                "prior_applied_voice_url"
            )
        settled.pop("transaction", None)
        return settled

    def _verify_remote(self, expected: dict[str, tuple[str, str]]) -> None:
        if self._read_remote_state() != expected:
            raise RuntimeError("exact target remote state did not converge")

    def _read_remote_state(self) -> dict[str, tuple[str, str]]:
        return {
            number.sid: (number.voice_url, number.voice_method.upper())
            for number in self.targets(require_exact_authority=True)
        }

    def _mark_uncertain(self, snapshot: dict) -> None:
        snapshot["status"] = "uncertain"
        snapshot["intent"] = None
        snapshot["uncertain_at"] = int(time.time())
        self._write_snapshot(snapshot)

    def _rollback_failed_transaction(
        self,
        snapshot: dict,
        preflight_rows: list[dict],
        preflight_runtime: Any,
        return_status: str,
    ) -> None:
        expected = self._expected_rows(preflight_rows)
        # Classify every exact target after an ambiguous request. A target that
        # still matches its preflight value is proven unchanged and is not
        # rewritten. A failed read makes every target ambiguous.
        try:
            observed = self._read_remote_state()
            rollback_sids = {
                sid for sid, prior in expected.items() if observed.get(sid) != prior
            }
        except Exception:
            rollback_sids = set(expected)
        try:
            self._restore_rows(
                preflight_rows,
                only=rollback_sids,
                snapshot=snapshot,
                allow_ambiguous_completion=True,
            )
            # A rollback request may itself commit and then raise. Only exact
            # readback decides convergence; the transport exception does not.
            self._verify_remote(expected)
        except Exception:
            self._mark_uncertain(snapshot)
            raise RuntimeError(
                "Twilio webhook transaction failed; remote convergence could not be verified"
            ) from None
        try:
            self._restore_runtime_state(preflight_runtime)
        except Exception:
            self._mark_uncertain(snapshot)
            raise RuntimeError(
                "Twilio webhook transaction failed; local convergence could not be verified"
            ) from None
        snapshot["rolled_back_at"] = int(time.time())
        settled = self._finished_apply_transaction(snapshot, return_status)
        self._write_snapshot(settled)
        raise RuntimeError("Twilio webhook transaction failed; remote rollback verified") from None

    def _load_snapshot(self, *, optional: bool) -> dict | None:
        try:
            info = self.state_path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise RuntimeError("rollback state is not a regular file")
            if info.st_mode & 0o077:
                raise RuntimeError("rollback state is not owner-only")
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            if optional:
                return None
            raise RuntimeError("rollback state does not exist")
        except (OSError, ValueError) as exc:
            raise RuntimeError("rollback state is unreadable") from exc
        if not isinstance(payload, dict) or payload.get("version") != 2:
            raise RuntimeError("rollback state version is invalid")
        return payload


def discover_quick_tunnel(process: subprocess.Popen, timeout: float = 45.0) -> str:
    """Read cloudflared output without letting a silent child defeat timeout."""
    deadline = time.monotonic() + timeout
    assert process.stdout is not None
    lines: queue.Queue[str | None] = queue.Queue(maxsize=256)

    def read_output() -> None:
        try:
            for line in process.stdout:
                try:
                    lines.put(line, timeout=0.1)
                except queue.Full:
                    # The URL appears near startup; bounding discarded noise
                    # prevents an untrusted child from growing memory forever.
                    # Drop the oldest line so a later URL cannot be starved.
                    try:
                        lines.get_nowait()
                        lines.put_nowait(line)
                    except (queue.Empty, queue.Full):
                        pass
        finally:
            try:
                lines.put_nowait(None)
            except queue.Full:
                pass

    threading.Thread(target=read_output, name="cloudflared-output", daemon=True).start()
    while time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            line = lines.get(timeout=min(0.25, remaining))
        except queue.Empty:
            if process.poll() is not None:
                raise RuntimeError("cloudflared exited before publishing a tunnel URL")
            continue
        if line is None:
            raise RuntimeError("cloudflared exited before publishing a tunnel URL")
        match = _TUNNEL_RE.search(line)
        if match:
            return match.group(0).rstrip("/")
    raise RuntimeError("timed out waiting for the Quick Tunnel URL")


def wait_for_bridge_ready(
    local_url: str,
    *,
    timeout: float = 30.0,
    opener: Callable = urlopen,
) -> None:
    """Require loopback readiness after URL state changes, before Twilio writes."""
    endpoint = local_url.rstrip("/") + "/readyz"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            request = Request(endpoint, method="GET")
            with opener(request, timeout=2) as response:
                payload = json.loads(response.read().decode("utf-8"))
                if response.status == 200 and payload.get("status") == "ready":
                    return
        except (
            HTTPError,
            URLError,
            TimeoutError,
            UnicodeDecodeError,
            ValueError,
            TypeError,
            AttributeError,
        ):
            pass
        time.sleep(0.2)
    raise RuntimeError("voice bridge did not become ready on loopback")


def _load_supervisor_config(path: Path) -> dict:
    try:
        import yaml

        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (ImportError, OSError, ValueError) as exc:
        raise RuntimeError("supervisor config is unreadable") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("supervisor config must be a mapping")
    return payload


def _transaction(args, config: dict) -> VoiceWebhookTransaction:
    account, token = _credentials(Path(args.env_file) if args.env_file else None)
    quick = dict(config.get("quick_tunnel") or {})
    expected = int(quick.get("expected_voice_number_count", 2))
    raw_sids = quick.get("managed_number_sids") or []
    if not isinstance(raw_sids, list):
        raise RuntimeError("managed_number_sids must be a list")
    sids = [str(value) for value in raw_sids]
    return VoiceWebhookTransaction(
        TwilioApi(account, token),
        state_path=Path(quick.get("rollback_state_file") or "~/.hermes/state/twilio-voice-rollback.json"),
        runtime_url_path=Path(quick.get("runtime_public_url_file") or "~/.hermes/state/twilio-voice-public-url.json"),
        expected_count=expected,
        managed_sids=sids,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hermes Twilio Voice Quick Tunnel supervisor")
    parser.add_argument("mode", choices=("supervise", "plan", "restore"))
    parser.add_argument("--config", required=True, help="Behavioral YAML config path")
    parser.add_argument("--env-file", help="Dotenv path; credentials are read, never logged")
    parser.add_argument("--apply", action="store_true", help="Permit Twilio Voice webhook mutation")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = _load_supervisor_config(Path(args.config))
    transaction = _transaction(args, config)
    if args.mode == "restore":
        transaction.restore()
        return 0
    quick = dict(config.get("quick_tunnel") or {})
    if args.mode == "plan":
        base = str(quick.get("plan_public_base_url") or "")
        if not base:
            raise RuntimeError("quick_tunnel.plan_public_base_url is required for plan mode")
        plan = transaction.plan(base)
        logger.info(
            "Plan: %d exact target(s), %d change(s), %s",
            len(plan["targets"]),
            plan["changes"],
            redact_url(plan["target_url"]),
        )
        return 0

    binary = str(quick.get("cloudflared_binary") or "/opt/homebrew/bin/cloudflared")
    local_url = str(quick.get("local_url") or "http://127.0.0.1:8091")
    parsed_local = urlsplit(local_url)
    if parsed_local.scheme != "http" or parsed_local.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("Quick Tunnel local_url must be loopback HTTP")
    command = [
        binary,
        "tunnel",
        "--url",
        local_url,
        "--no-autoupdate",
        "--protocol",
        "quic",
        "--ha-connections",
        "1",
        "--loglevel",
        "info",
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    previous_handlers: dict[int, Any] = {}

    def stop_child(_signum, _frame) -> None:
        if process.poll() is None:
            process.terminate()

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, stop_child)
    try:
        public_url = discover_quick_tunnel(process)
        logger.info("Quick Tunnel discovered (%s)", redact_url(public_url))
        plan = transaction.plan(public_url)
        logger.info(
            "Voice webhook plan has %d exact target(s) and %d change(s)",
            len(plan["targets"]),
            plan["changes"],
        )
        if not args.apply:
            logger.warning("Dry run only: pass supervise --apply to permit exact VoiceUrl writes")
            process.terminate()
            return 0
        transaction.apply(
            public_url,
            pre_update_check=lambda: wait_for_bridge_ready(local_url),
        )
        return process.wait()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        logger.error("Supervisor failed safely: %s", str(exc))
        raise SystemExit(1)
