from __future__ import annotations

import io
import json
import stat

import pytest

import twilio_voice.supervisor as supervisor
from twilio_voice.supervisor import (
    TwilioApi,
    VoiceNumber,
    VoiceWebhookTransaction,
    discover_quick_tunnel,
)


ACCOUNT = "AC" + "a" * 32
SID_1 = "PN" + "1" * 32
SID_2 = "PN" + "2" * 32
FIRST_BASE_URL = "https://first.trycloudflare.com"
FIRST_VOICE_URL = FIRST_BASE_URL + "/twilio/voice"
SECOND_BASE_URL = "https://second.trycloudflare.com"
SECOND_VOICE_URL = SECOND_BASE_URL + "/twilio/voice"


class FakeApi:
    account_sid = ACCOUNT

    def __init__(self, *, fail_sid=None):
        self.fail_sid = fail_sid
        self.rows = [
            VoiceNumber(SID_1, "https://old.example/one", "POST", ""),
            VoiceNumber(SID_2, "https://old.example/two", "GET", ""),
        ]
        self.updates = []

    def voice_numbers(self):
        return list(self.rows)

    def update_voice(self, sid, *, voice_url, voice_method):
        self.updates.append((sid, voice_url, voice_method))
        if sid == self.fail_sid and not voice_url.startswith("https://old.example/"):
            raise RuntimeError("synthetic failure")
        for index, row in enumerate(self.rows):
            if row.sid == sid:
                self.rows[index] = VoiceNumber(
                    sid, voice_url, voice_method, row.voice_application_sid
                )
                break


def transaction(tmp_path, api=None):
    return VoiceWebhookTransaction(
        api or FakeApi(),
        state_path=tmp_path / "rollback.json",
        runtime_url_path=tmp_path / "public.json",
        expected_count=2,
        managed_sids=[SID_1, SID_2],
    )


def test_apply_is_exact_owner_only_and_restore_preserves_prior_values(tmp_path):
    api = FakeApi()
    tx = transaction(tmp_path, api)
    assert tx.apply("https://rotating.trycloudflare.com") == 2
    assert [row[0] for row in api.updates] == [SID_1, SID_2]
    assert all(row[1].endswith("/twilio/voice") for row in api.updates)
    assert stat.S_IMODE((tmp_path / "rollback.json").stat().st_mode) == 0o600
    state = json.loads((tmp_path / "rollback.json").read_text())
    assert state["original"][0]["voice_url"] == "https://old.example/one"

    api.updates.clear()
    assert tx.restore() == 2
    assert api.updates == [
        (SID_1, "https://old.example/one", "POST"),
        (SID_2, "https://old.example/two", "GET"),
    ]
    assert not (tmp_path / "public.json").exists()


def test_restore_reinstates_prior_runtime_url_state(tmp_path):
    runtime = tmp_path / "public.json"
    runtime.write_text('{"public_base_url":"https://prior.example"}\n')
    runtime.chmod(0o600)
    tx = transaction(tmp_path)
    tx.apply("https://new.trycloudflare.com")
    assert "new.trycloudflare.com" in runtime.read_text()
    tx.restore()
    assert runtime.read_text() == '{"public_base_url":"https://prior.example"}\n'


def test_restore_classifies_exact_targets_before_replaying_rollback(tmp_path):
    api = FakeApi()
    tx = transaction(tmp_path, api)
    tx.apply("https://new.trycloudflare.com")

    # Simulate recovery after the first exact target already converged but the
    # durable transaction could not previously prove completion.
    api.rows[0] = VoiceNumber(SID_1, "https://old.example/one", "POST", "")
    state_path = tmp_path / "rollback.json"
    state = json.loads(state_path.read_text())
    state["status"] = "uncertain"
    state_path.write_text(json.dumps(state))
    state_path.chmod(0o600)
    api.updates.clear()

    assert tx.restore() == 1
    assert api.updates == [(SID_2, "https://old.example/two", "GET")]


def test_plan_fails_on_exact_allowlist_mismatch(tmp_path):
    api = FakeApi()
    api.rows.pop()
    with pytest.raises(RuntimeError, match="managed number SIDs did not match exactly"):
        transaction(tmp_path, api).plan("https://new.example")


def test_plan_refuses_twiml_application(tmp_path):
    api = FakeApi()
    api.rows[1] = VoiceNumber(SID_2, "", "POST", "AP" + "3" * 32)
    with pytest.raises(RuntimeError, match="Application"):
        transaction(tmp_path, api).plan("https://new.example")


@pytest.mark.parametrize(
    "managed_sids, match",
    [
        ([], "exact managed_number_sids"),
        ([SID_1, SID_1], "duplicate"),
        ([SID_1], "match exactly"),
        ([SID_1, "PN" + "f" * 32], "match exactly"),
        ([SID_1, "AC" + "f" * 32], "invalid"),
        ([SID_1, "not-a-sid"], "invalid"),
    ],
)
def test_apply_requires_valid_duplicate_free_exact_sid_authority(
    tmp_path, managed_sids, match
):
    api = FakeApi()
    tx = VoiceWebhookTransaction(
        api,
        state_path=tmp_path / "rollback.json",
        runtime_url_path=tmp_path / "public.json",
        expected_count=2,
        managed_sids=managed_sids,
    )

    with pytest.raises(RuntimeError, match=match):
        tx.apply("https://new.trycloudflare.com")

    assert api.updates == []


def test_equal_count_resource_substitution_cannot_authorize_apply(tmp_path):
    api = FakeApi()
    tx = transaction(tmp_path, api)
    api.rows = [
        VoiceNumber(SID_1, "https://old.example/one", "POST", ""),
        VoiceNumber("PN" + "3" * 32, "https://old.example/three", "POST", ""),
    ]

    with pytest.raises(RuntimeError, match="match exactly"):
        tx.apply("https://new.trycloudflare.com")

    assert api.updates == []


def test_count_only_discovery_remains_available_for_plan(tmp_path):
    api = FakeApi()
    tx = VoiceWebhookTransaction(
        api,
        state_path=tmp_path / "rollback.json",
        runtime_url_path=tmp_path / "public.json",
        expected_count=2,
    )

    assert tx.plan("https://new.example")["changes"] == 2
    assert api.updates == []


def test_partial_apply_rolls_back_already_changed_target(tmp_path):
    api = FakeApi(fail_sid=SID_2)
    tx = transaction(tmp_path, api)
    with pytest.raises(RuntimeError):
        tx.apply("https://new.trycloudflare.com")
    assert [(row.voice_url, row.voice_method) for row in api.rows] == [
        ("https://old.example/one", "POST"),
        ("https://old.example/two", "GET"),
    ]
    assert json.loads((tmp_path / "rollback.json").read_text())["status"] == "rolled_back"


def test_apply_checks_bridge_readiness_before_any_twilio_write(tmp_path):
    api = FakeApi()
    tx = transaction(tmp_path, api)

    def not_ready():
        assert "new.trycloudflare.com" in (tmp_path / "public.json").read_text()
        raise RuntimeError("synthetic not ready")

    with pytest.raises(RuntimeError, match="not ready"):
        tx.apply("https://new.trycloudflare.com", pre_update_check=not_ready)
    assert api.updates == []
    assert not (tmp_path / "public.json").exists()


def test_quick_tunnel_discovery_does_not_require_logging_raw_output():
    class Process:
        stdout = io.StringIO("noise\nINF Your quick Tunnel has been created! Visit https://opaque.trycloudflare.com\n")

        @staticmethod
        def poll():
            return None

    assert discover_quick_tunnel(Process(), timeout=1) == "https://opaque.trycloudflare.com"


def test_malformed_provider_update_response_is_ambiguous_failure():
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        @staticmethod
        def read():
            return b"{}"

    api = TwilioApi(
        ACCOUNT,
        "synthetic-token",
        opener=lambda *_args, **_kwargs: Response(),
    )
    with pytest.raises(RuntimeError, match="invalid update response"):
        api.update_voice(
            SID_1,
            voice_url="https://new.example/twilio/voice",
            voice_method="POST",
        )


def test_supervisor_is_dry_run_without_explicit_apply(monkeypatch, tmp_path):
    class Transaction:
        applied = False

        @staticmethod
        def plan(_public_url):
            return {"targets": [object(), object()], "changes": 2}

        def apply(self, _public_url):
            self.applied = True
            raise AssertionError("dry run must not mutate Twilio")

    class Process:
        returncode = None

        @staticmethod
        def poll():
            return None

        @staticmethod
        def terminate():
            return None

        @staticmethod
        def wait(timeout=None):
            return 0

        @staticmethod
        def kill():
            return None

    transaction = Transaction()
    monkeypatch.setattr(supervisor, "_load_supervisor_config", lambda _path: {"quick_tunnel": {}})
    monkeypatch.setattr(supervisor, "_transaction", lambda _args, _config: transaction)
    monkeypatch.setattr(supervisor.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    monkeypatch.setattr(
        supervisor,
        "discover_quick_tunnel",
        lambda _process: "https://opaque.trycloudflare.com",
    )
    assert supervisor.main(["supervise", "--config", str(tmp_path / "config.yaml")]) == 0
    assert transaction.applied is False


class ReconcilingApi(FakeApi):
    def __init__(
        self,
        *,
        commit_then_fail_on=None,
        fail_readback_once=False,
        rollback_fail_sid=None,
        rollback_commit_then_fail_sid=None,
        state_path=None,
    ):
        super().__init__()
        self.commit_then_fail_on = commit_then_fail_on
        self.fail_readback_once = fail_readback_once
        self.rollback_fail_sid = rollback_fail_sid
        self.rollback_commit_then_fail_sid = rollback_commit_then_fail_sid
        self.state_path = state_path
        self.forward_writes = 0
        self.failed = False
        self.intent_seen = []

    def voice_numbers(self):
        if self.failed and self.fail_readback_once:
            self.fail_readback_once = False
            raise RuntimeError("synthetic readback loss")
        return list(self.rows)

    def update_voice(self, sid, *, voice_url, voice_method):
        if self.state_path:
            durable = json.loads(self.state_path.read_text())
            self.intent_seen.append((sid, durable["status"], durable["intent"]["sid"]))
        self.updates.append((sid, voice_url, voice_method))
        is_forward = voice_url.startswith("https://new.trycloudflare.com")
        if not is_forward and sid == self.rollback_fail_sid:
            raise RuntimeError("synthetic rollback failure")
        for index, row in enumerate(self.rows):
            if row.sid == sid:
                self.rows[index] = VoiceNumber(
                    sid, voice_url, voice_method, row.voice_application_sid
                )
                break
        if not is_forward and sid == self.rollback_commit_then_fail_sid:
            raise RuntimeError("synthetic ambiguous rollback completion")
        if is_forward:
            self.forward_writes += 1
            if self.forward_writes == self.commit_then_fail_on:
                self.failed = True
                raise RuntimeError("synthetic ambiguous completion")


@pytest.mark.parametrize("write_number", [1, 2])
def test_commit_then_timeout_reconciles_and_verifies_exact_rollback(
    tmp_path, write_number
):
    state_path = tmp_path / "rollback.json"
    api = ReconcilingApi(commit_then_fail_on=write_number, state_path=state_path)
    tx = VoiceWebhookTransaction(
        api,
        state_path=state_path,
        runtime_url_path=tmp_path / "public.json",
        managed_sids=[SID_1, SID_2],
    )

    with pytest.raises(RuntimeError, match="rollback verified"):
        tx.apply("https://new.trycloudflare.com")

    assert [(row.voice_url, row.voice_method) for row in api.rows] == [
        ("https://old.example/one", "POST"),
        ("https://old.example/two", "GET"),
    ]
    assert json.loads(state_path.read_text())["status"] == "rolled_back"
    assert not (tmp_path / "public.json").exists()
    assert all(sid == intent_sid for sid, _status, intent_sid in api.intent_seen)
    rollback_sids = [
        sid
        for sid, url, _method in api.updates
        if url.startswith("https://old.example/")
    ]
    assert rollback_sids == ([SID_1] if write_number == 1 else [SID_1, SID_2])


def test_ambiguous_malformed_response_and_readback_loss_still_converge(tmp_path):
    api = ReconcilingApi(commit_then_fail_on=1, fail_readback_once=True)
    tx = transaction(tmp_path, api)

    with pytest.raises(RuntimeError, match="rollback verified"):
        tx.apply("https://new.trycloudflare.com")

    assert [row.voice_url for row in api.rows] == [
        "https://old.example/one",
        "https://old.example/two",
    ]
    assert json.loads((tmp_path / "rollback.json").read_text())["status"] == "rolled_back"


def test_unverified_rollback_persists_uncertain_and_keeps_runtime_policy(tmp_path):
    api = ReconcilingApi(commit_then_fail_on=2, rollback_fail_sid=SID_1)
    tx = transaction(tmp_path, api)

    with pytest.raises(RuntimeError, match="convergence could not be verified"):
        tx.apply("https://new.trycloudflare.com")

    state = json.loads((tmp_path / "rollback.json").read_text())
    assert state["status"] == "uncertain"
    assert "error" not in state
    assert "new.trycloudflare.com" in (tmp_path / "public.json").read_text()


def test_commit_then_timeout_during_rollback_is_verified_as_converged(tmp_path):
    api = ReconcilingApi(
        commit_then_fail_on=1,
        rollback_commit_then_fail_sid=SID_1,
    )
    tx = transaction(tmp_path, api)

    with pytest.raises(RuntimeError, match="rollback verified"):
        tx.apply("https://new.trycloudflare.com")

    assert [row.voice_url for row in api.rows] == [
        "https://old.example/one",
        "https://old.example/two",
    ]
    assert json.loads((tmp_path / "rollback.json").read_text())["status"] == "rolled_back"


def test_successful_apply_verifies_remote_convergence(tmp_path):
    api = ReconcilingApi()
    tx = transaction(tmp_path, api)

    assert tx.apply("https://new.trycloudflare.com") == 2

    assert all(row.voice_url.endswith("/twilio/voice") for row in api.rows)
    assert all(row.voice_method == "POST" for row in api.rows)
    assert json.loads((tmp_path / "rollback.json").read_text())["status"] == "active"


@pytest.mark.parametrize("status", ["applying", "rolling_back", "uncertain"])
def test_unresolved_durable_transaction_blocks_new_apply(tmp_path, status):
    state_path = tmp_path / "rollback.json"
    state_path.write_text(
        json.dumps(
            {
                "version": 2,
                "status": status,
                "account_sid": ACCOUNT,
                "target_sids": [SID_1, SID_2],
                "original": [
                    {"sid": SID_1, "voice_url": "https://old.example/one", "voice_method": "POST"},
                    {"sid": SID_2, "voice_url": "https://old.example/two", "voice_method": "GET"},
                ],
                "original_runtime": {"present": False},
                "intent": {"phase": "apply", "sid": SID_1},
            }
        )
    )
    state_path.chmod(0o600)
    api = ReconcilingApi()
    tx = VoiceWebhookTransaction(
        api,
        state_path=state_path,
        runtime_url_path=tmp_path / "public.json",
        managed_sids=[SID_1, SID_2],
    )

    with pytest.raises(RuntimeError, match="unresolved transaction"):
        tx.apply("https://new.trycloudflare.com")

    assert api.updates == []
    assert json.loads(state_path.read_text())["status"] == status


class RotationApi(FakeApi):
    def __init__(self, *, state_path=None):
        super().__init__()
        self.state_path = state_path
        self.fail_before: tuple[str, str] | None = None
        self.commit_then_fail: tuple[str, str] | None = None
        self.commit_failure_fired = False
        self.durable_states = []

    def update_voice(self, sid, *, voice_url, voice_method):
        if self.state_path:
            self.durable_states.append(json.loads(self.state_path.read_text()))
        self.updates.append((sid, voice_url, voice_method))
        if self.fail_before == (sid, voice_url):
            raise RuntimeError("synthetic pre-commit failure")
        for index, row in enumerate(self.rows):
            if row.sid == sid:
                self.rows[index] = VoiceNumber(
                    sid, voice_url, voice_method, row.voice_application_sid
                )
                break
        if (
            self.commit_then_fail == (sid, voice_url)
            and not self.commit_failure_fired
        ):
            self.commit_failure_fired = True
            raise RuntimeError("synthetic ambiguous completion")


def remote_rows(api):
    return [(row.voice_url, row.voice_method) for row in api.rows]


def test_second_apply_partial_failure_rolls_back_to_immediate_preflight(tmp_path):
    state_path = tmp_path / "rollback.json"
    runtime_path = tmp_path / "public.json"
    api = RotationApi(state_path=state_path)
    tx = transaction(tmp_path, api)
    assert tx.apply(FIRST_BASE_URL) == 2
    first_runtime = runtime_path.read_text()

    api.updates.clear()
    api.fail_before = (SID_2, SECOND_VOICE_URL)
    with pytest.raises(RuntimeError, match="rollback verified"):
        tx.apply(SECOND_BASE_URL)

    assert remote_rows(api) == [
        (FIRST_VOICE_URL, "POST"),
        (FIRST_VOICE_URL, "POST"),
    ]
    assert runtime_path.read_text() == first_runtime
    assert api.updates == [
        (SID_1, SECOND_VOICE_URL, "POST"),
        (SID_2, SECOND_VOICE_URL, "POST"),
        (SID_1, FIRST_VOICE_URL, "POST"),
    ]
    state = json.loads(state_path.read_text())
    assert state["status"] == "active"
    assert state["original"][0]["voice_url"] == "https://old.example/one"


def test_second_apply_commit_then_timeout_reconciles_to_immediate_preflight(
    tmp_path,
):
    state_path = tmp_path / "rollback.json"
    runtime_path = tmp_path / "public.json"
    api = RotationApi(state_path=state_path)
    tx = transaction(tmp_path, api)
    tx.apply(FIRST_BASE_URL)
    first_runtime = runtime_path.read_text()

    api.updates.clear()
    api.commit_then_fail = (SID_1, SECOND_VOICE_URL)
    with pytest.raises(RuntimeError, match="rollback verified"):
        tx.apply(SECOND_BASE_URL)

    assert remote_rows(api) == [
        (FIRST_VOICE_URL, "POST"),
        (FIRST_VOICE_URL, "POST"),
    ]
    assert runtime_path.read_text() == first_runtime
    assert api.updates == [
        (SID_1, SECOND_VOICE_URL, "POST"),
        (SID_1, FIRST_VOICE_URL, "POST"),
    ]
    assert json.loads(state_path.read_text())["status"] == "active"


def test_unresolved_second_rotation_recovers_preflight_then_restores_baseline(
    tmp_path,
):
    state_path = tmp_path / "rollback.json"
    runtime_path = tmp_path / "public.json"
    api = RotationApi(state_path=state_path)
    tx = transaction(tmp_path, api)
    tx.apply(FIRST_BASE_URL)
    first_runtime = runtime_path.read_text()

    api.commit_then_fail = (SID_1, SECOND_VOICE_URL)
    api.fail_before = (SID_1, FIRST_VOICE_URL)
    with pytest.raises(RuntimeError, match="convergence could not be verified"):
        tx.apply(SECOND_BASE_URL)
    assert json.loads(state_path.read_text())["status"] == "uncertain"

    api.commit_then_fail = None
    api.fail_before = None
    recovered = transaction(tmp_path, api)
    assert recovered.restore() == 1
    assert remote_rows(api) == [
        (FIRST_VOICE_URL, "POST"),
        (FIRST_VOICE_URL, "POST"),
    ]
    assert runtime_path.read_text() == first_runtime
    state = json.loads(state_path.read_text())
    assert state["status"] == "active"
    assert state["original"][0]["voice_url"] == "https://old.example/one"

    assert recovered.restore() == 2
    assert remote_rows(api) == [
        ("https://old.example/one", "POST"),
        ("https://old.example/two", "GET"),
    ]
    assert not runtime_path.exists()


def test_successful_second_rotation_retains_first_baseline_restore_authority(
    tmp_path,
):
    state_path = tmp_path / "rollback.json"
    runtime_path = tmp_path / "public.json"
    baseline_runtime = '{"public_base_url":"https://baseline.example"}\n'
    runtime_path.write_text(baseline_runtime)
    runtime_path.chmod(0o600)
    api = RotationApi(state_path=state_path)
    tx = transaction(tmp_path, api)
    tx.apply(FIRST_BASE_URL)

    api.durable_states.clear()
    assert tx.apply(SECOND_BASE_URL) == 2
    assert all(
        state["transaction"]["preflight_rows"][0]["voice_url"]
        == FIRST_VOICE_URL
        for state in api.durable_states
        if state["intent"]["phase"] == "apply"
    )
    stable = json.loads(state_path.read_text())
    assert stable["status"] == "active"
    assert stable["original"][0]["voice_url"] == "https://old.example/one"

    assert tx.restore() == 2
    assert remote_rows(api) == [
        ("https://old.example/one", "POST"),
        ("https://old.example/two", "GET"),
    ]
    assert runtime_path.read_text() == baseline_runtime


def test_second_rotation_readiness_failure_restores_prior_runtime_without_writes(
    tmp_path,
):
    state_path = tmp_path / "rollback.json"
    runtime_path = tmp_path / "public.json"
    api = RotationApi(state_path=state_path)
    tx = transaction(tmp_path, api)
    tx.apply(FIRST_BASE_URL)
    first_runtime = runtime_path.read_text()
    api.updates.clear()

    def not_ready():
        assert SECOND_BASE_URL in runtime_path.read_text()
        raise RuntimeError("synthetic second rotation not ready")

    with pytest.raises(RuntimeError, match="second rotation not ready"):
        tx.apply(SECOND_BASE_URL, pre_update_check=not_ready)

    assert api.updates == []
    assert runtime_path.read_text() == first_runtime
    state = json.loads(state_path.read_text())
    assert state["status"] == "active"
    assert state["original"][0]["voice_url"] == "https://old.example/one"


def test_existing_active_version_two_state_can_rotate_and_restore(tmp_path):
    state_path = tmp_path / "rollback.json"
    runtime_path = tmp_path / "public.json"
    state_path.write_text(
        json.dumps(
            {
                "version": 2,
                "status": "active",
                "account_sid": ACCOUNT,
                "target_sids": [SID_1, SID_2],
                "original": [
                    {
                        "sid": SID_1,
                        "voice_url": "https://old.example/one",
                        "voice_method": "POST",
                    },
                    {
                        "sid": SID_2,
                        "voice_url": "https://old.example/two",
                        "voice_method": "GET",
                    },
                ],
                "original_runtime": {"present": False},
                "applied_voice_url": FIRST_VOICE_URL,
                "intent": None,
            }
        )
    )
    state_path.chmod(0o600)
    runtime_path.write_text(
        json.dumps({"public_base_url": FIRST_BASE_URL}) + "\n"
    )
    runtime_path.chmod(0o600)
    api = RotationApi(state_path=state_path)
    api.rows = [
        VoiceNumber(SID_1, FIRST_VOICE_URL, "POST", ""),
        VoiceNumber(SID_2, FIRST_VOICE_URL, "POST", ""),
    ]
    tx = transaction(tmp_path, api)

    assert tx.apply(SECOND_BASE_URL) == 2
    assert tx.restore() == 2
    assert remote_rows(api) == [
        ("https://old.example/one", "POST"),
        ("https://old.example/two", "GET"),
    ]
    assert not runtime_path.exists()
