from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import time

import pytest

import gateway.juno_private_read_mvp as mvp
from gateway.config import GatewayConfig
from gateway.juno_private_read_mvp import (
    JunoPrivateReadDependencies,
    JunoPrivateReadError,
    JunoPrivateReadMvpConfig,
    JunoPrivateReadMvpHost,
    SensitiveRuntimeIdentity,
    SensitiveSubmission,
)
from tests.gateway.test_juno_private_read_mvp_e2e import (
    FakeJsonTransport,
    FakeOrdinary,
    ORDINARY_ACCOUNT,
    OWNER,
    SENSITIVE_ACCOUNT,
    _event,
    _host,
    _raw_config,
    _tool,
)
from tools.private_read_request_tool import (
    check_private_read_request_runtime,
    configure_private_read_mvp_handler,
)


PRIVATE_VALUE = "PRIVATE-CYCLE-5-DEADLINE-CANARY"


def _identity(now_us: int) -> SensitiveRuntimeIdentity:
    return SensitiveRuntimeIdentity(
        "cycle-5-runtime",
        SENSITIVE_ACCOUNT,
        "cycle-5-epoch",
        now_us,
        tuple(sorted(mvp._SENSITIVE_TRANSPORT_IDENTITY.items())),
    )


@pytest.mark.asyncio
async def test_provider_digest_and_descriptor_seal_every_sensitive_identity_element(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, _transport, _ordinary, _sensitive = await _host(tmp_path)
    try:
        result = _tool(
            _event(OWNER, "request", message="complete-sensitive-identity"), host
        )
        request = host.repository.get(dict(result.terminal.metadata)["request_id"])
        values = {
            name: getattr(request, name)
            for name in host.repository._STATE_FIELDS
        }
        descriptor = json.loads(host.repository._descriptor(values))
        assert descriptor["sensitive_authority"] == mvp.SENSITIVE_AUTHORITY
        assert descriptor["sensitive_submit_contract"] \
            == mvp.SENSITIVE_SUBMIT_CONTRACT_VERSION
        assert descriptor["sensitive_transport_identity"] \
            == mvp._SENSITIVE_TRANSPORT_IDENTITY

        expected_fields = {
            "manifest_sha256", "launcher_sha256", "source_sha256",
            "package_sha256", "lock_sha256", "verifier_sha256",
            "node_modules_tree_sha256", "package_name", "package_version",
            "submit_contract_version", "baileys_spec", "baileys_lock_version",
            "baileys_lock_resolved", "baileys_lock_integrity",
            "baileys_installed_name", "baileys_version",
            "baileys_package_sha256", "baileys_tree_sha256",
            "baileys_reviewed_release_git_head",
        }
        assert set(mvp._SENSITIVE_TRANSPORT_IDENTITY) == expected_fields
        baseline = mvp._provider_authority_digest(host.config)
        original = mvp._SENSITIVE_TRANSPORT_IDENTITY
        for name in sorted(expected_fields):
            changed = dict(original)
            changed[name] = changed[name] + "-artifact-b"
            monkeypatch.setattr(mvp, "_SENSITIVE_TRANSPORT_IDENTITY", changed)
            assert mvp._provider_authority_digest(host.config) != baseline
        monkeypatch.setattr(mvp, "_SENSITIVE_TRANSPORT_IDENTITY", original)
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_approved_request_is_bound_to_exact_sensitive_artifact_across_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, transport, ordinary, _sensitive = await _host(tmp_path)
    result = _tool(
        _event(OWNER, "request", message="artifact-a-approved-request"), host
    )
    request_id = dict(result.terminal.metadata)["request_id"]
    config = host.config
    await host.stop()

    artifact_b = dict(mvp._SENSITIVE_TRANSPORT_IDENTITY)
    artifact_b["manifest_sha256"] = "b" * 64
    monkeypatch.setattr(mvp, "_SENSITIVE_TRANSPORT_IDENTITY", artifact_b)

    class ArtifactBSensitive:
        def __init__(self) -> None:
            self.identity_reads = 0
            self.submits = 0

        async def observe_identity(self, *, request):
            self.identity_reads += 1
            return _identity(time.time_ns() // 1000)

        async def submit(self, **_kwargs):
            self.submits += 1
            return SensitiveSubmission(
                "submitted", "3EB0ABCDEF0123456789AB",
                SENSITIVE_ACCOUNT, "77777777777@s.whatsapp.net",
            )

    sensitive = ArtifactBSensitive()
    restarted = JunoPrivateReadMvpHost(
        config,
        JunoPrivateReadDependencies(
            mvp.OpenFgaChecker(config, transport),
            mvp.GmailNewestInboxProvider(config, transport),
            ordinary,
            sensitive,
        ),
        active_profile="juno",
    )
    assert await restarted.start(_background_worker=False)
    try:
        assert restarted.repository.get(request_id) is None
        assert await restarted.process_once() is False
        assert transport.calls == []
        assert ordinary.messages == []
        assert sensitive.identity_reads == 0
        assert sensitive.submits == 0
    finally:
        await restarted.stop()


@pytest.mark.asyncio
async def test_python_submit_coroutine_rejects_exact_expiry_before_start(
    tmp_path: Path,
) -> None:
    host, _provider_transport, _ordinary, _sensitive = await _host(tmp_path)
    try:
        result = _tool(
            _event(OWNER, "request", message="python-coroutine-entry-expiry"), host
        )
        request = host.repository.get(dict(result.terminal.metadata)["request_id"])
        clock = [request.expires_at_us - 1]
        transport = FakeJsonTransport()
        submitter = mvp._SensitiveHttpSubmitter(
            host.config, transport, _clock_us=lambda: clock[0]
        )
        coroutine = submitter.submit(
            request=request, plaintext=PRIVATE_VALUE, identity=_identity(clock[0])
        )
        clock[0] = request.expires_at_us
        submission = await coroutine
        assert submission.state == "expired"
        assert transport.calls == []
        assert host.repository.get(request.request_id).status == "approved"
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_python_submit_rechecks_exact_expiry_immediately_before_http_issue(
    tmp_path: Path,
) -> None:
    host, _provider_transport, _ordinary, _sensitive = await _host(tmp_path)
    try:
        result = _tool(
            _event(OWNER, "request", message="python-http-issue-expiry"), host
        )
        request = host.repository.get(dict(result.terminal.metadata)["request_id"])
        observed = iter((request.expires_at_us - 2, request.expires_at_us))
        transport = FakeJsonTransport()
        submitter = mvp._SensitiveHttpSubmitter(
            host.config, transport, _clock_us=lambda: next(observed)
        )
        submission = await submitter.submit(
            request=request,
            plaintext=PRIVATE_VALUE,
            identity=_identity(request.expires_at_us - 2),
        )
        assert submission.state == "expired"
        assert transport.calls == []
        assert host.repository.get(request.request_id).status == "approved"
    finally:
        await host.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("deadline", (None, "1785846896000000", 9_007_199_254_740_991))
async def test_python_submit_rejects_missing_malformed_or_incoherent_deadline(
    tmp_path: Path, deadline: object,
) -> None:
    host, _provider_transport, _ordinary, _sensitive = await _host(tmp_path)
    try:
        result = _tool(
            _event(OWNER, "request", message="python-malformed-deadline"), host
        )
        request = host.repository.get(dict(result.terminal.metadata)["request_id"])
        candidate = replace(request, expires_at_us=deadline)
        transport = FakeJsonTransport()
        submitter = mvp._SensitiveHttpSubmitter(
            host.config, transport, _clock_us=lambda: request.created_at_us
        )
        submission = await submitter.submit(
            request=candidate,
            plaintext=PRIVATE_VALUE,
            identity=_identity(request.created_at_us),
        )
        assert submission.state == "failed"
        assert transport.calls == []
        assert host.repository.get(request.request_id).status == "approved"
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_host_marks_boundary_expiry_without_consuming_or_sending(
    tmp_path: Path,
) -> None:
    config = JunoPrivateReadMvpConfig.parse(_raw_config(tmp_path))
    provider_transport = FakeJsonTransport()

    class NoSensitiveHttp:
        def __init__(self) -> None:
            self.calls = 0

        async def request(self, **_call):
            self.calls += 1
            raise AssertionError("expired request reached sensitive HTTP")

    sensitive_http = NoSensitiveHttp()

    class BoundarySensitive:
        def __init__(self) -> None:
            self.submit_calls = 0

        async def observe_identity(self, *, request):
            return _identity(time.time_ns() // 1000)

        async def submit(self, *, request, plaintext, identity):
            self.submit_calls += 1
            return await mvp._sealed_sensitive_submit(
                config, sensitive_http, request, plaintext, identity,
                _clock_us=lambda: request.expires_at_us,
            )

    sensitive = BoundarySensitive()
    host = JunoPrivateReadMvpHost(
        config,
        JunoPrivateReadDependencies(
            mvp.OpenFgaChecker(config, provider_transport),
            mvp.GmailNewestInboxProvider(config, provider_transport),
            FakeOrdinary(),
            sensitive,
        ),
        active_profile="juno",
    )
    assert await host.start(_background_worker=False)
    try:
        result = _tool(
            _event(OWNER, "request", message="host-submit-boundary-expiry"), host
        )
        request_id = dict(result.terminal.metadata)["request_id"]
        assert await host.process_once()
        request = host.repository.get(request_id)
        assert request.status == "expired"
        assert request.terminal_code == "expired_at_submission_boundary"
        assert request.provider_message_id is None
        assert sensitive.submit_calls == 1
        assert sensitive_http.calls == 0
    finally:
        await host.stop()


@pytest.mark.parametrize(
    ("destination", "valid"),
    (
        (ORDINARY_ACCOUNT, False),
        (ORDINARY_ACCOUNT.replace("@s.whatsapp.net", "@lid"), False),
        (ORDINARY_ACCOUNT.replace("@", ":7@"), False),
        (ORDINARY_ACCOUNT.replace("@s.whatsapp.net", "@c.us"), False),
        ("77777777777@s.whatsapp.net", True),
        ("77777777777@lid", True),
    ),
)
def test_sensitive_destination_must_be_verifiably_distinct_from_ordinary_account(
    tmp_path: Path, destination: str, valid: bool,
) -> None:
    raw = _raw_config(tmp_path)
    for requester in raw["requesters"]:
        requester["sensitive_destination"] = destination
    if not valid:
        with pytest.raises(JunoPrivateReadError):
            JunoPrivateReadMvpConfig.parse(raw)
        return
    parsed = JunoPrivateReadMvpConfig.parse(raw)
    assert parsed.requesters[0].sensitive_destination == destination
    assert parsed.requesters[0].source_chat == OWNER
    assert parsed.owner_chat == OWNER
    assert parsed.requesters[1].source_chat != parsed.owner_chat


def test_same_account_topology_is_required_while_destination_stays_distinct(
    tmp_path: Path,
) -> None:
    raw = _raw_config(tmp_path)
    raw["sensitive"]["account"] = ORDINARY_ACCOUNT
    parsed = JunoPrivateReadMvpConfig.parse(raw)
    assert parsed.ordinary_account == parsed.sensitive_account == ORDINARY_ACCOUNT
    assert parsed.requesters[0].sensitive_destination != ORDINARY_ACCOUNT

    raw["sensitive"]["account"] = "55555555555@s.whatsapp.net"
    with pytest.raises(JunoPrivateReadError):
        JunoPrivateReadMvpConfig.parse(raw)


def test_every_requester_is_bound_to_the_exact_owner_private_destination(
    tmp_path: Path,
) -> None:
    raw = _raw_config(tmp_path)
    raw["requesters"][1]["sensitive_destination"] = "77777777777@s.whatsapp.net"
    with pytest.raises(JunoPrivateReadError):
        JunoPrivateReadMvpConfig.parse(raw)


def test_sensitive_destination_rejects_persisted_phone_to_lid_provider_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    hermes_home = tmp_path / "isolated-hermes"
    session = hermes_home / "platforms" / "whatsapp" / "session"
    session.mkdir(parents=True)
    (session / "lid-mapping-33333333333.json").write_text(
        json.dumps("88888888888@lid"), encoding="utf-8"
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    authority = tmp_path / "authority"
    authority.mkdir()
    raw = _raw_config(authority)
    raw["requesters"][0]["sensitive_destination"] = "88888888888@lid"
    with pytest.raises(JunoPrivateReadError):
        JunoPrivateReadMvpConfig.parse(raw)


@pytest.mark.asyncio
async def test_rejected_ordinary_destination_topology_has_zero_external_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _raw_config(tmp_path)
    raw["requesters"][0]["sensitive_destination"] = ORDINARY_ACCOUNT
    constructions = 0

    class ForbiddenTransport:
        def __init__(self, *_args, **_kwargs) -> None:
            nonlocal constructions
            constructions += 1

    monkeypatch.setattr(mvp, "FixedHttpJsonTransport", ForbiddenTransport)
    from gateway.run import GatewayRunner

    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig.from_dict({
        "trusted_private_read": raw,
        "sessions_dir": str(tmp_path / "sessions"),
    })
    runner._trusted_private_read_host = None
    runner._active_profile_name = lambda: "juno"
    assert await runner._start_trusted_private_read_host() is False
    assert runner._trusted_private_read_host is None
    assert constructions == 0
    assert check_private_read_request_runtime() is False


@pytest.mark.asyncio
@pytest.mark.parametrize("active_profile", ("juno", "not-juno"))
async def test_real_gateway_runner_refuses_v2_private_host_when_multiplexed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    active_profile: str,
) -> None:
    from gateway.run import GatewayRunner
    import tools.tirith_security as tirith_security

    configure_private_read_mvp_handler(None)
    home = tmp_path / active_profile / "home"
    default_home = home / ".hermes"
    profile_home = default_home / "profiles" / active_profile
    profile_home.mkdir(parents=True, mode=0o700)
    (default_home / "active_profile").write_text(active_profile, encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(profile_home))
    monkeypatch.delenv("GATEWAY_MULTIPLEX_PROFILES", raising=False)
    monkeypatch.setattr(tirith_security, "ensure_installed", lambda **_kwargs: None)

    authority = tmp_path / active_profile / "authority"
    authority.mkdir(mode=0o700)
    raw = _raw_config(authority)
    config = GatewayConfig.from_dict({
        "multiplex_profiles": True,
        "trusted_private_read": raw,
        "sessions_dir": str(tmp_path / active_profile / "sessions"),
    })
    assert type(config) is GatewayConfig
    assert config.multiplex_profiles is True
    runner = GatewayRunner(config)
    assert type(runner) is GatewayRunner
    assert runner._active_profile_name() == active_profile

    provider_clients = 0
    original_transport = mvp.FixedHttpJsonTransport

    def forbidden_transport(*_args, **_kwargs):
        nonlocal provider_clients
        provider_clients += 1
        return original_transport()

    monkeypatch.setattr(mvp, "FixedHttpJsonTransport", forbidden_transport)
    try:
        assert await runner._start_trusted_private_read_host() is False
        assert runner._trusted_private_read_host is None
        assert provider_clients == 0
        assert check_private_read_request_runtime() is False
        state_dir = Path(raw["state_dir"])
        assert not (state_dir / "authorization.db").exists()
        assert not (state_dir / "mvp-store.key").exists()
        assert not (state_dir / "juno-replay.journal").exists()
        assert not any(
            task.get_name() == "juno-private-read-mvp"
            for task in __import__("asyncio").all_tasks()
        )
    finally:
        configure_private_read_mvp_handler(None)
        from agent.secret_scope import set_multiplex_active
        set_multiplex_active(False)
