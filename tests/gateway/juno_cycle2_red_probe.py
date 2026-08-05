"""Manual compatibility probes used to demonstrate cycle-2 RED/GREEN behavior."""

import asyncio
from pathlib import Path
import sqlite3
import sys
import tempfile

from gateway.juno_private_read_mvp import CAPABILITY_ID, JunoPrivateReadMvpHost
from tests.gateway.test_juno_private_read_mvp_e2e import (
    OWNER, ORDINARY_ACCOUNT, SENSITIVE_ACCOUNT, TRUSTED, TRUSTED_CHAT,
    _event, _host, _tool,
)


def _restart(config, dependencies):
    try:
        return JunoPrivateReadMvpHost(config, dependencies, active_profile="juno")
    except TypeError:
        return JunoPrivateReadMvpHost(config, dependencies)


async def _probe(name: str) -> None:
    root = Path(tempfile.mkdtemp(prefix="juno-cycle2-probe-")).resolve()
    host, _transport, _ordinary, sensitive = await _host(root)
    if name == "state_hmac":
        result = _tool(_event(TRUSTED, "request", message="red-state"), host)
        request_id = dict(result.terminal.metadata)["request_id"]
        conn = host.store._connect()
        conn.execute(
            "UPDATE private_read_mvp_requests SET status='approved' WHERE request_id=?",
            (request_id,),
        )
        conn.commit()
        conn.close()
        await host.process_once()
        assert sensitive.calls == [], "tampered status reached sensitive submission"
    elif name == "approval_replay":
        one = _tool(_event(TRUSTED, "request", message="red-replay-1"), host)
        two = _tool(_event(TRUSTED, "request", message="red-replay-2"), host)
        first = dict(one.terminal.metadata)["request_id"]
        second = dict(two.terminal.metadata)["request_id"]
        assert host.intercept_approval(_event(
            OWNER, f"/approve {first}", message="same-owner-provider-message"
        )).mutated
        assert not host.intercept_approval(_event(
            OWNER, f"/approve {second}", message="same-owner-provider-message"
        )).mutated, "one owner provider message approved two requests"
    elif name == "stale_identity":
        from gateway.juno_private_read_mvp import _sealed_sensitive_identity
        result = _tool(_event(OWNER, "request", message="red-identity"), host)
        request = host.repository.get(dict(result.terminal.metadata)["request_id"])

        class Transport:
            async def request(self, **_kwargs):
                return {
                    "outcome": "available", "submitted": False,
                    "provider_account_jid": SENSITIVE_ACCOUNT,
                    "identity_observed_us": 0,
                    "adapter_runtime_id": "stale-runtime",
                    "connection_epoch": "stale-epoch",
                    "transport_identity": {"arbitrary": True},
                }
        assert await _sealed_sensitive_identity(
            host.config, Transport(), request
        ) is None, "stale arbitrary transport identity was accepted"
    elif name == "dedicated_profile":
        assert host.context_for_event(_event(
            TRUSTED, "request", profile=None, message="red-profileless"
        )) is not None, "dedicated profileless production event was rejected"
    elif name == "legacy_migration":
        config, dependencies = host.config, host.dependencies
        db_path = config.state_dir / "authorization.db"
        await host.stop()
        conn = sqlite3.connect(db_path)
        conn.executescript("""
        DROP INDEX IF EXISTS idx_private_read_mvp_state;
        DROP INDEX IF EXISTS idx_private_read_mvp_source_event;
        DROP TABLE private_read_mvp_requests;
        CREATE TABLE private_read_mvp_requests (
          request_id TEXT PRIMARY KEY, requester TEXT NOT NULL,
          source_profile TEXT NOT NULL, source_account TEXT NOT NULL,
          source_chat TEXT NOT NULL, source_message TEXT NOT NULL,
          capability_id TEXT NOT NULL, destination_account TEXT NOT NULL,
          destination_chat TEXT NOT NULL, owner_sender TEXT NOT NULL,
          approval_chat TEXT NOT NULL, descriptor_digest TEXT NOT NULL,
          created_at_us INTEGER NOT NULL, expires_at_us INTEGER NOT NULL,
          status TEXT NOT NULL, notice_claimed INTEGER NOT NULL DEFAULT 0,
          claim_token_digest TEXT, provider_message_id TEXT, terminal_code TEXT,
          updated_at_us INTEGER NOT NULL, version INTEGER NOT NULL DEFAULT 1
        );
        """)
        conn.execute(
            "INSERT INTO private_read_mvp_requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("legacy-approved", TRUSTED, "juno", ORDINARY_ACCOUNT, TRUSTED_CHAT,
             "legacy-source", CAPABILITY_ID, SENSITIVE_ACCOUNT,
             "77777777777@s.whatsapp.net", OWNER, OWNER, "0" * 64,
             1, 9_000_000_000_000_000, "approved", 0, None, None, None, 1, 1),
        )
        conn.commit()
        conn.close()
        host = _restart(config, dependencies)
        assert await host.start(_background_worker=False)
        await host.process_once()
        assert sensitive.calls == [], "unauthenticated checkpoint row reached provider"
    else:
        raise ValueError(name)
    await host.stop()


if __name__ == "__main__":
    asyncio.run(_probe(sys.argv[1]))
