"""Versioned SQLite schema for durable authorization coordination."""

_TASKS_V2 = """
CREATE TABLE {table} (
    task_id TEXT PRIMARY KEY,
    correlation_id TEXT NOT NULL,
    scoped_request_key TEXT NOT NULL UNIQUE,
    binding_json TEXT NOT NULL,
    binding_digest TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    key_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'approval_required','approved','claimed','consumed','denied','expired',
        'canceled','failed_consumed'
    )),
    created_at_us INTEGER NOT NULL,
    expires_at_us INTEGER NOT NULL,
    decision_id TEXT,
    decision_digest TEXT,
    winning_challenge_attempt_id TEXT,
    winning_challenge_generation INTEGER,
    claim_owner_digest TEXT,
    claim_nonce_digest TEXT,
    claim_generation INTEGER,
    claim_lease_expires_at_us INTEGER,
    claimed_at_us INTEGER,
    heartbeat_at_us INTEGER,
    send_started_at_us INTEGER,
    completed_at_us INTEGER,
    receipt_code TEXT CHECK (receipt_code IS NULL OR receipt_code IN (
        'provider_accepted','provider_rejected','provider_timeout','render_failed',
        'internal_failure','ambiguous_after_restart'
    )),
    receipt_token TEXT,
    version INTEGER NOT NULL DEFAULT 1
)
"""

_AUDIT_V2 = """
CREATE TABLE {table} (
    event_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES authorization_tasks(task_id),
    kind TEXT NOT NULL CHECK (kind IN (
        'task_created','task_approved','task_denied','task_expired','task_canceled',
        'task_claimed','task_reclaimed','task_heartbeat','send_started',
        'task_consumed','task_failed_consumed','notification_created',
        'notification_claimed','notification_reclaimed','notification_heartbeat',
        'notification_send_started','notification_provider_accepted',
        'notification_failed','pdp_check_allowed','pdp_check_denied','pdp_check_failed',
        'pdp_grant_started','pdp_grant_recorded','pdp_grant_failed'
    )),
    reason_code TEXT NOT NULL CHECK (reason_code IN (
        'created','approval_challenge','approval_resolution','owner_approved',
        'owner_rejected','policy_denied','request_canceled','host_shutdown',
        'approval_expired','claim_acquired','claim_extended','provider_send_started',
        'stale_pre_send_claim','provider_accepted','provider_rejected',
        'provider_timeout','render_failed','internal_failure',
        'ambiguous_after_restart','policy_allowed','pdp_unavailable','pdp_malformed',
        'external_grant_started','external_grant_recorded','external_grant_failed'
    )),
    actor_token TEXT NOT NULL,
    target_token TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    key_version TEXT NOT NULL,
    occurred_at_us INTEGER NOT NULL
)
"""

_NOTIFICATIONS_V2 = """
CREATE TABLE {table} (
    attempt_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES authorization_tasks(task_id),
    correlation_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('approval_challenge','approval_resolution')),
    challenge_generation INTEGER NOT NULL CHECK (challenge_generation > 0),
    destination_profile TEXT NOT NULL,
    destination_account TEXT NOT NULL,
    destination_chat TEXT NOT NULL,
    destination_thread TEXT NOT NULL,
    destination_digest TEXT NOT NULL,
    key_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'pending','claimed','provider_accepted','failed'
    )),
    created_at_us INTEGER NOT NULL,
    due_at_us INTEGER NOT NULL,
    claim_owner_digest TEXT,
    claim_nonce_digest TEXT,
    claim_generation INTEGER,
    claim_lease_expires_at_us INTEGER,
    send_started_at_us INTEGER,
    completed_at_us INTEGER,
    receipt_code TEXT CHECK (receipt_code IS NULL OR receipt_code IN (
        'provider_accepted','provider_rejected','provider_timeout','internal_failure',
        'ambiguous_after_restart'
    )),
    challenge_nonce_digest TEXT NOT NULL,
    nonce_verifier_version TEXT NOT NULL,
    provider_message_verifier TEXT,
    provider_verifier_version TEXT,
    provider_acceptance_status TEXT CHECK (
        provider_acceptance_status IS NULL OR provider_acceptance_status='provider_accepted'
    ),
    provider_accepted_at_us INTEGER,
    adapter_instance_id TEXT,
    account_binding_token TEXT,
    connection_epoch INTEGER,
    challenge_state TEXT NOT NULL CHECK (
        challenge_state IN ('unaccepted','accepted','consumed','superseded')
    ),
    challenge_resolved_at_us INTEGER,
    challenge_decision_digest TEXT,
    challenge_record_digest TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(task_id, challenge_generation)
)
"""

_PDP_V2 = """
CREATE TABLE {table} (
    evidence_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES authorization_tasks(task_id),
    stage TEXT NOT NULL CHECK (stage IN ('pre_claim','pre_private_read')),
    decision TEXT NOT NULL CHECK (decision IN ('allow','deny','failure')),
    request_digest TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    policy_revision TEXT NOT NULL,
    checked_at_us INTEGER NOT NULL,
    consistency TEXT NOT NULL CHECK (consistency IN ('strongest','unknown')),
    pdp_call_id_verifier TEXT,
    cache_used INTEGER NOT NULL CHECK (cache_used IN (0,1)),
    evidence_digest TEXT NOT NULL,
    key_version TEXT NOT NULL,
    UNIQUE(task_id, stage, evidence_id)
)
"""

_TASKS_V3 = _TASKS_V2.replace(
    "    receipt_token TEXT,\n    version INTEGER NOT NULL DEFAULT 1",
    """    receipt_token TEXT,
    delivery_acceptance_status TEXT CHECK (
        delivery_acceptance_status IS NULL OR delivery_acceptance_status='provider_accepted'
    ),
    delivery_accepted_at_us INTEGER,
    delivery_transport_implementation TEXT,
    delivery_runtime_identity TEXT,
    delivery_account_binding_token TEXT,
    delivery_connection_epoch INTEGER,
    delivery_record_digest TEXT,
    version INTEGER NOT NULL DEFAULT 1""",
)

_NOTIFICATIONS_V3 = _NOTIFICATIONS_V2.replace(
    "    UNIQUE(task_id, challenge_generation)",
    "    UNIQUE(task_id, kind, challenge_generation)",
)

_PDP_V3 = _PDP_V2.replace(
    "    evidence_digest TEXT NOT NULL,\n    key_version TEXT NOT NULL,",
    """    evidence_digest TEXT NOT NULL,
    binding_digest TEXT,
    coordinator_owner_digest TEXT,
    coordinator_nonce_digest TEXT,
    coordinator_epoch INTEGER,
    claim_owner_digest TEXT,
    claim_nonce_digest TEXT,
    claim_generation INTEGER,
    context_record_digest TEXT,
    key_version TEXT NOT NULL,""",
)

_TASKS_V4 = _TASKS_V3.replace(
    "    version INTEGER NOT NULL DEFAULT 1",
    "    resolution_spec_digest TEXT,\n    version INTEGER NOT NULL DEFAULT 1",
).replace(
    "'internal_failure','ambiguous_after_restart'",
    "'internal_failure','ambiguous_after_restart','incomplete_delivery_binding'",
)

_AUDIT_V4 = _AUDIT_V2.replace(
    "'external_grant_started','external_grant_recorded','external_grant_failed'",
    "'external_grant_started','external_grant_recorded','external_grant_failed',\n        'incomplete_delivery_binding'",
)

_NOTIFICATIONS_V4 = _NOTIFICATIONS_V3.replace(
    "    version INTEGER NOT NULL DEFAULT 1,\n    UNIQUE(task_id, kind, challenge_generation)",
    """    notification_spec_digest TEXT NOT NULL,
    retry_ordinal INTEGER NOT NULL DEFAULT 1 CHECK (retry_ordinal > 0),
    supersedes_attempt_id TEXT REFERENCES {table}(attempt_id),
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(task_id, kind, challenge_generation, retry_ordinal)""",
).replace(
    "'ambiguous_after_restart'\n    ))",
    "'ambiguous_after_restart','incomplete_delivery_binding'\n    ))",
)

_TASKS_V6 = _TASKS_V4.replace(
    "    resolution_spec_digest TEXT,\n    version INTEGER NOT NULL DEFAULT 1",
    "    resolution_spec_digest TEXT,\n    mutable_state_digest TEXT NOT NULL,\n    version INTEGER NOT NULL DEFAULT 1",
)

_AUDIT_V6 = _AUDIT_V4.replace(
    "    occurred_at_us INTEGER NOT NULL",
    "    occurred_at_us INTEGER NOT NULL,\n    record_digest TEXT NOT NULL",
)

_NOTIFICATIONS_V6 = _NOTIFICATIONS_V4.replace(
    "    version INTEGER NOT NULL DEFAULT 1,\n    UNIQUE(task_id, kind, challenge_generation, retry_ordinal)",
    "    mutable_state_digest TEXT NOT NULL,\n    version INTEGER NOT NULL DEFAULT 1,\n    UNIQUE(task_id, kind, challenge_generation, retry_ordinal)",
)

_TASKS_V7 = _TASKS_V6.replace(
    "    mutable_state_digest TEXT NOT NULL,\n    version INTEGER NOT NULL DEFAULT 1",
    """    mutable_state_digest TEXT NOT NULL,
    audit_event_count INTEGER NOT NULL DEFAULT 0
        CHECK (audit_event_count BETWEEN 0 AND 100000),
    audit_head_digest TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL DEFAULT 1""",
)

_AUDIT_V7 = _AUDIT_V6.replace(
    "    occurred_at_us INTEGER NOT NULL,\n    record_digest TEXT NOT NULL",
    """    occurred_at_us INTEGER NOT NULL,
    audit_sequence INTEGER NOT NULL CHECK (audit_sequence BETWEEN 1 AND 100000),
    previous_record_digest TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    UNIQUE(task_id, audit_sequence)""",
)

_NOTIFICATIONS_V7 = _NOTIFICATIONS_V6.replace(
    "claim_generation INTEGER,",
    "claim_generation INTEGER CHECK (claim_generation IS NULL OR claim_generation BETWEEN 1 AND 8),",
).replace(
    "retry_ordinal INTEGER NOT NULL DEFAULT 1 CHECK (retry_ordinal > 0)",
    "retry_ordinal INTEGER NOT NULL DEFAULT 1 CHECK (retry_ordinal BETWEEN 1 AND 8)",
)

_LEASE = """
CREATE TABLE IF NOT EXISTS authorization_coordinator_lease (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    owner_digest TEXT NOT NULL,
    nonce_digest TEXT NOT NULL,
    key_version TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    heartbeat_at_us INTEGER NOT NULL,
    lease_expires_at_us INTEGER NOT NULL
)
"""

# The fast Juno MVP deliberately shares the authorization database and its
# coordinator with the existing authorization engine.  This additive table is
# payload-free: it contains only sealed routing metadata and lifecycle state.
_PRIVATE_READ_MVP = """
CREATE TABLE IF NOT EXISTS private_read_mvp_requests (
    request_id TEXT PRIMARY KEY,
    requester TEXT NOT NULL,
    source_profile TEXT NOT NULL,
    source_account TEXT NOT NULL,
    source_chat TEXT NOT NULL,
    source_message TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    destination_account TEXT NOT NULL,
    destination_chat TEXT NOT NULL,
    owner_sender TEXT NOT NULL,
    approval_chat TEXT NOT NULL,
    approval_message TEXT,
    gmail_account TEXT NOT NULL,
    openfga_store_id TEXT NOT NULL,
    openfga_model_id TEXT NOT NULL,
    provider_authority_digest TEXT NOT NULL,
    descriptor_digest TEXT NOT NULL,
    created_at_us INTEGER NOT NULL,
    expires_at_us INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'pending','approved','denied','expired','claimed','consumed',
        'failed_consumed'
    )),
    notice_claimed INTEGER NOT NULL DEFAULT 0 CHECK (notice_claimed IN (0,1)),
    claim_token_digest TEXT,
    provider_message_id TEXT,
    terminal_code TEXT,
    updated_at_us INTEGER NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    state_hmac TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_private_read_mvp_state
    ON private_read_mvp_requests(status, expires_at_us, created_at_us);
CREATE UNIQUE INDEX IF NOT EXISTS idx_private_read_mvp_source_event
    ON private_read_mvp_requests(
        source_profile, source_account, source_chat, requester,
        source_message, capability_id
    )
    WHERE source_message <> '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_private_read_mvp_approval_event
    ON private_read_mvp_requests(
        source_profile, source_account, owner_sender, approval_chat,
        approval_message, capability_id
    )
    WHERE approval_message IS NOT NULL
"""

_INDEXES_V2 = """
CREATE INDEX IF NOT EXISTS idx_authorization_tasks_state_due
    ON authorization_tasks(status, expires_at_us, created_at_us);
CREATE UNIQUE INDEX IF NOT EXISTS idx_authorization_tasks_decision
    ON authorization_tasks(decision_id) WHERE decision_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_authorization_tasks_receipt
    ON authorization_tasks(receipt_token) WHERE receipt_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_authorization_audit_task_time
    ON authorization_audit_events(task_id, occurred_at_us, event_id);
CREATE INDEX IF NOT EXISTS idx_authorization_notifications_due
    ON authorization_notification_attempts(status, due_at_us, created_at_us);
CREATE UNIQUE INDEX IF NOT EXISTS idx_authorization_provider_message
    ON authorization_notification_attempts(provider_message_verifier)
    WHERE provider_message_verifier IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_authorization_pdp_task_stage
    ON authorization_pdp_evidence(task_id, stage, checked_at_us);
"""

_INDEXES_V4 = _INDEXES_V2 + """
CREATE UNIQUE INDEX IF NOT EXISTS idx_authorization_resolution_active
    ON authorization_notification_attempts(task_id, kind, challenge_generation)
    WHERE kind='approval_resolution' AND status IN ('pending','claimed','provider_accepted');
CREATE UNIQUE INDEX IF NOT EXISTS idx_authorization_resolution_superseded
    ON authorization_notification_attempts(supersedes_attempt_id)
    WHERE supersedes_attempt_id IS NOT NULL;
"""

# Frozen WIP handoff shape used only as the source contract for the v1->v2
# migration. Runtime creation always uses v2 below.
_SCHEMA_V1 = """
CREATE TABLE authorization_tasks (
    task_id TEXT PRIMARY KEY, correlation_id TEXT NOT NULL,
    scoped_request_key TEXT NOT NULL UNIQUE, binding_json TEXT NOT NULL,
    binding_digest TEXT NOT NULL, request_digest TEXT NOT NULL,
    key_version TEXT NOT NULL, status TEXT NOT NULL,
    created_at_us INTEGER NOT NULL, expires_at_us INTEGER NOT NULL,
    decision_id TEXT, decision_digest TEXT, claim_owner_digest TEXT,
    claim_nonce_digest TEXT, claim_generation INTEGER,
    claim_lease_expires_at_us INTEGER, claimed_at_us INTEGER,
    heartbeat_at_us INTEGER, send_started_at_us INTEGER,
    completed_at_us INTEGER, receipt_code TEXT, receipt_token TEXT,
    version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE authorization_audit_events (
    event_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES authorization_tasks(task_id),
    kind TEXT NOT NULL, reason_code TEXT NOT NULL, actor_token TEXT NOT NULL,
    target_token TEXT NOT NULL, request_digest TEXT NOT NULL,
    key_version TEXT NOT NULL, occurred_at_us INTEGER NOT NULL
);
CREATE TABLE authorization_notification_attempts (
    attempt_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES authorization_tasks(task_id),
    kind TEXT NOT NULL, destination_profile TEXT NOT NULL,
    destination_account TEXT NOT NULL, destination_chat TEXT NOT NULL,
    destination_thread TEXT NOT NULL, destination_digest TEXT NOT NULL,
    key_version TEXT NOT NULL, status TEXT NOT NULL,
    created_at_us INTEGER NOT NULL, due_at_us INTEGER NOT NULL,
    claim_owner_digest TEXT, claim_nonce_digest TEXT, claim_generation INTEGER,
    claim_lease_expires_at_us INTEGER, send_started_at_us INTEGER,
    completed_at_us INTEGER, receipt_code TEXT, provider_message_token TEXT,
    challenge_nonce_digest TEXT NOT NULL, challenge_consumed_at_us INTEGER,
    challenge_decision_digest TEXT, version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE authorization_coordinator_lease (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    owner_digest TEXT NOT NULL, nonce_digest TEXT NOT NULL,
    key_version TEXT NOT NULL, epoch INTEGER NOT NULL CHECK (epoch > 0),
    heartbeat_at_us INTEGER NOT NULL, lease_expires_at_us INTEGER NOT NULL
);
PRAGMA user_version=1;
"""

_SCHEMA = ";".join(
    [
        _TASKS_V7.format(table="authorization_tasks"),
        _AUDIT_V7.format(table="authorization_audit_events"),
        _NOTIFICATIONS_V7.format(table="authorization_notification_attempts"),
        _PDP_V3.format(table="authorization_pdp_evidence"),
        _LEASE,
        _PRIVATE_READ_MVP,
        _INDEXES_V4,
    ]
)
