import { WAMessageStatus } from '@whiskeysockets/baileys';

export const DEFAULT_SEND_DEADLINE_MS = 15_000;
// The reviewed Baileys pin can buffer `messages.update` for 30 seconds.
// Keep the post-send acknowledgement window strictly beyond that bound.
export const DEFAULT_ACK_DEADLINE_MS = 31_000;
export const PROVIDER_MESSAGE_ID_PATTERN = /^3EB0[0-9A-F]{18}$/;
export const SENSITIVE_SUBMIT_CONTRACT_VERSION = 'juno-sensitive-submit-v2';

const ACCEPTED_STATUSES = new Set([
  WAMessageStatus.DELIVERY_ACK,
  WAMessageStatus.READ,
  WAMessageStatus.PLAYED,
]);
const INSUFFICIENT_STATUSES = new Set([WAMessageStatus.SERVER_ACK]);
const REJECTED_STATUSES = new Set([
  WAMessageStatus.ERROR,
  WAMessageStatus.PENDING,
]);
const MAX_PRIVATE_BYTES = 16 * 1024;
const MAX_OPAQUE_BYTES = 256;
const MAX_BINDING_BYTES = 512;
const MAX_DEADLINE_AHEAD_US = 300_000_000;
const MIN_TRUSTED_EPOCH_US = 1_000_000_000_000_000;
const MAX_TRUSTED_EPOCH_US = Number.MAX_SAFE_INTEGER;

export const REQUEST_FIELDS = Object.freeze([
  'authorization_task_id',
  'operation_id',
  'correlation_id',
  'attempt_id',
  'request_binding_hmac',
  'request_binding_key_version',
  'policy_version',
  'policy_hash',
  'expected_profile',
  'expected_platform',
  'expected_account_binding_ref',
  'expected_provider_account_jid',
  'destination_thread_id',
  'chat_jid',
  'expected_adapter_runtime_id',
  'expected_connection_epoch',
  'private_value',
]);

export const ECHO_FIELDS = Object.freeze([
  'authorization_task_id',
  'operation_id',
  'correlation_id',
  'attempt_id',
  'request_binding_hmac',
  'request_binding_key_version',
  'policy_version',
  'policy_hash',
  'expected_profile',
  'expected_platform',
  'expected_account_binding_ref',
  'destination_thread_id',
]);

export const OUTCOME_MATRIX = Object.freeze({
  malformed_or_binding_deny: Object.freeze({ outcome: 'denied', submitted: false }),
  auth_failure: Object.freeze({ outcome: 'rejected', submitted: false }),
  unavailable_or_disabled: Object.freeze({ outcome: 'unavailable', submitted: false }),
  capacity: Object.freeze({ outcome: 'capacity', submitted: false }),
  caller_abort_before_send: Object.freeze({ outcome: 'caller_abort', submitted: false }),
  send_boundary_failure_or_timeout: Object.freeze({ outcome: 'ambiguous', submitted: true }),
  acknowledgement_timeout: Object.freeze({ outcome: 'ambiguous', submitted: true }),
  disconnect_account_epoch_or_socket_drift: Object.freeze({ outcome: 'ambiguous', submitted: true }),
  caller_abort_after_send: Object.freeze({ outcome: 'ambiguous', submitted: true }),
  provider_error_pending_or_malformed_status: Object.freeze({ outcome: 'provider_rejected', submitted: true }),
  sender_companion_server_ack_only: Object.freeze({ outcome: 'ambiguous', submitted: true }),
  exact_destination_receipt_evidence: Object.freeze({ outcome: 'provider_accepted', submitted: true }),
});

function plainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, fields) {
  const keys = Object.keys(value);
  return keys.length === fields.length && fields.every((field) => Object.hasOwn(value, field));
}

function byteLength(value) {
  return Buffer.byteLength(value, 'utf8');
}

function boundedString(value, maximum = MAX_OPAQUE_BYTES) {
  return typeof value === 'string'
    && value.length > 0
    && value === value.trim()
    && byteLength(value) <= maximum
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function safeNow(nowUs) {
  try {
    const value = nowUs();
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  } catch {
    return null;
  }
}

function deadlineState(expiresAtUs, nowUs, previousNowUs = null) {
  const now = safeNow(nowUs);
  if (!Number.isSafeInteger(expiresAtUs)
      || expiresAtUs < MIN_TRUSTED_EPOCH_US
      || expiresAtUs > MAX_TRUSTED_EPOCH_US
      || now === null
      || now < MIN_TRUSTED_EPOCH_US
      || now > MAX_TRUSTED_EPOCH_US
      || (previousNowUs !== null && now < previousNowUs)
      || expiresAtUs - now > MAX_DEADLINE_AHEAD_US) {
    return { state: 'invalid', now };
  }
  return { state: now < expiresAtUs ? 'live' : 'expired', now };
}

function submitResult(state, account = '', destination = '') {
  return Object.freeze({ state, message_id: null, account, destination });
}

function addBounded(map, key, value, limit) {
  map.delete(key);
  map.set(key, value);
  while (map.size > limit) map.delete(map.keys().next().value);
}

function frozenClone(value) {
  return Object.freeze({ ...value });
}

function baseOutcome(outcome, submitted, errorCode, extra = {}) {
  const result = { outcome, submitted, ...extra };
  if (errorCode) result.error_code = errorCode;
  return Object.freeze(result);
}

function canonicalDirectJid(value, canonicalizeJid) {
  if (typeof value !== 'string'
      || !/^\d{1,32}(?::\d{1,5})?@(s\.whatsapp\.net|lid)$/.test(value)) {
    return { error: 'chat_not_direct' };
  }
  let canonical;
  try {
    canonical = canonicalizeJid(value);
  } catch {
    return { error: 'chat_not_canonical' };
  }
  return canonical === value ? { value } : { error: 'chat_not_canonical' };
}

function canonicalAccountJid(value, canonicalizeJid) {
  if (typeof value !== 'string'
      || !/^\d{1,32}(?::\d{1,5})?@(s\.whatsapp\.net|lid)$/.test(value)) {
    return { error: 'account_expectation_not_canonical' };
  }
  let canonical;
  try {
    canonical = canonicalizeJid(value);
  } catch {
    return { error: 'account_expectation_not_canonical' };
  }
  return canonical === value ? { value } : { error: 'account_expectation_not_canonical' };
}

function jidNamespace(value) {
  return value.slice(value.lastIndexOf('@') + 1);
}

function parseRequestMetadata(request, transport) {
  if (!plainObject(request) || !exactKeys(request, REQUEST_FIELDS)) {
    return { error: 'malformed_request' };
  }
  const echo = {};
  for (const field of ECHO_FIELDS) {
    const maximum = field === 'request_binding_hmac' ? MAX_BINDING_BYTES : MAX_OPAQUE_BYTES;
    if (!boundedString(request[field], maximum)) return { error: 'malformed_request' };
    echo[field] = request[field];
  }
  if (!/^[a-f0-9]{64}$/.test(request.policy_hash)) return { error: 'malformed_request' };
  if (request.expected_platform !== 'whatsapp') return { error: 'platform_mismatch', echo };
  if (!boundedString(request.expected_adapter_runtime_id)
      || request.expected_adapter_runtime_id !== transport.runtimeId) {
    return { error: 'runtime_mismatch', echo };
  }
  if (!boundedString(request.expected_connection_epoch)
      || request.expected_connection_epoch !== transport.connection?.epoch) {
    return { error: 'epoch_mismatch', echo };
  }
  const account = canonicalAccountJid(request.expected_provider_account_jid, transport.canonicalizeJid);
  if (account.error) return { error: account.error, echo };
  const chat = canonicalDirectJid(request.chat_jid, transport.canonicalizeJid);
  if (chat.error) return { error: chat.error, echo };
  if (!boundedString(request.destination_thread_id)) return { error: 'malformed_request', echo };
  if (request.destination_thread_id !== chat.value) return { error: 'destination_mismatch', echo };
  return { echo: frozenClone(echo), accountJid: account.value, chatJid: chat.value };
}

export class SensitiveDeliveryTransport {
  constructor({
    runtimeId,
    ordinaryAccountJid,
    transportIdentity,
    canonicalizeJid,
    generateMessageId,
    nowUs = () => Date.now() * 1000,
    sendDeadlineMs = DEFAULT_SEND_DEADLINE_MS,
    ackDeadlineMs = DEFAULT_ACK_DEADLINE_MS,
    activeLimit = 8,
    tombstoneLimit = 1024,
    attemptLimit = 4096,
    setTimeoutFn = setTimeout,
    clearTimeoutFn = clearTimeout,
  }) {
    if (!boundedString(runtimeId) || !plainObject(transportIdentity)) {
      throw new TypeError('invalid sensitive transport identity');
    }
    if (typeof canonicalizeJid !== 'function' || typeof generateMessageId !== 'function') {
      throw new TypeError('missing pinned provider helpers');
    }
    this.runtimeId = runtimeId;
    this.transportIdentity = Object.freeze({ ...transportIdentity });
    this.canonicalizeJid = canonicalizeJid;
    const ordinaryAccount = canonicalAccountJid(ordinaryAccountJid, canonicalizeJid);
    if (ordinaryAccount.error) throw new TypeError('ordinary account identity is required');
    this.ordinaryAccountJid = ordinaryAccount.value;
    this.generateMessageId = generateMessageId;
    this.nowUs = nowUs;
    this.sendDeadlineMs = Math.max(1, Math.floor(sendDeadlineMs));
    this.ackDeadlineMs = Math.max(1, Math.floor(ackDeadlineMs));
    this.activeLimit = Math.max(1, Math.floor(activeLimit));
    this.tombstoneLimit = Math.max(1, Math.floor(tombstoneLimit));
    this.attemptLimit = Math.max(1, Math.floor(attemptLimit));
    this.setTimeoutFn = setTimeoutFn;
    this.clearTimeoutFn = clearTimeoutFn;
    this.active = new Map();
    this.tombstones = new Map();
    this.attemptTombstones = new Map();
    this.connection = null;
    this.enabled = true;
    this._dispatcher = (updates) => this.#dispatchUpdates(updates);
  }

  bindConnection({ sock, accountJid, epoch }) {
    if (!sock || typeof sock.sendMessage !== 'function' || typeof sock.ev?.on !== 'function'
        || typeof sock.ev?.off !== 'function') {
      throw new TypeError('invalid sensitive socket');
    }
    const account = canonicalAccountJid(accountJid, this.canonicalizeJid);
    if (account.error || !boundedString(epoch)) throw new TypeError('invalid sensitive connection');
    if (account.value === this.ordinaryAccountJid) {
      throw new TypeError('separate sensitive account required');
    }
    if (jidNamespace(account.value) !== jidNamespace(this.ordinaryAccountJid)) {
      throw new TypeError('account identity namespace mismatch');
    }
    if (this.connection) {
      const reason = this.connection.sock !== sock ? 'socket_replaced'
        : this.connection.epoch !== epoch ? 'epoch_drift'
          : this.connection.accountJid !== accountJid ? 'account_drift'
            : null;
      if (!reason) return;
      this.#closeConnection(reason);
    }
    this.connection = Object.freeze({ sock, accountJid: account.value, epoch });
    sock.ev.on('messages.update', this._dispatcher);
  }

  unbindConnection(reason = 'disconnect') {
    this.#closeConnection(reason === 'disconnect' ? 'disconnect' : 'connection_unavailable');
  }

  setEnabled(enabled) {
    this.enabled = enabled === true;
    if (!this.enabled) this.#settleAll('service_disabled');
  }

  identityEvidence() {
    if (!this.enabled || !this.connection) {
      return baseOutcome('unavailable', false, this.enabled ? 'not_connected' : 'service_disabled');
    }
    const observed = safeNow(this.nowUs);
    const drift = this.#connectionDriftCode(this.connection);
    if (observed === null || drift) {
      return baseOutcome('unavailable', false, drift || 'time_unavailable');
    }
    return Object.freeze({
      outcome: 'available',
      submitted: false,
      provider_account_jid: this.connection.accountJid,
      identity_observed_us: observed,
      adapter_runtime_id: this.runtimeId,
      connection_epoch: this.connection.epoch,
      transport_identity: this.transportIdentity,
    });
  }

  async submit(request, { signal } = {}) {
    const fields = [
      'contract_version', 'request_id', 'registration', 'session', 'account',
      'destination', 'expires_at_us', 'private_value',
    ];
    if (!this.enabled || !this.connection) {
      return submitResult('failed');
    }
    if (!plainObject(request) || !exactKeys(request, fields)
        || request.contract_version !== SENSITIVE_SUBMIT_CONTRACT_VERSION
        || !boundedString(request.request_id)
        || !boundedString(request.registration)
        || !boundedString(request.session)
        || !boundedString(request.account)
        || !boundedString(request.destination)
        || typeof request.private_value !== 'string'
        || byteLength(request.private_value) === 0
        || byteLength(request.private_value) > MAX_PRIVATE_BYTES
        || signal?.aborted) {
      return submitResult('failed');
    }
    const connection = this.connection;
    const account = canonicalAccountJid(request.account, this.canonicalizeJid);
    const destination = canonicalDirectJid(request.destination, this.canonicalizeJid);
    if (account.error || destination.error || account.value !== connection.accountJid
        || request.registration !== this.runtimeId || request.session !== connection.epoch
        || this.#connectionDriftCode(connection, account.value)) {
      return Object.freeze({ state: 'failed', message_id: null,
        account: request.account, destination: request.destination });
    }
    const entryDeadline = deadlineState(request.expires_at_us, this.nowUs);
    if (entryDeadline.state === 'invalid') {
      return submitResult('failed', account.value, destination.value);
    }
    if (entryDeadline.state === 'expired') {
      return submitResult('expired', account.value, destination.value);
    }
    let messageId;
    try {
      messageId = this.generateMessageId(connection.sock.user?.id);
    } catch {
      return Object.freeze({ state: 'failed', message_id: null,
        account: account.value, destination: destination.value });
    }
    if (!PROVIDER_MESSAGE_ID_PATTERN.test(messageId)) {
      return Object.freeze({ state: 'failed', message_id: null,
        account: account.value, destination: destination.value });
    }
    // This is the final deadline fence. No await, microtask, timer, or other
    // event-loop yield may occur between this sample and the provider call.
    const sendDeadline = deadlineState(
      request.expires_at_us, this.nowUs, entryDeadline.now,
    );
    if (sendDeadline.state === 'invalid') {
      return submitResult('failed', account.value, destination.value);
    }
    if (sendDeadline.state === 'expired') {
      return submitResult('expired', account.value, destination.value);
    }
    try {
      const sent = await connection.sock.sendMessage(
        destination.value,
        { text: request.private_value, linkPreview: null },
        { messageId },
      );
      if (signal?.aborted || sent?.key?.id !== messageId
          || sent?.key?.remoteJid !== destination.value || sent?.key?.fromMe !== true
          || this.#connectionDriftCode(connection, account.value)) {
        return Object.freeze({ state: 'unknown', message_id: null,
          account: account.value, destination: destination.value });
      }
      return Object.freeze({ state: 'submitted', message_id: messageId,
        account: account.value, destination: destination.value });
    } catch {
      return Object.freeze({ state: 'unknown', message_id: null,
        account: account.value, destination: destination.value });
    }
  }

  async send(request, { signal } = {}) {
    if (!this.enabled) return baseOutcome('unavailable', false, 'service_disabled');
    const connection = this.connection;
    if (!connection) return baseOutcome('unavailable', false, 'not_connected');
    if (this.active.size >= this.activeLimit) return baseOutcome('capacity', false, 'active_capacity');

    const parsed = parseRequestMetadata(request, this);
    if (parsed.error) return baseOutcome('denied', false, parsed.error, parsed.echo || {});
    const initialDrift = this.#connectionDriftCode(connection, parsed.accountJid);
    if (initialDrift) return baseOutcome('denied', false, initialDrift, parsed.echo);
    if (this.attemptTombstones.has(parsed.echo.attempt_id)
        || [...this.active.values()].some((entry) => entry.echo.attempt_id === parsed.echo.attempt_id)) {
      return baseOutcome('denied', false, 'attempt_reused', parsed.echo);
    }
    // Read the request-local private value only after every host binding and
    // live connection expectation above has passed. It is never stored on an
    // entry, error, evidence object, timer, queue, or logger.
    const privateValue = request.private_value;
    if (typeof privateValue !== 'string' || privateValue.length === 0) {
      return baseOutcome('denied', false, 'private_value_invalid', parsed.echo);
    }
    if (byteLength(privateValue) > MAX_PRIVATE_BYTES) {
      return baseOutcome('denied', false, 'private_value_too_large', parsed.echo);
    }

    let messageId;
    try {
      messageId = this.generateMessageId(connection.sock.user?.id);
    } catch {
      return baseOutcome('denied', false, 'provider_id_invalid', parsed.echo);
    }
    if (!PROVIDER_MESSAGE_ID_PATTERN.test(messageId)) {
      return baseOutcome('denied', false, 'provider_id_invalid', parsed.echo);
    }
    if (this.active.has(messageId) || this.tombstones.has(messageId)) {
      return baseOutcome('denied', false, 'provider_id_reused', parsed.echo);
    }
    const identityObservedUs = safeNow(this.nowUs);
    if (identityObservedUs === null) return baseOutcome('unavailable', false, 'time_unavailable', parsed.echo);

    let resolveResult;
    const result = new Promise((resolve) => { resolveResult = resolve; });
    const entry = {
      messageId,
      echo: parsed.echo,
      chatJid: parsed.chatJid,
      accountJid: parsed.accountJid,
      sock: connection.sock,
      epoch: connection.epoch,
      identityObservedUs,
      sendStartedUs: null,
      submitted: false,
      sendResolved: false,
      candidate: null,
      settled: false,
      timer: null,
      abortSignal: signal,
      abortHandler: null,
      resolveResult,
      result,
    };
    this.active.set(messageId, entry);
    addBounded(this.attemptTombstones, parsed.echo.attempt_id, true, this.attemptLimit);

    entry.abortHandler = () => {
      this.#settle(entry, entry.submitted ? 'ambiguous' : 'caller_abort', 'caller_abort');
    };
    if (signal) {
      if (signal.aborted) entry.abortHandler();
      else signal.addEventListener('abort', entry.abortHandler, { once: true });
    }

    if (!entry.settled) {
      const sendStartedUs = safeNow(this.nowUs);
      const drift = this.#connectionDriftCode(connection, parsed.accountJid);
      if (sendStartedUs === null || sendStartedUs < identityObservedUs) {
        this.#settle(entry, 'unavailable', 'time_unavailable');
      } else if (drift || this.active.get(messageId) !== entry) {
        this.#settle(entry, 'denied', drift || 'registry_drift');
      } else {
        entry.sendStartedUs = sendStartedUs;
        entry.submitted = true;
        entry.timer = this.setTimeoutFn(
          () => this.#settle(entry, 'ambiguous', 'send_timeout'),
          this.sendDeadlineMs,
        );
        let submission;
        try {
          // This is the sole sensitive send boundary. The exact request-local
          // private value is not copied into any registry/evidence object.
          submission = connection.sock.sendMessage(
            parsed.chatJid,
            { text: privateValue, linkPreview: null },
            { messageId },
          );
        } catch {
          this.#settle(entry, 'ambiguous', 'send_failed');
        }
        if (!entry.settled && submission !== undefined) {
          Promise.resolve(submission).then(
            (sent) => this.#submissionResolved(entry, sent),
            () => this.#settle(entry, 'ambiguous', 'send_failed'),
          );
        }
      }
    }

    let evidence = await result;
    if (evidence.outcome === 'provider_accepted') {
      const drift = this.#connectionDriftCode(connection, parsed.accountJid);
      if (drift) evidence = this.#evidence(entry, 'ambiguous', drift, entry.candidate);
    }
    return evidence;
  }

  stats() {
    return Object.freeze({
      active: this.active.size,
      tombstones: this.tombstones.size,
      attempt_tombstones: this.attemptTombstones.size,
      dispatcher_listeners: this.connection?.sock.ev.listenerCount?.('messages.update') ?? 0,
    });
  }

  #submissionResolved(entry, sent) {
    if (entry.settled) return;
    const key = sent?.key;
    if (key?.id !== entry.messageId || key?.remoteJid !== entry.chatJid || key?.fromMe !== true) {
      this.#settle(entry, 'ambiguous', 'send_result_mismatch');
      return;
    }
    const drift = this.#entryDriftCode(entry);
    if (drift) {
      this.#settle(entry, 'ambiguous', drift);
      return;
    }
    entry.sendResolved = true;
    if (entry.timer !== null) this.clearTimeoutFn(entry.timer);
    entry.timer = null;
    if (entry.candidate) {
      if (this.#finishCandidate(entry)) return;
    }
    entry.timer = this.setTimeoutFn(
      () => this.#settle(entry, 'ambiguous', 'ack_timeout', entry.candidate),
      this.ackDeadlineMs,
    );
  }

  #dispatchUpdates(updates) {
    if (!Array.isArray(updates)) return;
    for (const value of updates) {
      const id = value?.key?.id;
      if (typeof id !== 'string') continue;
      const entry = this.active.get(id);
      if (!entry || entry.settled || !entry.submitted) continue;
      if (value?.key?.remoteJid !== entry.chatJid || value?.key?.fromMe !== true) continue;
      const drift = this.#entryDriftCode(entry);
      if (drift) {
        this.#settle(entry, 'ambiguous', drift);
        continue;
      }
      const status = value?.update?.status;
      const observedUs = safeNow(this.nowUs);
      if (observedUs === null) {
        this.#settle(entry, 'ambiguous', 'time_unavailable');
        continue;
      }
      if (observedUs < entry.identityObservedUs
          || (entry.sendStartedUs !== null && observedUs < entry.sendStartedUs)) {
        this.#settle(entry, 'ambiguous', 'time_unavailable');
        continue;
      }
      const candidate = { status, acceptedObservedUs: observedUs };
      const providerSeconds = value?.update?.messageTimestamp;
      // The pin maps a missing receipt `t` attribute to numeric zero. Treat
      // that sentinel as absent rather than manufacturing Unix-epoch evidence.
      if (Number.isSafeInteger(providerSeconds) && providerSeconds > 0
          && providerSeconds <= Math.floor(Number.MAX_SAFE_INTEGER / 1_000_000)) {
        candidate.providerTimestampUs = providerSeconds * 1_000_000;
      }
      entry.candidate = candidate;
      if (entry.sendResolved) this.#finishCandidate(entry);
    }
  }

  #finishCandidate(entry) {
    const { status } = entry.candidate;
    if (ACCEPTED_STATUSES.has(status)) {
      this.#settle(entry, 'provider_accepted', null, entry.candidate);
      return true;
    } else if (REJECTED_STATUSES.has(status)) {
      this.#settle(entry, 'provider_rejected', 'provider_rejected', entry.candidate);
      return true;
    } else if (INSUFFICIENT_STATUSES.has(status)) {
      return false;
    } else {
      this.#settle(entry, 'provider_rejected', 'provider_status_invalid', entry.candidate);
      return true;
    }
  }

  #liveAccountJid(sock) {
    try {
      return this.canonicalizeJid(sock?.user?.id || '');
    } catch {
      return null;
    }
  }

  #connectionDriftCode(connection, expectedAccount = connection?.accountJid) {
    if (!connection || this.connection !== connection) {
      if (!this.connection) return 'disconnect';
      if (this.connection.sock !== connection?.sock) return 'socket_replaced';
      if (this.connection.epoch !== connection?.epoch) return 'epoch_drift';
      return 'connection_unavailable';
    }
    if (this.#liveAccountJid(connection.sock) !== expectedAccount
        || connection.accountJid !== expectedAccount) return 'account_drift';
    return null;
  }

  #entryDriftCode(entry) {
    if (this.active.get(entry.messageId) !== entry) return 'registry_drift';
    if (!this.connection) return 'disconnect';
    if (this.connection.sock !== entry.sock) return 'socket_replaced';
    if (this.connection.epoch !== entry.epoch) return 'epoch_drift';
    if (this.connection.accountJid !== entry.accountJid
        || this.#liveAccountJid(entry.sock) !== entry.accountJid) return 'account_drift';
    return null;
  }

  #evidence(entry, outcome, errorCode, candidate = null) {
    const evidence = {
      outcome,
      submitted: entry.submitted,
      ...entry.echo,
      provider_account_jid: entry.accountJid,
      adapter_runtime_id: this.runtimeId,
      connection_epoch: entry.epoch,
      chat_jid: entry.chatJid,
      provider_message_id: entry.messageId,
      identity_observed_us: entry.identityObservedUs,
      transport_identity: this.transportIdentity,
    };
    if (entry.sendStartedUs !== null) evidence.send_started_us = entry.sendStartedUs;
    if (candidate && Number.isInteger(candidate.status)) evidence.provider_status_code = candidate.status;
    if (candidate?.providerTimestampUs !== undefined) {
      evidence.provider_timestamp_us = candidate.providerTimestampUs;
    }
    if (outcome === 'provider_accepted') {
      evidence.accepted_observed_us = candidate.acceptedObservedUs;
    }
    if (errorCode) evidence.error_code = errorCode;
    return Object.freeze(evidence);
  }

  #settle(entry, outcome, errorCode, candidate = null) {
    if (entry.settled) return false;
    entry.settled = true;
    if (entry.timer !== null) this.clearTimeoutFn(entry.timer);
    entry.timer = null;
    if (entry.abortSignal && entry.abortHandler) {
      entry.abortSignal.removeEventListener('abort', entry.abortHandler);
    }
    this.active.delete(entry.messageId);
    addBounded(this.tombstones, entry.messageId, true, this.tombstoneLimit);
    entry.resolveResult(this.#evidence(entry, outcome, errorCode, candidate ?? entry.candidate));
    return true;
  }

  #settleAll(reason) {
    for (const entry of [...this.active.values()]) {
      this.#settle(entry, entry.submitted ? 'ambiguous' : 'unavailable', reason);
    }
  }

  #closeConnection(reason) {
    const current = this.connection;
    if (!current) return;
    this.connection = null;
    try { current.sock.ev.off('messages.update', this._dispatcher); } catch {}
    this.#settleAll(reason);
  }
}
