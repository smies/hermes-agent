export const PROVIDER_MESSAGE_ID_PATTERN = /^3EB0[0-9A-F]{18}$/;
export const SENSITIVE_SUBMIT_CONTRACT_VERSION = 'juno-sensitive-submit-v2';

const MAX_PRIVATE_BYTES = 16 * 1024;
const MAX_OPAQUE_BYTES = 256;
const MAX_DEADLINE_AHEAD_US = 300_000_000;
const MIN_TRUSTED_EPOCH_US = 1_000_000_000_000_000;
const MAX_TRUSTED_EPOCH_US = Number.MAX_SAFE_INTEGER;

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

function baseOutcome(outcome, submitted, errorCode, extra = {}) {
  const result = { outcome, submitted, ...extra };
  if (errorCode) result.error_code = errorCode;
  return Object.freeze(result);
}

function canonicalDirectJid(value, canonicalizeJid) {
  if (typeof value !== 'string'
      || !/^\d{1,32}(?::\d{1,5})?@(s\.whatsapp\.net|lid|c\.us)$/.test(value)) {
    return { error: 'chat_not_direct' };
  }
  let canonical;
  try {
    canonical = canonicalizeJid(value);
  } catch {
    return { error: 'chat_not_canonical' };
  }
  return /^\d{1,32}@(s\.whatsapp\.net|lid)$/.test(canonical)
    ? { value: canonical }
    : { error: 'chat_not_canonical' };
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

export class SensitiveDeliveryTransport {
  constructor({
    runtimeId,
    ordinaryAccountJid,
    transportIdentity,
    canonicalizeJid,
    generateMessageId,
    nowUs = () => Date.now() * 1000,
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
    this.connection = null;
    this.enabled = true;
  }

  bindConnection({ sock, accountJid, epoch }) {
    if (!sock || typeof sock.sendMessage !== 'function' || typeof sock.ev?.on !== 'function'
        || typeof sock.ev?.off !== 'function') {
      throw new TypeError('invalid sensitive socket');
    }
    const account = canonicalAccountJid(accountJid, this.canonicalizeJid);
    if (account.error || !boundedString(epoch)) throw new TypeError('invalid sensitive connection');
    if (account.value !== this.ordinaryAccountJid) {
      throw new TypeError('same canonical account required');
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
  }

  unbindConnection(reason = 'disconnect') {
    this.#closeConnection(reason === 'disconnect' ? 'disconnect' : 'connection_unavailable');
  }

  setEnabled(enabled) {
    this.enabled = enabled === true;
    if (!this.enabled) this.connection = null;
  }

  identityEvidence(request) {
    if (!this.enabled || !this.connection) {
      return baseOutcome('unavailable', false, this.enabled ? 'not_connected' : 'service_disabled');
    }
    const fields = [
      'contract_version', 'operation', 'request_id', 'account',
      'destination', 'expires_at_us',
    ];
    const account = canonicalAccountJid(request?.account, this.canonicalizeJid);
    const destination = canonicalDirectJid(request?.destination, this.canonicalizeJid);
    const deadline = deadlineState(request?.expires_at_us, this.nowUs);
    if (!plainObject(request) || !exactKeys(request, fields)
        || request.contract_version !== SENSITIVE_SUBMIT_CONTRACT_VERSION
        || request.operation !== 'observe_identity'
        || !boundedString(request.request_id)
        || account.error || destination.error
        || account.value !== this.connection.accountJid
        || deadline.state !== 'live') {
      return baseOutcome('unavailable', false, 'identity_request_invalid');
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
    // Resolve the final destination against the live provider mapping. This is
    // deliberately the last asynchronous operation before the final deadline,
    // connection, and disclosure fences.
    if (await this.#ordinaryDestinationState(destination.value, connection) !== 'distinct') {
      return submitResult('failed', account.value, destination.value);
    }
    if (signal?.aborted || this.#connectionDriftCode(connection, account.value)) {
      return submitResult('failed', account.value, destination.value);
    }
    // No await, microtask, timer, or other event-loop yield may occur between
    // these final samples and the provider call.
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

  stats() {
    return Object.freeze({
      enabled: this.enabled,
      connected: this.connection !== null,
    });
  }

  async #ordinaryDestinationState(destination, connection) {
    if (destination === this.ordinaryAccountJid) return 'ordinary';
    const ordinaryNamespace = jidNamespace(this.ordinaryAccountJid);
    const destinationNamespace = jidNamespace(destination);
    if (ordinaryNamespace === destinationNamespace) return 'distinct';
    const mapping = connection.sock?.signalRepository?.lidMapping;
    if (!mapping || typeof mapping.getLIDForPN !== 'function') return 'unknown';
    const phone = ordinaryNamespace === 's.whatsapp.net'
      ? this.ordinaryAccountJid
      : destinationNamespace === 's.whatsapp.net' ? destination : null;
    const lid = ordinaryNamespace === 'lid'
      ? this.ordinaryAccountJid
      : destinationNamespace === 'lid' ? destination : null;
    if (!phone || !lid) return 'unknown';
    try {
      const mapped = this.canonicalizeJid(await mapping.getLIDForPN(phone));
      if (!/^\d{1,32}@lid$/.test(mapped)) return 'unknown';
      return mapped === lid ? 'ordinary' : 'distinct';
    } catch {
      return 'unknown';
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

  #closeConnection(reason) {
    this.connection = null;
  }
}
