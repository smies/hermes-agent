import { SessionPathGuard } from './session_paths.js';

export function buildSensitiveSocketConfig({ auth, logger }) {
  return {
    auth,
    logger,
    printQRInTerminal: false,
    // Exact @whiskeysockets/baileys@7.0.0-rc14 Browsers.macOS('Chrome').
    browser: ['Mac OS', 'Chrome', '14.4.1'],
    syncFullHistory: false,
    fireInitQueries: false,
    // The production session must finish its LID bootstrap during offline
    // provisioning. This delivery process never accepts history sync payloads.
    shouldSyncHistoryMessage: () => false,
    markOnlineOnConnect: false,
    emitOwnEvents: false,
    enableRecentMessageCache: false,
    maxMsgRetryCount: 0,
    retryRequestDelayMs: 0,
    enableAutoSessionRecreation: false,
    mediaCache: undefined,
    msgRetryCounterCache: undefined,
    userDevicesCache: undefined,
    callOfferCache: undefined,
    placeholderResendCache: undefined,
    cachedGroupMetadata: async () => undefined,
    // Receipt-triggered retransmission must never recover sensitive plaintext.
    getMessage: async () => undefined,
  };
}

export function createSilentLogger() {
  const logger = {
    level: 'silent',
    child: () => logger,
    trace() {},
    debug() {},
    info() {},
    warn() {},
    error() {},
    fatal() {},
  };
  return Object.freeze(logger);
}

function sessionPathRejectedError() {
  const error = new Error('session path rejected');
  error.code = 'session_path_rejected';
  return error;
}

export class SensitiveSocketLifecycle {
  constructor({
    sessionPathGuard,
    expectedSensitiveAccountJid,
    ordinaryAccountJid,
    useAuthState,
    makeSocket,
    canonicalizeJid = (value) => value,
    onBound,
    onUnbound,
    onFatal,
    logger = createSilentLogger(),
    reconnectDelayMs = 3_000,
    setTimeoutFn = setTimeout,
    clearTimeoutFn = clearTimeout,
    epochFactory = (generation) => `connection-${generation}-${Date.now().toString(36)}`,
  }) {
    if (!(sessionPathGuard instanceof SessionPathGuard)) {
      throw new TypeError('validated sensitive session path is required');
    }
    if (typeof useAuthState !== 'function' || typeof makeSocket !== 'function') {
      throw new TypeError('sensitive socket dependencies are required');
    }
    this.sessionPathGuard = sessionPathGuard;
    this.sessionDir = sessionPathGuard.sensitiveDir;
    this.useAuthState = useAuthState;
    this.makeSocket = makeSocket;
    this.canonicalizeJid = canonicalizeJid;
    this.expectedSensitiveAccountJid = this.#canonicalAccount(expectedSensitiveAccountJid);
    this.ordinaryAccountJid = this.#canonicalAccount(ordinaryAccountJid);
    if (!this.expectedSensitiveAccountJid || !this.ordinaryAccountJid) {
      throw new TypeError('canonical sensitive and ordinary account identities are required');
    }
    if (this.expectedSensitiveAccountJid !== this.ordinaryAccountJid) {
      throw new TypeError('same canonical account required');
    }
    this.onBound = typeof onBound === 'function' ? onBound : () => {};
    this.onUnbound = typeof onUnbound === 'function' ? onUnbound : () => {};
    this.onFatal = typeof onFatal === 'function' ? onFatal : () => {};
    this.logger = logger;
    this.reconnectDelayMs = Math.max(1, Math.floor(reconnectDelayMs));
    this.setTimeoutFn = setTimeoutFn;
    this.clearTimeoutFn = clearTimeoutFn;
    this.epochFactory = epochFactory;
    this.running = false;
    this.generation = 0;
    this.socket = null;
    this.connectionEpoch = null;
    this._record = null;
    this._reconnectTimer = null;
    this.fatalCode = null;
  }

  async start() {
    if (this.running) return;
    this.running = true;
    await this.#connectGeneration();
  }

  stop() {
    if (!this.running && !this._record) return;
    this.running = false;
    if (this._reconnectTimer !== null) {
      this.clearTimeoutFn(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    const record = this._record;
    this._record = null;
    this.socket = null;
    this.connectionEpoch = null;
    if (record) {
      record.closed = true;
      try { record.sock.ev.off('connection.update', record.onConnection); } catch {}
      try { record.sock.ev.off('creds.update', record.onCreds); } catch {}
      if (record.bound) this.onUnbound('service_disabled');
      try { record.sock.end?.(); } catch {}
    }
  }

  async #connectGeneration() {
    if (!this.running) return;
    const generation = ++this.generation;
    try {
      this.sessionPathGuard.revalidate();
    } catch {
      this.#fatal('session_path_rejected');
      return;
    }
    let auth;
    try {
      auth = await this.useAuthState(this.sessionDir);
    } catch {
      this.#scheduleReconnect(generation);
      return;
    }
    try {
      this.sessionPathGuard.revalidate();
    } catch {
      this.#fatal('session_path_rejected');
      return;
    }
    if (!this.running || generation !== this.generation) return;
    const storedPhone = this.#canonicalAccount(auth?.state?.creds?.me?.id);
    const storedLid = this.#canonicalAccount(auth?.state?.creds?.me?.lid);
    if ((storedPhone && storedPhone !== this.expectedSensitiveAccountJid)
        || (auth?.state?.creds?.me?.lid && (!storedLid || !storedLid.endsWith('@lid')))) {
      this.#fatal('sensitive_account_mismatch');
      return;
    }
    const guardedAuth = this.#wrapAuthState(auth, generation);
    let sock;
    try {
      sock = this.makeSocket(buildSensitiveSocketConfig({
        auth: guardedAuth.state,
        logger: this.logger,
      }));
    } catch {
      this.#scheduleReconnect(generation);
      return;
    }
    if (!this.running || generation !== this.generation) {
      try { sock.end?.(); } catch {}
      return;
    }
    const record = {
      generation,
      sock,
      saveCreds: guardedAuth.saveCreds,
      closed: false,
      bound: false,
      onConnection: null,
      onCreds: null,
    };
    record.onCreds = () => {
      if (!record.closed && this._record === record) {
        void Promise.resolve(record.saveCreds?.()).catch(() => {});
      }
    };
    record.onConnection = (update) => this.#handleConnection(record, update);
    this._record = record;
    this.socket = sock;
    sock.ev.on('creds.update', record.onCreds);
    sock.ev.on('connection.update', record.onConnection);
  }

  #handleConnection(record, update) {
    if (this._record !== record || record.closed || record.generation !== this.generation) return;
    if (update?.connection === 'open') {
      if (record.bound) return;
      let accountJid;
      try {
        accountJid = this.canonicalizeJid(record.sock.user?.id || '');
      } catch {
        accountJid = '';
      }
      if (!accountJid || accountJid !== this.expectedSensitiveAccountJid) {
        this.#failRecord(record, 'sensitive_account_mismatch');
        return;
      }
      const epoch = this.epochFactory(record.generation);
      if (typeof epoch !== 'string' || epoch.length === 0 || epoch.length > 256) {
        this.#closeRecord(record, 'epoch_unavailable');
        return;
      }
      record.bound = true;
      this.connectionEpoch = epoch;
      this.onBound({ sock: record.sock, accountJid, epoch });
      return;
    }
    if (update?.connection === 'close') this.#closeRecord(record, 'disconnect');
  }

  #closeRecord(record, reason) {
    if (record.closed) return;
    record.closed = true;
    if (this._record === record) {
      this._record = null;
      this.socket = null;
      this.connectionEpoch = null;
    }
    try { record.sock.ev.off('connection.update', record.onConnection); } catch {}
    try { record.sock.ev.off('creds.update', record.onCreds); } catch {}
    if (record.bound) this.onUnbound(reason);
    this.#scheduleReconnect(record.generation);
  }

  #scheduleReconnect(closedGeneration) {
    if (!this.running || this._reconnectTimer !== null) return;
    this._reconnectTimer = this.setTimeoutFn(async () => {
      this._reconnectTimer = null;
      if (!this.running || this.generation !== closedGeneration) return;
      await this.#connectGeneration();
    }, this.reconnectDelayMs);
  }

  #canonicalAccount(value) {
    if (typeof value !== 'string') return null;
    let canonical;
    try { canonical = this.canonicalizeJid(value); } catch { return null; }
    return /^\d{1,32}@(s\.whatsapp\.net|lid)$/.test(canonical) ? canonical : null;
  }

  #wrapAuthState(auth, generation) {
    const state = auth?.state || {};
    const keys = state.keys;
    const guardedKeys = keys && typeof keys === 'object' ? {
      ...keys,
      get: typeof keys.get === 'function'
        ? (...args) => this.#runAuthPathOperation(generation, keys, keys.get, args)
        : keys.get,
      set: typeof keys.set === 'function'
        ? (...args) => this.#runAuthPathOperation(generation, keys, keys.set, args)
        : keys.set,
    } : keys;
    return {
      state: { ...state, keys: guardedKeys },
      saveCreds: typeof auth?.saveCreds === 'function'
        ? (...args) => this.#runAuthPathOperation(generation, auth, auth.saveCreds, args)
        : auth?.saveCreds,
    };
  }

  async #runAuthPathOperation(generation, receiver, operation, args) {
    if (!this.running || this.fatalCode !== null || generation !== this.generation) {
      throw sessionPathRejectedError();
    }
    try {
      this.sessionPathGuard.revalidate();
    } catch {
      this.#fatal('session_path_rejected');
      throw sessionPathRejectedError();
    }

    let result;
    let operationError;
    let operationFailed = false;
    try {
      result = await Reflect.apply(operation, receiver, args);
    } catch (error) {
      operationFailed = true;
      operationError = error;
    }

    try {
      this.sessionPathGuard.revalidate();
    } catch {
      this.#fatal('session_path_rejected');
      throw sessionPathRejectedError();
    }
    if (!this.running || this.fatalCode !== null || generation !== this.generation) {
      throw sessionPathRejectedError();
    }
    if (operationFailed) throw operationError;
    return result;
  }

  #fatal(code) {
    if (this.fatalCode !== null) return;
    this.running = false;
    this.fatalCode = code;
    this.generation += 1;
    if (this._reconnectTimer !== null) {
      this.clearTimeoutFn(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    const record = this._record;
    this._record = null;
    this.socket = null;
    this.connectionEpoch = null;
    if (record && !record.closed) {
      record.closed = true;
      try { record.sock.ev.off('connection.update', record.onConnection); } catch {}
      try { record.sock.ev.off('creds.update', record.onCreds); } catch {}
      if (record.bound) this.onUnbound(code);
      try { record.sock.end?.(); } catch {}
    }
    try { this.onFatal(code); } catch {}
  }

  #failRecord(record, code) {
    if (record.closed || this._record !== record) return;
    this.#fatal(code);
  }
}
