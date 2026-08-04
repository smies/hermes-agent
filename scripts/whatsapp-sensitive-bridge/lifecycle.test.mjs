import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  buildSensitiveSocketConfig,
  SensitiveSocketLifecycle,
} from './lifecycle.js';
import { prepareSessionPaths } from './session_paths.js';

const SENSITIVE_ACCOUNT = '15551234567@s.whatsapp.net';
const ORDINARY_ACCOUNT = '15559876543@s.whatsapp.net';
const REAL_TMP = realpathSync.native(tmpdir());

function fakeSocket() {
  return {
    ev: new EventEmitter(),
    user: { id: '15551234567:4@s.whatsapp.net' },
    endCalls: 0,
    end() { this.endCalls += 1; },
  };
}

function freshSessionPaths() {
  const root = mkdtempSync(path.join(REAL_TMP, 'hermes-sensitive-session-'));
  const sensitive = path.join(root, 'sensitive');
  const ordinary = path.join(root, 'ordinary');
  mkdirSync(ordinary, { mode: 0o700 });
  return {
    root,
    sensitive,
    ordinary,
    sessionPathGuard: prepareSessionPaths(sensitive, ordinary),
  };
}

function replaceSensitiveWithOrdinaryAlias(root, sensitive, ordinary) {
  renameSync(sensitive, path.join(root, 'displaced-sensitive'));
  symlinkSync(ordinary, sensitive, 'dir');
}

function ordinaryTreeSnapshot(ordinary) {
  const stat = lstatSync(ordinary, { bigint: true });
  return {
    entries: readdirSync(ordinary).sort(),
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    size: stat.size,
    mtimeNs: stat.mtimeNs,
    ctimeNs: stat.ctimeNs,
  };
}

test('socket config explicitly disables own events, history/offline sync, retry/cache/retransmission, and replay sources', async () => {
  const auth = { creds: {}, keys: {} };
  const config = buildSensitiveSocketConfig({ auth, logger: { child() { return this; } } });
  assert.equal(config.auth, auth);
  assert.equal(config.emitOwnEvents, false);
  assert.equal(config.enableRecentMessageCache, false);
  assert.equal(config.maxMsgRetryCount, 0);
  assert.equal(config.retryRequestDelayMs, 0);
  assert.equal(config.enableAutoSessionRecreation, false);
  assert.equal(await config.getMessage({ id: 'sensitive-id' }), undefined);
  assert.equal(await config.cachedGroupMetadata('synthetic@g.us'), undefined);
  assert.equal(config.syncFullHistory, false);
  assert.equal(config.fireInitQueries, false);
  assert.equal(config.shouldSyncHistoryMessage({ syncType: 0 }), false);
  for (const cache of ['mediaCache', 'msgRetryCounterCache', 'userDevicesCache', 'callOfferCache', 'placeholderResendCache']) {
    assert.equal(Object.hasOwn(config, cache), true);
    assert.equal(config[cache], undefined);
  }
  assert.equal(config.markOnlineOnConnect, false);
});

test('lifecycle uses only the dedicated session path and never touches an ordinary fixture', async () => {
  const root = mkdtempSync(path.join(REAL_TMP, 'hermes-sensitive-session-'));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  mkdirSync(ordinary, { mode: 0o700 });
  const ordinarySentinel = path.join(ordinary, 'sentinel');
  writeFileSync(ordinarySentinel, 'ordinary-session-sentinel');
  const sessionPathGuard = prepareSessionPaths(sensitive, ordinary);
  const authPaths = [];
  const lifecycle = new SensitiveSocketLifecycle({
    sessionPathGuard,
    expectedSensitiveAccountJid: SENSITIVE_ACCOUNT,
    ordinaryAccountJid: ORDINARY_ACCOUNT,
    useAuthState: async (dir) => { authPaths.push(dir); return { state: {}, saveCreds() {} }; },
    makeSocket: () => fakeSocket(),
    onBound() {},
    onUnbound() {},
    reconnectDelayMs: 5,
  });
  await lifecycle.start();
  assert.deepEqual(authPaths, [sensitive]);
  assert.equal(readFileSync(ordinarySentinel, 'utf8'), 'ordinary-session-sentinel');
  lifecycle.stop();
});

test('closed generation cannot reopen and duplicate close schedules one tracked reconnect', async () => {
  const { sessionPathGuard } = freshSessionPaths();
  const sockets = [];
  const timers = [];
  const bound = [];
  const unbound = [];
  const lifecycle = new SensitiveSocketLifecycle({
    sessionPathGuard,
    expectedSensitiveAccountJid: SENSITIVE_ACCOUNT,
    ordinaryAccountJid: ORDINARY_ACCOUNT,
    useAuthState: async () => ({ state: {}, saveCreds() {} }),
    makeSocket: () => { const sock = fakeSocket(); sockets.push(sock); return sock; },
    canonicalizeJid: (jid) => jid.replace(/:\d+@/, '@'),
    onBound: (value) => bound.push(value),
    onUnbound: (value) => unbound.push(value),
    setTimeoutFn: (fn, ms) => { const timer = { fn, ms, cleared: false }; timers.push(timer); return timer; },
    clearTimeoutFn: (timer) => { timer.cleared = true; },
    reconnectDelayMs: 25,
    epochFactory: (generation) => `epoch-${generation}`,
  });

  await lifecycle.start();
  const first = sockets[0];
  first.ev.emit('connection.update', { connection: 'open' });
  assert.equal(bound.length, 1);
  first.ev.emit('connection.update', { connection: 'close' });
  first.ev.emit('connection.update', { connection: 'close' });
  assert.equal(unbound.length, 1);
  assert.equal(lifecycle.connectionEpoch, null);
  assert.equal(timers.length, 1);
  first.ev.emit('connection.update', { connection: 'open' });
  assert.equal(bound.length, 1, 'stale closed generation cannot reopen');

  await timers[0].fn();
  assert.equal(sockets.length, 2);
  sockets[1].ev.emit('connection.update', { connection: 'open' });
  assert.equal(bound.length, 2);
  lifecycle.stop();
  assert.equal(lifecycle.connectionEpoch, null);
});

test('same ordinary and sensitive account identities reject lifecycle construction', () => {
  const { sessionPathGuard } = freshSessionPaths();
  assert.throws(() => new SensitiveSocketLifecycle({
    sessionPathGuard,
    expectedSensitiveAccountJid: SENSITIVE_ACCOUNT,
    ordinaryAccountJid: SENSITIVE_ACCOUNT,
    useAuthState: async () => ({ state: {}, saveCreds() {} }),
    makeSocket: () => fakeSocket(),
    canonicalizeJid: (jid) => jid.replace(/:\d+@/, '@'),
  }), /separate sensitive account required/);
});

test('account identities in different provider namespaces reject as unverifiable', () => {
  const { sessionPathGuard } = freshSessionPaths();
  assert.throws(() => new SensitiveSocketLifecycle({
    sessionPathGuard,
    expectedSensitiveAccountJid: SENSITIVE_ACCOUNT,
    ordinaryAccountJid: '987654321@lid',
    useAuthState: async () => ({ state: {}, saveCreds() {} }),
    makeSocket: () => fakeSocket(),
    canonicalizeJid: (jid) => jid.replace(/:\d+@/, '@'),
  }), /account identity namespace mismatch/);
});

test('loaded auth identity must match the expected sensitive account before socket creation', async () => {
  const { sessionPathGuard } = freshSessionPaths();
  let madeSocket = false;
  const fatal = [];
  const lifecycle = new SensitiveSocketLifecycle({
    sessionPathGuard,
    expectedSensitiveAccountJid: SENSITIVE_ACCOUNT,
    ordinaryAccountJid: ORDINARY_ACCOUNT,
    useAuthState: async () => ({
      state: { creds: { me: { id: `${ORDINARY_ACCOUNT.split('@')[0]}:4@s.whatsapp.net` } } },
      saveCreds() {},
    }),
    makeSocket: () => { madeSocket = true; return fakeSocket(); },
    canonicalizeJid: (jid) => jid.replace(/:\d+@/, '@'),
    onFatal: (code) => fatal.push(code),
  });
  await lifecycle.start();
  assert.equal(madeSocket, false);
  assert.deepEqual(fatal, ['sensitive_account_mismatch']);
  assert.equal(lifecycle.running, false);
});

test('loaded auth cannot hide the ordinary account behind a matching sensitive identity', async () => {
  const { sessionPathGuard } = freshSessionPaths();
  let madeSocket = false;
  const fatal = [];
  const lifecycle = new SensitiveSocketLifecycle({
    sessionPathGuard,
    expectedSensitiveAccountJid: SENSITIVE_ACCOUNT,
    ordinaryAccountJid: ORDINARY_ACCOUNT,
    useAuthState: async () => ({
      state: {
        creds: {
          me: {
            id: `${SENSITIVE_ACCOUNT.split('@')[0]}:4@s.whatsapp.net`,
            lid: `${ORDINARY_ACCOUNT.split('@')[0]}:8@s.whatsapp.net`,
          },
        },
      },
      saveCreds() {},
    }),
    makeSocket: () => { madeSocket = true; return fakeSocket(); },
    canonicalizeJid: (jid) => jid.replace(/:\d+@/, '@'),
    onFatal: (code) => fatal.push(code),
  });
  await lifecycle.start();
  assert.equal(madeSocket, false);
  assert.deepEqual(fatal, ['sensitive_account_mismatch']);
  assert.equal(lifecycle.running, false);
});

test('live socket identity mismatch is fatal and never binds or reconnects', async () => {
  const { sessionPathGuard } = freshSessionPaths();
  const sock = fakeSocket();
  sock.user.id = `${ORDINARY_ACCOUNT.split('@')[0]}:4@s.whatsapp.net`;
  const bound = [];
  const fatal = [];
  const timers = [];
  const lifecycle = new SensitiveSocketLifecycle({
    sessionPathGuard,
    expectedSensitiveAccountJid: SENSITIVE_ACCOUNT,
    ordinaryAccountJid: ORDINARY_ACCOUNT,
    useAuthState: async () => ({ state: {}, saveCreds() {} }),
    makeSocket: () => sock,
    canonicalizeJid: (jid) => jid.replace(/:\d+@/, '@'),
    onBound: (value) => bound.push(value),
    onFatal: (code) => fatal.push(code),
    setTimeoutFn: (fn) => { timers.push(fn); return fn; },
  });
  await lifecycle.start();
  sock.ev.emit('connection.update', { connection: 'open' });
  assert.deepEqual(bound, []);
  assert.deepEqual(fatal, ['sensitive_account_mismatch']);
  assert.equal(lifecycle.running, false);
  assert.equal(lifecycle.connectionEpoch, null);
  assert.equal(sock.endCalls, 1);
  assert.deepEqual(timers, []);
});

test('sensitive identity swap after auth loading is fatal before socket creation', async () => {
  const { root, sensitive, sessionPathGuard } = freshSessionPaths();
  let authCalls = 0;
  let socketCalls = 0;
  const fatal = [];
  const lifecycle = new SensitiveSocketLifecycle({
    sessionPathGuard,
    expectedSensitiveAccountJid: SENSITIVE_ACCOUNT,
    ordinaryAccountJid: ORDINARY_ACCOUNT,
    useAuthState: async () => {
      authCalls += 1;
      renameSync(sensitive, path.join(root, 'displaced-sensitive'));
      mkdirSync(sensitive, { mode: 0o700 });
      return { state: {}, saveCreds() {} };
    },
    makeSocket: () => { socketCalls += 1; return fakeSocket(); },
    onFatal: (code) => fatal.push(code),
  });

  await lifecycle.start();
  assert.equal(authCalls, 1);
  assert.equal(socketCalls, 0);
  assert.deepEqual(fatal, ['session_path_rejected']);
  assert.equal(lifecycle.running, false);
});

test('sensitive symlink alias is rejected before auth-state access', async () => {
  const { root, sensitive, ordinary, sessionPathGuard } = freshSessionPaths();
  renameSync(sensitive, path.join(root, 'displaced-sensitive'));
  symlinkSync(ordinary, sensitive, 'dir');
  let authCalls = 0;
  let socketCalls = 0;
  const lifecycle = new SensitiveSocketLifecycle({
    sessionPathGuard,
    expectedSensitiveAccountJid: SENSITIVE_ACCOUNT,
    ordinaryAccountJid: ORDINARY_ACCOUNT,
    useAuthState: async () => { authCalls += 1; return { state: {}, saveCreds() {} }; },
    makeSocket: () => { socketCalls += 1; return fakeSocket(); },
  });

  await lifecycle.start();
  assert.equal(authCalls, 0);
  assert.equal(socketCalls, 0);
  assert.equal(lifecycle.fatalCode, 'session_path_rejected');
});

test('persistent post-start sensitive alias blocks every auth path operation and tears down once', async (t) => {
  for (const operation of ['saveCreds', 'keys.get', 'keys.set']) {
    await t.test(operation, async () => {
      const { root, sensitive, ordinary, sessionPathGuard } = freshSessionPaths();
      const sentinel = path.join(ordinary, 'sentinel');
      writeFileSync(sentinel, 'ordinary-session-sentinel');
      const ordinaryBefore = ordinaryTreeSnapshot(ordinary);
      const calls = { saveCreds: 0, get: 0, set: 0 };
      const fatal = [];
      const timers = [];
      const sock = fakeSocket();
      let socketAuth;
      const lifecycle = new SensitiveSocketLifecycle({
        sessionPathGuard,
        expectedSensitiveAccountJid: SENSITIVE_ACCOUNT,
        ordinaryAccountJid: ORDINARY_ACCOUNT,
        useAuthState: async () => ({
          state: {
            creds: {},
            keys: {
              async get() { calls.get += 1; return {}; },
              async set() { calls.set += 1; },
            },
          },
          async saveCreds() { calls.saveCreds += 1; },
        }),
        makeSocket: (config) => { socketAuth = config.auth; return sock; },
        onFatal: (code) => fatal.push(code),
        setTimeoutFn: (fn) => { timers.push(fn); return fn; },
      });
      await lifecycle.start();
      replaceSensitiveWithOrdinaryAlias(root, sensitive, ordinary);

      if (operation === 'saveCreds') {
        sock.ev.emit('creds.update', { changed: true });
        await new Promise((resolve) => setImmediate(resolve));
      } else if (operation === 'keys.get') {
        await assert.rejects(socketAuth.keys.get('session', ['id']), {
          code: 'session_path_rejected',
        });
      } else {
        await assert.rejects(socketAuth.keys.set({ session: { id: {} } }), {
          code: 'session_path_rejected',
        });
      }

      assert.deepEqual(calls, { saveCreds: 0, get: 0, set: 0 });
      assert.equal(readFileSync(sentinel, 'utf8'), 'ordinary-session-sentinel');
      assert.deepEqual(ordinaryTreeSnapshot(ordinary), ordinaryBefore);
      assert.deepEqual(fatal, ['session_path_rejected']);
      assert.equal(lifecycle.running, false);
      assert.equal(lifecycle.socket, null);
      assert.equal(sock.endCalls, 1);
      assert.deepEqual(timers, []);
    });
  }
});

test('sensitive alias swap during async auth operation fails its post-check and forbids later operations', async () => {
  const { root, sensitive, ordinary, sessionPathGuard } = freshSessionPaths();
  const sentinel = path.join(ordinary, 'sentinel');
  writeFileSync(sentinel, 'ordinary-session-sentinel');
  const ordinaryBefore = ordinaryTreeSnapshot(ordinary);
  let rejectGet;
  let getCalls = 0;
  let setCalls = 0;
  const fatal = [];
  const sock = fakeSocket();
  let socketAuth;
  const lifecycle = new SensitiveSocketLifecycle({
    sessionPathGuard,
    expectedSensitiveAccountJid: SENSITIVE_ACCOUNT,
    ordinaryAccountJid: ORDINARY_ACCOUNT,
    useAuthState: async () => ({
      state: {
        creds: {},
        keys: {
          get() {
            getCalls += 1;
            return new Promise((resolve, reject) => { rejectGet = reject; });
          },
          async set() { setCalls += 1; },
        },
      },
      async saveCreds() {},
    }),
    makeSocket: (config) => { socketAuth = config.auth; return sock; },
    onFatal: (code) => fatal.push(code),
  });
  await lifecycle.start();

  const pendingGet = socketAuth.keys.get('session', ['id']);
  assert.equal(getCalls, 1);
  replaceSensitiveWithOrdinaryAlias(root, sensitive, ordinary);
  rejectGet(new Error('underlying auth operation failed'));
  await assert.rejects(pendingGet, { code: 'session_path_rejected' });
  await assert.rejects(socketAuth.keys.set({ session: { id: {} } }), {
    code: 'session_path_rejected',
  });
  await assert.rejects(socketAuth.keys.get('session', ['later']), {
    code: 'session_path_rejected',
  });

  assert.equal(getCalls, 1);
  assert.equal(setCalls, 0);
  assert.equal(readFileSync(sentinel, 'utf8'), 'ordinary-session-sentinel');
  assert.deepEqual(ordinaryTreeSnapshot(ordinary), ordinaryBefore);
  assert.deepEqual(fatal, ['session_path_rejected']);
  assert.equal(lifecycle.running, false);
  assert.equal(lifecycle.socket, null);
  assert.equal(sock.endCalls, 1);
});
