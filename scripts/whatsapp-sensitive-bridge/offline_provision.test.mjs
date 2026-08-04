import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { provisionOffline } from './offline_provision.js';
import { parseProvisioningRequest } from './provisioning_core.js';

function identities() {
  const phone = `1${'6'.repeat(10)}`;
  return { phone, phoneJid: `${phone}@s.whatsapp.net`, lidJid: `${'8'.repeat(9)}@lid` };
}

function fakeSocket({ phoneJid, lidJid, update, onPairingCode }) {
  const ev = new EventEmitter();
  const socket = {
    ev,
    user: { id: phoneJid },
    signalRepository: { lidMapping: { getLIDForPN: async () => lidJid } },
    requestPairingCode: async () => {
      onPairingCode();
      return 'A1B2-C3D4';
    },
    endCalled: false,
    end() { this.endCalled = true; },
  };
  queueMicrotask(() => ev.emit('connection.update', update(socket)));
  return socket;
}

test('offline provisioning uses only requestPairingCode and persists canonical LID readiness', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-provision-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const { phone, phoneJid, lidJid } = identities();
  const ordinaryPhoneJid = `${`2${'4'.repeat(10)}`}@s.whatsapp.net`;
  const ordinaryLidJid = `${'7'.repeat(9)}@lid`;
  let pairingCalls = 0;
  let sendCalls = 0;
  let socket;
  try {
    await chmod(root, 0o700);
    await mkdir(ordinary, { mode: 0o700 });
    await writeFile(path.join(ordinary, 'creds.json'), JSON.stringify({
      registered: true,
      me: { id: ordinaryPhoneJid },
    }), { mode: 0o600 });
    const request = parseProvisioningRequest({
      version: 1,
      action: 'provision',
      role: 'sensitive',
      phone,
      ordinary_session: ordinary,
      sensitive_session: sensitive,
    });
    const result = await provisionOffline({
      request,
      canonicalizeJid: (value) => String(value).replace(/:\d+@/, '@'),
      useAuthState: async (session) => ({
        state: session === ordinary ? {
          creds: { registered: true, me: { id: ordinaryPhoneJid } },
          keys: { get: async () => ({
            [ordinaryPhoneJid.split('@')[0]]: ordinaryLidJid.split('@')[0],
          }) },
        } : {
          creds: { registered: false },
          keys: {
            get: async () => ({ [phoneJid.split('@')[0]]: lidJid.split('@')[0] }),
            set: async () => {},
          },
        },
        saveCreds: async () => {
          await writeFile(path.join(session, 'creds.json'), '{}', { mode: 0o600 });
          await chmod(path.join(session, 'creds.json'), 0o600);
        },
      }),
      makeSocket: () => {
        socket = fakeSocket({
          phoneJid,
          lidJid,
          onPairingCode: () => { pairingCalls += 1; },
          update: () => ({ connection: 'connecting' }),
        });
        socket.sendMessage = () => { sendCalls += 1; };
        queueMicrotask(() => socket.ev.emit('connection.update', { connection: 'open' }));
        return socket;
      },
      emitCode: (code) => assert.equal(code, 'A1B2-C3D4'),
      timeoutMs: 2_000,
    });
    assert.deepEqual(result, { account_namespace: 's.whatsapp.net', lid_ready: true });
    assert.equal(pairingCalls, 1);
    assert.equal(sendCalls, 0);
    assert.equal(socket.endCalled, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('offline provisioning closes the socket on a forbidden alternate payload', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-provision-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const { phone, phoneJid, lidJid } = identities();
  let socket;
  try {
    const request = parseProvisioningRequest({
      version: 1,
      action: 'provision',
      role: 'ordinary',
      phone,
      ordinary_session: ordinary,
      sensitive_session: sensitive,
    });
    await assert.rejects(provisionOffline({
      request,
      canonicalizeJid: (value) => String(value),
      useAuthState: async () => ({ state: { creds: {}, keys: {} }, saveCreds: async () => {} }),
      makeSocket: () => {
        socket = fakeSocket({
          phoneJid,
          lidJid,
          onPairingCode: () => {},
          update: () => ({ qr: 'forbidden' }),
        });
        return socket;
      },
      emitCode: () => assert.fail('pairing code must not be emitted'),
      timeoutMs: 2_000,
    }), /qr_payload_forbidden/);
    assert.equal(socket.endCalled, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('reprovision stages fresh auth, requests a fresh code, and preserves existing bytes and inode on failure', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-reprovision-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'3'.repeat(10)}`;
  const original = JSON.stringify({ registered: true, me: { id: `${phone}@s.whatsapp.net` } });
  let authPath;
  let pairingCalls = 0;
  try {
    await chmod(root, 0o700);
    await mkdir(ordinary, { mode: 0o700 });
    await writeFile(path.join(ordinary, 'creds.json'), original, { mode: 0o600 });
    const before = await stat(path.join(ordinary, 'creds.json'));
    const request = parseProvisioningRequest({
      version: 1,
      action: 'provision',
      reprovision: true,
      role: 'ordinary',
      phone,
      ordinary_session: ordinary,
      sensitive_session: sensitive,
    });
    await assert.rejects(provisionOffline({
      request,
      canonicalizeJid: (value) => String(value).replace(/:\d+@/, '@'),
      useAuthState: async (session) => {
        authPath = session;
        return {
          // Even a misleading registered flag in the newly staged provider
          // object must not suppress the explicit fresh-code request.
          state: { creds: { registered: true }, keys: { get: async () => ({}), set: async () => {} } },
          saveCreds: async () => {
            await writeFile(path.join(session, 'creds.json'), '{}', { mode: 0o600 });
          },
        };
      },
      makeSocket: ({ auth }) => {
        const ev = new EventEmitter();
        const socket = {
          ev,
          user: { id: `${phone}@s.whatsapp.net` },
          requestPairingCode: async () => { pairingCalls += 1; return 'R3PR-0V1S'; },
          end() {},
        };
        queueMicrotask(() => ev.emit('connection.update', { connection: 'connecting' }));
        queueMicrotask(() => ev.emit('connection.update', { connection: 'close' }));
        return socket;
      },
      emitCode: () => {},
      timeoutMs: 2_000,
    }), /connection_closed/);
    const after = await stat(path.join(ordinary, 'creds.json'));
    assert.notEqual(authPath, ordinary);
    assert.match(path.basename(authPath), /^\.whatsapp-provision-stage-/);
    assert.equal(pairingCalls, 1);
    assert.equal(await readFile(path.join(ordinary, 'creds.json'), 'utf8'), original);
    assert.equal(after.ino, before.ino);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('suspicious pre-existing auth modes are rejected without repair or provider access', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-unsafe-reuse-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'5'.repeat(10)}`;
  try {
    await chmod(root, 0o700);
    await mkdir(ordinary, { mode: 0o700 });
    const credentials = path.join(ordinary, 'creds.json');
    await writeFile(credentials, JSON.stringify({
      registered: true,
      me: { id: `${phone}@s.whatsapp.net` },
    }), { mode: 0o644 });
    await chmod(credentials, 0o644);
    const before = await stat(credentials);
    const request = parseProvisioningRequest({
      version: 1,
      action: 'provision',
      reprovision: true,
      role: 'ordinary',
      phone,
      ordinary_session: ordinary,
      sensitive_session: sensitive,
    });
    await assert.rejects(provisionOffline({
      request,
      useAuthState: async () => assert.fail('unsafe reuse must fail before provider auth'),
      makeSocket: () => assert.fail('unsafe reuse must fail before socket creation'),
      canonicalizeJid: (value) => String(value),
      emitCode: () => assert.fail('unsafe reuse must not emit a code'),
      timeoutMs: 2_000,
    }), /auth_file_unsafe/);
    const after = await stat(credentials);
    assert.equal(after.mode & 0o777, 0o644);
    assert.equal(after.ino, before.ino);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('cross-role lock permits only one concurrent same-account provisioning attempt', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-race-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'2'.repeat(10)}`;
  let releaseFirst;
  const firstMayContinue = new Promise((resolve) => { releaseFirst = resolve; });
  try {
    await chmod(root, 0o700);
    const request = parseProvisioningRequest({
      version: 1,
      action: 'provision',
      role: 'ordinary',
      phone,
      ordinary_session: ordinary,
      sensitive_session: sensitive,
    });
    const first = provisionOffline({
      request,
      canonicalizeJid: (value) => String(value).replace(/:\d+@/, '@'),
      useAuthState: async (session) => ({
        state: {
          creds: { registered: false },
          keys: {
            get: async () => ({ [phone]: '777777777' }),
            set: async () => {},
          },
        },
        saveCreds: async () => {
          await writeFile(path.join(session, 'creds.json'), '{}', { mode: 0o600 });
        },
      }),
      makeSocket: () => {
        const ev = new EventEmitter();
        const socket = {
          ev,
          user: { id: `${phone}@s.whatsapp.net` },
          signalRepository: { lidMapping: { getLIDForPN: async () => '777777777@lid' } },
          requestPairingCode: async () => 'R4CE-C0DE',
          end() {},
        };
        queueMicrotask(async () => {
          ev.emit('connection.update', { connection: 'connecting' });
          await firstMayContinue;
          ev.emit('connection.update', { connection: 'open' });
        });
        return socket;
      },
      emitCode: () => {},
      timeoutMs: 2_000,
    });
    await assert.rejects(provisionOffline({
      request: Object.freeze({ ...request, role: 'sensitive', session: sensitive }),
      useAuthState: async () => assert.fail('loser must fail before provider auth'),
      makeSocket: () => assert.fail('loser must fail before socket creation'),
      canonicalizeJid: (value) => String(value),
      emitCode: () => {},
      timeoutMs: 2_000,
    }), /provisioning_lock_unavailable/);
    releaseFirst();
    assert.deepEqual(await first, { account_namespace: 's.whatsapp.net', lid_ready: true });
    assert.equal(await stat(ordinary).then((item) => item.mode & 0o777), 0o700);
    assert.equal(await stat(path.join(ordinary, 'creds.json')).then((item) => item.mode & 0o777), 0o600);
  } finally {
    releaseFirst?.();
    await rm(root, { recursive: true, force: true });
  }
});
