import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
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
          keys: { get: async () => ({ [ordinaryPhoneJid]: { lid: ordinaryLidJid } }) },
        } : {
          creds: { registered: false },
          keys: { get: async () => ({ [phoneJid]: { lid: lidJid } }) },
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
