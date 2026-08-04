import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, realpath, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { jidNormalizedUser, useMultiFileAuthState } from '@whiskeysockets/baileys';

import { provisionOffline } from './offline_provision.js';
import { parseProvisioningRequest, verifyLidBootstrap } from './provisioning_core.js';

test('real pinned multi-file auth uses bare numeric LID keys and staged owner-only modes under parent umask 0022', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-real-auth-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'8'.repeat(10)}`;
  const lidUser = '666666666';
  const previousUmask = process.umask(0o022);
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
    const result = await provisionOffline({
      request,
      useAuthState: useMultiFileAuthState,
      canonicalizeJid: jidNormalizedUser,
      makeSocket: ({ auth }) => {
        const listeners = new Map();
        const ev = {
          on(name, handler) { listeners.set(name, handler); },
          removeAllListeners() { listeners.clear(); },
        };
        const socket = {
          ev,
          user: { id: `${phone}@s.whatsapp.net` },
          signalRepository: { lidMapping: { getLIDForPN: async () => `${lidUser}@lid` } },
          requestPairingCode: async () => 'R34KC9DE',
          end() {},
        };
        queueMicrotask(async () => {
          listeners.get('connection.update')?.({ connection: 'connecting' });
          await auth.keys.set({ 'lid-mapping': { [phone]: lidUser } });
          auth.creds.registered = true;
          auth.creds.me = { id: `${phone}@s.whatsapp.net`, lid: `${lidUser}@lid` };
          listeners.get('connection.update')?.({ connection: 'open' });
        });
        return socket;
      },
      emitCode: () => {},
      timeoutMs: 3_000,
    });
    assert.equal(result.lid_ready, true);
    assert.equal((await stat(ordinary)).mode & 0o777, 0o700);
    assert.equal((await stat(path.join(ordinary, 'creds.json'))).mode & 0o777, 0o600);
    const real = await useMultiFileAuthState(ordinary);
    assert.equal(await verifyLidBootstrap({
      auth: real,
      sock: {},
      phoneJid: `${phone}@s.whatsapp.net`,
      canonicalizeJid: jidNormalizedUser,
    }), `${lidUser}@lid`);
  } finally {
    process.umask(previousUmask);
    await rm(root, { recursive: true, force: true });
  }
});
