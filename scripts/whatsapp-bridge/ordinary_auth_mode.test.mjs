import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { useMultiFileAuthState } from '@whiskeysockets/baileys';

function mode(filePath) {
  return statSync(filePath).mode & 0o777;
}

test('ordinary production auth writes stay owner-only under an ambient 0022 mask', async () => {
  const originalArgv = [...process.argv];
  const originalUmask = process.umask(0o022);
  const root = mkdtempSync(path.join(tmpdir(), 'hermes-ordinary-auth-mode-'));
  const session = path.join(root, 'session');

  try {
    mkdirSync(session, { mode: 0o700 });
    assert.equal(mode(session), 0o700, 'synthetic session must start owner-only');

    const ambientProbe = path.join(session, '.ambient-mask-probe');
    writeFileSync(ambientProbe, 'probe');
    assert.equal(
      mode(ambientProbe),
      0o644,
      'ambient 0022 mask must reproduce a non-owner-only new file',
    );
    unlinkSync(ambientProbe);

    process.argv.push('--session', session);
    const bridge = await import(`./bridge.js?ordinary-auth-mode=${Date.now()}`);
    const events = new EventEmitter();
    const socket = {
      user: { id: '33333333333:1@s.whatsapp.net', lid: '44444444444@lid' },
      ev: events,
    };
    let authState;
    let credsWrite;

    await bridge.startSocket({
      useAuthState: async folder => {
        assert.equal(folder, session);
        const auth = await useMultiFileAuthState(folder);
        auth.state.creds.registered = true;
        auth.state.creds.me = { id: socket.user.id };
        authState = auth.state;
        return {
          ...auth,
          saveCreds: () => {
            credsWrite = auth.saveCreds();
            return credsWrite;
          },
        };
      },
      verifyBootstrap: async () => socket.user.lid,
      resolveVersion: async () => null,
      createSocket: () => socket,
      canonicalizeJid: value => String(value).replace(/:\d+@/, '@'),
    });

    events.emit('creds.update', {});
    assert.ok(credsWrite, 'production creds.update must invoke Baileys saveCreds');
    await credsWrite;
    await authState.keys.set({
      session: { 'synthetic-owner-session': { synthetic: true } },
    });

    const authFiles = readdirSync(session)
      .filter(name => name.endsWith('.json'))
      .sort();
    assert.deepEqual(authFiles, [
      'creds.json',
      'session-synthetic-owner-session.json',
    ]);
    for (const name of authFiles) {
      assert.equal(
        mode(path.join(session, name)),
        0o600,
        `${name} must be created mode 0600`,
      );
    }
  } finally {
    process.argv.splice(0, process.argv.length, ...originalArgv);
    process.umask(originalUmask);
    rmSync(root, { recursive: true, force: true });
  }
});
