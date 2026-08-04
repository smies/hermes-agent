import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { jidNormalizedUser, useMultiFileAuthState } from '@whiskeysockets/baileys';

import { parseProvisioningRequest } from './provisioning_core.js';
import { validateExistingOffline } from './offline_provision.js';

function syntheticBuffer(length, fill) {
  return { type: 'Buffer', data: Buffer.alloc(length, fill).toString('base64') };
}

function syntheticRc9Creds(phone, lid) {
  const keyPair = (fill) => ({
    private: syntheticBuffer(32, fill),
    public: syntheticBuffer(32, fill + 1),
  });
  return {
    noiseKey: keyPair(1),
    pairingEphemeralKeyPair: keyPair(3),
    signedIdentityKey: keyPair(5),
    signedPreKey: {
      keyPair: keyPair(7),
      signature: syntheticBuffer(64, 9),
      keyId: 1,
    },
    registrationId: 1234,
    advSecretKey: Buffer.alloc(32, 10).toString('base64'),
    processedHistoryMessages: [],
    nextPreKeyId: 1,
    firstUnuploadedPreKeyId: 1,
    accountSyncCounter: 0,
    accountSettings: { unarchiveChats: false },
    registered: true,
    me: { id: `${phone}:4@s.whatsapp.net`, lid: `${lid}@lid`, name: 'Synthetic RC9' },
  };
}

test('wholly synthetic rc9 multi-file auth loads, validates, and saves under rc14 without a socket', async () => {
  const root = realpathSync.native(mkdtempSync(path.join(tmpdir(), 'hermes-rc9-compat-')));
  chmodSync(root, 0o700);
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  mkdirSync(ordinary, { mode: 0o700 });
  const phone = '15550001111';
  const lid = '777777777';
  const credsPath = path.join(ordinary, 'creds.json');
  const lidPath = path.join(ordinary, `lid-mapping-${phone}.json`);
  writeFileSync(credsPath, JSON.stringify(syntheticRc9Creds(phone, lid)), { mode: 0o600 });
  // rc9 and rc14 both use a bare numeric PN filename key and JSON string LID value.
  writeFileSync(lidPath, JSON.stringify(lid), { mode: 0o600 });

  const request = parseProvisioningRequest({
    version: 1,
    action: 'validate',
    role: 'ordinary',
    ordinary_session: ordinary,
    sensitive_session: sensitive,
  });
  let socketCreated = false;
  const auth = await useMultiFileAuthState(ordinary);
  assert.equal(auth.state.creds.registered, true);
  assert.equal(Buffer.isBuffer(auth.state.creds.noiseKey.private), true);
  assert.equal((await auth.state.keys.get('lid-mapping', [phone]))[phone], lid);
  const result = await validateExistingOffline({
    request,
    useAuthState: async (directory) => {
      assert.equal(directory, ordinary);
      return useMultiFileAuthState(directory);
    },
    canonicalizeJid: jidNormalizedUser,
    makeSocket: () => { socketCreated = true; },
  });
  assert.deepEqual(result, { account_namespace: 's.whatsapp.net', lid_ready: true });
  assert.equal(socketCreated, false);
  const beforeSave = readFileSync(credsPath);
  await auth.saveCreds();
  assert.ok(readFileSync(credsPath).length > 0);
  assert.ok(beforeSave.length > 0);
  assert.equal(statSync(ordinary).mode & 0o777, 0o700);
  assert.equal(statSync(credsPath).mode & 0o777, 0o600);
  assert.equal(statSync(lidPath).mode & 0o777, 0o600);
});
