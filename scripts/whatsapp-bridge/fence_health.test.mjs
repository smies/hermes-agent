import { strict as assert } from 'node:assert';
import { createHmac } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const key = 'ab'.repeat(32);
process.env.HERMES_INTERNAL_WHATSAPP_FENCE_PROFILE = 'juno';
process.env.HERMES_INTERNAL_WHATSAPP_FENCE_KEY = key;
const session = mkdtempSync(path.join(tmpdir(), 'ordinary-fence-health-'));
process.argv.push('--session', session);

const { privateReadFenceEvidence, startSocket } = await import(`./bridge.js?fence-health=${Date.now()}`);

test('bridge emits fresh profile runtime and topology bound fence evidence', async () => {
  const ev = new EventEmitter();
  const sock = {
    user: { id: '33333333333:4@s.whatsapp.net', lid: '44444444444@lid' },
    ev,
  };
  await startSocket({
    useAuthState: async () => ({
      state: { creds: { registered: true, me: { id: sock.user.id } } },
      saveCreds() {},
    }),
    verifyBootstrap: async () => sock.user.lid,
    resolveVersion: async () => null,
    createSocket: () => sock,
    canonicalizeJid: value => String(value).replace(/:\d+@/, '@'),
  });
  ev.emit('connection.update', { connection: 'open' });
  const identity = {
    manifest_sha256: '1'.repeat(64),
    source_sha256: '2'.repeat(64),
  };
  const evidence = privateReadFenceEvidence(identity);
  assert.deepEqual(Object.keys(evidence).sort(), [
    'active', 'manifestSha256', 'observedAtUs', 'profile', 'proof',
    'runtimeId', 'socketGeneration', 'accountPhoneJid', 'accountLidJid',
    'sessionPath', 'sessionIdentity', 'scriptHash', 'sourceSha256', 'version',
  ].sort());
  assert.equal(evidence.version, 2);
  assert.equal(evidence.active, true);
  assert.equal(evidence.profile, 'juno');
  assert.match(evidence.runtimeId, /^[a-f0-9]{64}$/);
  assert.equal(evidence.manifestSha256, identity.manifest_sha256);
  assert.equal(evidence.sourceSha256, identity.source_sha256);
  assert.ok(Date.now() * 1000 - evidence.observedAtUs < 1_000_000);
  const material = [
    'juno-sender-companion-fence-v2', evidence.profile, evidence.runtimeId,
    String(evidence.socketGeneration), evidence.accountPhoneJid,
    evidence.accountLidJid, evidence.sessionPath, evidence.sessionIdentity,
    String(evidence.observedAtUs), evidence.manifestSha256,
    evidence.sourceSha256, evidence.scriptHash,
  ].join('\0');
  const expected = createHmac('sha256', Buffer.from(key, 'hex'))
    .update(material)
    .digest('hex');
  assert.equal(evidence.proof, expected);
});
