import { strict as assert } from 'node:assert';
import { createHmac } from 'node:crypto';
import test from 'node:test';

const key = 'ab'.repeat(32);
process.env.HERMES_INTERNAL_WHATSAPP_FENCE_PROFILE = 'juno';
process.env.HERMES_INTERNAL_WHATSAPP_FENCE_KEY = key;

const { privateReadFenceEvidence } = await import(`./bridge.js?fence-health=${Date.now()}`);

test('bridge emits fresh profile runtime and artifact bound fence evidence', () => {
  const identity = {
    manifest_sha256: '1'.repeat(64),
    source_sha256: '2'.repeat(64),
  };
  const evidence = privateReadFenceEvidence(identity);
  assert.deepEqual(Object.keys(evidence).sort(), [
    'active', 'manifestSha256', 'observedAtUs', 'profile', 'proof',
    'runtimeId', 'scriptHash', 'sourceSha256', 'version',
  ].sort());
  assert.equal(evidence.version, 1);
  assert.equal(evidence.active, true);
  assert.equal(evidence.profile, 'juno');
  assert.match(evidence.runtimeId, /^[a-f0-9]{64}$/);
  assert.equal(evidence.manifestSha256, identity.manifest_sha256);
  assert.equal(evidence.sourceSha256, identity.source_sha256);
  assert.ok(Date.now() * 1000 - evidence.observedAtUs < 1_000_000);
  const material = [
    'juno-sender-companion-fence-v1', evidence.profile, evidence.runtimeId,
    String(evidence.observedAtUs), evidence.manifestSha256,
    evidence.sourceSha256, evidence.scriptHash,
  ].join('\0');
  const expected = createHmac('sha256', Buffer.from(key, 'hex'))
    .update(material)
    .digest('hex');
  assert.equal(evidence.proof, expected);
});
