import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';

import {
  buildProvisioningSocketConfig,
  normalizePairingCode,
  normalizePhone,
  PAIRING_CODE_ALPHABET,
  parseProvisioningRequest,
  verifyLidBootstrap,
} from './provisioning_core.js';

test('exact rc14 pairing-code alphabet normalization with no QR surface', () => {
  const digits = `1${'7'.repeat(10)}`;
  assert.equal(normalizePhone(`+${digits}`), digits);
  assert.equal(normalizePairingCode('ab12cd34'), 'AB12CD34');
  assert.equal(PAIRING_CODE_ALPHABET, '123456789ABCDEFGHJKLMNPQRSTVWXYZ');
  assert.equal(normalizePairingCode('WXYZ1234'), 'WXYZ1234');
  for (const invalid of [
    '00000000', 'bad code', 'AB12-CD34', 'ABCD123', 'ABCD12345',
    'ABCDI234', 'ABCDO234', 'ABCDU234',
  ]) {
    assert.throws(() => normalizePairingCode(invalid), /pairing_code_invalid/);
  }
  assert.throws(() => normalizePhone('not-a-phone'), /phone_input_invalid/);
  const config = buildProvisioningSocketConfig({ auth: {}, logger: {} });
  assert.equal(config.printQRInTerminal, false);
  assert.equal(config.syncFullHistory, true);
  assert.equal(config.fireInitQueries, true);
  assert.equal(config.shouldSyncHistoryMessage({}), true);
  assert.equal('qr' in config, false);
});

test('separated canonical ordinary/sensitive roots and no argv-shaped sensitive fields', () => {
  const root = path.resolve('/tmp/hermes-provision-test');
  const parsed = parseProvisioningRequest({
    version: 1,
    action: 'provision',
    role: 'sensitive',
    phone: `1${'5'.repeat(10)}`,
    ordinary_session: path.join(root, 'ordinary'),
    sensitive_session: path.join(root, 'sensitive'),
  });
  assert.equal(parsed.session, path.join(root, 'sensitive'));
  assert.throws(() => parseProvisioningRequest({
    version: 1,
    action: 'provision',
    role: 'ordinary',
    phone: `1${'5'.repeat(10)}`,
    ordinary_session: root,
    sensitive_session: path.join(root, 'nested'),
  }), /session_separation_required/);
});

test('provider-canonical persisted LID bootstrap readiness', async () => {
  const canonicalize = (value) => String(value).replace(/:\d+@/, '@');
  const phoneJid = `${`1${'5'.repeat(10)}`}@s.whatsapp.net`;
  const lidJid = `${'9'.repeat(9)}@lid`;
  assert.equal(await verifyLidBootstrap({
    auth: { state: { keys: { get: async (kind, ids) => {
      assert.equal(kind, 'lid-mapping');
      assert.deepEqual(ids, [phoneJid.split('@')[0]]);
      return { [phoneJid.split('@')[0]]: lidJid.split('@')[0] };
    } } } },
    sock: {},
    phoneJid,
    canonicalizeJid: canonicalize,
  }), lidJid);
  assert.equal(await verifyLidBootstrap({
    auth: { state: { keys: { get: async () => ({}) } } },
    sock: {},
    phoneJid,
    canonicalizeJid: canonicalize,
  }), null);
});
