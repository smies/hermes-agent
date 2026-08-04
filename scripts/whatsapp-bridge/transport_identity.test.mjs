import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BAILEYS_INTEGRITY,
  BAILEYS_REVIEWED_RELEASE_GIT_HEAD,
  BAILEYS_SPEC,
  BAILEYS_TARBALL,
  computeTransportIdentity,
} from './transport_identity.js';
import { EXPECTED_MANIFEST_SHA256 } from './launcher.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

test('ordinary bridge verifies the exact rc14 npm artifact and reviewed bytes', () => {
  const identity = computeTransportIdentity(HERE, EXPECTED_MANIFEST_SHA256);
  assert.equal(identity.baileys_spec, BAILEYS_SPEC);
  assert.equal(identity.baileys_lock_version, BAILEYS_SPEC);
  assert.equal(identity.baileys_lock_resolved, BAILEYS_TARBALL);
  assert.equal(identity.baileys_lock_integrity, BAILEYS_INTEGRITY);
  assert.equal(identity.baileys_installed_name, '@whiskeysockets/baileys');
  assert.equal(identity.baileys_version, BAILEYS_SPEC);
  assert.equal(identity.baileys_reviewed_release_git_head, BAILEYS_REVIEWED_RELEASE_GIT_HEAD);
  for (const key of ['manifest_sha256', 'source_sha256', 'package_sha256', 'lock_sha256', 'baileys_package_sha256', 'baileys_tree_sha256']) {
    assert.match(identity[key], /^[a-f0-9]{64}$/);
  }
});

test('ordinary bridge source tampering fails before bridge import can create a socket', () => {
  const copy = mkdtempSync(path.join(tmpdir(), 'hermes-ordinary-identity-'));
  cpSync(HERE, copy, { recursive: true });
  const target = path.join(copy, 'bridge_helpers.js');
  writeFileSync(target, `${readFileSync(target, 'utf8')}\n// tamper\n`);
  assert.throws(() => computeTransportIdentity(copy, EXPECTED_MANIFEST_SHA256), /reviewed manifest/);
});

for (const fileName of ['package.json', 'package-lock.json']) {
  test(`ordinary bridge ${fileName} tampering fails before socket creation`, () => {
    const copy = mkdtempSync(path.join(tmpdir(), 'hermes-ordinary-identity-'));
    cpSync(HERE, copy, { recursive: true });
    const target = path.join(copy, fileName);
    writeFileSync(target, `${readFileSync(target, 'utf8')}\n`);
    assert.throws(() => computeTransportIdentity(copy, EXPECTED_MANIFEST_SHA256), /reviewed manifest/);
  });
}
