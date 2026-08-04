import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  generateMessageIDV2,
  jidNormalizedUser,
  WAMessageStatus,
} from '@whiskeysockets/baileys';

import {
  BAILEYS_INTEGRITY,
  BAILEYS_REVIEWED_RELEASE_GIT_HEAD,
  BAILEYS_SPEC,
  BAILEYS_TARBALL,
  computeTransportIdentity,
} from './transport_identity.js';
import { EXPECTED_MANIFEST_SHA256 } from './launcher.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

test('rc14 exports the reviewed canonicalizer, ID pattern, and numeric statuses', () => {
  for (let index = 0; index < 100; index++) {
    assert.match(generateMessageIDV2('15551234567:4@s.whatsapp.net'), /^3EB0[0-9A-F]{18}$/);
  }
  assert.equal(jidNormalizedUser('15551234567:4@s.whatsapp.net'), '15551234567@s.whatsapp.net');
  assert.deepEqual(
    [WAMessageStatus.ERROR, WAMessageStatus.PENDING, WAMessageStatus.SERVER_ACK, WAMessageStatus.DELIVERY_ACK, WAMessageStatus.READ, WAMessageStatus.PLAYED],
    [0, 1, 2, 3, 4, 5],
  );
});

test('package, lock, installed metadata, and deterministic tree bind the exact npm artifact', () => {
  const identity = computeTransportIdentity(HERE, EXPECTED_MANIFEST_SHA256);
  assert.equal(Object.isFrozen(identity), true);
  const pkg = JSON.parse(readFileSync(path.join(HERE, 'package.json'), 'utf8'));
  const lock = JSON.parse(readFileSync(path.join(HERE, 'package-lock.json'), 'utf8'));
  const installed = JSON.parse(readFileSync(path.join(HERE, 'node_modules/@whiskeysockets/baileys/package.json'), 'utf8'));
  const lockEntry = lock.packages['node_modules/@whiskeysockets/baileys'];
  assert.equal(pkg.dependencies['@whiskeysockets/baileys'], BAILEYS_SPEC);
  assert.equal(lock.packages[''].dependencies['@whiskeysockets/baileys'], BAILEYS_SPEC);
  assert.equal(lockEntry.version, BAILEYS_SPEC);
  assert.equal(lockEntry.resolved, BAILEYS_TARBALL);
  assert.equal(lockEntry.integrity, BAILEYS_INTEGRITY);
  assert.equal(identity.baileys_spec, BAILEYS_SPEC);
  assert.equal(identity.baileys_lock_version, BAILEYS_SPEC);
  assert.equal(identity.baileys_lock_resolved, BAILEYS_TARBALL);
  assert.equal(identity.baileys_lock_integrity, BAILEYS_INTEGRITY);
  assert.equal(identity.baileys_installed_name, '@whiskeysockets/baileys');
  assert.equal(identity.baileys_version, installed.version);
  assert.equal(identity.baileys_reviewed_release_git_head, BAILEYS_REVIEWED_RELEASE_GIT_HEAD);
  assert.equal(installed.gitHead, undefined, 'reviewed Git head is metadata, not artifact ancestry');
  for (const key of ['manifest_sha256', 'verifier_sha256', 'source_sha256', 'node_modules_tree_sha256', 'package_sha256', 'lock_sha256', 'baileys_package_sha256', 'baileys_tree_sha256']) {
    assert.match(identity[key], /^[a-f0-9]{64}$/);
  }
  assert.deepEqual(computeTransportIdentity(HERE, EXPECTED_MANIFEST_SHA256), identity);
});

test('transport identity fails closed after source or installed package tampering', () => {
  const copy = mkdtempSync(path.join(tmpdir(), 'hermes-sensitive-identity-'));
  cpSync(HERE, copy, {
    recursive: true,
    verbatimSymlinks: true,
    filter: (source) => !source.split(path.sep).includes('.git'),
  });
  const before = computeTransportIdentity(copy, EXPECTED_MANIFEST_SHA256);
  const modulePath = path.join(copy, 'session_paths.js');
  writeFileSync(modulePath, `${readFileSync(modulePath, 'utf8')}\n// tamper\n`);
  assert.throws(() => computeTransportIdentity(copy, EXPECTED_MANIFEST_SHA256), /reviewed manifest/);

  writeFileSync(modulePath, readFileSync(path.join(HERE, 'session_paths.js')));
  const installedPath = path.join(copy, 'node_modules/@whiskeysockets/baileys/package.json');
  writeFileSync(installedPath, `${readFileSync(installedPath, 'utf8')} `);
  assert.throws(() => computeTransportIdentity(copy, EXPECTED_MANIFEST_SHA256), /reviewed manifest/);
  assert.match(before.manifest_sha256, /^[a-f0-9]{64}$/);
});
