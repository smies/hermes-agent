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
  SENSITIVE_SUBMIT_CONTRACT_VERSION,
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

test('package, lock, installed metadata, and deterministic tree bind the exact npm artifact', async () => {
  const identity = await computeTransportIdentity(HERE, EXPECTED_MANIFEST_SHA256);
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
  assert.equal(identity.submit_contract_version, SENSITIVE_SUBMIT_CONTRACT_VERSION);
  assert.equal(identity.baileys_lock_version, BAILEYS_SPEC);
  assert.equal(identity.baileys_lock_resolved, BAILEYS_TARBALL);
  assert.equal(identity.baileys_lock_integrity, BAILEYS_INTEGRITY);
  assert.equal(identity.baileys_installed_name, '@whiskeysockets/baileys');
  assert.equal(identity.baileys_version, installed.version);
  assert.equal(identity.baileys_reviewed_release_git_head, BAILEYS_REVIEWED_RELEASE_GIT_HEAD);
  assert.equal(identity.baileys_patch_contract, 'hermes-baileys-rc14-pairing-iq-v1');
  assert.equal(identity.baileys_patch_upstream_commit, '834dc742e349958fd162f7a2239514e9b237fb5a');
  assert.equal(identity.baileys_patch_target, 'lib/Socket/socket.js');
  assert.equal(identity.baileys_patch_preimage_sha256, 'ff8b19ff02491fa080ee371f066d49c94acb903207dd0d9fdb5548e5a594fb4a');
  assert.equal(identity.baileys_patch_postimage_sha256, 'cd1b74943cc78d74a0abdc0b98d23b12badaf5d9bc3f98369d7fa043735c99bf');
  assert.equal(identity.baileys_preimage_tree_sha256, 'bdb0b02cb790daa88421bf29700b43b1e449378a77f51edcfd8d524e9b9f0112');
  assert.equal(installed.gitHead, undefined, 'reviewed Git head is metadata, not artifact ancestry');
  for (const key of ['manifest_sha256', 'verifier_sha256', 'patcher_sha256', 'source_sha256', 'node_modules_tree_sha256', 'package_sha256', 'lock_sha256', 'baileys_package_sha256', 'baileys_preimage_tree_sha256', 'baileys_tree_sha256', 'baileys_patch_preimage_sha256', 'baileys_patch_postimage_sha256', 'baileys_patch_postimage_contract_sha256']) {
    assert.match(identity[key], /^[a-f0-9]{64}$/);
  }
  assert.deepEqual(await computeTransportIdentity(HERE, EXPECTED_MANIFEST_SHA256), identity);
});

test('transport identity fails closed after source or installed package tampering', async () => {
  const copy = mkdtempSync(path.join(tmpdir(), 'hermes-sensitive-identity-'));
  cpSync(HERE, copy, {
    recursive: true,
    verbatimSymlinks: true,
    filter: (source) => !source.split(path.sep).includes('.git'),
  });
  const before = await computeTransportIdentity(copy, EXPECTED_MANIFEST_SHA256);
  const modulePath = path.join(copy, 'session_paths.js');
  writeFileSync(modulePath, `${readFileSync(modulePath, 'utf8')}\n// tamper\n`);
  await assert.rejects(computeTransportIdentity(copy, EXPECTED_MANIFEST_SHA256), /reviewed manifest/);

  writeFileSync(modulePath, readFileSync(path.join(HERE, 'session_paths.js')));
  const installedPath = path.join(copy, 'node_modules/@whiskeysockets/baileys/package.json');
  writeFileSync(installedPath, `${readFileSync(installedPath, 'utf8')} `);
  await assert.rejects(
    computeTransportIdentity(copy, EXPECTED_MANIFEST_SHA256),
    /reviewed manifest|rc14 package metadata is unexpected/,
  );
  assert.match(before.manifest_sha256, /^[a-f0-9]{64}$/);
});
