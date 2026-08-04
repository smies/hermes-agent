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

import { computeTransportIdentity } from './transport_identity.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PIN = '01047debd81beb20da7b7779b08edcb06aa03770';

test('exact pin exports the reviewed canonicalizer, ID pattern, and numeric statuses', () => {
  for (let index = 0; index < 100; index++) {
    assert.match(generateMessageIDV2('15551234567:4@s.whatsapp.net'), /^3EB0[0-9A-F]{18}$/);
  }
  assert.equal(jidNormalizedUser('15551234567:4@s.whatsapp.net'), '15551234567@s.whatsapp.net');
  assert.deepEqual(
    [WAMessageStatus.ERROR, WAMessageStatus.PENDING, WAMessageStatus.SERVER_ACK, WAMessageStatus.DELIVERY_ACK, WAMessageStatus.READ, WAMessageStatus.PLAYED],
    [0, 1, 2, 3, 4, 5],
  );
});

test('package, lock, installed package metadata, and deterministic tree identity bind the same exact commit', () => {
  const identity = computeTransportIdentity(HERE);
  assert.equal(Object.isFrozen(identity), true);
  const pkg = JSON.parse(readFileSync(path.join(HERE, 'package.json'), 'utf8'));
  const lock = JSON.parse(readFileSync(path.join(HERE, 'package-lock.json'), 'utf8'));
  const installed = JSON.parse(readFileSync(path.join(HERE, 'node_modules/@whiskeysockets/baileys/package.json'), 'utf8'));
  assert.ok(pkg.dependencies['@whiskeysockets/baileys'].endsWith(`#${PIN}`));
  assert.equal(lock.packages[''].dependencies['@whiskeysockets/baileys'], pkg.dependencies['@whiskeysockets/baileys']);
  assert.ok(lock.packages['node_modules/@whiskeysockets/baileys'].resolved.endsWith(`#${PIN}`));
  assert.equal(identity.baileys_commit, PIN);
  assert.equal(identity.baileys_version, installed.version);
  assert.match(identity.baileys_lock_integrity, /^sha512-/);
  for (const key of ['manifest_sha256', 'source_sha256', 'package_sha256', 'lock_sha256', 'baileys_tree_sha256']) {
    assert.match(identity[key], /^[a-f0-9]{64}$/);
  }
  assert.deepEqual(computeTransportIdentity(HERE), identity);
});

test('transport identity changes after session-path enforcement or installed package tampering', () => {
  const copy = mkdtempSync(path.join(tmpdir(), 'hermes-sensitive-identity-'));
  cpSync(HERE, copy, { recursive: true, filter: (source) => !source.includes(`${path.sep}.git`) });
  const before = computeTransportIdentity(copy);
  const modulePath = path.join(copy, 'session_paths.js');
  writeFileSync(modulePath, `${readFileSync(modulePath, 'utf8')}\n// tamper\n`);
  const sourceTamper = computeTransportIdentity(copy);
  assert.notEqual(sourceTamper.manifest_sha256, before.manifest_sha256);
  assert.notEqual(sourceTamper.source_sha256, before.source_sha256);

  const installedPath = path.join(copy, 'node_modules/@whiskeysockets/baileys/package.json');
  writeFileSync(installedPath, `${readFileSync(installedPath, 'utf8')} `);
  const treeTamper = computeTransportIdentity(copy);
  assert.notEqual(treeTamper.baileys_tree_sha256, sourceTamper.baileys_tree_sha256);
});
