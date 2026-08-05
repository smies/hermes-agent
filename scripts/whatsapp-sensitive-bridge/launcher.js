#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const EXPECTED_MANIFEST_SHA256 = 'c10ec43325576c3bccd5027c3e46c85cb02050ea22334e36a3de6bb4909dffb2';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function parseAnchoredManifest(manifestBytes) {
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const keys = [
    'version', 'package_name', 'package_version', 'package_sha256',
    'lock_sha256', 'verifier_sha256', 'source_sha256',
    'node_modules_tree_sha256', 'baileys',
  ];
  const baileysKeys = [
    'spec', 'lock_version', 'lock_resolved', 'lock_integrity',
    'installed_name', 'installed_version', 'reviewed_release_git_head',
    'package_sha256', 'tree_sha256',
  ];
  const exact = (value, expected) => value
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join('\0') === [...expected].sort().join('\0');
  const digest = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  if (!exact(manifest, keys) || manifest.version !== 3
      || typeof manifest.package_name !== 'string' || !manifest.package_name
      || typeof manifest.package_version !== 'string' || !manifest.package_version
      || !['package_sha256', 'lock_sha256', 'verifier_sha256', 'source_sha256',
        'node_modules_tree_sha256'].every((name) => digest(manifest[name]))
      || !exact(manifest.baileys, baileysKeys)
      || !digest(manifest.baileys.package_sha256)
      || !digest(manifest.baileys.tree_sha256)) {
    throw new Error('sensitive transport manifest schema mismatch');
  }
  return manifest;
}

export async function launchSensitiveBridge(argv = process.argv.slice(2), env = process.env) {
  const root = path.dirname(fileURLToPath(import.meta.url));
  const manifestBytes = readFileSync(path.join(root, 'transport-manifest.json'));
  if (sha256(manifestBytes) !== EXPECTED_MANIFEST_SHA256) {
    throw new Error('sensitive transport manifest anchor mismatch');
  }
  const manifest = parseAnchoredManifest(manifestBytes);
  const verifierPath = path.join(root, 'transport_identity.js');
  const verifierStat = lstatSync(verifierPath);
  const verifierBytes = readFileSync(verifierPath);
  if (!verifierStat.isFile() || verifierStat.isSymbolicLink()
      || sha256(verifierBytes) !== manifest.verifier_sha256) {
    throw new Error('sensitive transport verifier mismatch');
  }
  const verifier = await import(
    `data:text/javascript;base64,${verifierBytes.toString('base64')}`
  );
  const verified = verifier.computeTransportIdentity(
    root, EXPECTED_MANIFEST_SHA256,
  );
  const identity = Object.freeze({
    ...verified,
    launcher_sha256: sha256(readFileSync(fileURLToPath(import.meta.url))),
  });
  const core = await import('./sensitive_bridge.js');
  return core.runSensitiveBridge({ argv, env, transportIdentity: identity });
}

if (process.argv[1]
    && realpathSync.native(process.argv[1]) === fileURLToPath(import.meta.url)) {
  launchSensitiveBridge().catch(() => { process.exitCode = 1; });
}
