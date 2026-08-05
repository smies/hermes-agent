#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const EXPECTED_MANIFEST_SHA256 = '4e63abb3b8081ee011f8be1d266bd1866f5a829c2ae3372920e1736dd8568b30';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function parseAnchoredManifest(manifestBytes) {
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const keys = [
    'version', 'package_name', 'package_version', 'package_sha256',
    'submit_contract_version', 'lock_sha256', 'verifier_sha256', 'source_sha256',
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
      || manifest.submit_contract_version !== 'juno-sensitive-submit-v2'
      || !['package_sha256', 'lock_sha256', 'verifier_sha256', 'source_sha256',
        'node_modules_tree_sha256'].every((name) => digest(manifest[name]))
      || !exact(manifest.baileys, baileysKeys)
      || !digest(manifest.baileys.package_sha256)
      || !digest(manifest.baileys.tree_sha256)) {
    throw new Error('sensitive transport manifest schema mismatch');
  }
  return manifest;
}

export async function launchProvisioner(argv = process.argv.slice(2)) {
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
  verifier.computeTransportIdentity(root, EXPECTED_MANIFEST_SHA256);
  if (argv.length === 1 && argv[0] === '--verify-only') return 0;
  const core = await import('./offline_provision.js');
  const operatorOutput = argv.length === 1 && argv[0] === '--operator-stdio'
    ? process.stderr
    : null;
  return core.runProvisioner({ operatorOutput });
}

if (process.argv[1]
    && realpathSync.native(process.argv[1]) === fileURLToPath(import.meta.url)) {
  launchProvisioner().then((code) => { process.exitCode = code; })
    .catch(() => { process.exitCode = 1; });
}
