#!/usr/bin/env node

// Trust-root launcher: built-ins only until the anchored manifest has been
// byte-qualified.  This file is bound independently by the Python host/release
// source identity and is deliberately excluded from the manifest it anchors.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const EXPECTED_MANIFEST_SHA256 = 'b48227d65ee62e7b79b005e98644ec8dbf9bbe91bde2461995be5b2b577639a5';

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
    throw new Error('ordinary transport manifest schema mismatch');
  }
  return manifest;
}

export async function launchOrdinaryBridge(argv = process.argv.slice(2)) {
  const root = path.dirname(fileURLToPath(import.meta.url));
  const manifestBytes = readFileSync(path.join(root, 'transport-manifest.json'));
  if (sha256(manifestBytes) !== EXPECTED_MANIFEST_SHA256) {
    throw new Error('ordinary transport manifest anchor mismatch');
  }
  const manifest = parseAnchoredManifest(manifestBytes);
  const verifierPath = path.join(root, 'transport_identity.js');
  const verifierStat = lstatSync(verifierPath);
  const verifierBytes = readFileSync(verifierPath);
  if (!verifierStat.isFile() || verifierStat.isSymbolicLink()
      || sha256(verifierBytes) !== manifest.verifier_sha256) {
    throw new Error('ordinary transport verifier mismatch');
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
  const core = await import('./bridge.js');
  return core.runBridge({ argv, transportIdentity: identity });
}

if (process.argv[1]
    && realpathSync.native(process.argv[1]) === fileURLToPath(import.meta.url)) {
  launchOrdinaryBridge().catch(() => { process.exitCode = 1; });
}
