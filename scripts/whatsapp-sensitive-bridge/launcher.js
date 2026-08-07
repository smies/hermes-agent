#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const EXPECTED_MANIFEST_SHA256 = '6c93f93d70ec51ac8c02162fad9c4e2381c5854acc61c75260c81966afe10ef0';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function parseAnchoredManifest(manifestBytes) {
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const keys = [
    'version', 'package_name', 'package_version', 'package_sha256',
    'submit_contract_version', 'lock_sha256', 'verifier_sha256', 'source_sha256',
    'node_modules_tree_sha256', 'patcher_sha256', 'baileys',
  ];
  const baileysKeys = [
    'spec', 'lock_version', 'lock_resolved', 'lock_integrity',
    'installed_name', 'installed_version', 'reviewed_release_git_head',
    'package_sha256', 'preimage_tree_sha256', 'tree_sha256', 'patch_contract',
    'patch_upstream_commit', 'patch_target', 'patch_preimage_sha256',
    'patch_postimage_sha256', 'patch_postimage_contract_sha256',
  ];
  const exact = (value, expected) => value
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join('\0') === [...expected].sort().join('\0');
  const digest = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  if (!exact(manifest, keys) || manifest.version !== 4
      || typeof manifest.package_name !== 'string' || !manifest.package_name
      || typeof manifest.package_version !== 'string' || !manifest.package_version
      || manifest.submit_contract_version !== 'juno-sensitive-submit-v2'
      || !['package_sha256', 'lock_sha256', 'verifier_sha256', 'source_sha256',
        'node_modules_tree_sha256', 'patcher_sha256'].every((name) => digest(manifest[name]))
      || !exact(manifest.baileys, baileysKeys)
      || !['package_sha256', 'preimage_tree_sha256', 'tree_sha256',
        'patch_preimage_sha256', 'patch_postimage_sha256',
        'patch_postimage_contract_sha256'].every((name) => digest(manifest.baileys[name]))) {
    throw new Error('sensitive transport manifest schema mismatch');
  }
  return manifest;
}

export async function verifySensitiveTransport(
  root = path.dirname(fileURLToPath(import.meta.url)),
) {
  root = realpathSync.native(root);
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
  const verified = await verifier.computeTransportIdentity(
    root, EXPECTED_MANIFEST_SHA256,
  );
  const identity = Object.freeze({
    ...verified,
    launcher_sha256: sha256(readFileSync(fileURLToPath(import.meta.url))),
  });
  return identity;
}

export async function launchSensitiveBridge(argv = process.argv.slice(2), env = process.env) {
  const identity = await verifySensitiveTransport();
  const core = await import('./sensitive_bridge.js');
  let testProviderSeam = null;
  if ([
    'HERMES_INTERNAL_JUNO_TEST_PROVIDER_AUTHORITY_FD',
    'HERMES_INTERNAL_JUNO_TEST_PROVIDER_CAPTURE_FD',
    'HERMES_INTERNAL_JUNO_TEST_PROVIDER_AUTHORITY_SHA256',
  ].some(name => env[name] !== undefined)) {
    const seam = await import('./inherited_test_provider.js');
    let launch;
    try { launch = JSON.parse(env.HERMES_INTERNAL_WHATSAPP_SENSITIVE_LAUNCH); } catch {
      throw new Error('inherited test provider authority rejected');
    }
    testProviderSeam = seam.loadInheritedTestProvider(env, launch);
  }
  return core.runSensitiveBridge({
    argv, env, transportIdentity: identity, testProviderSeam,
  });
}

if (process.argv[1]
    && realpathSync.native(process.argv[1]) === fileURLToPath(import.meta.url)) {
  launchSensitiveBridge().catch(() => { process.exitCode = 1; });
}
