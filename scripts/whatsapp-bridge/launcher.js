#!/usr/bin/env node

// Trust-root launcher: built-ins only until the anchored manifest has been
// byte-qualified.  This file is bound independently by the Python host/release
// source identity and is deliberately excluded from the manifest it anchors.
import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const EXPECTED_MANIFEST_SHA256 = '55ad7f331c7695ed4390fde153ca4713e0e250b881d9b65ea4c570bb70ef6e2b';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export async function launchOrdinaryBridge(argv = process.argv.slice(2)) {
  const root = path.dirname(fileURLToPath(import.meta.url));
  const manifestBytes = readFileSync(path.join(root, 'transport-manifest.json'));
  if (sha256(manifestBytes) !== EXPECTED_MANIFEST_SHA256) {
    throw new Error('ordinary transport manifest anchor mismatch');
  }
  const verifier = await import('./transport_identity.js');
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
