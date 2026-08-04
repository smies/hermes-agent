#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const EXPECTED_MANIFEST_SHA256 = '43da91eca417376b405cb8f2bff82195c5ad602921e6edd4dc149b9ed0095bc0';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export async function launchSensitiveBridge(argv = process.argv.slice(2), env = process.env) {
  const root = path.dirname(fileURLToPath(import.meta.url));
  const manifestBytes = readFileSync(path.join(root, 'transport-manifest.json'));
  if (sha256(manifestBytes) !== EXPECTED_MANIFEST_SHA256) {
    throw new Error('sensitive transport manifest anchor mismatch');
  }
  const verifier = await import('./transport_identity.js');
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
