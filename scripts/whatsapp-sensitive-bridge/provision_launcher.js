#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const EXPECTED_MANIFEST_SHA256 = '43da91eca417376b405cb8f2bff82195c5ad602921e6edd4dc149b9ed0095bc0';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export async function launchProvisioner(argv = process.argv.slice(2)) {
  const root = path.dirname(fileURLToPath(import.meta.url));
  const manifestBytes = readFileSync(path.join(root, 'transport-manifest.json'));
  if (sha256(manifestBytes) !== EXPECTED_MANIFEST_SHA256) {
    throw new Error('sensitive transport manifest anchor mismatch');
  }
  const verifier = await import('./transport_identity.js');
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
