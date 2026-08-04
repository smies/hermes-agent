import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

export const BAILEYS_COMMIT = '01047debd81beb20da7b7779b08edcb06aa03770';
export const CANONICAL_SOURCE_FILES = Object.freeze([
  'delivery_core.js',
  'http_server.js',
  'lifecycle.js',
  'offline_provision.js',
  'provisioning_core.js',
  'session_paths.js',
  'sensitive_bridge.js',
  'transport_identity.js',
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function fileHash(filePath) {
  return sha256(readFileSync(filePath));
}

function framedManifest(entries) {
  const hash = createHash('sha256');
  for (const [name, digest] of entries) {
    const nameBytes = Buffer.from(name, 'utf8');
    hash.update(`${nameBytes.length}:`);
    hash.update(nameBytes);
    hash.update(`:${digest.length}:`);
    hash.update(digest);
    hash.update('\n');
  }
  return hash.digest('hex');
}

function treeEntries(root, relative = '') {
  const directory = path.join(root, relative);
  const entries = [];
  for (const name of readdirSync(directory).sort()) {
    const childRelative = relative ? path.posix.join(relative.split(path.sep).join('/'), name) : name;
    const child = path.join(root, ...childRelative.split('/'));
    const stat = lstatSync(child);
    if (stat.isSymbolicLink()) throw new Error('transport identity refuses symlinks');
    if (stat.isDirectory()) entries.push(...treeEntries(root, childRelative));
    else if (stat.isFile()) entries.push([childRelative, fileHash(child)]);
    else throw new Error('transport identity found unsupported tree entry');
  }
  return entries;
}

function exactPinFromLock(lockEntry) {
  const resolved = lockEntry?.resolved;
  const match = typeof resolved === 'string' ? resolved.match(/#([0-9a-f]{40})$/) : null;
  return match?.[1] || null;
}

export function computeTransportIdentity(packageRoot) {
  const root = path.resolve(packageRoot);
  const packagePath = path.join(root, 'package.json');
  const lockPath = path.join(root, 'package-lock.json');
  const packageBytes = readFileSync(packagePath);
  const lockBytes = readFileSync(lockPath);
  const pkg = JSON.parse(packageBytes.toString('utf8'));
  const lock = JSON.parse(lockBytes.toString('utf8'));
  const requested = pkg.dependencies?.['@whiskeysockets/baileys'];
  const lockedRequested = lock.packages?.['']?.dependencies?.['@whiskeysockets/baileys'];
  const lockEntry = lock.packages?.['node_modules/@whiskeysockets/baileys'];
  const lockCommit = exactPinFromLock(lockEntry);
  if (typeof requested !== 'string' || !requested.endsWith(`#${BAILEYS_COMMIT}`)
      || lockedRequested !== requested || lockCommit !== BAILEYS_COMMIT) {
    throw new Error('sensitive Baileys pin mismatch');
  }
  const baileysRoot = path.join(root, 'node_modules', '@whiskeysockets', 'baileys');
  const installed = JSON.parse(readFileSync(path.join(baileysRoot, 'package.json'), 'utf8'));
  if (installed.name !== 'baileys' && installed.name !== '@whiskeysockets/baileys') {
    throw new Error('unexpected sensitive Baileys package');
  }
  if (typeof lockEntry.integrity !== 'string' || !lockEntry.integrity.startsWith('sha512-')) {
    throw new Error('sensitive Baileys lock integrity is unavailable');
  }

  const sourceEntries = CANONICAL_SOURCE_FILES.map((name) => [name, fileHash(path.join(root, name))]);
  const sourceSha256 = framedManifest(sourceEntries);
  const packageSha256 = sha256(packageBytes);
  const lockSha256 = sha256(lockBytes);
  const baileysTreeSha256 = framedManifest(treeEntries(baileysRoot));
  const bounded = {
    version: 1,
    source_sha256: sourceSha256,
    package_sha256: packageSha256,
    lock_sha256: lockSha256,
    baileys_tree_sha256: baileysTreeSha256,
    baileys_commit: BAILEYS_COMMIT,
    baileys_version: String(installed.version || ''),
    baileys_lock_integrity: lockEntry.integrity,
  };
  return Object.freeze({
    ...bounded,
    manifest_sha256: sha256(JSON.stringify(bounded)),
  });
}
