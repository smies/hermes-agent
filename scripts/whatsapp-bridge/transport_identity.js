import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

export const BAILEYS_SPEC = '7.0.0-rc14';
export const BAILEYS_TARBALL = 'https://registry.npmjs.org/@whiskeysockets/baileys/-/baileys-7.0.0-rc14.tgz';
export const BAILEYS_INTEGRITY = 'sha512-WK+X8ju8TPGxvWIsP8hrY6JB6FltYuFe+vsqKfjOYX25JObij9qLf2c3ZGdl1Q+vhFwbnT+AZmWAB5pTvzmSiQ==';
// Reviewed release metadata only. The npm artifact does not claim gitHead, so
// this value must never be used as proof of tarball ancestry.
export const BAILEYS_REVIEWED_RELEASE_GIT_HEAD = '7e7b0757e3f9f3c7789fb1cfd2f241d5002a199a';
export const CANONICAL_SOURCE_FILES = Object.freeze([
  'allowlist.js',
  'bridge.js',
  'bridge_helpers.js',
  'outbound_ids.js',
  'owner_message_gate.js',
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

function exactObject(value, keys, label) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

export function computeTransportIdentity(packageRoot) {
  const root = path.resolve(packageRoot);
  const packageBytes = readFileSync(path.join(root, 'package.json'));
  const lockBytes = readFileSync(path.join(root, 'package-lock.json'));
  const manifestBytes = readFileSync(path.join(root, 'transport-manifest.json'));
  const pkg = JSON.parse(packageBytes.toString('utf8'));
  const lock = JSON.parse(lockBytes.toString('utf8'));
  const manifest = exactObject(
    JSON.parse(manifestBytes.toString('utf8')),
    ['version', 'package_name', 'package_version', 'package_sha256', 'lock_sha256', 'source_sha256', 'baileys'],
    'transport manifest',
  );
  const expected = exactObject(
    manifest.baileys,
    ['spec', 'lock_version', 'lock_resolved', 'lock_integrity', 'installed_name', 'installed_version', 'reviewed_release_git_head', 'package_sha256', 'tree_sha256'],
    'transport manifest Baileys identity',
  );
  if (manifest.version !== 2
      || manifest.package_name !== pkg.name
      || manifest.package_version !== pkg.version
      || pkg.dependencies?.['@whiskeysockets/baileys'] !== BAILEYS_SPEC
      || expected.spec !== BAILEYS_SPEC
      || expected.lock_version !== BAILEYS_SPEC
      || expected.lock_resolved !== BAILEYS_TARBALL
      || expected.lock_integrity !== BAILEYS_INTEGRITY
      || expected.installed_name !== '@whiskeysockets/baileys'
      || expected.installed_version !== BAILEYS_SPEC
      || expected.reviewed_release_git_head !== BAILEYS_REVIEWED_RELEASE_GIT_HEAD) {
    throw new Error('ordinary Baileys artifact identity mismatch');
  }
  const lockEntry = lock.packages?.['node_modules/@whiskeysockets/baileys'];
  if (lock.lockfileVersion !== 3
      || lock.packages?.['']?.dependencies?.['@whiskeysockets/baileys'] !== BAILEYS_SPEC
      || lockEntry?.version !== BAILEYS_SPEC
      || lockEntry?.resolved !== BAILEYS_TARBALL
      || lockEntry?.integrity !== BAILEYS_INTEGRITY) {
    throw new Error('ordinary Baileys lock identity mismatch');
  }
  const baileysRoot = path.join(root, 'node_modules', '@whiskeysockets', 'baileys');
  const installedPackageBytes = readFileSync(path.join(baileysRoot, 'package.json'));
  const installed = JSON.parse(installedPackageBytes.toString('utf8'));
  if (installed.name !== '@whiskeysockets/baileys' || installed.version !== BAILEYS_SPEC) {
    throw new Error('unexpected ordinary Baileys package');
  }
  const sourceSha256 = framedManifest(
    CANONICAL_SOURCE_FILES.map((name) => [name, fileHash(path.join(root, name))]),
  );
  const packageSha256 = sha256(packageBytes);
  const lockSha256 = sha256(lockBytes);
  const baileysPackageSha256 = sha256(installedPackageBytes);
  const baileysTreeSha256 = framedManifest(treeEntries(baileysRoot));
  if (manifest.package_sha256 !== packageSha256
      || manifest.lock_sha256 !== lockSha256
      || manifest.source_sha256 !== sourceSha256
      || expected.package_sha256 !== baileysPackageSha256
      || expected.tree_sha256 !== baileysTreeSha256) {
    throw new Error('ordinary transport bytes do not match reviewed manifest');
  }
  return Object.freeze({
    manifest_sha256: sha256(manifestBytes),
    source_sha256: sourceSha256,
    package_sha256: packageSha256,
    lock_sha256: lockSha256,
    package_name: pkg.name,
    package_version: pkg.version,
    baileys_spec: BAILEYS_SPEC,
    baileys_lock_version: lockEntry.version,
    baileys_lock_resolved: lockEntry.resolved,
    baileys_lock_integrity: lockEntry.integrity,
    baileys_installed_name: installed.name,
    baileys_version: installed.version,
    baileys_package_sha256: baileysPackageSha256,
    baileys_tree_sha256: baileysTreeSha256,
    baileys_reviewed_release_git_head: BAILEYS_REVIEWED_RELEASE_GIT_HEAD,
  });
}
