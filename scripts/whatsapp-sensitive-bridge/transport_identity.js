import { createHash } from 'node:crypto';
import {
  lstatSync, readFileSync, readlinkSync, readdirSync,
} from 'node:fs';
import path from 'node:path';

export const BAILEYS_SPEC = '7.0.0-rc14';
export const BAILEYS_TARBALL = 'https://registry.npmjs.org/@whiskeysockets/baileys/-/baileys-7.0.0-rc14.tgz';
export const BAILEYS_INTEGRITY = 'sha512-WK+X8ju8TPGxvWIsP8hrY6JB6FltYuFe+vsqKfjOYX25JObij9qLf2c3ZGdl1Q+vhFwbnT+AZmWAB5pTvzmSiQ==';
// Reviewed release metadata only. The npm artifact does not claim gitHead, so
// this value must never be used as proof of tarball ancestry.
export const BAILEYS_REVIEWED_RELEASE_GIT_HEAD = '7e7b0757e3f9f3c7789fb1cfd2f241d5002a199a';
export const SENSITIVE_SUBMIT_CONTRACT_VERSION = 'juno-sensitive-submit-v2';
export const CANONICAL_SOURCE_FILES = Object.freeze([
  'delivery_core.js',
  'http_server.js',
  'inherited_test_provider.js',
  'lifecycle.js',
  'offline_provision.js',
  'parent_control.js',
  'patch_rc14_pairing.js',
  'provisioning_core.js',
  'replay_authority.js',
  'session_paths.js',
  'sensitive_bridge.js',
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

function treeEntries(root, relative = '', replacements = null) {
  const directory = path.join(root, relative);
  const entries = [];
  for (const name of readdirSync(directory).sort()) {
    const childRelative = relative ? path.posix.join(relative.split(path.sep).join('/'), name) : name;
    const child = path.join(root, ...childRelative.split('/'));
    const stat = lstatSync(child);
    if (stat.isSymbolicLink()) throw new Error('transport identity refuses symlinks');
    if (stat.isDirectory()) entries.push(...treeEntries(root, childRelative, replacements));
    else if (stat.isFile()) entries.push([
      childRelative,
      replacements?.has(childRelative)
        ? sha256(replacements.get(childRelative)) : fileHash(child),
    ]);
    else throw new Error('transport identity found unsupported tree entry');
  }
  return entries;
}

function dependencyTreeEntries(root, relative = '', replacements = null) {
  const directory = path.join(root, relative);
  const entries = [];
  for (const name of readdirSync(directory).sort()) {
    const childRelative = relative
      ? path.posix.join(relative.split(path.sep).join('/'), name)
      : name;
    const child = path.join(root, ...childRelative.split('/'));
    const stat = lstatSync(child);
    if (stat.isDirectory()) {
      entries.push(...dependencyTreeEntries(root, childRelative, replacements));
    } else if (stat.isSymbolicLink()) {
      entries.push([
        childRelative,
        sha256(Buffer.from(`symlink\0${readlinkSync(child)}`, 'utf8')),
      ]);
    } else if (stat.isFile()) {
      entries.push([
        childRelative,
        sha256(Buffer.concat([
          Buffer.from('file\0'),
          replacements?.has(childRelative)
            ? replacements.get(childRelative) : readFileSync(child),
        ])),
      ]);
    } else {
      throw new Error('transport identity found unsupported dependency entry');
    }
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

export async function computeTransportIdentity(packageRoot, expectedManifestSha256) {
  const root = path.resolve(packageRoot);
  const packagePath = path.join(root, 'package.json');
  const lockPath = path.join(root, 'package-lock.json');
  const manifestPath = path.join(root, 'transport-manifest.json');
  const packageBytes = readFileSync(packagePath);
  const lockBytes = readFileSync(lockPath);
  const manifestBytes = readFileSync(manifestPath);
  if (typeof expectedManifestSha256 !== 'string'
      || !/^[a-f0-9]{64}$/.test(expectedManifestSha256)
      || sha256(manifestBytes) !== expectedManifestSha256) {
    throw new Error('sensitive transport manifest anchor mismatch');
  }
  const pkg = JSON.parse(packageBytes.toString('utf8'));
  const lock = JSON.parse(lockBytes.toString('utf8'));
  const manifest = exactObject(
    JSON.parse(manifestBytes.toString('utf8')),
    ['version', 'package_name', 'package_version', 'submit_contract_version', 'package_sha256', 'lock_sha256', 'verifier_sha256', 'source_sha256', 'node_modules_tree_sha256', 'patcher_sha256', 'baileys'],
    'transport manifest',
  );
  const expected = exactObject(
    manifest.baileys,
    ['spec', 'lock_version', 'lock_resolved', 'lock_integrity', 'installed_name', 'installed_version', 'reviewed_release_git_head', 'package_sha256', 'preimage_tree_sha256', 'tree_sha256', 'patch_contract', 'patch_upstream_commit', 'patch_target', 'patch_preimage_sha256', 'patch_postimage_sha256', 'patch_postimage_contract_sha256'],
    'transport manifest Baileys identity',
  );
  if (manifest.version !== 4
      || manifest.package_name !== pkg.name
      || manifest.package_version !== pkg.version
      || manifest.submit_contract_version !== SENSITIVE_SUBMIT_CONTRACT_VERSION
      || pkg.dependencies?.['@whiskeysockets/baileys'] !== BAILEYS_SPEC
      || expected.spec !== BAILEYS_SPEC
      || expected.lock_version !== BAILEYS_SPEC
      || expected.lock_resolved !== BAILEYS_TARBALL
      || expected.lock_integrity !== BAILEYS_INTEGRITY
      || expected.installed_name !== '@whiskeysockets/baileys'
      || expected.installed_version !== BAILEYS_SPEC
      || expected.reviewed_release_git_head !== BAILEYS_REVIEWED_RELEASE_GIT_HEAD) {
    throw new Error('sensitive Baileys artifact identity mismatch');
  }
  const lockEntry = lock.packages?.['node_modules/@whiskeysockets/baileys'];
  if (lock.lockfileVersion !== 3
      || lock.packages?.['']?.dependencies?.['@whiskeysockets/baileys'] !== BAILEYS_SPEC
      || lockEntry?.version !== BAILEYS_SPEC
      || lockEntry?.resolved !== BAILEYS_TARBALL
      || lockEntry?.integrity !== BAILEYS_INTEGRITY) {
    throw new Error('sensitive Baileys lock identity mismatch');
  }
  const baileysRoot = path.join(root, 'node_modules', '@whiskeysockets', 'baileys');
  const installedPackagePath = path.join(baileysRoot, 'package.json');
  const installedPackageBytes = readFileSync(installedPackagePath);
  const installed = JSON.parse(installedPackageBytes.toString('utf8'));
  if (installed.name !== '@whiskeysockets/baileys' || installed.version !== BAILEYS_SPEC) {
    throw new Error('unexpected sensitive Baileys package');
  }
  const patcherPath = path.join(root, 'patch_rc14_pairing.js');
  const patcherBytes = readFileSync(patcherPath);
  const patcherSha256 = sha256(patcherBytes);
  if (manifest.patcher_sha256 !== patcherSha256) {
    throw new Error('sensitive rc14 patcher identity mismatch');
  }
  const patcher = await import(
    `data:text/javascript;base64,${patcherBytes.toString('base64')}`
  );
  const patchIdentity = patcher.verifyInstalledPatch(root);
  const expectedPostimageContract = sha256(Buffer.from(
    `${patchIdentity.contract}\0${patchIdentity.preimage_sha256}\0`
      + `${patchIdentity.postimage_sha256}\0${patchIdentity.preimage_tree_sha256}\0`
      + `${patchIdentity.postimage_tree_sha256}\0${patcherSha256}`,
    'utf8',
  ));
  if (expected.patch_contract !== patchIdentity.contract
      || expected.patch_upstream_commit !== patchIdentity.upstream_commit
      || expected.patch_target !== patchIdentity.target
      || expected.patch_preimage_sha256 !== patchIdentity.preimage_sha256
      || expected.patch_postimage_sha256 !== patchIdentity.postimage_sha256
      || expected.preimage_tree_sha256 !== patchIdentity.preimage_tree_sha256
      || expected.tree_sha256 !== patchIdentity.postimage_tree_sha256
      || expected.patch_postimage_contract_sha256 !== expectedPostimageContract) {
    throw new Error('sensitive rc14 patch contract mismatch');
  }

  const sourceSha256 = framedManifest(
    CANONICAL_SOURCE_FILES.map((name) => [name, fileHash(path.join(root, name))]),
  );
  const packageSha256 = sha256(packageBytes);
  const lockSha256 = sha256(lockBytes);
  const verifierSha256 = fileHash(path.join(root, 'transport_identity.js'));
  const nodeModulesTreeSha256 = framedManifest(
    dependencyTreeEntries(path.join(root, 'node_modules')),
  );
  const baileysPackageSha256 = sha256(installedPackageBytes);
  const baileysTreeSha256 = framedManifest(
    treeEntries(baileysRoot),
  );
  if (manifest.package_sha256 !== packageSha256
      || manifest.lock_sha256 !== lockSha256
      || manifest.verifier_sha256 !== verifierSha256
      || manifest.source_sha256 !== sourceSha256
      || manifest.node_modules_tree_sha256 !== nodeModulesTreeSha256
      || expected.package_sha256 !== baileysPackageSha256
      || expected.tree_sha256 !== baileysTreeSha256) {
    throw new Error('sensitive transport bytes do not match reviewed manifest');
  }
  const bounded = {
    manifest_sha256: sha256(manifestBytes),
    source_sha256: sourceSha256,
    package_sha256: packageSha256,
    lock_sha256: lockSha256,
    verifier_sha256: verifierSha256,
    patcher_sha256: patcherSha256,
    node_modules_tree_sha256: nodeModulesTreeSha256,
    package_name: pkg.name,
    package_version: pkg.version,
    submit_contract_version: SENSITIVE_SUBMIT_CONTRACT_VERSION,
    baileys_spec: BAILEYS_SPEC,
    baileys_lock_version: lockEntry.version,
    baileys_lock_resolved: lockEntry.resolved,
    baileys_lock_integrity: lockEntry.integrity,
    baileys_installed_name: installed.name,
    baileys_version: installed.version,
    baileys_package_sha256: baileysPackageSha256,
    baileys_tree_sha256: baileysTreeSha256,
    baileys_reviewed_release_git_head: BAILEYS_REVIEWED_RELEASE_GIT_HEAD,
    baileys_patch_contract: patchIdentity.contract,
    baileys_patch_upstream_commit: patchIdentity.upstream_commit,
    baileys_patch_target: patchIdentity.target,
    baileys_patch_preimage_sha256: patchIdentity.preimage_sha256,
    baileys_patch_postimage_sha256: patchIdentity.postimage_sha256,
    baileys_preimage_tree_sha256: patchIdentity.preimage_tree_sha256,
    baileys_patch_postimage_contract_sha256: expectedPostimageContract,
  };
  return Object.freeze(bounded);
}
