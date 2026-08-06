#!/usr/bin/env node

import { createHash } from 'node:crypto';
import {
  lstatSync, readFileSync, readdirSync, realpathSync, renameSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const PATCH_CONTRACT = 'hermes-baileys-rc14-pairing-iq-v1';
export const PATCH_UPSTREAM_COMMIT = '834dc742e349958fd162f7a2239514e9b237fb5a';
export const BAILEYS_SPEC = '7.0.0-rc14';
export const BAILEYS_TARBALL = 'https://registry.npmjs.org/@whiskeysockets/baileys/-/baileys-7.0.0-rc14.tgz';
export const BAILEYS_INTEGRITY = 'sha512-WK+X8ju8TPGxvWIsP8hrY6JB6FltYuFe+vsqKfjOYX25JObij9qLf2c3ZGdl1Q+vhFwbnT+AZmWAB5pTvzmSiQ==';
export const ROOT_PACKAGE_SHA256 = '725e3923282066d4c42f4017c1cf430059a6a95c124d8f32f61d9d077146c3da';
export const ROOT_LOCK_SHA256 = '11763893096a6abe8b28a017dc652506bd47d39ef2ddeb0fe2ea110be58dc05a';
export const BAILEYS_PACKAGE_SHA256 = 'b5f4f2d1a8af27239e0e9869594345b5d99ecc102193b98117332cadffcebc0d';
export const SOCKET_PREIMAGE_SHA256 = 'ff8b19ff02491fa080ee371f066d49c94acb903207dd0d9fdb5548e5a594fb4a';
export const SOCKET_POSTIMAGE_SHA256 = 'cd1b74943cc78d74a0abdc0b98d23b12badaf5d9bc3f98369d7fa043735c99bf';
export const BAILEYS_PREIMAGE_TREE_SHA256 = 'bdb0b02cb790daa88421bf29700b43b1e449378a77f51edcfd8d524e9b9f0112';
export const BAILEYS_POSTIMAGE_TREE_SHA256 = '86ab52f7e1c341371f7a2b7237f495c5b1bbcfc7773fda934f1aeabbd02a02a6';
export const PATCH_TARGET = 'lib/Socket/socket.js';

const START_MARKER = '/* hermes-baileys-rc14-pairing-iq:start ';
const END_MARKER = '/* hermes-baileys-rc14-pairing-iq:end */';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
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

function regularFile(filePath, label) {
  const info = lstatSync(filePath);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1
      || realpathSync.native(filePath) !== filePath) {
    throw new Error(`${label} is unsafe`);
  }
  return info;
}

function canonicalPackageRoot(packageRoot) {
  const root = path.resolve(packageRoot);
  if (realpathSync.native(root) !== root) throw new Error('patch root is unsafe');
  const rootPackagePath = path.join(root, 'package.json');
  const rootLockPath = path.join(root, 'package-lock.json');
  regularFile(rootPackagePath, 'patch package metadata');
  regularFile(rootLockPath, 'patch lock metadata');
  const rootPackageBytes = readFileSync(rootPackagePath);
  const rootLockBytes = readFileSync(rootLockPath);
  let rootPackage;
  let rootLock;
  try {
    rootPackage = JSON.parse(rootPackageBytes.toString('utf8'));
    rootLock = JSON.parse(rootLockBytes.toString('utf8'));
  } catch { throw new Error('patch install metadata is invalid'); }
  const lockEntry = rootLock.packages?.['node_modules/@whiskeysockets/baileys'];
  if (sha256(rootPackageBytes) !== ROOT_PACKAGE_SHA256
      || sha256(rootLockBytes) !== ROOT_LOCK_SHA256
      || rootPackage.dependencies?.['@whiskeysockets/baileys'] !== BAILEYS_SPEC
      || rootPackage.scripts?.postinstall !== 'node patch_rc14_pairing.js'
      || rootLock.lockfileVersion !== 3
      || rootLock.packages?.['']?.dependencies?.['@whiskeysockets/baileys'] !== BAILEYS_SPEC
      || lockEntry?.version !== BAILEYS_SPEC
      || lockEntry?.resolved !== BAILEYS_TARBALL
      || lockEntry?.integrity !== BAILEYS_INTEGRITY) {
    throw new Error('patch install metadata is unexpected');
  }
  for (const relative of ['node_modules', 'node_modules/@whiskeysockets',
    'node_modules/@whiskeysockets/baileys']) {
    const item = path.join(root, ...relative.split('/'));
    const info = lstatSync(item);
    if (!info.isDirectory() || info.isSymbolicLink()
        || realpathSync.native(item) !== item) throw new Error('patch root is unsafe');
  }
  return path.join(root, 'node_modules', '@whiskeysockets', 'baileys');
}

function treeEntries(root, replacement = null, relative = '') {
  const entries = [];
  for (const name of readdirSync(path.join(root, relative)).sort()) {
    const childRelative = relative ? path.posix.join(relative, name) : name;
    const child = path.join(root, ...childRelative.split('/'));
    const info = lstatSync(child);
    if (info.isSymbolicLink()) throw new Error('patch refuses dependency symlinks');
    if (info.isDirectory()) entries.push(...treeEntries(root, replacement, childRelative));
    else if (info.isFile() && info.nlink === 1) {
      const bytes = replacement && childRelative === PATCH_TARGET
        ? replacement : readFileSync(child);
      entries.push([childRelative, sha256(bytes)]);
    } else throw new Error('patch found unsupported dependency entry');
  }
  return entries;
}

function requestBlockBounds(source) {
  const startPattern = /(^|\n)([\t ]*)const requestPairingCode = async \(phoneNumber, customPairingCode\) => \{/g;
  const matches = [...source.matchAll(startPattern)];
  if (matches.length !== 1) throw new Error('rc14 pairing preimage is unexpected');
  const start = matches[0].index + matches[0][1].length;
  const indent = matches[0][2];
  const tail = `${indent}async function generatePairingKey()`;
  const tailIndex = source.indexOf(tail, start);
  if (tailIndex < 0 || source.indexOf(tail, tailIndex + 1) >= 0) {
    throw new Error('rc14 pairing preimage is unexpected');
  }
  return { start, end: tailIndex, indent };
}

function reviewedOriginalFromPatched(source) {
  const start = source.indexOf(START_MARKER);
  const end = source.indexOf(END_MARKER);
  if (start < 0 || end < start || source.indexOf(START_MARKER, start + 1) >= 0
      || source.indexOf(END_MARKER, end + 1) >= 0) {
    throw new Error('rc14 pairing postimage is unexpected');
  }
  const headerEnd = source.indexOf(' */\n', start);
  if (headerEnd < 0 || headerEnd > end) throw new Error('rc14 pairing postimage is unexpected');
  const header = source.slice(start + START_MARKER.length, headerEnd);
  const match = /^([a-f0-9]{64}) ([A-Za-z0-9+/=]+)$/.exec(header);
  if (!match) throw new Error('rc14 pairing postimage is unexpected');
  const original = Buffer.from(match[2], 'base64').toString('utf8');
  if (sha256(original) !== match[1]) throw new Error('rc14 pairing postimage is unexpected');
  const markerEnd = end + END_MARKER.length;
  if (source[markerEnd] !== '\n') throw new Error('rc14 pairing postimage is unexpected');
  return { original, start, end: markerEnd + 1 };
}

function canonicalPatchedBlock(original, indent) {
  const inner = `${indent}    `;
  const deep = `${inner}    `;
  const originalDigest = sha256(original);
  const encoded = Buffer.from(original, 'utf8').toString('base64');
  return `${START_MARKER}${originalDigest} ${encoded} */\n`
    + `${indent}const requestPairingCode = async (phoneNumber, customPairingCode) => {\n`
    + `${inner}if (customPairingCode && customPairingCode.length !== 8) {\n`
    + `${deep}throw new Error('Custom pairing code must be exactly 8 chars');\n`
    + `${inner}}\n`
    + `${inner}const pairingCode = customPairingCode ?? bytesToCrockford(randomBytes(5));\n`
    + `${inner}const jid = jidEncode(phoneNumber, 's.whatsapp.net');\n`
    + `${inner}try {\n`
    + `${deep}const result = await query({\n`
    + `${deep}    tag: 'iq',\n`
    + `${deep}    attrs: { to: S_WHATSAPP_NET, type: 'set', xmlns: 'md' },\n`
    + `${deep}    content: [{\n`
    + `${deep}        tag: 'link_code_companion_reg',\n`
    + `${deep}        attrs: {\n`
    + `${deep}            jid,\n`
    + `${deep}            stage: 'companion_hello',\n`
    + `${deep}            should_show_push_notification: 'true',\n`
    + `${deep}        },\n`
    + `${deep}        content: [{\n`
    + `${deep}            tag: 'link_code_pairing_wrapped_companion_ephemeral_pub',\n`
    + `${deep}            attrs: {},\n`
    + `${deep}            content: await generatePairingKey(pairingCode),\n`
    + `${deep}        }, {\n`
    + `${deep}            tag: 'companion_server_auth_key_pub',\n`
    + `${deep}            attrs: {},\n`
    + `${deep}            content: authState.creds.noiseKey.public,\n`
    + `${deep}        }, {\n`
    + `${deep}            tag: 'companion_platform_id',\n`
    + `${deep}            attrs: {},\n`
    + `${deep}            content: '1',\n`
    + `${deep}        }, {\n`
    + `${deep}            tag: 'companion_platform_display',\n`
    + `${deep}            attrs: {},\n`
    + `${deep}            content: 'Chrome (Mac OS)',\n`
    + `${deep}        }, {\n`
    + `${deep}            tag: 'link_code_pairing_nonce',\n`
    + `${deep}            attrs: {},\n`
    + `${deep}            content: '0',\n`
    + `${deep}        }],\n`
    + `${deep}    }],\n`
    + `${deep}});\n`
    + `${deep}if (!result) {\n`
    + `${deep}    throw new Boom('Timed out waiting for pairing code response', { statusCode: DisconnectReason.timedOut });\n`
    + `${deep}}\n`
    + `${deep}authState.creds.pairingCode = pairingCode;\n`
    + `${deep}authState.creds.me = { id: jid, name: '~' };\n`
    + `${deep}ev.emit('creds.update', authState.creds);\n`
    + `${deep}return pairingCode;\n`
    + `${inner}} catch (error) {\n`
    + `${deep}if (authState.creds.pairingCode === pairingCode) {\n`
    + `${deep}    authState.creds.pairingCode = undefined;\n`
    + `${deep}}\n`
    + `${deep}throw error;\n`
    + `${inner}}\n`
    + `${indent}};\n`
    + `${END_MARKER}\n`;
}

function replaceGeneratePairingKey(source, toPatched) {
  const pre = 'derivePairingCodeKey(authState.creds.pairingCode, salt)';
  const post = 'derivePairingCodeKey(pairingCode, salt)';
  const signaturePre = 'async function generatePairingKey()';
  const signaturePost = 'async function generatePairingKey(pairingCode)';
  const from = toPatched ? [[pre, post], [signaturePre, signaturePost]]
    : [[post, pre], [signaturePost, signaturePre]];
  let value = source;
  for (const [oldValue, newValue] of from) {
    if (value.split(oldValue).length !== 2 || value.includes(newValue)) {
      throw new Error('rc14 pairing key preimage is unexpected');
    }
    value = value.replace(oldValue, newValue);
  }
  return value;
}

export function patchSocketSource(bytes) {
  const source = Buffer.from(bytes).toString('utf8');
  if (source.includes(START_MARKER) || source.includes(END_MARKER)) {
    throw new Error('rc14 pairing preimage is already patched');
  }
  const bounds = requestBlockBounds(source);
  const original = source.slice(bounds.start, bounds.end);
  const replaced = source.slice(0, bounds.start)
    + canonicalPatchedBlock(original, bounds.indent)
    + source.slice(bounds.end);
  return Buffer.from(replaceGeneratePairingKey(replaced, true), 'utf8');
}

export function normalizePatchedSocket(bytes) {
  const source = Buffer.from(bytes).toString('utf8');
  const embedded = reviewedOriginalFromPatched(source);
  let normalized = source.slice(0, embedded.start) + embedded.original + source.slice(embedded.end);
  normalized = replaceGeneratePairingKey(normalized, false);
  if (!patchSocketSource(Buffer.from(normalized)).equals(Buffer.from(bytes))) {
    throw new Error('rc14 pairing postimage is unexpected');
  }
  return Buffer.from(normalized, 'utf8');
}

function validateArtifact(baileysRoot, normalizedSocket) {
  const packagePath = path.join(baileysRoot, 'package.json');
  regularFile(packagePath, 'rc14 package metadata');
  const packageBytes = readFileSync(packagePath);
  let installed;
  try { installed = JSON.parse(packageBytes.toString('utf8')); } catch {
    throw new Error('rc14 package metadata is invalid');
  }
  if (installed.name !== '@whiskeysockets/baileys'
      || installed.version !== BAILEYS_SPEC
      || sha256(packageBytes) !== BAILEYS_PACKAGE_SHA256) {
    throw new Error('rc14 package metadata is unexpected');
  }
  if (sha256(normalizedSocket) !== SOCKET_PREIMAGE_SHA256) {
    throw new Error('rc14 socket preimage is unexpected');
  }
  const normalizedTree = framedManifest(treeEntries(baileysRoot, normalizedSocket));
  if (normalizedTree !== BAILEYS_PREIMAGE_TREE_SHA256) {
    throw new Error('rc14 package preimage is unexpected');
  }
}

export function verifyInstalledPatch(packageRoot) {
  const baileysRoot = canonicalPackageRoot(packageRoot);
  const target = path.join(baileysRoot, ...PATCH_TARGET.split('/'));
  regularFile(target, 'rc14 patch target');
  const postBytes = readFileSync(target);
  const preBytes = normalizePatchedSocket(postBytes);
  validateArtifact(baileysRoot, preBytes);
  if (sha256(postBytes) !== SOCKET_POSTIMAGE_SHA256
      || framedManifest(treeEntries(baileysRoot)) !== BAILEYS_POSTIMAGE_TREE_SHA256) {
    throw new Error('rc14 package postimage is unexpected');
  }
  return Object.freeze({
    contract: PATCH_CONTRACT,
    upstream_commit: PATCH_UPSTREAM_COMMIT,
    target: PATCH_TARGET,
    preimage_sha256: SOCKET_PREIMAGE_SHA256,
    postimage_sha256: SOCKET_POSTIMAGE_SHA256,
    preimage_tree_sha256: BAILEYS_PREIMAGE_TREE_SHA256,
    postimage_tree_sha256: BAILEYS_POSTIMAGE_TREE_SHA256,
  });
}

export function patchInstalledBaileys(packageRoot) {
  const baileysRoot = canonicalPackageRoot(packageRoot);
  const target = path.join(baileysRoot, ...PATCH_TARGET.split('/'));
  const info = regularFile(target, 'rc14 patch target');
  const current = readFileSync(target);
  let preBytes;
  let postBytes;
  if (current.toString('utf8').includes(START_MARKER)) {
    preBytes = normalizePatchedSocket(current);
    postBytes = current;
  } else {
    preBytes = current;
    postBytes = patchSocketSource(current);
  }
  validateArtifact(baileysRoot, preBytes);
  if (sha256(postBytes) !== SOCKET_POSTIMAGE_SHA256) {
    throw new Error('rc14 socket postimage is unexpected');
  }
  if (!current.equals(postBytes)) {
    const staged = `${target}.hermes-rc14-patch-${process.pid}`;
    writeFileSync(staged, postBytes, { flag: 'wx', mode: info.mode & 0o777 });
    regularFile(target, 'rc14 patch target');
    renameSync(staged, target);
  }
  const verified = verifyInstalledPatch(packageRoot);
  process.stdout.write('Hermes rc14 pairing patch: verified\n');
  return verified;
}

const scriptPath = import.meta.url.startsWith('file:') ? fileURLToPath(import.meta.url) : null;
if (scriptPath && process.argv[1]
    && realpathSync.native(process.argv[1]) === scriptPath) {
  try {
    patchInstalledBaileys(path.dirname(scriptPath));
  } catch {
    process.stderr.write('Hermes rc14 pairing patch: rejected\n');
    process.exitCode = 1;
  }
}
