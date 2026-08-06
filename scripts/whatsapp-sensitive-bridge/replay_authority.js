import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync, closeSync, constants, existsSync, fsyncSync, fstatSync,
  lstatSync, mkdirSync, openSync, readFileSync, realpathSync,
  unlinkSync, writeFileSync, writeSync,
} from 'node:fs';
import path from 'node:path';

const AUTHORITY_FILE = '.authority';
const AUTHORITY_SUFFIX = '.anchor';
const TOMBSTONE_VERSION = 1;
const MAX_TOMBSTONE_BYTES = 512;
const DIGEST = /^[a-f0-9]{64}$/;
const PROBE_RETRIES = 100;
const PROBE_WAIT_MS = 10;
const PROBE_WAIT_WORD = new Int32Array(new SharedArrayBuffer(4));

export class ReceiverReplayAuthorityError extends Error {
  constructor() {
    super('sensitive receiver replay authority unavailable');
    this.name = 'ReceiverReplayAuthorityError';
  }
}

function fail() {
  throw new ReceiverReplayAuthorityError();
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map(key => (
      `${JSON.stringify(key)}:${canonical(value[key])}`
    )).join(',')}}`;
  }
  return JSON.stringify(value);
}

function exactObject(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function ownerUid(stat) {
  return typeof process.getuid !== 'function' || stat.uid === process.getuid();
}

function validateAncestors(target) {
  let cursor = path.dirname(target);
  const ancestors = [];
  while (true) {
    ancestors.push(cursor);
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  for (const item of ancestors.reverse()) {
    const info = lstatSync(item);
    const mode = info.mode & 0o7777;
    const safeRootSticky = info.uid === 0 && (mode & 0o1000) !== 0;
    if (!info.isDirectory() || info.isSymbolicLink()
        || (!ownerUid(info) && info.uid !== 0)
        || ((mode & 0o022) !== 0 && !safeRootSticky)) fail();
  }
}

function regularOwnerFile(file, mode = 0o600) {
  const named = lstatSync(file);
  if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1
      || (named.mode & 0o777) !== mode || !ownerUid(named)) fail();
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC);
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.dev !== named.dev || opened.ino !== named.ino
        || opened.nlink !== 1 || (opened.mode & 0o777) !== mode || !ownerUid(opened)) fail();
  } finally {
    closeSync(fd);
  }
  return named;
}

function identityOf(info) {
  return `${info.dev}:${info.ino}`;
}

function validateRoot(root, expectedIdentity) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || path.normalize(root) !== root) fail();
  validateAncestors(root);
  if (realpathSync.native(root) !== root) fail();
  const info = lstatSync(root);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o700
      || !ownerUid(info) || identityOf(info) !== expectedIdentity) fail();
  return info;
}

function writeAll(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(fd, bytes, offset, bytes.length - offset);
    if (written <= 0) fail();
    offset += written;
  }
}

export function initializeReceiverReplayAuthority(root) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || path.normalize(root) !== root) fail();
  const anchorPath = `${root}${AUTHORITY_SUFFIX}`;
  if (existsSync(root) || existsSync(anchorPath)) fail();
  validateAncestors(root);
  mkdirSync(root, { mode: 0o700 });
  chmodSync(root, 0o700);
  const marker = `${randomBytes(32).toString('hex')}\n`;
  const authorityPath = path.join(root, AUTHORITY_FILE);
  writeFileSync(authorityPath, marker, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  chmodSync(authorityPath, 0o600);
  const authorityFd = openSync(authorityPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { fsyncSync(authorityFd); } finally { closeSync(authorityFd); }
  const authoritySha256 = sha256(marker);
  writeFileSync(anchorPath, `${authoritySha256}\n`, {
    encoding: 'ascii', mode: 0o600, flag: 'wx',
  });
  chmodSync(anchorPath, 0o600);
  const anchorFd = openSync(anchorPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { fsyncSync(anchorFd); } finally { closeSync(anchorFd); }
  const directoryFd = openSync(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  const parentFd = openSync(path.dirname(root), constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(parentFd); } finally { closeSync(parentFd); }
  return Object.freeze({
    root,
    root_identity: identityOf(lstatSync(root)),
    anchor_path: anchorPath,
    authority_sha256: authoritySha256,
  });
}

export class DurableReceiverReplayAuthority {
  constructor(identity) {
    if (!exactObject(identity, [
      'root', 'root_identity', 'anchor_path', 'authority_sha256',
    ]) || typeof identity.root_identity !== 'string'
        || identity.anchor_path !== `${identity.root}${AUTHORITY_SUFFIX}`
        || !DIGEST.test(identity.authority_sha256)) fail();
    this.identity = Object.freeze({ ...identity });
    this.#validate();
    this.#probeWritable();
  }

  #probeWritable() {
    const target = path.join(this.identity.root, '.writable-probe');
    let fd;
    for (let attempt = 0; attempt < PROBE_RETRIES; attempt += 1) {
      try {
        fd = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL
          | constants.O_NOFOLLOW | constants.O_CLOEXEC, 0o600);
        break;
      } catch (error) {
        if (error?.code !== 'EEXIST' || attempt === PROBE_RETRIES - 1) fail();
        // Construction is synchronous and short. Serialize simultaneous fresh
        // receivers, but leave a probe abandoned by a crashed owner as a
        // bounded fail-closed startup condition rather than silently healing.
        Atomics.wait(PROBE_WAIT_WORD, 0, 0, PROBE_WAIT_MS);
      }
    }
    try {
      const opened = fstatSync(fd);
      if (!opened.isFile() || opened.nlink !== 1 || (opened.mode & 0o777) !== 0o600
          || !ownerUid(opened)) fail();
      fsyncSync(fd);
    } catch {
      try { unlinkSync(target); } catch {}
      fail();
    } finally {
      closeSync(fd);
    }
    try { unlinkSync(target); } catch { fail(); }
    const directoryFd = openSync(
      this.identity.root,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
    this.#validate();
  }

  #validate() {
    const { root, root_identity: expectedIdentity, anchor_path: anchorPath,
      authority_sha256: authoritySha256 } = this.identity;
    validateRoot(root, expectedIdentity);
    regularOwnerFile(anchorPath);
    regularOwnerFile(path.join(root, AUTHORITY_FILE));
    const anchor = readFileSync(anchorPath, { encoding: 'ascii' });
    const marker = readFileSync(path.join(root, AUTHORITY_FILE));
    if (anchor !== `${authoritySha256}\n` || marker.length !== 65
        || !/^[a-f0-9]{64}\n$/.test(marker.toString('ascii'))
        || sha256(marker) !== authoritySha256) fail();
  }

  burn(requestId, descriptor) {
    try {
      if (typeof requestId !== 'string' || Buffer.byteLength(requestId, 'utf8') > 256
          || requestId.length === 0 || !exactObject(descriptor, [
            'profile', 'mode', 'runtime', 'process_generation', 'session',
            'account', 'destination', 'expires_at_us', 'payload_sha256',
            'topology_sha256', 'transport_manifest_sha256',
          ]) || descriptor.profile !== 'juno'
          || descriptor.mode !== 'sensitive-outbound-only'
          || !DIGEST.test(descriptor.process_generation)
          || !DIGEST.test(descriptor.payload_sha256)
          || !DIGEST.test(descriptor.topology_sha256)
          || !DIGEST.test(descriptor.transport_manifest_sha256)
          || !Number.isSafeInteger(descriptor.expires_at_us)) fail();
      this.#validate();
      const requestIdSha256 = sha256(Buffer.from(requestId, 'utf8'));
      const descriptorSha256 = sha256(Buffer.from(canonical(descriptor), 'utf8'));
      const record = Buffer.from(`${canonical({
        descriptor_sha256: descriptorSha256,
        request_id_sha256: requestIdSha256,
        version: TOMBSTONE_VERSION,
      })}\n`, 'ascii');
      if (record.length > MAX_TOMBSTONE_BYTES) fail();
      const name = `request-${requestIdSha256}.burn`;
      const target = path.join(this.identity.root, name);
      let fd;
      try {
        fd = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL
          | constants.O_NOFOLLOW | constants.O_CLOEXEC, 0o600);
      } catch (error) {
        if (error?.code !== 'EEXIST') fail();
        regularOwnerFile(target);
        const existing = readFileSync(target);
        if (existing.length === 0 || existing.length > MAX_TOMBSTONE_BYTES
            || !existing.equals(record)) {
          // Mismatched reuse is burned too, but corruption/aliasing makes the
          // whole receiver authority unavailable rather than silently healing.
          fail();
        }
        return false;
      }
      try {
        writeAll(fd, record);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      regularOwnerFile(target);
      this.#validate();
      const directoryFd = openSync(
        this.identity.root,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
      return true;
    } catch (error) {
      if (error instanceof ReceiverReplayAuthorityError) throw error;
      fail();
    }
  }
}

export const RECEIVER_REPLAY_AUTHORITY_FILE = AUTHORITY_FILE;
export const RECEIVER_REPLAY_ANCHOR_SUFFIX = AUTHORITY_SUFFIX;
