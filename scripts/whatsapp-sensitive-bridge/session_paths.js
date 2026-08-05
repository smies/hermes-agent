import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';

const DIRECTORY_MODE = 0o700;
const PERMISSION_BITS = 0o7777;
const UNTRUSTED_WRITE_BITS = 0o022;
const STICKY_BIT = 0o1000;

export class SessionPathError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SessionPathError';
    this.code = code;
  }
}

function reject(code) {
  throw new SessionPathError(code);
}

function identityOf(stat) {
  return Object.freeze({ dev: stat.dev, ino: stat.ino });
}

function printableIdentity(identity) {
  return `${identity.dev}:${identity.ino}`;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(
      Object.keys(value).sort().map(key => [key, stableValue(value[key])]),
    );
  }
  return value;
}

function deviceIdentityDigest(creds) {
  if (!creds || Object.getPrototypeOf(creds) !== Object.prototype) {
    reject('credential_identity_invalid');
  }
  const required = [
    'registrationId', 'noiseKey', 'signedIdentityKey', 'advSecretKey',
  ];
  if (required.some(name => creds[name] === undefined || creds[name] === null)) {
    reject('credential_identity_invalid');
  }
  return sha256(JSON.stringify(stableValue(Object.fromEntries(
    required.map(name => [name, creds[name]]),
  ))));
}

function accountTopology(creds) {
  const canonical = (value, namespace) => {
    if (typeof value !== 'string') return null;
    const normalized = value.replace(/:\d+@/, '@');
    return new RegExp(`^\\d{1,32}@${namespace}$`).test(normalized) ? normalized : null;
  };
  const phone = canonical(creds?.me?.id, 's\\.whatsapp\\.net');
  const lid = canonical(creds?.me?.lid, 'lid');
  if (creds?.registered !== true || !phone || !lid) {
    reject('credential_account_topology_invalid');
  }
  return Object.freeze({ phone, lid });
}

function sameAccountTopology(left, right) {
  return left.phone === right.phone && left.lid === right.lid;
}

function captureAuthArtifacts(root, uid) {
  const entries = [];
  const identities = new Set();
  let credsSeal = null;
  let deviceDigest = null;
  let topology = null;
  const walk = (directory, relative = '') => {
    for (const name of readdirSync(directory).sort()) {
      const childRelative = relative ? path.posix.join(relative, name) : name;
      const child = path.join(root, ...childRelative.split('/'));
      const info = lstatSync(child, { bigint: true });
      if (info.isSymbolicLink()) reject('auth_tree_symlink_rejected');
      if (uid !== null && Number(info.uid) !== uid) reject('auth_tree_owner_rejected');
      if (info.isDirectory()) {
        if ((Number(info.mode) & PERMISSION_BITS) !== DIRECTORY_MODE) {
          reject('auth_directory_permissions_rejected');
        }
        walk(child, childRelative);
        continue;
      }
      if (!info.isFile() || !name.endsWith('.json')) reject('auth_tree_entry_rejected');
      if (Number(info.nlink) !== 1) reject('auth_file_hardlink_rejected');
      if ((Number(info.mode) & PERMISSION_BITS) !== 0o600) {
        reject('auth_file_permissions_rejected');
      }
      if (realpathSync.native(child) !== child) reject('auth_tree_non_canonical');
      const identity = `${info.dev}:${info.ino}`;
      if (identities.has(identity)) reject('auth_file_inode_alias_rejected');
      identities.add(identity);
      const bytes = readFileSync(child);
      entries.push([childRelative, sha256(bytes)]);
      if (childRelative === 'creds.json') {
        let creds;
        try { creds = JSON.parse(bytes.toString('utf8')); } catch { reject('credential_identity_invalid'); }
        deviceDigest = deviceIdentityDigest(creds);
        topology = accountTopology(creds);
        credsSeal = Object.freeze({
          dev: info.dev,
          ino: info.ino,
          mode: Number(info.mode) & PERMISSION_BITS,
        });
      }
    }
  };
  walk(root);
  if (!credsSeal || !deviceDigest || !topology) reject('credential_identity_invalid');
  return Object.freeze({
    treeDigest: sha256(JSON.stringify(entries)),
    deviceDigest,
    topology,
    credsSeal,
    identities,
  });
}

function assertDistinctAuthArtifacts(sensitive, ordinary) {
  if (!sameAccountTopology(sensitive.topology, ordinary.topology)) {
    reject('session_account_topology_mismatch');
  }
  for (const identity of sensitive.identities) {
    if (ordinary.identities.has(identity)) reject('auth_file_inode_alias_rejected');
  }
  if (sensitive.treeDigest === ordinary.treeDigest) reject('copied_session_credentials');
  if (sensitive.deviceDigest === ordinary.deviceDigest) reject('linked_device_identity_reused');
}

function sameCredentialSeal(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode;
}

export function sameFilesystemIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function componentPaths(absolutePath) {
  const root = path.parse(absolutePath).root;
  const relative = path.relative(root, absolutePath);
  if (!relative) return [root];
  const components = relative.split(path.sep);
  const paths = [root];
  let current = root;
  for (const component of components) {
    current = path.join(current, component);
    paths.push(current);
  }
  return paths;
}

function assertCanonicalAbsolute(candidate, code) {
  if (typeof candidate !== 'string' || !path.isAbsolute(candidate)
      || path.normalize(candidate) !== candidate) {
    reject(code);
  }
}

function assertTrustedComponent(stat, uid) {
  const owner = Number(stat.uid);
  if (uid !== null && owner !== 0 && owner !== uid) {
    reject('session_path_untrusted_owner');
  }
  const mode = Number(stat.mode) & PERMISSION_BITS;
  if ((mode & UNTRUSTED_WRITE_BITS) !== 0 && (mode & STICKY_BIT) === 0) {
    reject('session_path_replaceable');
  }
}

function lstatDirectory(component) {
  let stat;
  try {
    stat = lstatSync(component, { bigint: true });
  } catch {
    reject('session_path_unavailable');
  }
  if (stat.isSymbolicLink()) reject('session_path_symlink_rejected');
  if (!stat.isDirectory()) reject('session_path_non_directory');
  return stat;
}

function snapshotComponent(component, stat) {
  return Object.freeze({ component, identity: identityOf(stat) });
}

function assertComponentSnapshots(expected, driftCode) {
  for (const snapshot of expected) {
    const observed = lstatDirectory(snapshot.component);
    if (!sameFilesystemIdentity(snapshot.identity, identityOf(observed))) reject(driftCode);
  }
}

function inspectSensitivePath(absolutePath, uid) {
  const components = componentPaths(absolutePath);
  const snapshots = [];
  let missingIndex = null;
  for (let index = 0; index < components.length; index += 1) {
    const component = components[index];
    let stat;
    try {
      stat = lstatSync(component, { bigint: true });
    } catch (error) {
      if (error?.code !== 'ENOENT' || index === 0) reject('session_path_unavailable');
      missingIndex = index;
      break;
    }
    if (stat.isSymbolicLink()) reject('session_path_symlink_rejected');
    if (!stat.isDirectory()) reject('session_path_non_directory');
    if (index < components.length - 1) assertTrustedComponent(stat, uid);
    snapshots.push(snapshotComponent(component, stat));
  }

  const nearest = snapshots.at(-1);
  let nearestResolved;
  try {
    nearestResolved = realpathSync.native(nearest.component);
  } catch {
    reject('session_path_unavailable');
  }
  const prospective = missingIndex === null
    ? nearestResolved
    : path.join(nearestResolved, path.relative(nearest.component, absolutePath));
  if (prospective !== absolutePath) reject('session_path_non_canonical');

  return Object.freeze({
    components: Object.freeze(snapshots),
    missing: missingIndex === null
      ? Object.freeze([])
      : Object.freeze(components.slice(missingIndex)),
    prospective,
  });
}

function createSensitiveDirectory(preflight, ordinary, uid) {
  let parentSnapshot = preflight.components.at(-1);
  for (const component of preflight.missing) {
    assertComponentSnapshots(preflight.components, 'sensitive_session_path_identity_changed');
    assertComponentSnapshots([parentSnapshot], 'sensitive_session_path_identity_changed');
    const ordinaryNow = captureDirectory(ordinary.absolutePath, { sensitive: false, uid });
    assertSameSnapshot(ordinary, ordinaryNow, 'ordinary_session_path_identity_changed');
    assertSeparatedProspective(preflight.prospective, ordinaryNow);
    try {
      mkdirSync(component, { mode: DIRECTORY_MODE });
      chmodSync(component, DIRECTORY_MODE);
    } catch {
      reject('session_path_unavailable');
    }
    assertComponentSnapshots([parentSnapshot], 'sensitive_session_path_identity_changed');
    const created = lstatDirectory(component);
    if (uid !== null && Number(created.uid) !== uid) reject('session_path_owner_rejected');
    if ((Number(created.mode) & PERMISSION_BITS) !== DIRECTORY_MODE) {
      reject('session_path_permissions_rejected');
    }
    parentSnapshot = snapshotComponent(component, created);
    const ordinaryAfter = captureDirectory(ordinary.absolutePath, { sensitive: false, uid });
    assertSameSnapshot(ordinary, ordinaryAfter, 'ordinary_session_path_identity_changed');
    assertSeparatedProspective(preflight.prospective, ordinaryAfter);
  }
}

function captureDirectory(absolutePath, { sensitive, uid }) {
  const components = componentPaths(absolutePath);
  const snapshots = components.map((component, index) => {
    const stat = lstatDirectory(component);
    if (index < components.length - 1) assertTrustedComponent(stat, uid);
    return snapshotComponent(component, stat);
  });
  const targetStat = lstatDirectory(absolutePath);
  if (sensitive) {
    if (uid !== null && Number(targetStat.uid) !== uid) reject('session_path_owner_rejected');
    if ((Number(targetStat.mode) & PERMISSION_BITS) !== DIRECTORY_MODE) {
      reject('session_path_permissions_rejected');
    }
  } else {
    assertTrustedComponent(targetStat, uid);
  }

  let resolved;
  try {
    resolved = realpathSync.native(absolutePath);
  } catch {
    reject('session_path_unavailable');
  }
  if (resolved !== absolutePath) reject('session_path_non_canonical');

  let descriptor;
  let openedStat;
  try {
    descriptor = openSync(
      absolutePath,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    openedStat = fstatSync(descriptor, { bigint: true });
  } catch {
    reject('session_path_open_rejected');
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  if (!openedStat.isDirectory()
      || !sameFilesystemIdentity(identityOf(targetStat), identityOf(openedStat))) {
    reject('session_path_identity_changed');
  }

  return Object.freeze({
    absolutePath,
    resolved,
    identity: identityOf(targetStat),
    components: Object.freeze(snapshots),
  });
}

function assertSameSnapshot(expected, observed, driftCode) {
  if (expected.absolutePath !== observed.absolutePath
      || expected.resolved !== observed.resolved
      || expected.components.length !== observed.components.length
      || !sameFilesystemIdentity(expected.identity, observed.identity)) {
    reject(driftCode);
  }
  for (let index = 0; index < expected.components.length; index += 1) {
    const before = expected.components[index];
    const after = observed.components[index];
    if (before.component !== after.component
        || !sameFilesystemIdentity(before.identity, after.identity)) {
      reject(driftCode);
    }
  }
}

function isWithin(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === ''
    || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function assertSeparatedProspective(sensitivePath, ordinary) {
  if (isWithin(sensitivePath, ordinary.resolved)
      || isWithin(ordinary.resolved, sensitivePath)) {
    reject('separate_sensitive_session_path_required');
  }
}

function assertSeparated(sensitive, ordinary) {
  assertSeparatedProspective(sensitive.resolved, ordinary);
  if (sameFilesystemIdentity(sensitive.identity, ordinary.identity)) {
    reject('separate_sensitive_session_path_required');
  }
}

export class SessionPathGuard {
  #sensitiveSnapshot;

  #ordinarySnapshot;

  #uid;

  #credentialSnapshots;

  constructor(sensitiveSnapshot, ordinarySnapshot, uid, credentialSnapshots = null) {
    this.#sensitiveSnapshot = sensitiveSnapshot;
    this.#ordinarySnapshot = ordinarySnapshot;
    this.#uid = uid;
    this.#credentialSnapshots = credentialSnapshots;
    this.sensitiveDir = sensitiveSnapshot.absolutePath;
    this.ordinaryDir = ordinarySnapshot.absolutePath;
    Object.freeze(this);
  }

  revalidate() {
    const sensitive = captureDirectory(this.sensitiveDir, { sensitive: true, uid: this.#uid });
    const ordinary = captureDirectory(this.ordinaryDir, { sensitive: false, uid: this.#uid });
    assertSameSnapshot(
      this.#sensitiveSnapshot,
      sensitive,
      'sensitive_session_path_identity_changed',
    );
    assertSameSnapshot(this.#ordinarySnapshot, ordinary, 'ordinary_session_path_identity_changed');
    assertSeparated(sensitive, ordinary);
    if (this.#credentialSnapshots) {
      const sensitiveArtifacts = captureAuthArtifacts(this.sensitiveDir, this.#uid);
      const ordinaryArtifacts = captureAuthArtifacts(this.ordinaryDir, this.#uid);
      const expected = this.#credentialSnapshots;
      if (!sameCredentialSeal(expected.sensitive.credsSeal, sensitiveArtifacts.credsSeal)
          || !sameCredentialSeal(expected.ordinary.credsSeal, ordinaryArtifacts.credsSeal)
          || expected.sensitive.deviceDigest !== sensitiveArtifacts.deviceDigest
          || expected.ordinary.deviceDigest !== ordinaryArtifacts.deviceDigest) {
        reject('session_credentials_changed');
      }
      if (!sameAccountTopology(expected.sensitive.topology, sensitiveArtifacts.topology)
          || !sameAccountTopology(expected.ordinary.topology, ordinaryArtifacts.topology)) {
        reject('session_account_topology_changed');
      }
      if (expected.sensitive.treeDigest !== sensitiveArtifacts.treeDigest
          || expected.ordinary.treeDigest !== ordinaryArtifacts.treeDigest) {
        reject('session_credentials_changed');
      }
      assertDistinctAuthArtifacts(sensitiveArtifacts, ordinaryArtifacts);
    }
  }

  topologyEvidence() {
    this.revalidate();
    if (!this.#credentialSnapshots) reject('credential_identity_invalid');
    const evidence = (snapshot, credentials) => Object.freeze({
      session_path: snapshot.absolutePath,
      session_identity: printableIdentity(snapshot.identity),
      credential_identity: `${credentials.credsSeal.dev}:${credentials.credsSeal.ino}`,
      device_identity_sha256: credentials.deviceDigest,
      credential_tree_sha256: credentials.treeDigest,
      account_phone_jid: credentials.topology.phone,
      account_lid_jid: credentials.topology.lid,
    });
    return Object.freeze({
      ordinary: evidence(this.#ordinarySnapshot, this.#credentialSnapshots.ordinary),
      sensitive: evidence(this.#sensitiveSnapshot, this.#credentialSnapshots.sensitive),
    });
  }
}

export function prepareSessionPaths(sensitiveDir, ordinaryDir, {
  uid = typeof process.getuid === 'function' ? process.getuid() : null,
  requireDistinctCredentials = false,
} = {}) {
  assertCanonicalAbsolute(sensitiveDir, 'canonical_absolute_sensitive_session_path_required');
  assertCanonicalAbsolute(ordinaryDir, 'canonical_absolute_ordinary_session_path_required');
  assertSeparatedProspective(sensitiveDir, { resolved: ordinaryDir });

  const ordinary = captureDirectory(ordinaryDir, { sensitive: false, uid });
  const sensitivePreflight = inspectSensitivePath(sensitiveDir, uid);
  assertSeparatedProspective(sensitivePreflight.prospective, ordinary);
  assertComponentSnapshots(
    sensitivePreflight.components,
    'sensitive_session_path_identity_changed',
  );
  const ordinaryPreCreation = captureDirectory(ordinaryDir, { sensitive: false, uid });
  assertSameSnapshot(ordinary, ordinaryPreCreation, 'ordinary_session_path_identity_changed');

  if (sensitivePreflight.missing.length > 0) {
    createSensitiveDirectory(sensitivePreflight, ordinaryPreCreation, uid);
  }

  const sensitive = captureDirectory(sensitiveDir, { sensitive: true, uid });
  const ordinaryAfterCreation = captureDirectory(ordinaryDir, { sensitive: false, uid });
  assertComponentSnapshots(
    sensitivePreflight.components,
    'sensitive_session_path_identity_changed',
  );
  assertSameSnapshot(ordinary, ordinaryAfterCreation, 'ordinary_session_path_identity_changed');
  assertSeparated(sensitive, ordinaryAfterCreation);

  const sensitiveStable = captureDirectory(sensitiveDir, { sensitive: true, uid });
  const ordinaryStable = captureDirectory(ordinaryDir, { sensitive: false, uid });
  assertSameSnapshot(sensitive, sensitiveStable, 'sensitive_session_path_identity_changed');
  assertSameSnapshot(ordinaryAfterCreation, ordinaryStable, 'ordinary_session_path_identity_changed');
  assertSeparated(sensitiveStable, ordinaryStable);
  let credentialSnapshots = null;
  if (requireDistinctCredentials) {
    const sensitiveArtifacts = captureAuthArtifacts(sensitiveDir, uid);
    const ordinaryArtifacts = captureAuthArtifacts(ordinaryDir, uid);
    assertDistinctAuthArtifacts(sensitiveArtifacts, ordinaryArtifacts);
    credentialSnapshots = Object.freeze({
      sensitive: sensitiveArtifacts,
      ordinary: ordinaryArtifacts,
    });
  }
  return new SessionPathGuard(
    sensitiveStable, ordinaryStable, uid, credentialSnapshots,
  );
}
