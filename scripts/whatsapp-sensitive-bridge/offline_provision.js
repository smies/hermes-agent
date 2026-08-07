#!/usr/bin/env node

import { randomUUID } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  realpathSync,
  readdirSync,
} from 'node:fs';
import { chmod, mkdir, mkdtemp, open, readFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';

import makeWASocket, { jidNormalizedUser, useMultiFileAuthState } from '@whiskeysockets/baileys';

import {
  buildProvisioningSocketConfig,
  canonicalAccount,
  normalizePairingCode,
  parseProvisioningRequest,
  verifyLidBootstrap,
} from './provisioning_core.js';
import { prepareSessionPaths } from './session_paths.js';

const MAX_INPUT_BYTES = 4096;
const DEFAULT_TIMEOUT_MS = 120_000;
const AUTH_DIRECTORY_MODE = 0o700;
const AUTH_FILE_MODE = 0o600;
export const PRE_CODE_FAILURE_REASONS = Object.freeze([
  'connection_closed',
  'ordinary_session_not_ready',
  'pairing_code_invalid',
  'pairing_request_failed',
  'provisioning_failed',
  'provisioning_timeout',
]);

// Set before any call to useMultiFileAuthState.  Baileys otherwise creates
// auth JSON as 0644 under the usual 0022 umask.
process.umask(0o077);

function silentLogger() {
  const logger = { level: 'silent', child: () => logger };
  for (const name of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) logger[name] = () => {};
  return Object.freeze(logger);
}

async function readRequest(stream) {
  let value = '';
  for await (const chunk of stream) {
    value += chunk;
    if (Buffer.byteLength(value, 'utf8') > MAX_INPUT_BYTES) throw new Error('request_invalid');
  }
  const lines = value.split(/\r?\n/).filter(Boolean);
  if (lines.length !== 1) throw new Error('request_invalid');
  return parseProvisioningRequest(JSON.parse(lines[0]));
}

async function existingAccount(session, canonicalizeJid) {
  try {
    const payload = JSON.parse(await readFile(path.join(session, 'creds.json'), 'utf8'));
    return canonicalAccount(payload?.me?.id || payload?.me?.lid || '', canonicalizeJid);
  } catch { return null; }
}

async function stagedRegisteredAccount(session, canonicalizeJid) {
  try {
    const payload = JSON.parse(await readFile(path.join(session, 'creds.json'), 'utf8'));
    if (payload?.registered !== true) return null;
    return canonicalAccount(payload?.me?.id || '', canonicalizeJid);
  } catch { return null; }
}

async function sessionTopology(auth, canonicalizeJid, sock = {}) {
  if (auth?.state?.creds?.registered !== true) return null;
  const phone = canonicalAccount(auth.state.creds?.me?.id || '', canonicalizeJid);
  if (!phone?.endsWith('@s.whatsapp.net')) return null;
  const lid = await verifyLidBootstrap({ auth, sock, phoneJid: phone, canonicalizeJid });
  if (!lid?.endsWith('@lid')) return null;
  const storedLidValue = auth.state.creds?.me?.lid;
  const storedLid = storedLidValue
    ? canonicalAccount(storedLidValue, canonicalizeJid)
    : null;
  if (storedLidValue && storedLid !== lid) return null;
  return Object.freeze({ phone, lid });
}

function sameTopology(left, right) {
  return Boolean(left && right && left.phone === right.phone && left.lid === right.lid);
}

function validateCredentialFile(session) {
  const target = path.join(session, 'creds.json');
  const info = lstatSync(target);
  if (info.isSymbolicLink() || !info.isFile() || info.nlink !== 1
      || (info.mode & 0o777) !== 0o600
      || (typeof process.getuid === 'function' && info.uid !== process.getuid())
      || realpathSync.native(target) !== target) throw new Error('credential_file_unsafe');
}

function validateAuthFiles(session) {
  validateCredentialFile(session);
  const validateDirectory = (directory) => {
    const directoryInfo = lstatSync(directory);
    if (directoryInfo.isSymbolicLink() || !directoryInfo.isDirectory()
        || (directoryInfo.mode & 0o777) !== AUTH_DIRECTORY_MODE
        || (typeof process.getuid === 'function' && directoryInfo.uid !== process.getuid())
        || realpathSync.native(directory) !== directory) throw new Error('auth_directory_unsafe');
    for (const name of readdirSync(directory)) {
      const target = path.join(directory, name);
      const info = lstatSync(target);
      if (info.isDirectory() && !info.isSymbolicLink()) {
        validateDirectory(target);
        continue;
      }
      if (!name.endsWith('.json') || info.isSymbolicLink() || !info.isFile() || info.nlink !== 1
          || (info.mode & 0o777) !== AUTH_FILE_MODE
          || (typeof process.getuid === 'function' && info.uid !== process.getuid())
          || realpathSync.native(target) !== target) throw new Error('auth_file_unsafe');
    }
  };
  validateDirectory(session);
}

async function normalizeNewAuthTree(session) {
  const normalizeDirectory = async (directory) => {
    await chmod(directory, AUTH_DIRECTORY_MODE);
    for (const name of readdirSync(directory)) {
      const target = path.join(directory, name);
      const info = lstatSync(target);
      if (info.isSymbolicLink() || (!info.isFile() && !info.isDirectory())) {
        throw new Error('staged_auth_tree_unsafe');
      }
      if (info.isDirectory()) await normalizeDirectory(target);
      else await chmod(target, AUTH_FILE_MODE);
    }
  };
  await normalizeDirectory(session);
}

function wrapStagedAuth(auth, session) {
  const keys = auth?.state?.keys;
  const guardedKeys = keys && typeof keys.get === 'function' && typeof keys.set === 'function'
    ? {
      get: (...args) => keys.get(...args),
      set: async (...args) => {
        const result = await keys.set(...args);
        await normalizeNewAuthTree(session);
        return result;
      },
    }
    : keys;
  return {
    state: { ...(auth?.state || {}), keys: guardedKeys },
    saveCreds: async (...args) => {
      const result = await auth.saveCreds(...args);
      await normalizeNewAuthTree(session);
      return result;
    },
  };
}

function commonOwnerRoot(left, right) {
  const leftParts = path.resolve(left).split(path.sep);
  const rightParts = path.resolve(right).split(path.sep);
  const shared = [];
  while (leftParts.length && rightParts.length && leftParts[0] === rightParts[0]) {
    shared.push(leftParts.shift());
    rightParts.shift();
  }
  const root = shared.length === 1 && shared[0] === ''
    ? path.parse(path.resolve(left)).root
    : shared.join(path.sep) || path.parse(path.resolve(left)).root;
  validateOwnerDirectory(root, { required: true });
  return root;
}

async function ensureNewSessionParent(session) {
  validateOwnerDirectory(session, { required: false });
  const parent = path.dirname(session);
  await mkdir(parent, { recursive: true, mode: AUTH_DIRECTORY_MODE });
  validateOwnerDirectory(parent, { required: true });
}

async function syncDirectory(directory) {
  const handle = await open(directory, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
}

export class ProvisioningCommitError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ProvisioningCommitError';
    this.code = code;
    this.retryable = false;
  }
}

async function retryRecovery(operation, attempts = 2) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      await operation();
      return true;
    } catch {}
  }
  return false;
}

function inodeSeal(target) {
  if (!existsSync(target)) return null;
  const info = lstatSync(target);
  return Object.freeze({ dev: info.dev, ino: info.ino });
}

function sameInode(target, seal) {
  if (!seal || !existsSync(target)) return false;
  const info = lstatSync(target);
  return info.dev === seal.dev && info.ino === seal.ino;
}

function validateLegacyReprovisionTarget(target, expected = null) {
  if (!existsSync(target)) return null;
  let cursor = path.parse(target).root;
  for (const component of path.relative(cursor, target).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, component);
    const info = lstatSync(cursor);
    if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('session_path_unsafe');
    if (typeof process.getuid === 'function' && info.uid !== 0 && info.uid !== process.getuid()) {
      throw new Error('session_path_unsafe');
    }
    if ((info.mode & 0o022) !== 0 && !(info.uid === 0 && (info.mode & 0o1000) !== 0)) {
      throw new Error('session_path_unsafe');
    }
  }
  if (realpathSync.native(target) !== target) throw new Error('session_path_unsafe');
  const info = lstatSync(target);
  if (typeof process.getuid === 'function' && info.uid !== process.getuid()) {
    throw new Error('session_path_unsafe');
  }
  const seal = Object.freeze({ dev: info.dev, ino: info.ino, mode: info.mode & 0o777 });
  if (expected && (seal.dev !== expected.dev || seal.ino !== expected.ino
      || seal.mode !== expected.mode)) throw new Error('session_path_changed');
  return seal;
}

export async function commitStagedSession(
  stage,
  session,
  ownerRoot,
  legacySeal = null,
  beforeDurableConfirmation = null,
  commitOps = null,
) {
  const renamePath = commitOps?.rename || rename;
  const removePath = commitOps?.remove || rm;
  const syncParent = commitOps?.syncDirectory || syncDirectory;
  await normalizeNewAuthTree(stage);
  validateAuthFiles(stage);
  if (legacySeal) validateOwnerDirectory(path.dirname(session), { required: true });
  else await ensureNewSessionParent(session);
  const rollback = path.join(ownerRoot, `.whatsapp-provision-rollback-${randomUUID()}`);
  const failed = path.join(ownerRoot, `.whatsapp-provision-failed-${randomUUID()}`);
  let originalSeal = null;
  let commitState = 'prepared';
  try {
    if (existsSync(session)) {
      if (legacySeal) validateLegacyReprovisionTarget(session, legacySeal);
      else {
        validateOwnerDirectory(session, { required: true });
        validateAuthFiles(session);
      }
      originalSeal = inodeSeal(session);
      await renamePath(session, rollback);
      commitState = 'old_backup_renamed';
      if (legacySeal) validateLegacyReprovisionTarget(rollback, legacySeal);
      await syncParent(path.dirname(session));
      commitState = 'old_backup_durable';
    }
    await renamePath(stage, session);
    commitState = 'new_canonical_renamed';
    await syncParent(path.dirname(session));
    commitState = 'new_canonical_durable';
    validateOwnerDirectory(session, { required: true });
    validateAuthFiles(session);
    if (typeof beforeDurableConfirmation === 'function') await beforeDurableConfirmation();
    commitState = 'new_canonical_validated';
    if (originalSeal) {
      // Irreversible boundary. From this point onward the new canonical tree
      // is the survivor; cleanup uncertainty must never move/delete it.
      commitState = 'cleanup_started';
      await removePath(rollback, { recursive: true, force: false });
      commitState = 'old_backup_deleted';
      await syncParent(path.dirname(session));
    }
    commitState = 'committed';
  } catch {
    if (['cleanup_started', 'old_backup_deleted'].includes(commitState)) {
      throw new ProvisioningCommitError('cleanup_durability_uncertain');
    }

    // A failed rename can be ambiguous to its caller: the namespace mutation
    // may have happened before the error surfaced. Recover from observed
    // inodes, not only from the last in-memory state transition.
    let recoveryCertain = true;
    if (existsSync(session) && !sameInode(session, originalSeal)) {
      recoveryCertain = await retryRecovery(() => renamePath(session, failed));
    }
    if (originalSeal && !sameInode(session, originalSeal)) {
      if (!existsSync(session) && existsSync(rollback)) {
        const restored = await retryRecovery(() => renamePath(rollback, session));
        const synced = restored
          ? await retryRecovery(() => syncParent(path.dirname(session)))
          : false;
        recoveryCertain = recoveryCertain && restored && synced
          && sameInode(session, originalSeal);
      } else {
        recoveryCertain = false;
      }
    }
    // Removal is bounded and only targets staged NEW state. A persistent
    // cleanup failure keeps an owner-only survivor and becomes non-retryable;
    // it never risks the restored original.
    let cleanupCertain = true;
    if (existsSync(failed)) {
      cleanupCertain = await retryRecovery(
        () => removePath(failed, { recursive: true, force: true }),
      );
    }
    if (existsSync(stage)) {
      cleanupCertain = await retryRecovery(
        () => removePath(stage, { recursive: true, force: true }),
      ) && cleanupCertain;
    }
    if (!recoveryCertain || !cleanupCertain) {
      throw new ProvisioningCommitError('recovery_durability_uncertain');
    }
    throw new Error('staged_commit_failed');
  }
}

function validateOwnerDirectory(target, { required }) {
  if (!existsSync(target)) {
    if (required) throw new Error('session_path_unavailable');
    let cursor = path.dirname(target);
    while (!existsSync(cursor)) cursor = path.dirname(cursor);
    if (realpathSync.native(cursor) !== cursor) throw new Error('session_path_unsafe');
    return false;
  }
  let cursor = path.parse(target).root;
  for (const component of path.relative(cursor, target).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, component);
    const info = lstatSync(cursor);
    if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('session_path_unsafe');
    if (typeof process.getuid === 'function' && info.uid !== 0 && info.uid !== process.getuid()) {
      throw new Error('session_path_unsafe');
    }
    if ((info.mode & 0o022) !== 0 && !(info.uid === 0 && (info.mode & 0o1000) !== 0)) {
      throw new Error('session_path_unsafe');
    }
  }
  if (realpathSync.native(target) !== target) throw new Error('session_path_unsafe');
  const targetInfo = lstatSync(target);
  if ((targetInfo.mode & 0o777) !== 0o700
      || (typeof process.getuid === 'function' && targetInfo.uid !== process.getuid())) {
    throw new Error('session_path_unsafe');
  }
  return true;
}

async function validateSessionDirectories(request, { create }) {
  if (create) {
    // Sensitive provisioning is anchored to an already trusted ordinary
    // session.  It must never manufacture an empty ordinary root and then
    // treat that path as an account-separation proof.
    if (request.role === 'sensitive' && !existsSync(request.ordinarySession)) {
      throw new Error('ordinary_session_not_ready');
    }
    if (!existsSync(request.ordinarySession)) {
      validateOwnerDirectory(request.ordinarySession, { required: false });
      await mkdir(request.ordinarySession, { recursive: true, mode: 0o700 });
    }
    validateOwnerDirectory(request.ordinarySession, { required: true });
    // prepareSessionPaths creates only the sensitive directory, after proving
    // it cannot alias or nest the ordinary root.
    const guard = prepareSessionPaths(request.sensitiveSession, request.ordinarySession);
    guard.revalidate();
    return guard;
  }
  validateOwnerDirectory(request.session, { required: true });
  validateAuthFiles(request.session);
  const other = request.role === 'ordinary' ? request.sensitiveSession : request.ordinarySession;
  if (validateOwnerDirectory(other, { required: false })
      && existsSync(path.join(other, 'creds.json'))) {
    validateAuthFiles(other);
  }
  return Object.freeze({ revalidate() { return validateSessionDirectories(request, { create: false }); } });
}

export async function validateExistingOffline({
  request,
  useAuthState = useMultiFileAuthState,
  canonicalizeJid = jidNormalizedUser,
}) {
  try {
    await validateSessionDirectories(request, { create: false });
    const selected = await useAuthState(request.session);
    const selectedTopology = await sessionTopology(selected, canonicalizeJid);
    if (!selectedTopology) return null;
    const otherSession = request.role === 'ordinary'
      ? request.sensitiveSession : request.ordinarySession;
    const otherReady = existsSync(path.join(otherSession, 'creds.json'));
    if (!otherReady) {
      return request.role === 'ordinary'
        ? Object.freeze({ account_namespace: 's.whatsapp.net', lid_ready: true })
        : null;
    }
    validateAuthFiles(otherSession);
    validateAuthFiles(request.session);
    const other = await useAuthState(otherSession);
    const otherTopology = await sessionTopology(other, canonicalizeJid);
    if (!sameTopology(selectedTopology, otherTopology)) return null;
    const artifactGuard = prepareSessionPaths(
      request.sensitiveSession,
      request.ordinarySession,
      { requireDistinctCredentials: true },
    );
    artifactGuard.revalidate();
    return Object.freeze({ account_namespace: 's.whatsapp.net', lid_ready: true });
  } catch {
    return null;
  }
}

export async function provisionOffline({
  request,
  makeSocket = makeWASocket,
  useAuthState = useMultiFileAuthState,
  canonicalizeJid = jidNormalizedUser,
  emitCode,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  acquireLock = null,
  beforeDurableConfirmation = null,
  commitOps = null,
}) {
  process.umask(0o077);
  if (typeof emitCode !== 'function') throw new TypeError('operator channel required');
  const ownerRoot = commonOwnerRoot(request.ordinarySession, request.sensitiveSession);
  // Production serialization is held by the Python parent with flock(2) for
  // the exact child lifetime, so process death releases it automatically.
  // Direct unit callers may inject an in-memory lock contract.
  const lock = typeof acquireLock === 'function' ? acquireLock(request, ownerRoot) : null;
  let stage = null;
  const otherSession = request.role === 'ordinary' ? request.sensitiveSession : request.ordinarySession;
  const sockets = new Set();
  let timer;
  let pairedCode = false;
  let codeEmitted = false;
  let done = false;
  let transitionChain = Promise.resolve();
  let authWriteChain = Promise.resolve();
  let account = null;
  let lid = null;
  let legacySeal = null;
  const phoneJid = `${request.phone}@s.whatsapp.net`;
  const fenceSockets = () => {
    for (const candidate of sockets) {
      try { candidate.ev?.removeAllListeners?.(); } catch {}
      try { candidate.end?.(); } catch {}
    }
  };
  const close = () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    fenceSockets();
  };
  try {
    if (request.role === 'sensitive') {
      const ordinaryRequest = Object.freeze({
        ...request,
        action: 'validate',
        phone: null,
        role: 'ordinary',
        session: request.ordinarySession,
      });
      const ordinaryReady = await validateExistingOffline({
        request: ordinaryRequest,
        useAuthState,
        canonicalizeJid,
      });
      if (!ordinaryReady) throw new Error('ordinary_session_not_ready');
    }
    if (existsSync(request.session)) {
      if (request.reprovision) legacySeal = validateLegacyReprovisionTarget(request.session);
      else {
        validateOwnerDirectory(request.session, { required: true });
        validateAuthFiles(request.session);
      }
    } else {
      validateOwnerDirectory(request.session, { required: false });
    }
    if (existsSync(otherSession)) {
      validateOwnerDirectory(otherSession, { required: true });
      if (existsSync(path.join(otherSession, 'creds.json'))) validateAuthFiles(otherSession);
    } else {
      validateOwnerDirectory(otherSession, { required: false });
    }
    const otherAccountBeforePairing = await existingAccount(otherSession, canonicalizeJid);
    stage = await mkdtemp(path.join(ownerRoot, '.whatsapp-provision-stage-'));
    await chmod(stage, AUTH_DIRECTORY_MODE);
    const rawAuth = await useAuthState(stage);
    const auth = wrapStagedAuth(rawAuth, stage);
    await normalizeNewAuthTree(stage);
    let authWriteFailed = false;
    let finishing = false;
    let generationCounter = 0;
    let activeGeneration = 0;
    let pendingRestartGeneration = 0;
    let restartCount = 0;
    let settled = false;
    let commitStarted = false;
    const persistAuth = () => {
      authWriteChain = authWriteChain
        .then(() => auth.saveCreds())
        .catch(() => { authWriteFailed = true; });
      return authWriteChain;
    };
    const outcome = await new Promise((resolve, reject) => {
      const isActive = generation => !settled && generation === activeGeneration;
      const settle = (error, value = null) => {
        if (settled) return false;
        settled = true;
        activeGeneration = 0;
        pendingRestartGeneration = 0;
        close();
        if (error) reject(error instanceof Error ? error : new Error(error));
        else resolve(value);
        return true;
      };
      const fail = code => settle(code instanceof Error ? code : new Error(code));
      const enqueueTransition = operation => {
        const current = transitionChain.then(operation);
        transitionChain = current.catch(() => {});
        return current;
      };
      timer = setTimeout(() => {
        if (!commitStarted) fail('provisioning_timeout');
      }, timeoutMs);
      const statusCode = (update) => {
        const value = update?.lastDisconnect?.error?.output?.statusCode;
        return Number.isInteger(value) ? value : null;
      };
      let startSocket;
      const onConnectionUpdate = async (
        candidate, generation, onCredsUpdate, update,
        restartFenced = false, postCodeOpen = false,
      ) => {
        if (restartFenced) {
          if (settled || pendingRestartGeneration !== generation) return;
          try {
            if (statusCode(update) !== 515 || restartCount !== 0) {
              return fail('connection_closed');
            }
            await persistAuth();
            if (settled || pendingRestartGeneration !== generation) return;
            if (authWriteFailed) return fail('credential_persistence_failed');
            if (!codeEmitted) return fail('connection_closed');
            validateAuthFiles(stage);
            if (await stagedRegisteredAccount(stage, canonicalizeJid) !== phoneJid) {
              if (settled || pendingRestartGeneration !== generation) return;
              return fail('connection_closed');
            }
            if (settled || pendingRestartGeneration !== generation) return;
            restartCount = 1;
            pendingRestartGeneration = 0;
            finishing = false;
            startSocket();
          } catch {
            fail('provisioning_failed');
          }
          return;
        }
        const mayFinishPairing = () => isActive(generation);
        if (!isActive(generation)
            && !(update?.qr && pendingRestartGeneration === generation)) return;
        try {
          validateOwnerDirectory(stage, { required: true });
          // rc14 emits `connecting` before its WebSocket/Noise handshake is
          // usable, and requestPairingCode() fails immediately if called then.
          // Its private QR-reference update is the first post-handshake signal
          // for an unregistered socket.  Treat only the presence of that field
          // as readiness; never inspect, retain, emit, or display its payload.
          if (!pairedCode && update?.qr) {
            pairedCode = true;
            let providerCode;
            try {
              providerCode = await candidate.requestPairingCode(request.phone);
            } catch {
              return fail('pairing_request_failed');
            }
            if (!mayFinishPairing()) return;
            let code;
            try {
              code = normalizePairingCode(providerCode);
            } catch {
              return fail('pairing_code_invalid');
            } finally {
              providerCode = null;
            }
            emitCode(code);
            codeEmitted = true;
          }
          if (!codeEmitted || !postCodeOpen) return;
          if (finishing) return;
          finishing = true;
          // Fence later provider writes, then drain every already-scheduled
          // write and one final credential snapshot before validation/commit.
          candidate.ev.off?.('creds.update', onCredsUpdate);
          await persistAuth();
          if (!isActive(generation)) return;
          if (authWriteFailed) return fail('credential_persistence_failed');
          account = canonicalAccount(candidate.user?.id || '', canonicalizeJid);
          if (!account || account !== phoneJid) return fail('account_binding_failed');
          const otherAccountAfterPairing = await existingAccount(otherSession, canonicalizeJid);
          if (!isActive(generation)) return;
          if ((otherAccountBeforePairing && otherAccountAfterPairing !== otherAccountBeforePairing)
              || (otherAccountAfterPairing && account !== otherAccountAfterPairing)) {
            return fail('session_process_isolation_required');
          }
          lid = await verifyLidBootstrap({
            auth, sock: candidate, phoneJid, canonicalizeJid,
          });
          if (!isActive(generation)) return;
          if (!lid) return fail('lid_bootstrap_incomplete');
          const persistedLid = await verifyLidBootstrap({
            auth,
            sock: {},
            phoneJid,
            canonicalizeJid,
          });
          if (!isActive(generation)) return;
          if (!persistedLid || persistedLid !== lid) return fail('lid_bootstrap_incomplete');
          if (otherAccountAfterPairing) {
            const otherAuth = await useAuthState(otherSession);
            if (!isActive(generation)) return;
            const otherTopology = await sessionTopology(otherAuth, canonicalizeJid);
            if (!isActive(generation)) return;
            if (!sameTopology({ phone: account, lid }, otherTopology)) {
              return fail('account_topology_mismatch');
            }
          }
          await normalizeNewAuthTree(stage);
          if (!isActive(generation)) return;
          validateAuthFiles(stage);
          if (otherAccountAfterPairing) {
            const stagedGuard = request.role === 'sensitive'
              ? prepareSessionPaths(stage, otherSession, { requireDistinctCredentials: true })
              : prepareSessionPaths(otherSession, stage, { requireDistinctCredentials: true });
            stagedGuard.revalidate();
          }
          // Re-read the other role immediately before commit while the
          // cross-role lock is still held.  A same-account race therefore has
          // exactly one possible winner.
          const otherAccountBeforeCommit = await existingAccount(otherSession, canonicalizeJid);
          if (!isActive(generation)) return;
          if ((otherAccountAfterPairing && otherAccountBeforeCommit !== otherAccountAfterPairing)
              || (otherAccountBeforeCommit && account !== otherAccountBeforeCommit)) {
            return fail('session_process_isolation_required');
          }
          const confirmIsolation = async () => {
            if (!isActive(generation)) throw new Error('stale_generation');
            if (otherAccountBeforeCommit) {
              const committedGuard = prepareSessionPaths(
                request.sensitiveSession,
                request.ordinarySession,
                { requireDistinctCredentials: true },
              );
              committedGuard.revalidate();
              const committed = await useAuthState(request.session);
              if (!isActive(generation)) throw new Error('stale_generation');
              const other = await useAuthState(otherSession);
              if (!isActive(generation)) throw new Error('stale_generation');
              const committedTopology = await sessionTopology(committed, canonicalizeJid);
              if (!isActive(generation)) throw new Error('stale_generation');
              const otherTopology = await sessionTopology(other, canonicalizeJid);
              if (!isActive(generation)) throw new Error('stale_generation');
              if (!sameTopology(committedTopology, otherTopology)) {
                throw new Error('account_topology_mismatch');
              }
            }
            if (typeof beforeDurableConfirmation === 'function') {
              await beforeDurableConfirmation();
              if (!isActive(generation)) throw new Error('stale_generation');
            }
          };
          if (!isActive(generation)) return;
          // The ordinary deadline governs pairing and validation only. Once
          // commit owns the generation, provider listeners are fenced and the
          // timer is disarmed; commitStagedSession must converge through its
          // existing durable success or bounded rollback/recovery contract.
          commitStarted = true;
          clearTimeout(timer);
          fenceSockets();
          await commitStagedSession(
            stage,
            request.session,
            ownerRoot,
            legacySeal,
            confirmIsolation,
            commitOps,
          );
          if (!isActive(generation)) return;
          stage = null;
          settle(null, Object.freeze({
            account_namespace: account.split('@')[1], lid_ready: true,
          }));
        } catch (error) {
          fail(error instanceof ProvisioningCommitError ? error : 'provisioning_failed');
        }
      };
      startSocket = () => {
        const generation = ++generationCounter;
        activeGeneration = generation;
        const candidate = makeSocket(buildProvisioningSocketConfig({
          auth: auth.state,
          logger: silentLogger(),
        }));
        sockets.add(candidate);
        const onCredsUpdate = () => {
          if (isActive(generation)) void persistAuth();
        };
        candidate.ev.on('creds.update', onCredsUpdate);
        candidate.ev.on('connection.update', (update) => {
          if (!isActive(generation)) return;
          if (update?.connection === 'close') {
            // Fence synchronously at event ingress. An already-entered open
            // handler will observe the lost generation after its next await;
            // the serialized close transition validates restart eligibility
            // after all earlier connection transitions have quiesced.
            activeGeneration = 0;
            pendingRestartGeneration = generation;
            candidate.ev.off?.('creds.update', onCredsUpdate);
            void enqueueTransition(() => onConnectionUpdate(
              candidate, generation, onCredsUpdate, update, true,
            ));
            return;
          }
          // Capture authentication eligibility at event ingress. An `open`
          // received before the operator code exists is transport readiness,
          // even if a queued handler runs after code emission. The provider
          // must emit a fresh post-code `open` before credentials are trusted.
          const postCodeOpen = codeEmitted && update?.connection === 'open';
          void enqueueTransition(() => onConnectionUpdate(
            candidate, generation, onCredsUpdate, update, false, postCodeOpen,
          ));
        });
      };
      try { startSocket(); } catch { fail('provisioning_failed'); }
    });
    return outcome;
  } finally {
    close();
    try { await transitionChain; } catch {}
    try { await authWriteChain; } catch {}
    if (stage) {
      try { await rm(stage, { recursive: true, force: true }); } catch {}
    }
    lock?.release();
  }
}

export async function runProvisioner({
  input = process.stdin,
  output = process.stdout,
  operatorOutput = null,
  provision = provisionOffline,
} = {}) {
  let request;
  let codeWritten = false;
  try {
    request = await readRequest(input);
    if (request.action === 'validate') {
      const validated = await validateExistingOffline({ request });
      output.write(`${JSON.stringify({
        event: 'complete',
        state: validated ? 'ready_for_production' : 'needs_provisioning',
        ...(validated || {}),
      })}\n`);
      return validated ? 0 : 1;
    }
    if (!operatorOutput || typeof operatorOutput.write !== 'function') {
      throw new Error('operator_channel_required');
    }
    const result = await provision({
      request,
      emitCode: (code) => {
        if (codeWritten) throw new Error('pairing_code_reuse');
        codeWritten = true;
        operatorOutput.write(`${JSON.stringify({ event: 'pairing_code', code })}\n`);
      },
    });
    output.write(`${JSON.stringify({ event: 'complete', state: 'ready_for_production', ...result })}\n`);
    return 0;
  } catch (error) {
    const code = String(error?.message || '');
    const unsafeExisting = new Set([
      'auth_file_unsafe', 'auth_directory_unsafe', 'credential_file_unsafe',
      'session_path_unsafe', 'session_path_changed',
    ]).has(code);
    output.write(`${JSON.stringify({
      event: 'complete',
      state: 'needs_provisioning',
      ...(error instanceof ProvisioningCommitError
        ? { error: error.code, retryable: false }
        : {}),
      ...(unsafeExisting ? { error: 'unsafe_existing_session_requires_reprovision' } : {}),
    })}\n`);
    if (!codeWritten && operatorOutput && typeof operatorOutput.write === 'function') {
      const reason = PRE_CODE_FAILURE_REASONS.includes(code) ? code : 'provisioning_failed';
      operatorOutput.write(`${JSON.stringify({ event: 'pairing_failure', reason })}\n`);
    }
    return 1;
  } finally {
    request = null;
  }
}
