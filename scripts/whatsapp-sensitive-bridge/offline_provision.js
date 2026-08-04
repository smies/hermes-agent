#!/usr/bin/env node

import { createWriteStream } from 'node:fs';
import { mkdir, readFile } from 'node:fs/promises';
import { existsSync, lstatSync, realpathSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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
  for (const name of readdirSync(session)) {
    if (!name.endsWith('.json')) continue;
    const target = path.join(session, name);
    const info = lstatSync(target);
    if (info.isSymbolicLink() || !info.isFile() || info.nlink !== 1
        || (info.mode & 0o777) !== 0o600
        || (typeof process.getuid === 'function' && info.uid !== process.getuid())
        || realpathSync.native(target) !== target) throw new Error('auth_file_unsafe');
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
  await validateSessionDirectories(request, { create: false });
  const selected = await useAuthState(request.session);
  if (selected?.state?.creds?.registered !== true) return null;
  const account = canonicalAccount(selected.state.creds?.me?.id || '', canonicalizeJid);
  if (!account) return null;
  const otherSession = request.role === 'ordinary' ? request.sensitiveSession : request.ordinarySession;
  if (existsSync(path.join(otherSession, 'creds.json'))) validateAuthFiles(otherSession);
  if (existsSync(path.join(request.session, 'creds.json'))) validateAuthFiles(request.session);
  const otherAccount = await existingAccount(otherSession, canonicalizeJid);
  if (otherAccount && otherAccount === account) return null;
  const phoneJid = account.endsWith('@s.whatsapp.net') ? account : null;
  if (!phoneJid) return null;
  const lid = await verifyLidBootstrap({ auth: selected, sock: {}, phoneJid, canonicalizeJid });
  if (!lid) return null;
  return Object.freeze({ account_namespace: account.split('@')[1], lid_ready: true });
}

export async function provisionOffline({
  request,
  makeSocket = makeWASocket,
  useAuthState = useMultiFileAuthState,
  canonicalizeJid = jidNormalizedUser,
  emitCode,
  timeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  if (typeof emitCode !== 'function') throw new TypeError('operator channel required');
  if (request.role === 'sensitive') {
    const ordinaryRequest = Object.freeze({
      ...request,
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
  const pathGuard = await validateSessionDirectories(request, { create: true });
  const otherSession = request.role === 'ordinary' ? request.sensitiveSession : request.ordinarySession;
  const otherAccount = await existingAccount(otherSession, canonicalizeJid);
  const auth = await useAuthState(request.session);
  const storedAccount = canonicalAccount(auth?.state?.creds?.me?.id || '', canonicalizeJid);
  if (storedAccount && otherAccount && storedAccount === otherAccount) throw new Error('account_separation_required');

  const sock = makeSocket(buildProvisioningSocketConfig({ auth: auth.state, logger: silentLogger() }));
  let timer;
  let pairedCode = false;
  let done = false;
  let account = null;
  let lid = null;
  const phoneJid = `${request.phone}@s.whatsapp.net`;
  const close = () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    try { sock.ev?.removeAllListeners?.(); } catch {}
    try { sock.end?.(); } catch {}
  };
  try {
    const outcome = await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error('provisioning_timeout')), timeoutMs);
      const fail = (code) => reject(new Error(code));
      sock.ev.on('creds.update', () => { void Promise.resolve(auth.saveCreds?.()).catch(() => {}); });
      sock.ev.on('connection.update', async (update) => {
        try {
          if (update?.qr) return fail('qr_payload_forbidden');
          pathGuard.revalidate();
          if (!pairedCode && !auth.state?.creds?.registered
              && (update?.connection === 'connecting' || update?.connection === undefined)) {
            pairedCode = true;
            const code = normalizePairingCode(await sock.requestPairingCode(request.phone));
            emitCode(code);
          }
          if (update?.connection === 'close') return fail('connection_closed');
          if (update?.connection !== 'open') return;
          account = canonicalAccount(sock.user?.id || '', canonicalizeJid);
          if (!account || account !== phoneJid) return fail('account_binding_failed');
          if (otherAccount && account === otherAccount) return fail('account_separation_required');
          lid = await verifyLidBootstrap({ auth, sock, phoneJid, canonicalizeJid });
          if (!lid) return fail('lid_bootstrap_incomplete');
          await Promise.resolve(auth.saveCreds?.());
          const persistedLid = await verifyLidBootstrap({
            auth,
            sock: {},
            phoneJid,
            canonicalizeJid,
          });
          if (!persistedLid || persistedLid !== lid) return fail('lid_bootstrap_incomplete');
          validateAuthFiles(request.session);
          resolve(Object.freeze({ account_namespace: account.split('@')[1], lid_ready: true }));
        } catch { fail('provisioning_failed'); }
      });
    });
    return outcome;
  } finally {
    close();
  }
}

export async function runProvisioner({
  input = process.stdin,
  output = process.stdout,
  operatorOutput = null,
} = {}) {
  let request;
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
    let codeWritten = false;
    if (!operatorOutput || typeof operatorOutput.write !== 'function') {
      throw new Error('operator_channel_required');
    }
    const result = await provisionOffline({
      request,
      emitCode: (code) => {
        if (codeWritten) throw new Error('pairing_code_reuse');
        codeWritten = true;
        operatorOutput.write(`${JSON.stringify({ event: 'pairing_code', code })}\n`);
      },
    });
    output.write(`${JSON.stringify({ event: 'complete', state: 'ready_for_production', ...result })}\n`);
    return 0;
  } catch {
    output.write(`${JSON.stringify({ event: 'complete', state: 'needs_provisioning' })}\n`);
    return 1;
  } finally {
    request = null;
  }
}

if (path.resolve(process.argv[1] || '') === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const operatorIndex = args.indexOf('--operator-fd');
  const operatorFd = operatorIndex >= 0 && args.length === 2
    ? Number(args[operatorIndex + 1])
    : null;
  const operatorOutput = Number.isInteger(operatorFd) && operatorFd >= 3
    ? createWriteStream(null, { fd: operatorFd, autoClose: false })
    : null;
  process.exitCode = await runProvisioner({ operatorOutput });
}
