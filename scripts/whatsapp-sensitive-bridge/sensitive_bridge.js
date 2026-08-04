#!/usr/bin/env node

import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import path from 'node:path';

import makeWASocket, {
  generateMessageIDV2,
  jidNormalizedUser,
  useMultiFileAuthState,
} from '@whiskeysockets/baileys';

import { SensitiveDeliveryTransport } from './delivery_core.js';
import { createSensitiveHttpHandler, listenLoopback } from './http_server.js';
import { SensitiveSocketLifecycle } from './lifecycle.js';
import { prepareSessionPaths, SessionPathError } from './session_paths.js';
import { computeTransportIdentity } from './transport_identity.js';
import { verifyLidBootstrap } from './provisioning_core.js';

const PACKAGE_ROOT = path.dirname(fileURLToPath(import.meta.url));
const CAPABILITY_ENV = 'HERMES_WHATSAPP_SENSITIVE_CAPABILITY';

export function parseCanonicalArgs(argv) {
  const accepted = new Set([
    '--port',
    '--session',
    '--ordinary-session',
    '--sensitive-account-jid',
    '--ordinary-account-jid',
  ]);
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!accepted.has(name) || value === undefined || values.has(name)) {
      throw new Error('invalid canonical sensitive bridge arguments');
    }
    values.set(name, value);
  }
  const port = Number(values.get('--port'));
  const sessionDir = values.get('--session');
  const ordinarySessionDir = values.get('--ordinary-session');
  const sensitiveAccountJid = values.get('--sensitive-account-jid');
  const ordinaryAccountJid = values.get('--ordinary-account-jid');
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('invalid sensitive bridge port');
  }
  if (typeof sessionDir !== 'string' || !path.isAbsolute(sessionDir)
      || path.normalize(sessionDir) !== sessionDir) {
    throw new Error('canonical absolute sensitive session path is required');
  }
  if (typeof ordinarySessionDir !== 'string' || !path.isAbsolute(ordinarySessionDir)
      || path.normalize(ordinarySessionDir) !== ordinarySessionDir) {
    throw new Error('canonical absolute ordinary session path is required');
  }
  if (typeof sensitiveAccountJid !== 'string'
      || !/^\d{1,32}@(s\.whatsapp\.net|lid)$/.test(sensitiveAccountJid)
      || jidNormalizedUser(sensitiveAccountJid) !== sensitiveAccountJid) {
    throw new Error('canonical sensitive account identity is required');
  }
  if (typeof ordinaryAccountJid !== 'string'
      || !/^\d{1,32}@(s\.whatsapp\.net|lid)$/.test(ordinaryAccountJid)
      || jidNormalizedUser(ordinaryAccountJid) !== ordinaryAccountJid) {
    throw new Error('canonical ordinary account identity is required');
  }
  if (sensitiveAccountJid === ordinaryAccountJid) {
    throw new Error('separate sensitive account required');
  }
  if (sensitiveAccountJid.split('@')[1] !== ordinaryAccountJid.split('@')[1]) {
    throw new Error('account identity namespace mismatch');
  }
  let sessionPathGuard;
  try {
    sessionPathGuard = prepareSessionPaths(sessionDir, ordinarySessionDir);
  } catch (error) {
    if (error instanceof SessionPathError
        && error.code === 'separate_sensitive_session_path_required') {
      throw new Error('separate sensitive session path required');
    }
    throw new Error('sensitive session path validation failed');
  }
  return Object.freeze({
    port,
    sessionDir,
    ordinarySessionDir,
    sessionPathGuard,
    sensitiveAccountJid,
    ordinaryAccountJid,
  });
}

export async function runSensitiveBridge({ argv = process.argv.slice(2), env = process.env } = {}) {
  const capability = env[CAPABILITY_ENV];
  if (typeof capability !== 'string' || Buffer.byteLength(capability, 'utf8') < 32
      || Buffer.byteLength(capability, 'utf8') > 512) {
    throw new Error('sensitive delivery is disabled');
  }
  const {
    port,
    sessionPathGuard,
    sensitiveAccountJid,
    ordinaryAccountJid,
  } = parseCanonicalArgs(argv);
  const transportIdentity = computeTransportIdentity(PACKAGE_ROOT);
  const transport = new SensitiveDeliveryTransport({
    runtimeId: `sensitive-${randomUUID()}`,
    ordinaryAccountJid,
    transportIdentity,
    canonicalizeJid: jidNormalizedUser,
    generateMessageId: (userId) => generateMessageIDV2(userId),
  });
  const server = http.createServer();
  let fatalCode = null;
  const lifecycle = new SensitiveSocketLifecycle({
    sessionPathGuard,
    expectedSensitiveAccountJid: sensitiveAccountJid,
    ordinaryAccountJid,
    useAuthState: async (sessionDir) => {
      const auth = await useMultiFileAuthState(sessionDir);
      if (auth?.state?.creds?.registered !== true) {
        throw new Error('provisioning_required');
      }
      const phoneJid = jidNormalizedUser(auth.state.creds?.me?.id || '');
      const storedLid = jidNormalizedUser(auth.state.creds?.me?.lid || '');
      const lid = await verifyLidBootstrap({
        auth,
        sock: {},
        phoneJid,
        canonicalizeJid: jidNormalizedUser,
      });
      if (!lid || (storedLid && lid !== storedLid)
          || ![phoneJid, storedLid].includes(sensitiveAccountJid)) {
        throw new Error('lid_bootstrap_incomplete');
      }
      return auth;
    },
    makeSocket: makeWASocket,
    canonicalizeJid: jidNormalizedUser,
    onBound: (connection) => transport.bindConnection(connection),
    onUnbound: (reason) => transport.unbindConnection(reason),
    onFatal: (code) => {
      fatalCode = code;
      transport.setEnabled(false);
      if (server.listening) server.close();
      process.exitCode = 1;
    },
  });
  const handler = createSensitiveHttpHandler({ capability, transport });
  server.on('request', handler);
  server.requestTimeout = 60_000;
  server.headersTimeout = 5_000;
  server.keepAliveTimeout = 1_000;
  server.maxRequestsPerSocket = 32;
  await lifecycle.start();
  if (fatalCode || lifecycle.fatalCode) throw new Error('sensitive bridge startup rejected');
  await listenLoopback(server, { port });

  let stopped = false;
  const stop = () => {
    if (stopped) return;
    stopped = true;
    transport.setEnabled(false);
    lifecycle.stop();
    server.close();
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  return Object.freeze({ server, lifecycle, transport, stop, transportIdentity });
}

if (path.resolve(process.argv[1] || '') === fileURLToPath(import.meta.url)) {
  runSensitiveBridge().catch(() => {
    process.exitCode = 1;
  });
}
