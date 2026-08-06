#!/usr/bin/env node

import { createHash } from 'node:crypto';
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
import { DurableReceiverReplayAuthority } from './replay_authority.js';
import { bindOwnedParentControl } from './parent_control.js';
import { prepareSessionPaths, SessionPathError } from './session_paths.js';
import { verifyLidBootstrap } from './provisioning_core.js';

const CAPABILITY_ENV = 'HERMES_WHATSAPP_SENSITIVE_CAPABILITY';
const LAUNCH_ENV = 'HERMES_INTERNAL_WHATSAPP_SENSITIVE_LAUNCH';

function exactObject(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
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

export function parseCanonicalArgs(argv, env = process.env) {
  const accepted = new Set(['--port']);
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
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('invalid sensitive bridge port');
  }
  let launch;
  try { launch = JSON.parse(env[LAUNCH_ENV]); } catch { throw new Error('sealed launch required'); }
  if (!exactObject(launch, [
    'version', 'process_generation', 'configured_account_jid',
    'profile', 'mode', 'replay', 'ordinary', 'sensitive',
  ]) || launch.version !== 2
      || typeof launch.process_generation !== 'string'
      || !/^[a-f0-9]{64}$/.test(launch.process_generation)
      || launch.profile !== 'juno'
      || launch.mode !== 'sensitive-outbound-only'
      || !exactObject(launch.replay, [
        'root', 'root_identity', 'anchor_path', 'authority_sha256',
      ])
      || !exactObject(launch.ordinary, [
        'adapter_generation', 'runtime_id', 'socket_generation',
        'account_phone_jid', 'account_lid_jid', 'session_path',
        'session_identity', 'manifest_sha256', 'source_sha256',
        'launcher_sha256',
      ])
      || !exactObject(launch.sensitive, [
        'session_path', 'session_identity', 'credential_identity',
        'device_identity_sha256', 'credential_tree_sha256',
        'account_phone_jid', 'account_lid_jid',
      ])) {
    throw new Error('sealed launch invalid');
  }
  const sessionDir = launch.sensitive.session_path;
  const ordinarySessionDir = launch.ordinary.session_path;
  const sensitiveAccountJid = launch.configured_account_jid;
  const ordinaryAccountJid = launch.configured_account_jid;
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
  if (sensitiveAccountJid !== ordinaryAccountJid) {
    throw new Error('same canonical account required');
  }
  if (![launch.ordinary.account_phone_jid, launch.ordinary.account_lid_jid]
    .includes(ordinaryAccountJid)) {
    throw new Error('sealed account topology mismatch');
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
    launch,
    replayIdentity: Object.freeze({ ...launch.replay }),
  });
}

export async function runSensitiveBridge({
  argv = process.argv.slice(2),
  env = process.env,
  transportIdentity,
  testProviderSeam = null,
} = {}) {
  // This is a dedicated process. Keep every subsequently created auth/session
  // artifact owner-only even if the service manager inherited a looser mask.
  process.umask(0o077);
  const capability = env[CAPABILITY_ENV];
  if (typeof capability !== 'string' || Buffer.byteLength(capability, 'utf8') < 32
      || Buffer.byteLength(capability, 'utf8') > 512) {
    throw new Error('sensitive delivery is disabled');
  }
  const {
    port,
    sessionDir,
    ordinarySessionDir,
    sensitiveAccountJid,
    ordinaryAccountJid,
    launch,
    replayIdentity,
  } = parseCanonicalArgs(argv, env);
  // Replay authority is opened and validated before auth state, socket, HTTP
  // publication, or any provider object is constructed.
  const replayAuthority = new DurableReceiverReplayAuthority(replayIdentity);
  // Activation requires two independently generated linked-device auth
  // artifacts, not merely two different path strings.
  const sessionPathGuard = prepareSessionPaths(sessionDir, ordinarySessionDir, {
    requireDistinctCredentials: true,
  });
  const sessionTopology = sessionPathGuard.topologyEvidence();
  if (sessionTopology.ordinary.session_path !== launch.ordinary.session_path
      || sessionTopology.ordinary.session_identity !== launch.ordinary.session_identity
      || sessionTopology.ordinary.account_phone_jid !== launch.ordinary.account_phone_jid
      || sessionTopology.ordinary.account_lid_jid !== launch.ordinary.account_lid_jid
      || sessionTopology.sensitive.session_path !== launch.sensitive.session_path
      || sessionTopology.sensitive.session_identity !== launch.sensitive.session_identity
      || sessionTopology.sensitive.credential_identity
        !== launch.sensitive.credential_identity
      || sessionTopology.sensitive.device_identity_sha256
        !== launch.sensitive.device_identity_sha256
      || sessionTopology.sensitive.credential_tree_sha256
        !== launch.sensitive.credential_tree_sha256
      || sessionTopology.sensitive.account_phone_jid
        !== launch.sensitive.account_phone_jid
      || sessionTopology.sensitive.account_lid_jid
        !== launch.sensitive.account_lid_jid
      || ![sessionTopology.sensitive.account_phone_jid,
        sessionTopology.sensitive.account_lid_jid].includes(sensitiveAccountJid)) {
    throw new Error('sealed topology mismatch');
  }
  if (!transportIdentity || typeof transportIdentity !== 'object'
      || !/^[a-f0-9]{64}$/.test(String(transportIdentity.manifest_sha256 || ''))) {
    throw new Error('verified sensitive transport identity is required');
  }
  const transport = new SensitiveDeliveryTransport({
    runtimeId: `sensitive-${launch.process_generation}`,
    processGeneration: launch.process_generation,
    topologyIdentity: Object.freeze({
      ordinary: Object.freeze({ ...launch.ordinary }),
      sensitive: sessionTopology.sensitive,
      topology_sha256: createHash('sha256').update(JSON.stringify(stableValue({
        ordinary: launch.ordinary,
        sensitive: sessionTopology.sensitive,
      }))).digest('hex'),
    }),
    ordinaryAccountJid,
    transportIdentity,
    canonicalizeJid: jidNormalizedUser,
    generateMessageId: (userId) => generateMessageIDV2(userId),
    replayAuthority,
  });
  const server = http.createServer();
  let fatalCode = null;
  let stopped = false;
  let lifecycle = null;
  let parentAlive = true;
  const closeAuthority = () => {
    if (stopped) return;
    stopped = true;
    transport.setEnabled(false);
    lifecycle?.stop();
    try { server.closeAllConnections?.(); } catch {}
    try { server.close(); } catch {}
  };
  const parentLost = () => {
    if (!parentAlive) return;
    parentAlive = false;
    closeAuthority();
    process.exitCode = 1;
    setImmediate(() => process.exit(1));
  };
  const parentControl = bindOwnedParentControl(parentLost);
  lifecycle = new SensitiveSocketLifecycle({
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
    makeSocket: testProviderSeam?.makeSocket || makeWASocket,
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
  if (!parentAlive || !parentControl.live() || fatalCode || lifecycle.fatalCode) {
    closeAuthority();
    throw new Error('sensitive bridge startup rejected');
  }
  await listenLoopback(server, { port });
  if (!parentAlive || !parentControl.live()) {
    closeAuthority();
    throw new Error('sensitive bridge parent unavailable');
  }

  const stop = () => {
    closeAuthority();
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  return Object.freeze({ server, lifecycle, transport, stop, transportIdentity });
}
