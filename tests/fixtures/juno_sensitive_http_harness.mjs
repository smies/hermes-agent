import { EventEmitter } from 'node:events';
import { createHash } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import http from 'node:http';

import { SensitiveDeliveryTransport } from '../../scripts/whatsapp-sensitive-bridge/delivery_core.js';
import {
  createSensitiveHttpHandler,
  listenLoopback,
} from '../../scripts/whatsapp-sensitive-bridge/http_server.js';
import { verifySensitiveTransport } from '../../scripts/whatsapp-sensitive-bridge/launcher.js';
import { prepareSessionPaths } from '../../scripts/whatsapp-sensitive-bridge/session_paths.js';

const CAPABILITY_ENV = 'HERMES_WHATSAPP_SENSITIVE_CAPABILITY';
const LAUNCH_ENV = 'HERMES_INTERNAL_WHATSAPP_SENSITIVE_LAUNCH';

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(
      Object.keys(value).sort().map(key => [key, stableValue(value[key])]),
    );
  }
  return value;
}

function exactObject(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function sealedLaunch() {
  let launch;
  try { launch = JSON.parse(process.env[LAUNCH_ENV]); } catch { throw new Error('sealed launch required'); }
  if (!exactObject(launch, [
    'version', 'process_generation', 'configured_account_jid', 'ordinary', 'sensitive',
  ]) || launch.version !== 1
      || typeof launch.process_generation !== 'string'
      || !/^[a-f0-9]{64}$/.test(launch.process_generation)
      || !exactObject(launch.ordinary, [
        'adapter_generation', 'runtime_id', 'socket_generation',
        'account_phone_jid', 'account_lid_jid', 'session_path',
        'session_identity', 'manifest_sha256', 'source_sha256', 'launcher_sha256',
      ])
      || !exactObject(launch.sensitive, [
        'session_path', 'session_identity', 'credential_identity',
        'device_identity_sha256', 'credential_tree_sha256',
        'account_phone_jid', 'account_lid_jid',
      ])) {
    throw new Error('sealed launch invalid');
  }
  const accountAliases = new Set([
    launch.ordinary.account_phone_jid, launch.ordinary.account_lid_jid,
  ]);
  if (!accountAliases.has(launch.configured_account_jid)) {
    throw new Error('sealed account topology mismatch');
  }
  return launch;
}

function requestedPort() {
  const argv = process.argv.slice(2);
  if (argv.length !== 2 || argv[0] !== '--port' || !/^\d{1,5}$/.test(argv[1])) {
    throw new Error('canonical requested port required');
  }
  const port = Number(argv[1]);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('canonical requested port required');
  }
  return port;
}

const launch = sealedLaunch();
const capability = process.env[CAPABILITY_ENV];
if (typeof capability !== 'string' || Buffer.byteLength(capability, 'utf8') < 32
    || Buffer.byteLength(capability, 'utf8') > 512) {
  throw new Error('sensitive capability required');
}
const capture = process.env.JUNO_TEST_DELIVERY_CAPTURE;
if (typeof capture !== 'string' || !capture) throw new Error('delivery capture required');

const sessionGuard = prepareSessionPaths(
  launch.sensitive.session_path,
  launch.ordinary.session_path,
  { requireDistinctCredentials: true },
);
const observed = sessionGuard.topologyEvidence();
const ordinaryMatches = observed.ordinary.session_path === launch.ordinary.session_path
  && observed.ordinary.session_identity === launch.ordinary.session_identity
  && observed.ordinary.account_phone_jid === launch.ordinary.account_phone_jid
  && observed.ordinary.account_lid_jid === launch.ordinary.account_lid_jid;
const sensitiveMatches = Object.entries(launch.sensitive)
  .every(([name, value]) => observed.sensitive[name] === value);
if (!ordinaryMatches || !sensitiveMatches) throw new Error('sealed topology mismatch');

const identity = await verifySensitiveTransport();
const topologyIdentity = {
  ordinary: Object.freeze({ ...launch.ordinary }),
  sensitive: observed.sensitive,
};
if (process.env.JUNO_TEST_SENSITIVE_STALE_TOPOLOGY === '1') {
  topologyIdentity.ordinary = Object.freeze({
    ...topologyIdentity.ordinary,
    socket_generation: topologyIdentity.ordinary.socket_generation + 1,
  });
}
topologyIdentity.topology_sha256 = createHash('sha256').update(JSON.stringify(stableValue({
  ordinary: topologyIdentity.ordinary,
  sensitive: topologyIdentity.sensitive,
}))).digest('hex');
const reportedGeneration = process.env.JUNO_TEST_SENSITIVE_STALE_PROCESS_GENERATION === '1'
  ? '0'.repeat(64) : launch.process_generation;
const reportedCapability = process.env.JUNO_TEST_SENSITIVE_STALE_CAPABILITY === '1'
  ? `${capability}-stale` : capability;
const runtime = `sensitive-${reportedGeneration}`;
const epoch = `vertical-epoch-${process.pid}`;
const ev = new EventEmitter();
const socket = {
  user: { id: launch.sensitive.account_phone_jid },
  ev,
  async sendMessage(chat, content, options) {
    sessionGuard.revalidate();
    appendFileSync(capture, `${JSON.stringify({
      chat, text: content.text, messageId: options.messageId,
    })}\n`, { encoding: 'utf8', mode: 0o600 });
    return { key: { id: options.messageId, remoteJid: chat, fromMe: true } };
  },
};
const canonicalizeJid = value => String(value).replace(/:\d+@/, '@');
const transport = new SensitiveDeliveryTransport({
  runtimeId: runtime,
  processGeneration: reportedGeneration,
  topologyIdentity,
  ordinaryAccountJid: launch.configured_account_jid,
  transportIdentity: identity,
  canonicalizeJid,
  generateMessageId: () => '3EB0ABCDEF0123456789AB',
});
transport.bindConnection({
  socket, sock: socket,
  accountJid: launch.sensitive.account_phone_jid,
  epoch,
});

const server = http.createServer(createSensitiveHttpHandler({
  capability: reportedCapability,
  transport,
}));
try {
  await listenLoopback(server, { port: requestedPort() });
} catch (error) {
  if (['EACCES', 'EPERM'].includes(error?.code) && error?.syscall === 'listen') {
    process.stderr.write(`JUNO_SOCKET_BIND_DENIED:${error.code}:listen\n`);
    process.exit(73);
  }
  process.stderr.write('JUNO_HARNESS_STARTUP_FAILURE\n');
  process.exit(74);
}

const stop = () => {
  transport.setEnabled(false);
  server.close(() => process.exit(0));
};
process.once('SIGTERM', stop);
process.once('SIGINT', stop);
