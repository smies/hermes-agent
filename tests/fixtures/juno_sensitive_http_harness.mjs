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

const account = '33333333333@s.whatsapp.net';
const ordinary = account;
const processGeneration = 'b'.repeat(64);
const runtime = `sensitive-${processGeneration}`;
const epoch = `vertical-epoch-${process.pid}`;
const identity = await verifySensitiveTransport();
const capture = process.env.JUNO_TEST_DELIVERY_CAPTURE;
const capability = process.env.JUNO_TEST_SENSITIVE_CAPABILITY;
const topologyIdentity = {
  ordinary: {
    adapter_generation: 'a'.repeat(64), runtime_id: 'ordinary-vertical-runtime',
    socket_generation: 1, account_phone_jid: account,
    account_lid_jid: '44444444444@lid', session_path: '/synthetic/ordinary',
    session_identity: '1:2', manifest_sha256: 'c'.repeat(64),
    source_sha256: 'd'.repeat(64), launcher_sha256: 'e'.repeat(64),
  },
  sensitive: {
    session_path: '/synthetic/sensitive', session_identity: '1:3',
    credential_identity: '1:4', device_identity_sha256: 'f'.repeat(64),
    credential_tree_sha256: '0'.repeat(64), account_phone_jid: account,
    account_lid_jid: '44444444444@lid',
  },
};
topologyIdentity.topology_sha256 = createHash('sha256').update(JSON.stringify({
  ordinary: Object.fromEntries(Object.entries(topologyIdentity.ordinary).sort()),
  sensitive: Object.fromEntries(Object.entries(topologyIdentity.sensitive).sort()),
})).digest('hex');
const ev = new EventEmitter();
const socket = {
  user: { id: '33333333333:4@s.whatsapp.net' },
  ev,
  async sendMessage(chat, content, options) {
    appendFileSync(capture, `${JSON.stringify({
      chat, text: content.text, messageId: options.messageId,
    })}\n`, { encoding: 'utf8', mode: 0o600 });
    return { key: { id: options.messageId, remoteJid: chat, fromMe: true } };
  },
};
const canonicalizeJid = (value) => String(value).replace(/:\d+@/, '@');
const transport = new SensitiveDeliveryTransport({
  runtimeId: runtime,
  processGeneration,
  topologyIdentity,
  ordinaryAccountJid: ordinary,
  transportIdentity: identity,
  canonicalizeJid,
  generateMessageId: () => '3EB0ABCDEF0123456789AB',
});
transport.bindConnection({ socket, sock: socket, accountJid: account, epoch });

const server = http.createServer(createSensitiveHttpHandler({ capability, transport }));
try {
  await listenLoopback(server, { port: 0 });
} catch (error) {
  if (['EACCES', 'EPERM'].includes(error?.code) && error?.syscall === 'listen') {
    process.stderr.write(`JUNO_SOCKET_BIND_DENIED:${error.code}:listen\n`);
    process.exit(73);
  }
  process.stderr.write('JUNO_HARNESS_STARTUP_FAILURE\n');
  process.exit(74);
}
process.stdout.write(`${JSON.stringify({ port: server.address().port, identity })}\n`);

const stop = () => {
  transport.setEnabled(false);
  server.close(() => process.exit(0));
};
process.once('SIGTERM', stop);
process.once('SIGINT', stop);
