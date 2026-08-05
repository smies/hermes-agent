import { EventEmitter } from 'node:events';
import { appendFileSync } from 'node:fs';
import http from 'node:http';

import { SensitiveDeliveryTransport } from '../../scripts/whatsapp-sensitive-bridge/delivery_core.js';
import {
  createSensitiveHttpHandler,
  listenLoopback,
} from '../../scripts/whatsapp-sensitive-bridge/http_server.js';

const account = '55555555555@s.whatsapp.net';
const ordinary = '33333333333@s.whatsapp.net';
const runtime = `vertical-runtime-${process.pid}`;
const epoch = `vertical-epoch-${process.pid}`;
const identity = JSON.parse(process.env.JUNO_TEST_TRANSPORT_IDENTITY);
const capture = process.env.JUNO_TEST_DELIVERY_CAPTURE;
const capability = process.env.JUNO_TEST_SENSITIVE_CAPABILITY;
const ev = new EventEmitter();
const socket = {
  user: { id: '55555555555:4@s.whatsapp.net' },
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
process.stdout.write(`${JSON.stringify({ port: server.address().port })}\n`);

const stop = () => {
  transport.setEnabled(false);
  server.close(() => process.exit(0));
};
process.once('SIGTERM', stop);
process.once('SIGINT', stop);
