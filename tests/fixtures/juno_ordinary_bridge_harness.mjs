import { EventEmitter } from 'node:events';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const bridge = await import(pathToFileURL(process.env.JUNO_BRIDGE_MODULE));
const ev = new EventEmitter();
const socket = {
  user: { id: '33333333333:19@s.whatsapp.net', lid: '44444444444@lid' },
  ev,
  updateMediaMessage: async () => {},
  async sendMessage(chatId) {
    return {
      key: {
        id: `OFFLINE-${Date.now()}`,
        remoteJid: chatId,
        fromMe: true,
      },
    };
  },
  async sendPresenceUpdate() {},
  async readMessages() {},
};

await bridge.startSocket({
  useAuthState: async () => ({
    state: { creds: { registered: true, me: { id: socket.user.id } } },
    saveCreds: async () => {},
  }),
  verifyBootstrap: async () => socket.user.lid,
  resolveVersion: async () => [2, 3000, 0],
  createSocket: () => socket,
  canonicalizeJid: value => String(value).replace(/:\d+@/, '@'),
});

function invokeMessagesRoute() {
  return new Promise((resolve, reject) => {
    const headers = new Map();
    let body = '';
    const request = {
      method: 'GET',
      url: '/messages',
      originalUrl: '/messages',
      headers: { host: '127.0.0.1' },
      connection: {},
      socket: {},
    };
    const response = {
      statusCode: 200,
      setHeader(name, value) { headers.set(String(name).toLowerCase(), value); },
      getHeader(name) { return headers.get(String(name).toLowerCase()); },
      removeHeader(name) { headers.delete(String(name).toLowerCase()); },
      write(value) { body += Buffer.from(value).toString('utf8'); return true; },
      end(value) {
        if (value) body += Buffer.from(value).toString('utf8');
        resolve({ status: this.statusCode, body });
      },
      on() { return this; },
      once() { return this; },
      emit() { return false; },
    };
    bridge.bridgeHttpApp.handle(request, response, reject);
  });
}

const server = bridge.bridgeHttpApp.listen(0, '127.0.0.1', () => {
  process.stdout.write(`${JSON.stringify({
    ready: true,
    transport: 'loopback',
    port: server.address().port,
    callbackRegistered: ev.listenerCount('messages.upsert') === 1,
  })}\n`);
});
server.once('error', error => {
  if (['EACCES', 'EPERM'].includes(error?.code) && error?.syscall === 'listen') {
    process.stderr.write(`JUNO_SOCKET_BIND_DENIED:${error.code}:listen\n`);
    process.stdout.write(`${JSON.stringify({
      ready: true,
      transport: 'in_process',
      port: null,
      callbackRegistered: ev.listenerCount('messages.upsert') === 1,
    })}\n`);
    return;
  }
  process.stderr.write('JUNO_HARNESS_STARTUP_FAILURE\n');
  process.exit(74);
});

const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
const stop = () => server.close(() => process.exit(0));
process.once('SIGTERM', stop);
process.once('SIGINT', stop);
for await (const line of input) {
  if (!line.trim()) continue;
  const value = JSON.parse(line);
  if (value.command === 'poll') {
    const response = await invokeMessagesRoute();
    process.stdout.write(`${JSON.stringify({
      poll: true,
      status: response.status,
      messages: JSON.parse(response.body),
    })}\n`);
    continue;
  }
  const sender = value.sender;
  const outcome = await Promise.all(ev.listeners('messages.upsert').map(handler => handler({
    type: 'notify',
    messages: [{
      key: {
        id: value.messageId,
        remoteJid: sender,
        participant: sender,
        fromMe: false,
      },
      pushName: 'Synthetic User',
      messageTimestamp: 1_786_000_000,
      message: { conversation: value.text },
    }],
  })));
  process.stdout.write(`${JSON.stringify({
    messageId: value.messageId,
    callbackCount: ev.listenerCount('messages.upsert'),
    outcome: outcome[0] || null,
  })}\n`);
}

if (server.listening) {
  await new Promise(resolve => server.close(resolve));
}
process.exit(0);
