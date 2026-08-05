import { EventEmitter } from 'node:events';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const sessionArgument = process.argv.indexOf('--session');
if (sessionArgument >= 0 && process.argv[sessionArgument + 1]) {
  process.env.WHATSAPP_SESSION_PATH = process.argv[sessionArgument + 1];
}
const bridgeUrl = pathToFileURL(process.env.JUNO_BRIDGE_MODULE);
const bridge = await import(bridgeUrl);
if (process.env.HERMES_INTERNAL_WHATSAPP_FENCE_PROFILE !== undefined
    || process.env.HERMES_INTERNAL_WHATSAPP_FENCE_KEY !== undefined) {
  // Run the real, copied launcher verification before exercising fenced
  // health.  The temporary listen replacement prevents launcher startup from
  // opening a socket or scheduling a production Baileys connection, while
  // still installing the exact verified transport identity used by /health.
  const verifiedLauncher = await import(new URL('./launcher.js', bridgeUrl));
  const productionListen = bridge.bridgeHttpApp.listen;
  bridge.bridgeHttpApp.listen = () => ({});
  try {
    await verifiedLauncher.launchOrdinaryBridge(process.argv.slice(2));
  } finally {
    bridge.bridgeHttpApp.listen = productionListen;
  }
}
const ev = new EventEmitter();
const sentMessages = [];
const socket = {
  user: { id: '33333333333:19@s.whatsapp.net', lid: '44444444444@lid' },
  ev,
  updateMediaMessage: async () => {},
  async sendMessage(chatId, content) {
    sentMessages.push({ chatId, text: content?.text || '' });
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
const originalConsoleLog = console.log;
console.log = () => {};
try {
  ev.emit('connection.update', { connection: 'open' });
} finally {
  console.log = originalConsoleLog;
}

function invokeGetRoute(route) {
  return new Promise((resolve, reject) => {
    const headers = new Map();
    let body = '';
    const request = {
      method: 'GET',
      url: route,
      originalUrl: route,
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

const inProcessOnly = process.argv.includes('--in-process-only');
let server = null;
if (inProcessOnly) {
  process.stdout.write(`${JSON.stringify({
    ready: true,
    transport: 'in_process',
    port: null,
    callbackRegistered: ev.listenerCount('messages.upsert') === 1,
  })}\n`);
} else {
  server = bridge.bridgeHttpApp.listen(0, '127.0.0.1', () => {
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
}

const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
const stop = () => {
  if (server?.listening) server.close(() => process.exit(0));
  else process.exit(0);
};
process.once('SIGTERM', stop);
process.once('SIGINT', stop);
for await (const line of input) {
  if (!line.trim()) continue;
  const value = JSON.parse(line);
  if (value.command === 'request') {
    if (!['/health', '/messages'].includes(value.url)) {
      throw new Error('unsupported in-process route');
    }
    const response = await invokeGetRoute(value.url);
    process.stdout.write(`${JSON.stringify({
      request: true,
      url: value.url,
      status: response.status,
      body: JSON.parse(response.body),
    })}\n`);
    continue;
  }
  if (value.command === 'sent') {
    process.stdout.write(`${JSON.stringify({ sent: [...sentMessages] })}\n`);
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

if (server?.listening) {
  await new Promise(resolve => server.close(resolve));
}
process.exit(0);
