import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  createBoundedMessageStore,
  extractBridgeEvent,
} from './bridge_helpers.js';
import {
  REGISTERED_INBOUND_PROVENANCE,
  registerInboundMessageHandler,
} from './inbound_producer.js';

class FakeEmitter {
  constructor() { this.handlers = new Map(); }
  on(name, handler) { this.handlers.set(name, handler); }
  async emit(name, value) {
    const handler = this.handlers.get(name);
    if (!handler) throw new Error(`missing handler: ${name}`);
    return handler(value);
  }
}

function socket(account = '33333333333:19@s.whatsapp.net') {
  return { user: { id: account, lid: '44444444444@lid' }, ev: new FakeEmitter() };
}

function message({
  id = 'JUNO-PROVIDER-MESSAGE-1',
  sender = '22222222222@s.whatsapp.net',
  fromMe = false,
  text = 'read newest inbox message',
} = {}) {
  return {
    key: { id, remoteJid: sender, participant: sender, fromMe },
    pushName: 'Trusted Person',
    messageTimestamp: 1_786_000_000,
    message: { conversation: text },
  };
}

function register({
  emittingSocket,
  activeSocket,
  queue = [],
  extractEvent,
  mode = 'bot',
  forwardOwnerMessages = true,
  recentlySentIds = new Set(),
  senderCompanionFenceActive = false,
  handlePollUpdate = null,
} = {}) {
  const store = createBoundedMessageStore();
  registerInboundMessageHandler({
    emittingSocket,
    isActiveSocket: candidate => candidate === activeSocket.current,
    producerDependencies: {
      // A mismatching independent authority is deliberately ignored: the
      // production API has no socketUser parameter.
      socketUser: { id: '99999999999@s.whatsapp.net' },
      mode, dmPolicy: 'allowlist', forwardOwnerMessages,
      recentlySentIds, senderCompanionFenceActive,
      allowlistMatches: id => new Set([
        '11111111111@s.whatsapp.net',
        '22222222222@s.whatsapp.net',
      ]).has(id),
      extractEvent: extractEvent || extractBridgeEvent,
      cacheDirs: {}, replyPrefix: '', messageStore: store,
      messageQueue: queue, maxQueueSize: 100,
      handlePollUpdate,
    },
  });
  return { queue, store };
}

test('generic self-chat fromMe event traverses extraction and queues', async () => {
  const emittingSocket = socket();
  const activeSocket = { current: emittingSocket };
  let extractions = 0;
  const { queue } = register({
    emittingSocket,
    activeSocket,
    mode: 'self-chat',
    extractEvent: async args => {
      extractions += 1;
      return extractBridgeEvent(args);
    },
  });
  const outcome = await emittingSocket.ev.emit('messages.upsert', {
    type: 'append',
    messages: [message({
      id: 'GENERIC-SELF-CHAT-1',
      sender: '33333333333@s.whatsapp.net',
      fromMe: true,
      text: 'ordinary self-chat input',
    })],
  });
  assert.equal(outcome.action, 'queued');
  assert.equal(extractions, 1);
  assert.deepEqual(queue.map(item => item.messageId), ['GENERIC-SELF-CHAT-1']);
  assert.equal(queue[0].fromOwner, false);
});

test('generic bot forwards owner-typed fromMe and suppresses tracked agent echo', async () => {
  const emittingSocket = socket();
  const activeSocket = { current: emittingSocket };
  const tracked = new Set(['GENERIC-AGENT-ECHO-1']);
  const { queue } = register({
    emittingSocket,
    activeSocket,
    recentlySentIds: tracked,
  });
  const owner = await emittingSocket.ev.emit('messages.upsert', {
    type: 'notify', messages: [message({
      id: 'GENERIC-OWNER-TYPED-1',
      sender: '11111111111@s.whatsapp.net',
      fromMe: true,
      text: 'owner handover reply',
    })],
  });
  const echo = await emittingSocket.ev.emit('messages.upsert', {
    type: 'notify', messages: [message({
      id: 'GENERIC-AGENT-ECHO-1',
      sender: '11111111111@s.whatsapp.net',
      fromMe: true,
      text: 'tracked agent response',
    })],
  });
  assert.equal(owner.action, 'queued');
  assert.equal(queue.length, 1);
  assert.equal(queue[0].fromOwner, true);
  assert.deepEqual(echo, { action: 'ignored', reason: 'drop_echo' });
});

test('exact production registration extracts, gates, stamps socket, and queues', async () => {
  const emittingSocket = socket();
  const activeSocket = { current: emittingSocket };
  const { queue, store } = register({ emittingSocket, activeSocket });
  const outcome = await emittingSocket.ev.emit('messages.upsert', {
    type: 'notify', messages: [message()],
  });
  assert.equal(outcome.action, 'queued');
  assert.equal(queue.length, 1);
  assert.equal(store.get('JUNO-PROVIDER-MESSAGE-1').key.id, 'JUNO-PROVIDER-MESSAGE-1');
  assert.deepEqual({
    messageId: queue[0].messageId,
    accountId: queue[0].accountId,
    senderId: queue[0].senderId,
    chatId: queue[0].chatId,
    fromOwner: queue[0].fromOwner,
    inboundProvenance: queue[0].inboundProvenance,
  }, {
    messageId: 'JUNO-PROVIDER-MESSAGE-1',
    accountId: '33333333333@s.whatsapp.net',
    senderId: '22222222222@s.whatsapp.net',
    chatId: '22222222222@s.whatsapp.net',
    fromOwner: false,
    inboundProvenance: REGISTERED_INBOUND_PROVENANCE,
  });
});

test('all authenticated sender-companion upsert shapes are fenced before plaintext surfaces', async () => {
  const sentinel = 'PRIVATE-SENDER-COMPANION-SENTINEL';
  const shapes = [
    { type: 'notify', requestId: undefined, label: 'live sender fan-out' },
    { type: 'append', requestId: undefined, label: 'offline sender fan-out' },
    { type: 'append', requestId: 'pdo-retry-1', label: 'phone retry/PDO append' },
    { type: 'notify', requestId: 'provider-retry-2', label: 'retry notify' },
  ];
  for (const shape of shapes) {
    const emittingSocket = socket();
    const activeSocket = { current: emittingSocket };
    const queue = [];
    const debug = [];
    let extractions = 0;
    let polls = 0;
    const store = createBoundedMessageStore();
    registerInboundMessageHandler({
      emittingSocket,
      isActiveSocket: candidate => candidate === activeSocket.current,
      emitDebugEvent: value => debug.push(value),
      producerDependencies: {
        mode: 'bot', dmPolicy: 'allowlist', forwardOwnerMessages: true,
        senderCompanionFenceActive: true,
        recentlySentIds: new Set(), allowlistMatches: () => true,
        extractEvent: async () => {
          extractions += 1;
          throw new Error(`extractor received ${sentinel}`);
        },
        cacheDirs: {}, replyPrefix: '', messageStore: store,
        messageQueue: queue, maxQueueSize: 100,
        debugEnabled: true,
        handlePollUpdate: async () => { polls += 1; return false; },
      },
    });
    const outcome = await emittingSocket.ev.emit('messages.upsert', {
      type: shape.type,
      ...(shape.requestId ? { requestId: shape.requestId } : {}),
      messages: [message({
        id: `SENDER-${shape.type}-${shape.requestId || 'direct'}`,
        sender: '11111111111@s.whatsapp.net',
        fromMe: true,
        text: sentinel,
      })],
    });
    assert.deepEqual(outcome, {
      action: 'ignored', reason: 'sender_companion_fenced',
    }, shape.label);
    assert.equal(extractions, 0, shape.label);
    assert.equal(polls, 0, shape.label);
    assert.deepEqual(queue, [], shape.label);
    assert.equal(store.get(`SENDER-${shape.type}-${shape.requestId || 'direct'}`), null, shape.label);
    assert.equal(JSON.stringify(debug).includes(sentinel), false, shape.label);
    assert.deepEqual(debug, [], shape.label);
  }
});

test('concurrent ordinary inbound and sensitive sender echo cannot cross-suppress', async () => {
  const emittingSocket = socket();
  const activeSocket = { current: emittingSocket };
  const { queue } = register({
    emittingSocket, activeSocket, senderCompanionFenceActive: true,
  });
  const [ordinary, sensitive] = await Promise.all([
    emittingSocket.ev.emit('messages.upsert', {
      type: 'notify', messages: [message({ id: 'ORDINARY-CONCURRENT', fromMe: false })],
    }),
    emittingSocket.ev.emit('messages.upsert', {
      type: 'notify', messages: [message({
        id: 'SENSITIVE-CONCURRENT', fromMe: true,
        text: 'PRIVATE-CONCURRENT-SENTINEL',
      })],
    }),
  ]);
  assert.equal(ordinary.action, 'queued');
  assert.deepEqual(sensitive, {
    action: 'ignored', reason: 'sender_companion_fenced',
  });
  assert.deepEqual(queue.map(item => item.messageId), ['ORDINARY-CONCURRENT']);
});

test('sender-companion events are fenced regardless of owner allowlist', async () => {
  const emittingSocket = socket();
  const activeSocket = { current: emittingSocket };
  const { queue } = register({
    emittingSocket, activeSocket, senderCompanionFenceActive: true,
  });
  const owner = await emittingSocket.ev.emit('messages.upsert', {
    type: 'notify', messages: [message({
      id: 'JUNO-OWNER-PROVIDER-MESSAGE-1',
      sender: '11111111111@s.whatsapp.net', fromMe: true,
    })],
  });
  assert.deepEqual(owner, { action: 'ignored', reason: 'sender_companion_fenced' });
  const rejected = await emittingSocket.ev.emit('messages.upsert', {
    type: 'notify', messages: [message({
      id: 'JUNO-OWNER-PROVIDER-MESSAGE-2',
      sender: '99999999999@s.whatsapp.net', fromMe: true,
    })],
  });
  assert.equal(rejected.reason, 'sender_companion_fenced');
  assert.equal(queue.length, 0);
});

test('replaced socket generation rejects late old-socket upserts', async () => {
  const oldSocket = socket('33333333333:19@s.whatsapp.net');
  const activeSocket = { current: oldSocket };
  const { queue } = register({ emittingSocket: oldSocket, activeSocket });
  activeSocket.current = socket('55555555555:7@s.whatsapp.net');
  const outcome = await oldSocket.ev.emit('messages.upsert', {
    type: 'notify', messages: [message()],
  });
  assert.equal(outcome.reason, 'stale_emitting_socket');
  assert.equal(queue.length, 0);
});

test('socket replacement during extraction cannot cross-attribute or queue', async () => {
  const oldSocket = socket('33333333333:19@s.whatsapp.net');
  const activeSocket = { current: oldSocket };
  let release;
  const paused = new Promise(resolve => { release = resolve; });
  const { queue } = register({
    emittingSocket: oldSocket,
    activeSocket,
    extractEvent: async args => {
      const event = await extractBridgeEvent(args);
      await paused;
      return event;
    },
  });
  const pending = oldSocket.ev.emit('messages.upsert', {
    type: 'notify', messages: [message()],
  });
  activeSocket.current = socket('55555555555:7@s.whatsapp.net');
  release();
  const outcome = await pending;
  assert.equal(outcome.reason, 'stale_emitting_socket');
  assert.equal(queue.length, 0);
});

test('actual startSocket production body registers the authoritative callback', async () => {
  const previous = new Map([
    ['WHATSAPP_MODE', process.env.WHATSAPP_MODE],
    ['WHATSAPP_DM_POLICY', process.env.WHATSAPP_DM_POLICY],
    ['WHATSAPP_ALLOWED_USERS', process.env.WHATSAPP_ALLOWED_USERS],
  ]);
  process.env.WHATSAPP_MODE = 'bot';
  process.env.WHATSAPP_DM_POLICY = 'allowlist';
  process.env.WHATSAPP_ALLOWED_USERS = '22222222222@s.whatsapp.net';
  try {
    const bridge = await import(`./bridge.js?start-socket-authority=${Date.now()}`);
    const connectionSocket = socket();
    await bridge.startSocket({
      useAuthState: async () => ({
        state: { creds: { registered: true, me: { id: connectionSocket.user.id } } },
        saveCreds: async () => {},
      }),
      verifyBootstrap: async () => connectionSocket.user.lid,
      resolveVersion: async () => [2, 3000, 0],
      createSocket: () => connectionSocket,
      canonicalizeJid: value => String(value).replace(/:\d+@/, '@'),
    });
    const outcome = await connectionSocket.ev.emit('messages.upsert', {
      type: 'notify', messages: [message()],
    });
    const queue = bridge.takeProductionInboundMessages();
    assert.equal(outcome.action, 'queued');
    assert.equal(queue.length, 1);
    assert.equal(queue[0].messageId, 'JUNO-PROVIDER-MESSAGE-1');
    assert.equal(queue[0].inboundProvenance, REGISTERED_INBOUND_PROVENANCE);
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});
