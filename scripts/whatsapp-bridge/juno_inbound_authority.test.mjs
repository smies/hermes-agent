import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
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

function register({ emittingSocket, activeSocket, queue = [], extractEvent } = {}) {
  const store = createBoundedMessageStore();
  registerInboundMessageHandler({
    emittingSocket,
    isActiveSocket: candidate => candidate === activeSocket.current,
    producerDependencies: {
      // A mismatching independent authority is deliberately ignored: the
      // production API has no socketUser parameter.
      socketUser: { id: '99999999999@s.whatsapp.net' },
      mode: 'bot', dmPolicy: 'allowlist', forwardOwnerMessages: true,
      recentlySentIds: new Set(),
      allowlistMatches: id => new Set([
        '11111111111@s.whatsapp.net',
        '22222222222@s.whatsapp.net',
      ]).has(id),
      extractEvent: extractEvent || extractBridgeEvent,
      cacheDirs: {}, replyPrefix: '', messageStore: store,
      messageQueue: queue, maxQueueSize: 100,
    },
  });
  return { queue, store };
}

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

test('owner gate and provider message id are enforced by registered callback', async () => {
  const emittingSocket = socket();
  const activeSocket = { current: emittingSocket };
  const { queue } = register({ emittingSocket, activeSocket });
  const owner = await emittingSocket.ev.emit('messages.upsert', {
    type: 'notify', messages: [message({
      id: 'JUNO-OWNER-PROVIDER-MESSAGE-1',
      sender: '11111111111@s.whatsapp.net', fromMe: true,
    })],
  });
  assert.equal(owner.action, 'queued');
  assert.equal(queue[0].fromOwner, true);
  const rejected = await emittingSocket.ev.emit('messages.upsert', {
    type: 'notify', messages: [message({
      id: 'JUNO-OWNER-PROVIDER-MESSAGE-2',
      sender: '99999999999@s.whatsapp.net', fromMe: true,
    })],
  });
  assert.equal(rejected.reason, 'drop_allowlist');
  assert.equal(queue.length, 1);
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

test('production bridge calls its exported exact production composition', () => {
  const source = readFileSync(new URL('./bridge.js', import.meta.url), 'utf8');
  assert.match(source, /import \{ registerInboundMessageHandler \}/);
  assert.match(source, /export function registerProductionInboundMessageHandler/);
  assert.match(source, /registerProductionInboundMessageHandler\(\{ connectionSocket, isActiveSocket \}\)/);
  assert.match(source, /const msgs = takeProductionInboundMessages\(\)/);
  assert.doesNotMatch(source, /sock\.ev\.on\(['"]messages\.upsert/);
});
