import { strict as assert } from 'node:assert';

import {
  createBoundedMessageStore,
  extractBridgeEvent,
} from './bridge_helpers.js';
import { produceInboundMessage } from './inbound_producer.js';

const msg = {
  key: {
    id: 'JUNO-PROVIDER-MESSAGE-1',
    remoteJid: '22222222222@s.whatsapp.net',
    participant: '22222222222@s.whatsapp.net',
    fromMe: false,
  },
  pushName: 'Trusted Person',
  messageTimestamp: 1_786_000_000,
  message: { conversation: 'read newest inbox message' },
};

const messageQueue = [];
const messageStore = createBoundedMessageStore();
const allowed = new Set([
  '11111111111@s.whatsapp.net',
  '22222222222@s.whatsapp.net',
]);
const outcome = await produceInboundMessage({
  msg,
  socketUser: { id: '33333333333:19@s.whatsapp.net' },
  socket: {},
  mode: 'bot',
  dmPolicy: 'allowlist',
  forwardOwnerMessages: true,
  recentlySentIds: new Set(),
  allowlistMatches: id => allowed.has(id),
  extractEvent: extractBridgeEvent,
  downloadMedia: undefined,
  cacheDirs: {},
  replyPrefix: '',
  messageStore,
  messageQueue,
  maxQueueSize: 100,
});
assert.equal(outcome.action, 'queued');
assert.equal(messageQueue.length, 1);
const event = messageQueue[0];

assert.equal(event.messageId, 'JUNO-PROVIDER-MESSAGE-1');
assert.equal(event.accountId, '33333333333@s.whatsapp.net');
assert.equal(event.senderId, '22222222222@s.whatsapp.net');
assert.equal(event.chatId, '22222222222@s.whatsapp.net');
assert.equal(event.fromOwner, false);

const ownerQueue = [];
const ownerMsg = {
  ...msg,
  key: { ...msg.key, id: 'JUNO-OWNER-PROVIDER-MESSAGE-1', fromMe: true,
    remoteJid: '11111111111@s.whatsapp.net',
    participant: '11111111111@s.whatsapp.net' },
};
const owner = await produceInboundMessage({
  msg: ownerMsg,
  socketUser: { id: '33333333333:19@s.whatsapp.net' },
  socket: {}, mode: 'bot', dmPolicy: 'allowlist', forwardOwnerMessages: true,
  recentlySentIds: new Set(), allowlistMatches: id => allowed.has(id),
  extractEvent: extractBridgeEvent, cacheDirs: {}, replyPrefix: '',
  messageStore, messageQueue: ownerQueue, maxQueueSize: 100,
});
assert.equal(owner.action, 'queued');
assert.equal(ownerQueue[0].fromOwner, true);

const rejected = await produceInboundMessage({
  msg: { ...ownerMsg, key: { ...ownerMsg.key,
    remoteJid: '99999999999@s.whatsapp.net' } },
  socketUser: { id: '33333333333:19@s.whatsapp.net' },
  socket: {}, mode: 'bot', dmPolicy: 'allowlist', forwardOwnerMessages: true,
  recentlySentIds: new Set(), allowlistMatches: id => allowed.has(id),
  extractEvent: extractBridgeEvent, cacheDirs: {}, replyPrefix: '',
  messageStore, messageQueue: ownerQueue, maxQueueSize: 100,
});
assert.equal(rejected.reason, 'drop_allowlist');
assert.equal(ownerQueue.length, 1);
