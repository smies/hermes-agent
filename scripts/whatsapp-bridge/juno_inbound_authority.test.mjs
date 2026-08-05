import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';

import {
  extractBridgeEvent,
  normalizeWhatsAppId,
} from './bridge_helpers.js';

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

const event = await extractBridgeEvent({
  msg,
  chatId: msg.key.remoteJid,
  senderId: msg.key.participant,
  senderNumber: '22222222222',
  isGroup: false,
});
// This assertion binds the fixture to the real messages.upsert forwarding
// statements, rather than treating the helper output as the production event.
const production = readFileSync(new URL('./bridge.js', import.meta.url), 'utf8');
assert.match(production, /const event = await extractBridgeEvent\([\s\S]*?event\.fromOwner = fromOwner;[\s\S]*?event\.accountId = normalizeWhatsAppId\(sock\.user\?\.id\);[\s\S]*?messageQueue\.push\(event\);/);
event.fromOwner = false;
event.accountId = normalizeWhatsAppId('33333333333:19@s.whatsapp.net');

assert.equal(event.messageId, 'JUNO-PROVIDER-MESSAGE-1');
assert.equal(event.accountId, '33333333333@s.whatsapp.net');
assert.equal(event.senderId, '22222222222@s.whatsapp.net');
assert.equal(event.chatId, '22222222222@s.whatsapp.net');
assert.equal(event.fromOwner, false);
