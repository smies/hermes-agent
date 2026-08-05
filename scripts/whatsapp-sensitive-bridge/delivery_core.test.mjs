import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import {
  SENSITIVE_SUBMIT_CONTRACT_VERSION,
  SensitiveDeliveryTransport,
} from './delivery_core.js';

const CHAT = '15557654321@s.whatsapp.net';
const ACCOUNT = '15551234567@s.whatsapp.net';
const ORDINARY_ACCOUNT = '15559876543@s.whatsapp.net';
const ORDINARY_LID = '90909090909@lid';
const RUNTIME = 'runtime-01HZX7M6Y2PE5F8K9W3R4T6V7X';
const EPOCH = 'epoch-01HZX7M6Y2PE5F8K9W3R4T6V7X';
const PRIVATE = 'PRIVATE-CANARY-é-7b5031';
const MESSAGE_ID = '3EB0ABCDEFABCDEFABCDEF';
const NOW = 1_785_846_896_000_000;
const TRANSPORT_IDENTITY = Object.freeze({ manifest_sha256: 'a'.repeat(64) });

function canonicalize(jid) {
  return String(jid).replace(/:\d+@/, '@').replace('@c.us', '@s.whatsapp.net');
}

function submission({
  account = ACCOUNT,
  destination = CHAT,
  expiresAtUs = NOW + 4_000_000,
} = {}) {
  return {
    contract_version: SENSITIVE_SUBMIT_CONTRACT_VERSION,
    request_id: 'request-01HZX7M6Y2PE5F8K9W3R4T6V7X',
    registration: RUNTIME,
    session: EPOCH,
    account,
    destination,
    expires_at_us: expiresAtUs,
    private_value: PRIVATE,
  };
}

function harness({
  account = ACCOUNT,
  ordinaryAccount = ORDINARY_ACCOUNT,
  nowUs = () => NOW,
  lidForPhone = async () => null,
  sendMessage,
} = {}) {
  const calls = [];
  const operations = [];
  const ev = new EventEmitter();
  const sock = {
    user: { id: account.replace('@s.whatsapp.net', ':4@s.whatsapp.net') },
    ev,
    signalRepository: {
      lidMapping: {
        async getLIDForPN(phone) {
          operations.push(['mapping', phone]);
          return lidForPhone(phone);
        },
      },
    },
    async sendMessage(...args) {
      operations.push(['send', args[0]]);
      calls.push(args);
      if (sendMessage) return sendMessage(args);
      return { key: { id: args[2].messageId, remoteJid: args[0], fromMe: true } };
    },
  };
  const transport = new SensitiveDeliveryTransport({
    runtimeId: RUNTIME,
    ordinaryAccountJid: ordinaryAccount,
    transportIdentity: TRANSPORT_IDENTITY,
    canonicalizeJid: canonicalize,
    generateMessageId: () => MESSAGE_ID,
    nowUs,
  });
  transport.bindConnection({ sock, accountJid: account, epoch: EPOCH });
  return { calls, operations, sock, transport };
}

test('v2 submit performs one exact correlated plaintext send', async () => {
  const h = harness();
  const result = await h.transport.submit(submission());
  assert.deepEqual(result, {
    state: 'submitted', message_id: MESSAGE_ID, account: ACCOUNT, destination: CHAT,
  });
  assert.deepEqual(h.calls, [[
    CHAT, { text: PRIVATE, linkPreview: null }, { messageId: MESSAGE_ID },
  ]]);
  assert.equal(JSON.stringify(result).includes(PRIVATE), false);
});

test('legacy transport.send is absent and cannot reach the provider', () => {
  const h = harness();
  assert.equal(Object.hasOwn(SensitiveDeliveryTransport.prototype, 'send'), false);
  assert.throws(() => h.transport.send(submission()), TypeError);
  assert.deepEqual(h.calls, []);
});

test('final transport boundary rejects every direct ordinary-account alias', async () => {
  for (const destination of [
    ORDINARY_ACCOUNT,
    '15559876543:9@s.whatsapp.net',
    '15559876543@c.us',
  ]) {
    const h = harness();
    const result = await h.transport.submit(submission({ destination }));
    assert.equal(result.state, 'failed', destination);
    assert.deepEqual(h.calls, [], destination);
  }
});

test('final boundary resolves phone-to-LID ordinary aliases and rejects with zero sends', async () => {
  const h = harness({
    lidForPhone: async (phone) => phone === ORDINARY_ACCOUNT ? ORDINARY_LID : null,
  });
  const result = await h.transport.submit(submission({ destination: ORDINARY_LID }));
  assert.equal(result.state, 'failed');
  assert.deepEqual(h.operations, [['mapping', ORDINARY_ACCOUNT]]);
  assert.deepEqual(h.calls, []);
});

test('final boundary resolves LID-to-phone ordinary aliases and rejects with zero sends', async () => {
  const sensitiveLid = '80808080808@lid';
  const h = harness({
    account: sensitiveLid,
    ordinaryAccount: ORDINARY_LID,
    lidForPhone: async (phone) => phone === ORDINARY_ACCOUNT ? ORDINARY_LID : null,
  });
  const result = await h.transport.submit(submission({
    account: sensitiveLid,
    destination: '15559876543:3@s.whatsapp.net',
  }));
  assert.equal(result.state, 'failed');
  assert.deepEqual(h.operations, [['mapping', ORDINARY_ACCOUNT]]);
  assert.deepEqual(h.calls, []);

  const deviceAlias = harness({
    account: sensitiveLid,
    ordinaryAccount: ORDINARY_LID,
  });
  assert.equal((await deviceAlias.transport.submit(submission({
    account: sensitiveLid,
    destination: '90909090909:12@lid',
  }))).state, 'failed');
  assert.deepEqual(deviceAlias.operations, []);
  assert.deepEqual(deviceAlias.calls, []);
});

test('distinct phone and mapped LID controls cross the same final fence and send once', async () => {
  const phone = harness();
  assert.equal((await phone.transport.submit(submission())).state, 'submitted');
  assert.equal(phone.calls.length, 1);

  const distinctLid = '70707070707@lid';
  const lid = harness({
    lidForPhone: async (value) => value === ORDINARY_ACCOUNT ? ORDINARY_LID : null,
  });
  const result = await lid.transport.submit(submission({ destination: distinctLid }));
  assert.equal(result.state, 'submitted');
  assert.deepEqual(lid.operations, [
    ['mapping', ORDINARY_ACCOUNT], ['send', distinctLid],
  ]);
  assert.equal(lid.calls.length, 1);
});

test('unknown cross-namespace mapping fails closed before provider invocation', async () => {
  const h = harness({ lidForPhone: async () => { throw new Error('mapping unavailable'); } });
  assert.equal((await h.transport.submit(submission({
    destination: '70707070707@lid',
  }))).state, 'failed');
  assert.equal(h.calls.length, 0);
});

test('exact expiry and malformed deadlines remain zero-send failures', async () => {
  const h = harness();
  assert.equal((await h.transport.submit(submission({ expiresAtUs: NOW }))).state, 'expired');
  for (const deadline of ['1785846896000001', Number.MAX_SAFE_INTEGER]) {
    assert.equal((await h.transport.submit(submission({ expiresAtUs: deadline }))).state, 'failed');
  }
  assert.equal(h.calls.length, 0);
});

test('expiry is sampled again after alias resolution immediately before send', async () => {
  const expiry = NOW + 1;
  const samples = [NOW, expiry];
  const h = harness({ nowUs: () => samples.shift() });
  const result = await h.transport.submit(submission({ expiresAtUs: expiry }));
  assert.equal(result.state, 'expired');
  assert.equal(h.calls.length, 0);
  assert.equal(samples.length, 0);
});

test('same sensitive and ordinary accounts remain impossible to bind', () => {
  assert.throws(() => harness({ ordinaryAccount: ACCOUNT }), /separate sensitive account/);
  assert.throws(
    () => harness({ ordinaryAccount: ORDINARY_LID }),
    /account identity namespace mismatch/,
  );
});
