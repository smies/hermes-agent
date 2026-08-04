import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import {
  DEFAULT_ACK_DEADLINE_MS,
  SensitiveDeliveryTransport,
} from './delivery_core.js';

const CHAT = '15557654321@s.whatsapp.net';
const ACCOUNT = '15551234567@s.whatsapp.net';
const ORDINARY_ACCOUNT = '15559876543@s.whatsapp.net';
const RUNTIME = 'runtime-01HZX7M6Y2PE5F8K9W3R4T6V7X';
const EPOCH = 'epoch-01HZX7M6Y2PE5F8K9W3R4T6V7X';
const PRIVATE = 'PRIVATE-CANARY-é-7b5031';
const TRANSPORT_IDENTITY = Object.freeze({
  manifest_sha256: 'a'.repeat(64),
  baileys_spec: '7.0.0-rc14',
  baileys_reviewed_release_git_head: '7e7b0757e3f9f3c7789fb1cfd2f241d5002a199a',
});
const BINDINGS = Object.freeze({
  authorization_task_id: 'task-01HZX7M6Y2PE5F8K9W3R4T6V7X',
  operation_id: 'operation-read-trip-arrival',
  correlation_id: 'correlation-01HZX7M6Y2PE5F8K9W3R4T6V7X',
  attempt_id: 'attempt-01HZX7M6Y2PE5F8K9W3R4T6V7X',
  request_binding_hmac: 'mWvS3YV4Qm9xX1fD_0YTcJ2q7aLp8kNe',
  request_binding_key_version: 'request-hmac-v1',
  policy_version: 'policy-v1',
  policy_hash: 'b'.repeat(64),
  expected_profile: 'kite',
  expected_platform: 'whatsapp',
  expected_account_binding_ref: 'account-binding-primary',
  destination_thread_id: CHAT,
});

function request(overrides = {}) {
  return {
    ...BINDINGS,
    expected_provider_account_jid: ACCOUNT,
    chat_jid: CHAT,
    expected_adapter_runtime_id: RUNTIME,
    expected_connection_epoch: EPOCH,
    private_value: PRIVATE,
    ...overrides,
  };
}

function update(id, {
  chat = CHAT,
  fromMe = true,
  status = 3,
  messageTimestamp = 1_785_846_895,
} = {}) {
  return {
    key: { id, remoteJid: chat, fromMe },
    update: { status, messageTimestamp },
  };
}

function harness(options = {}) {
  const ev = new EventEmitter();
  const calls = [];
  let generated = 0;
  let clock = 1_785_846_896_000_000;
  const sock = {
    user: { id: `${ACCOUNT.replace('@s.whatsapp.net', '')}:4@s.whatsapp.net` },
    ev,
    sendMessage(...args) {
      calls.push(args);
      if (options.sendMessage) return options.sendMessage({ args, ev, sock });
      return Promise.resolve({ key: { id: args[2].messageId, remoteJid: args[0], fromMe: true } });
    },
  };
  const ids = options.ids || [];
  const transport = new SensitiveDeliveryTransport({
    runtimeId: RUNTIME,
    ordinaryAccountJid: ORDINARY_ACCOUNT,
    transportIdentity: TRANSPORT_IDENTITY,
    canonicalizeJid: (jid) => String(jid).replace(/:\d+@/, '@').replace('@c.us', '@s.whatsapp.net'),
    generateMessageId: () => ids[generated++] || `3EB0${String(generated).padStart(18, 'A')}`,
    nowUs: options.nowUs || (() => clock++),
    sendDeadlineMs: options.sendDeadlineMs ?? 40,
    ackDeadlineMs: options.ackDeadlineMs ?? 500,
    activeLimit: options.activeLimit ?? 4,
    tombstoneLimit: options.tombstoneLimit ?? 8,
    attemptLimit: options.attemptLimit ?? 8,
  });
  transport.bindConnection({ sock, accountJid: ACCOUNT, epoch: EPOCH });
  return { calls, ev, sock, transport };
}

const tick = () => new Promise((resolve) => setImmediate(resolve));

test('production ACK deadline exceeds the exact-pin 30 second event buffer', () => {
  assert.ok(DEFAULT_ACK_DEADLINE_MS >= 31_000);
});

test('pre-reserved exact ID is registered before one exact plaintext send and synchronous ACK resolves', async () => {
  const id = '3EB0ABCDEF0123456789AB';
  const h = harness({
    ids: [id],
    sendMessage: async ({ args, ev }) => {
      ev.emit('messages.update', [update(args[2].messageId)]);
      return { key: { id, remoteJid: CHAT, fromMe: true } };
    },
  });

  const evidence = await h.transport.send(request());

  assert.deepEqual(h.calls, [[CHAT, { text: PRIVATE, linkPreview: null }, { messageId: id }]]);
  assert.equal(evidence.outcome, 'provider_accepted');
  assert.equal(evidence.submitted, true);
  assert.equal(evidence.provider_message_id, id);
  assert.equal(evidence.provider_status_code, 3);
  assert.equal(evidence.provider_timestamp_us, 1_785_846_895_000_000);
  assert.equal(Number.isSafeInteger(evidence.identity_observed_us), true);
  assert.equal(Number.isSafeInteger(evidence.send_started_us), true);
  assert.equal(Number.isSafeInteger(evidence.accepted_observed_us), true);
  assert.ok(evidence.identity_observed_us <= evidence.send_started_us);
  assert.ok(evidence.send_started_us <= evidence.accepted_observed_us);
  for (const [key, value] of Object.entries(BINDINGS)) assert.equal(evidence[key], value);
  assert.equal(JSON.stringify(evidence).includes(PRIVATE), false);
  assert.equal(h.ev.listenerCount('messages.update'), 1);
});

test('stale, wrong-key, wrong-account-context, and malformed updates never cross-correlate', async () => {
  const ids = ['3EB0AAAABBBBCCCCDDDD11', '3EB0AAAABBBBCCCCDDDD22'];
  const h = harness({ ids, ackDeadlineMs: 500 });
  h.ev.emit('messages.update', [update(ids[0])]);
  const first = h.transport.send(request());
  const second = h.transport.send(request({ attempt_id: 'attempt-second' }));
  await tick();
  h.ev.emit('messages.update', [
    update(ids[0], { chat: '15550000000@s.whatsapp.net' }),
    update(ids[0], { fromMe: false }),
    update(ids[1], { status: null }),
  ]);
  const [a, b] = await Promise.all([first, second]);
  assert.equal(a.outcome, 'ambiguous');
  assert.equal(a.error_code, 'ack_timeout');
  assert.equal(b.outcome, 'provider_rejected');
  assert.equal(b.error_code, 'provider_status_invalid');
  assert.equal(h.calls.length, 2);
});

test('concurrent same-chat attempts use exact IDs and one dispatcher', async () => {
  const ids = ['3EB0111111111111111111', '3EB0222222222222222222'];
  const h = harness({ ids, ackDeadlineMs: 100 });
  const a = h.transport.send(request());
  const b = h.transport.send(request({ attempt_id: 'attempt-concurrent-b' }));
  await tick();
  h.ev.emit('messages.update', [update(ids[1]), update(ids[0])]);
  const results = await Promise.all([a, b]);
  assert.deepEqual(results.map((item) => item.provider_message_id), ids);
  assert.deepEqual(results.map((item) => item.outcome), ['provider_accepted', 'provider_accepted']);
  assert.equal(h.ev.listenerCount('messages.update'), 1);
});

test('duplicate attempt and generated ID reuse reject before submission; tombstoned late ACK cannot satisfy later work', async () => {
  const reused = '3EB0333333333333333333';
  const h = harness({ ids: [reused, reused, '3EB0444444444444444444'], ackDeadlineMs: 12 });
  const first = await h.transport.send(request());
  assert.equal(first.error_code, 'ack_timeout');

  const duplicateAttempt = await h.transport.send(request());
  assert.equal(duplicateAttempt.outcome, 'denied');
  assert.equal(duplicateAttempt.error_code, 'attempt_reused');

  const reusedId = await h.transport.send(request({ attempt_id: 'attempt-new' }));
  assert.equal(reusedId.outcome, 'denied');
  assert.equal(reusedId.error_code, 'provider_id_reused');
  h.ev.emit('messages.update', [update(reused)]);

  const later = h.transport.send(request({ attempt_id: 'attempt-later' }));
  await tick();
  h.ev.emit('messages.update', [update('3EB0444444444444444444')]);
  assert.equal((await later).outcome, 'provider_accepted');
  assert.equal(h.calls.length, 2);
});

test('exact returned key is required and only destination receipt statuses mean provider acceptance', async () => {
  for (const returnedKey of [
    { id: 'wrong', remoteJid: CHAT, fromMe: true },
    { id: '3EB0555555555555555555', remoteJid: '15550000000@s.whatsapp.net', fromMe: true },
    { id: '3EB0555555555555555555', remoteJid: CHAT, fromMe: false },
  ]) {
    const id = '3EB0555555555555555555';
    const h = harness({ ids: [id], sendMessage: async () => ({ key: returnedKey }) });
    const evidence = await h.transport.send(request());
    assert.equal(evidence.outcome, 'ambiguous');
    assert.equal(evidence.error_code, 'send_result_mismatch');
  }

  for (const status of [3, 4, 5]) {
    const id = `3EB0${String(status).repeat(18)}`;
    const h = harness({ ids: [id] });
    const promise = h.transport.send(request({ attempt_id: `attempt-status-${status}` }));
    await tick();
    h.ev.emit('messages.update', [update(id, { status })]);
    const evidence = await promise;
    assert.equal(evidence.outcome, 'provider_accepted');
    assert.equal(Object.hasOwn(evidence, 'provider_status'), false);
    assert.equal(Object.hasOwn(evidence, 'delivery_status'), false);
    assert.equal(Object.hasOwn(evidence, 'read_status'), false);
    assert.equal(Object.hasOwn(evidence, 'played_status'), false);
  }
});

test('SERVER_ACK from a sender companion is insufficient and cannot produce acceptance', async () => {
  const id = '3EB0222222222222222222';
  const h = harness({ ids: [id], ackDeadlineMs: 50 });
  const promise = h.transport.send(request({ attempt_id: 'attempt-server-only' }));
  await tick();
  h.ev.emit('messages.update', [update(id, { status: 2 })]);
  const evidence = await promise;
  assert.equal(evidence.outcome, 'ambiguous');
  assert.equal(evidence.error_code, 'ack_timeout');
  assert.equal(evidence.provider_status_code, 2);
  assert.equal(Object.hasOwn(evidence, 'accepted_observed_us'), false);
});

test('account drift after a destination ACK cannot escape the final return fence', async () => {
  const id = '3EB0232323232323232323';
  const h = harness({
    ids: [id],
    sendMessage: async ({ ev, sock }) => {
      ev.emit('messages.update', [update(id, { status: 3 })]);
      sock.user.id = '15550000000:4@s.whatsapp.net';
      return { key: { id, remoteJid: CHAT, fromMe: true } };
    },
  });
  const evidence = await h.transport.send(request({ attempt_id: 'attempt-post-ack-drift' }));
  assert.equal(evidence.outcome, 'ambiguous');
  assert.equal(evidence.error_code, 'account_drift');
  assert.equal(evidence.provider_status_code, 3);
  assert.equal(Object.hasOwn(evidence, 'accepted_observed_us'), false);
});

test('same-account sensitive connection is rejected before it can send', () => {
  assert.throws(
    () => new SensitiveDeliveryTransport({
      runtimeId: RUNTIME,
      ordinaryAccountJid: ACCOUNT,
      transportIdentity: TRANSPORT_IDENTITY,
      canonicalizeJid: (jid) => String(jid).replace(/:\d+@/, '@'),
      generateMessageId: () => '3EB0ABCDEF0123456789AB',
    }).bindConnection({
      sock: harness().sock,
      accountJid: ACCOUNT,
      epoch: EPOCH,
    }),
    /separate sensitive account required/,
  );
  assert.throws(
    () => new SensitiveDeliveryTransport({
      runtimeId: RUNTIME,
      ordinaryAccountJid: '987654321@lid',
      transportIdentity: TRANSPORT_IDENTITY,
      canonicalizeJid: (jid) => String(jid).replace(/:\d+@/, '@'),
      generateMessageId: () => '3EB0ABCDEF0123456789AB',
    }).bindConnection({ sock: harness().sock, accountJid: ACCOUNT, epoch: EPOCH }),
    /account identity namespace mismatch/,
  );
});

test('ERROR and PENDING are typed provider rejection, never acceptance', async () => {
  for (const status of [0, 1]) {
    const id = `3EB0${String(status).repeat(18)}`;
    const h = harness({ ids: [id] });
    const promise = h.transport.send(request({ attempt_id: `attempt-reject-${status}` }));
    await tick();
    h.ev.emit('messages.update', [update(id, { status })]);
    const evidence = await promise;
    assert.equal(evidence.outcome, 'provider_rejected');
    assert.equal(evidence.submitted, true);
    assert.equal(evidence.provider_status_code, status);
  }
});

test('provider timestamp is optional evidence and may precede precise send time in its coarse second', async () => {
  const id = '3EB0666666666666666666';
  const h = harness({ ids: [id] });
  const promise = h.transport.send(request());
  await tick();
  h.ev.emit('messages.update', [update(id, { messageTimestamp: 1_785_846_895 })]);
  const evidence = await promise;
  assert.ok(evidence.provider_timestamp_us < evidence.send_started_us);

  const id2 = '3EB0777777777777777777';
  const h2 = harness({ ids: [id2] });
  const promise2 = h2.transport.send(request({ attempt_id: 'attempt-no-provider-time' }));
  await tick();
  h2.ev.emit('messages.update', [update(id2, { messageTimestamp: 'bad' })]);
  const evidence2 = await promise2;
  assert.equal(Object.hasOwn(evidence2, 'provider_timestamp_us'), false);

  const id3 = '3EB0707070707070707070';
  const h3 = harness({ ids: [id3] });
  const promise3 = h3.transport.send(request({ attempt_id: 'attempt-zero-provider-time' }));
  await tick();
  h3.ev.emit('messages.update', [update(id3, { messageTimestamp: 0 })]);
  const evidence3 = await promise3;
  assert.equal(Object.hasOwn(evidence3, 'provider_timestamp_us'), false);
});

test('host-observed chronology cannot move backward into an accepted outcome', async () => {
  const id = '3EB0787878787878787878';
  const times = [30, 31, 29];
  const h = harness({ ids: [id], nowUs: () => times.shift() });
  const promise = h.transport.send(request({ attempt_id: 'attempt-backward-clock' }));
  await tick();
  h.ev.emit('messages.update', [update(id, { status: 3 })]);
  const evidence = await promise;
  assert.equal(evidence.outcome, 'ambiguous');
  assert.equal(evidence.error_code, 'time_unavailable');
  assert.equal(Object.hasOwn(evidence, 'accepted_observed_us'), false);
});

test('send-promise and ACK deadlines are distinct, bounded, preserve evidence, and never retry', async () => {
  const id = '3EB0888888888888888888';
  const hanging = harness({ ids: [id], sendDeadlineMs: 10, sendMessage: () => new Promise(() => {}) });
  const sendTimeout = await hanging.transport.send(request());
  assert.equal(sendTimeout.outcome, 'ambiguous');
  assert.equal(sendTimeout.error_code, 'send_timeout');
  assert.equal(sendTimeout.provider_message_id, id);
  assert.equal(Number.isSafeInteger(sendTimeout.send_started_us), true);
  assert.equal(hanging.calls.length, 1);

  const id2 = '3EB0999999999999999999';
  const noAck = harness({ ids: [id2], ackDeadlineMs: 10 });
  const ackTimeout = await noAck.transport.send(request({ attempt_id: 'attempt-ack-timeout' }));
  assert.equal(ackTimeout.outcome, 'ambiguous');
  assert.equal(ackTimeout.error_code, 'ack_timeout');
  assert.equal(noAck.calls.length, 1);
});

test('disconnect, account/socket/epoch drift, service disable, and caller abort fence active attempts', async () => {
  const cases = [
    ['disconnect', (h) => h.transport.unbindConnection('disconnect')],
    ['account_drift', (h) => { h.sock.user.id = '15550000000:4@s.whatsapp.net'; h.ev.emit('messages.update', [update(h.id)]); }],
    ['socket_replaced', (h) => h.transport.bindConnection({ sock: { ...h.sock, ev: new EventEmitter() }, accountJid: ACCOUNT, epoch: EPOCH })],
    ['epoch_drift', (h) => h.transport.bindConnection({ sock: h.sock, accountJid: ACCOUNT, epoch: 'epoch-new' })],
    ['service_disabled', (h) => h.transport.setEnabled(false)],
  ];
  let n = 10;
  for (const [expected, mutate] of cases) {
    const id = `3EB0${String(n++).padStart(18, '0')}`;
    const h = harness({ ids: [id], ackDeadlineMs: 100 });
    h.id = id;
    const promise = h.transport.send(request({ attempt_id: `attempt-${expected}` }));
    await tick();
    mutate(h);
    const evidence = await promise;
    assert.equal(evidence.outcome, 'ambiguous', expected);
    assert.equal(evidence.error_code, expected, expected);
    assert.equal(evidence.provider_message_id, id);
  }

  const id = '3EB0121212121212121212';
  const h = harness({ ids: [id], ackDeadlineMs: 100 });
  const controller = new AbortController();
  const promise = h.transport.send(request({ attempt_id: 'attempt-abort' }), { signal: controller.signal });
  await tick();
  controller.abort();
  const evidence = await promise;
  assert.equal(evidence.outcome, 'ambiguous');
  assert.equal(evidence.error_code, 'caller_abort');
  assert.equal(h.calls.length, 1);
  assert.equal(h.transport.stats().active, 0);
});

test('pre-submit validation is exact, direct-chat-only, bounded, and does not read plaintext early', async () => {
  const invalid = [
    [request({ chat_jid: '15557654321:4@s.whatsapp.net' }), 'chat_not_canonical'],
    [request({ chat_jid: '120363001234@g.us' }), 'chat_not_direct'],
    [request({ chat_jid: 'status@broadcast' }), 'chat_not_direct'],
    [request({ chat_jid: '1555@newsletter' }), 'chat_not_direct'],
    [request({ expected_provider_account_jid: '15551234567:4@s.whatsapp.net' }), 'account_expectation_not_canonical'],
    [request({ expected_adapter_runtime_id: 'wrong-runtime' }), 'runtime_mismatch'],
    [request({ expected_connection_epoch: 'wrong-epoch' }), 'epoch_mismatch'],
    [request({ expected_platform: 'telegram' }), 'platform_mismatch'],
    [request({ destination_thread_id: '15550000000@s.whatsapp.net' }), 'destination_mismatch'],
    [request({ private_value: '' }), 'private_value_invalid'],
    [request({ private_value: 'x'.repeat(16 * 1024 + 1) }), 'private_value_too_large'],
    [request({ extra: 'forbidden' }), 'malformed_request'],
  ];
  for (const [fixture, code] of invalid) {
    const h = harness();
    const evidence = await h.transport.send(fixture);
    assert.equal(evidence.submitted, false, code);
    assert.equal(evidence.error_code, code, code);
    assert.equal(h.calls.length, 0, code);
  }

  const h = harness();
  const fixture = request();
  let read = false;
  Object.defineProperty(fixture, 'private_value', { enumerable: true, get() { read = true; return PRIVATE; } });
  fixture.expected_adapter_runtime_id = 'wrong-runtime';
  await h.transport.send(fixture);
  assert.equal(read, false);
});

test('active cap and bounded tombstone/attempt maps hold under storms without listener growth', async () => {
  const ids = Array.from({ length: 40 }, (_, index) => `3EB0${index.toString(16).toUpperCase().padStart(18, '0')}`);
  const h = harness({ ids, activeLimit: 1, tombstoneLimit: 3, attemptLimit: 4, ackDeadlineMs: 5 });
  const active = h.transport.send(request());
  const capacity = await h.transport.send(request({ attempt_id: 'attempt-over-capacity' }));
  assert.equal(capacity.outcome, 'capacity');
  assert.equal(capacity.submitted, false);
  await active;
  for (let index = 0; index < 12; index++) {
    await h.transport.send(request({ attempt_id: `attempt-storm-${index}` }));
  }
  for (let index = 0; index < 10_000; index++) {
    h.ev.emit('messages.update', [{ nope: index }]);
  }
  const stats = h.transport.stats();
  assert.ok(stats.tombstones <= 3);
  assert.ok(stats.attempt_tombstones <= 4);
  assert.equal(stats.active, 0);
  assert.equal(h.ev.listenerCount('messages.update'), 1);
});

test('plaintext and common encodings never enter evidence or bounded errors', async () => {
  const h = harness({ ids: ['3EB0ABCABCABCABCABCABC'], sendMessage: () => { throw new Error(PRIVATE); } });
  const evidence = await h.transport.send(request());
  const serialized = JSON.stringify(evidence);
  for (const value of [PRIVATE, Buffer.from(PRIVATE).toString('base64'), Buffer.from(PRIVATE).toString('hex')]) {
    assert.equal(serialized.includes(value), false);
  }
  assert.equal(evidence.outcome, 'ambiguous');
  assert.equal(evidence.error_code, 'send_failed');
});
