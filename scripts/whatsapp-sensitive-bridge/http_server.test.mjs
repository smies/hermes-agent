import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { chmodSync, mkdtempSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  CAPABILITY_HEADER,
  SENSITIVE_SUBMIT_CONTRACT_VERSION,
  createSensitiveHttpHandler,
  listenLoopback,
} from './http_server.js';
import { SensitiveDeliveryTransport } from './delivery_core.js';
import {
  DurableReceiverReplayAuthority,
  initializeReceiverReplayAuthority,
} from './replay_authority.js';

const CAPABILITY = 'capability-8f0e9d16c2ac4ab096e9d30db0371fcba4c2cde36b424db8';
const MVP_SUBMIT_CONTRACT = SENSITIVE_SUBMIT_CONTRACT_VERSION;

function freshReplayAuthority() {
  const state = mkdtempSync(path.join(realpathSync.native(tmpdir()), 'juno-http-replay-'));
  chmodSync(state, 0o700);
  return new DurableReceiverReplayAuthority(
    initializeReceiverReplayAuthority(path.join(state, 'receiver-replay')),
  );
}

function invoke(handler, { method = 'POST', path = '/v1/submit', headers = {}, chunks = [] } = {}) {
  return new Promise((resolve) => {
    const req = new EventEmitter();
    req.method = method;
    req.url = path;
    req.headers = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
    req.socket = { remoteAddress: '127.0.0.1' };
    const responseChunks = [];
    const res = {
      statusCode: 200,
      headers: {},
      setHeader(key, value) { this.headers[key.toLowerCase()] = value; },
      end(value = '') { responseChunks.push(String(value)); resolve({ status: this.statusCode, body: responseChunks.join(''), headers: this.headers }); },
    };
    handler(req, res);
    for (const chunk of chunks) req.emit('data', Buffer.from(chunk));
    req.emit('end');
  });
}

test('capability authentication is timing-safe and completes before JSON parsing/body reads', async () => {
  let parses = 0;
  const handler = createSensitiveHttpHandler({
    capability: CAPABILITY,
    parseJson(bytes) { parses += 1; return JSON.parse(bytes); },
    transport: { async submit() { return { state: 'failed' }; } },
  });
  const body = '{not-json-and-private';
  const result = await invoke(handler, {
    headers: {
      host: '127.0.0.1',
      [CAPABILITY_HEADER]: 'wrong',
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(body)),
    },
    chunks: [body],
  });
  assert.equal(result.status, 401);
  assert.equal(parses, 0);
  assert.equal(result.body.includes(body), false);
});

test('handler enforces loopback peer/host, exact content type/length, body and active caps', async () => {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const handler = createSensitiveHttpHandler({
    capability: CAPABILITY,
    maxBodyBytes: 512,
    activeRequestLimit: 1,
    nowUs: () => 1_785_846_896_000_000,
    transport: { async submit() { await pending; return { state: 'failed' }; } },
  });
  const valid = JSON.stringify({
    contract_version: MVP_SUBMIT_CONTRACT,
    expires_at_us: 1_785_846_900_000_000,
  });
  const baseHeaders = {
    host: '127.0.0.1',
    [CAPABILITY_HEADER]: CAPABILITY,
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(valid)),
  };
  const first = invoke(handler, { headers: baseHeaders, chunks: [valid] });
  await new Promise((resolve) => setImmediate(resolve));
  const capacity = await invoke(handler, { headers: baseHeaders, chunks: [valid] });
  assert.equal(capacity.status, 429);
  release();
  await first;

  for (const [headers, status] of [
    [{ ...baseHeaders, host: 'attacker.example' }, 400],
    [{ ...baseHeaders, 'content-type': 'text/plain' }, 415],
    [{ ...baseHeaders, 'content-length': '513' }, 413],
    [{ ...baseHeaders, 'content-length': undefined }, 411],
  ]) {
    const cleaned = Object.fromEntries(Object.entries(headers).filter(([, value]) => value !== undefined));
    assert.equal((await invoke(handler, { headers: cleaned, chunks: [valid] })).status, status);
  }
});

test('rate cap and malformed bodies produce bounded content-free outcomes', async () => {
  const handler = createSensitiveHttpHandler({
    capability: CAPABILITY,
    rateLimit: 2,
    rateWindowMs: 60_000,
    transport: { async submit() { return { state: 'failed' }; } },
  });
  const headers = {
    host: 'localhost',
    [CAPABILITY_HEADER]: CAPABILITY,
    'content-type': 'application/json',
    'content-length': '1',
  };
  assert.equal((await invoke(handler, { headers, chunks: ['{'] })).status, 400);
  assert.equal((await invoke(handler, { headers, chunks: ['{'] })).status, 400);
  assert.equal((await invoke(handler, { headers, chunks: ['{'] })).status, 429);
});

test('listener binds only 127.0.0.1 even when callers request another host', async () => {
  const server = new EventEmitter();
  server.listen = (port, host) => {
    server.bound = { port, host };
    queueMicrotask(() => server.emit('listening'));
  };
  server.address = () => ({ address: server.bound.host, port: server.bound.port });
  await listenLoopback(server, { port: 0, host: '0.0.0.0' });
  assert.deepEqual(server.bound, { port: 0, host: '127.0.0.1' });
});

test('MVP submit route dispatches only to the submission operation', async () => {
  let submits = 0;
  let sends = 0;
  const body = JSON.stringify({
    contract_version: MVP_SUBMIT_CONTRACT,
    request_id: 'opaque', expires_at_us: 1_785_846_900_000_000,
    private_value: 'PRIVATE',
  });
  const result = await invoke(createSensitiveHttpHandler({
    capability: CAPABILITY,
    nowUs: () => 1_785_846_896_000_000,
    transport: {
      async submit() {
        submits += 1;
        return { state: 'submitted', message_id: 'message-1', account: 'a', destination: 'd' };
      },
      async send() { sends += 1; return { outcome: 'denied', submitted: false }; },
    },
  }), {
    path: '/v1/submit',
    headers: {
      host: '127.0.0.1',
      [CAPABILITY_HEADER]: CAPABILITY,
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(body)),
    },
    chunks: [body],
  });
  assert.equal(result.status, 200);
  assert.equal(submits, 1);
  assert.equal(sends, 0);
  assert.equal(result.body.includes('PRIVATE'), false);
});

test('authenticated legacy and alternate routes are unpublished and never dispatch', async () => {
  let submits = 0;
  let legacySends = 0;
  const body = JSON.stringify({
    contract_version: MVP_SUBMIT_CONTRACT,
    request_id: 'otherwise-valid-legacy-payload',
    registration: 'runtime', session: 'epoch',
    account: '15551234567@s.whatsapp.net',
    destination: '15557654321@s.whatsapp.net',
    expires_at_us: 1_785_846_900_000_000,
    private_value: 'PRIVATE-LEGACY-ROUTE',
  });
  const handler = createSensitiveHttpHandler({
    capability: CAPABILITY,
    nowUs: () => 1_785_846_896_000_000,
    transport: {
      async submit() { submits += 1; return { state: 'submitted' }; },
      async send() { legacySends += 1; return { outcome: 'provider_accepted' }; },
    },
  });
  const headers = {
    host: '127.0.0.1', [CAPABILITY_HEADER]: CAPABILITY,
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(body)),
  };
  for (const path of [
    '/v1/send', '/send', '/v1/deliver', '/v1/submit/',
    '/messages', '/v1/messages', '/model', '/v1/model', '/inbound',
  ]) {
    const result = await invoke(handler, { path, headers, chunks: [body] });
    assert.equal(result.status, 404, path);
    assert.equal(result.body.includes('PRIVATE-LEGACY-ROUTE'), false, path);
  }
  assert.equal(submits, 0);
  assert.equal(legacySends, 0);
});

test('identity preflight is an expiring operation on exact POST /v1/submit only', async () => {
  const now = 1_785_846_896_000_000;
  let observations = 0;
  const handler = createSensitiveHttpHandler({
    capability: CAPABILITY,
    nowUs: () => now,
    transport: {
      identityEvidence(request) {
        observations += 1;
        assert.equal(request.operation, 'observe_identity');
        return {
          outcome: 'available', submitted: false,
          provider_account_jid: request.account,
          identity_observed_us: now,
          adapter_runtime_id: 'runtime-identity-only',
          connection_epoch: 'epoch-identity-only',
          transport_identity: { manifest_sha256: 'a'.repeat(64) },
        };
      },
      async submit() { assert.fail('identity preflight must not dispatch plaintext submit'); },
    },
  });
  const get = await invoke(handler, {
    method: 'GET', path: '/v1/identity',
    headers: { host: '127.0.0.1', [CAPABILITY_HEADER]: CAPABILITY },
  });
  assert.equal(get.status, 404);

  const body = JSON.stringify({
    contract_version: MVP_SUBMIT_CONTRACT,
    operation: 'observe_identity',
    request_id: 'request-identity-preflight',
    account: '15551234567@s.whatsapp.net',
    destination: '15557654321@s.whatsapp.net',
    expires_at_us: now + 5_000_000,
  });
  const result = await invoke(handler, {
    method: 'POST', path: '/v1/submit',
    headers: {
      host: '127.0.0.1', [CAPABILITY_HEADER]: CAPABILITY,
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(body)),
    },
    chunks: [body],
  });
  assert.equal(result.status, 200);
  assert.equal(JSON.parse(result.body).adapter_runtime_id, 'runtime-identity-only');
  assert.equal(observations, 1);
});

test('MVP handler rejects exact expiry immediately before delivery dispatch', async () => {
  const now = 1_785_846_896_000_000;
  let submits = 0;
  const body = JSON.stringify({
    contract_version: MVP_SUBMIT_CONTRACT,
    request_id: 'expired-handler-request',
    registration: 'runtime', session: 'epoch',
    account: '15551234567@s.whatsapp.net',
    destination: '15557654321@s.whatsapp.net',
    expires_at_us: now,
    private_value: 'PRIVATE-HANDLER-DEADLINE',
  });
  const result = await invoke(createSensitiveHttpHandler({
    capability: CAPABILITY,
    nowUs: () => now,
    transport: {
      async submit() { submits += 1; return { state: 'submitted' }; },
    },
  }), {
    path: '/v1/submit',
    headers: {
      host: '127.0.0.1', [CAPABILITY_HEADER]: CAPABILITY,
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(body)),
    },
    chunks: [body],
  });
  assert.deepEqual(JSON.parse(result.body), {
    state: 'expired', message_id: null, account: '', destination: '',
  });
  assert.equal(submits, 0);
  assert.equal(result.body.includes('PRIVATE-HANDLER-DEADLINE'), false);
});

test('real HTTP handler calls real MVP transport with live identity and fake socket', async () => {
  const ev = new EventEmitter();
  const sends = [];
  const account = '15551234567@s.whatsapp.net';
  const ordinary = account;
  const destination = '15557654321@s.whatsapp.net';
  const runtime = 'runtime-live-synthetic';
  const epoch = 'epoch-live-synthetic';
  const messageId = '3EB0ABCDEF0123456789AB';
  const sock = {
    user: { id: '15551234567:4@s.whatsapp.net' }, ev,
    async sendMessage(...args) {
      sends.push(args);
      return { key: { id: messageId, remoteJid: destination, fromMe: true } };
    },
  };
  const transport = new SensitiveDeliveryTransport({
    runtimeId: runtime, ordinaryAccountJid: ordinary,
    processGeneration: 'b'.repeat(64),
    topologyIdentity: { topology_sha256: 'c'.repeat(64) },
    transportIdentity: { manifest_sha256: 'a'.repeat(64) },
    canonicalizeJid: (jid) => String(jid).replace(/:\d+@/, '@'),
    generateMessageId: () => messageId,
    replayAuthority: freshReplayAuthority(),
  });
  transport.bindConnection({ sock, accountJid: account, epoch });
  const handler = createSensitiveHttpHandler({ capability: CAPABILITY, transport });

  const identityRequest = JSON.stringify({
    contract_version: MVP_SUBMIT_CONTRACT,
    operation: 'observe_identity',
    request_id: 'request-http-vertical',
    account,
    destination,
    expires_at_us: Date.now() * 1000 + 60_000_000,
  });
  const identity = await invoke(handler, {
    method: 'POST', path: '/v1/submit',
    headers: {
      host: '127.0.0.1', [CAPABILITY_HEADER]: CAPABILITY,
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(identityRequest)),
    },
    chunks: [identityRequest],
  });
  const evidence = JSON.parse(identity.body);
  assert.equal(evidence.adapter_runtime_id, runtime);
  assert.equal(evidence.connection_epoch, epoch);
  assert.equal(evidence.provider_account_jid, account);

  const request = JSON.stringify({
    contract_version: MVP_SUBMIT_CONTRACT,
    request_id: 'request-http-vertical', registration: runtime, session: epoch,
    process_generation: 'b'.repeat(64), topology_sha256: 'c'.repeat(64),
    account, destination, expires_at_us: Date.now() * 1000 + 60_000_000,
    private_value: 'PRIVATE-HTTP-VERTICAL',
  });
  const result = await invoke(handler, {
    path: '/v1/submit',
    headers: {
      host: '127.0.0.1', [CAPABILITY_HEADER]: CAPABILITY,
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(request)),
    },
    chunks: [request],
  });
  assert.deepEqual(JSON.parse(result.body), {
    state: 'submitted', message_id: messageId, account, destination,
  });
  assert.deepEqual(sends, [[destination, {
    text: 'PRIVATE-HTTP-VERTICAL', linkPreview: null,
  }, { messageId }]]);
});

test('aborted partial submit bodies release the active-request slot without parsing', async () => {
  let submits = 0;
  const handler = createSensitiveHttpHandler({
    capability: CAPABILITY,
    activeRequestLimit: 1,
    nowUs: () => 1_785_846_896_000_000,
    transport: { async submit() { submits += 1; return { state: 'failed' }; } },
  });
  const partial = new EventEmitter();
  partial.method = 'POST';
  partial.url = '/v1/submit';
  partial.headers = {
    host: '127.0.0.1',
    [CAPABILITY_HEADER]: CAPABILITY,
    'content-type': 'application/json',
    'content-length': '10',
  };
  partial.socket = { remoteAddress: '127.0.0.1' };
  const ignoredResponse = {
    statusCode: 200,
    setHeader() {},
    end() {},
  };
  handler(partial, ignoredResponse);
  partial.emit('data', Buffer.from('{'));
  partial.emit('aborted');

  const body = JSON.stringify({
    contract_version: MVP_SUBMIT_CONTRACT,
    expires_at_us: 1_785_846_900_000_000,
  });
  const result = await invoke(handler, {
    headers: {
      host: '127.0.0.1',
      [CAPABILITY_HEADER]: CAPABILITY,
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(body)),
    },
    chunks: [body],
  });
  assert.equal(result.status, 200);
  assert.equal(submits, 1);
});

test('process capability rotation rejects every prior-generation submission', async () => {
  let submits = 0;
  const nextCapability = 'n'.repeat(48);
  const handler = createSensitiveHttpHandler({
    capability: nextCapability,
    transport: { async submit() { submits += 1; return { state: 'failed' }; } },
  });
  const body = JSON.stringify({ private_value: 'PRIVATE-ROTATION-PROBE' });
  const rejected = await invoke(handler, {
    headers: {
      host: '127.0.0.1',
      [CAPABILITY_HEADER]: CAPABILITY,
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(body)),
    },
    chunks: [body],
  });
  assert.equal(rejected.status, 401);
  assert.equal(submits, 0);
  assert.equal(rejected.body.includes('PRIVATE-ROTATION-PROBE'), false);
});
