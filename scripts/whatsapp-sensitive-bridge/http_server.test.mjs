import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import {
  CAPABILITY_HEADER,
  createSensitiveHttpHandler,
  listenLoopback,
} from './http_server.js';

const CAPABILITY = 'capability-8f0e9d16c2ac4ab096e9d30db0371fcba4c2cde36b424db8';

function invoke(handler, { method = 'POST', path = '/v1/send', headers = {}, chunks = [] } = {}) {
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
    transport: { async send() { return { outcome: 'denied', submitted: false }; } },
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
    maxBodyBytes: 64,
    activeRequestLimit: 1,
    transport: { async send() { await pending; return { outcome: 'denied', submitted: false }; } },
  });
  const valid = JSON.stringify({ a: 1 });
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
    [{ ...baseHeaders, 'content-length': '65' }, 413],
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
    transport: { async send() { return { outcome: 'denied', submitted: false }; } },
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

test('aborted partial bodies release the active-request slot without parsing', async () => {
  let sends = 0;
  const handler = createSensitiveHttpHandler({
    capability: CAPABILITY,
    activeRequestLimit: 1,
    transport: { async send() { sends += 1; return { outcome: 'denied', submitted: false }; } },
  });
  const partial = new EventEmitter();
  partial.method = 'POST';
  partial.url = '/v1/send';
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

  const body = '{}';
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
  assert.equal(sends, 1);
});
