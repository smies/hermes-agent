import test from 'node:test';
import assert from 'node:assert/strict';
import { register } from 'node:module';

globalThis.__hermesRc14MockSockets = [];
register('./pairing_iq_test_hooks.mjs', import.meta.url);

const {
  default: makeWASocket,
  DEFAULT_CONNECTION_CONFIG,
  initAuthCreds,
} = await import('@whiskeysockets/baileys');

function silentCaptureLogger() {
  const xml = [];
  const logger = {
    level: 'trace',
    child: () => logger,
    trace: value => { if (typeof value?.xml === 'string') xml.push(value.xml); },
    debug() {}, info() {}, warn() {}, error() {}, fatal() {},
  };
  return { logger, xml };
}

function authState() {
  return {
    creds: initAuthCreds(),
    keys: { get: async () => ({}), set: async () => {} },
  };
}

function makeFixture(timeoutMs = 250, browser = ['Mac OS', 'Chrome', '14.4.1']) {
  const auth = authState();
  const capture = silentCaptureLogger();
  const updates = [];
  const sock = makeWASocket({
    ...DEFAULT_CONNECTION_CONFIG,
    auth,
    logger: capture.logger,
    defaultQueryTimeoutMs: timeoutMs,
    browser,
  });
  sock.ev.on('creds.update', update => updates.push(update));
  const ws = globalThis.__hermesRc14MockSockets.at(-1);
  return { auth, capture, sock, updates, ws };
}

async function pairingRequest(fixture) {
  const promise = fixture.sock.requestPairingCode('1234567890', 'A1B2C3D4');
  let xml;
  for (let attempt = 0; attempt < 200; attempt += 1) {
    xml = fixture.capture.xml.find(value => value.includes('link_code_companion_reg'));
    if (xml) break;
    await new Promise(resolve => setTimeout(resolve, 1));
  }
  assert.ok(xml, 'companion_hello was not sent');
  const id = /<iq[^>]* id=['"]([^'"]+)['"]/.exec(xml)?.[1];
  assert.ok(id, 'companion_hello did not have a query id');
  return { id, promise, xml };
}

async function endFixture(fixture) {
  await fixture.sock.end(new Error('test complete'));
}

test('real patched rc14 normalizes platform metadata and waits for matching IQ success', async () => {
  const fixture = makeFixture(250, ['Hermes Sensitive', 'Chrome', '120.0']);
  const request = await pairingRequest(fixture);
  let settled = false;
  request.promise.finally(() => { settled = true; }).catch(() => {});
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false);
  assert.equal(fixture.auth.creds.me, undefined);
  assert.equal(fixture.auth.creds.pairingCode, undefined);
  assert.match(request.xml, /<companion_platform_id[^>]*>\s*1\s*<\/companion_platform_id>/);
  assert.match(
    request.xml,
    /<companion_platform_display[^>]*>\s*Chrome \(Mac OS\)\s*<\/companion_platform_display>/,
  );
  fixture.ws.emit('TAG:wrong-id', {
    tag: 'iq', attrs: { id: 'wrong-id', type: 'result' },
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false);
  fixture.ws.emit(`TAG:${request.id}`, {
    tag: 'iq', attrs: { id: request.id, type: 'result' },
  });
  assert.equal(await request.promise, 'A1B2C3D4');
  assert.equal(fixture.auth.creds.me.id, '1234567890@s.whatsapp.net');
  assert.equal(fixture.updates.length, 1);
  await endFixture(fixture);
});

test('real patched rc14 rejects matching IQ error with no code or credential update', async () => {
  const fixture = makeFixture();
  const request = await pairingRequest(fixture);
  fixture.ws.emit(`TAG:${request.id}`, {
    tag: 'iq',
    attrs: { id: request.id, type: 'error' },
    content: [{ tag: 'error', attrs: { code: '400', text: 'bad-request' } }],
  });
  await assert.rejects(request.promise);
  assert.equal(fixture.auth.creds.me, undefined);
  assert.equal(fixture.auth.creds.pairingCode, undefined);
  assert.equal(fixture.updates.length, 0);
  await endFixture(fixture);
});

test('real patched rc14 rejects missing response timeout and socket close', async () => {
  const timeoutFixture = makeFixture(25);
  const timed = await pairingRequest(timeoutFixture);
  await assert.rejects(timed.promise);
  assert.equal(timeoutFixture.auth.creds.me, undefined);
  assert.equal(timeoutFixture.auth.creds.pairingCode, undefined);
  await endFixture(timeoutFixture);

  const closeFixture = makeFixture();
  const closed = await pairingRequest(closeFixture);
  closeFixture.ws.emit('close', new Error('closed'));
  await assert.rejects(closed.promise);
  assert.equal(closeFixture.auth.creds.me, undefined);
  assert.equal(closeFixture.auth.creds.pairingCode, undefined);
});
