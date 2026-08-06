import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { spawn } from 'node:child_process';
import {
  chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync,
  statSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SensitiveDeliveryTransport } from './delivery_core.js';
import {
  DurableReceiverReplayAuthority,
  initializeReceiverReplayAuthority,
} from './replay_authority.js';

const ACCOUNT = '15551234567@s.whatsapp.net';
const DESTINATION = '15557654321@s.whatsapp.net';
const NOW = 1_785_846_896_000_000;
const REQUEST_ID = 'logical-request-survives-receiver-replacement';
const PRIVATE = 'PRIVATE-RESTART-SENTINEL';
const HERE = path.dirname(fileURLToPath(import.meta.url));

function freshAuthority() {
  const state = mkdtempSync(path.join(realpathSync.native(tmpdir()), 'juno-receiver-replay-'));
  chmodSync(state, 0o700);
  const identity = initializeReceiverReplayAuthority(path.join(state, 'receiver-replay'));
  return { state, identity };
}

function transport(identity, calls, { generation = 'a'.repeat(64) } = {}) {
  const epoch = `epoch-${generation.slice(0, 8)}`;
  const runtime = `sensitive-${generation}`;
  const replayAuthority = new DurableReceiverReplayAuthority(identity);
  const instance = new SensitiveDeliveryTransport({
    runtimeId: runtime,
    processGeneration: generation,
    topologyIdentity: { topology_sha256: 'c'.repeat(64) },
    ordinaryAccountJid: ACCOUNT,
    transportIdentity: { manifest_sha256: 'd'.repeat(64) },
    canonicalizeJid: value => String(value).replace(/:\d+@/, '@'),
    generateMessageId: () => '3EB0ABCDEF0123456789AB',
    nowUs: () => NOW,
    replayAuthority,
  });
  const sock = {
    user: { id: '15551234567:4@s.whatsapp.net' },
    ev: new EventEmitter(),
    async sendMessage(...args) {
      calls.push(args);
      return {
        key: { id: args[2].messageId, remoteJid: args[0], fromMe: true },
      };
    },
  };
  instance.bindConnection({ sock, accountJid: ACCOUNT, epoch });
  return { instance, epoch, runtime, generation };
}

function request(receiver, overrides = {}) {
  return {
    contract_version: 'juno-sensitive-submit-v2',
    request_id: REQUEST_ID,
    registration: receiver.runtime,
    process_generation: receiver.generation,
    session: receiver.epoch,
    topology_sha256: 'c'.repeat(64),
    account: ACCOUNT,
    destination: DESTINATION,
    expires_at_us: NOW + 4_000_000,
    private_value: PRIVATE,
    ...overrides,
  };
}

test('two fresh receivers atomically burn one logical request before one provider call', async () => {
  const { identity } = freshAuthority();
  const calls = [];
  const first = transport(identity, calls, { generation: 'a'.repeat(64) });
  const second = transport(identity, calls, { generation: 'b'.repeat(64) });
  const results = await Promise.all([
    first.instance.submit(request(first)),
    second.instance.submit(request(second)),
  ]);
  assert.equal(results.filter(result => result.state === 'submitted').length, 1);
  assert.equal(results.filter(result => result.state === 'failed').length, 1);
  assert.equal(calls.length, 1);
});

test('two fresh receiver processes make one total provider call', async () => {
  const { identity } = freshAuthority();
  const run = generation => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      path.join(HERE, 'replay_process_worker.mjs'),
      JSON.stringify(identity), generation,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', code => {
      if (code !== 0) reject(new Error(stderr));
      else resolve(JSON.parse(stdout));
    });
  });
  const results = await Promise.all([run('a'.repeat(64)), run('b'.repeat(64))]);
  assert.equal(results.reduce((total, item) => total + item.providerCalls, 0), 1);
  assert.deepEqual(results.map(item => item.state).sort(), ['failed', 'submitted']);
});

test('process crash immediately after durable reservation burns the request fail closed', async () => {
  const { identity } = freshAuthority();
  const generation = 'a'.repeat(64);
  const crashed = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      path.join(HERE, 'replay_process_worker.mjs'),
      JSON.stringify(identity), generation, 'burn-only',
    ], { stdio: 'ignore' });
    child.once('error', reject);
    child.once('exit', resolve);
  });
  assert.equal(crashed, 86);
  const replacement = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      path.join(HERE, 'replay_process_worker.mjs'),
      JSON.stringify(identity), generation,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', code => code === 0
      ? resolve(JSON.parse(stdout)) : reject(new Error(stderr)));
  });
  assert.deepEqual(replacement, { state: 'failed', providerCalls: 0 });
});

test('restart, crash-window, mismatched reuse, and authorization rollback cannot restore a burn', async () => {
  const { state, identity } = freshAuthority();
  const calls = [];
  const first = transport(identity, calls);
  assert.equal((await first.instance.submit(request(first))).state, 'submitted');
  writeFileSync(path.join(state, 'authorization.db'), 'valid-old-snapshot');
  const replacement = transport(identity, calls, { generation: 'b'.repeat(64) });
  assert.equal((await replacement.instance.submit(request(replacement))).state, 'failed');
  assert.equal((await replacement.instance.submit(request(replacement, {
    private_value: `${PRIVATE}-changed`,
  }))).state, 'failed');
  assert.equal(calls.length, 1);
  const files = statSync(identity.root).isDirectory()
    && readFileSync(path.join(identity.root, '.authority'), 'utf8');
  assert.equal(files.includes(PRIVATE), false);
});

test('corrupt, aliased, hardlinked, missing, and permission-unsafe authority fails closed', () => {
  const { state, identity } = freshAuthority();
  const authorityFile = path.join(identity.root, '.authority');
  writeFileSync(authorityFile, 'corrupt');
  assert.throws(() => new DurableReceiverReplayAuthority(identity));

  const alias = path.join(state, 'alias');
  symlinkSync(identity.root, alias, 'dir');
  assert.throws(() => new DurableReceiverReplayAuthority({ ...identity, root: alias }));

  const fresh = freshAuthority();
  linkSync(
    path.join(fresh.identity.root, '.authority'),
    path.join(fresh.identity.root, '.authority.link'),
  );
  assert.throws(() => new DurableReceiverReplayAuthority(fresh.identity));

  const unsafe = freshAuthority();
  chmodSync(unsafe.identity.root, 0o755);
  assert.throws(() => new DurableReceiverReplayAuthority(unsafe.identity));

  assert.throws(() => new DurableReceiverReplayAuthority({
    ...identity, root: path.join(state, 'missing'),
  }));
});
