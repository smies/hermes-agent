import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync, closeSync, mkdtempSync, openSync, readFileSync, realpathSync,
  rmSync, statSync, writeFileSync,
} from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  jidNormalizedUser, useMultiFileAuthState,
} from '@whiskeysockets/baileys';

import { provisionOffline } from './offline_provision.js';
import { parseProvisioningRequest } from './provisioning_core.js';
import { initializeReceiverReplayAuthority } from './replay_authority.js';
import { prepareSessionPaths } from './session_paths.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LAUNCHER = path.join(HERE, 'launcher.js');
const PORT = 3011;
const PHONE = '33333333333';
const LID = '44444444444';
const ACCOUNT = `${PHONE}@s.whatsapp.net`;
const DESTINATION = '77777777777@s.whatsapp.net';
const CAPABILITY = `exact-${'a'.repeat(64)}`;
const PRIVATE = 'PRIVATE-EXACT-LAUNCHER-SENTINEL';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function provision(role, ordinary, sensitive) {
  await provisionOffline({
    request: parseProvisioningRequest({
      version: 1, action: 'provision', role, phone: PHONE,
      ordinary_session: ordinary, sensitive_session: sensitive,
      reprovision: false,
    }),
    useAuthState: useMultiFileAuthState,
    canonicalizeJid: jidNormalizedUser,
    makeSocket: ({ auth }) => {
      const listeners = new Map();
      const ev = {
        on(name, handler) { listeners.set(name, handler); },
        removeAllListeners() { listeners.clear(); },
      };
      const socket = {
        ev,
        user: { id: `${PHONE}:4@s.whatsapp.net`, lid: `${LID}@lid` },
        signalRepository: {
          lidMapping: { async getLIDForPN() { return `${LID}@lid`; } },
        },
        async requestPairingCode() { return 'R34KC9DE'; },
        end() {},
      };
      queueMicrotask(async () => {
        await auth.keys.set({ 'lid-mapping': { [PHONE]: LID } });
        auth.creds.registered = true;
        auth.creds.me = { id: socket.user.id, lid: socket.user.lid };
        listeners.get('connection.update')?.({ qr: 'provider-private-readiness' });
        listeners.get('connection.update')?.({ connection: 'open' });
      });
      return socket;
    },
    emitCode() {},
    timeoutMs: 3_000,
  });
}

async function requestJson(body, capability = CAPABILITY) {
  const encoded = Buffer.from(JSON.stringify(body));
  return await new Promise((resolve, reject) => {
    const request = http.request({
      hostname: '127.0.0.1', port: PORT, method: 'POST', path: '/v1/submit',
      headers: {
        host: `127.0.0.1:${PORT}`,
        'x-hermes-sensitive-capability': capability,
        'content-type': 'application/json',
        'content-length': String(encoded.length),
      },
      agent: false,
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({
        status: response.statusCode,
        body: JSON.parse(Buffer.concat(chunks).toString('utf8')),
      }));
    });
    request.once('error', reject);
    request.end(encoded);
  });
}

async function waitReady(account, generation, child) {
  const deadline = Date.now() + 12_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`exact launcher exited ${child.exitCode}: ${child.stderrText || ''}`);
    }
    try {
      const result = await requestJson({
        contract_version: 'juno-sensitive-submit-v2',
        operation: 'observe_identity',
        request_id: `identity-${randomBytes(12).toString('hex')}`,
        account,
        destination: DESTINATION,
        expires_at_us: Date.now() * 1000 + 5_000_000,
      });
      if (result.body.outcome === 'available'
          && result.body.process_generation === generation) return result.body;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('exact production launcher did not publish');
}

function launch({ launch, authorityPath, capturePath, extraEnv = {} }) {
  const authority = {
    version: 1,
    purpose: 'juno-exact-launcher-below-baileys-send',
    parent_pid: process.pid,
    process_generation: launch.process_generation,
    expires_at_us: Date.now() * 1000 + 60_000_000,
    nonce: randomBytes(32).toString('hex'),
  };
  const authorityBytes = Buffer.from(JSON.stringify(authority));
  writeFileSync(authorityPath, authorityBytes, { mode: 0o600 });
  chmodSync(authorityPath, 0o600);
  writeFileSync(capturePath, '', { mode: 0o600 });
  chmodSync(capturePath, 0o600);
  const authorityFd = openSync(authorityPath, 'r');
  const captureFd = openSync(capturePath, 'r+');
  const child = spawn(process.execPath, [LAUNCHER, '--port', String(PORT)], {
    cwd: HERE,
    stdio: ['pipe', 'ignore', 'pipe', authorityFd, captureFd],
    env: {
      ...process.env,
      HERMES_WHATSAPP_SENSITIVE_CAPABILITY: CAPABILITY,
      HERMES_INTERNAL_WHATSAPP_SENSITIVE_LAUNCH: JSON.stringify(launch),
      HERMES_INTERNAL_JUNO_TEST_PROVIDER_AUTHORITY_FD: '3',
      HERMES_INTERNAL_JUNO_TEST_PROVIDER_CAPTURE_FD: '4',
      HERMES_INTERNAL_JUNO_TEST_PROVIDER_AUTHORITY_SHA256: sha256(authorityBytes),
      HTTP_PROXY: 'http://127.0.0.1:9',
      HTTPS_PROXY: 'http://127.0.0.1:9',
      ...extraEnv,
    },
  });
  child.stderrText = '';
  child.stderr.on('data', chunk => { child.stderrText += chunk.toString('utf8'); });
  closeSync(authorityFd);
  closeSync(captureFd);
  return child;
}

async function stop(child) {
  if (child.exitCode !== null) return;
  child.stdin.end();
  await Promise.race([
    new Promise(resolve => child.once('exit', resolve)),
    new Promise((_, reject) => setTimeout(() => reject(new Error('child stop timeout')), 3_000)),
  ]);
}

test('exact reviewed launcher reaches one inherited-authority send and durable restart rejects replay', async (t) => {
  const loopbackAllowed = await new Promise((resolve, reject) => {
    const probe = http.createServer();
    probe.once('error', error => {
      if (['EACCES', 'EPERM'].includes(error?.code)) resolve(false);
      else reject(error);
    });
    probe.listen(PORT, '127.0.0.1', () => probe.close(() => resolve(true)));
  });
  if (!loopbackAllowed) {
    t.skip('execution sandbox denied exact-launcher loopback listener');
    return;
  }
  const root = realpathSync.native(mkdtempSync(path.join(tmpdir(), 'juno-exact-launcher-')));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  await provision('ordinary', ordinary, sensitive);
  await provision('sensitive', ordinary, sensitive);
  const topology = prepareSessionPaths(sensitive, ordinary, {
    requireDistinctCredentials: true,
  }).topologyEvidence();
  const replay = initializeReceiverReplayAuthority(path.join(root, 'receiver-replay'));

  const generation = '1'.repeat(64);
  const launchDescriptor = {
    version: 2,
    process_generation: generation,
    configured_account_jid: ACCOUNT,
    profile: 'juno',
    mode: 'sensitive-outbound-only',
    replay,
    ordinary: {
      adapter_generation: '2'.repeat(64), runtime_id: 'ordinary-exact-runtime',
      socket_generation: 7, account_phone_jid: ACCOUNT,
      account_lid_jid: `${LID}@lid`, session_path: ordinary,
      session_identity: topology.ordinary.session_identity,
      manifest_sha256: '3'.repeat(64), source_sha256: '4'.repeat(64),
      launcher_sha256: '5'.repeat(64),
    },
    sensitive: { ...topology.sensitive },
  };
  const capture = path.join(root, 'capture.jsonl');
  const authority = path.join(root, 'test-authority.json');
  let child = launch({ launch: launchDescriptor, authorityPath: authority, capturePath: capture });
  try {
    const identity = await waitReady(ACCOUNT, generation, child);
    assert.equal(
      identity.transport_identity.manifest_sha256,
      sha256(readFileSync(path.join(HERE, 'transport-manifest.json'))),
    );
    assert.equal((await requestJson({
      contract_version: 'juno-sensitive-submit-v2',
      request_id: 'exact-logical-request',
      registration: identity.adapter_runtime_id,
      process_generation: generation,
      session: identity.connection_epoch,
      topology_sha256: identity.topology_identity.topology_sha256,
      account: ACCOUNT,
      destination: DESTINATION,
      expires_at_us: Date.now() * 1000 + 5_000_000,
      private_value: PRIVATE,
    })).body.state, 'submitted');
    const sent = JSON.parse(readFileSync(capture, 'utf8').trim());
    assert.equal(sent.destination, DESTINATION);
    assert.equal(sent.private_value, PRIVATE);

    for (const invalid of [
      { capability: `${CAPABILITY}-stale` },
      { process_generation: '9'.repeat(64) },
      { topology_sha256: '8'.repeat(64) },
      { account: '99999999999@s.whatsapp.net' },
      { destination: ACCOUNT },
      { expires_at_us: Date.now() * 1000 - 1 },
    ]) {
      const before = statSync(capture).size;
      const body = {
        contract_version: 'juno-sensitive-submit-v2',
        request_id: `negative-${randomBytes(8).toString('hex')}`,
        registration: identity.adapter_runtime_id,
        process_generation: generation,
        session: identity.connection_epoch,
        topology_sha256: identity.topology_identity.topology_sha256,
        account: ACCOUNT, destination: DESTINATION,
        expires_at_us: Date.now() * 1000 + 5_000_000,
        private_value: PRIVATE,
        ...invalid,
      };
      const staleCapability = body.capability;
      delete body.capability;
      const rejected = await requestJson(body, staleCapability || CAPABILITY);
      assert.notEqual(rejected.body.state, 'submitted');
      assert.equal(statSync(capture).size, before);
    }
  } finally {
    await stop(child);
  }

  const replacementGeneration = '6'.repeat(64);
  const replacementLaunch = {
    ...launchDescriptor,
    process_generation: replacementGeneration,
  };
  const replacementCapture = path.join(root, 'replacement-capture.jsonl');
  const replacementAuthority = path.join(root, 'replacement-authority.json');
  child = launch({
    launch: replacementLaunch,
    authorityPath: replacementAuthority,
    capturePath: replacementCapture,
  });
  try {
    const identity = await waitReady(ACCOUNT, replacementGeneration, child);
    const duplicate = await requestJson({
      contract_version: 'juno-sensitive-submit-v2',
      request_id: 'exact-logical-request',
      registration: identity.adapter_runtime_id,
      process_generation: replacementGeneration,
      session: identity.connection_epoch,
      topology_sha256: identity.topology_identity.topology_sha256,
      account: ACCOUNT, destination: DESTINATION,
      expires_at_us: Date.now() * 1000 + 5_000_000,
      private_value: PRIVATE,
    });
    assert.equal(duplicate.body.state, 'failed');
    assert.equal(readFileSync(replacementCapture, 'utf8'), '');
  } finally {
    await stop(child);
  }

  const wrongAccountCapture = path.join(root, 'wrong-account-capture.jsonl');
  const wrongAccountAuthority = path.join(root, 'wrong-account-authority.json');
  child = launch({
    launch: {
      ...launchDescriptor,
      process_generation: '7'.repeat(64),
      configured_account_jid: '99999999999@s.whatsapp.net',
    },
    authorityPath: wrongAccountAuthority,
    capturePath: wrongAccountCapture,
  });
  await Promise.race([
    new Promise(resolve => child.once('exit', resolve)),
    new Promise((_, reject) => setTimeout(
      () => reject(new Error('different-account launch did not fail closed')), 3_000,
    )),
  ]);
  assert.notEqual(child.exitCode, 0);
  assert.equal(readFileSync(wrongAccountCapture, 'utf8'), '');
});
