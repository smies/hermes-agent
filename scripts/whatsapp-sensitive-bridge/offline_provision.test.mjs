import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import { Readable } from 'node:stream';
import {
  chmod, mkdir, mkdtemp, open, readFile, realpath, rename, rm, stat, writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  commitStagedSession,
  PRE_CODE_FAILURE_REASONS,
  ProvisioningCommitError,
  provisionOffline,
  runProvisioner,
  validateExistingOffline,
} from './offline_provision.js';
import { parseProvisioningRequest } from './provisioning_core.js';

function identities() {
  const phone = `1${'6'.repeat(10)}`;
  return { phone, phoneJid: `${phone}@s.whatsapp.net`, lidJid: `${'8'.repeat(9)}@lid` };
}

function authIdentity(account, lid, device) {
  const material = value => ({ type: 'Buffer', data: [value, value + 1] });
  return {
    registered: true,
    me: { id: account, lid },
    registrationId: device,
    noiseKey: { private: material(device), public: material(device + 2) },
    signedIdentityKey: { private: material(device + 4), public: material(device + 6) },
    signedPreKey: {
      keyPair: { private: material(device + 8), public: material(device + 10) },
      signature: material(device + 12), keyId: device,
    },
    advSecretKey: `synthetic-adv-${device}`,
  };
}

async function existingTopologyFixture({ differentAccount = false, copiedDevice = false,
  missingOtherLid = false } = {}) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-topology-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  await chmod(root, 0o700);
  await mkdir(ordinary, { mode: 0o700 });
  await mkdir(sensitive, { mode: 0o700 });
  const account = '15551234567@s.whatsapp.net';
  const otherAccount = differentAccount ? '15557654321@s.whatsapp.net' : account;
  const lid = '90909090909@lid';
  const otherLid = differentAccount ? '80808080808@lid' : lid;
  const ordinaryCreds = authIdentity(account, lid, 17);
  const sensitiveCreds = copiedDevice
    ? { ...ordinaryCreds, independentMarker: true }
    : authIdentity(otherAccount, otherLid, 53);
  for (const [directory, creds] of [[ordinary, ordinaryCreds], [sensitive, sensitiveCreds]]) {
    await writeFile(path.join(directory, 'creds.json'), JSON.stringify(creds), { mode: 0o600 });
    await chmod(path.join(directory, 'creds.json'), 0o600);
  }
  const auth = new Map([
    [ordinary, {
      state: { creds: ordinaryCreds, keys: { get: async () => (
        missingOtherLid ? {} : { [account.split('@')[0]]: lid.split('@')[0] }
      ) } }, saveCreds: async () => {},
    }],
    [sensitive, {
      state: { creds: sensitiveCreds, keys: { get: async () => ({
        [otherAccount.split('@')[0]]: otherLid.split('@')[0],
      }) } }, saveCreds: async () => {},
    }],
  ]);
  const request = parseProvisioningRequest({
    version: 1, action: 'validate', role: 'sensitive',
    ordinary_session: ordinary, sensitive_session: sensitive,
  });
  return { root, request, useAuthState: async session => auth.get(session) };
}

test('existing same-account independently paired sessions validate as production-ready', async () => {
  const fixture = await existingTopologyFixture();
  try {
    assert.deepEqual(await validateExistingOffline({
      request: fixture.request,
      useAuthState: fixture.useAuthState,
      canonicalizeJid: value => String(value).replace(/:\d+@/, '@'),
    }), { account_namespace: 's.whatsapp.net', lid_ready: true });
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('different account, unknown LID topology, and copied device identity fail closed', async () => {
  for (const options of [
    { differentAccount: true },
    { missingOtherLid: true },
    { copiedDevice: true },
  ]) {
    const fixture = await existingTopologyFixture(options);
    try {
      assert.equal(await validateExistingOffline({
        request: fixture.request,
        useAuthState: fixture.useAuthState,
        canonicalizeJid: value => String(value).replace(/:\d+@/, '@'),
      }), null);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

function fakeSocket({ phoneJid, lidJid, update, onPairingCode }) {
  const ev = new EventEmitter();
  const socket = {
    ev,
    user: { id: phoneJid },
    signalRepository: { lidMapping: { getLIDForPN: async () => lidJid } },
    requestPairingCode: async () => {
      onPairingCode();
      return 'A1B2C3D4';
    },
    endCalled: false,
    end() { this.endCalled = true; },
  };
  queueMicrotask(() => ev.emit('connection.update', update(socket)));
  return socket;
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function waitFor(predicate, message) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 1));
  }
  assert.fail(message);
}

function wireRequest(phone = '+15551234567') {
  return Readable.from([`${JSON.stringify({
    version: 1,
    action: 'provision',
    role: 'ordinary',
    phone,
    ordinary_session: '/tmp/hermes-wire-ordinary',
    sensitive_session: '/tmp/hermes-wire-sensitive',
  })}\n`]);
}

test('operator wire accepts leading plus and emits exactly one pairing-code frame', async () => {
  const output = [];
  const operator = [];
  const exitCode = await runProvisioner({
    input: wireRequest(),
    output: { write: frame => output.push(frame) },
    operatorOutput: { write: frame => operator.push(frame) },
    provision: async ({ request, emitCode }) => {
      assert.equal(request.phone, '15551234567');
      emitCode('ABCD3FGH');
      return { account_namespace: 's.whatsapp.net', lid_ready: true };
    },
  });
  assert.equal(exitCode, 0);
  assert.deepEqual(operator.map(JSON.parse), [{ event: 'pairing_code', code: 'ABCD3FGH' }]);
  assert.deepEqual(output.map(JSON.parse), [{
    event: 'complete', state: 'ready_for_production',
    account_namespace: 's.whatsapp.net', lid_ready: true,
  }]);
});

test('pre-code wire failures expose only a finite content-free allowlisted reason', async () => {
  const raw = 'provider rejected 15551234567@s.whatsapp.net from /private/session';
  const output = [];
  const operator = [];
  const exitCode = await runProvisioner({
    input: wireRequest(),
    output: { write: frame => output.push(frame) },
    operatorOutput: { write: frame => operator.push(frame) },
    provision: async () => {
      throw new Error('pairing_request_failed', { cause: new Error(raw) });
    },
  });
  assert.equal(exitCode, 1);
  assert.deepEqual(operator.map(JSON.parse), [
    { event: 'pairing_failure', reason: 'pairing_request_failed' },
  ]);
  assert.ok(PRE_CODE_FAILURE_REASONS.includes(JSON.parse(operator[0]).reason));
  assert.equal(`${output.join('')}\n${operator.join('')}`.includes(raw), false);
  assert.equal(`${output.join('')}\n${operator.join('')}`.includes('15551234567'), false);
  assert.equal(`${output.join('')}\n${operator.join('')}`.includes('/private/session'), false);
});

async function syncDirectoryForTest(directory) {
  const handle = await open(directory, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
}

async function commitFixture(prefix) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), prefix)));
  await chmod(root, 0o700);
  const session = path.join(root, 'ordinary');
  const stage = path.join(root, '.whatsapp-provision-stage-test');
  await mkdir(session, { mode: 0o700 });
  await mkdir(stage, { mode: 0o700 });
  await writeFile(path.join(session, 'creds.json'), 'old-synthetic', { mode: 0o600 });
  await writeFile(path.join(stage, 'creds.json'), 'new-synthetic', { mode: 0o600 });
  return {
    root,
    session,
    stage,
    oldDirectory: await stat(session),
    oldCredentials: await stat(path.join(session, 'creds.json')),
  };
}

for (const failurePoint of [
  'rename_old', 'rename_old_after_move', 'sync_after_old',
  'rename_stage', 'rename_stage_after_move', 'sync_after_stage',
  'move_failed_once', 'restore_old_once', 'sync_after_restore_once',
  'remove_failed_state_once',
]) {
  test(`commit restores exact old session before cleanup boundary: ${failurePoint}`, async () => {
    const fixture = await commitFixture('hermes-wa-boundary-pre-');
    let renameCalls = 0;
    let syncCalls = 0;
    const ops = {
      rename: async (...args) => {
        renameCalls += 1;
        if (failurePoint === 'rename_old_after_move' && renameCalls === 1) {
          await rename(...args);
          throw new Error('injected');
        }
        if (failurePoint === 'rename_stage_after_move' && renameCalls === 2) {
          await rename(...args);
          throw new Error('injected');
        }
        if ((failurePoint === 'rename_old' && renameCalls === 1)
            || (failurePoint === 'rename_stage' && renameCalls === 2)
            || (failurePoint === 'move_failed_once' && renameCalls === 3)
            || (failurePoint === 'restore_old_once' && renameCalls === 4)) {
          throw new Error('injected');
        }
        return rename(...args);
      },
      syncDirectory: async (...args) => {
        syncCalls += 1;
        if ((failurePoint === 'sync_after_old' && syncCalls === 1)
            || (['sync_after_stage', 'move_failed_once', 'restore_old_once',
              'sync_after_restore_once', 'remove_failed_state_once'].includes(failurePoint)
              && syncCalls === 2)
            || (failurePoint === 'sync_after_restore_once' && syncCalls === 3)) {
          throw new Error('injected');
        }
        return syncDirectoryForTest(...args);
      },
      remove: async (...args) => {
        if (failurePoint === 'remove_failed_state_once' && !ops.remove.failed) {
          ops.remove.failed = true;
          throw new Error('injected');
        }
        return rm(...args);
      },
    };
    try {
      await assert.rejects(
        commitStagedSession(fixture.stage, fixture.session, fixture.root, null, null, ops),
        /staged_commit_failed/,
      );
      const directory = await stat(fixture.session);
      const credentials = await stat(path.join(fixture.session, 'creds.json'));
      assert.equal(await readFile(path.join(fixture.session, 'creds.json'), 'utf8'), 'old-synthetic');
      assert.equal(directory.ino, fixture.oldDirectory.ino);
      assert.equal(directory.mode & 0o777, 0o700);
      assert.equal(credentials.ino, fixture.oldCredentials.ino);
      assert.equal(credentials.mode & 0o777, 0o600);
      await assert.rejects(stat(fixture.stage));
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
}

for (const failurePoint of ['remove_backup', 'sync_after_backup_delete']) {
  test(`commit preserves new canonical session after cleanup boundary: ${failurePoint}`, async () => {
    const fixture = await commitFixture('hermes-wa-boundary-post-');
    let syncCalls = 0;
    const ops = {
      remove: async (...args) => {
        if (failurePoint === 'remove_backup') throw new Error('injected');
        return rm(...args);
      },
      syncDirectory: async (...args) => {
        syncCalls += 1;
        if (failurePoint === 'sync_after_backup_delete' && syncCalls === 3) {
          throw new Error('injected');
        }
        return syncDirectoryForTest(...args);
      },
    };
    try {
      let observed;
      try {
        await commitStagedSession(
          fixture.stage, fixture.session, fixture.root, null, null, ops,
        );
      } catch (error) {
        observed = error;
      }
      assert.ok(observed instanceof ProvisioningCommitError);
      assert.equal(observed.code, 'cleanup_durability_uncertain');
      assert.equal(observed.retryable, false);
      assert.equal(await readFile(path.join(fixture.session, 'creds.json'), 'utf8'), 'new-synthetic');
      assert.equal((await stat(fixture.session)).mode & 0o777, 0o700);
      assert.equal((await stat(path.join(fixture.session, 'creds.json'))).mode & 0o777, 0o600);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
}

test('offline provisioning uses only requestPairingCode and persists canonical LID readiness', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-provision-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const { phone, phoneJid, lidJid } = identities();
  const ordinaryPhoneJid = phoneJid;
  const ordinaryLidJid = lidJid;
  const ordinaryCreds = authIdentity(ordinaryPhoneJid, ordinaryLidJid, 17);
  const sensitiveCreds = authIdentity(phoneJid, lidJid, 53);
  let pairingCalls = 0;
  let sendCalls = 0;
  let socket;
  try {
    await chmod(root, 0o700);
    await mkdir(ordinary, { mode: 0o700 });
    await writeFile(
      path.join(ordinary, 'creds.json'), JSON.stringify(ordinaryCreds), { mode: 0o600 },
    );
    const request = parseProvisioningRequest({
      version: 1,
      action: 'provision',
      role: 'sensitive',
      phone,
      ordinary_session: ordinary,
      sensitive_session: sensitive,
    });
    const result = await provisionOffline({
      request,
      canonicalizeJid: (value) => String(value).replace(/:\d+@/, '@'),
      useAuthState: async (session) => ({
        state: session === ordinary ? {
          creds: ordinaryCreds,
          keys: { get: async () => ({
            [ordinaryPhoneJid.split('@')[0]]: ordinaryLidJid.split('@')[0],
          }) },
        } : {
          creds: sensitiveCreds,
          keys: {
            get: async () => ({ [phoneJid.split('@')[0]]: lidJid.split('@')[0] }),
            set: async () => {},
          },
        },
        saveCreds: async () => {
          const creds = session === ordinary ? ordinaryCreds : sensitiveCreds;
          await writeFile(path.join(session, 'creds.json'), JSON.stringify(creds), { mode: 0o600 });
          await chmod(path.join(session, 'creds.json'), 0o600);
        },
      }),
      makeSocket: () => {
        socket = fakeSocket({
          phoneJid,
          lidJid,
          onPairingCode: () => { pairingCalls += 1; },
          update: () => ({ qr: 'provider-private-readiness' }),
        });
        socket.sendMessage = () => { sendCalls += 1; };
        queueMicrotask(() => socket.ev.emit('connection.update', { connection: 'open' }));
        return socket;
      },
      emitCode: (code) => assert.equal(code, 'A1B2C3D4'),
      timeoutMs: 2_000,
    });
    assert.deepEqual(result, { account_namespace: 's.whatsapp.net', lid_ready: true });
    assert.equal(pairingCalls, 1);
    assert.equal(sendCalls, 0);
    assert.equal(socket.endCalled, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('pairing request failure discards provider details and leaves the target absent', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-provision-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const { phone, phoneJid, lidJid } = identities();
  const ordinaryCreds = authIdentity(phoneJid, lidJid, 17);
  let socket;
  try {
    await chmod(root, 0o700);
    await mkdir(ordinary, { mode: 0o700 });
    const ordinaryBytes = JSON.stringify(ordinaryCreds);
    await writeFile(path.join(ordinary, 'creds.json'), ordinaryBytes, { mode: 0o600 });
    const ordinaryBefore = await stat(ordinary);
    const credentialsBefore = await stat(path.join(ordinary, 'creds.json'));
    const request = parseProvisioningRequest({
      version: 1,
      action: 'provision',
      role: 'sensitive',
      phone,
      ordinary_session: ordinary,
      sensitive_session: sensitive,
    });
    await assert.rejects(provisionOffline({
      request,
      canonicalizeJid: (value) => String(value).replace(/:\d+@/, '@'),
      useAuthState: async (session) => ({
        state: session === ordinary ? {
          creds: ordinaryCreds,
          keys: { get: async () => ({ [phone]: lidJid.split('@')[0] }) },
        } : { creds: {}, keys: {} },
        saveCreds: async () => {},
      }),
      makeSocket: () => {
        socket = fakeSocket({
          phoneJid,
          lidJid,
          onPairingCode: () => { throw new Error('raw provider response with identifiers'); },
          update: () => ({ qr: 'provider-private-readiness' }),
        });
        return socket;
      },
      emitCode: () => assert.fail('pairing code must not be emitted'),
      timeoutMs: 2_000,
    }), /pairing_request_failed/);
    assert.equal(socket.endCalled, true);
    assert.equal(await readFile(path.join(ordinary, 'creds.json'), 'utf8'), ordinaryBytes);
    assert.equal((await stat(ordinary)).ino, ordinaryBefore.ino);
    assert.equal((await stat(path.join(ordinary, 'creds.json'))).ino, credentialsBefore.ino);
    await assert.rejects(stat(sensitive), { code: 'ENOENT' });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('reprovision stages fresh auth, requests a fresh code, and preserves existing bytes and inode on failure', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-reprovision-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'3'.repeat(10)}`;
  const original = JSON.stringify({ registered: true, me: { id: `${phone}@s.whatsapp.net` } });
  let authPath;
  let pairingCalls = 0;
  try {
    await chmod(root, 0o700);
    await mkdir(ordinary, { mode: 0o755 });
    await writeFile(path.join(ordinary, 'creds.json'), original, { mode: 0o644 });
    await chmod(ordinary, 0o755);
    await chmod(path.join(ordinary, 'creds.json'), 0o644);
    const beforeDirectory = await stat(ordinary);
    const before = await stat(path.join(ordinary, 'creds.json'));
    const request = parseProvisioningRequest({
      version: 1,
      action: 'provision',
      reprovision: true,
      role: 'ordinary',
      phone,
      ordinary_session: ordinary,
      sensitive_session: sensitive,
    });
    await assert.rejects(provisionOffline({
      request,
      canonicalizeJid: (value) => String(value).replace(/:\d+@/, '@'),
      useAuthState: async (session) => {
        authPath = session;
        return {
          // Even a misleading registered flag in the newly staged provider
          // object must not suppress the explicit fresh-code request.
          state: { creds: { registered: true }, keys: { get: async () => ({}), set: async () => {} } },
          saveCreds: async () => {
            await writeFile(path.join(session, 'creds.json'), '{}', { mode: 0o600 });
          },
        };
      },
      makeSocket: ({ auth }) => {
        const ev = new EventEmitter();
        const socket = {
          ev,
          user: { id: `${phone}@s.whatsapp.net` },
          requestPairingCode: async () => { pairingCalls += 1; return 'R3PR9V1S'; },
          end() {},
        };
        queueMicrotask(() => ev.emit('connection.update', { qr: 'provider-private-readiness' }));
        queueMicrotask(() => ev.emit('connection.update', { connection: 'close' }));
        return socket;
      },
      emitCode: () => {},
      timeoutMs: 2_000,
    }), /connection_closed/);
    const after = await stat(path.join(ordinary, 'creds.json'));
    assert.notEqual(authPath, ordinary);
    assert.match(path.basename(authPath), /^\.whatsapp-provision-stage-/);
    assert.equal(pairingCalls, 1);
    assert.equal(await readFile(path.join(ordinary, 'creds.json'), 'utf8'), original);
    assert.equal(after.ino, before.ino);
    assert.equal(after.mode & 0o777, 0o644);
    assert.equal((await stat(ordinary)).ino, beforeDirectory.ino);
    assert.equal((await stat(ordinary)).mode & 0o777, 0o755);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('explicit reprovision replaces unsafe legacy auth with fresh owner-only state', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-legacy-replace-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'9'.repeat(10)}`;
  const lid = '424242424';
  let pairingCalls = 0;
  try {
    await chmod(root, 0o700);
    await mkdir(ordinary, { mode: 0o755 });
    await writeFile(path.join(ordinary, 'creds.json'), 'legacy-bytes', { mode: 0o644 });
    await chmod(ordinary, 0o755);
    await chmod(path.join(ordinary, 'creds.json'), 0o644);
    const request = parseProvisioningRequest({
      version: 1,
      action: 'provision',
      reprovision: true,
      role: 'ordinary',
      phone,
      ordinary_session: ordinary,
      sensitive_session: sensitive,
    });
    const result = await provisionOffline({
      request,
      canonicalizeJid: (value) => String(value).replace(/:\d+@/, '@'),
      useAuthState: async (session) => {
        assert.notEqual(session, ordinary, 'legacy auth must never be opened by provider code');
        const creds = { registered: false };
        return {
          state: {
            creds,
            keys: {
              get: async () => ({ [phone]: lid }),
              set: async () => {},
            },
          },
          saveCreds: async () => {
            creds.registered = true;
            creds.me = { id: `${phone}@s.whatsapp.net`, lid: `${lid}@lid` };
            await writeFile(path.join(session, 'creds.json'), JSON.stringify(creds), { mode: 0o600 });
          },
        };
      },
      makeSocket: () => {
        const ev = new EventEmitter();
        const socket = {
          ev,
          user: { id: `${phone}@s.whatsapp.net` },
          signalRepository: { lidMapping: { getLIDForPN: async () => `${lid}@lid` } },
          requestPairingCode: async () => { pairingCalls += 1; return 'M3GYC9DE'; },
          end() {},
        };
        queueMicrotask(() => ev.emit('connection.update', { qr: 'provider-private-readiness' }));
        queueMicrotask(() => ev.emit('connection.update', { connection: 'open' }));
        return socket;
      },
      emitCode: (code) => assert.equal(code, 'M3GYC9DE'),
      timeoutMs: 2_000,
    });
    assert.deepEqual(result, { account_namespace: 's.whatsapp.net', lid_ready: true });
    assert.equal(pairingCalls, 1);
    assert.equal((await stat(ordinary)).mode & 0o777, 0o700);
    assert.equal((await stat(path.join(ordinary, 'creds.json'))).mode & 0o777, 0o600);
    assert.notEqual(await readFile(path.join(ordinary, 'creds.json'), 'utf8'), 'legacy-bytes');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('post-install staged failure restores the exact unsafe legacy tree', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-rollback-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'8'.repeat(10)}`;
  const original = 'legacy-exact-bytes';
  try {
    await chmod(root, 0o700);
    await mkdir(ordinary, { mode: 0o755 });
    await writeFile(path.join(ordinary, 'creds.json'), original, { mode: 0o644 });
    await chmod(ordinary, 0o755);
    await chmod(path.join(ordinary, 'creds.json'), 0o644);
    const beforeDirectory = await stat(ordinary);
    const beforeCredentials = await stat(path.join(ordinary, 'creds.json'));
    const request = parseProvisioningRequest({
      version: 1,
      action: 'provision',
      reprovision: true,
      role: 'ordinary',
      phone,
      ordinary_session: ordinary,
      sensitive_session: sensitive,
    });
    await assert.rejects(provisionOffline({
      request,
      canonicalizeJid: (value) => String(value).replace(/:\d+@/, '@'),
      useAuthState: async (session) => {
        assert.notEqual(session, ordinary, 'legacy auth must never be opened by provider code');
        const creds = { registered: false };
        return {
          state: {
            creds,
            keys: {
              get: async () => ({ [phone]: '818181818' }),
              set: async () => {},
            },
          },
          saveCreds: async () => {
            creds.registered = true;
            creds.me = { id: `${phone}@s.whatsapp.net`, lid: '818181818@lid' };
            await writeFile(path.join(session, 'creds.json'), JSON.stringify(creds), { mode: 0o600 });
          },
        };
      },
      makeSocket: () => {
        const ev = new EventEmitter();
        const socket = {
          ev,
          user: { id: `${phone}@s.whatsapp.net` },
          signalRepository: { lidMapping: { getLIDForPN: async () => '818181818@lid' } },
          requestPairingCode: async () => 'R9MMB4CK',
          end() {},
        };
        queueMicrotask(() => ev.emit('connection.update', { qr: 'provider-private-readiness' }));
        queueMicrotask(() => ev.emit('connection.update', { connection: 'open' }));
        return socket;
      },
      emitCode: () => {},
      beforeDurableConfirmation: async () => { throw new Error('injected_commit_failure'); },
      timeoutMs: 2_000,
    }), /provisioning_failed/);
    const afterDirectory = await stat(ordinary);
    const afterCredentials = await stat(path.join(ordinary, 'creds.json'));
    assert.equal(await readFile(path.join(ordinary, 'creds.json'), 'utf8'), original);
    assert.equal(afterDirectory.ino, beforeDirectory.ino);
    assert.equal(afterDirectory.mode & 0o777, 0o755);
    assert.equal(afterCredentials.ino, beforeCredentials.ino);
    assert.equal(afterCredentials.mode & 0o777, 0o644);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('ordinary reuse rejects unsafe legacy auth before provider access', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-unsafe-reuse-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'5'.repeat(10)}`;
  try {
    await chmod(root, 0o700);
    await mkdir(ordinary, { mode: 0o755 });
    const credentials = path.join(ordinary, 'creds.json');
    await writeFile(credentials, JSON.stringify({
      registered: true,
      me: { id: `${phone}@s.whatsapp.net` },
    }), { mode: 0o644 });
    await chmod(credentials, 0o644);
    await chmod(ordinary, 0o755);
    const beforeDirectory = await stat(ordinary);
    const before = await stat(credentials);
    const request = parseProvisioningRequest({
      version: 1,
      action: 'provision',
      reprovision: false,
      role: 'ordinary',
      phone,
      ordinary_session: ordinary,
      sensitive_session: sensitive,
    });
    await assert.rejects(provisionOffline({
      request,
      useAuthState: async () => assert.fail('unsafe reuse must fail before provider auth'),
      makeSocket: () => assert.fail('unsafe reuse must fail before socket creation'),
      canonicalizeJid: (value) => String(value),
      emitCode: () => assert.fail('unsafe reuse must not emit a code'),
      timeoutMs: 2_000,
    }), /session_path_unsafe/);
    const after = await stat(credentials);
    assert.equal((await stat(ordinary)).ino, beforeDirectory.ino);
    assert.equal((await stat(ordinary)).mode & 0o777, 0o755);
    assert.equal(after.mode & 0o777, 0o644);
    assert.equal(after.ino, before.ino);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('cross-role lock permits only one concurrent same-account provisioning attempt', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-race-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'2'.repeat(10)}`;
  let releaseFirst;
  let lockHeld = false;
  const acquireLock = () => {
    if (lockHeld) throw new Error('provisioning_lock_unavailable');
    lockHeld = true;
    return Object.freeze({ release() { lockHeld = false; } });
  };
  const firstMayContinue = new Promise((resolve) => { releaseFirst = resolve; });
  try {
    await chmod(root, 0o700);
    const request = parseProvisioningRequest({
      version: 1,
      action: 'provision',
      role: 'ordinary',
      phone,
      ordinary_session: ordinary,
      sensitive_session: sensitive,
    });
    const first = provisionOffline({
      request,
      canonicalizeJid: (value) => String(value).replace(/:\d+@/, '@'),
      useAuthState: async (session) => ({
        state: {
          creds: { registered: false },
          keys: {
            get: async () => ({ [phone]: '777777777' }),
            set: async () => {},
          },
        },
        saveCreds: async () => {
          await writeFile(path.join(session, 'creds.json'), '{}', { mode: 0o600 });
        },
      }),
      makeSocket: () => {
        const ev = new EventEmitter();
        const socket = {
          ev,
          user: { id: `${phone}@s.whatsapp.net` },
          signalRepository: { lidMapping: { getLIDForPN: async () => '777777777@lid' } },
          requestPairingCode: async () => 'R4CEC9DE',
          end() {},
        };
        queueMicrotask(async () => {
          ev.emit('connection.update', { qr: 'provider-private-readiness' });
          await firstMayContinue;
          ev.emit('connection.update', { connection: 'open' });
        });
        return socket;
      },
      emitCode: () => {},
      timeoutMs: 2_000,
      acquireLock,
    });
    await assert.rejects(provisionOffline({
      request: Object.freeze({ ...request, role: 'sensitive', session: sensitive }),
      useAuthState: async () => assert.fail('loser must fail before provider auth'),
      makeSocket: () => assert.fail('loser must fail before socket creation'),
      canonicalizeJid: (value) => String(value),
      emitCode: () => {},
      timeoutMs: 2_000,
      acquireLock,
    }), /provisioning_lock_unavailable/);
    releaseFirst();
    assert.deepEqual(await first, { account_namespace: 's.whatsapp.net', lid_ready: true });
    assert.equal(await stat(ordinary).then((item) => item.mode & 0o777), 0o700);
    assert.equal(await stat(path.join(ordinary, 'creds.json')).then((item) => item.mode & 0o777), 0o600);
  } finally {
    releaseFirst?.();
    await rm(root, { recursive: true, force: true });
  }
});

async function restartJourney(mode = 'success') {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-restart-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'3'.repeat(10)}`;
  const lidUser = '737373737';
  const creds = { registered: false };
  const sockets = [];
  let codeCount = 0;
  let codeEmittedBeforeRestart = false;
  let saveCount = 0;
  await chmod(root, 0o700);
  const request = parseProvisioningRequest({
    version: 1,
    action: 'provision',
    role: 'ordinary',
    phone,
    ordinary_session: ordinary,
    sensitive_session: sensitive,
  });
  const tick = () => new Promise(resolve => setImmediate(resolve));
  const useAuthState = async session => ({
    state: {
      creds,
      keys: {
        get: async () => ({ [phone]: lidUser }),
        set: async () => {},
      },
    },
    saveCreds: async () => {
      saveCount += 1;
      if (mode === 'save_failure') throw new Error('injected_save_failure');
      await writeFile(path.join(session, 'creds.json'), JSON.stringify(creds), { mode: 0o600 });
    },
  });
  const makeSocket = () => {
    const ev = new EventEmitter();
    const generation = sockets.length + 1;
    const socket = {
      ev,
      generation,
      user: { id: `${phone}@s.whatsapp.net` },
      signalRepository: { lidMapping: { getLIDForPN: async () => `${lidUser}@lid` } },
      requestPairingCode: async () => 'R3START1',
      ended: false,
      end() { this.ended = true; },
    };
    sockets.push(socket);
    queueMicrotask(async () => {
      if (generation === 1) {
        ev.emit('connection.update', { qr: 'provider-private-readiness' });
        await tick();
        if (mode !== 'restart_before_registration') {
          creds.registered = true;
          creds.me = { id: `${phone}@s.whatsapp.net`, lid: `${lidUser}@lid` };
          ev.emit('creds.update', { registered: true, me: creds.me });
          await tick();
        }
        codeEmittedBeforeRestart = codeCount === 1;
        ev.emit('connection.update', {
          connection: 'close',
          lastDisconnect: { error: { output: { statusCode: 515 } } },
        });
        await tick();
        // Must be ignored after the first generation is fenced.
        ev.emit('connection.update', { connection: 'open' });
      } else if (mode === 'repeated_restart') {
        ev.emit('connection.update', {
          connection: 'close',
          lastDisconnect: { error: { output: { statusCode: 515 } } },
        });
      } else if (mode !== 'reconnect_timeout') {
        await tick();
        ev.emit('connection.update', { connection: 'open' });
      }
    });
    return socket;
  };
  try {
    const outcome = await provisionOffline({
      request,
      useAuthState,
      makeSocket,
      canonicalizeJid: value => String(value).replace(/:\d+@/, '@'),
      emitCode: () => { codeCount += 1; },
      timeoutMs: mode === 'reconnect_timeout' ? 75 : 2_000,
    });
    return {
      outcome, root, ordinary, sockets, codeCount, codeEmittedBeforeRestart, saveCount,
    };
  } catch (error) {
    return {
      error, root, ordinary, sockets, codeCount, codeEmittedBeforeRestart, saveCount,
    };
  }
}

test('accepted pairing survives one 515 restart and commits only after reauthenticated open', async () => {
  const fixture = await restartJourney();
  try {
    assert.deepEqual(fixture.outcome, {
      account_namespace: 's.whatsapp.net', lid_ready: true,
    });
    assert.equal(fixture.codeCount, 1);
    assert.equal(fixture.codeEmittedBeforeRestart, true);
    assert.equal(fixture.sockets.length, 2);
    assert.equal(fixture.sockets[0].ended, true);
    assert.equal(fixture.sockets[1].ended, true);
    assert.ok(fixture.saveCount >= 2, 'restart and authenticated open must each drain creds');
    assert.equal((await stat(fixture.ordinary)).mode & 0o777, 0o700);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('515 recovery rejects pre-registration, repeated restart, save failure, and reconnect timeout', async () => {
  const cases = [
    ['restart_before_registration', /connection_closed/],
    ['repeated_restart', /connection_closed/],
    ['save_failure', /credential_persistence_failed/],
    ['reconnect_timeout', /provisioning_timeout/],
  ];
  for (const [mode, expected] of cases) {
    const fixture = await restartJourney(mode);
    try {
      assert.match(String(fixture.error?.message || ''), expected, mode);
      assert.equal(fixture.codeCount, 1, mode);
      assert.equal(existsSync(fixture.ordinary), false, mode);
      assert.ok(fixture.sockets.length <= 2, mode);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test('open before QR waits for its active generation to emit a pairing code', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-open-code-race-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'1'.repeat(10)}`;
  const phoneJid = `${phone}@s.whatsapp.net`;
  const lidJid = '171717171@lid';
  const creds = { registered: true, me: { id: phoneJid, lid: lidJid } };
  const pairingStarted = deferred();
  const pairingResult = deferred();
  const credentialSaveStarted = deferred();
  const milestones = [];
  let provisioningState = 'pending';
  let socket;
  await chmod(root, 0o700);
  const request = parseProvisioningRequest({
    version: 1, action: 'provision', role: 'ordinary', phone,
    ordinary_session: ordinary, sensitive_session: sensitive,
  });
  const provisioning = provisionOffline({
    request,
    canonicalizeJid: value => String(value).replace(/:\d+@/, '@'),
    useAuthState: async session => ({
      state: {
        creds,
        keys: { get: async () => ({ [phone]: lidJid.split('@')[0] }), set: async () => {} },
      },
      saveCreds: async () => {
        credentialSaveStarted.resolve();
        await writeFile(path.join(session, 'creds.json'), JSON.stringify(creds), { mode: 0o600 });
      },
    }),
    makeSocket: () => {
      const ev = new EventEmitter();
      socket = {
        ev,
        user: { id: phoneJid },
        signalRepository: { lidMapping: { getLIDForPN: async () => lidJid } },
        requestPairingCode: async () => {
          pairingStarted.resolve();
          return pairingResult.promise;
        },
        end() {},
      };
      return socket;
    },
    emitCode: code => {
      assert.equal(code, 'P3ND1NG9');
      milestones.push('code');
    },
    beforeDurableConfirmation: async () => { milestones.push('commit'); },
    timeoutMs: 2_000,
  });
  void provisioning.then(
    () => { provisioningState = 'completed'; },
    () => { provisioningState = 'failed'; },
  );
  try {
    await waitFor(() => Boolean(socket), 'socket was not created');
    socket.ev.emit('connection.update', { connection: 'open' });
    const firstTransition = await Promise.race([
      credentialSaveStarted.promise.then(() => 'credential_save_started'),
      new Promise(resolve => setImmediate(() => resolve('event_loop_turn'))),
    ]);
    assert.equal(firstTransition, 'event_loop_turn');
    assert.equal(provisioningState, 'pending');
    assert.deepEqual(milestones, []);
    assert.equal(existsSync(ordinary), false, 'session committed before pairing code emission');

    socket.ev.emit('connection.update', { connection: 'connecting' });
    const secondTransition = await Promise.race([
      credentialSaveStarted.promise.then(() => 'credential_save_started'),
      new Promise(resolve => setImmediate(() => resolve('event_loop_turn'))),
    ]);
    assert.equal(secondTransition, 'event_loop_turn');
    assert.equal(provisioningState, 'pending');

    socket.ev.emit('connection.update', { qr: 'provider-private-readiness' });
    await pairingStarted.promise;
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(provisioningState, 'pending');
    assert.deepEqual(milestones, []);
    assert.equal(existsSync(ordinary), false, 'session committed during pairing-code request');

    pairingResult.resolve('P3ND1NG9');
    assert.deepEqual(await provisioning, {
      account_namespace: 's.whatsapp.net', lid_ready: true,
    });
    assert.deepEqual(milestones, ['code', 'commit']);
  } finally {
    pairingResult.resolve('P3ND1NG9');
    await provisioning.catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});

test('close ingress suppresses a blocked pairing code before non-515 failure', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-pair-close-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'2'.repeat(10)}`;
  const pairingStarted = deferred();
  const pairingResult = deferred();
  let socket;
  let codeCount = 0;
  await chmod(root, 0o700);
  const request = parseProvisioningRequest({
    version: 1, action: 'provision', role: 'ordinary', phone,
    ordinary_session: ordinary, sensitive_session: sensitive,
  });
  const provisioning = provisionOffline({
    request,
    useAuthState: async session => ({
      state: {
        creds: { registered: false },
        keys: { get: async () => ({}), set: async () => {} },
      },
      saveCreds: async () => {
        await writeFile(path.join(session, 'creds.json'), '{}', { mode: 0o600 });
      },
    }),
    makeSocket: () => {
      const ev = new EventEmitter();
      socket = {
        ev,
        requestPairingCode: async () => {
          pairingStarted.resolve();
          return pairingResult.promise;
        },
        end() {},
      };
      return socket;
    },
    emitCode: () => { codeCount += 1; },
    timeoutMs: 2_000,
  });
  try {
    await waitFor(() => Boolean(socket), 'socket was not created');
    socket.ev.emit('connection.update', { qr: 'provider-private-readiness' });
    await pairingStarted.promise;
    socket.ev.emit('connection.update', {
      connection: 'close',
      lastDisconnect: { error: { output: { statusCode: 500 } } },
    });
    pairingResult.resolve('D3ADC0DE');
    const result = await Promise.race([
      provisioning.then(() => ({ outcome: 'success' }), error => ({ error })),
      new Promise(resolve => setTimeout(() => resolve({ outcome: 'still_pending' }), 250)),
    ]);
    assert.match(String(result.error?.message || ''), /connection_closed/);
    assert.equal(codeCount, 0);
    assert.equal(existsSync(ordinary), false);
  } finally {
    pairingResult.resolve('D3ADC0DE');
    await provisioning.catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});

test('515 fences an old open already blocked in credential save until replacement opens', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-old-open-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'4'.repeat(10)}`;
  const phoneJid = `${phone}@s.whatsapp.net`;
  const lidJid = '474747474@lid';
  const creds = { registered: false };
  const firstSaveStarted = deferred();
  const releaseFirstSave = deferred();
  const sockets = [];
  let saveCalls = 0;
  let codeCount = 0;
  await chmod(root, 0o700);
  const request = parseProvisioningRequest({
    version: 1, action: 'provision', role: 'ordinary', phone,
    ordinary_session: ordinary, sensitive_session: sensitive,
  });
  const provisioning = provisionOffline({
    request,
    canonicalizeJid: value => String(value).replace(/:\d+@/, '@'),
    useAuthState: async session => ({
      state: {
        creds,
        keys: { get: async () => ({ [phone]: lidJid.split('@')[0] }), set: async () => {} },
      },
      saveCreds: async () => {
        saveCalls += 1;
        if (saveCalls === 1) {
          firstSaveStarted.resolve();
          await releaseFirstSave.promise;
        }
        await writeFile(path.join(session, 'creds.json'), JSON.stringify(creds), { mode: 0o600 });
      },
    }),
    makeSocket: () => {
      const ev = new EventEmitter();
      const socket = {
        ev,
        user: { id: phoneJid },
        signalRepository: { lidMapping: { getLIDForPN: async () => lidJid } },
        requestPairingCode: async () => 'G3N3R4T1',
        end() {},
      };
      sockets.push(socket);
      return socket;
    },
    emitCode: () => { codeCount += 1; },
    timeoutMs: 2_000,
  });
  try {
    await waitFor(() => sockets.length === 1, 'first socket was not created');
    sockets[0].ev.emit('connection.update', { qr: 'provider-private-readiness' });
    await waitFor(() => codeCount === 1, 'pairing code was not emitted');
    creds.registered = true;
    creds.me = { id: phoneJid, lid: lidJid };
    sockets[0].ev.emit('connection.update', { connection: 'open' });
    await firstSaveStarted.promise;
    sockets[0].ev.emit('connection.update', {
      connection: 'close',
      lastDisconnect: { error: { output: { statusCode: 515 } } },
    });
    releaseFirstSave.resolve();
    await waitFor(() => sockets.length === 2, 'replacement socket was not created');
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(existsSync(ordinary), false, 'old generation committed before replacement open');
    let settled = false;
    provisioning.finally(() => { settled = true; }).catch(() => {});
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(settled, false);
    sockets[1].ev.emit('connection.update', { connection: 'open' });
    assert.deepEqual(await provisioning, {
      account_namespace: 's.whatsapp.net', lid_ready: true,
    });
    assert.equal(codeCount, 1);
  } finally {
    releaseFirstSave.resolve();
    if (sockets[1]) sockets[1].ev.emit('connection.update', { connection: 'open' });
    await provisioning.catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});

test('deadline cannot settle or release the lock after canonical rename begins', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-commit-timeout-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'5'.repeat(10)}`;
  const phoneJid = `${phone}@s.whatsapp.net`;
  const lidJid = '575757575@lid';
  const creds = { registered: true, me: { id: phoneJid, lid: lidJid } };
  const confirmationEntered = deferred();
  const releaseConfirmation = deferred();
  const sockets = [];
  let lockHeld = false;
  let releaseCount = 0;
  await chmod(root, 0o700);
  const request = parseProvisioningRequest({
    version: 1, action: 'provision', role: 'ordinary', phone,
    ordinary_session: ordinary, sensitive_session: sensitive,
  });
  const provisioning = provisionOffline({
    request,
    canonicalizeJid: value => String(value).replace(/:\d+@/, '@'),
    useAuthState: async session => ({
      state: {
        creds,
        keys: { get: async () => ({ [phone]: lidJid.split('@')[0] }), set: async () => {} },
      },
      saveCreds: async () => {
        await writeFile(path.join(session, 'creds.json'), JSON.stringify(creds), { mode: 0o600 });
      },
    }),
    makeSocket: () => {
      const ev = new EventEmitter();
      const socket = {
        ev,
        user: { id: phoneJid },
        signalRepository: { lidMapping: { getLIDForPN: async () => lidJid } },
        requestPairingCode: async () => 'C4N1N1C4',
        end() {},
      };
      sockets.push(socket);
      return socket;
    },
    emitCode: code => assert.equal(code, 'C4N1N1C4'),
    timeoutMs: 40,
    acquireLock: () => {
      lockHeld = true;
      return Object.freeze({ release() { lockHeld = false; releaseCount += 1; } });
    },
    beforeDurableConfirmation: async () => {
      confirmationEntered.resolve();
      await releaseConfirmation.promise;
    },
  });
  try {
    await waitFor(() => sockets.length === 1, 'socket was not created');
    sockets[0].ev.emit('connection.update', { qr: 'provider-private-readiness' });
    sockets[0].ev.emit('connection.update', { connection: 'open' });
    await confirmationEntered.promise;
    assert.equal(existsSync(path.join(ordinary, 'creds.json')), true, 'canonical rename did not occur');
    const early = await Promise.race([
      provisioning.then(() => 'success', () => 'failure'),
      new Promise(resolve => setTimeout(() => resolve('pending'), 100)),
    ]);
    assert.equal(early, 'pending');
    assert.equal(lockHeld, true);
    assert.equal(releaseCount, 0);
    releaseConfirmation.resolve();
    assert.deepEqual(await provisioning, {
      account_namespace: 's.whatsapp.net', lid_ready: true,
    });
    assert.equal(lockHeld, false);
    assert.equal(releaseCount, 1);
  } finally {
    releaseConfirmation.resolve();
    await provisioning.catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});

test('late credential writes in the final drain quiesce before timeout releases the lock', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-wa-creds-drain-')));
  const ordinary = path.join(root, 'ordinary');
  const sensitive = path.join(root, 'sensitive');
  const phone = `1${'7'.repeat(10)}`;
  const phoneJid = `${phone}@s.whatsapp.net`;
  const lidJid = '676767676@lid';
  const creds = { registered: true, me: { id: phoneJid, lid: lidJid } };
  const firstSaveStarted = deferred();
  const releaseFirstSave = deferred();
  let socket;
  let saveCalls = 0;
  let lockHeld = false;
  let releaseCount = 0;
  await chmod(root, 0o700);
  const request = parseProvisioningRequest({
    version: 1, action: 'provision', role: 'ordinary', phone,
    ordinary_session: ordinary, sensitive_session: sensitive,
  });
  const provisioning = provisionOffline({
    request,
    canonicalizeJid: value => String(value).replace(/:\d+@/, '@'),
    useAuthState: async session => ({
      state: {
        creds,
        keys: { get: async () => ({ [phone]: lidJid.split('@')[0] }), set: async () => {} },
      },
      saveCreds: async () => {
        saveCalls += 1;
        if (saveCalls === 1) {
          firstSaveStarted.resolve();
          await releaseFirstSave.promise;
        }
        await writeFile(path.join(session, 'creds.json'), JSON.stringify(creds), { mode: 0o600 });
      },
    }),
    makeSocket: () => {
      const ev = new EventEmitter();
      socket = {
        ev,
        user: { id: phoneJid },
        signalRepository: { lidMapping: { getLIDForPN: async () => lidJid } },
        requestPairingCode: async () => 'D4R41N3D',
        end() {},
      };
      return socket;
    },
    emitCode: code => assert.equal(code, 'D4R41N3D'),
    timeoutMs: 40,
    acquireLock: () => {
      lockHeld = true;
      return Object.freeze({ release() { lockHeld = false; releaseCount += 1; } });
    },
  });
  try {
    await waitFor(() => Boolean(socket), 'socket was not created');
    socket.ev.emit('creds.update', { late: true });
    socket.ev.emit('connection.update', { qr: 'provider-private-readiness' });
    socket.ev.emit('connection.update', { connection: 'open' });
    await firstSaveStarted.promise;
    const early = await Promise.race([
      provisioning.then(() => 'success', () => 'failure'),
      new Promise(resolve => setTimeout(() => resolve('pending'), 100)),
    ]);
    assert.equal(early, 'pending');
    assert.equal(lockHeld, true);
    assert.equal(releaseCount, 0);
    socket.ev.emit('creds.update', { fenced: true });
    releaseFirstSave.resolve();
    await assert.rejects(provisioning, /provisioning_timeout/);
    assert.equal(saveCalls, 2, 'fenced late event escaped the final credential drain');
    assert.equal(lockHeld, false);
    assert.equal(releaseCount, 1);
    assert.equal(existsSync(ordinary), false);
  } finally {
    releaseFirstSave.resolve();
    await provisioning.catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});
