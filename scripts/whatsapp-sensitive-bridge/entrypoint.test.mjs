import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  lstatSync,
  mkdtempSync,
  realpathSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseCanonicalArgs, runSensitiveBridge } from './sensitive_bridge.js';
import { initializeReceiverReplayAuthority } from './replay_authority.js';
import { SessionPathGuard } from './session_paths.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SENSITIVE = '15551234567@s.whatsapp.net';
const ORDINARY = SENSITIVE;
const DIFFERENT = '15559876543@s.whatsapp.net';
const SESSION_ROOT = mkdtempSync(path.join(realpathSync.native(tmpdir()), 'hermes-entrypoint-'));
const SENSITIVE_SESSION = path.join(SESSION_ROOT, 'sensitive');
const ORDINARY_SESSION = path.join(SESSION_ROOT, 'ordinary');
mkdirSync(ORDINARY_SESSION, { mode: 0o700 });
mkdirSync(SENSITIVE_SESSION, { mode: 0o700 });
const REPLAY = initializeReceiverReplayAuthority(path.join(SESSION_ROOT, 'receiver-replay'));

function args(overrides = {}) {
  const values = {
    '--port': '31873',
    ...overrides,
  };
  return Object.entries(values).flat();
}

function launchEnv(overrides = {}) {
  const ordinaryStat = lstatSync(ORDINARY_SESSION, { bigint: true });
  const sensitiveStat = lstatSync(SENSITIVE_SESSION, { bigint: true });
  const launch = {
    version: 2,
    process_generation: 'a'.repeat(64),
    configured_account_jid: SENSITIVE,
    profile: 'juno',
    mode: 'sensitive-outbound-only',
    replay: REPLAY,
    ordinary: {
      adapter_generation: 'b'.repeat(64), runtime_id: 'ordinary-runtime',
      socket_generation: 1, account_phone_jid: SENSITIVE,
      account_lid_jid: '90909090909@lid', session_path: ORDINARY_SESSION,
      session_identity: `${ordinaryStat.dev}:${ordinaryStat.ino}`,
      manifest_sha256: 'c'.repeat(64), source_sha256: 'd'.repeat(64),
      launcher_sha256: 'e'.repeat(64),
    },
    sensitive: {
      session_path: SENSITIVE_SESSION,
      session_identity: `${sensitiveStat.dev}:${sensitiveStat.ino}`,
      credential_identity: '1:4', device_identity_sha256: 'f'.repeat(64),
      credential_tree_sha256: '0'.repeat(64), account_phone_jid: SENSITIVE,
      account_lid_jid: '90909090909@lid',
    },
    ...overrides,
  };
  return { HERMES_INTERNAL_WHATSAPP_SENSITIVE_LAUNCH: JSON.stringify(launch) };
}

test('canonical launcher requires the same exact account identity and refuses injection arguments', () => {
  const parsed = parseCanonicalArgs(args(), launchEnv());
  assert.ok(parsed.sessionPathGuard instanceof SessionPathGuard);
  assert.deepEqual({ ...parsed, sessionPathGuard: undefined }, {
    port: 31873,
    sessionDir: SENSITIVE_SESSION,
    ordinarySessionDir: ORDINARY_SESSION,
    sessionPathGuard: undefined,
    sensitiveAccountJid: SENSITIVE,
    ordinaryAccountJid: ORDINARY,
    launch: parsed.launch,
    replayIdentity: parsed.replayIdentity,
  });
  assert.throws(
    () => parseCanonicalArgs(args(), launchEnv({ configured_account_jid: DIFFERENT })),
    /sealed account topology mismatch/,
  );
  assert.throws(
    () => parseCanonicalArgs([...args(), '--bridge-script', '/tmp/custom.js'], launchEnv()),
    /invalid canonical sensitive bridge arguments/,
  );
  assert.throws(
    () => parseCanonicalArgs([...args(), '--ordinary-session', ORDINARY_SESSION], launchEnv()),
    /invalid canonical sensitive bridge arguments/,
  );
  const nestedOrdinary = path.join(SENSITIVE_SESSION, 'ordinary');
  mkdirSync(nestedOrdinary, { mode: 0o700 });
  assert.throws(
    () => parseCanonicalArgs(args(), launchEnv({
      ordinary: {
        ...JSON.parse(launchEnv().HERMES_INTERNAL_WHATSAPP_SENSITIVE_LAUNCH).ordinary,
        session_path: nestedOrdinary,
      },
    })),
    /separate sensitive session path required/,
  );
});

test('missing inherited capability remains disabled before argument parsing or filesystem access', async () => {
  await assert.rejects(
    runSensitiveBridge({ argv: ['--not-even-parsed'], env: {} }),
    /sensitive delivery is disabled/,
  );
});

test('sealed launch rejects either session symlinked to the other real directory', () => {
  for (const direction of ['sensitive-to-ordinary', 'ordinary-to-sensitive']) {
    const root = mkdtempSync(path.join(realpathSync.native(tmpdir()), 'hermes-entry-alias-'));
    const sensitive = path.join(root, 'sensitive');
    const ordinary = path.join(root, 'ordinary');
    if (direction === 'sensitive-to-ordinary') {
      mkdirSync(ordinary, { mode: 0o700 });
      symlinkSync(ordinary, sensitive, 'dir');
    } else {
      mkdirSync(sensitive, { mode: 0o700 });
      symlinkSync(sensitive, ordinary, 'dir');
    }
    assert.throws(
      () => parseCanonicalArgs(args(), launchEnv({
        ordinary: {
          ...JSON.parse(launchEnv().HERMES_INTERNAL_WHATSAPP_SENSITIVE_LAUNCH).ordinary,
          session_path: ordinary,
        },
        sensitive: {
          ...JSON.parse(launchEnv().HERMES_INTERNAL_WHATSAPP_SENSITIVE_LAUNCH).sensitive,
          session_path: sensitive,
          session_identity: '1:1',
        },
      })),
      /sensitive session path validation failed/,
    );
  }
});

test('canonical module graph imports without loading any ordinary bridge module', () => {
  const result = spawnSync(process.execPath, [
    '--no-warnings',
    '--experimental-loader', path.join(HERE, 'isolation_loader.mjs'),
    '--input-type=module',
    '--eval', "await import('./sensitive_bridge.js')",
  ], { cwd: HERE, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
});

test('direct sensitive core is inert and launcher sanitizes startup failure', () => {
  const result = spawnSync(process.execPath, [path.join(HERE, 'sensitive_bridge.js')], {
    cwd: HERE,
    encoding: 'utf8',
    env: {},
  });
  assert.equal(result.status, 0);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
  const launched = spawnSync(process.execPath, [path.join(HERE, 'launcher.js')], {
    cwd: HERE,
    encoding: 'utf8',
    env: {},
  });
  assert.equal(launched.status, 1);
  assert.equal(launched.stdout, '');
  assert.equal(launched.stderr, '');
});
