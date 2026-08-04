import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseCanonicalArgs, runSensitiveBridge } from './sensitive_bridge.js';
import { SessionPathGuard } from './session_paths.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SENSITIVE = '15551234567@s.whatsapp.net';
const ORDINARY = '15559876543@s.whatsapp.net';
const SESSION_ROOT = mkdtempSync(path.join(realpathSync.native(tmpdir()), 'hermes-entrypoint-'));
const SENSITIVE_SESSION = path.join(SESSION_ROOT, 'sensitive');
const ORDINARY_SESSION = path.join(SESSION_ROOT, 'ordinary');
mkdirSync(ORDINARY_SESSION, { mode: 0o700 });

function args(overrides = {}) {
  const values = {
    '--port': '31873',
    '--session': SENSITIVE_SESSION,
    '--ordinary-session': ORDINARY_SESSION,
    '--sensitive-account-jid': SENSITIVE,
    '--ordinary-account-jid': ORDINARY,
    ...overrides,
  };
  return Object.entries(values).flat();
}

test('canonical launcher requires distinct exact account identities and refuses injection arguments', () => {
  const parsed = parseCanonicalArgs(args());
  assert.ok(parsed.sessionPathGuard instanceof SessionPathGuard);
  assert.deepEqual({ ...parsed, sessionPathGuard: undefined }, {
    port: 31873,
    sessionDir: SENSITIVE_SESSION,
    ordinarySessionDir: ORDINARY_SESSION,
    sessionPathGuard: undefined,
    sensitiveAccountJid: SENSITIVE,
    ordinaryAccountJid: ORDINARY,
  });
  assert.throws(
    () => parseCanonicalArgs(args({ '--ordinary-account-jid': SENSITIVE })),
    /separate sensitive account required/,
  );
  assert.throws(
    () => parseCanonicalArgs([...args(), '--bridge-script', '/tmp/custom.js']),
    /invalid canonical sensitive bridge arguments/,
  );
  assert.throws(
    () => parseCanonicalArgs(args({ '--sensitive-account-jid': '15551234567:4@s.whatsapp.net' })),
    /canonical sensitive account identity is required/,
  );
  assert.throws(
    () => parseCanonicalArgs(args({ '--ordinary-account-jid': '987654321@lid' })),
    /account identity namespace mismatch/,
  );
  assert.throws(
    () => parseCanonicalArgs(args({ '--ordinary-session': SENSITIVE_SESSION })),
    /separate sensitive session path required/,
  );
  const nestedOrdinary = path.join(SENSITIVE_SESSION, 'ordinary');
  mkdirSync(nestedOrdinary, { mode: 0o700 });
  assert.throws(
    () => parseCanonicalArgs(args({ '--ordinary-session': nestedOrdinary })),
    /separate sensitive session path required/,
  );
});

test('missing inherited capability remains disabled before argument parsing or filesystem access', async () => {
  await assert.rejects(
    runSensitiveBridge({ argv: ['--not-even-parsed'], env: {} }),
    /sensitive delivery is disabled/,
  );
});

test('argument parsing rejects either session symlinked to the other real directory', () => {
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
      () => parseCanonicalArgs(args({
        '--session': sensitive,
        '--ordinary-session': ordinary,
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

test('canonical executable never prints a missing capability or argument failure', () => {
  const result = spawnSync(process.execPath, [path.join(HERE, 'sensitive_bridge.js')], {
    cwd: HERE,
    encoding: 'utf8',
    env: {},
  });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});
