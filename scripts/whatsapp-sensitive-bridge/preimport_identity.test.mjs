import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  cpSync, existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function copyPackage() {
  const root = realpathSync.native(
    mkdtempSync(path.join(tmpdir(), 'hermes-sensitive-preimport-')),
  );
  cpSync(HERE, root, { recursive: true, verbatimSymlinks: true });
  return root;
}

function prependMarker(root, relative, marker) {
  const target = path.join(root, relative);
  writeFileSync(
    target,
    `process.getBuiltinModule('node:fs').writeFileSync(${JSON.stringify(marker)}, 'x');\n${readFileSync(target, 'utf8')}`,
  );
}

function packageEntrypoint(root, packageName) {
  const packageRoot = path.join(root, 'node_modules', ...packageName.split('/'));
  const pkg = JSON.parse(readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
  return path.relative(root, path.join(packageRoot, pkg.main || 'index.js'));
}

function runRejected(root, launcher) {
  const result = spawnSync(
    process.execPath,
    [path.join(root, launcher), '--verify-only'],
    { cwd: root, encoding: 'utf8', env: {} },
  );
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
}

for (const launcher of ['launcher.js', 'provision_launcher.js']) {
  test(`${launcher} pre-hashes the verifier before its marker can execute`, () => {
    const root = copyPackage();
    const marker = path.join(root, `${launcher}-verifier-evaluated`);
    prependMarker(root, 'transport_identity.js', marker);
    runRejected(root, launcher);
    assert.equal(existsSync(marker), false);
  });

  test(`${launcher} pre-hashes the rc14 patcher before its marker can execute`, () => {
    const root = copyPackage();
    const marker = path.join(root, `${launcher}-patcher-evaluated`);
    const target = path.join(root, 'patch_rc14_pairing.js');
    const source = readFileSync(target, 'utf8');
    writeFileSync(target, source.replace(
      '#!/usr/bin/env node\n',
      `#!/usr/bin/env node\nprocess.getBuiltinModule('node:fs').writeFileSync(${JSON.stringify(marker)}, 'x');\n`,
    ));
    runRejected(root, launcher);
    assert.equal(existsSync(marker), false);
  });

  for (const packageName of ['libsignal', 'pino', 'protobufjs']) {
    test(`${launcher} rejects tampered ${packageName} before evaluation`, () => {
      const root = copyPackage();
      const marker = path.join(
        root, `${launcher}-${packageName.replaceAll('/', '-')}-evaluated`,
      );
      prependMarker(root, packageEntrypoint(root, packageName), marker);
      runRejected(root, launcher);
      assert.equal(existsSync(marker), false);
    });
  }
}

for (const launcher of ['launcher.js', 'provision_launcher.js']) {
  test(`${launcher} rejects a real tampered Baileys entrypoint before evaluation`, () => {
    const root = copyPackage();
    const marker = path.join(root, 'baileys-evaluated');
    const installed = JSON.parse(readFileSync(
      path.join(root, 'node_modules/@whiskeysockets/baileys/package.json'), 'utf8',
    ));
    const entry = path.join(root, 'node_modules/@whiskeysockets/baileys', installed.main);
    writeFileSync(
      entry,
      `import { writeFileSync } from 'node:fs';writeFileSync(${JSON.stringify(marker)}, 'x');\n${readFileSync(entry, 'utf8')}`,
    );
    const result = spawnSync(process.execPath, [path.join(root, launcher), '--verify-only'], {
      cwd: root, encoding: 'utf8', env: {},
    });
    assert.equal(result.status, 1);
    assert.equal(existsSync(marker), false);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '');
  });
}

for (const mutation of ['whitespace', 'manifest-and-listed-hashes']) {
  test(`sensitive immutable manifest anchor rejects ${mutation} tampering`, () => {
    const root = copyPackage();
    const manifestPath = path.join(root, 'transport-manifest.json');
    if (mutation === 'whitespace') {
      writeFileSync(manifestPath, `${readFileSync(manifestPath, 'utf8')} `);
    } else {
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
      manifest.source_sha256 = '0'.repeat(64);
      manifest.package_sha256 = '1'.repeat(64);
      writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
      writeFileSync(
        path.join(root, 'lifecycle.js'),
        `${readFileSync(path.join(root, 'lifecycle.js'), 'utf8')}\n// changed\n`,
      );
    }
    const result = spawnSync(process.execPath, [path.join(root, 'launcher.js')], {
      cwd: root, encoding: 'utf8', env: {},
    });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '');
  });
}

test('sensitive cores are inert and graph has no ordinary local edge', () => {
  for (const core of ['sensitive_bridge.js', 'offline_provision.js']) {
    const result = spawnSync(process.execPath, [
      '--input-type=module', '--eval', `await import('./${core}')`,
    ], { cwd: HERE, encoding: 'utf8', env: {} });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '');
  }
  for (const name of [
    'launcher.js', 'provision_launcher.js', 'sensitive_bridge.js',
    'transport_identity.js', 'offline_provision.js', 'lifecycle.js',
    'patch_rc14_pairing.js', 'provisioning_core.js', 'delivery_core.js', 'http_server.js',
    'session_paths.js',
  ]) {
    assert.equal(
      readFileSync(path.join(HERE, name), 'utf8').includes('/whatsapp-bridge/'),
      false,
      name,
    );
  }
});
