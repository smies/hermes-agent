import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import {
  cp, lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BAILEYS_POSTIMAGE_TREE_SHA256,
  BAILEYS_PREIMAGE_TREE_SHA256,
  BAILEYS_SPEC,
  normalizePatchedSocket,
  patchInstalledBaileys,
  PATCH_CONTRACT,
  PATCH_TARGET,
  PATCH_UPSTREAM_COMMIT,
  SOCKET_POSTIMAGE_SHA256,
  SOCKET_PREIMAGE_SHA256,
  verifyInstalledPatch,
} from './patch_rc14_pairing.js';

const packageRoot = path.dirname(fileURLToPath(import.meta.url));

async function exactPreimageFixture() {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'hermes-rc14-patch-')));
  const source = path.join(packageRoot, 'node_modules', '@whiskeysockets', 'baileys');
  const destination = path.join(root, 'node_modules', '@whiskeysockets', 'baileys');
  await mkdir(path.dirname(destination), { recursive: true });
  await cp(source, destination, { recursive: true, verbatimSymlinks: true });
  await cp(path.join(packageRoot, 'package.json'), path.join(root, 'package.json'));
  await cp(path.join(packageRoot, 'package-lock.json'), path.join(root, 'package-lock.json'));
  const target = path.join(destination, ...PATCH_TARGET.split('/'));
  await writeFile(target, normalizePatchedSocket(await readFile(target)));
  return { root, destination, target };
}

test('fresh lockfile install has the exact reviewed rc14 postinstall patch', async () => {
  const identity = verifyInstalledPatch(packageRoot);
  assert.equal(identity.contract, PATCH_CONTRACT);
  assert.equal(identity.upstream_commit, PATCH_UPSTREAM_COMMIT);
  assert.equal(identity.preimage_sha256, SOCKET_PREIMAGE_SHA256);
  assert.equal(identity.postimage_sha256, SOCKET_POSTIMAGE_SHA256);
  assert.equal(identity.preimage_tree_sha256, BAILEYS_PREIMAGE_TREE_SHA256);
  assert.equal(identity.postimage_tree_sha256, BAILEYS_POSTIMAGE_TREE_SHA256);
  const pkg = JSON.parse(await readFile(path.join(packageRoot, 'package.json'), 'utf8'));
  const lock = JSON.parse(await readFile(path.join(packageRoot, 'package-lock.json'), 'utf8'));
  assert.equal(pkg.dependencies['@whiskeysockets/baileys'], BAILEYS_SPEC);
  assert.equal(pkg.scripts.postinstall, 'node patch_rc14_pairing.js');
  assert.equal(lock.packages[''].dependencies['@whiskeysockets/baileys'], BAILEYS_SPEC);
  assert.equal(lock.packages['node_modules/@whiskeysockets/baileys'].version, BAILEYS_SPEC);
});

test('exact rc14 preimage patches to one exact postimage and is idempotent', async () => {
  const fixture = await exactPreimageFixture();
  try {
    const first = patchInstalledBaileys(fixture.root);
    const firstBytes = await readFile(fixture.target);
    const second = patchInstalledBaileys(fixture.root);
    assert.deepEqual(second, first);
    assert.deepEqual(await readFile(fixture.target), firstBytes);
    assert.equal(first.postimage_sha256, verifyInstalledPatch(packageRoot).postimage_sha256);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('patcher rejects wrong spec/version, preimage tampering, postimage tampering, and symlinks', async () => {
  for (const mode of ['spec', 'version', 'preimage', 'postimage', 'symlink']) {
    const fixture = await exactPreimageFixture();
    try {
      if (mode === 'spec') {
        const metadata = path.join(fixture.root, 'package.json');
        const value = JSON.parse(await readFile(metadata, 'utf8'));
        value.dependencies['@whiskeysockets/baileys'] = '^7.0.0';
        await writeFile(metadata, `${JSON.stringify(value)}\n`);
      } else if (mode === 'version') {
        const metadata = path.join(fixture.destination, 'package.json');
        const value = JSON.parse(await readFile(metadata, 'utf8'));
        value.version = '7.0.0-rc13';
        await writeFile(metadata, `${JSON.stringify(value)}\n`);
      } else if (mode === 'preimage') {
        await writeFile(fixture.target, Buffer.concat([await readFile(fixture.target), Buffer.from('\n')]));
      } else {
        patchInstalledBaileys(fixture.root);
        if (mode === 'postimage') {
          await writeFile(fixture.target, Buffer.concat([await readFile(fixture.target), Buffer.from('\n')]));
        } else {
          const outside = path.join(fixture.root, 'outside.js');
          await writeFile(outside, await readFile(fixture.target));
          await rm(fixture.target);
          await symlink(outside, fixture.target);
          assert.equal((await lstat(fixture.target)).isSymbolicLink(), true);
        }
      }
      assert.throws(() => (
        mode === 'postimage' || mode === 'symlink'
          ? verifyInstalledPatch(fixture.root)
          : patchInstalledBaileys(fixture.root)
      ));
      assert.equal(existsSync(path.join(fixture.root, 'node_modules')), true);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});
