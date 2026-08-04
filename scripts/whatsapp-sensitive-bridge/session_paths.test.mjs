import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  prepareSessionPaths,
  sameFilesystemIdentity,
  SessionPathError,
} from './session_paths.js';

const REAL_TMP = realpathSync.native(tmpdir());

function freshRoot() {
  return mkdtempSync(path.join(REAL_TMP, 'hermes-session-paths-'));
}

function expectPathRejection(fn, code = undefined) {
  assert.throws(fn, (error) => error instanceof SessionPathError
    && (code === undefined || error.code === code));
}

function treeSnapshot(root, relative = '') {
  const current = relative ? path.join(root, relative) : root;
  const stat = lstatSync(current, { bigint: true });
  const metadata = {
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    nlink: stat.nlink,
    uid: stat.uid,
    gid: stat.gid,
    size: stat.size,
    mtimeNs: stat.mtimeNs,
    ctimeNs: stat.ctimeNs,
  };
  if (stat.isDirectory()) {
    return {
      metadata,
      entries: readdirSync(current).sort().map((name) => ({
        name,
        value: treeSnapshot(root, relative ? path.join(relative, name) : name),
      })),
    };
  }
  return { metadata, contents: readFileSync(current) };
}

test('accepts separate owner-only real directories without modifying ordinary auth contents', () => {
  const root = freshRoot();
  const sensitive = path.join(root, 'sensitive');
  const ordinary = path.join(root, 'ordinary');
  mkdirSync(sensitive, { mode: 0o700 });
  mkdirSync(ordinary, { mode: 0o755 });
  chmodSync(ordinary, 0o755);
  const sentinel = path.join(ordinary, 'sentinel');
  writeFileSync(sentinel, 'ordinary-auth');
  const ordinaryBefore = lstatSync(ordinary, { bigint: true });

  const guard = prepareSessionPaths(sensitive, ordinary);
  guard.revalidate();

  const ordinaryAfter = lstatSync(ordinary, { bigint: true });
  assert.equal(readFileSync(sentinel, 'utf8'), 'ordinary-auth');
  assert.equal(ordinaryAfter.dev, ordinaryBefore.dev);
  assert.equal(ordinaryAfter.ino, ordinaryBefore.ino);
  assert.equal(Number(ordinaryAfter.mode) & 0o7777, 0o755);
});

test('rejects sensitive-to-ordinary and ordinary-to-sensitive symbolic-link aliases', () => {
  for (const direction of ['sensitive-to-ordinary', 'ordinary-to-sensitive']) {
    const root = freshRoot();
    const sensitive = path.join(root, 'sensitive');
    const ordinary = path.join(root, 'ordinary');
    if (direction === 'sensitive-to-ordinary') {
      mkdirSync(ordinary, { mode: 0o700 });
      symlinkSync(ordinary, sensitive, 'dir');
    } else {
      mkdirSync(sensitive, { mode: 0o700 });
      symlinkSync(sensitive, ordinary, 'dir');
    }
    expectPathRejection(
      () => prepareSessionPaths(sensitive, ordinary),
      'session_path_symlink_rejected',
    );
  }
});

test('rejects a symbolic link in either session path ancestor', () => {
  for (const linkedSide of ['sensitive', 'ordinary']) {
    const root = freshRoot();
    const realParent = path.join(root, 'real-parent');
    const aliasParent = path.join(root, 'alias-parent');
    mkdirSync(realParent, { mode: 0o700 });
    symlinkSync(realParent, aliasParent, 'dir');
    const sensitive = linkedSide === 'sensitive'
      ? path.join(aliasParent, 'sensitive') : path.join(root, 'sensitive');
    const ordinary = linkedSide === 'ordinary'
      ? path.join(aliasParent, 'ordinary') : path.join(root, 'ordinary');
    if (linkedSide === 'sensitive') mkdirSync(ordinary, { mode: 0o700 });
    else mkdirSync(path.join(realParent, 'ordinary'), { mode: 0o700 });
    expectPathRejection(
      () => prepareSessionPaths(sensitive, ordinary),
      'session_path_symlink_rejected',
    );
  }
});

test('rejects equal and both nested path directions after realpath resolution', () => {
  const equalRoot = freshRoot();
  const equal = path.join(equalRoot, 'session');
  mkdirSync(equal, { mode: 0o700 });
  expectPathRejection(
    () => prepareSessionPaths(equal, equal),
    'separate_sensitive_session_path_required',
  );

  const sensitiveParentRoot = freshRoot();
  const sensitiveParent = path.join(sensitiveParentRoot, 'sensitive');
  const ordinaryChild = path.join(sensitiveParent, 'ordinary');
  mkdirSync(sensitiveParent, { mode: 0o700 });
  mkdirSync(ordinaryChild, { mode: 0o700 });
  expectPathRejection(
    () => prepareSessionPaths(sensitiveParent, ordinaryChild),
    'separate_sensitive_session_path_required',
  );

  const ordinaryParentRoot = freshRoot();
  const ordinaryParent = path.join(ordinaryParentRoot, 'ordinary');
  const sensitiveChild = path.join(ordinaryParent, 'sensitive');
  mkdirSync(ordinaryParent, { mode: 0o700 });
  mkdirSync(sensitiveChild, { mode: 0o700 });
  expectPathRejection(
    () => prepareSessionPaths(sensitiveChild, ordinaryParent),
    'separate_sensitive_session_path_required',
  );
});

test('missing sensitive child beneath ordinary is rejected without any ordinary tree mutation', () => {
  const root = freshRoot();
  const ordinary = path.join(root, 'ordinary');
  const nested = path.join(ordinary, 'nested');
  const sensitive = path.join(nested, 'missing-sensitive');
  mkdirSync(nested, { mode: 0o700, recursive: true });
  writeFileSync(path.join(ordinary, 'sentinel'), 'ordinary-auth');
  writeFileSync(path.join(nested, 'keys.json'), '{"ordinary":true}');
  const before = treeSnapshot(ordinary);

  expectPathRejection(
    () => prepareSessionPaths(sensitive, ordinary),
    'separate_sensitive_session_path_required',
  );

  assert.equal(existsSync(sensitive), false);
  assert.deepEqual(treeSnapshot(ordinary), before);
});

test('missing sensitive child reached through a symlinked ancestor is rejected without writes', () => {
  const root = freshRoot();
  const ordinary = path.join(root, 'ordinary');
  const alias = path.join(root, 'ordinary-alias');
  const sensitive = path.join(alias, 'missing-sensitive');
  mkdirSync(ordinary, { mode: 0o700 });
  writeFileSync(path.join(ordinary, 'sentinel'), 'ordinary-auth');
  symlinkSync(ordinary, alias, 'dir');
  const before = treeSnapshot(ordinary);

  expectPathRejection(
    () => prepareSessionPaths(sensitive, ordinary),
    'session_path_symlink_rejected',
  );

  assert.equal(existsSync(path.join(ordinary, 'missing-sensitive')), false);
  assert.deepEqual(treeSnapshot(ordinary), before);
});

test('device and inode equality is an independent alias rejection invariant', (t) => {
  assert.equal(
    sameFilesystemIdentity({ dev: 17n, ino: 29n }, { dev: 17n, ino: 29n }),
    true,
  );
  assert.equal(
    sameFilesystemIdentity({ dev: 17n, ino: 29n }, { dev: 17n, ino: 30n }),
    false,
  );

  const root = freshRoot();
  const sensitive = path.join(root, 'sensitive');
  const ordinary = path.join(root, 'ordinary');
  mkdirSync(sensitive, { mode: 0o700 });
  try {
    linkSync(sensitive, ordinary);
  } catch (error) {
    if (['EPERM', 'EISDIR', 'EACCES', 'ENOTSUP'].includes(error?.code)) {
      t.diagnostic(`directory hard-link alias is not constructible: ${error.code}`);
      return;
    }
    throw error;
  }
  expectPathRejection(
    () => prepareSessionPaths(sensitive, ordinary),
    'separate_sensitive_session_path_required',
  );
});

test('rejects pre-existing sensitive mode 0755 and 0770 without repairing it', () => {
  for (const mode of [0o755, 0o770]) {
    const root = freshRoot();
    const sensitive = path.join(root, 'sensitive');
    const ordinary = path.join(root, 'ordinary');
    mkdirSync(sensitive, { mode });
    chmodSync(sensitive, mode);
    mkdirSync(ordinary, { mode: 0o700 });
    expectPathRejection(
      () => prepareSessionPaths(sensitive, ordinary),
      'session_path_permissions_rejected',
    );
    assert.equal(Number(lstatSync(sensitive, { bigint: true }).mode) & 0o7777, mode);
  }
});

test('rejects non-directory components in either path', () => {
  for (const invalidSide of ['sensitive', 'ordinary']) {
    const root = freshRoot();
    const file = path.join(root, 'not-a-directory');
    writeFileSync(file, 'x');
    const sensitive = invalidSide === 'sensitive'
      ? path.join(file, 'sensitive') : path.join(root, 'sensitive');
    const ordinary = invalidSide === 'ordinary'
      ? path.join(file, 'ordinary') : path.join(root, 'ordinary');
    if (invalidSide === 'sensitive') mkdirSync(ordinary, { mode: 0o700 });
    expectPathRejection(
      () => prepareSessionPaths(sensitive, ordinary),
      'session_path_non_directory',
    );
  }
});

test('rejects a replaceable non-sticky parent chain', () => {
  const root = freshRoot();
  const replaceable = path.join(root, 'replaceable');
  const ordinary = path.join(root, 'ordinary');
  mkdirSync(replaceable, { mode: 0o777 });
  chmodSync(replaceable, 0o777);
  mkdirSync(ordinary, { mode: 0o700 });
  expectPathRejection(
    () => prepareSessionPaths(path.join(replaceable, 'sensitive'), ordinary),
    'session_path_replaceable',
  );
});

test('rejects non-canonical absolute spellings before filesystem traversal', () => {
  const root = freshRoot();
  const ordinary = path.join(root, 'ordinary');
  mkdirSync(ordinary, { mode: 0o700 });
  expectPathRejection(
    () => prepareSessionPaths(`${root}${path.sep}missing${path.sep}..${path.sep}sensitive`, ordinary),
    'canonical_absolute_sensitive_session_path_required',
  );
});
