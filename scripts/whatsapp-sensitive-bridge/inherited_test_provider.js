import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { fstatSync, fsyncSync, readFileSync, writeSync } from 'node:fs';

const AUTHORITY_FD_ENV = 'HERMES_INTERNAL_JUNO_TEST_PROVIDER_AUTHORITY_FD';
const CAPTURE_FD_ENV = 'HERMES_INTERNAL_JUNO_TEST_PROVIDER_CAPTURE_FD';
const DIGEST_ENV = 'HERMES_INTERNAL_JUNO_TEST_PROVIDER_AUTHORITY_SHA256';
const MAX_AUTHORITY_BYTES = 512;

function exactObject(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function exactOwnerFile(fd, { empty = false } = {}) {
  const info = fstatSync(fd);
  if (!info.isFile() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600
      || (typeof process.getuid === 'function' && info.uid !== process.getuid())
      || (empty && info.size !== 0)) {
    throw new Error('inherited test provider authority rejected');
  }
  return info;
}

function writeAll(fd, value) {
  const bytes = Buffer.from(value, 'utf8');
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(fd, bytes, offset, bytes.length - offset);
    if (written <= 0) throw new Error('test provider capture failed');
    offset += written;
  }
  fsyncSync(fd);
}

export function loadInheritedTestProvider(env, launch) {
  const requested = [AUTHORITY_FD_ENV, CAPTURE_FD_ENV, DIGEST_ENV]
    .some(name => env[name] !== undefined);
  if (!requested) return null;
  if (env[AUTHORITY_FD_ENV] !== '3' || env[CAPTURE_FD_ENV] !== '4'
      || typeof env[DIGEST_ENV] !== 'string'
      || !/^[a-f0-9]{64}$/.test(env[DIGEST_ENV])) {
    throw new Error('inherited test provider authority rejected');
  }
  exactOwnerFile(3);
  exactOwnerFile(4, { empty: true });
  const bytes = readFileSync(3);
  if (bytes.length === 0 || bytes.length > MAX_AUTHORITY_BYTES
      || sha256(bytes) !== env[DIGEST_ENV]) {
    throw new Error('inherited test provider authority rejected');
  }
  let authority;
  try { authority = JSON.parse(bytes); } catch {
    throw new Error('inherited test provider authority rejected');
  }
  if (!exactObject(authority, [
    'version', 'purpose', 'parent_pid', 'process_generation', 'expires_at_us', 'nonce',
  ]) || authority.version !== 1
      || authority.purpose !== 'juno-exact-launcher-below-baileys-send'
      || authority.parent_pid !== process.ppid
      || authority.process_generation !== launch.process_generation
      || !Number.isSafeInteger(authority.expires_at_us)
      || authority.expires_at_us <= Date.now() * 1000
      || authority.expires_at_us - Date.now() * 1000 > 300_000_000
      || typeof authority.nonce !== 'string'
      || !/^[a-f0-9]{64}$/.test(authority.nonce)) {
    throw new Error('inherited test provider authority rejected');
  }
  return Object.freeze({
    makeSocket() {
      const ev = new EventEmitter();
      const sock = {
        user: {
          id: launch.sensitive.account_phone_jid.replace('@s.whatsapp.net', ':4@s.whatsapp.net'),
          lid: launch.sensitive.account_lid_jid,
        },
        ev,
        signalRepository: {
          lidMapping: {
            async getLIDForPN() { return launch.sensitive.account_lid_jid; },
          },
        },
        async sendMessage(destination, content, options) {
          writeAll(4, `${JSON.stringify({
            destination,
            message_id: options?.messageId,
            private_value: content?.text,
          })}\n`);
          return {
            key: {
              id: options?.messageId,
              remoteJid: destination,
              fromMe: true,
            },
          };
        },
        end() {},
      };
      setImmediate(() => ev.emit('connection.update', { connection: 'open' }));
      return sock;
    },
  });
}

export const INHERITED_TEST_PROVIDER_ENVIRONMENT = Object.freeze([
  AUTHORITY_FD_ENV, CAPTURE_FD_ENV, DIGEST_ENV,
]);
