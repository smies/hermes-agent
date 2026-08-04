import path from 'node:path';

const ACCOUNT_RE = /^\d{1,32}@(s\.whatsapp\.net|lid)$/;
const PHONE_RE = /^\d{7,15}$/;
// Exact Baileys 7.0.0-rc14 phone-link alphabet (custom base-32), not generic
// Crockford Base32. In particular 0/I/O are impossible and must fail closed.
export const PAIRING_CODE_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTVWXYZ';
const CODE_RE = new RegExp(`^[${PAIRING_CODE_ALPHABET}]{8}$`);

export function normalizePhone(value) {
  if (typeof value !== 'string') throw new Error('phone_input_invalid');
  const normalized = value.trim().replace(/[\s()+.-]/g, '');
  if (!PHONE_RE.test(normalized)) throw new Error('phone_input_invalid');
  return normalized;
}

function canonicalPath(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
      || path.normalize(value) !== value) throw new Error(`${label}_invalid`);
  return value;
}

function within(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative));
}

export function parseProvisioningRequest(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error('request_invalid');
  }
  const allowed = new Set([
    'version', 'action', 'role', 'phone', 'ordinary_session',
    'sensitive_session', 'reprovision',
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key)) || value.version !== 1
      || !['validate', 'provision'].includes(value.action)
      || !['ordinary', 'sensitive'].includes(value.role)
      || (value.reprovision !== undefined && typeof value.reprovision !== 'boolean')) {
    throw new Error('request_invalid');
  }
  const ordinarySession = canonicalPath(value.ordinary_session, 'ordinary_session');
  const sensitiveSession = canonicalPath(value.sensitive_session, 'sensitive_session');
  if (within(ordinarySession, sensitiveSession) || within(sensitiveSession, ordinarySession)) {
    throw new Error('session_separation_required');
  }
  return Object.freeze({
    version: 1,
    role: value.role,
    action: value.action,
    phone: value.action === 'provision' ? normalizePhone(value.phone) : null,
    reprovision: value.reprovision === true,
    ordinarySession,
    sensitiveSession,
    session: value.role === 'ordinary' ? ordinarySession : sensitiveSession,
  });
}

export function buildProvisioningSocketConfig({ auth, logger }) {
  return Object.freeze({
    auth,
    logger,
    printQRInTerminal: false,
    browser: ['Hermes Offline Provisioner', 'Chrome', '120.0'],
    // Provisioning alone may perform the initial LID bootstrap. Production
    // sockets keep all three disabled.
    syncFullHistory: true,
    fireInitQueries: true,
    shouldSyncHistoryMessage: () => true,
    markOnlineOnConnect: false,
    emitOwnEvents: false,
    getMessage: async () => undefined,
  });
}

export function canonicalAccount(value, canonicalizeJid) {
  if (typeof value !== 'string') return null;
  let canonical;
  try { canonical = canonicalizeJid(value); } catch { return null; }
  return ACCOUNT_RE.test(canonical) ? canonical : null;
}

export function canonicalAccountUser(value, suffix, canonicalizeJid) {
  const account = canonicalAccount(value, canonicalizeJid);
  if (!account || !account.endsWith(`@${suffix}`)) return null;
  return account.slice(0, -(suffix.length + 1));
}

export async function verifyLidBootstrap({ auth, sock, phoneJid, canonicalizeJid }) {
  const canonicalPhone = canonicalAccount(phoneJid, canonicalizeJid);
  if (!canonicalPhone || !canonicalPhone.endsWith('@s.whatsapp.net')) return null;
  const pnUser = canonicalAccountUser(canonicalPhone, 's.whatsapp.net', canonicalizeJid);
  if (!pnUser) return null;
  let lidUser = null;
  const repository = sock?.signalRepository?.lidMapping;
  if (repository && typeof repository.getLIDForPN === 'function') {
    try {
      const mapped = await repository.getLIDForPN(canonicalPhone);
      lidUser = canonicalAccountUser(mapped, 'lid', canonicalizeJid)
        || (/^\d{1,32}$/.test(String(mapped || '')) ? String(mapped) : null);
    } catch {}
  }
  if (!lidUser && auth?.state?.keys && typeof auth.state.keys.get === 'function') {
    try {
      // Pinned Baileys persists lid-mapping with a bare numeric PN key and a
      // bare numeric LID value.  Full JIDs here silently miss real stores.
      const records = await auth.state.keys.get('lid-mapping', [pnUser]);
      const mapped = records?.[pnUser] ?? null;
      lidUser = /^\d{1,32}$/.test(String(mapped || '')) ? String(mapped) : null;
    } catch {}
  }
  const canonicalLid = canonicalAccount(lidUser ? `${lidUser}@lid` : '', canonicalizeJid);
  return canonicalLid?.endsWith('@lid') ? canonicalLid : null;
}

export function normalizePairingCode(value) {
  const code = String(value || '').trim().toUpperCase();
  if (!CODE_RE.test(code)) throw new Error('pairing_code_invalid');
  return code;
}
