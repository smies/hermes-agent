const ACCOUNT_RE = /^\d{1,32}@(s\.whatsapp\.net|lid)$/;

function canonicalAccount(value, canonicalizeJid) {
  if (typeof value !== 'string') return null;
  let canonical;
  try { canonical = canonicalizeJid(value); } catch { return null; }
  return ACCOUNT_RE.test(canonical) ? canonical : null;
}

function canonicalAccountUser(value, suffix, canonicalizeJid) {
  const account = canonicalAccount(value, canonicalizeJid);
  if (!account || !account.endsWith(`@${suffix}`)) return null;
  return account.slice(0, -(suffix.length + 1));
}

// Ordinary-local copy of the small pure rc14 LID readiness check.  Keeping it
// here makes the ordinary and sensitive executable graphs disjoint; neither
// role imports lifecycle/auth/session code from the other package.
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
      const records = await auth.state.keys.get('lid-mapping', [pnUser]);
      const mapped = records?.[pnUser] ?? null;
      lidUser = /^\d{1,32}$/.test(String(mapped || '')) ? String(mapped) : null;
    } catch {}
  }
  const canonicalLid = canonicalAccount(
    lidUser ? `${lidUser}@lid` : '', canonicalizeJid,
  );
  return canonicalLid?.endsWith('@lid') ? canonicalLid : null;
}
