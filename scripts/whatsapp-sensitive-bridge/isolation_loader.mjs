export async function resolve(specifier, context, nextResolve) {
  const resolved = await nextResolve(specifier, context);
  if (resolved.url.includes('/scripts/whatsapp-bridge/')) {
    throw new Error('ordinary WhatsApp bridge import forbidden');
  }
  return resolved;
}
