import { appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export async function resolve(specifier, context, nextResolve) {
  const resolved = await nextResolve(specifier, context);
  if (resolved.url.startsWith('file:')
      && fileURLToPath(resolved.url).endsWith('/sensitive_bridge.js')) {
    appendFileSync(process.env.JUNO_CORE_BOUNDARY_MARKER, 'sensitive_bridge.js\n');
  }
  return resolved;
}
