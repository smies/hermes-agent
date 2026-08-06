import http from 'node:http';

import { bindOwnedParentControl } from '../../scripts/whatsapp-sensitive-bridge/parent_control.js';

const port = Number(process.argv[2]);
if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) process.exit(64);
const server = http.createServer((_request, response) => {
  response.end('old-authority-must-die');
});
const control = bindOwnedParentControl(() => {
  try { server.closeAllConnections?.(); } catch {}
  try { server.close(); } catch {}
  setImmediate(() => process.exit(0));
});
process.on('SIGTERM', () => {});
server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`${JSON.stringify({ pid: process.pid, live: control.live() })}\n`);
});
