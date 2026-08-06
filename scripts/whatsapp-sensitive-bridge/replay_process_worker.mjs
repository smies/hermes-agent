import { EventEmitter } from 'node:events';

import { SensitiveDeliveryTransport } from './delivery_core.js';
import { DurableReceiverReplayAuthority } from './replay_authority.js';

const identity = JSON.parse(process.argv[2]);
const generation = process.argv[3];
const mode = process.argv[4] || 'submit';
const epoch = `epoch-${generation.slice(0, 8)}`;
let providerCalls = 0;
const replayAuthority = new DurableReceiverReplayAuthority(identity);
if (mode === 'burn-only') {
  replayAuthority.burn('same-logical-request-across-fresh-processes', {
    profile: 'juno', mode: 'sensitive-outbound-only',
    runtime: `sensitive-${generation}`, process_generation: generation, session: epoch,
    account: '15551234567@s.whatsapp.net',
    destination: '15557654321@s.whatsapp.net',
    expires_at_us: 1_785_846_900_000_000,
    payload_sha256: '502a9df3c0d88cc2b5836433f940fc6ebb34547a4fa208c3197161bd7e0e2a93',
    topology_sha256: 'c'.repeat(64), transport_manifest_sha256: 'd'.repeat(64),
  });
  process.exit(86);
}
const ev = new EventEmitter();
const transport = new SensitiveDeliveryTransport({
  runtimeId: `sensitive-${generation}`,
  processGeneration: generation,
  topologyIdentity: { topology_sha256: 'c'.repeat(64) },
  ordinaryAccountJid: '15551234567@s.whatsapp.net',
  transportIdentity: { manifest_sha256: 'd'.repeat(64) },
  canonicalizeJid: value => String(value).replace(/:\d+@/, '@'),
  generateMessageId: () => '3EB0ABCDEF0123456789AB',
  nowUs: () => 1_785_846_896_000_000,
  replayAuthority,
});
const sock = {
  user: { id: '15551234567:4@s.whatsapp.net' },
  ev,
  async sendMessage(destination, _content, options) {
    providerCalls += 1;
    return { key: { id: options.messageId, remoteJid: destination, fromMe: true } };
  },
};
transport.bindConnection({
  sock, accountJid: '15551234567@s.whatsapp.net', epoch,
});
const result = await transport.submit({
  contract_version: 'juno-sensitive-submit-v2',
  request_id: 'same-logical-request-across-fresh-processes',
  registration: `sensitive-${generation}`,
  process_generation: generation,
  session: epoch,
  topology_sha256: 'c'.repeat(64),
  account: '15551234567@s.whatsapp.net',
  destination: '15557654321@s.whatsapp.net',
  expires_at_us: 1_785_846_900_000_000,
  private_value: 'PRIVATE-FRESH-PROCESS-SENTINEL',
});
process.stdout.write(`${JSON.stringify({ state: result.state, providerCalls })}\n`);
