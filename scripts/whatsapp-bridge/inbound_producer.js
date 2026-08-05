import { normalizeWhatsAppId } from './bridge_helpers.js';

export const REGISTERED_INBOUND_PROVENANCE =
  'messages.upsert:registered-emitting-socket:v1';

function socketAuthority(emittingSocket) {
  if (!emittingSocket || typeof emittingSocket !== 'object') return null;
  const user = emittingSocket.user;
  if (!user || typeof user !== 'object') return null;
  const accountId = normalizeWhatsAppId(user.id);
  if (!accountId) return null;
  return Object.freeze({
    accountId,
    id: user.id,
    lid: user.lid,
  });
}

/**
 * Production messages.upsert producer, dependency-injected for inert tests.
 *
 * This is the single control flow that authenticates the socket account,
 * applies the owner/customer gate, preserves the provider message id through
 * extraction, and inserts the accepted event into the ordinary bridge queue.
 */
export async function produceInboundMessage({
  msg,
  emittingSocket,
  isActiveSocket,
  mode,
  dmPolicy,
  allowlistMatches,
  extractEvent,
  downloadMedia,
  cacheDirs,
  messageStore,
  messageQueue,
  maxQueueSize,
  emitDebugEvent = () => {},
  handlePollUpdate = null,
}) {
  if (typeof isActiveSocket !== 'function' || !isActiveSocket(emittingSocket)) {
    return { action: 'ignored', reason: 'stale_emitting_socket' };
  }
  // Pinned Baileys rc14 derives key.fromMe while decrypting the authenticated
  // provider stanza. It is true both for local own events and for messages
  // sent by another companion linked to this same account. Keep this
  // defense-in-depth fence ahead of socket metadata, extraction, poll logic,
  // stores, queues, and diagnostics; the registered callback applies the
  // same decision even earlier.
  if (msg?.key?.fromMe !== false) {
    return { action: 'ignored', reason: 'sender_companion_fenced' };
  }
  const socketUser = socketAuthority(emittingSocket);
  if (!socketUser) return { action: 'ignored', reason: 'invalid_socket_authority' };
  if (!msg?.message) return { action: 'ignored', reason: 'empty_envelope' };
  const chatId = msg.key?.remoteJid;
  const senderId = msg.key?.participant || chatId;
  if (!chatId || !senderId || !msg.key?.id) {
    return { action: 'ignored', reason: 'invalid_authority' };
  }
  const isGroup = chatId.endsWith('@g.us');
  const senderNumber = senderId.replace(/@.*/, '');
  const botIds = Array.from(new Set([
    normalizeWhatsAppId(socketUser?.id),
    normalizeWhatsAppId(socketUser?.lid),
  ].filter(Boolean)));
  const fromOwner = false;

  if (mode === 'self-chat') {
    return { action: 'ignored', reason: 'self_chat_mode_rejects_non_self' };
  }
  if (dmPolicy !== 'pairing' && !allowlistMatches(senderId)) {
    return { action: 'ignored', reason: 'allowlist_mismatch' };
  }

  if (typeof handlePollUpdate === 'function' && await handlePollUpdate({
    msg, chatId, senderId, socketUser,
  })) {
    return { action: 'poll' };
  }

  const event = await extractEvent({
    msg,
    chatId,
    senderId,
    senderNumber,
    botIds,
    isGroup,
    downloadMedia,
    cacheDirs,
  });
  event.fromOwner = fromOwner;
  event.accountId = socketUser.accountId;
  event.inboundProvenance = REGISTERED_INBOUND_PROVENANCE;
  if (!event.accountId || event.messageId !== msg.key.id) {
    return { action: 'ignored', reason: 'authority_extraction_mismatch' };
  }
  if (!event.body && !event.hasMedia) {
    return { action: 'ignored', reason: 'empty' };
  }
  const currentAuthority = socketAuthority(emittingSocket);
  if (!isActiveSocket(emittingSocket)
      || !currentAuthority
      || currentAuthority.accountId !== socketUser.accountId
      || normalizeWhatsAppId(currentAuthority.lid) !== normalizeWhatsAppId(socketUser.lid)) {
    return { action: 'ignored', reason: 'stale_emitting_socket' };
  }
  messageStore.remember(msg);
  messageQueue.push(event);
  if (messageQueue.length > maxQueueSize) messageQueue.shift();
  emitDebugEvent({
    stage: 'queued', chatId, senderId, fromOwner: !!fromOwner,
    bodyLength: event.body.length, hasMedia: event.hasMedia,
    mediaType: event.mediaType, queueLength: messageQueue.length,
  });
  return { action: 'queued', event };
}

/**
 * Register the production upsert callback on one exact socket generation.
 *
 * Tests inject an inert emitter and the same dependencies used by bridge.js;
 * there is no parallel test-only callback path.
 */
export function registerInboundMessageHandler({
  emittingSocket,
  isActiveSocket,
  producerDependencies,
  emitDebugEvent = () => {},
}) {
  if (!emittingSocket?.ev || typeof emittingSocket.ev.on !== 'function'
      || typeof isActiveSocket !== 'function'
      || !producerDependencies || typeof producerDependencies !== 'object') {
    throw new TypeError('exact inbound registration dependencies are required');
  }
  const registeredSocket = emittingSocket;
  const active = candidate => (
    candidate === registeredSocket && isActiveSocket(registeredSocket)
  );
  const handler = async ({ messages, type } = {}) => {
    if (!active(registeredSocket)) {
      return { action: 'ignored', reason: 'stale_emitting_socket' };
    }
    // In self-chat mode, your own messages commonly arrive as 'append'.
    if (type !== 'notify' && type !== 'append') {
      return { action: 'ignored', reason: 'unsupported_upsert_type' };
    }
    let lastOutcome = { action: 'ignored', reason: 'empty_upsert' };
    for (const msg of messages || []) {
      if (!active(registeredSocket)) {
        return { action: 'ignored', reason: 'stale_emitting_socket' };
      }
      // This is the earliest application callback reached by every rc14
      // messages.upsert producer: live notify, offline append,
      // sender-companion fan-out, local own event, and PDO/retry response.
      // Missing/unknown provenance is rejected with the same no-observation
      // behavior. Nothing below this branch may inspect message content.
      if (msg?.key?.fromMe !== false) {
        lastOutcome = { action: 'ignored', reason: 'sender_companion_fenced' };
        continue;
      }
      emitDebugEvent({
        stage: 'upsert', type, fromMe: !!msg?.key?.fromMe,
        chatId: producerDependencies.redactWhatsAppId?.(msg?.key?.remoteJid),
        senderId: producerDependencies.redactWhatsAppId?.(
          msg?.key?.participant || msg?.key?.remoteJid,
        ),
        messageKeys: Object.keys(msg?.message || {}),
      });
      lastOutcome = await produceInboundMessage({
        ...producerDependencies,
        msg,
        emittingSocket: registeredSocket,
        isActiveSocket: active,
        emitDebugEvent,
      });
      if (lastOutcome.action === 'ignored' && producerDependencies.debugEnabled) {
        emitDebugEvent({
          stage: 'ignored', reason: lastOutcome.reason,
          chatId: producerDependencies.redactWhatsAppId?.(msg?.key?.remoteJid),
          senderId: producerDependencies.redactWhatsAppId?.(
            msg?.key?.participant || msg?.key?.remoteJid,
          ),
        });
      }
    }
    return lastOutcome;
  };
  emittingSocket.ev.on('messages.upsert', handler);
  return handler;
}
