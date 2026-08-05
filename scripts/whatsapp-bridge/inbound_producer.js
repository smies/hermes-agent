import { normalizeWhatsAppId } from './bridge_helpers.js';
import { classifyOwnerMessageGate } from './owner_message_gate.js';

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
  forwardOwnerMessages,
  recentlySentIds,
  allowlistMatches,
  extractEvent,
  downloadMedia,
  cacheDirs,
  replyPrefix,
  messageStore,
  messageQueue,
  maxQueueSize,
  emitDebugEvent = () => {},
  handlePollUpdate = null,
}) {
  if (typeof isActiveSocket !== 'function' || !isActiveSocket(emittingSocket)) {
    return { action: 'ignored', reason: 'stale_emitting_socket' };
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
  let fromOwner = false;

  if (msg.key.fromMe) {
    if (isGroup || chatId.includes('status')) {
      return { action: 'ignored', reason: isGroup ? 'from_me_group' : 'from_me_status' };
    }
    if (mode === 'bot') {
      const decision = classifyOwnerMessageGate({
        fromMe: true,
        fromOwnerEnabled: forwardOwnerMessages,
        recentlySent: recentlySentIds,
        allowlistMatches,
        messageId: msg.key.id,
        chatId,
      });
      if (decision.action !== 'forward_owner') {
        return { action: 'ignored', reason: decision.action };
      }
      fromOwner = true;
    } else {
      const myNumber = (socketUser?.id || '').replace(/:.*@/, '@').replace(/@.*/, '');
      const myLid = (socketUser?.lid || '').replace(/:.*@/, '@').replace(/@.*/, '');
      const chatNumber = chatId.replace(/@.*/, '');
      if (!((myNumber && chatNumber === myNumber) || (myLid && chatNumber === myLid))) {
        return { action: 'ignored', reason: 'self_chat_mismatch' };
      }
    }
  } else {
    if (mode === 'self-chat') {
      return { action: 'ignored', reason: 'self_chat_mode_rejects_non_self' };
    }
    if (dmPolicy !== 'pairing' && !allowlistMatches(senderId)) {
      return { action: 'ignored', reason: 'allowlist_mismatch' };
    }
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
  if (msg.key.fromMe && (
    (replyPrefix && event.body.startsWith(replyPrefix)) || recentlySentIds.has(msg.key.id)
  )) {
    return { action: 'ignored', reason: 'agent_echo' };
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
