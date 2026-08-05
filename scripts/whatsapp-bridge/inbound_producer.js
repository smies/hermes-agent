import { normalizeWhatsAppId } from './bridge_helpers.js';
import { classifyOwnerMessageGate } from './owner_message_gate.js';

/**
 * Production messages.upsert producer, dependency-injected for inert tests.
 *
 * This is the single control flow that authenticates the socket account,
 * applies the owner/customer gate, preserves the provider message id through
 * extraction, and inserts the accepted event into the ordinary bridge queue.
 */
export async function produceInboundMessage({
  msg,
  socketUser,
  socket,
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
  event.accountId = normalizeWhatsAppId(socketUser?.id);
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
