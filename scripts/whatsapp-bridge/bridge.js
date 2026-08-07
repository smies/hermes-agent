#!/usr/bin/env node
/**
 * Hermes Agent WhatsApp Bridge
 *
 * Standalone Node.js process that connects to WhatsApp via Baileys
 * and exposes HTTP endpoints for the Python gateway adapter.
 *
 * Endpoints (matches gateway/platforms/whatsapp.py expectations):
 *   GET  /messages       - Long-poll for new incoming messages
 *   POST /send           - Send a message { chatId, message, replyTo? }
 *   POST /edit           - Edit a sent message { chatId, messageId, message }
 *   POST /send-media     - Send media natively { chatId, filePath, mediaType?, caption?, fileName? }
 *   POST /send-location  - Send location pin { chatId, latitude, longitude, name?, address? }
 *   POST /typing         - Send typing indicator { chatId }
 *   POST /private-read-roster - Fence-authenticated complete group roster
 *   GET  /chat/:id       - Get chat info
 *   GET  /health         - Health check
 *
 * Usage:
 *   node bridge.js --port 3000 --session ~/.hermes/whatsapp/session
 */

import { makeWASocket, useMultiFileAuthState, DisconnectReason, fetchLatestBaileysVersion, downloadMediaMessage, getAggregateVotesInPollMessage, decryptPollVote, getKeyAuthor, jidNormalizedUser } from '@whiskeysockets/baileys';
import express from 'express';
import { Boom } from '@hapi/boom';
import pino from 'pino';
import path from 'path';
import { mkdirSync, readFileSync, existsSync, readdirSync, unlinkSync, lstatSync } from 'fs';
import { fileURLToPath } from 'url';
import { randomBytes, createHash, createHmac, timingSafeEqual } from 'crypto';
import { execFileSync } from 'child_process';
import { tmpdir } from 'os';
import { matchesAllowedUser, parseAllowedUsers } from './allowlist.js';
import { createOutboundIdTracker } from './outbound_ids.js';
import { registerInboundMessageHandler } from './inbound_producer.js';
import { verifyLidBootstrap } from './lid_bootstrap.js';
import {
  buildPollPayload,
  createReconnectScheduler,
  createVersionResolver,
  buildLocationPayload,
  buildTextSendPayload,
  createBoundedMessageStore,
  extractBridgeEvent,
  inboundReadReceiptKeys,
  inferMediaType,
  mediaPayloadForFile,
  pollCreationMessageFromPayload,
  pollUpdateForAggregation,
} from './bridge_helpers.js';

// This is a dedicated process. Keep every subsequently created auth/session
// artifact owner-only even if the service manager inherited a looser mask.
process.umask(0o077);

const PACKAGE_ROOT = path.dirname(fileURLToPath(import.meta.url));
let TRANSPORT_IDENTITY = null;

// Parse CLI args
const args = process.argv.slice(2);
function getArg(name, defaultVal) {
  const idx = args.indexOf(`--${name}`);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : defaultVal;
}

const WHATSAPP_DEBUG =
  typeof process !== 'undefined' &&
  process.env &&
  typeof process.env.WHATSAPP_DEBUG === 'string' &&
  ['1', 'true', 'yes', 'on'].includes(process.env.WHATSAPP_DEBUG.toLowerCase());

// Opt-in generic bot behavior retained from the public bridge contract.
// The Juno private-read fence below takes precedence when it is installed by
// the profile-owning Python host.
const FORWARD_OWNER_MESSAGES =
  typeof process !== 'undefined' &&
  process.env &&
  typeof process.env.WHATSAPP_FORWARD_OWNER_MESSAGES === 'string' &&
  ['1', 'true', 'yes', 'on'].includes(process.env.WHATSAPP_FORWARD_OWNER_MESSAGES.toLowerCase());

const PRIVATE_READ_FENCE_PROFILE_ENV = 'HERMES_INTERNAL_WHATSAPP_FENCE_PROFILE';
const PRIVATE_READ_FENCE_KEY_ENV = 'HERMES_INTERNAL_WHATSAPP_FENCE_KEY';

function readPrivateReadFenceBootstrap() {
  const profile = process.env[PRIVATE_READ_FENCE_PROFILE_ENV];
  const key = process.env[PRIVATE_READ_FENCE_KEY_ENV];
  if (profile === undefined && key === undefined) return null;
  if (profile !== 'juno' || typeof key !== 'string' || !/^[a-f0-9]{64}$/.test(key)) {
    throw new Error('private-read sender-companion fence bootstrap is invalid');
  }
  return Object.freeze({
    profile,
    key,
    runtimeId: randomBytes(32).toString('hex'),
  });
}

const PRIVATE_READ_FENCE = readPrivateReadFenceBootstrap();

export function privateReadFenceEvidence(
  transportIdentity = TRANSPORT_IDENTITY,
) {
  if (!PRIVATE_READ_FENCE || !transportIdentity || connectionState !== 'connected'
      || !ordinaryAccountPhoneJid || !ordinaryAccountLidJid) return null;
  let sessionIdentity;
  try {
    const info = lstatSync(SESSION_DIR, { bigint: true });
    if (!info.isDirectory()) return null;
    sessionIdentity = `${info.dev}:${info.ino}`;
  } catch {
    return null;
  }
  const observedAtUs = Date.now() * 1000;
  const material = [
    'juno-sender-companion-fence-v2',
    PRIVATE_READ_FENCE.profile,
    PRIVATE_READ_FENCE.runtimeId,
    String(socketGeneration),
    ordinaryAccountPhoneJid,
    ordinaryAccountLidJid,
    SESSION_DIR,
    sessionIdentity,
    String(observedAtUs),
    transportIdentity.manifest_sha256,
    transportIdentity.source_sha256,
    SCRIPT_HASH,
  ].join('\0');
  return {
    version: 2,
    active: true,
    profile: PRIVATE_READ_FENCE.profile,
    runtimeId: PRIVATE_READ_FENCE.runtimeId,
    socketGeneration,
    accountPhoneJid: ordinaryAccountPhoneJid,
    accountLidJid: ordinaryAccountLidJid,
    sessionPath: SESSION_DIR,
    sessionIdentity,
    observedAtUs,
    manifestSha256: transportIdentity.manifest_sha256,
    sourceSha256: transportIdentity.source_sha256,
    scriptHash: SCRIPT_HASH,
    proof: createHmac('sha256', Buffer.from(PRIVATE_READ_FENCE.key, 'hex'))
      .update(material)
      .digest('hex'),
  };
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite canonical JSON number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(
      key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
    ).join(',')}}`;
  }
  throw new Error('unsupported canonical JSON value');
}

function canonicalParticipantIdentity(value) {
  if (typeof value !== 'string' || !value) return null;
  let normalized;
  try { normalized = jidNormalizedUser(value); } catch { return null; }
  return /^\d{1,32}@(s\.whatsapp\.net|lid)$/.test(normalized) ? normalized : null;
}

function canonicalRosterMembers(participants) {
  if (!Array.isArray(participants) || participants.length === 0) {
    throw new Error('complete group roster unavailable');
  }
  const seen = new Set();
  const members = participants.map(participant => {
    if (!participant || typeof participant !== 'object') {
      throw new Error('malformed group participant');
    }
    const identities = [...new Set([
      participant.id,
      participant.phoneNumber,
      participant.lid,
    ].map(canonicalParticipantIdentity).filter(Boolean))].sort();
    if (identities.length === 0 || identities.some(identity => seen.has(identity))) {
      throw new Error('ambiguous group participant');
    }
    identities.forEach(identity => seen.add(identity));
    return identities;
  });
  members.sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  return members;
}

export function privateReadRosterEvidence({ groupId, challenge, metadata }) {
  if (!PRIVATE_READ_FENCE || connectionState !== 'connected'
      || !/^\d{1,32}@g\.us$/.test(String(groupId || ''))
      || !/^[a-f0-9]{64}$/.test(String(challenge || ''))
      || !metadata || typeof metadata !== 'object'
      || typeof metadata.id !== 'string' || metadata.id !== groupId
      || !ordinaryAccountPhoneJid || !ordinaryAccountLidJid) {
    return null;
  }
  const unsigned = {
    version: 1,
    groupId,
    isGroup: true,
    complete: true,
    participants: canonicalRosterMembers(metadata.participants),
    botIdentities: [ordinaryAccountPhoneJid, ordinaryAccountLidJid].sort(),
    runtimeId: PRIVATE_READ_FENCE.runtimeId,
    socketGeneration,
    observedAtUs: Date.now() * 1000,
    challenge,
  };
  return {
    ...unsigned,
    proof: createHmac('sha256', Buffer.from(PRIVATE_READ_FENCE.key, 'hex'))
      .update(canonicalJson(unsigned))
      .digest('hex'),
  };
}

const SEND_READ_RECEIPTS =
  typeof process !== 'undefined' &&
  process.env &&
  typeof process.env.WHATSAPP_SEND_READ_RECEIPTS === 'string' &&
  ['1', 'true', 'yes', 'on'].includes(process.env.WHATSAPP_SEND_READ_RECEIPTS.toLowerCase());

const PORT = parseInt(getArg('port', '3000'), 10);
const SESSION_DIR = getArg('session', path.join(process.env.HOME || '~', '.hermes', 'whatsapp', 'session'));
// Cache directories: the Python gateway passes the profile-aware paths via
// env (HERMES_HOME-aware, new cache/ layout).  Fall back to the legacy
// hardcoded locations for bridges launched outside the gateway.
const IMAGE_CACHE_DIR = process.env.HERMES_IMAGE_CACHE_DIR
  || path.join(process.env.HOME || '~', '.hermes', 'image_cache');
const DOCUMENT_CACHE_DIR = process.env.HERMES_DOCUMENT_CACHE_DIR
  || path.join(process.env.HOME || '~', '.hermes', 'document_cache');
const AUDIO_CACHE_DIR = process.env.HERMES_AUDIO_CACHE_DIR
  || path.join(process.env.HOME || '~', '.hermes', 'audio_cache');

// Self-hash of this script file.  Reported in /health so the Python gateway
// can detect a running bridge that predates the current bridge.js and
// restart it instead of silently reusing stale code (stale-bridge trap:
// `hermes update` updates bridge.js on disk but a long-lived bridge process
// keeps serving the old behavior forever).
let SCRIPT_HASH = '';
try {
  SCRIPT_HASH = createHash('sha256')
    .update(readFileSync(fileURLToPath(import.meta.url)))
    .digest('hex')
    .slice(0, 16);
} catch {}
const WHATSAPP_MODE = getArg('mode', process.env.WHATSAPP_MODE || 'self-chat'); // "bot" or "self-chat"
const WHATSAPP_DM_POLICY = String(process.env.WHATSAPP_DM_POLICY || 'open').trim().toLowerCase();
const ALLOWED_USERS = parseAllowedUsers(process.env.WHATSAPP_ALLOWED_USERS || '');
const DEFAULT_REPLY_PREFIX = '⚕ *Hermes Agent*\n────────────\n';
const REPLY_PREFIX = process.env.WHATSAPP_REPLY_PREFIX === undefined
  ? DEFAULT_REPLY_PREFIX
  : process.env.WHATSAPP_REPLY_PREFIX.replace(/\\n/g, '\n');
const MAX_MESSAGE_LENGTH = parseInt(process.env.WHATSAPP_MAX_MESSAGE_LENGTH || '4096', 10);
const CHUNK_DELAY_MS = parseInt(process.env.WHATSAPP_CHUNK_DELAY_MS || '300', 10);
// Per-call timeout for sock.sendMessage(). Baileys occasionally hangs forever
// when uploading media to WhatsApp servers (and, less often, on text sends),
// which pins the bridge's HTTP handler until the upstream aiohttp timeout
// fires. Fail fast instead so the gateway can surface a real error and retry.
const SEND_TIMEOUT_MS = parseInt(process.env.WHATSAPP_SEND_TIMEOUT_MS || '60000', 10);

// --- Send queue: serialise all sock.sendMessage() calls across concurrent
//     HTTP handlers so a single Baileys socket never has overlapping sends.
//     Overlapping sends are the root cause of cross-chat contamination
//     (#33360) — the WhatsApp protocol-level routing can misdeliver when
//     two sendMessage() Promises race on the same socket. ---
let _sendQueue = Promise.resolve();

function enqueueSend(fn) {
  const task = _sendQueue.then(() => fn(), () => fn());
  _sendQueue = task.catch(() => {});
  return task;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function sendWithTimeout(chatId, payload, options = {}, timeoutMs = SEND_TIMEOUT_MS) {
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`sendMessage timed out after ${timeoutMs / 1000}s`)),
      timeoutMs,
    );
  });
  return enqueueSend(() =>
    Promise.race([sock.sendMessage(chatId, payload, options), timeoutPromise])
      .finally(() => clearTimeout(timer))
  );
}

function formatOutgoingMessage(message) {
  // In bot mode, messages come from a different number so the prefix is
  // redundant — the sender identity is already clear.  Only prepend in
  // self-chat mode where bot and user share the same number.
  if (WHATSAPP_MODE !== 'self-chat') return message;
  return REPLY_PREFIX ? `${REPLY_PREFIX}${message}` : message;
}

function splitLongMessage(message, maxLength = MAX_MESSAGE_LENGTH) {
  const text = String(message || '');
  if (!text) return [];
  if (!Number.isFinite(maxLength) || maxLength < 1 || text.length <= maxLength) {
    return [text];
  }

  const chunks = [];
  let remaining = text;
  while (remaining.length > maxLength) {
    let splitAt = remaining.lastIndexOf('\n', maxLength);
    if (splitAt < Math.floor(maxLength / 2)) {
      splitAt = remaining.lastIndexOf(' ', maxLength);
    }
    if (splitAt < 1) splitAt = maxLength;

    chunks.push(remaining.slice(0, splitAt).trimEnd());
    remaining = remaining.slice(splitAt).trimStart();
  }
  if (remaining) chunks.push(remaining);
  return chunks;
}

function rememberSentMessage(sent, payload) {
  if (!sent?.key?.id) return;
  if (sent.message) {
    messageStore.remember(sent);
    return;
  }
  const syntheticMessage = pollCreationMessageFromPayload(payload);
  if (syntheticMessage) {
    messageStore.remember({ ...sent, message: syntheticMessage });
  }
}

function trackSentMessageId(sent) {
  rememberSentId(sent?.key?.id);
}

function normalizeWhatsAppId(value) {
  if (!value) return '';
  const raw = String(value).trim();
  const colon = raw.indexOf(':');
  const domain = raw.indexOf('@');
  return colon >= 0 && domain > colon ? `${raw.slice(0, colon)}${raw.slice(domain)}` : raw;
}

function redactWhatsAppId(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  const [userPart, domainPart = ''] = raw.split('@', 2);
  const bare = userPart.split(':', 1)[0];
  const digits = bare.replace(/\D/g, '');
  const suffix = digits ? digits.slice(-4) : bare.slice(-4);
  return `${suffix ? `…${suffix}` : '…'}${domainPart ? `@${domainPart}` : ''}`;
}

function emitDebugEvent(payload) {
  if (!WHATSAPP_DEBUG) return;
  try {
    console.log(JSON.stringify({ event: 'debug', ...payload }));
  } catch {}
}

function getMessageContent(msg) {
  const content = msg?.message || {};
  if (content.ephemeralMessage?.message) return content.ephemeralMessage.message;
  if (content.viewOnceMessage?.message) return content.viewOnceMessage.message;
  if (content.viewOnceMessageV2?.message) return content.viewOnceMessageV2.message;
  if (content.documentWithCaptionMessage?.message) return content.documentWithCaptionMessage.message;
  if (content.templateMessage?.hydratedTemplate) return content.templateMessage.hydratedTemplate;
  if (content.buttonsMessage) return content.buttonsMessage;
  if (content.listMessage) return content.listMessage;
  return content;
}

function getContextInfo(messageContent) {
  if (!messageContent || typeof messageContent !== 'object') return {};
  for (const value of Object.values(messageContent)) {
    if (value && typeof value === 'object' && value.contextInfo) {
      return value.contextInfo;
    }
  }
  return {};
}

mkdirSync(SESSION_DIR, { recursive: true });

// Build LID → phone reverse map from session files (lid-mapping-{phone}.json)
function buildLidMap() {
  const map = {};
  try {
    for (const f of readdirSync(SESSION_DIR)) {
      const m = f.match(/^lid-mapping-(\d+)\.json$/);
      if (!m) continue;
      const phone = m[1];
      const lid = JSON.parse(readFileSync(path.join(SESSION_DIR, f), 'utf8'));
      if (lid) map[String(lid)] = phone;
    }
  } catch {}
  return map;
}
let lidToPhone = buildLidMap();

const logger = pino({ level: 'warn' });

// Message queue for polling
const messageQueue = [];
const MAX_QUEUE_SIZE = 100;

// Track recently sent message IDs for poll-origin correlation and for the
// generic bot-mode owner-forwarding echo classifier. Capacity is bounded.
const recentlySentIds = createOutboundIdTracker(512);
const recentlyProcessedPollUpdates = createOutboundIdTracker(512);
const messageStore = createBoundedMessageStore(512);

function normalizePollUpdateOptions(aggregation, pollUpdateMessage, meId) {
  const selected = [];
  for (const option of aggregation || []) {
    if ((option.voters || []).length > 0 && option.name && option.name !== 'Unknown') {
      selected.push(option.name);
    }
  }
  if (selected.length > 0) return selected;

  // Fallback for already-decrypted pollUpdateMessage payloads where Baileys did
  // not have the creation message available. This may only yield hashes, but
  // keeping them in metadata is still better than dropping the vote entirely.
  const raw = pollUpdateMessage?.vote?.selectedOptions || [];
  return raw.map(option => String(option)).filter(Boolean);
}

function pollAggregationSummary(aggregation) {
  return (aggregation || []).map(option => ({
    name: option?.name || '',
    voterCount: (option?.voters || []).length,
  }));
}

function logPollUpdateDiagnostic({ sourcePath, pollId, pollCreation, pollUpdates, selectedOptions, aggregation }) {
  const firstUpdate = pollUpdates?.[0] || {};
  try {
    console.log(JSON.stringify({
      event: 'poll_update_decode',
      sourcePath,
      pollId: pollId || '',
      pollCreationFound: !!pollCreation,
      updateKeys: Object.keys(firstUpdate),
      hasVote: !!firstUpdate.vote,
      selectedOptionsLength: selectedOptions?.length || 0,
      aggregation: pollAggregationSummary(aggregation),
    }));
  } catch {}
}

function enqueuePollUpdateEvent({ key, update, selectedOptions, aggregation }) {
  const chatId = normalizeWhatsAppId(key?.remoteJid || update?.pollUpdates?.[0]?.pollUpdateMessageKey?.remoteJid || '');
  const senderId = normalizeWhatsAppId(
    key?.participant
    || update?.pollUpdates?.[0]?.pollUpdateMessageKey?.participant
    || chatId
  );
  const pollId = key?.id
    || update?.pollUpdates?.[0]?.pollCreationMessageKey?.id
    || update?.pollUpdates?.[0]?.pollUpdateMessageKey?.id
    || '';
  // Only surface votes on polls Hermes itself created (tracked when
  // /send-poll returns). Arbitrary human polls in a group chat must not
  // inject agent-visible messages on every vote.
  if (!pollId || !recentlySentIds.has(pollId)) {
    if (WHATSAPP_DEBUG) {
      try { console.log(JSON.stringify({ event: 'ignored', reason: 'foreign_poll_update', pollId })); } catch {}
    }
    return;
  }
  const chosenText = selectedOptions.length ? selectedOptions.join(', ') : `[Poll update${pollId ? `: ${pollId}` : ''}]`;
  const dedupeId = `poll:${pollId}:${senderId}:${selectedOptions.join('|')}`;
  if (recentlyProcessedPollUpdates.has(dedupeId)) return;
  recentlyProcessedPollUpdates.remember(dedupeId);
  const event = {
    messageId: `${pollId || 'poll'}:update:${Date.now()}`,
    chatId,
    senderId,
    senderName: senderId.replace(/@.*/, ''),
    chatName: chatId.replace(/@.*/, ''),
    isGroup: chatId.endsWith('@g.us'),
    body: chosenText,
    hasMedia: false,
    mediaType: 'poll_update',
    mime: '',
    fileName: '',
    nativeType: 'pollUpdateMessage',
    nativeMetadata: {
      pollUpdate: {
        pollId,
        selectedOptions,
        aggregation,
      },
    },
    mediaUrls: [],
    mentionedIds: [],
    quotedMessageId: pollId,
    quotedParticipant: '',
    quotedRemoteJid: chatId,
    quotedText: '',
    hasQuotedMessage: !!pollId,
    botIds: [],
    timestamp: Math.floor(Date.now() / 1000),
  };
  messageQueue.push(event);
  if (messageQueue.length > MAX_QUEUE_SIZE) {
    messageQueue.shift();
  }
}

function rememberSentId(id) {
  recentlySentIds.remember(id);
}

let sock = null;
let socketGeneration = 0;
let connectionState = 'disconnected';
let ordinaryAccountPhoneJid = null;
let ordinaryAccountLidJid = null;

const scheduleReconnect = createReconnectScheduler(() => startSocket());
const getWAVersion = createVersionResolver(fetchLatestBaileysVersion);

const PRODUCTION_SOCKET_DEPENDENCIES = Object.freeze({
  useAuthState: useMultiFileAuthState,
  verifyBootstrap: verifyLidBootstrap,
  resolveVersion: getWAVersion,
  createSocket: makeWASocket,
  canonicalizeJid: jidNormalizedUser,
});

/**
 * Register the exact production inbound composition used by startSocket().
 * Every producer dependency and the queue remain production objects owned by
 * this module.
 */
export function registerProductionInboundMessageHandler({
  connectionSocket,
  isActiveSocket,
  generation,
}) {
  return registerInboundMessageHandler({
    emittingSocket: connectionSocket,
    isActiveSocket,
    emitDebugEvent,
    producerDependencies: {
      mode: WHATSAPP_MODE,
      dmPolicy: WHATSAPP_DM_POLICY,
      forwardOwnerMessages: FORWARD_OWNER_MESSAGES,
      recentlySentIds,
      replyPrefix: REPLY_PREFIX,
      senderCompanionFenceActive: PRIVATE_READ_FENCE !== null,
      allowlistMatches: id => matchesAllowedUser(id, ALLOWED_USERS, SESSION_DIR),
      extractEvent: async args => {
        const event = await extractBridgeEvent(args);
        if (PRIVATE_READ_FENCE !== null) {
          event.inboundRuntimeId = PRIVATE_READ_FENCE.runtimeId;
          event.inboundSocketGeneration = generation;
        }
        return event;
      },
      downloadMedia: async mediaMsg => downloadMediaMessage(
        mediaMsg, 'buffer', {},
        { logger, reuploadRequest: connectionSocket.updateMediaMessage },
      ),
      cacheDirs: {
        image: IMAGE_CACHE_DIR,
        document: DOCUMENT_CACHE_DIR,
        audio: AUDIO_CACHE_DIR,
      },
      messageStore,
      messageQueue,
      maxQueueSize: MAX_QUEUE_SIZE,
      debugEnabled: WHATSAPP_DEBUG,
      redactWhatsAppId,
      handlePollUpdate: async ({ msg: pollMsg, chatId, senderId, socketUser }) => {
        const messageContent = getMessageContent(pollMsg);
        if (!messageContent.pollUpdateMessage) return false;
        const pollUpdateMessage = messageContent.pollUpdateMessage;
        const pollKey = pollUpdateMessage.pollCreationMessageKey || {
          id: pollUpdateMessage.key?.id || pollMsg.key.id,
          remoteJid: chatId,
          participant: senderId,
        };
        const pollCreation = messageStore.get(pollKey.id);
        let aggregation = [];
        let pollUpdates = [pollUpdateMessage];
        try {
          if (pollCreation) {
            const meId = jidNormalizedUser(socketUser?.id || 'me');
            const pollUpdate = pollUpdateForAggregation({
              pollUpdateMessage, pollUpdateMessageKey: pollMsg.key, pollCreation,
              decryptPollVote, getKeyAuthor, meId,
              pollCreatorJids: [
                jidNormalizedUser(socketUser?.lid || ''),
                jidNormalizedUser(socketUser?.id || ''),
                getKeyAuthor(pollUpdateMessage.pollCreationMessageKey || pollKey, jidNormalizedUser(socketUser?.lid || '')),
                getKeyAuthor(pollUpdateMessage.pollCreationMessageKey || pollKey, jidNormalizedUser(socketUser?.id || '')),
              ],
              voterJids: [
                normalizeWhatsAppId(pollMsg.key?.participant || ''),
                normalizeWhatsAppId(pollMsg.key?.remoteJid || chatId || ''),
                normalizeWhatsAppId(senderId || ''),
              ],
            });
            if (pollUpdate) pollUpdates = [pollUpdate];
            aggregation = getAggregateVotesInPollMessage({
              message: pollCreation.message, pollUpdates,
            });
          }
        } catch (err) {
          console.warn('[bridge] failed to aggregate poll upsert:', err.message);
        }
        const selectedOptions = normalizePollUpdateOptions(aggregation, pollUpdates[0]);
        logPollUpdateDiagnostic({
          sourcePath: 'messages.upsert', pollId: pollKey.id, pollCreation,
          pollUpdates, selectedOptions, aggregation,
        });
        if (!isActiveSocket(connectionSocket)) return true;
        enqueuePollUpdateEvent({
          key: { ...pollKey, remoteJid: pollKey.remoteJid || chatId,
            participant: pollKey.participant || senderId },
          update: { pollUpdates }, selectedOptions, aggregation,
        });
        return true;
      },
    },
  });
}

export function takeProductionInboundMessages() {
  return messageQueue.splice(0, messageQueue.length);
}

export async function startSocket(dependencies = PRODUCTION_SOCKET_DEPENDENCIES) {
  const {
    useAuthState,
    verifyBootstrap,
    resolveVersion,
    createSocket,
    canonicalizeJid,
  } = dependencies || {};
  if (![useAuthState, verifyBootstrap, resolveVersion, createSocket, canonicalizeJid]
    .every(dependency => typeof dependency === 'function')) {
    throw new Error('complete socket dependencies are required');
  }
  const { state, saveCreds } = await useAuthState(SESSION_DIR);
  if (state?.creds?.registered !== true) {
    console.log('❌ WhatsApp session requires offline provisioning.');
    process.exitCode = 1;
    return;
  }
  const phoneJid = canonicalizeJid(state?.creds?.me?.id || '');
  const persistedLid = await verifyBootstrap({
    auth: { state },
    sock: {},
    phoneJid,
    canonicalizeJid,
  });
  if (!persistedLid) {
    console.log('❌ WhatsApp session LID bootstrap is incomplete.');
    process.exitCode = 1;
    return;
  }
  const canonicalPersistedLid = canonicalizeJid(persistedLid);
  if (!/^\d{1,32}@s\.whatsapp\.net$/.test(phoneJid)
      || !/^\d{1,32}@lid$/.test(canonicalPersistedLid)) {
    process.exitCode = 1;
    return;
  }
  ordinaryAccountPhoneJid = phoneJid;
  ordinaryAccountLidJid = canonicalPersistedLid;
  const version = await resolveVersion();

  const connectionSocket = createSocket({
    ...(version ? { version } : {}),
    auth: state,
    logger,
    printQRInTerminal: false,
    browser: ['Hermes Agent', 'Chrome', '120.0'],
    syncFullHistory: false,
    fireInitQueries: false,
    shouldSyncHistoryMessage: () => false,
    markOnlineOnConnect: false,
    emitOwnEvents: false,
    // Production never recovers offline payloads. Authentication and the
    // initial LID mapping are completed only by offline_provision.js.
    getMessage: async () => undefined,
  });
  const generation = ++socketGeneration;
  sock = connectionSocket;
  connectionState = 'connecting';
  const isCurrentSocket = candidate => (
    candidate === connectionSocket
    && sock === connectionSocket
    && socketGeneration === generation
  );
  const isActiveSocket = candidate => (
    isCurrentSocket(candidate) && connectionState !== 'disconnected'
  );

  connectionSocket.ev.on('creds.update', () => {
    if (!isCurrentSocket(connectionSocket)) return;
    saveCreds();
    lidToPhone = buildLidMap();
  });

  connectionSocket.ev.on('connection.update', (update) => {
    if (!isCurrentSocket(connectionSocket)) return;
    const { connection, lastDisconnect } = update;

    if (connection === 'close') {
      const reason = new Boom(lastDisconnect?.error)?.output?.statusCode;
      connectionState = 'disconnected';

      if (reason === DisconnectReason.loggedOut) {
        console.log('❌ Logged out. Run the offline provisioner to authenticate again.');
        process.exit(1);
      } else {
        // 515 = restart requested (common after pairing). Always reconnect.
        if (reason === 515) {
          console.log('↻ WhatsApp requested restart (code 515). Reconnecting...');
        } else {
          console.log(`⚠️  Connection closed (reason: ${reason}). Reconnecting in 3s...`);
        }
        scheduleReconnect(reason === 515 ? 1000 : 3000);
      }
    } else if (connection === 'open') {
      connectionState = 'connected';
      console.log('✅ WhatsApp connected!');
    }
  });

  connectionSocket.ev.on('messages.update', async (updates) => {
    if (!isActiveSocket(connectionSocket)) return;
    for (const { key, update } of updates || []) {
      if (!isActiveSocket(connectionSocket)) return;
      if (!update?.pollUpdates) continue;
      const pollCreationId = key?.id || update.pollUpdates?.[0]?.pollCreationMessageKey?.id;
      const pollCreation = messageStore.get(pollCreationId);
      let aggregation = [];
      let pollUpdates = update.pollUpdates;
      try {
        if (pollCreation) {
          const meId = jidNormalizedUser(connectionSocket.user?.id || 'me');
          pollUpdates = update.pollUpdates.map(pollUpdate => (
            pollUpdateForAggregation({
              pollUpdateMessage: pollUpdate,
              pollUpdateMessageKey: pollUpdate.pollUpdateMessageKey,
              pollCreation,
              decryptPollVote,
              getKeyAuthor,
              meId,
              pollCreatorJids: [
                jidNormalizedUser(connectionSocket.user?.lid || ''),
                jidNormalizedUser(connectionSocket.user?.id || ''),
                getKeyAuthor(pollUpdate.pollCreationMessageKey || key, jidNormalizedUser(connectionSocket.user?.lid || '')),
                getKeyAuthor(pollUpdate.pollCreationMessageKey || key, jidNormalizedUser(connectionSocket.user?.id || '')),
              ],
              voterJids: [
                normalizeWhatsAppId(pollUpdate.pollUpdateMessageKey?.participant || ''),
                normalizeWhatsAppId(pollUpdate.pollUpdateMessageKey?.remoteJid || key?.remoteJid || ''),
              ],
            }) || pollUpdate
          ));
          aggregation = getAggregateVotesInPollMessage({
            message: pollCreation.message,
            pollUpdates,
          });
        }
      } catch (err) {
        console.warn('[bridge] failed to aggregate poll update:', err.message);
      }
      const selectedOptions = normalizePollUpdateOptions(aggregation, pollUpdates?.[0]);
      logPollUpdateDiagnostic({
        sourcePath: 'messages.update',
        pollId: pollCreationId,
        pollCreation,
        pollUpdates,
        selectedOptions,
        aggregation,
      });
      if (isActiveSocket(connectionSocket)) {
        enqueuePollUpdateEvent({ key, update: { ...update, pollUpdates }, selectedOptions, aggregation });
      }
    }
  });

  registerProductionInboundMessageHandler({
    connectionSocket,
    isActiveSocket,
    generation,
  });
}

// HTTP server
const app = express();
app.use(express.json());

// The offline acceptance harness listens with this exact application after
// startSocket() has registered the production callback. Production startup
// continues to go only through runBridge() below.
export { app as bridgeHttpApp };

// Host-header validation — defends against DNS rebinding.
// The bridge binds loopback-only (127.0.0.1) but a victim browser on
// the same machine could be tricked into fetching from an attacker
// hostname that TTL-flips to 127.0.0.1. Reject any request whose Host
// header doesn't resolve to a loopback alias.
// See GHSA-ppp5-vxwm-4cf7.
const _ACCEPTED_HOST_VALUES = new Set([
  'localhost',
  '127.0.0.1',
  '[::1]',
  '::1',
]);

app.use((req, res, next) => {
  const raw = (req.headers.host || '').trim();
  if (!raw) {
    return res.status(400).json({ error: 'Missing Host header' });
  }
  // Strip port suffix: "localhost:3000" → "localhost"
  const hostOnly = (raw.includes(':')
    ? raw.substring(0, raw.lastIndexOf(':'))
    : raw
  ).replace(/^\[|\]$/g, '').toLowerCase();
  if (!_ACCEPTED_HOST_VALUES.has(hostOnly)) {
    return res.status(400).json({
      error: 'Invalid Host header. Bridge accepts loopback hosts only.',
    });
  }
  next();
});

// Poll for new messages (long-poll style)
app.get('/messages', (req, res) => {
  const msgs = takeProductionInboundMessages();
  res.json(msgs);
});

// Send a message
app.post('/send', async (req, res) => {
  if (!sock || connectionState !== 'connected') {
    return res.status(503).json({ error: 'Not connected to WhatsApp' });
  }

  const { chatId, message, replyTo } = req.body;
  if (!chatId || !message) {
    return res.status(400).json({ error: 'chatId and message are required' });
  }

  try {
    const chunks = splitLongMessage(formatOutgoingMessage(message));
    const messageIds = [];
    for (let i = 0; i < chunks.length; i += 1) {
      const { content: payload, options } = buildTextSendPayload(chunks[i], {
        chatId,
        replyTo: i === 0 ? replyTo : undefined,
        messageStore,
      });
      const sent = await sendWithTimeout(chatId, payload, options);
      trackSentMessageId(sent);
      messageStore.remember(sent);
      if (sent?.key?.id) messageIds.push(sent.key.id);
      if (chunks.length > 1 && i < chunks.length - 1) {
        await sleep(CHUNK_DELAY_MS);
      }
    }

    res.json({
      success: true,
      messageId: messageIds[messageIds.length - 1],
      messageIds,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Edit a previously sent message
app.post('/edit', async (req, res) => {
  if (!sock || connectionState !== 'connected') {
    return res.status(503).json({ error: 'Not connected to WhatsApp' });
  }

  const { chatId, messageId, message } = req.body;
  if (!chatId || !messageId || !message) {
    return res.status(400).json({ error: 'chatId, messageId, and message are required' });
  }

  try {
    const key = { id: messageId, fromMe: true, remoteJid: chatId };
    const chunks = splitLongMessage(formatOutgoingMessage(message));
    const messageIds = [];

    await sendWithTimeout(chatId, { text: chunks[0], edit: key });
    if (chunks.length > 1) {
      for (let i = 1; i < chunks.length; i += 1) {
        const sent = await sendWithTimeout(chatId, { text: chunks[i] });
        trackSentMessageId(sent);
        if (sent?.key?.id) messageIds.push(sent.key.id);
        if (i < chunks.length - 1) {
          await sleep(CHUNK_DELAY_MS);
        }
      }
    }

    res.json({ success: true, messageIds });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Send media (image, video, document) natively
app.post('/send-media', async (req, res) => {
  if (!sock || connectionState !== 'connected') {
    return res.status(503).json({ error: 'Not connected to WhatsApp' });
  }

  const { chatId, filePath, mediaType, caption, fileName } = req.body;
  if (!chatId || !filePath) {
    return res.status(400).json({ error: 'chatId and filePath are required' });
  }

  try {
    if (!existsSync(filePath)) {
      return res.status(404).json({ error: `File not found: ${filePath}` });
    }

    const buffer = readFileSync(filePath);
    const ext = filePath.toLowerCase().split('.').pop();
    const type = mediaType || inferMediaType(ext);
    let msgPayload;

    switch (type) {
      case 'image':
        if (ext === 'gif') {
          // WhatsApp's native animated-GIF UX is an MP4 video payload with
          // gifPlayback=true. Convert when ffmpeg is available; otherwise fall
          // back to a truthful image/gif send instead of mislabeling GIF bytes
          // as video/mp4.
          let tmpGifMp4 = null;
          try {
            tmpGifMp4 = path.join(tmpdir(), `hermes_gif_${randomBytes(6).toString('hex')}.mp4`);
            execFileSync(
              'ffmpeg',
              ['-y', '-i', filePath, '-movflags', 'faststart', '-pix_fmt', 'yuv420p', '-vf', 'scale=trunc(iw/2)*2:trunc(ih/2)*2', tmpGifMp4],
              { timeout: 30000, stdio: 'pipe' }
            );
            msgPayload = {
              video: readFileSync(tmpGifMp4),
              caption: caption || undefined,
              mimetype: 'video/mp4',
              gifPlayback: true,
            };
          } catch (gifErr) {
            console.warn('[bridge] gif conversion failed, sending as image/gif:', gifErr.message);
            msgPayload = mediaPayloadForFile({ buffer, filePath, mediaType: type, caption, fileName });
          } finally {
            try { if (tmpGifMp4 && existsSync(tmpGifMp4)) unlinkSync(tmpGifMp4); } catch (_) {}
          }
        } else {
          msgPayload = mediaPayloadForFile({ buffer, filePath, mediaType: type, caption, fileName });
        }
        break;
      case 'video':
        msgPayload = mediaPayloadForFile({ buffer, filePath, mediaType: type, caption, fileName });
        break;
      case 'audio': {
        // WhatsApp only renders a native voice bubble (ptt) when the file is ogg/opus.
        // If the caller passes mp3, wav, m4a etc. (e.g. from Edge TTS / NeuTTS),
        // silently convert to ogg/opus via ffmpeg so ptt is always honoured.
        let audioBuffer = buffer;
        let audioExt = ext;
        const needsConversion = !['ogg', 'opus'].includes(ext);
        let tmpPath = null;
        if (needsConversion) {
          tmpPath = path.join(tmpdir(), `hermes_voice_${randomBytes(6).toString('hex')}.ogg`);
          try {
            execFileSync(
              'ffmpeg',
              ['-y', '-i', filePath, '-ar', '48000', '-ac', '1', '-c:a', 'libopus', tmpPath],
              { timeout: 30000, stdio: 'pipe' }
            );
            audioBuffer = readFileSync(tmpPath);
            audioExt = 'ogg';
          } catch (convErr) {
            // ffmpeg not available or conversion failed — fall back to original format
            console.warn('[bridge] ffmpeg conversion failed, sending as file attachment:', convErr.message);
          } finally {
            try { if (tmpPath && existsSync(tmpPath)) unlinkSync(tmpPath); } catch (_) {}
          }
        }
        const audioMime = (audioExt === 'ogg' || audioExt === 'opus') ? 'audio/ogg; codecs=opus' : 'audio/mpeg';
        msgPayload = { audio: audioBuffer, mimetype: audioMime, ptt: audioExt === 'ogg' || audioExt === 'opus' };
        break;
      }
      case 'document':
      default:
        msgPayload = mediaPayloadForFile({ buffer, filePath, mediaType: 'document', caption, fileName });
        break;
    }

    const sent = await sendWithTimeout(chatId, msgPayload);
    trackSentMessageId(sent);
    messageStore.remember(sent);
    res.json({ success: true, messageId: sent?.key?.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Send poll primitive. Approval UX is intentionally not wired here; gateway
// approvals need text fallback and explicit confirmation semantics above this
// low-level transport helper.
app.post('/send-poll', async (req, res) => {
  if (!sock || connectionState !== 'connected') {
    return res.status(503).json({ error: 'Not connected to WhatsApp' });
  }

  const { chatId, question, options, selectableCount } = req.body;
  if (!chatId || !question || !Array.isArray(options)) {
    return res.status(400).json({ error: 'chatId, question, and options are required' });
  }

  try {
    const payload = buildPollPayload({ question, options, selectableCount });
    const sent = await sendWithTimeout(chatId, payload);
    trackSentMessageId(sent);
    rememberSentMessage(sent, payload);
    res.json({ success: true, messageId: sent?.key?.id });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Send native WhatsApp location pin
app.post('/send-location', async (req, res) => {
  if (!sock || connectionState !== 'connected') {
    return res.status(503).json({ error: 'Not connected to WhatsApp' });
  }

  const { chatId, latitude, longitude, name, address } = req.body;
  if (!chatId || latitude === undefined || longitude === undefined) {
    return res.status(400).json({ error: 'chatId, latitude, and longitude are required' });
  }

  try {
    const payload = buildLocationPayload({ latitude, longitude, name, address });
    const sent = await sendWithTimeout(chatId, payload);
    trackSentMessageId(sent);
    messageStore.remember(sent);
    res.json({ success: true, messageId: sent?.key?.id });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Typing indicator
app.post('/typing', async (req, res) => {
  if (!sock || connectionState !== 'connected') {
    return res.status(503).json({ error: 'Not connected' });
  }

  const { chatId } = req.body;
  if (!chatId) return res.status(400).json({ error: 'chatId required' });

  try {
    await sock.sendPresenceUpdate('composing', chatId);
    res.json({ success: true });
  } catch (err) {
    res.json({ success: false });
  }
});

// Mark an inbound message as read only after the Python adapter has accepted
// it through the authoritative DM/group/mention intake policy.
app.post('/read', async (req, res) => {
  if (!sock || connectionState !== 'connected') {
    return res.status(503).json({ error: 'Not connected' });
  }

  const receiptKeys = inboundReadReceiptKeys({
    key: req.body?.key,
    enabled: SEND_READ_RECEIPTS,
  });
  if (receiptKeys.length === 0) {
    return res.json({ success: true, marked: false });
  }

  try {
    await sock.readMessages(receiptKeys);
    return res.json({ success: true, marked: true });
  } catch (err) {
    console.warn('[bridge] failed to send read receipt:', err.message);
    return res.status(500).json({ error: 'Failed to send read receipt' });
  }
});

// Complete live roster authority for the trusted-principal plugin. This route
// has no fallback response: it exists only on the managed fenced bridge, and
// every returned field is bound to a caller challenge plus the current socket
// generation. Raw participants are never logged here.
app.post('/private-read-roster', async (req, res) => {
  if (!sock || connectionState !== 'connected' || !PRIVATE_READ_FENCE) {
    return res.status(503).json({ error: 'Roster authority unavailable' });
  }
  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).sort().join(',') !== 'challenge,groupId,requestProof,version'
      || body.version !== 1
      || !/^\d{1,32}@g\.us$/.test(String(body.groupId || ''))
      || !/^[a-f0-9]{64}$/.test(String(body.challenge || ''))
      || !/^[a-f0-9]{64}$/.test(String(body.requestProof || ''))) {
    return res.status(400).json({ error: 'Invalid roster authority request' });
  }
  const requestUnsigned = {
    version: body.version,
    groupId: body.groupId,
    challenge: body.challenge,
  };
  const expectedRequestProof = createHmac(
    'sha256', Buffer.from(PRIVATE_READ_FENCE.key, 'hex'),
  ).update(canonicalJson(requestUnsigned)).digest();
  const suppliedRequestProof = Buffer.from(body.requestProof, 'hex');
  if (suppliedRequestProof.length !== expectedRequestProof.length
      || !timingSafeEqual(suppliedRequestProof, expectedRequestProof)) {
    return res.status(403).json({ error: 'Roster authority denied' });
  }
  const authoritySocket = sock;
  const authorityGeneration = socketGeneration;
  try {
    const metadata = await authoritySocket.groupMetadata(body.groupId);
    if (sock !== authoritySocket || socketGeneration !== authorityGeneration
        || connectionState !== 'connected') {
      return res.status(503).json({ error: 'Roster authority unavailable' });
    }
    const evidence = privateReadRosterEvidence({
      groupId: body.groupId,
      challenge: body.challenge,
      metadata,
    });
    if (!evidence) {
      return res.status(503).json({ error: 'Roster authority unavailable' });
    }
    return res.json(evidence);
  } catch {
    return res.status(503).json({ error: 'Roster authority unavailable' });
  }
});

// Chat info
app.get('/chat/:id', async (req, res) => {
  const chatId = req.params.id;
  const isGroup = chatId.endsWith('@g.us');

  if (isGroup && sock) {
    try {
      const metadata = await sock.groupMetadata(chatId);
      return res.json({
        name: metadata.subject,
        isGroup: true,
        participants: metadata.participants.map(p => p.id),
      });
    } catch {
      // Fall through to default
    }
  }

  res.json({
    name: chatId.replace(/@.*/, ''),
    isGroup,
    participants: [],
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: connectionState,
    queueLength: messageQueue.length,
    uptime: process.uptime(),
    scriptHash: SCRIPT_HASH,
    launcherHash: TRANSPORT_IDENTITY.launcher_sha256,
    transportManifestHash: TRANSPORT_IDENTITY.manifest_sha256,
    sendReadReceipts: SEND_READ_RECEIPTS,
    senderCompanionFence: privateReadFenceEvidence(),
  });
});

// Production startup is deliberately pairing-free. Missing or invalid auth
// can only be repaired by the separately invoked offline provisioner.
export function runBridge({ transportIdentity } = {}) {
  if (!transportIdentity || typeof transportIdentity !== 'object'
      || !/^[a-f0-9]{64}$/.test(String(transportIdentity.manifest_sha256 || ''))) {
    throw new Error('verified ordinary transport identity is required');
  }
  TRANSPORT_IDENTITY = Object.freeze({ ...transportIdentity });
  return app.listen(PORT, '127.0.0.1', () => {
    console.log('🌉 WhatsApp bridge is listening');
    if (ALLOWED_USERS.size > 0) {
      console.log('🔒 An explicit allowlist is active.');
    } else if (WHATSAPP_MODE === 'self-chat') {
      console.log(`🔒 Self-chat mode — only your own messages to yourself are processed.`);
    } else if (WHATSAPP_MODE === 'bot' && WHATSAPP_DM_POLICY === 'pairing') {
      console.log(`🤝 WHATSAPP_DM_POLICY=pairing — unknown DMs are forwarded for gateway pairing.`);
    } else {
      console.log(`🔒 No WHATSAPP_ALLOWED_USERS set — incoming messages are rejected.`);
      console.log(`   Set WHATSAPP_ALLOWED_USERS=<phone> to authorize specific users,`);
      console.log(`   or WHATSAPP_ALLOWED_USERS=* for an explicit open bot.`);
    }
    if (WHATSAPP_MODE === 'bot' && FORWARD_OWNER_MESSAGES && !PRIVATE_READ_FENCE) {
      console.log('👤 Owner-typed messages are forwarded with fromOwner:true');
    }
    if (PRIVATE_READ_FENCE) {
      console.log('🔒 Profile-attested sender-companion fence is active');
    }
    console.log();
  scheduleReconnect(0);
  });
}
