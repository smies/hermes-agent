import { createHash, timingSafeEqual } from 'node:crypto';

export const CAPABILITY_HEADER = 'x-hermes-sensitive-capability';
export const DEFAULT_MAX_BODY_BYTES = 24 * 1024;
export const DEFAULT_ACTIVE_REQUEST_LIMIT = 8;
export const DEFAULT_RATE_LIMIT = 30;
export const DEFAULT_RATE_WINDOW_MS = 60_000;

const LOOPBACK_PEERS = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

function digest(value) {
  return createHash('sha256').update(value, 'utf8').digest();
}

export function capabilityMatches(provided, expected) {
  const candidate = typeof provided === 'string' && Buffer.byteLength(provided, 'utf8') <= 512
    ? provided
    : '';
  const configured = typeof expected === 'string'
    && Buffer.byteLength(expected, 'utf8') >= 32
    && Buffer.byteLength(expected, 'utf8') <= 512;
  return timingSafeEqual(digest(candidate), digest(typeof expected === 'string' ? expected : ''))
    && configured;
}

function hostIsLoopback(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) return false;
  const lower = value.toLowerCase();
  if (LOOPBACK_HOSTS.has(lower)) return true;
  if (lower.startsWith('[::1]:')) return /^\[::1\]:\d{1,5}$/.test(lower);
  const match = lower.match(/^(localhost|127\.0\.0\.1):(\d{1,5})$/);
  return Boolean(match);
}

function writeJson(res, status, value) {
  if (res.writableEnded || res.destroyed) return;
  const body = JSON.stringify(value);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-content-type-options', 'nosniff');
  res.end(body);
}

function boundedError(res, status, code) {
  writeJson(res, status, { outcome: 'rejected', submitted: false, error_code: code });
}

function responseStatus(evidence) {
  if (evidence?.outcome === 'capacity') return 429;
  if (evidence?.outcome === 'unavailable') return 503;
  return 200;
}

export function createSensitiveHttpHandler({
  capability,
  transport,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  activeRequestLimit = DEFAULT_ACTIVE_REQUEST_LIMIT,
  rateLimit = DEFAULT_RATE_LIMIT,
  rateWindowMs = DEFAULT_RATE_WINDOW_MS,
  nowMs = () => Date.now(),
  parseJson = (bytes) => JSON.parse(bytes.toString('utf8')),
}) {
  const maxBytes = Math.max(1, Math.floor(maxBodyBytes));
  const maxActive = Math.max(1, Math.floor(activeRequestLimit));
  const maxRate = Math.max(1, Math.floor(rateLimit));
  const windowMs = Math.max(1, Math.floor(rateWindowMs));
  let active = 0;
  const rateByPeer = new Map();

  function takeRate(peer) {
    const now = nowMs();
    let bucket = rateByPeer.get(peer);
    if (!bucket || now - bucket.startedMs >= windowMs) {
      bucket = { startedMs: now, count: 0 };
      rateByPeer.set(peer, bucket);
    }
    bucket.count += 1;
    return bucket.count <= maxRate;
  }

  return function sensitiveHttpHandler(req, res) {
    const peer = req.socket?.remoteAddress || '';
    if (!LOOPBACK_PEERS.has(peer) || !hostIsLoopback(req.headers?.host)) {
      boundedError(res, 400, 'loopback_required');
      return;
    }
    // Authentication deliberately precedes route-specific body validation,
    // listener attachment, allocation, and JSON parsing.
    if (typeof capability !== 'string' || Buffer.byteLength(capability, 'utf8') < 32) {
      boundedError(res, 404, 'service_disabled');
      return;
    }
    if (!capabilityMatches(req.headers?.[CAPABILITY_HEADER], capability)) {
      boundedError(res, 401, 'auth_failed');
      return;
    }
    if (!takeRate(peer)) {
      boundedError(res, 429, 'rate_capacity');
      return;
    }
    if (active >= maxActive) {
      boundedError(res, 429, 'active_capacity');
      return;
    }

    if (req.method === 'GET' && req.url === '/v1/identity') {
      active += 1;
      try {
        const evidence = transport.identityEvidence();
        writeJson(res, responseStatus(evidence), evidence);
      } catch {
        boundedError(res, 503, 'transport_unavailable');
      } finally {
        active -= 1;
      }
      return;
    }
    if (req.method !== 'POST' || !new Set(['/v1/send', '/v1/submit']).has(req.url)) {
      boundedError(res, 404, 'route_not_found');
      return;
    }
    if (req.headers?.['content-type'] !== 'application/json') {
      boundedError(res, 415, 'content_type_invalid');
      return;
    }
    if (req.headers?.['transfer-encoding'] !== undefined) {
      boundedError(res, 400, 'transfer_encoding_forbidden');
      return;
    }
    const lengthText = req.headers?.['content-length'];
    if (typeof lengthText !== 'string') {
      boundedError(res, 411, 'content_length_required');
      return;
    }
    if (!/^(0|[1-9]\d*)$/.test(lengthText)) {
      boundedError(res, 400, 'content_length_invalid');
      return;
    }
    const contentLength = Number(lengthText);
    if (!Number.isSafeInteger(contentLength) || contentLength > maxBytes) {
      boundedError(res, 413, 'body_too_large');
      return;
    }
    if (contentLength === 0) {
      boundedError(res, 400, 'body_invalid');
      return;
    }

    active += 1;
    let complete = false;
    let received = 0;
    const chunks = [];
    const abort = new AbortController();
    const finishActive = () => {
      if (!complete) {
        complete = true;
        active -= 1;
      }
    };
    req.on('aborted', () => {
      abort.abort();
      finishActive();
    });
    req.on('error', () => {
      abort.abort();
      finishActive();
      boundedError(res, 400, 'body_invalid');
    });
    req.on('data', (chunk) => {
      if (complete) return;
      received += chunk.length;
      if (received > contentLength || received > maxBytes) {
        abort.abort();
        finishActive();
        boundedError(res, 413, 'body_too_large');
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', async () => {
      if (complete) return;
      if (received !== contentLength) {
        finishActive();
        boundedError(res, 400, 'content_length_mismatch');
        return;
      }
      let body;
      try {
        body = parseJson(Buffer.concat(chunks, received));
      } catch {
        finishActive();
        boundedError(res, 400, 'body_invalid');
        return;
      }
      try {
        const operation = req.url === '/v1/submit' ? transport.submit : transport.send;
        if (typeof operation !== 'function') {
          finishActive();
          boundedError(res, 503, 'transport_unavailable');
          return;
        }
        const evidence = await operation.call(transport, body, { signal: abort.signal });
        finishActive();
        writeJson(res, responseStatus(evidence), evidence);
      } catch {
        finishActive();
        boundedError(res, 503, 'transport_unavailable');
      }
    });
  };
}

export function listenLoopback(server, { port }) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.off('error', onError);
      resolve(server.address());
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, '127.0.0.1');
  });
}
