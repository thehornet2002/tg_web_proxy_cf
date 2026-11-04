/**
 * TWP (Telegram Worker Proxy) Core Engine v2.2 - Hardened & Fixed
 * Serverless Telegram WEB Proxy relay for Cloudflare Workers.
 *
 * Improvements in v2.2 vs v2.1:
 *  - Fixed TCP socket leak race condition when a stream closes during DC dial.
 *  - Fixed socket leak & unhandled promise rejections on DC dial timeouts.
 *  - Added server-side dead-peer / idle timeout detection to prevent ghost session lockouts.
 *  - Tuned per-IP session limits to prevent false HTTP 429 errors during multi-lane rotation.
 *  - Implemented real token revocation on DELETE /api/v1/session.
 *  - Fixed active-probing camouflage leak on /api/v1/* endpoints.
 *  - Fixed Map FIFO ordering bug in handshake replay cache.
 *  - Hardened camouflage response headers (stripping alt-svc, clear-site-data, etc.).
 *  - Fixed bridge lane promotion warm-up check & modernized binary helpers.
 *
 * Env vars:
 *   PROXY_SECRET   (required)  32 hex chars, optionally prefixed with "dd"
 *   ADMIN_TOKEN    (optional)  >= 20 chars [A-Za-z0-9._~-]; enables the dashboard
 *   CAMOUFLAGE_URL (optional)  https:// site shown to browsers / probes
 *   TOKEN_SALT     (optional)  change it to invalidate every issued token
 *   MAX_DIALS, MAX_SESSIONS, MAX_SESSIONS_PER_IP (optional numbers)
 *
 * License: MIT
 */

import { connect } from 'cloudflare:sockets';

// ==================================================================================
// 1. PROTOCOL CONSTANTS & TELEGRAM DATACENTERS
// ==================================================================================

const BRIDGE_DOMAIN_LABEL   = 'tdesktop-web-proxy-bridge-v1\n';
const TOKEN_LABEL_PREFIX    = 'tgp-token-v1\0';
const TOKEN_KEY_DERIVATION  = 'tgp-token-key-v1';
const INSECURE_DEFAULT_SECRET = '000102030405060708090a0b0c0d0e0f';

const FRAME_OPEN    = 1;
const FRAME_DATA    = 2;
const FRAME_CLOSE   = 3;
const FRAME_WINDOW  = 4;
const FRAME_PING    = 5;
const FRAME_PONG    = 6;
const FRAME_HELLO   = 0x10;
const FRAME_WELCOME = 0x11;

const CHUNK_SIZE              = 64 * 1024;
const INITIAL_STREAM_WIN      = 4 * 1024 * 1024;
const MAX_FRAME_PAYLOAD       = 1024 * 1024;
const MAX_FRAMES_PER_MSG      = 4096;
const MAX_CARRIER_MSG         = 4 * 1024 * 1024;
const MAX_STREAMS_COUNT       = 48;
const MAX_RETIRED_IDS         = 4096;
const DEFAULT_DIAL_LIMIT      = 45;
const DIAL_TIMEOUT_MS         = 6000;
const CARRIER_PING_MS         = 20000;
const CARRIER_IDLE_TIMEOUT_MS = 65000;

// Backpressure / abuse limits
const MAX_PENDING_UPLINK_PER_STREAM = 8 * 1024 * 1024;   // bytes waiting to be re-encrypted per stream
const MAX_QUEUED_MSG_BYTES          = 16 * 1024 * 1024;  // bytes waiting in the WS message queue per session
const DEFAULT_MAX_SESSIONS          = 300;               // per isolate
const DEFAULT_MAX_SESSIONS_PER_IP   = 24;                // per isolate (accommodates multi-lane rotation)
const REPLAY_TTL_MS                 = 10 * 60 * 1000;
const REPLAY_CACHE_MAX              = 20000;
const REVOKED_TOKEN_CACHE_MAX       = 10000;

const TOKEN_TTL_BOOTSTRAP = 120;
const TOKEN_TTL_SESSION   = 600;
const TOKEN_TTL_RENEWAL   = 3600;

/**
 * Telegram DC endpoints (port 443).
 * Negative DC IDs (media) map to the same IPs via Math.abs(dcId).
 */
const TELEGRAM_DCS = {
  1: ['149.154.175.50', '149.154.175.51', '149.154.175.55'],
  2: ['149.154.167.50', '149.154.167.51', '149.154.167.41'],
  3: ['149.154.175.100', '149.154.175.101'],
  4: ['149.154.167.91', '149.154.167.92', '149.154.167.222'],
  5: ['149.154.171.5', '149.154.171.6'],
};

const PROTOCOL_TAGS = new Set([0xefefefef, 0xeeeeeeee, 0xdddddddd]);
const FORBIDDEN_WORDS = new Set([
  0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0xdddddddd, 0xeeeeeeee, 0x02010316,
]);

const textEncoder = new TextEncoder();

// ==================================================================================
// 2. BINARY PRIMITIVES
// ==================================================================================

function parseHex(hexStr) {
  const bytes = new Uint8Array(hexStr.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hexStr.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function concatArrays(...arrays) {
  let length = 0;
  for (const arr of arrays) length += arr.length;
  const result = new Uint8Array(length);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function reverseBytes(bytes) {
  const reversed = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) reversed[i] = bytes[bytes.length - 1 - i];
  return reversed;
}

function toBase64Url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(base64Url) {
  const standard = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = standard + '='.repeat((4 - (standard.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function toHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

function timingSafeEquals(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a[i] ^ b[i];
  return result === 0;
}

function writeUint32BE(value) {
  const buffer = new Uint8Array(4);
  new DataView(buffer.buffer).setUint32(0, value);
  return buffer;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}

function parseIntEnv(env, name, def, min, max) {
  const v = parseInt(env?.[name], 10);
  return Number.isFinite(v) && v >= min ? Math.min(v, max) : def;
}

function packFrame(type, streamId, payload) {
  const payloadLen = payload ? payload.length : 0;
  const frame = new Uint8Array(8 + payloadLen);
  frame[0] = type;
  frame[1] = streamId >>> 16;
  frame[2] = streamId >>> 8;
  frame[3] = streamId;
  new DataView(frame.buffer).setUint32(4, payloadLen);
  if (payloadLen > 0) frame.set(payload, 8);
  return frame;
}

function unpackFrameBatch(bytes) {
  const frames = [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let cursor = 0;
  while (cursor < bytes.length) {
    if (frames.length >= MAX_FRAMES_PER_MSG || bytes.length - cursor < 8) {
      throw new Error('TWP: Batch size error');
    }
    const size = view.getUint32(cursor + 4);
    if (size > MAX_FRAME_PAYLOAD || cursor + 8 + size > bytes.length) {
      throw new Error('TWP: Invalid frame length');
    }
    frames.push({
      type: bytes[cursor],
      id: (bytes[cursor + 1] << 16) | (bytes[cursor + 2] << 8) | bytes[cursor + 3],
      payload: bytes.subarray(cursor + 8, cursor + 8 + size),
    });
    cursor += 8 + size;
  }
  if (frames.length === 0) throw new Error('TWP: Empty frame batch');
  return frames;
}

function validateClientFrame(f) {
  if (f.id === 0) {
    if (f.type !== FRAME_PONG || f.payload.length > 64) throw new Error('TWP: Invalid control frame');
    return;
  }
  if (f.type === FRAME_OPEN || f.type === FRAME_CLOSE) {
    if (f.payload.length !== 0) throw new Error('TWP: Unexpected control payload');
  } else if (f.type === FRAME_DATA) {
    if (f.payload.length === 0) throw new Error('TWP: Zero-length data frame');
  } else if (f.type === FRAME_WINDOW) {
    if (
      f.payload.length !== 4 ||
      new DataView(f.payload.buffer, f.payload.byteOffset, 4).getUint32(0) === 0
    ) {
      throw new Error('TWP: Malformed window frame');
    }
  } else {
    throw new Error('TWP: Unknown frame type');
  }
}

// ==================================================================================
// 3. WEB CRYPTO PRIMITIVES
// ==================================================================================

async function createHmacKey(rawBytes) {
  return crypto.subtle.importKey('raw', rawBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

async function computeHmac(key, data) {
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

async function computeSha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

function incrementCounter128(initialIv, blockOffset) {
  const counter = initialIv.slice();
  let carry = blockOffset;
  for (let i = 15; i >= 0 && carry > 0; i--) {
    const val = counter[i] + (carry % 256);
    counter[i] = val & 255;
    carry = Math.floor(carry / 256) + (val >> 8);
  }
  return counter;
}

async function createAesCtrCipher(keyBytes, iv) {
  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-CTR', false, ['encrypt']);
  return { cryptoKey, iv };
}

async function applyAesCtr(cipher, byteOffset, inputData) {
  if (inputData.length === 0) return inputData;
  const remainder = byteOffset % 16;
  const blockCounter = incrementCounter128(cipher.iv, Math.floor(byteOffset / 16));
  let source = inputData;
  if (remainder !== 0) {
    source = new Uint8Array(remainder + inputData.length);
    source.set(inputData, remainder);
  }
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CTR', counter: blockCounter, length: 128 }, cipher.cryptoKey, source)
  );
  return remainder !== 0 ? encrypted.subarray(remainder) : encrypted;
}

// ==================================================================================
// 4. CONFIGURATION, TOKENS, ABUSE CONTROLS
// ==================================================================================

let cachedConfig = null;
let warnedConfigError = false;

async function resolveConfig(env) {
  const secretInput = typeof env?.PROXY_SECRET === 'string' ? env.PROXY_SECRET
    : typeof env?.SECRET === 'string' ? env.SECRET : '';
  const rawSecret = secretInput.trim().toLowerCase();

  // Fail closed: no secret, or the well-known default => proxy disabled.
  if (!rawSecret || rawSecret === INSECURE_DEFAULT_SECRET || rawSecret === 'dd' + INSECURE_DEFAULT_SECRET) {
    if (!warnedConfigError) {
      warnedConfigError = true;
      console.error('TWP: PROXY_SECRET missing or insecure; proxy disabled');
    }
    return null;
  }

  const salt = typeof env?.TOKEN_SALT === 'string' ? env.TOKEN_SALT.trim() : '';
  const cacheKey = rawSecret + '|' + salt;
  if (cachedConfig && cachedConfig.raw === cacheKey) {
    return cachedConfig.value;
  }

  try {
    const built = await buildConfigKeys(rawSecret, salt);
    if (!built) {
      if (!warnedConfigError) {
        warnedConfigError = true;
        console.error('TWP: PROXY_SECRET must be 32 hex chars (optionally prefixed with "dd")');
      }
      return null;
    }
    cachedConfig = { raw: cacheKey, value: built };
    return built;
  } catch {
    return null;
  }
}

async function buildConfigKeys(rawSecret, salt) {
  const match = /^(dd)?([0-9a-f]{32})$/.exec(rawSecret);
  if (!match) return null;
  const fullSecretBytes = parseHex(rawSecret);
  const capabilityKey = await createHmacKey(fullSecretBytes);
  const tokenMasterKey = await createHmacKey(
    await computeHmac(capabilityKey, textEncoder.encode(TOKEN_KEY_DERIVATION + salt))
  );
  return {
    fullBytes: fullSecretBytes,
    secret16: parseHex(match[2]),
    isPadded: Boolean(match[1]),
    capabilityKey,
    tokenMasterKey,
  };
}

function resolveMaxDials(env) {
  return parseIntEnv(env, 'MAX_DIALS', DEFAULT_DIAL_LIMIT, 4, 100000);
}

// Revoked session token store (best-effort per isolate)
const revokedTokens = new Map();

function revokeToken(tokenStr) {
  if (!tokenStr) return;
  const now = Date.now();
  revokedTokens.delete(tokenStr);
  revokedTokens.set(tokenStr, now);
  if (revokedTokens.size > REVOKED_TOKEN_CACHE_MAX) {
    const ttlMs = TOKEN_TTL_RENEWAL * 1000;
    for (const [k, t] of revokedTokens) {
      if (now - t > ttlMs || revokedTokens.size > REVOKED_TOKEN_CACHE_MAX) {
        revokedTokens.delete(k);
      } else {
        break;
      }
    }
  }
}

function isTokenRevoked(tokenStr) {
  const revokedAt = revokedTokens.get(tokenStr);
  if (revokedAt === undefined) return false;
  if (Date.now() - revokedAt > TOKEN_TTL_RENEWAL * 1000) {
    revokedTokens.delete(tokenStr);
    return false;
  }
  return true;
}

async function issueStatelessToken(config, kind, epochSec = Math.floor(Date.now() / 1000)) {
  const nonce = new Uint8Array(16);
  crypto.getRandomValues(nonce);
  new DataView(nonce.buffer).setUint32(0, epochSec);
  const mac = (
    await computeHmac(
      config.tokenMasterKey,
      concatArrays(textEncoder.encode(TOKEN_LABEL_PREFIX), Uint8Array.of(kind), nonce)
    )
  ).subarray(0, 16);
  return toBase64Url(concatArrays(nonce, mac));
}

async function verifyStatelessToken(config, tokenStr, kind, maxTtl, epochSec = Math.floor(Date.now() / 1000)) {
  if (typeof tokenStr !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(tokenStr)) return false;
  if (isTokenRevoked(tokenStr)) return false;
  let rawBytes;
  try {
    rawBytes = fromBase64Url(tokenStr);
  } catch {
    return false;
  }
  if (rawBytes.length !== 32) return false;
  const nonce = rawBytes.subarray(0, 16);
  const providedMac = rawBytes.subarray(16);
  const expectedMac = (
    await computeHmac(
      config.tokenMasterKey,
      concatArrays(textEncoder.encode(TOKEN_LABEL_PREFIX), Uint8Array.of(kind), nonce)
    )
  ).subarray(0, 16);
  if (!timingSafeEquals(providedMac, expectedMac)) return false;
  const tokenAge = epochSec - new DataView(nonce.buffer, nonce.byteOffset, 4).getUint32(0);
  return tokenAge >= -30 && tokenAge <= maxTtl;
}

function extractBearerToken(request) {
  const authHeader = request.headers.get('Authorization') || '';
  const match = /^Bearer\s+([A-Za-z0-9_-]{43})$/i.exec(authHeader);
  return match ? match[1] : '';
}

async function isAdmin(env, provided) {
  const expected = typeof env?.ADMIN_TOKEN === 'string' ? env.ADMIN_TOKEN.trim() : '';
  if (expected.length < 20 || typeof provided !== 'string') return false;
  const [a, b] = await Promise.all([
    computeSha256(textEncoder.encode(provided)),
    computeSha256(textEncoder.encode(expected)),
  ]);
  return timingSafeEquals(a, b);
}

// Best-effort (per-isolate) session accounting.
let activeSessions = 0;
const sessionsPerIp = new Map();

function acquireSession(ip, env) {
  const maxTotal = parseIntEnv(env, 'MAX_SESSIONS', DEFAULT_MAX_SESSIONS, 1, 100000);
  const maxPerIp = parseIntEnv(env, 'MAX_SESSIONS_PER_IP', DEFAULT_MAX_SESSIONS_PER_IP, 1, 1000);
  const current = sessionsPerIp.get(ip) || 0;
  if (activeSessions >= maxTotal || current >= maxPerIp) return null;
  activeSessions++;
  sessionsPerIp.set(ip, current + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    activeSessions = Math.max(0, activeSessions - 1);
    const n = (sessionsPerIp.get(ip) || 1) - 1;
    if (n <= 0) sessionsPerIp.delete(ip);
    else sessionsPerIp.set(ip, n);
  };
}

// Obfuscated2 handshake replay cache (FIFO-safe Map per isolate).
const seenHandshakes = new Map();

function registerHandshake(handshakeBuffer) {
  const now = Date.now();
  const key = toBase64Url(handshakeBuffer.subarray(8, 56));
  const seenAt = seenHandshakes.get(key);
  if (seenAt !== undefined) {
    if (now - seenAt < REPLAY_TTL_MS) return false;
    // Delete before re-inserting so Map iteration order stays strictly chronological (FIFO).
    seenHandshakes.delete(key);
  }
  seenHandshakes.set(key, now);
  if (seenHandshakes.size > REPLAY_CACHE_MAX) {
    for (const [k, t] of seenHandshakes) {
      if (now - t > REPLAY_TTL_MS || seenHandshakes.size > REPLAY_CACHE_MAX) {
        seenHandshakes.delete(k);
      } else {
        break;
      }
    }
  }
  return true;
}

// ==================================================================================
// 5. OBFUSCATED2 RELAY ENGINE
// ==================================================================================

async function parseClientHandshake(config, handshakeBuffer) {
  const downKeySource = reverseBytes(handshakeBuffer.subarray(8, 56));
  const [clientUpKey, clientDownKey] = await Promise.all([
    computeSha256(concatArrays(handshakeBuffer.subarray(8, 40), config.secret16)),
    computeSha256(concatArrays(downKeySource.subarray(0, 32), config.secret16)),
  ]);
  const clientDownIv = downKeySource.slice(32, 48);

  const clientUpCipher = await createAesCtrCipher(clientUpKey, handshakeBuffer.slice(40, 56));
  const decryptedHeader = await applyAesCtr(clientUpCipher, 0, handshakeBuffer);

  const transportTag = new DataView(decryptedHeader.buffer, decryptedHeader.byteOffset + 56, 4).getUint32(0);
  const datacenterId = new DataView(decryptedHeader.buffer, decryptedHeader.byteOffset + 60, 2).getInt16(0, true);

  return { clientUpCipher, clientDownKey, clientDownIv, transportTag, datacenterId };
}

async function generateDcHandshake(clientHandshake) {
  const reversedDownMaterial = reverseBytes(
    concatArrays(clientHandshake.clientDownKey, clientHandshake.clientDownIv)
  );
  while (true) {
    const dcInit = new Uint8Array(64);
    crypto.getRandomValues(dcInit);
    const view = new DataView(dcInit.buffer);
    const firstWordLE = view.getUint32(0, true);
    const firstWordBE = view.getUint32(0, false);
    const secondWord = view.getUint32(4, false);

    if (
      dcInit[0] === 0xef ||
      FORBIDDEN_WORDS.has(firstWordLE) ||
      FORBIDDEN_WORDS.has(firstWordBE) ||
      secondWord === 0
    ) {
      continue;
    }

    dcInit.set(reversedDownMaterial, 8);
    view.setUint32(56, clientHandshake.transportTag);
    view.setInt16(60, clientHandshake.datacenterId, true);

    const dcUpCipher = await createAesCtrCipher(dcInit.slice(8, 40), dcInit.slice(40, 56));
    const sealed = await applyAesCtr(dcUpCipher, 0, dcInit);

    const wirePayload = dcInit.slice();
    wirePayload.set(sealed.subarray(56, 64), 56);
    return { wirePayload, dcUpCipher };
  }
}

async function connectToDatacenter(dcId) {
  const targetEndpoints = TELEGRAM_DCS[Math.abs(dcId)];
  if (!targetEndpoints || targetEndpoints.length === 0) {
    throw new Error(`TWP: Unsupported DC ID ${dcId}`);
  }
  let lastError = null;
  for (const hostname of targetEndpoints) {
    let timer = null;
    let tcpSocket = null;
    try {
      // Obfuscated2/MTProto uses its own encryption, so no TLS to the DC.
      tcpSocket = connect({ hostname, port: 443 }, { secureTransport: 'off', allowHalfOpen: false });
      // Prevent unhandled rejection crashes in workerd if socket closes/resets asynchronously.
      tcpSocket.opened?.catch(() => {});
      tcpSocket.closed?.catch(() => {});

      if (tcpSocket.opened) {
        await Promise.race([
          tcpSocket.opened,
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error('TWP: DC Connect Timeout')), DIAL_TIMEOUT_MS);
          }),
        ]);
      }
      clearTimeout(timer);
      return tcpSocket;
    } catch (err) {
      clearTimeout(timer);
      try { tcpSocket?.close(); } catch {}
      lastError = err;
    }
  }
  throw lastError || new Error('TWP: Datacenter connection failed');
}

// ==================================================================================
// 6. MULTIPLEXED CARRIER SESSION MANAGER
// ==================================================================================

function handleCarrierSession(webSocket, config, options) {
  const activeStreams = new Map();
  const retiredStreamIds = new Set();
  let totalDials = 0;
  let isClosed = false;
  let pingIntervalId = null;
  let queuedMsgBytes = 0;
  let lastHeardAt = Date.now();

  const sendRawBytes = (bytes) => {
    if (isClosed) return;
    try {
      webSocket.send(bytes);
    } catch {
      terminateSession(4001);
    }
  };

  const closeStreamSocket = (stream) => {
    stream.isTerminated = true;
    if (stream.wakeResolver) {
      const resolver = stream.wakeResolver;
      stream.wakeResolver = null;
      resolver();
    }
    if (stream.streamReader) {
      const reader = stream.streamReader;
      stream.streamReader = null;
      try { reader.cancel().catch(() => {}); } catch {}
      try { reader.releaseLock(); } catch {}
    }
    if (stream.streamWriter) {
      const writer = stream.streamWriter;
      stream.streamWriter = null;
      try { writer.releaseLock(); } catch {}
    }
    if (stream.tcpSocket) {
      const sock = stream.tcpSocket;
      stream.tcpSocket = null;
      try { sock.close(); } catch {}
    }
  };

  const terminateSession = (closeCode) => {
    if (isClosed) return;
    isClosed = true;
    if (pingIntervalId) {
      clearInterval(pingIntervalId);
      pingIntervalId = null;
    }
    for (const stream of activeStreams.values()) closeStreamSocket(stream);
    activeStreams.clear();
    try { webSocket.close(closeCode); } catch {}
    try { options.onClose?.(); } catch {}
  };

  const teardownStream = (stream, notifyPeer) => {
    const wasTerminated = stream.isTerminated;
    closeStreamSocket(stream);
    activeStreams.delete(stream.streamId);
    if (!wasTerminated && notifyPeer) {
      sendRawBytes(packFrame(FRAME_CLOSE, stream.streamId));
    }
  };

  const grantFlowWindow = (stream, bytesConsumed) => {
    stream.pendingWindowGrant += bytesConsumed;
    if (stream.isWindowGrantScheduled) return;
    stream.isWindowGrantScheduled = true;
    queueMicrotask(() => {
      stream.isWindowGrantScheduled = false;
      if (stream.isTerminated || isClosed || stream.pendingWindowGrant <= 0) return;
      const amount = stream.pendingWindowGrant;
      stream.pendingWindowGrant = 0;
      sendRawBytes(packFrame(FRAME_WINDOW, stream.streamId, writeUint32BE(amount)));
    });
  };

  const pumpDownlink = async (stream) => {
    try {
      while (!stream.isTerminated && stream.streamReader) {
        const { value: chunk, done: isDone } = await stream.streamReader.read();
        if (isDone || stream.isTerminated || !chunk) break;
        for (let offset = 0; offset < chunk.length; ) {
          while (stream.outboundCredit <= 0 && !stream.isTerminated) {
            await new Promise((resolve) => (stream.wakeResolver = resolve));
          }
          if (stream.isTerminated) return;
          const sendLen = Math.min(CHUNK_SIZE, chunk.length - offset, stream.outboundCredit);
          stream.outboundCredit -= sendLen;
          sendRawBytes(packFrame(FRAME_DATA, stream.streamId, chunk.subarray(offset, offset + sendLen)));
          offset += sendLen;
        }
      }
    } catch {}
    teardownStream(stream, true);
  };

  const initializeDatacenterConnection = async (stream) => {
    const clientHandshake = await parseClientHandshake(config, stream.handshakeBuffer);
    if (
      !PROTOCOL_TAGS.has(clientHandshake.transportTag) ||
      (config.isPadded && clientHandshake.transportTag !== 0xdddddddd) ||
      !TELEGRAM_DCS[Math.abs(clientHandshake.datacenterId)]
    ) {
      throw new Error('TWP: Handshake header rejected');
    }
    if (!registerHandshake(stream.handshakeBuffer)) {
      throw new Error('TWP: Handshake replay');
    }

    const dcHandshake = await generateDcHandshake(clientHandshake);
    const tcpSocket = await connectToDatacenter(clientHandshake.datacenterId);
    stream.tcpSocket = tcpSocket;

    if (stream.isTerminated || isClosed) {
      closeStreamSocket(stream);
      return;
    }

    stream.streamWriter = tcpSocket.writable.getWriter();
    stream.streamReader = tcpSocket.readable.getReader();

    await stream.streamWriter.write(dcHandshake.wirePayload);
    if (stream.isTerminated || isClosed) {
      closeStreamSocket(stream);
      return;
    }

    stream.clientCipher = clientHandshake.clientUpCipher;
    stream.dcCipher = dcHandshake.dcUpCipher;
    stream.isHandshakeComplete = true;

    pumpDownlink(stream);
  };

  const processUplinkPayload = async (stream, chunk) => {
    if (stream.isTerminated) return;
    let remainingChunk = chunk;

    if (!stream.isHandshakeComplete) {
      const neededBytes = Math.min(64 - stream.handshakeBytesReceived, remainingChunk.length);
      stream.handshakeBuffer.set(remainingChunk.subarray(0, neededBytes), stream.handshakeBytesReceived);
      stream.handshakeBytesReceived += neededBytes;
      remainingChunk = remainingChunk.subarray(neededBytes);

      if (stream.handshakeBytesReceived < 64) {
        grantFlowWindow(stream, chunk.length);
        return;
      }
      await initializeDatacenterConnection(stream);
      if (stream.isTerminated) return;
    }

    if (remainingChunk.length > 0) {
      const offset = stream.streamByteOffset;
      stream.streamByteOffset += remainingChunk.length;
      const plaintext = await applyAesCtr(stream.clientCipher, offset, remainingChunk);
      const reEncrypted = await applyAesCtr(stream.dcCipher, offset, plaintext);
      if (stream.isTerminated || !stream.streamWriter) return;
      await stream.streamWriter.write(reEncrypted);
    }
    grantFlowWindow(stream, chunk.length);
  };

  const handleIncomingFrame = (f) => {
    if (f.id === 0) return; // FRAME_PONG already updated lastHeardAt

    if (f.type === FRAME_OPEN) {
      if (retiredStreamIds.has(f.id)) return terminateSession(4001);
      if (retiredStreamIds.size >= MAX_RETIRED_IDS) {
        const oldest = retiredStreamIds.values().next().value;
        retiredStreamIds.delete(oldest);
      }
      retiredStreamIds.add(f.id);

      if (totalDials >= options.maxDials || activeStreams.size >= MAX_STREAMS_COUNT) {
        return sendRawBytes(packFrame(FRAME_CLOSE, f.id));
      }
      totalDials++;

      activeStreams.set(f.id, {
        streamId: f.id,
        isTerminated: false,
        isHandshakeComplete: false,
        outboundCredit: INITIAL_STREAM_WIN,
        wakeResolver: null,
        pendingWindowGrant: 0,
        isWindowGrantScheduled: false,
        handshakeBuffer: new Uint8Array(64),
        handshakeBytesReceived: 0,
        streamByteOffset: 64,
        pendingUplink: 0,
        clientCipher: null,
        dcCipher: null,
        tcpSocket: null,
        streamReader: null,
        streamWriter: null,
        pipelinePromise: Promise.resolve(),
      });
      return;
    }

    const stream = activeStreams.get(f.id);
    if (!stream) {
      if (!retiredStreamIds.has(f.id)) terminateSession(4001);
      return;
    }

    if (f.type === FRAME_DATA) {
      const payloadSlice = f.payload.slice();
      stream.pendingUplink += payloadSlice.length;
      if (stream.pendingUplink > MAX_PENDING_UPLINK_PER_STREAM) {
        teardownStream(stream, true);
        return;
      }
      stream.pipelinePromise = stream.pipelinePromise
        .then(async () => {
          try {
            await processUplinkPayload(stream, payloadSlice);
          } finally {
            stream.pendingUplink -= payloadSlice.length;
          }
        })
        .catch(() => teardownStream(stream, true));
    } else if (f.type === FRAME_CLOSE) {
      teardownStream(stream, false);
    } else if (f.type === FRAME_WINDOW) {
      const creditIncrement = new DataView(f.payload.buffer, f.payload.byteOffset, 4).getUint32(0);
      stream.outboundCredit = Math.min(0x7fffffff, stream.outboundCredit + creditIncrement);
      if (stream.wakeResolver) {
        const resolver = stream.wakeResolver;
        stream.wakeResolver = null;
        resolver();
      }
    }
  };

  let messageQueue = Promise.resolve();
  webSocket.addEventListener('message', (event) => {
    if (isClosed) return;
    lastHeardAt = Date.now();
    const declaredSize = event.data?.byteLength ?? event.data?.size ?? 0;
    queuedMsgBytes += declaredSize;
    if (queuedMsgBytes > MAX_QUEUED_MSG_BYTES) return terminateSession(4001);

    messageQueue = messageQueue.then(async () => {
      try {
        if (isClosed) return;
        let data = event.data;
        if (typeof Blob !== 'undefined' && data instanceof Blob) {
          try { data = await data.arrayBuffer(); } catch { return terminateSession(4001); }
        }
        if (ArrayBuffer.isView(data)) {
          data = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
        }
        if (!(data instanceof ArrayBuffer) || data.byteLength === 0 || data.byteLength > MAX_CARRIER_MSG) {
          return terminateSession(4001);
        }
        let frames;
        try {
          frames = unpackFrameBatch(new Uint8Array(data));
          frames.forEach(validateClientFrame);
        } catch {
          return terminateSession(4001);
        }
        for (const f of frames) {
          if (isClosed) return;
          handleIncomingFrame(f);
        }
      } finally {
        queuedMsgBytes -= declaredSize;
      }
    }).catch(() => terminateSession(4001));
  });

  webSocket.addEventListener('close', () => terminateSession(1000));
  webSocket.addEventListener('error', () => terminateSession(1000));

  if (options.pingMs) {
    pingIntervalId = setInterval(() => {
      if (isClosed) return;
      if (Date.now() - lastHeardAt > CARRIER_IDLE_TIMEOUT_MS) {
        terminateSession(4000);
        return;
      }
      issueStatelessToken(config, 2).then((sessionToken) => {
        sendRawBytes(packFrame(FRAME_PING, 0, textEncoder.encode(sessionToken)));
      }, () => {});
    }, options.pingMs);
  }
}

// ==================================================================================
// 7. BRIDGE SCRIPT & PAGES
// ==================================================================================

const EMBEDDED_BRIDGE_SCRIPT = String.raw`(()=>{
'use strict';
const BASE=__BASE__,BOOT=__BOOT__,DIALS=__DIALS__;
const found=/^#android=([A-Za-z0-9_-]{43})$/.exec(location.hash);
const androidNonce=found?found[1]:'';
history.replaceState(null,'',location.pathname);
const QUEUE_LIMIT=33554432,MESSAGE_LIMIT=262144,BUFFER_LIMIT=4194304,FRAME_LIMIT=4096,PAYLOAD_LIMIT=1048576;
const WARM_AT=Math.max(1,DIALS-12),SWITCH_AT=Math.max(1,DIALS-2),QUIET_MS=65000,TRIES=3,DEATHS=4,DEATH_WINDOW_MS=30000;
const HELLO=[16,0,0,0,0,0,0,1,1];
const textDecoder=new TextDecoder();
let closed=false,started=false,connected=false,token=BOOT,port=null,queued=0,cur=null,next=null,watch=0;
const lanes=new Set(),route=new Map(),deaths=[];
const post=(value)=>{if(port&&!closed)port.postMessage(value)};
const status=(state)=>post({t:'status',state});
const traffic=(up,down)=>post({t:'traffic',up,down});
const request=(method,token,body)=>({method,body,keepalive:method==='DELETE',mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',headers:Object.assign(token?{Authorization:'Bearer '+token}:{},body?{'Content-Type':'application/octet-stream'}:{})});
const pause=(ms)=>new Promise((resolve)=>setTimeout(resolve,ms));
function split(buffer){
 const view=new DataView(buffer),frames=[];let at=0;
 while(at<buffer.byteLength){
  if(buffer.byteLength-at<8||frames.length>=FRAME_LIMIT)throw new Error('batch');
  const size=view.getUint32(at+4),end=at+8+size;
  if(size>PAYLOAD_LIMIT||end>buffer.byteLength||(view.getUint8(at)===2&&!size))throw new Error('frame');
  frames.push(at===0&&end===buffer.byteLength?buffer:buffer.slice(at,end));at=end;
 }
 if(!frames.length)throw new Error('empty');
 return frames;
}
function frameOf(type,id,payload){
 const size=payload?payload.length:0,out=new Uint8Array(8+size),view=new DataView(out.buffer);
 view.setUint32(0,id);out[0]=type;view.setUint32(4,size);if(size)out.set(payload,8);
 return out.buffer;
}
const typeOf=(item)=>new DataView(item).getUint8(0);
const idOf=(item)=>new DataView(item).getUint32(0)&16777215;
function fail(){
 if(closed)return;
 status('failed');post({t:'close'});close(true);
}
function close(notify){
 if(closed)return;closed=true;
 if(watch)clearInterval(watch);
 for(const lane of lanes)shut(lane);
 if(notify&&token!==BOOT)fetch(BASE+'api/v1/session',request('DELETE',token,null)).catch(()=>{});
 if(port&&port.close)port.close();
}
function makeLane(){
 const lane={ws:null,ready:false,dead:false,opens:0,streams:new Set(),out:[],heard:0,pinged:false,timer:0};
 lanes.add(lane);return lane;
}
function shut(lane){
 if(lane.dead)return false;
 lane.dead=true;lane.ready=false;lanes.delete(lane);
 if(lane.timer)clearTimeout(lane.timer);
 for(const item of lane.out)queued-=item.byteLength;
 lane.out=[];
 try{if(lane.ws)lane.ws.close()}catch(e){}
 if(cur===lane)cur=null;
 if(next===lane)next=null;
 return true;
}
function lost(lane){
 if(!shut(lane)||closed)return;
 for(const id of lane.streams){if(route.get(id)===lane)route.delete(id);post(frameOf(3,id))}
 lane.streams.clear();
 const now=Date.now();deaths.push(now);
 while(now-deaths[0]>DEATH_WINDOW_MS)deaths.shift();
 if(deaths.length>=DEATHS){fail();return}
 if(connected&&!cur)warm();
}
function retire(lane){
 if(lane!==cur&&lane!==next&&!lane.streams.size&&!lane.out.length)shut(lane);
}
function openSocket(lane,session){
 return new Promise((resolve,reject)=>{
  const ws=new WebSocket(BASE.replace(/^https:/,'wss:')+'api/v1/ws','tproxy-v1.'+session);
  lane.ws=ws;ws.binaryType='arraybuffer';
  ws.onopen=()=>{if(lane.ws!==ws||lane.dead){reject(new Error('gone'));return}lane.ready=true;lane.heard=Date.now();resolve()};
  ws.onerror=()=>{if(!lane.ready)reject(new Error('socket'))};
  ws.onclose=()=>{if(lane.ws!==ws)return;if(lane.ready)lost(lane);else reject(new Error('socket'))};
  ws.onmessage=(event)=>{if(lane.ws===ws)fromRelay(lane,event.data)};
 });
}
async function connectLane(lane,hello,tries){
 for(let i=1;;i++){
  try{
   const response=await fetch(BASE+'api/v1/session',request('POST',token,hello));
   if(response.status!==200||response.headers.get('X-Carrier-Mode')!=='websocket')throw new Error(response.status===404?'refused':'rejected');
   const session=response.headers.get('X-Session-Token')||'';
   if(!session)throw new Error('token');
   const welcome=await response.arrayBuffer();
   if(lane.dead)return null;
   token=session;
   await openSocket(lane,session);
   return welcome;
  }catch(e){
   if(lane.dead||i>=tries||e.message==='refused')throw e;
   try{if(lane.ws)lane.ws.close()}catch(x){}
   await pause(800*i);
  }
 }
}
function promote(lane){
 if(next===lane)next=null;
 const old=cur;cur=lane;
 flush(lane);
 if(old)retire(old);
 if(lane.opens>=WARM_AT)warm();
}
function warm(){
 if(next||closed)return;
 const lane=makeLane();next=lane;
 connectLane(lane,new Uint8Array(HELLO).buffer,TRIES).then((welcome)=>{if(welcome&&!closed&&!lane.dead)promote(lane)},()=>{
  if(closed)return;
  if(!cur||cur.opens>=SWITCH_AT){fail();return}
  lost(lane);
 });
}
function laneFor(){
 if(cur&&cur.opens<SWITCH_AT)return cur;
 warm();
 return next;
}
function send(lane,item){
 if(lane.dead)return;
 if(queued+item.byteLength>QUEUE_LIMIT){fail();return}
 queued+=item.byteLength;lane.out.push(item);flush(lane);
}
function flush(lane){
 if(closed||!lane.ready)return;
 const ws=lane.ws;
 while(lane.out.length){
  if(ws.bufferedAmount>BUFFER_LIMIT){if(!lane.timer)lane.timer=setTimeout(()=>{lane.timer=0;flush(lane);retire(lane)},10);return}
  let total=0,count=0;
  while(count<lane.out.length&&count<FRAME_LIMIT){
   const size=lane.out[count].byteLength;
   if(count&&total+size>MESSAGE_LIMIT)break;
   total+=size;count++;
  }
  const body=new Uint8Array(total);let at=0;
  for(const item of lane.out.splice(0,count)){body.set(new Uint8Array(item),at);at+=item.byteLength}
  queued-=total;
  try{ws.send(body)}catch(e){lost(lane);return}
  traffic(total,0);
 }
}
function fromApp(item){
 const type=typeOf(item),id=idOf(item);
 if(!id)return;
 if(type===1){
  const lane=laneFor();
  if(!lane)return;
  route.set(id,lane);lane.streams.add(id);lane.opens++;
  send(lane,item);
  if(lane===cur&&lane.opens>=WARM_AT)warm();
  return;
 }
 const lane=route.get(id);
 if(!lane)return;
 if(type===3){route.delete(id);lane.streams.delete(id)}
 send(lane,item);
 if(type===3)retire(lane);
}
function fromRelay(lane,data){
 if(lane.dead||closed)return;
 if(!(data instanceof ArrayBuffer)||!data.byteLength){lost(lane);return}
 let frames;try{frames=split(data)}catch(e){lost(lane);return}
 lane.heard=Date.now();
 traffic(0,data.byteLength);
 for(const item of frames){
  const type=typeOf(item),id=idOf(item);
  if(!id){if(type===5)ping(lane,item);continue}
  if(type===3){lane.streams.delete(id);if(route.get(id)===lane)route.delete(id)}
  post(item);
 }
 retire(lane);
 flush(lane);
}
function ping(lane,item){
 const echo=new Uint8Array(item,8);
 if(echo.length>64)return;
 lane.pinged=true;
 const text=textDecoder.decode(echo);
 if(/^[A-Za-z0-9_-]{43}$/.test(text))token=text;
 send(lane,frameOf(6,0,echo));
}
function check(){
 const now=Date.now();
 for(const lane of lanes)if(lane.ready&&lane.pinged&&now-lane.heard>QUIET_MS)lost(lane);
}
async function start(hello){
 status('connecting');
 const lane=makeLane();next=lane;
 try{
  const welcome=await connectLane(lane,hello,1);
  if(!welcome||closed)return;
  connected=true;
  promote(lane);
  post(welcome);status('connected');
  watch=setInterval(check,15000);
 }catch(e){fail()}
}
function onApp(data){
 if(data instanceof ArrayBuffer){
  if(!started){started=true;start(data);return}
  let frames;try{frames=split(data)}catch(e){fail();return}
  for(const item of frames)fromApp(item);
 }else if(data&&data.t==='close')close(true);
}
const bridge=globalThis.TelegramWebProxy;
if(androidNonce&&bridge&&typeof bridge.postMessage==='function'){
 port={postMessage(value){bridge.postMessage(value instanceof ArrayBuffer?value:JSON.stringify(value))},close(){bridge.onmessage=null}};
 bridge.onmessage=(event)=>{
  let data=event.data;
  if(typeof data==='string'){try{data=JSON.parse(data)}catch(e){return}}
  onApp(data);
 };
 status('connecting');
 bridge.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce:androidNonce}));
}
addEventListener('message',(event)=>{
 if(port||event.source!==parent||event.data===null||typeof event.data!=='object')return;
 const keys=Object.keys(event.data).sort();
 if(keys.length!==2||keys[0]!=='t'||keys[1]!=='v'||event.data.t!=='tproxy-init'||event.data.v!==1||event.ports.length!==1)return;
 let from;try{from=new URL(event.origin)}catch(e){return}
 if(from.protocol!=='http:'||from.hostname!=='127.0.0.1'||!from.port||from.origin!==event.origin)return;
 const channel=event.ports[0];
 port={postMessage(value){if(value instanceof ArrayBuffer)channel.postMessage(value,[value]);else channel.postMessage(value)},close(){channel.close()}};
 channel.onmessage=(message)=>onApp(message.data);
 channel.start();status('connecting');
});
addEventListener('pagehide',()=>close(true),{once:true});
})();`;

const PERMISSIONS_POLICY =
  'accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), ' +
  'encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), ' +
  'magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), screen-wake-lock=(), ' +
  'serial=(), usb=(), web-share=(), xr-spatial-tracking=()';

function renderBridgeHtml(hostname, bootstrapToken, maxDials) {
  const nonceBytes = new Uint8Array(18);
  crypto.getRandomValues(nonceBytes);
  const nonceStr = toBase64Url(nonceBytes);

  const populatedScript = EMBEDDED_BRIDGE_SCRIPT
    .replace('__BASE__', () => JSON.stringify(`https://${hostname}/`))
    .replace('__BOOT__', () => JSON.stringify(bootstrapToken))
    .replace('__DIALS__', () => String(maxDials));

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Connection</title>
</head>
<body>
  <script nonce="${nonceStr}">${populatedScript}</script>
</body>
</html>`;

  const csp = [
    "default-src 'none'",
    "base-uri 'none'",
    "child-src 'none'",
    `connect-src 'self' wss://${hostname}`,
    "font-src 'none'",
    "form-action 'none'",
    'frame-ancestors http://127.0.0.1:*',
    "frame-src 'none'",
    "img-src 'none'",
    "manifest-src 'none'",
    "media-src 'none'",
    "object-src 'none'",
    `script-src 'nonce-${nonceStr}'`,
    "style-src 'none'",
    "worker-src 'none'",
    'sandbox allow-same-origin allow-scripts',
  ].join('; ');

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': csp,
      'Permissions-Policy': PERMISSIONS_POLICY,
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'X-DNS-Prefetch-Control': 'off',
    },
  });
}

function renderAdminDashboard(hostname, secretHex) {
  const nonceBytes = new Uint8Array(18);
  crypto.getRandomValues(nonceBytes);
  const nonce = toBase64Url(nonceBytes);

  const q = 'server=' + encodeURIComponent(hostname) + '&secret=' + encodeURIComponent(secretHex);
  const deepLink = 'tg://webproxy?' + q;
  const webLink = 'https://t.me/webproxy?' + q;

  const html = `<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>TWP Admin</title>
<style nonce="${nonce}">
:root{--bg:#000;--card:#070a10;--border:rgba(255,255,255,.1);--accent:#00d2ff;--text:#f8fafc;--muted:#94a3b8}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Vazirmatn,Tahoma,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem}
.card{width:100%;max-width:560px;background:var(--card);border:1px solid var(--border);border-radius:1.1rem;padding:1.5rem}
h1{font-size:1.3rem;margin-bottom:.4rem}
p{color:var(--muted);font-size:.85rem;line-height:1.6;margin-bottom:1rem}
.warn{border:1px solid rgba(245,158,11,.4);background:rgba(245,158,11,.08);color:#fbbf24;border-radius:.6rem;padding:.6rem .8rem;font-size:.8rem;margin-bottom:1rem}
a.btn{display:block;text-align:center;background:#229ED9;color:#fff;text-decoration:none;font-weight:700;padding:.85rem;border-radius:.75rem;margin-bottom:1rem}
.row{display:flex;gap:.5rem;align-items:center;background:#030508;border:1px solid var(--border);border-radius:.65rem;padding:.6rem .7rem;margin-bottom:.7rem}
code{flex:1;overflow-x:auto;white-space:nowrap;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.78rem;color:var(--accent);direction:ltr;text-align:left}
button{background:rgba(255,255,255,.1);border:1px solid var(--border);color:var(--text);border-radius:.45rem;padding:.4rem .75rem;font-size:.75rem;cursor:pointer}
.meta{display:grid;grid-template-columns:1fr 1fr;gap:.5rem;margin-top:1rem;font-size:.78rem;color:var(--muted);direction:ltr}
.meta div{border:1px solid var(--border);border-radius:.5rem;padding:.5rem .65rem;overflow:hidden;text-overflow:ellipsis}
</style>
</head>
<body>
<div class="card">
  <h1>Telegram WEB Proxy - Admin</h1>
  <p>Admin only. Do not share this page or its URL: it contains your proxy secret.<br>فقط برای مدیر. این صفحه و آدرسش را به اشتراک نگذارید؛ شامل سیکرت پروکسی است.</p>
  <div class="warn">Anyone who has these links can use your proxy and your Worker quota.</div>
  <a class="btn" href="${escapeHtml(deepLink)}">Connect in Telegram</a>
  <div class="row"><code>${escapeHtml(deepLink)}</code><button data-copy="${escapeHtml(deepLink)}">Copy</button></div>
  <div class="row"><code>${escapeHtml(webLink)}</code><button data-copy="${escapeHtml(webLink)}">Copy</button></div>
  <div class="meta"><div>Host: ${escapeHtml(hostname)}</div><div>Port: 443 (WSS)</div></div>
</div>
<script nonce="${nonce}">
document.querySelectorAll('button[data-copy]').forEach(function(b){
  b.addEventListener('click',function(){
    navigator.clipboard.writeText(b.getAttribute('data-copy')).then(function(){
      var o=b.textContent;b.textContent='OK';setTimeout(function(){b.textContent=o},1500);
    });
  });
});
</script>
</body>
</html>`;

  const csp = [
    "default-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "img-src 'none'",
    "connect-src 'none'",
    `script-src 'nonce-${nonce}'`,
    `style-src 'nonce-${nonce}'`,
  ].join('; ');

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': csp,
      'Cache-Control': 'no-store, max-age=0',
      'Referrer-Policy': 'no-referrer',
      'X-Robots-Tag': 'noindex, nofollow',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    },
  });
}

function renderNotFound() {
  const notFoundHtml =
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>';
  return new Response(notFoundHtml, {
    status: 404,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

const CAMOUFLAGE_FORWARD_HEADERS = [
  'accept',
  'accept-language',
  'accept-encoding',
  'user-agent',
  'if-none-match',
  'if-modified-since',
  'range',
];

const CAMOUFLAGE_STRIP_RESPONSE_HEADERS = [
  'set-cookie',
  'alt-svc',
  'clear-site-data',
  'strict-transport-security',
];

/**
 * Anything that is not a valid proxy/bridge/admin request ends up here.
 * With CAMOUFLAGE_URL it looks like the decoy site; otherwise a plain 404.
 */
async function fallback(request, env) {
  const base = typeof env?.CAMOUFLAGE_URL === 'string' ? env.CAMOUFLAGE_URL.trim() : '';
  if (!base || (request.method !== 'GET' && request.method !== 'HEAD')) return renderNotFound();
  try {
    const baseUrl = new URL(base);
    if (baseUrl.protocol !== 'https:') return renderNotFound();
    const incoming = new URL(request.url);
    const target = new URL(incoming.pathname + incoming.search, baseUrl);
    const headers = new Headers();
    for (const name of CAMOUFLAGE_FORWARD_HEADERS) {
      const v = request.headers.get(name);
      if (v) headers.set(name, v);
    }
    const upstream = await fetch(target.toString(), {
      method: request.method,
      headers,
      redirect: 'follow',
    });
    const out = new Response(upstream.body, upstream);
    for (const h of CAMOUFLAGE_STRIP_RESPONSE_HEADERS) {
      out.headers.delete(h);
    }
    return out;
  } catch {
    return renderNotFound();
  }
}

// ==================================================================================
// 8. HTTP ROUTER
// ==================================================================================

const HELLO_FRAME_BYTES = Uint8Array.of(FRAME_HELLO, 0, 0, 0, 0, 0, 0, 1, 1);
const HOSTNAME_RE =
  /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

async function handleHttpRequest(request, env) {
  const config = await resolveConfig(env);
  if (!config) return fallback(request, env);

  const url = new URL(request.url);
  const hostname = url.hostname.toLowerCase();
  if (!HOSTNAME_RE.test(hostname)) return renderNotFound();

  // Route 1: Bridge initializer
  if (url.pathname === '/' && request.method === 'GET' && /^\?bridge=[A-Za-z0-9_-]{43}$/.test(url.search)) {
    const expectedCapability = toBase64Url(
      await computeHmac(config.capabilityKey, textEncoder.encode(BRIDGE_DOMAIN_LABEL + hostname))
    );
    const providedCapability = url.search.slice(8);
    if (!timingSafeEquals(textEncoder.encode(providedCapability), textEncoder.encode(expectedCapability))) {
      return fallback(request, env);
    }
    const bootstrapToken = await issueStatelessToken(config, 1);
    return renderBridgeHtml(hostname, bootstrapToken, resolveMaxDials(env));
  }

  // Route 2: Admin dashboard (the only place the secret is ever shown)
  if (url.pathname === '/' && request.method === 'GET' && /^\?admin=[A-Za-z0-9._~-]{20,128}$/.test(url.search)) {
    if (await isAdmin(env, url.search.slice(7))) {
      return renderAdminDashboard(hostname, toHex(config.fullBytes));
    }
    return fallback(request, env);
  }

  // Route 3: Session lifecycle API
  if (url.pathname === '/api/v1/session') {
    if (request.method === 'POST') {
      const authBearer = extractBearerToken(request);
      const isBootstrapValid = await verifyStatelessToken(config, authBearer, 1, TOKEN_TTL_BOOTSTRAP);
      const isRenewalValid =
        isBootstrapValid || (await verifyStatelessToken(config, authBearer, 2, TOKEN_TTL_RENEWAL));
      if (!isRenewalValid) return fallback(request, env);

      const contentLengthHeader = request.headers.get('Content-Length');
      if (contentLengthHeader !== null) {
        const declaredLength = parseInt(contentLengthHeader, 10);
        if (!Number.isFinite(declaredLength) || declaredLength !== HELLO_FRAME_BYTES.length) {
          return fallback(request, env);
        }
      }

      const requestBody = new Uint8Array(await request.arrayBuffer());
      if (!timingSafeEquals(requestBody, HELLO_FRAME_BYTES)) return fallback(request, env);

      return new Response(packFrame(FRAME_WELCOME, 0), {
        status: 200,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Cache-Control': 'no-store',
          'X-Session-Token': await issueStatelessToken(config, 2),
          'X-Down-Cursor': '0',
          'X-Carrier-Mode': 'websocket',
        },
      });
    }

    if (request.method === 'DELETE') {
      const authBearer = extractBearerToken(request);
      if (!(await verifyStatelessToken(config, authBearer, 2, TOKEN_TTL_RENEWAL))) {
        return fallback(request, env);
      }
      revokeToken(authBearer);
      return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
    }

    return fallback(request, env);
  }

  // Route 4: Multiplexed WebSocket upgrade
  if (
    url.pathname === '/api/v1/ws' &&
    request.method === 'GET' &&
    (request.headers.get('Upgrade') || '').toLowerCase() === 'websocket'
  ) {
    const rawProtocols = request.headers.get('Sec-WebSocket-Protocol') || '';
    const subprotocols = rawProtocols.split(',').map((p) => p.trim());
    let tokenMatch = null;
    let selectedProtocol = '';
    for (const sp of subprotocols) {
      const match = /^tproxy-v1\.([A-Za-z0-9_-]{43})$/.exec(sp);
      if (match) {
        tokenMatch = match[1];
        selectedProtocol = sp;
        break;
      }
    }
    if (!tokenMatch || !(await verifyStatelessToken(config, tokenMatch, 2, TOKEN_TTL_SESSION))) {
      return fallback(request, env);
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const release = acquireSession(ip, env);
    if (!release) {
      return new Response('Too Many Requests', {
        status: 429,
        headers: { 'Retry-After': '30', 'Cache-Control': 'no-store' },
      });
    }

    const pair = new WebSocketPair();
    const clientSocket = pair[0];
    const serverSocket = pair[1];
    serverSocket.accept();

    handleCarrierSession(serverSocket, config, {
      maxDials: resolveMaxDials(env),
      pingMs: CARRIER_PING_MS,
      onClose: release,
    });

    return new Response(null, {
      status: 101,
      webSocket: clientSocket,
      headers: { 'Sec-WebSocket-Protocol': selectedProtocol },
    });
  }

  // Everything else: decoy site or plain 404 (never reveals the secret or the proxy)
  return fallback(request, env);
}

export default {
  async fetch(request, env) {
    try {
      return await handleHttpRequest(request, env);
    } catch {
      return renderNotFound();
    }
  },
};