import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { URLSearchParams } from 'node:url';
import { createRequire } from 'node:module';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import yaml from 'js-yaml';
import knex from 'knex';
import { generateSecret, generateURI, verifySync } from 'otplib';

const app = express();
const AUTH_COOKIE_NAME = 'auth_token';
const TERMINAL_COOKIE_NAME = 'terminal_token';
const REFRESH_COOKIE_NAME = 'refresh_token';
const REFRESH_SESSION_COOKIE_NAME = 'refresh_session';
const CSRF_COOKIE_NAME = 'csrf_token';
const ACCESS_TOKEN_TTL_MINUTES = Math.max(5, parseInt(process.env.TAILSHELL_ACCESS_TOKEN_TTL_MIN || '15', 10) || 15);
const REFRESH_TOKEN_TTL_DAYS = Math.max(1, parseInt(process.env.TAILSHELL_REFRESH_TOKEN_TTL_DAYS || '7', 10) || 7);
const ACCESS_TOKEN_TTL_MS = ACCESS_TOKEN_TTL_MINUTES * 60 * 1000;
const REFRESH_TOKEN_TTL_MS = REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000;
const TAILSHELL_RELEASE = String(process.env.TAILSHELL_RELEASE || '').trim() || null;

const require = createRequire(import.meta.url);

// Behind nginx in Docker; trust X-Forwarded-* for correct client IP and proto.
app.set('trust proxy', 1);

// Security middleware
app.use(helmet());
const corsOriginEnv = (process.env.CORS_ORIGIN || '').trim();
if (corsOriginEnv.length === 0) {
  // Default: disable CORS (nginx serves API same-origin at /api)
  app.use(cors({ origin: false }));
} else {
  const allowlist = corsOriginEnv
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin) return callback(null, false);
        if (allowlist.includes(origin)) return callback(null, true);
        return callback(null, false);
      },
      // Default to header-based auth for cross-origin dev; enable cookies explicitly if needed
      credentials: String(process.env.CORS_CREDENTIALS || '').toLowerCase() === 'true'
    })
  );
}
app.use(express.json({ limit: '1mb' }));

function readSecretFile(path) {
  if (!path) return null;
  try {
    return fs.readFileSync(path, 'utf8').trim();
  } catch (error) {
    console.warn(`Unable to read secret file ${path}:`, error?.message ?? error);
    return null;
  }
}

function getEnvValue(key) {
  const fileKey = `${key}_FILE`;
  const filePath = String(process.env[fileKey] || '').trim();
  if (filePath) {
    const fromFile = readSecretFile(filePath);
    if (fromFile !== null) return fromFile;
  }
  return String(process.env[key] || '').trim();
}

const DATABASE_PASSWORD = getEnvValue('DATABASE_PASSWORD');
const JWT_SECRET = getEnvValue('JWT_SECRET');
const ADMIN_BOOTSTRAP_PASSWORD = getEnvValue('TAILSHELL_ADMIN_PASSWORD');

// Request context + structured logging
function normalizeRequestId(value) {
  const id = String(value || '').trim();
  if (id.length === 0) return null;
  // Prevent unbounded header growth / log spam
  return id.slice(0, 128);
}

function sanitizeLogPath(value) {
  const path = String(value || '').split('?')[0];
  return path
    .replace(/^\/api\/invites\/[^/]+(\/accept)?$/, '/api/invites/[token]$1')
    .replace(/^\/api\/password-resets\/[^/]+$/, '/api/password-resets/[token]');
}

app.use((req, res, next) => {
  const headerId = normalizeRequestId(req.headers['x-request-id']);
  const requestId = headerId || crypto.randomUUID();
  req.requestId = requestId;
  res.locals.requestId = requestId;
  res.setHeader('X-Request-Id', requestId);

  const start = process.hrtime.bigint();
  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
    const user = req.user && typeof req.user === 'object' ? req.user : null;

    const entry = {
      ts: new Date().toISOString(),
      release: TAILSHELL_RELEASE,
      requestId,
      method: req.method,
      path: sanitizeLogPath(req.originalUrl),
      status: res.statusCode,
      durationMs: Math.round(durationMs * 100) / 100,
      ip: req.ip,
      userId: user?.userId ?? null,
      username: user?.username ?? null,
      role: user?.role ?? null
    };

    // Avoid logging extremely noisy endpoints.
    const path = String(req.path || '');
    if (path === '/api/health' || path === '/api/ready') return;
    console.log(JSON.stringify(entry));
  });

  next();
});

function isPlainObject(value) {
  if (!value || typeof value !== 'object') return false;
  if (Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

const ERROR_CODE_BY_STATUS = new Map([
  [400, 'BAD_REQUEST'],
  [401, 'UNAUTHORIZED'],
  [403, 'FORBIDDEN'],
  [404, 'NOT_FOUND'],
  [409, 'CONFLICT'],
  [410, 'GONE'],
  [413, 'PAYLOAD_TOO_LARGE'],
  [415, 'UNSUPPORTED_MEDIA'],
  [422, 'VALIDATION_ERROR'],
  [429, 'RATE_LIMITED'],
  [500, 'INTERNAL_ERROR'],
  [502, 'BAD_GATEWAY'],
  [503, 'SERVICE_UNAVAILABLE'],
  [504, 'GATEWAY_TIMEOUT']
]);

function statusToErrorCode(status) {
  return ERROR_CODE_BY_STATUS.get(status) || 'ERROR';
}

function normalizeErrorPayload(body, statusCode, requestId) {
  const isObject = isPlainObject(body);
  const error = isObject
    ? (body.error ?? body.message ?? 'Request failed')
    : typeof body === 'string'
      ? body
      : 'Request failed';
  const code = isObject ? (body.code ?? statusToErrorCode(statusCode)) : statusToErrorCode(statusCode);
  const details = isObject ? (body.details ?? body.fields ?? body.meta) : undefined;
  const normalized = { error, code, requestId };
  if (details !== undefined) normalized.details = details;

  if (!isObject) return normalized;

  const passthrough = { ...body };
  delete passthrough.error;
  delete passthrough.message;
  delete passthrough.code;
  delete passthrough.details;
  delete passthrough.fields;
  delete passthrough.meta;
  delete passthrough.requestId;
  return { ...normalized, ...passthrough };
}

app.use((req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = (body) => {
    if (res.headersSent) return originalJson(body);
    if (res.statusCode >= 400) {
      const normalized = normalizeErrorPayload(body, res.statusCode, res.locals.requestId);
      return originalJson(normalized);
    }
    return originalJson(body);
  };
  next();
});

const JSON_BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);
app.use((req, res, next) => {
  if (!JSON_BODY_METHODS.has(req.method)) return next();
  if (!req.is('application/json')) return next();
  if (!isPlainObject(req.body)) {
    return res.status(400).json({ error: 'Invalid JSON body', code: 'INVALID_BODY' });
  }
  return next();
});

const CSRF_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const CSRF_EXEMPT_PATHS = new Set(['/api/auth/login']);
const csrfOriginAllowlist = (() => {
  const raw = String(process.env.TAILSHELL_CSRF_ORIGINS || process.env.CORS_ORIGIN || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  return raw;
})();

function isSameOrigin(requestOrigin, expectedOrigin) {
  if (!requestOrigin || !expectedOrigin) return false;
  try {
    const originUrl = new URL(requestOrigin);
    const expectedUrl = new URL(expectedOrigin);
    return originUrl.protocol === expectedUrl.protocol && originUrl.host === expectedUrl.host;
  } catch {
    return false;
  }
}

function isAllowedOrigin(requestOrigin, req) {
  if (!requestOrigin) return false;
  if (csrfOriginAllowlist.length > 0) {
    return csrfOriginAllowlist.some((allowed) => isSameOrigin(requestOrigin, allowed));
  }
  const expected = `${req.protocol}://${req.get('host')}`;
  return isSameOrigin(requestOrigin, expected);
}

app.use((req, res, next) => {
  if (!CSRF_METHODS.has(req.method)) return next();
  if (CSRF_EXEMPT_PATHS.has(req.path)) return next();
  if (req.headers['authorization']) return next();

  const authCookie = getCookieValue(req, AUTH_COOKIE_NAME);
  if (!authCookie) return next();

  const headerToken = String(req.headers['x-csrf-token'] || '').trim();
  const cookieToken = String(getCookieValue(req, CSRF_COOKIE_NAME) || '').trim();
  if (headerToken && cookieToken && headerToken === cookieToken) {
    return next();
  }

  const origin = req.get('origin');
  if (origin && isAllowedOrigin(origin, req)) return next();

  const referer = req.get('referer');
  if (referer) {
    try {
      const refererOrigin = new URL(referer).origin;
      if (isAllowedOrigin(refererOrigin, req)) return next();
    } catch {
      // fall through
    }
  }

  return res.status(403).json({ error: 'CSRF validation failed', code: 'CSRF_BLOCKED' });
});

function getAuthCookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'strict',
    secure: String(process.env.TAILSHELL_COOKIE_SECURE || '').toLowerCase() === 'true',
    path: '/'
  };
}

function getCsrfCookieOptions() {
  return {
    httpOnly: false,
    sameSite: 'strict',
    secure: String(process.env.TAILSHELL_COOKIE_SECURE || '').toLowerCase() === 'true',
    path: '/'
  };
}

function hashTokenValue(token) {
  return crypto
    .createHash('sha256')
    .update(String(token || ''))
    .digest('hex');
}

function signAccessToken({ sessionId, userId, username, role }) {
  return jwt.sign({ sessionId, userId, username, role }, JWT_SECRET, {
    expiresIn: `${ACCESS_TOKEN_TTL_MINUTES}m`
  });
}

function generateRefreshToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCsrfToken() {
  return crypto.randomBytes(24).toString('base64url');
}

function setAuthCookies(res, { accessToken, refreshToken, sessionId, terminalToken, csrfToken }) {
  if (accessToken) {
    res.cookie(AUTH_COOKIE_NAME, accessToken, {
      ...getAuthCookieOptions(),
      maxAge: ACCESS_TOKEN_TTL_MS
    });
  }
  if (refreshToken) {
    res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
      ...getAuthCookieOptions(),
      maxAge: REFRESH_TOKEN_TTL_MS
    });
  }
  if (sessionId) {
    res.cookie(REFRESH_SESSION_COOKIE_NAME, sessionId, {
      ...getAuthCookieOptions(),
      maxAge: REFRESH_TOKEN_TTL_MS
    });
  }
  if (terminalToken) {
    res.cookie(TERMINAL_COOKIE_NAME, terminalToken, {
      ...getAuthCookieOptions(),
      maxAge: REFRESH_TOKEN_TTL_MS
    });
  }
  if (csrfToken) {
    res.cookie(CSRF_COOKIE_NAME, csrfToken, {
      ...getCsrfCookieOptions(),
      maxAge: REFRESH_TOKEN_TTL_MS
    });
  }
}

function clearAuthCookies(res) {
  res.clearCookie(AUTH_COOKIE_NAME, getAuthCookieOptions());
  res.clearCookie(TERMINAL_COOKIE_NAME, getAuthCookieOptions());
  res.clearCookie(REFRESH_COOKIE_NAME, getAuthCookieOptions());
  res.clearCookie(REFRESH_SESSION_COOKIE_NAME, getAuthCookieOptions());
  res.clearCookie(CSRF_COOKIE_NAME, getCsrfCookieOptions());
}

function getCookieValue(req, name) {
  const cookieHeader = String(req.headers['cookie'] || '');
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(';');
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;
    const key = trimmed.slice(0, eqIndex).trim();
    if (key !== name) continue;
    const value = trimmed.slice(eqIndex + 1).trim();
    if (!value) return null;
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }
  return null;
}

function normalizeTerminalArg(userId, sessionId) {
  const safeUser = String(userId || '').replace(/[^a-zA-Z0-9_-]/g, '');
  const safeSession = String(sessionId || '').replace(/[^a-zA-Z0-9_-]/g, '');
  if (!safeUser && !safeSession) return '';
  if (!safeSession) return safeUser;
  return `${safeUser}:${safeSession}`;
}

function isTerminalRoleAllowed(role) {
  return TERMINAL_ALLOWED_ROLES.has(String(role || '').toLowerCase());
}

function isValidTotpToken(token, secret) {
  if (!token || !secret) return false;
  const result = verifySync({ token, secret, epochTolerance: MFA_EPOCH_TOLERANCE });
  return Boolean(result?.valid);
}

async function createSessionRecord(conn, { userId, ip, userAgent }) {
  const sessionId = crypto.randomUUID();
  const terminalToken = crypto.randomBytes(32).toString('base64url');
  const refreshToken = generateRefreshToken();
  const csrfToken = generateCsrfToken();
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);

  await conn.execute(
    `INSERT INTO sessions
      (id, user_id, expires_at, terminal_token, refresh_token_hash, refresh_expires_at, csrf_token, last_seen_at, ip_address, user_agent)
     VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?)`,
    [
      sessionId,
      userId,
      expiresAt,
      terminalToken,
      hashTokenValue(refreshToken),
      expiresAt,
      csrfToken,
      ip,
      String(userAgent || '').slice(0, 255)
    ]
  );

  return { sessionId, terminalToken, refreshToken, csrfToken, expiresAt };
}

function parseIfNoneMatch(headerValue) {
  return String(headerValue || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}

function sendJsonWithEtag(req, res, value) {
  const body = JSON.stringify(value);
  const etag = `"${crypto.createHash('sha256').update(body).digest('base64')}"`;
  res.setHeader('ETag', etag);

  const ifNoneMatch = parseIfNoneMatch(req.headers['if-none-match']);
  if (ifNoneMatch.includes(etag) || ifNoneMatch.includes(`W/${etag}`)) {
    return res.status(304).end();
  }

  return res.type('json').send(body);
}

const AUTH_CACHE_TTL_MS = Math.max(0, parseInt(process.env.TAILSHELL_AUTH_CACHE_TTL_MS || '30000', 10) || 0);
const AUTH_CACHE_MAX_ENTRIES = Math.max(0, parseInt(process.env.TAILSHELL_AUTH_CACHE_MAX_ENTRIES || '5000', 10) || 0);
const authCache = new Map();

const METADATA_CACHE_TTL_MS = Math.max(0, parseInt(process.env.TAILSHELL_METADATA_CACHE_TTL_MS || '5000', 10) || 0);
const METADATA_CACHE_MAX_ENTRIES = Math.max(
  0,
  parseInt(process.env.TAILSHELL_METADATA_CACHE_MAX_ENTRIES || '5000', 10) || 0
);
const metadataCache = new Map();

function getCachedAuth(sessionId) {
  if (!AUTH_CACHE_TTL_MS || !AUTH_CACHE_MAX_ENTRIES) return null;
  const entry = authCache.get(sessionId);
  if (!entry) return null;
  if (entry.expiresAtMs <= Date.now()) {
    authCache.delete(sessionId);
    return null;
  }
  return entry.user;
}

function setCachedAuth(sessionId, user) {
  if (!AUTH_CACHE_TTL_MS || !AUTH_CACHE_MAX_ENTRIES) return;
  while (authCache.size >= AUTH_CACHE_MAX_ENTRIES) {
    const oldestKey = authCache.keys().next().value;
    if (!oldestKey) break;
    authCache.delete(oldestKey);
  }
  authCache.set(sessionId, { user, expiresAtMs: Date.now() + AUTH_CACHE_TTL_MS });
}

function invalidateAuthCacheSession(sessionId) {
  authCache.delete(sessionId);
}

function invalidateAuthCacheUser(userId) {
  for (const [sessionId, entry] of authCache.entries()) {
    if (entry?.user?.userId === userId) authCache.delete(sessionId);
  }
}

function getCachedMetadata(key) {
  if (!METADATA_CACHE_TTL_MS || !METADATA_CACHE_MAX_ENTRIES) return null;
  const entry = metadataCache.get(key);
  if (!entry) return null;
  if (entry.expiresAtMs <= Date.now()) {
    metadataCache.delete(key);
    return null;
  }
  return entry;
}

function setCachedMetadata(key, value) {
  if (!METADATA_CACHE_TTL_MS || !METADATA_CACHE_MAX_ENTRIES) return;
  while (metadataCache.size >= METADATA_CACHE_MAX_ENTRIES) {
    const oldestKey = metadataCache.keys().next().value;
    if (!oldestKey) break;
    metadataCache.delete(oldestKey);
  }
  metadataCache.set(key, value);
}

function invalidateMetadataCacheUser(userId) {
  const prefix = `${userId}:`;
  for (const key of metadataCache.keys()) {
    if (key.startsWith(prefix)) metadataCache.delete(key);
  }
}

const IDEMPOTENCY_TTL_MS = Math.max(
  0,
  parseInt(process.env.TAILSHELL_IDEMPOTENCY_TTL_MS || String(24 * 60 * 60 * 1000), 10) || 0
);
const IDEMPOTENCY_MAX_KEY_LENGTH = Math.max(
  16,
  parseInt(process.env.TAILSHELL_IDEMPOTENCY_KEY_MAX_LENGTH || '128', 10) || 128
);
const IDEMPOTENCY_HEADER = 'idempotency-key';

function stableStringify(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  const keys = Object.keys(value).sort();
  const entries = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`);
  return `{${entries.join(',')}}`;
}

function parseIdempotencyKey(req) {
  const raw = req.get(IDEMPOTENCY_HEADER) || req.get(`x-${IDEMPOTENCY_HEADER}`);
  if (!raw) return { key: null, error: null };
  const key = String(raw).trim();
  if (!key) return { key: null, error: null };
  if (key.length > IDEMPOTENCY_MAX_KEY_LENGTH) {
    return { key: null, error: `Idempotency-Key exceeds ${IDEMPOTENCY_MAX_KEY_LENGTH} characters` };
  }
  return { key, error: null };
}

function hashIdempotencyRequest(req) {
  const body = stableStringify(req.body ?? {});
  const base = {
    method: req.method,
    path: req.originalUrl,
    body
  };
  return crypto.createHash('sha256').update(stableStringify(base)).digest('hex');
}

function parseStoredResponseBody(value) {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

async function fetchIdempotencyRecord(userId, endpoint, key) {
  if (!IDEMPOTENCY_TTL_MS) return null;
  const cutoff = new Date(Date.now() - IDEMPOTENCY_TTL_MS);
  const [rows] = await pool.execute(
    `SELECT request_hash, status_code, response_body
     FROM idempotency_keys
     WHERE user_id = ? AND endpoint = ? AND idempotency_key = ? AND created_at >= ?
     ORDER BY created_at DESC
     LIMIT 1`,
    [userId, endpoint, key, cutoff]
  );
  return rows[0] ?? null;
}

async function storeIdempotencyRecord(userId, endpoint, key, requestHash, statusCode, responseBody) {
  if (!IDEMPOTENCY_TTL_MS) return;
  await pool.execute(
    `INSERT INTO idempotency_keys (user_id, endpoint, idempotency_key, request_hash, status_code, response_body)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [userId, endpoint, key, requestHash, statusCode, JSON.stringify(responseBody ?? null)]
  );
}

async function runIdempotentCreate(req, res, endpoint, execute) {
  const { key, error } = parseIdempotencyKey(req);
  if (error) {
    return res.status(400).json({ error, code: 'IDEMPOTENCY_KEY_INVALID' });
  }
  if (!key) {
    const result = await execute();
    return res.status(result.status).json(result.body);
  }
  if (!req.user?.userId) {
    const result = await execute();
    return res.status(result.status).json(result.body);
  }

  const userId = req.user.userId;
  const requestHash = hashIdempotencyRequest(req);

  const existing = await fetchIdempotencyRecord(userId, endpoint, key);
  if (existing) {
    if (existing.request_hash !== requestHash) {
      return res.status(409).json({
        error: 'Idempotency key reuse with different payload',
        code: 'IDEMPOTENCY_CONFLICT'
      });
    }
    const responseBody = parseStoredResponseBody(existing.response_body);
    return res.status(Number(existing.status_code) || 200).json(responseBody ?? {});
  }

  const result = await execute();
  try {
    await storeIdempotencyRecord(userId, endpoint, key, requestHash, result.status, result.body);
  } catch (storeError) {
    if (storeError?.code === 'ER_DUP_ENTRY') {
      const replay = await fetchIdempotencyRecord(userId, endpoint, key);
      if (replay && replay.request_hash === requestHash) {
        const responseBody = parseStoredResponseBody(replay.response_body);
        return res.status(Number(replay.status_code) || 200).json(responseBody ?? {});
      }
    }
    console.warn('Idempotency record store warning:', storeError?.message ?? storeError);
  }
  return res.status(result.status).json(result.body);
}

async function refreshSessionFromCookies(req, res, { rotate = true } = {}) {
  const sessionId = getCookieValue(req, REFRESH_SESSION_COOKIE_NAME);
  const refreshToken = getCookieValue(req, REFRESH_COOKIE_NAME);
  if (!sessionId || !refreshToken) return null;

  const refreshHash = hashTokenValue(refreshToken);
  const [rows] = await pool.execute(
    `SELECT s.id AS session_id,
            s.user_id,
            s.refresh_token_hash,
            s.refresh_expires_at,
            s.revoked,
            s.terminal_token,
            s.csrf_token,
            u.username,
            u.role,
            u.must_change_password,
            u.active
     FROM sessions s
     INNER JOIN users u ON u.id = s.user_id
     WHERE s.id = ?
     LIMIT 1`,
    [sessionId]
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  if (row.revoked) return null;
  if (row.active === 0 || row.active === false) return null;
  if (!row.refresh_expires_at || new Date(row.refresh_expires_at).getTime() < Date.now()) return null;

  if (!row.refresh_token_hash || String(row.refresh_token_hash) !== refreshHash) {
    await pool.execute('UPDATE sessions SET revoked = TRUE WHERE id = ?', [sessionId]);
    invalidateAuthCacheSession(sessionId);
    invalidateTerminalSession(sessionId);
    clearAuthCookies(res);
    return null;
  }

  let newRefreshToken = refreshToken;
  const csrfToken = row.csrf_token ? String(row.csrf_token) : generateCsrfToken();
  const refreshExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);

  if (rotate) {
    newRefreshToken = generateRefreshToken();
    await pool.execute(
      'UPDATE sessions SET refresh_token_hash = ?, refresh_expires_at = ?, refresh_last_used_at = NOW(), csrf_token = ?, expires_at = ? WHERE id = ?',
      [hashTokenValue(newRefreshToken), refreshExpiresAt, csrfToken, refreshExpiresAt, sessionId]
    );
  } else {
    await pool.execute('UPDATE sessions SET refresh_last_used_at = NOW() WHERE id = ?', [sessionId]);
  }

  const terminalToken = row.terminal_token ? String(row.terminal_token) : '';
  const accessToken = signAccessToken({
    sessionId,
    userId: Number(row.user_id),
    username: row.username,
    role: row.role
  });

  setAuthCookies(res, {
    accessToken,
    refreshToken: newRefreshToken,
    sessionId,
    terminalToken,
    csrfToken
  });

  const user = {
    sessionId,
    userId: Number(row.user_id),
    username: row.username,
    role: row.role,
    mustChangePassword: Boolean(row.must_change_password),
    terminalToken
  };
  setCachedAuth(sessionId, user);
  return { user, accessToken, csrfToken };
}

function metadataKey(userId, name) {
  return `${userId}:${name}`;
}

async function sendJsonWithEtagCached(req, res, cacheKey, computeValue) {
  res.setHeader('Cache-Control', `private, max-age=${Math.max(0, Math.ceil(METADATA_CACHE_TTL_MS / 1000))}`);
  res.setHeader('Vary', 'Authorization');

  const cached = getCachedMetadata(cacheKey);
  if (cached) {
    res.setHeader('ETag', cached.etag);
    const ifNoneMatch = parseIfNoneMatch(req.headers['if-none-match']);
    if (ifNoneMatch.includes(cached.etag) || ifNoneMatch.includes(`W/${cached.etag}`)) {
      return res.status(304).end();
    }
    return res.type('json').send(cached.body);
  }

  const value = await computeValue();
  const body = JSON.stringify(value);
  const etag = `"${crypto.createHash('sha256').update(body).digest('base64')}"`;
  const entry = { body, etag, expiresAtMs: Date.now() + METADATA_CACHE_TTL_MS };
  setCachedMetadata(cacheKey, entry);

  res.setHeader('ETag', etag);
  const ifNoneMatch = parseIfNoneMatch(req.headers['if-none-match']);
  if (ifNoneMatch.includes(etag) || ifNoneMatch.includes(`W/${etag}`)) {
    return res.status(304).end();
  }
  return res.type('json').send(body);
}

function isTruthyEnv(value) {
  return ['1', 'true', 'yes', 'on'].includes(
    String(value || '')
      .trim()
      .toLowerCase()
  );
}

app.use((req, res, next) => {
  if (!isTruthyEnv(process.env.TAILSHELL_MAINTENANCE_MODE)) return next();

  const allow = new Set(['/api/health', '/api/ready', '/api/auth/validate']);
  if (allow.has(req.path)) return next();

  res.setHeader('Retry-After', '60');
  return res.status(503).json({ error: 'Service temporarily in maintenance mode', code: 'MAINTENANCE_MODE' });
});

function isWeakSecret(value, { allowEmpty = false } = {}) {
  const trimmed = String(value || '').trim();
  if (trimmed.length === 0) return !allowEmpty;
  if (trimmed.startsWith('generate_')) return true;
  if (['changeme', 'admin', 'password', 'secret'].includes(trimmed.toLowerCase())) return true;
  return false;
}

const PASSWORD_MIN_LENGTH = Math.max(10, parseInt(process.env.TAILSHELL_PASSWORD_MIN_LENGTH || '12', 10) || 12);
const PASSWORD_REQUIRE_UPPER = String(process.env.TAILSHELL_PASSWORD_REQUIRE_UPPER || 'true').toLowerCase() !== 'false';
const PASSWORD_REQUIRE_LOWER = String(process.env.TAILSHELL_PASSWORD_REQUIRE_LOWER || 'true').toLowerCase() !== 'false';
const PASSWORD_REQUIRE_NUMBER =
  String(process.env.TAILSHELL_PASSWORD_REQUIRE_NUMBER || 'true').toLowerCase() !== 'false';
const PASSWORD_REQUIRE_SYMBOL =
  String(process.env.TAILSHELL_PASSWORD_REQUIRE_SYMBOL || 'true').toLowerCase() !== 'false';
const PASSWORD_HASH_ROUNDS = Math.max(10, parseInt(process.env.TAILSHELL_PASSWORD_HASH_ROUNDS || '12', 10) || 12);
const ROLE_VALUES = ['admin', 'user', 'editor', 'readonly', 'auditor'];
const WRITE_ROLES = new Set(['admin', 'user', 'editor']);
const MFA_ENFORCED_ROLES = new Set(['admin']);
const MFA_EPOCH_TOLERANCE = Math.max(0, parseInt(process.env.TAILSHELL_MFA_EPOCH_TOLERANCE || '30', 10) || 30);

function parseRoleList(value, fallback) {
  const raw = String(value || '').trim();
  const list = raw.length > 0 ? raw.split(',') : fallback;
  return list
    .map((role) =>
      String(role || '')
        .trim()
        .toLowerCase()
    )
    .filter((role) => ROLE_VALUES.includes(role));
}

const TERMINAL_ALLOWED_ROLES = new Set(parseRoleList(process.env.TAILSHELL_TERMINAL_ALLOWED_ROLES, ['admin', 'user']));

function validatePasswordPolicy(password) {
  const value = String(password || '');
  if (value.length < PASSWORD_MIN_LENGTH) {
    return `Password must be at least ${PASSWORD_MIN_LENGTH} characters`;
  }
  if (PASSWORD_REQUIRE_UPPER && !/[A-Z]/.test(value)) {
    return 'Password must include an uppercase letter';
  }
  if (PASSWORD_REQUIRE_LOWER && !/[a-z]/.test(value)) {
    return 'Password must include a lowercase letter';
  }
  if (PASSWORD_REQUIRE_NUMBER && !/[0-9]/.test(value)) {
    return 'Password must include a number';
  }
  if (PASSWORD_REQUIRE_SYMBOL && !/[^A-Za-z0-9]/.test(value)) {
    return 'Password must include a symbol';
  }
  return null;
}

function validateRuntimeConfig() {
  const isProduction = String(process.env.NODE_ENV || '').toLowerCase() === 'production';
  const allowWeak = isTruthyEnv(process.env.TAILSHELL_ALLOW_WEAK_SECRETS);

  const required = ['DATABASE_HOST', 'DATABASE_NAME', 'DATABASE_USER'];
  const missing = required.filter((key) => String(process.env[key] || '').trim().length === 0);
  if (!DATABASE_PASSWORD) missing.push('DATABASE_PASSWORD');
  if (!JWT_SECRET) missing.push('JWT_SECRET');

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  const problems = [];

  if (isWeakSecret(DATABASE_PASSWORD)) {
    problems.push('DATABASE_PASSWORD is missing/weak (set a strong value in .env)');
  }

  if (isWeakSecret(JWT_SECRET) || String(JWT_SECRET).trim().length < 32) {
    problems.push('JWT_SECRET is missing/weak (use a strong random secret)');
  }

  const adminPassword = String(ADMIN_BOOTSTRAP_PASSWORD || '').trim();
  if (adminPassword.length > 0 && isWeakSecret(adminPassword)) {
    problems.push('TAILSHELL_ADMIN_PASSWORD is weak (set a strong bootstrap password or leave empty to auto-generate)');
  }

  if (problems.length === 0) return;

  const message =
    'Weak secrets detected:\n' +
    problems.map((p) => `- ${p}`).join('\n') +
    '\n\nFix: run ./scripts/generate-env (recommended)\n' +
    (allowWeak ? '' : 'Override: set TAILSHELL_ALLOW_WEAK_SECRETS=true');

  if (isProduction && !allowWeak) {
    throw new Error(message);
  }

  console.warn(message);
}

// Rate limiting
const rateLimitStats = {
  auth: {
    blocked: 0,
    lastBlockedAt: null,
    lastBlockedIp: null,
    lastBlockedUserAgent: null
  }
};

const LOGIN_LOCK_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_LOCK_MAX_ATTEMPTS = 10;
const LOGIN_LOCK_DURATION_MS = 15 * 60 * 1000;
const LOGIN_IP_WINDOW_MS = Math.max(60 * 1000, parseInt(process.env.TAILSHELL_LOGIN_IP_WINDOW_MS || '900000', 10) || 0);
const LOGIN_IP_MAX_ATTEMPTS = Math.max(5, parseInt(process.env.TAILSHELL_LOGIN_IP_MAX_ATTEMPTS || '20', 10) || 20);
const LOGIN_USERNAME_WINDOW_MS = Math.max(
  60 * 1000,
  parseInt(process.env.TAILSHELL_LOGIN_USERNAME_WINDOW_MS || '900000', 10) || 0
);
const LOGIN_USERNAME_MAX_ATTEMPTS = Math.max(
  5,
  parseInt(process.env.TAILSHELL_LOGIN_USERNAME_MAX_ATTEMPTS || '10', 10) || 10
);
const LOGIN_CAPTCHA_THRESHOLD = Math.max(3, parseInt(process.env.TAILSHELL_LOGIN_CAPTCHA_THRESHOLD || '5', 10) || 5);
const TURNSTILE_SITE_KEY = String(process.env.TAILSHELL_TURNSTILE_SITE_KEY || '').trim();
const TURNSTILE_SECRET_KEY = getEnvValue('TAILSHELL_TURNSTILE_SECRET_KEY');

const loginIpStats = new Map();
const loginUserStats = new Map();

function recordLoginAttempt(map, key, now, windowMs) {
  if (!key) return { count: 0, last: 0, windowStart: now };
  const entry = map.get(key) || { count: 0, last: 0, windowStart: now };
  if (now - entry.last > windowMs) {
    entry.count = 0;
    entry.windowStart = now;
  }
  entry.count += 1;
  entry.last = now;
  map.set(key, entry);
  return entry;
}

function getLoginRetryAfterSeconds(entry, windowMs, now) {
  if (!entry) return 0;
  const windowStart = Number(entry.windowStart) || now;
  const remainingMs = Math.max(0, windowMs - (now - windowStart));
  return Math.max(1, Math.ceil(remainingMs / 1000));
}

function resetLoginAttempt(map, key) {
  if (!key) return;
  map.delete(key);
}

function shouldRequireCaptcha(ipEntry, userEntry) {
  if (!TURNSTILE_SITE_KEY || !TURNSTILE_SECRET_KEY) return false;
  const maxCount = Math.max(ipEntry?.count ?? 0, userEntry?.count ?? 0);
  return maxCount >= LOGIN_CAPTCHA_THRESHOLD;
}

async function validateTurnstileToken(token, ip) {
  if (!TURNSTILE_SECRET_KEY) return false;
  if (!token) return false;
  const body = new URLSearchParams();
  body.set('secret', TURNSTILE_SECRET_KEY);
  body.set('response', token);
  if (ip) body.set('remoteip', ip);

  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body
    });
    const data = await resp.json();
    return Boolean(data?.success);
  } catch (error) {
    console.warn('Turnstile validation warning:', error?.message ?? error);
    return false;
  }
}

const TERMINAL_SESSION_TTL_MS = Math.max(
  30000,
  parseInt(process.env.TAILSHELL_TERMINAL_SESSION_TTL_MS || '120000', 10) || 120000
);
const TERMINAL_MAX_SESSIONS_PER_USER = Math.max(
  1,
  parseInt(process.env.TAILSHELL_TERMINAL_MAX_SESSIONS_PER_USER || '2', 10) || 2
);
const terminalSessionCache = new Map();

function pruneTerminalSessions(now = Date.now()) {
  for (const [sessionId, entry] of terminalSessionCache.entries()) {
    if (!entry) {
      terminalSessionCache.delete(sessionId);
      continue;
    }
    if (now - entry.lastSeenAt > TERMINAL_SESSION_TTL_MS) {
      terminalSessionCache.delete(sessionId);
    }
  }
}

function countTerminalSessionsForUser(userId) {
  let count = 0;
  for (const entry of terminalSessionCache.values()) {
    if (entry?.userId === userId) count += 1;
  }
  return count;
}

function registerTerminalSession(sessionId, userId) {
  const now = Date.now();
  pruneTerminalSessions(now);
  const existing = terminalSessionCache.get(sessionId);
  if (existing) {
    existing.lastSeenAt = now;
    terminalSessionCache.set(sessionId, existing);
    return { allowed: true, existing: true, count: countTerminalSessionsForUser(userId) };
  }

  const activeCount = countTerminalSessionsForUser(userId);
  if (activeCount >= TERMINAL_MAX_SESSIONS_PER_USER) {
    return { allowed: false, existing: false, count: activeCount };
  }

  terminalSessionCache.set(sessionId, { userId, lastSeenAt: now });
  return { allowed: true, existing: false, count: activeCount + 1 };
}

function invalidateTerminalSession(sessionId) {
  terminalSessionCache.delete(sessionId);
}

function invalidateTerminalSessionsForUser(userId) {
  for (const [sessionId, entry] of terminalSessionCache.entries()) {
    if (entry?.userId === userId) terminalSessionCache.delete(sessionId);
  }
}

function invalidateTerminalSessionsForUserExcept(userId, keepSessionId) {
  for (const [sessionId, entry] of terminalSessionCache.entries()) {
    if (entry?.userId === userId && sessionId !== keepSessionId) {
      terminalSessionCache.delete(sessionId);
    }
  }
}

const sessionLastSeenCache = new Map();
const SESSION_LAST_SEEN_MIN_INTERVAL_MS = 60 * 1000;

async function touchSessionLastSeen(sessionId) {
  const now = Date.now();
  const last = sessionLastSeenCache.get(sessionId) ?? 0;
  if (now - last < SESSION_LAST_SEEN_MIN_INTERVAL_MS) return;
  sessionLastSeenCache.set(sessionId, now);
  try {
    await pool.execute('UPDATE sessions SET last_seen_at = NOW() WHERE id = ?', [sessionId]);
  } catch (error) {
    console.warn('Session last_seen_at update warning:', error?.message ?? error);
  }
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts, try again later' },
  handler: (req, res, _next, options) => {
    rateLimitStats.auth.blocked += 1;
    rateLimitStats.auth.lastBlockedAt = new Date().toISOString();
    rateLimitStats.auth.lastBlockedIp = req.ip;
    rateLimitStats.auth.lastBlockedUserAgent = String(req.headers['user-agent'] || '');
    res.status(options.statusCode).json(options.message);
  }
});

// Database connection pool with timeouts
const DATABASE_POOL_SIZE = (() => {
  const parsed = parseInt(process.env.DATABASE_POOL_SIZE || '10', 10);
  if (!Number.isFinite(parsed) || parsed < 1) return 10;
  return Math.min(50, parsed);
})();

const DATABASE_POOL_QUEUE_LIMIT = (() => {
  const parsed = parseInt(process.env.DATABASE_POOL_QUEUE_LIMIT || '50', 10);
  if (!Number.isFinite(parsed) || parsed < 0) return 50;
  return Math.min(1000, parsed);
})();

const pool = mysql.createPool({
  host: process.env.DATABASE_HOST,
  port: parseInt(process.env.DATABASE_PORT || '3306', 10),
  database: process.env.DATABASE_NAME,
  user: process.env.DATABASE_USER,
  password: DATABASE_PASSWORD,
  waitForConnections: true,
  connectionLimit: DATABASE_POOL_SIZE,
  queueLimit: DATABASE_POOL_QUEUE_LIMIT, // Max queued connection requests
  connectTimeout: 10000, // 10s connection timeout
  enableKeepAlive: true,
  keepAliveInitialDelay: 30000 // 30s keepalive
});

// Transient error codes that may be retried
const TRANSIENT_DB_ERRORS = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'PROTOCOL_CONNECTION_LOST',
  'ER_LOCK_DEADLOCK',
  'ER_LOCK_WAIT_TIMEOUT'
]);

const DB_OUTAGE_ERRORS = new Set([
  ...TRANSIENT_DB_ERRORS,
  'ENOTFOUND',
  'EPIPE',
  'PROTOCOL_ENQUEUE_AFTER_FATAL_ERROR',
  'PROTOCOL_ENQUEUE_AFTER_QUIT',
  'ER_ACCESS_DENIED_ERROR',
  'ER_CON_COUNT_ERROR',
  'ER_HOST_IS_BLOCKED'
]);

const DB_CIRCUIT_FAILURE_THRESHOLD = Math.max(
  1,
  parseInt(process.env.DATABASE_CIRCUIT_FAILURE_THRESHOLD || '5', 10) || 5
);
const DB_CIRCUIT_RESET_MS = Math.max(1000, parseInt(process.env.DATABASE_CIRCUIT_RESET_MS || '30000', 10) || 30000);
const DB_CIRCUIT_FAILURE_WINDOW_MS = Math.max(
  1000,
  parseInt(process.env.DATABASE_CIRCUIT_FAILURE_WINDOW_MS || '60000', 10) || 60000
);

const dbCircuit = {
  state: 'closed',
  failureCount: 0,
  openedAt: 0,
  lastFailureAt: 0,
  lastErrorCode: null,
  halfOpenInFlight: false
};

function formatCircuitTimestamp(ts) {
  if (!ts) return null;
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function getDbCircuitSnapshot() {
  return {
    state: dbCircuit.state,
    failureCount: dbCircuit.failureCount,
    openedAt: formatCircuitTimestamp(dbCircuit.openedAt),
    lastFailureAt: formatCircuitTimestamp(dbCircuit.lastFailureAt),
    lastErrorCode: dbCircuit.lastErrorCode,
    threshold: DB_CIRCUIT_FAILURE_THRESHOLD,
    resetMs: DB_CIRCUIT_RESET_MS,
    failureWindowMs: DB_CIRCUIT_FAILURE_WINDOW_MS,
    halfOpenInFlight: dbCircuit.halfOpenInFlight
  };
}

function isDbOutageError(error) {
  const code = String(error?.code || error?.errno || '').trim();
  return DB_OUTAGE_ERRORS.has(code);
}

function createDbCircuitError() {
  const error = new Error('Database unavailable');
  error.code = 'DB_CIRCUIT_OPEN';
  error.statusCode = 503;
  return error;
}

function allowDbRequest() {
  if (dbCircuit.state === 'open') {
    const now = Date.now();
    if (now - dbCircuit.openedAt >= DB_CIRCUIT_RESET_MS) {
      dbCircuit.state = 'half_open';
      dbCircuit.halfOpenInFlight = false;
    } else {
      return false;
    }
  }
  if (dbCircuit.state === 'half_open') {
    if (dbCircuit.halfOpenInFlight) return false;
    dbCircuit.halfOpenInFlight = true;
    return true;
  }
  return true;
}

function recordDbSuccess() {
  if (dbCircuit.state !== 'closed') {
    dbCircuit.state = 'closed';
    dbCircuit.failureCount = 0;
    dbCircuit.openedAt = 0;
    dbCircuit.lastFailureAt = 0;
    dbCircuit.lastErrorCode = null;
    dbCircuit.halfOpenInFlight = false;
  }
}

function recordDbFailure(error) {
  const now = Date.now();
  if (now - dbCircuit.lastFailureAt > DB_CIRCUIT_FAILURE_WINDOW_MS) {
    dbCircuit.failureCount = 0;
  }
  dbCircuit.failureCount += 1;
  dbCircuit.lastFailureAt = now;
  dbCircuit.lastErrorCode = String(error?.code || error?.errno || '') || null;

  if (dbCircuit.failureCount >= DB_CIRCUIT_FAILURE_THRESHOLD) {
    dbCircuit.state = 'open';
    dbCircuit.openedAt = now;
    dbCircuit.halfOpenInFlight = false;
  }
}

app.use((req, res, next) => {
  if (dbCircuit.state === 'open' && req.path !== '/api/health') {
    return res.status(503).json({ error: 'Database unavailable', code: 'DB_UNAVAILABLE' });
  }
  return next();
});

// Retry wrapper for transient DB errors with exponential backoff
async function withRetry(fn, { maxRetries = 3, baseDelayMs = 100, maxDelayMs = 2000, onRetry } = {}) {
  let lastError;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      const code = error?.code || error?.errno;
      const isTransient = TRANSIENT_DB_ERRORS.has(code);
      if (!isTransient || attempt === maxRetries) {
        throw error;
      }
      const delay = Math.min(baseDelayMs * Math.pow(2, attempt), maxDelayMs);
      const jitter = Math.random() * delay * 0.2;
      await new Promise((resolve) => setTimeout(resolve, delay + jitter));
      try {
        onRetry?.({ attempt: attempt + 1, maxRetries, code, error });
      } catch (hookError) {
        console.warn('DB onRetry hook warning:', hookError?.message ?? hookError);
      }
      console.warn(`DB retry ${attempt + 1}/${maxRetries} after ${code}: ${error?.message ?? error}`);
    }
  }
  throw lastError;
}

const DB_QUERY_TIMEOUT_MS = Math.max(1000, parseInt(process.env.DATABASE_QUERY_TIMEOUT_MS || '30000', 10) || 30000);
const DB_READ_QUERY_RETRIES = Math.max(0, parseInt(process.env.DATABASE_READ_QUERY_RETRIES || '2', 10) || 0);
const DB_SLOW_QUERY_MS = Math.max(0, parseInt(process.env.TAILSHELL_SLOW_QUERY_MS || '250', 10) || 0);
const DB_SLOW_QUERY_MAX_ENTRIES = Math.max(0, parseInt(process.env.TAILSHELL_SLOW_QUERY_MAX_ENTRIES || '50', 10) || 0);

const dbQueryStats = {
  startedAt: new Date().toISOString(),
  total: 0,
  inFlight: 0,
  retries: 0,
  errors: 0,
  timeouts: 0,
  slow: 0,
  totalMs: 0,
  maxMs: 0,
  byKind: {
    read: { count: 0, totalMs: 0, maxMs: 0, slow: 0 },
    write: { count: 0, totalMs: 0, maxMs: 0, slow: 0 }
  },
  slowQueries: [],
  lastSlow: null,
  lastError: null
};

function normalizeSqlForLog(sql) {
  const normalized = String(sql || '')
    .replace(/\s+/g, ' ')
    .trim();
  if (normalized.length <= 500) return normalized;
  return `${normalized.slice(0, 500)}…`;
}

function isAbortError(error) {
  const name = String(error?.name || '');
  const code = String(error?.code || '');
  return name === 'AbortError' || code === 'ABORT_ERR';
}

function recordDbQuery({ kind, durationMs, sql, retries, error }) {
  const safeDuration = Number.isFinite(durationMs) ? durationMs : 0;
  const safeRetries = Number.isFinite(retries) ? retries : 0;
  const queryKind = kind === 'read' || kind === 'write' ? kind : 'write';

  dbQueryStats.total += 1;
  dbQueryStats.totalMs += safeDuration;
  dbQueryStats.maxMs = Math.max(dbQueryStats.maxMs, safeDuration);

  const bucket = dbQueryStats.byKind[queryKind] ?? dbQueryStats.byKind.write;
  bucket.count += 1;
  bucket.totalMs += safeDuration;
  bucket.maxMs = Math.max(bucket.maxMs, safeDuration);

  if (error) {
    dbQueryStats.errors += 1;
    if (isAbortError(error)) dbQueryStats.timeouts += 1;
    dbQueryStats.lastError = {
      ts: new Date().toISOString(),
      durationMs: Math.round(safeDuration * 100) / 100,
      kind: queryKind,
      retries: safeRetries,
      code: error?.code ?? null,
      message: String(error?.message ?? error),
      sql: normalizeSqlForLog(sql)
    };
  }

  if (DB_SLOW_QUERY_MS > 0 && safeDuration >= DB_SLOW_QUERY_MS) {
    dbQueryStats.slow += 1;
    bucket.slow += 1;

    const entry = {
      ts: new Date().toISOString(),
      durationMs: Math.round(safeDuration * 100) / 100,
      kind: queryKind,
      retries: safeRetries,
      sql: normalizeSqlForLog(sql)
    };

    dbQueryStats.lastSlow = entry;
    if (DB_SLOW_QUERY_MAX_ENTRIES > 0) {
      dbQueryStats.slowQueries.push(entry);
      if (dbQueryStats.slowQueries.length > DB_SLOW_QUERY_MAX_ENTRIES) {
        dbQueryStats.slowQueries.splice(0, dbQueryStats.slowQueries.length - DB_SLOW_QUERY_MAX_ENTRIES);
      }
    }
    console.warn(JSON.stringify({ event: 'db_slow_query', ...entry }));
  }
}

function getDbMetricsSnapshot() {
  const total = dbQueryStats.total;
  const avgMs = total > 0 ? dbQueryStats.totalMs / total : 0;

  const summarizeBucket = (bucket) => {
    const count = bucket.count;
    return {
      count,
      slow: bucket.slow,
      avgMs: count > 0 ? Math.round((bucket.totalMs / count) * 100) / 100 : 0,
      maxMs: Math.round(bucket.maxMs * 100) / 100
    };
  };

  return {
    startedAt: dbQueryStats.startedAt,
    inFlight: dbQueryStats.inFlight,
    total: total,
    retries: dbQueryStats.retries,
    errors: dbQueryStats.errors,
    timeouts: dbQueryStats.timeouts,
    slow: dbQueryStats.slow,
    slowThresholdMs: DB_SLOW_QUERY_MS,
    avgMs: Math.round(avgMs * 100) / 100,
    maxMs: Math.round(dbQueryStats.maxMs * 100) / 100,
    circuit: getDbCircuitSnapshot(),
    byKind: {
      read: summarizeBucket(dbQueryStats.byKind.read),
      write: summarizeBucket(dbQueryStats.byKind.write)
    },
    lastSlow: dbQueryStats.lastSlow,
    lastError: dbQueryStats.lastError,
    recentSlow: DB_SLOW_QUERY_MAX_ENTRIES > 0 ? dbQueryStats.slowQueries : undefined
  };
}

function isReadQuery(sql) {
  const head = String(sql || '')
    .trim()
    .slice(0, 16)
    .toUpperCase();
  return (
    head.startsWith('SELECT') || head.startsWith('SHOW') || head.startsWith('DESCRIBE') || head.startsWith('EXPLAIN')
  );
}

async function executeWithTimeout(rawExecute, sql, values, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await rawExecute({ sql, values, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function wrapExecute(rawExecute, { retryReads = true } = {}) {
  return async (sql, params) => {
    if (!allowDbRequest()) {
      throw createDbCircuitError();
    }
    const statement = typeof sql === 'string' ? sql : sql?.sql;
    const values = Array.isArray(params) ? params : Array.isArray(sql?.values) ? sql.values : [];
    const timeoutMs = Math.max(1000, parseInt(sql?.timeoutMs || DB_QUERY_TIMEOUT_MS, 10) || DB_QUERY_TIMEOUT_MS);

    const kind = isReadQuery(statement) ? 'read' : 'write';
    const start = process.hrtime.bigint();
    dbQueryStats.inFlight += 1;

    let retries = 0;
    const onRetry = () => {
      retries += 1;
      dbQueryStats.retries += 1;
    };

    try {
      const run = () => executeWithTimeout(rawExecute, statement, values, timeoutMs);
      const result =
        retryReads && isReadQuery(statement) && DB_READ_QUERY_RETRIES > 0
          ? await withRetry(run, { maxRetries: DB_READ_QUERY_RETRIES, onRetry })
          : await run();

      const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
      recordDbQuery({ kind, durationMs, sql: statement, retries });
      recordDbSuccess();
      return result;
    } catch (error) {
      const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
      recordDbQuery({ kind, durationMs, sql: statement, retries, error });
      if (isDbOutageError(error)) {
        recordDbFailure(error);
      }
      throw error;
    } finally {
      dbQueryStats.inFlight = Math.max(0, dbQueryStats.inFlight - 1);
      if (dbCircuit.state === 'half_open') {
        dbCircuit.halfOpenInFlight = false;
      }
    }
  };
}

const rawPoolExecute = pool.execute.bind(pool);
pool.execute = wrapExecute(rawPoolExecute);

const rawGetConnection = pool.getConnection.bind(pool);
pool.getConnection = async (...args) => {
  if (!allowDbRequest()) {
    throw createDbCircuitError();
  }
  const conn = await rawGetConnection(...args);
  if (!conn.__Tailshell_wrapped) {
    conn.__Tailshell_wrapped = true;
    const rawConnExecute = conn.execute.bind(conn);
    conn.execute = wrapExecute(rawConnExecute, { retryReads: false });
  }
  return conn;
};

let server = null;
let cleanupInterval = null;
let shuttingDown = false;

async function shutdown(signal, { exitCode = 0 } = {}) {
  if (shuttingDown) return;
  shuttingDown = true;

  console.warn(`Shutdown requested (${signal})`);

  const forceTimer = setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 8000);
  forceTimer.unref();

  try {
    if (cleanupInterval) clearInterval(cleanupInterval);
  } catch (error) {
    console.warn('Cleanup interval stop warning:', error?.message ?? error);
  }

  try {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  } catch (error) {
    console.error('HTTP server shutdown error:', error?.message ?? error);
  }

  try {
    await pool.end();
  } catch (error) {
    console.error('DB pool shutdown error:', error?.message ?? error);
  }

  clearTimeout(forceTimer);
  process.exit(exitCode);
}

// Middleware: Authenticate JWT token
async function authenticateToken(req, res, next) {
  const cookieToken = getCookieValue(req, AUTH_COOKIE_NAME);
  const authHeader = String(req.headers['authorization'] || '').trim();
  const bearerToken = authHeader.toLowerCase().startsWith('bearer ') ? authHeader.slice(7).trim() : null;

  // Prefer HttpOnly cookie auth to avoid surprises from stale browser Basic Auth.
  const token = cookieToken || bearerToken;

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    let decoded = null;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (error) {
      const isExpired = error?.name === 'TokenExpiredError';
      if (isExpired && cookieToken) {
        const refreshed = await refreshSessionFromCookies(req, res, { rotate: true });
        if (!refreshed) return res.status(401).json({ error: 'Session expired or revoked' });
        req.user = refreshed.user;
        return next();
      }
      return res.status(401).json({ error: 'Invalid token' });
    }
    if (!decoded || typeof decoded !== 'object') return res.status(401).json({ error: 'Invalid token' });

    const sessionId = decoded.sessionId;
    const tokenUserId = decoded.userId;
    if (!sessionId || !tokenUserId) return res.status(401).json({ error: 'Invalid token' });

    const cached = getCachedAuth(sessionId);
    if (cached && String(cached.userId) === String(tokenUserId)) {
      req.user = cached;
      return next();
    }

    const [rows] = await pool.execute(
      `SELECT s.id AS session_id, s.user_id, s.terminal_token, s.csrf_token,
              u.username, u.role, u.must_change_password, u.active
       FROM sessions s
       INNER JOIN users u ON u.id = s.user_id
       WHERE s.id = ? AND s.revoked = FALSE AND s.expires_at > NOW()
       LIMIT 1`,
      [sessionId]
    );
    if (rows.length === 0) return res.status(401).json({ error: 'Session expired or revoked' });

    const row = rows[0];
    if (String(row.user_id) !== String(tokenUserId))
      return res.status(401).json({ error: 'Session expired or revoked' });
    if (row.active === 0 || row.active === false) {
      return res.status(401).json({ error: 'Account disabled', code: 'ACCOUNT_DISABLED' });
    }

    let terminalToken = row.terminal_token ? String(row.terminal_token) : '';
    if (!terminalToken) {
      terminalToken = crypto.randomBytes(32).toString('base64url');
      try {
        await pool.execute('UPDATE sessions SET terminal_token = ? WHERE id = ?', [terminalToken, sessionId]);
      } catch (error) {
        console.warn('Terminal token bootstrap warning:', error?.message ?? error);
      }
    }

    const csrfToken = row.csrf_token ? String(row.csrf_token) : generateCsrfToken();
    if (!row.csrf_token) {
      try {
        await pool.execute('UPDATE sessions SET csrf_token = ? WHERE id = ?', [csrfToken, sessionId]);
      } catch (error) {
        console.warn('CSRF token bootstrap warning:', error?.message ?? error);
      }
    }

    const user = {
      sessionId,
      userId: Number(row.user_id),
      username: row.username,
      role: row.role,
      mustChangePassword: Boolean(row.must_change_password),
      terminalToken
    };
    setCachedAuth(sessionId, user);
    req.user = user;

    if (cookieToken) {
      const terminalCookie = getCookieValue(req, TERMINAL_COOKIE_NAME);
      const csrfCookie = getCookieValue(req, CSRF_COOKIE_NAME);
      if ((terminalToken && terminalCookie !== terminalToken) || (csrfToken && csrfCookie !== csrfToken)) {
        setAuthCookies(res, {
          terminalToken,
          csrfToken
        });
      }
    }
    return next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireRole(roles, message) {
  const allow = new Set(roles);
  return (req, res, next) => {
    if (!allow.has(req.user.role)) {
      return res.status(403).json({ error: message || 'Access denied' });
    }
    return next();
  };
}

// Middleware: Require admin role
const requireAdmin = requireRole(['admin'], 'Admin access required');

// Middleware: Require audit role (admin or auditor)
const requireAuditAccess = requireRole(['admin', 'auditor'], 'Audit access required');

function requireWriteAccess(req, res, next) {
  if (!WRITE_ROLES.has(req.user.role)) {
    return res.status(403).json({ error: 'Read-only account', code: 'READONLY' });
  }
  next();
}

// Middleware: Require password rotation to be complete
function requirePasswordChangeCleared(req, res, next) {
  if (req.user.mustChangePassword) {
    return res.status(403).json({
      error: 'Password change required',
      code: 'PASSWORD_CHANGE_REQUIRED'
    });
  }
  next();
}

function normalizeWorkspaceName(value) {
  return String(value || '').trim();
}

function isValidWorkspaceName(value) {
  if (!value) return false;
  if (value.length > 64) return false;
  return true;
}

function generateWorkspaceTmuxSession(userId) {
  const suffix = crypto.randomBytes(8).toString('hex');
  return `ai-${userId}-ws-${suffix}`;
}

async function ensureUserHasWorkspace(userId) {
  const [rows] = await pool.execute(
    'SELECT id, tmux_session, pinned, sort_order, is_default FROM workspaces WHERE user_id = ?',
    [userId]
  );
  if (rows.length > 0) {
    const hasDefault = rows.some((row) => Boolean(row.is_default));
    if (!hasDefault) {
      const sorted = [...rows].sort((a, b) => {
        if (a.pinned !== b.pinned) return b.pinned ? 1 : -1;
        if (Number(a.sort_order) !== Number(b.sort_order)) return Number(a.sort_order) - Number(b.sort_order);
        return Number(a.id) - Number(b.id);
      });
      await pool.execute('UPDATE workspaces SET is_default = TRUE WHERE id = ? AND user_id = ?', [
        sorted[0].id,
        userId
      ]);
    }
    return rows[0];
  }

  // The ttyd entrypoint attaches users to `ai-<userId>` by default; use that as the first workspace.
  const defaultTmuxSession = `ai-${userId}`;
  try {
    await pool.execute(
      `INSERT INTO workspaces (user_id, name, tmux_session, sort_order, pinned, is_default)
       VALUES (?, 'Main', ?, 0, FALSE, TRUE)`,
      [userId, defaultTmuxSession]
    );
  } catch (err) {
    // Handle race condition or stale data - workspace might already exist
    if (err?.code === 'ER_DUP_ENTRY') {
      const [existing] = await pool.execute(
        'SELECT id, tmux_session FROM workspaces WHERE user_id = ? ORDER BY id ASC LIMIT 1',
        [userId]
      );
      if (existing.length > 0) {
        return existing[0];
      }
    }
    throw err;
  }

  const [created] = await pool.execute(
    'SELECT id, tmux_session FROM workspaces WHERE user_id = ? ORDER BY id ASC LIMIT 1',
    [userId]
  );
  return created[0];
}

async function pingDatabase(timeoutMs = 2000) {
  let timer = null;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error('Database ping timeout'));
    }, timeoutMs);
  });
  try {
    await Promise.race([pool.execute('SELECT 1'), timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// Health check
app.get('/api/health', async (_req, res) => {
  try {
    await pingDatabase();
    res.json({ status: 'healthy', database: 'connected', release: TAILSHELL_RELEASE });
  } catch {
    res.status(503).json({ status: 'unhealthy', database: 'disconnected', release: TAILSHELL_RELEASE });
  }
});

// Readiness check (DB reachable)
app.get('/api/ready', async (_req, res) => {
  try {
    await pingDatabase();
    res.json({ ready: true, release: TAILSHELL_RELEASE });
  } catch {
    res.status(503).json({ ready: false, release: TAILSHELL_RELEASE });
  }
});

// Public: invite acceptance (no auth)
app.get('/api/invites/:token', async (req, res) => {
  try {
    const token = String(req.params.token || '').trim();
    if (!token) return res.status(400).json({ valid: false, error: 'Invalid token' });

    const [rows] = await pool.execute(
      'SELECT id, role, expires_at, redeemed_at FROM user_invites WHERE token = ? LIMIT 1',
      [token]
    );
    if (rows.length === 0) return res.status(404).json({ valid: false, error: 'Invite not found' });
    const invite = rows[0];
    if (invite.redeemed_at) return res.status(404).json({ valid: false, error: 'Invite already used' });

    const expiresAt = new Date(invite.expires_at);
    if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() < Date.now()) {
      return res.status(404).json({ valid: false, error: 'Invite expired' });
    }

    res.json({ valid: true, role: invite.role, expiresAt: invite.expires_at });
  } catch (error) {
    console.error('Invite validate error:', error);
    res.status(500).json({ valid: false, error: 'Internal server error' });
  }
});

app.post('/api/invites/:token/accept', async (req, res) => {
  try {
    const token = String(req.params.token || '').trim();
    const username = String(req.body?.username || '')
      .trim()
      .slice(0, 50);
    const password = String(req.body?.password || '');
    if (!token) return res.status(400).json({ error: 'Invalid token' });
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const passwordError = validatePasswordPolicy(password);
    if (passwordError) return res.status(400).json({ error: passwordError });

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [invites] = await conn.execute(
        'SELECT id, role, expires_at, redeemed_at FROM user_invites WHERE token = ? FOR UPDATE',
        [token]
      );
      if (invites.length === 0) {
        await conn.rollback();
        return res.status(404).json({ error: 'Invite not found' });
      }
      const invite = invites[0];
      if (invite.redeemed_at) {
        await conn.rollback();
        return res.status(404).json({ error: 'Invite already used' });
      }
      const expiresAt = new Date(invite.expires_at);
      if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() < Date.now()) {
        await conn.rollback();
        return res.status(404).json({ error: 'Invite expired' });
      }

      const [existingUsers] = await conn.execute('SELECT id FROM users WHERE username = ? LIMIT 1', [username]);
      if (existingUsers.length > 0) {
        await conn.rollback();
        return res.status(409).json({ error: 'Username already exists' });
      }

      const hash = await bcrypt.hash(password, PASSWORD_HASH_ROUNDS);
      const [userInsert] = await conn.execute(
        'INSERT INTO users (username, password_hash, role, active, must_change_password) VALUES (?, ?, ?, TRUE, FALSE)',
        [username, hash, invite.role]
      );
      const userId = userInsert.insertId;

      await conn.execute('UPDATE user_invites SET redeemed_at = NOW(), redeemed_by_user_id = ? WHERE id = ?', [
        userId,
        invite.id
      ]);

      const session = await createSessionRecord(conn, {
        userId,
        ip: req.ip,
        userAgent: req.headers['user-agent']
      });

      const jwtToken = signAccessToken({ sessionId: session.sessionId, userId, username, role: invite.role });

      setAuthCookies(res, {
        accessToken: jwtToken,
        refreshToken: session.refreshToken,
        sessionId: session.sessionId,
        terminalToken: session.terminalToken,
        csrfToken: session.csrfToken
      });

      await audit(conn, { userId, action: 'invite_accept', details: { inviteId: invite.id }, ip: req.ip });
      await conn.commit();

      res.json({
        token: jwtToken,
        user: { id: userId, username, role: invite.role },
        mustChangePassword: false,
        expiresAt: new Date(Date.now() + ACCESS_TOKEN_TTL_MS).toISOString(),
        refreshExpiresAt: session.expiresAt.toISOString()
      });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  } catch (error) {
    console.error('Invite accept error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Public: password reset (no auth)
app.get('/api/password-resets/:token', async (req, res) => {
  try {
    const token = String(req.params.token || '').trim();
    if (!token) return res.status(400).json({ valid: false, error: 'Invalid token' });

    const [rows] = await pool.execute(
      `SELECT prt.id, prt.expires_at, prt.used_at, u.username
       FROM password_reset_tokens prt
       INNER JOIN users u ON u.id = prt.user_id
       WHERE prt.token = ?
       LIMIT 1`,
      [token]
    );
    if (rows.length === 0) return res.status(404).json({ valid: false, error: 'Reset not found' });
    const reset = rows[0];
    if (reset.used_at) return res.status(404).json({ valid: false, error: 'Reset already used' });
    const expiresAt = new Date(reset.expires_at);
    if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() < Date.now()) {
      return res.status(404).json({ valid: false, error: 'Reset expired' });
    }
    res.json({ valid: true, username: reset.username, expiresAt: reset.expires_at });
  } catch (error) {
    console.error('Password reset validate error:', error);
    res.status(500).json({ valid: false, error: 'Internal server error' });
  }
});

app.post('/api/password-resets/:token', async (req, res) => {
  try {
    const token = String(req.params.token || '').trim();
    const newPassword = String(req.body?.newPassword || req.body?.password || '');
    if (!token) return res.status(400).json({ error: 'Invalid token' });
    if (!newPassword) return res.status(400).json({ error: 'New password required' });
    const passwordError = validatePasswordPolicy(newPassword);
    if (passwordError) return res.status(400).json({ error: passwordError });

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [rows] = await conn.execute(
        `SELECT prt.id, prt.user_id, prt.expires_at, prt.used_at, u.username, u.role
         FROM password_reset_tokens prt
         INNER JOIN users u ON u.id = prt.user_id
         WHERE prt.token = ?
         FOR UPDATE`,
        [token]
      );
      if (rows.length === 0) {
        await conn.rollback();
        return res.status(404).json({ error: 'Reset not found' });
      }
      const reset = rows[0];
      if (reset.used_at) {
        await conn.rollback();
        return res.status(404).json({ error: 'Reset already used' });
      }
      const expiresAt = new Date(reset.expires_at);
      if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() < Date.now()) {
        await conn.rollback();
        return res.status(404).json({ error: 'Reset expired' });
      }

      const hash = await bcrypt.hash(newPassword, PASSWORD_HASH_ROUNDS);
      await conn.execute(
        'UPDATE users SET password_hash = ?, must_change_password = FALSE, active = TRUE WHERE id = ?',
        [hash, reset.user_id]
      );
      await conn.execute('UPDATE password_reset_tokens SET used_at = NOW() WHERE id = ?', [reset.id]);

      // Revoke all previous sessions
      await conn.execute('UPDATE sessions SET revoked = TRUE WHERE user_id = ?', [reset.user_id]);
      invalidateAuthCacheUser(Number(reset.user_id));
      invalidateTerminalSessionsForUser(Number(reset.user_id));

      // Create a new session and log the user in immediately.
      const session = await createSessionRecord(conn, {
        userId: reset.user_id,
        ip: req.ip,
        userAgent: req.headers['user-agent']
      });

      const jwtToken = signAccessToken({
        sessionId: session.sessionId,
        userId: reset.user_id,
        username: reset.username,
        role: reset.role
      });

      setAuthCookies(res, {
        accessToken: jwtToken,
        refreshToken: session.refreshToken,
        sessionId: session.sessionId,
        terminalToken: session.terminalToken,
        csrfToken: session.csrfToken
      });

      await audit(conn, {
        userId: reset.user_id,
        action: 'password_reset_accept',
        details: { resetId: reset.id },
        ip: req.ip
      });
      await conn.commit();

      res.json({
        token: jwtToken,
        user: { id: reset.user_id, username: reset.username, role: reset.role },
        mustChangePassword: false,
        expiresAt: new Date(Date.now() + ACCESS_TOKEN_TTL_MS).toISOString(),
        refreshExpiresAt: session.expiresAt.toISOString()
      });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  } catch (error) {
    console.error('Password reset accept error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Workspaces (per-user metadata)
app.get('/api/workspaces', authenticateToken, requirePasswordChangeCleared, async (req, res) => {
  try {
    return sendJsonWithEtagCached(req, res, metadataKey(req.user.userId, 'workspaces'), async () => {
      await ensureUserHasWorkspace(req.user.userId);
      const [rows] = await pool.execute(
        `SELECT w.id, w.name, w.tmux_session, w.sort_order, w.pinned, w.is_default, w.last_used_at,
                COUNT(DISTINCT pw.prompt_id) AS prompt_count
         FROM workspaces w
         LEFT JOIN prompt_workspaces pw ON pw.workspace_id = w.id
         LEFT JOIN prompts p ON p.id = pw.prompt_id AND p.user_id = w.user_id
         WHERE w.user_id = ?
         GROUP BY w.id
         ORDER BY w.pinned DESC, w.sort_order ASC, w.name ASC`,
        [req.user.userId]
      );
      return rows;
    });
  } catch (error) {
    console.error('Get workspaces error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/workspaces/:id/activate', authenticateToken, requirePasswordChangeCleared, async (req, res) => {
  try {
    const workspaceId = parseInt(req.params.id, 10);
    if (!Number.isFinite(workspaceId)) return res.status(400).json({ error: 'Invalid workspace id' });

    const [rows] = await pool.execute('SELECT id FROM workspaces WHERE id = ? AND user_id = ?', [
      workspaceId,
      req.user.userId
    ]);
    if (rows.length === 0) return res.status(404).json({ error: 'Workspace not found' });

    await pool.execute('UPDATE workspaces SET last_used_at = NOW() WHERE id = ? AND user_id = ?', [
      workspaceId,
      req.user.userId
    ]);
    await audit(pool, { userId: req.user.userId, action: 'workspace_activate', details: { workspaceId }, ip: req.ip });
    invalidateMetadataCacheUser(req.user.userId);
    res.json({ success: true });
  } catch (error) {
    console.error('Activate workspace error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/workspaces', authenticateToken, requirePasswordChangeCleared, requireWriteAccess, async (req, res) => {
  try {
    return await runIdempotentCreate(req, res, 'workspaces:create', async () => {
      const name = normalizeWorkspaceName(req.body?.name);
      if (!isValidWorkspaceName(name)) {
        return { status: 400, body: { error: 'Workspace name is required (max 64 chars)' } };
      }

      const [sortRows] = await pool.execute(
        'SELECT COALESCE(MAX(sort_order), 0) AS max_sort FROM workspaces WHERE user_id = ?',
        [req.user.userId]
      );
      const sortOrder = Number(sortRows[0]?.max_sort ?? 0) + 1;

      let tmuxSession = generateWorkspaceTmuxSession(req.user.userId);
      let insertedId = null;

      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          const [result] = await pool.execute(
            `INSERT INTO workspaces (user_id, name, tmux_session, sort_order, pinned, is_default)
             VALUES (?, ?, ?, ?, FALSE, FALSE)`,
            [req.user.userId, name, tmuxSession, sortOrder]
          );
          insertedId = result.insertId;
          break;
        } catch (err) {
          if (err?.code === 'ER_DUP_ENTRY') {
            tmuxSession = generateWorkspaceTmuxSession(req.user.userId);
            continue;
          }
          throw err;
        }
      }

      if (!insertedId) {
        return { status: 500, body: { error: 'Failed to create workspace (retry)' } };
      }

      invalidateMetadataCacheUser(req.user.userId);
      await audit(pool, {
        userId: req.user.userId,
        action: 'workspace_create',
        details: { id: insertedId, name },
        ip: req.ip,
        requestId: req.requestId
      });
      return {
        status: 201,
        body: {
          id: insertedId,
          name,
          tmux_session: tmuxSession,
          sort_order: sortOrder,
          pinned: false,
          is_default: false,
          prompt_count: 0
        }
      };
    });
  } catch (error) {
    if (error?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Workspace name already exists' });
    }
    console.error('Create workspace error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put(
  '/api/workspaces/:id',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      const workspaceId = parseInt(req.params.id, 10);
      if (!Number.isFinite(workspaceId)) {
        return res.status(400).json({ error: 'Invalid workspace id' });
      }

      const [existing] = await pool.execute('SELECT id FROM workspaces WHERE id = ? AND user_id = ?', [
        workspaceId,
        req.user.userId
      ]);
      if (existing.length === 0) {
        return res.status(404).json({ error: 'Workspace not found' });
      }

      const updates = {};
      if (req.body?.name !== undefined) {
        const name = normalizeWorkspaceName(req.body.name);
        if (!isValidWorkspaceName(name)) {
          return res.status(400).json({ error: 'Workspace name is required (max 64 chars)' });
        }
        updates.name = name;
      }
      if (req.body?.pinned !== undefined) {
        updates.pinned = Boolean(req.body.pinned);
      }
      if (req.body?.sort_order !== undefined) {
        const sortOrder = Number(req.body.sort_order);
        if (!Number.isFinite(sortOrder)) {
          return res.status(400).json({ error: 'Invalid sort_order' });
        }
        updates.sort_order = Math.max(0, Math.floor(sortOrder));
      }

      const wantsDefault = req.body?.is_default === true;
      const updateKeys = Object.keys(updates);

      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();

        if (wantsDefault) {
          await conn.execute('UPDATE workspaces SET is_default = FALSE WHERE user_id = ?', [req.user.userId]);
          updates.is_default = true;
          if (!updateKeys.includes('is_default')) updateKeys.push('is_default');
        }

        if (updateKeys.length > 0) {
          const setClause = updateKeys.map((key) => `${key} = ?`).join(', ');
          const params = updateKeys.map((key) => updates[key]);
          params.push(workspaceId, req.user.userId);
          await conn.execute(`UPDATE workspaces SET ${setClause} WHERE id = ? AND user_id = ?`, params);
        }

        // Ensure at least one default workspace.
        const [defaults] = await conn.execute(
          'SELECT id FROM workspaces WHERE user_id = ? AND is_default = TRUE LIMIT 1',
          [req.user.userId]
        );
        if (defaults.length === 0) {
          const [first] = await conn.execute(
            'SELECT id FROM workspaces WHERE user_id = ? ORDER BY pinned DESC, sort_order ASC, id ASC LIMIT 1',
            [req.user.userId]
          );
          if (first.length > 0) {
            await conn.execute('UPDATE workspaces SET is_default = TRUE WHERE id = ? AND user_id = ?', [
              first[0].id,
              req.user.userId
            ]);
          }
        }

        await conn.commit();
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }

      invalidateMetadataCacheUser(req.user.userId);
      await audit(pool, {
        userId: req.user.userId,
        action: 'workspace_update',
        details: { id: workspaceId, updates },
        ip: req.ip,
        requestId: req.requestId
      });
      res.json({ success: true });
    } catch (error) {
      if (error?.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'Workspace name already exists' });
      }
      console.error('Update workspace error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.post(
  '/api/workspaces/reorder',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      const ids = Array.isArray(req.body?.ids)
        ? req.body.ids.map((id) => parseInt(id, 10)).filter(Number.isFinite)
        : [];
      if (ids.length === 0) {
        return res.status(400).json({ error: 'ids array is required' });
      }

      const [rows] = await pool.execute(
        `SELECT id FROM workspaces WHERE user_id = ? AND id IN (${ids.map(() => '?').join(',')})`,
        [req.user.userId, ...ids]
      );
      if (rows.length !== ids.length) {
        return res.status(400).json({ error: 'One or more workspaces not found' });
      }

      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        for (let i = 0; i < ids.length; i += 1) {
          await conn.execute('UPDATE workspaces SET sort_order = ? WHERE id = ? AND user_id = ?', [
            i,
            ids[i],
            req.user.userId
          ]);
        }
        await conn.commit();
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }

      invalidateMetadataCacheUser(req.user.userId);
      await audit(pool, {
        userId: req.user.userId,
        action: 'workspace_reorder',
        details: { ids },
        ip: req.ip,
        requestId: req.requestId
      });
      res.json({ success: true });
    } catch (error) {
      console.error('Reorder workspaces error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.delete(
  '/api/workspaces/:id',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      const workspaceId = parseInt(req.params.id, 10);
      if (!Number.isFinite(workspaceId)) {
        return res.status(400).json({ error: 'Invalid workspace id' });
      }

      const confirm = String(req.query.confirm || '').toLowerCase() === 'true';

      const [workspaceRows] = await pool.execute('SELECT id, is_default FROM workspaces WHERE id = ? AND user_id = ?', [
        workspaceId,
        req.user.userId
      ]);
      if (workspaceRows.length === 0) {
        return res.status(404).json({ error: 'Workspace not found' });
      }

      const [countRows] = await pool.execute('SELECT COUNT(*) AS count FROM workspaces WHERE user_id = ?', [
        req.user.userId
      ]);
      const workspaceCount = Number(countRows[0]?.count ?? 0);
      if (workspaceCount <= 1) {
        return res.status(400).json({ error: 'Cannot delete your last workspace' });
      }

      const [promptCountRows] = await pool.execute(
        `SELECT COUNT(DISTINCT pw.prompt_id) AS prompt_count
       FROM prompt_workspaces pw
       INNER JOIN prompts p ON p.id = pw.prompt_id
       WHERE pw.workspace_id = ? AND p.user_id = ?`,
        [workspaceId, req.user.userId]
      );
      const promptCount = Number(promptCountRows[0]?.prompt_count ?? 0);

      if (promptCount > 0 && !confirm) {
        return res.status(409).json({
          error: `Workspace has ${promptCount} associated prompt(s)`,
          code: 'WORKSPACE_HAS_PROMPTS',
          promptCount
        });
      }

      const wasDefault = Boolean(workspaceRows[0]?.is_default);

      const conn = await pool.getConnection();
      let orphanedDeleted = 0;
      try {
        await conn.beginTransaction();

        await conn.execute('DELETE FROM workspaces WHERE id = ? AND user_id = ?', [workspaceId, req.user.userId]);

        // Delete orphaned scoped prompts (global prompts are preserved).
        const [deleteResult] = await conn.execute(
          `DELETE p
         FROM prompts p
         LEFT JOIN prompt_workspaces pw ON pw.prompt_id = p.id
         WHERE p.user_id = ?
           AND p.is_global = FALSE
           AND pw.prompt_id IS NULL`,
          [req.user.userId]
        );
        orphanedDeleted = deleteResult.affectedRows ?? 0;

        if (wasDefault) {
          const [defaults] = await conn.execute(
            'SELECT id FROM workspaces WHERE user_id = ? AND is_default = TRUE LIMIT 1',
            [req.user.userId]
          );
          if (defaults.length === 0) {
            const [first] = await conn.execute(
              'SELECT id FROM workspaces WHERE user_id = ? ORDER BY pinned DESC, sort_order ASC, id ASC LIMIT 1',
              [req.user.userId]
            );
            if (first.length > 0) {
              await conn.execute('UPDATE workspaces SET is_default = TRUE WHERE id = ? AND user_id = ?', [
                first[0].id,
                req.user.userId
              ]);
            }
          }
        }

        await conn.commit();
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }

      invalidateMetadataCacheUser(req.user.userId);
      await audit(pool, {
        userId: req.user.userId,
        action: 'workspace_delete',
        details: { id: workspaceId, promptCount, orphanedPromptsDeleted: orphanedDeleted },
        ip: req.ip,
        requestId: req.requestId
      });
      res.json({ success: true, promptCount, orphanedPromptsDeleted: orphanedDeleted });
    } catch (error) {
      console.error('Delete workspace error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Login options (no auth required)
app.get('/api/auth/options', (_req, res) => {
  res.json({
    turnstileSiteKey: TURNSTILE_SITE_KEY || null,
    captchaEnabled: Boolean(TURNSTILE_SITE_KEY && TURNSTILE_SECRET_KEY)
  });
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const username = normalizeName(req.body?.username, 50);
    const password = String(req.body?.password || '');
    const totp = String(req.body?.totp || req.body?.mfa || '').replace(/\s+/g, '');
    const captchaToken = String(req.body?.captchaToken || '').trim();
    const now = Date.now();
    const ipKey = String(req.ip || 'unknown');
    const userKey = username ? username.toLowerCase() : '';
    const ipEntry = recordLoginAttempt(loginIpStats, ipKey, now, LOGIN_IP_WINDOW_MS);
    const userEntry = recordLoginAttempt(loginUserStats, userKey, now, LOGIN_USERNAME_WINDOW_MS);

    const ipBlocked = ipEntry.count >= LOGIN_IP_MAX_ATTEMPTS;
    const userBlocked = userEntry.count >= LOGIN_USERNAME_MAX_ATTEMPTS;
    if (ipBlocked || userBlocked) {
      const retryAfterSeconds = Math.max(
        getLoginRetryAfterSeconds(ipEntry, LOGIN_IP_WINDOW_MS, now),
        getLoginRetryAfterSeconds(userEntry, LOGIN_USERNAME_WINDOW_MS, now)
      );
      res.setHeader('Retry-After', String(retryAfterSeconds));
      await audit(pool, {
        userId: null,
        action: 'login_throttled',
        details: { username, ipAttempts: ipEntry.count, userAttempts: userEntry.count },
        ip: req.ip,
        requestId: req.requestId
      }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
      return res.status(429).json({
        error: 'Too many login attempts. Try again later.',
        code: 'LOGIN_THROTTLED',
        retryAfterSeconds
      });
    }

    const captchaRequired = shouldRequireCaptcha(ipEntry, userEntry);
    if (captchaRequired) {
      const captchaValid = await validateTurnstileToken(captchaToken, req.ip);
      if (!captchaValid) {
        await audit(pool, {
          userId: null,
          action: 'login_captcha_required',
          details: { username },
          ip: req.ip,
          requestId: req.requestId
        }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
        return res.status(403).json({
          error: 'Captcha validation required',
          code: 'CAPTCHA_REQUIRED',
          captchaRequired: true
        });
      }
    }

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const [rows] = await pool.execute(
      `SELECT id, username, password_hash, role, must_change_password, active,
              failed_login_attempts, last_failed_login_at, locked_until,
              mfa_totp_secret, mfa_totp_enabled
       FROM users WHERE username = ?`,
      [username]
    );

    if (rows.length === 0) {
      // Timing-safe: still hash to prevent timing attacks
      await bcrypt.hash(password, PASSWORD_HASH_ROUNDS);
      await audit(pool, {
        userId: null,
        action: 'login_failed',
        details: { username, reason: 'invalid_credentials' },
        ip: req.ip,
        requestId: req.requestId
      }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = rows[0];
    const lockedUntil = user.locked_until ? new Date(user.locked_until).getTime() : null;
    if (lockedUntil && Number.isFinite(lockedUntil) && lockedUntil > Date.now()) {
      // Timing-safe: still do a hash to reduce enumeration via timing.
      await bcrypt.hash(password, PASSWORD_HASH_ROUNDS);
      const retryAfterSeconds = Math.max(1, Math.ceil((lockedUntil - Date.now()) / 1000));
      res.setHeader('Retry-After', String(retryAfterSeconds));
      return res
        .status(429)
        .json({ error: 'Account temporarily locked. Try again later.', code: 'ACCOUNT_LOCKED', retryAfterSeconds });
    }
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      const now = Date.now();
      const lastFailedAt = user.last_failed_login_at ? new Date(user.last_failed_login_at).getTime() : null;
      const withinWindow = lastFailedAt && Number.isFinite(lastFailedAt) && now - lastFailedAt <= LOGIN_LOCK_WINDOW_MS;
      const previousAttempts = withinWindow ? Number(user.failed_login_attempts ?? 0) : 0;
      const attempts = Math.max(0, previousAttempts) + 1;
      const shouldLock = attempts >= LOGIN_LOCK_MAX_ATTEMPTS;
      const lockUntilDate = shouldLock ? new Date(now + LOGIN_LOCK_DURATION_MS) : null;
      try {
        await pool.execute(
          'UPDATE users SET failed_login_attempts = ?, last_failed_login_at = NOW(), locked_until = ? WHERE id = ?',
          [attempts, lockUntilDate, user.id]
        );
      } catch (error) {
        console.warn('Failed login counter update warning:', error?.message ?? error);
      }
      if (shouldLock) {
        const retryAfterSeconds = Math.max(1, Math.ceil(LOGIN_LOCK_DURATION_MS / 1000));
        res.setHeader('Retry-After', String(retryAfterSeconds));
        await audit(pool, { userId: user.id, action: 'login_locked', details: { attempts }, ip: req.ip });
        return res
          .status(429)
          .json({ error: 'Account temporarily locked. Try again later.', code: 'ACCOUNT_LOCKED', retryAfterSeconds });
      }
      await audit(pool, {
        userId: user.id,
        action: 'login_failed',
        details: { username, reason: 'invalid_credentials' },
        ip: req.ip,
        requestId: req.requestId
      }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.active === 0 || user.active === false) {
      await audit(pool, {
        userId: user.id,
        action: 'login_failed',
        details: { username, reason: 'account_disabled' },
        ip: req.ip,
        requestId: req.requestId
      }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
      return res.status(403).json({ error: 'Account disabled', code: 'ACCOUNT_DISABLED' });
    }

    const mfaEnabled = Boolean(user.mfa_totp_enabled);
    const mfaSecret = user.mfa_totp_secret ? String(user.mfa_totp_secret) : '';
    if (MFA_ENFORCED_ROLES.has(user.role) && mfaEnabled) {
      if (!totp) {
        await audit(pool, {
          userId: user.id,
          action: 'login_mfa_required',
          details: { username },
          ip: req.ip,
          requestId: req.requestId
        }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
        return res.status(401).json({ error: 'MFA code required', code: 'MFA_REQUIRED', mfaRequired: true });
      }
      const isValidTotp = isValidTotpToken(totp, mfaSecret);
      if (!isValidTotp) {
        await audit(pool, {
          userId: user.id,
          action: 'login_mfa_failed',
          details: { username },
          ip: req.ip,
          requestId: req.requestId
        }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
        return res.status(401).json({ error: 'Invalid MFA code', code: 'MFA_INVALID' });
      }
    }

    // Clear lock state after successful auth.
    try {
      await pool.execute(
        'UPDATE users SET failed_login_attempts = 0, last_failed_login_at = NULL, locked_until = NULL WHERE id = ?',
        [user.id]
      );
    } catch (error) {
      console.warn('Failed login counter reset warning:', error?.message ?? error);
    }

    resetLoginAttempt(loginIpStats, ipKey);
    resetLoginAttempt(loginUserStats, userKey);

    const session = await createSessionRecord(pool, {
      userId: user.id,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    const accessToken = signAccessToken({
      sessionId: session.sessionId,
      userId: user.id,
      username: user.username,
      role: user.role
    });

    setAuthCookies(res, {
      accessToken,
      refreshToken: session.refreshToken,
      sessionId: session.sessionId,
      terminalToken: session.terminalToken,
      csrfToken: session.csrfToken
    });

    await audit(pool, {
      userId: user.id,
      action: 'login',
      details: { username, mfaUsed: MFA_ENFORCED_ROLES.has(user.role) && mfaEnabled },
      ip: req.ip,
      requestId: req.requestId
    });

    res.json({
      token: accessToken,
      user: { id: user.id, username: user.username, role: user.role },
      mustChangePassword: Boolean(user.must_change_password),
      expiresAt: new Date(Date.now() + ACCESS_TOKEN_TTL_MS).toISOString(),
      refreshExpiresAt: session.expiresAt.toISOString()
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Refresh access token using refresh cookie
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const refreshed = await refreshSessionFromCookies(req, res, { rotate: true });
    if (!refreshed) return res.status(401).json({ error: 'Session expired or revoked' });
    const user = refreshed.user;
    await audit(pool, {
      userId: user.userId,
      action: 'token_refresh',
      details: { username: user.username },
      ip: req.ip,
      requestId: req.requestId
    }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
    res.json({
      token: refreshed.accessToken,
      user: { id: user.userId, username: user.username, role: user.role },
      expiresAt: new Date(Date.now() + ACCESS_TOKEN_TTL_MS).toISOString()
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    await pool.execute(
      'UPDATE sessions SET revoked = TRUE, refresh_token_hash = NULL, refresh_expires_at = NOW() WHERE id = ?',
      [req.user.sessionId]
    );
    invalidateAuthCacheSession(req.user.sessionId);
    invalidateTerminalSession(req.user.sessionId);
    clearAuthCookies(res);
    await audit(pool, {
      userId: req.user.userId,
      action: 'logout',
      details: { username: req.user.username },
      ip: req.ip,
      requestId: req.requestId
    }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
    res.json({ success: true });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Validate token (for nginx auth_request)
app.get('/api/auth/validate', authenticateToken, (req, res) => {
  touchSessionLastSeen(req.user.sessionId);
  res.set('X-TAILSHELL-User-Id', String(req.user.userId));
  res.set('X-TAILSHELL-Username', req.user.username);
  res.set('X-TAILSHELL-Role', req.user.role);
  res.set('X-TAILSHELL-Session-Id', String(req.user.sessionId));

  if (req.user.mustChangePassword) {
    return res.status(403).json({
      valid: false,
      error: 'Password change required',
      code: 'PASSWORD_CHANGE_REQUIRED'
    });
  }
  res.json({ valid: true, user: req.user });
});

// Validate terminal access (for nginx auth_request on /ws, /token, /terminal)
app.get('/api/terminal/validate', authenticateToken, (req, res) => {
  touchSessionLastSeen(req.user.sessionId);

  if (!isTerminalRoleAllowed(req.user.role)) {
    return res.status(403).json({ valid: false, error: 'Terminal access restricted', code: 'TERMINAL_FORBIDDEN' });
  }

  const terminalCookie = getCookieValue(req, TERMINAL_COOKIE_NAME);
  if (!terminalCookie || terminalCookie !== req.user.terminalToken) {
    return res.status(401).json({ valid: false, error: 'Terminal access denied' });
  }

  const registration = registerTerminalSession(req.user.sessionId, req.user.userId);
  if (!registration.allowed) {
    return res.status(429).json({
      valid: false,
      error: 'Too many active terminal sessions',
      code: 'TERMINAL_LIMIT_REACHED',
      limit: TERMINAL_MAX_SESSIONS_PER_USER
    });
  }

  const terminalArg = normalizeTerminalArg(req.user.userId, req.user.sessionId);
  res.set('X-TAILSHELL-User-Id', String(req.user.userId));
  res.set('X-TAILSHELL-Username', req.user.username);
  res.set('X-TAILSHELL-Role', req.user.role);
  res.set('X-TAILSHELL-Session-Id', String(req.user.sessionId));
  res.set('X-TAILSHELL-Terminal-Arg', terminalArg);

  if (req.user.mustChangePassword) {
    return res.status(403).json({
      valid: false,
      error: 'Password change required',
      code: 'PASSWORD_CHANGE_REQUIRED'
    });
  }
  res.json({ valid: true });
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    return sendJsonWithEtagCached(req, res, metadataKey(req.user.userId, 'me'), async () => {
      const [rows] = await pool.execute(
        'SELECT id, username, role, must_change_password, active, created_at, mfa_totp_enabled FROM users WHERE id = ?',
        [req.user.userId]
      );
      if (rows.length === 0) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }
      return {
        id: rows[0].id,
        username: rows[0].username,
        role: rows[0].role,
        mustChangePassword: Boolean(rows[0].must_change_password),
        active: Boolean(rows[0].active),
        mfaEnabled: Boolean(rows[0].mfa_totp_enabled),
        terminalAllowed: isTerminalRoleAllowed(rows[0].role),
        created_at: rows[0].created_at
      };
    });
  } catch (error) {
    if (error?.statusCode === 404) {
      return res.status(404).json({ error: 'User not found' });
    }
    console.error('Get user error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Change password
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password required' });
    }

    const passwordError = validatePasswordPolicy(newPassword);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    const [rows] = await pool.execute('SELECT password_hash FROM users WHERE id = ?', [req.user.userId]);

    const valid = await bcrypt.compare(currentPassword, rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const newHash = await bcrypt.hash(newPassword, PASSWORD_HASH_ROUNDS);
    await pool.execute('UPDATE users SET password_hash = ?, must_change_password = FALSE WHERE id = ?', [
      newHash,
      req.user.userId
    ]);

    // Revoke all other sessions
    await pool.execute('UPDATE sessions SET revoked = TRUE WHERE user_id = ? AND id != ?', [
      req.user.userId,
      req.user.sessionId
    ]);
    invalidateAuthCacheUser(req.user.userId);
    invalidateMetadataCacheUser(req.user.userId);
    invalidateTerminalSessionsForUserExcept(req.user.userId, req.user.sessionId);

    await audit(pool, {
      userId: req.user.userId,
      action: 'password_change',
      details: { username: req.user.username },
      ip: req.ip,
      requestId: req.requestId
    }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));

    res.json({ success: true });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// MFA status (admins only)
app.get('/api/auth/mfa', authenticateToken, requirePasswordChangeCleared, requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT mfa_totp_enabled, mfa_totp_confirmed_at FROM users WHERE id = ?', [
      req.user.userId
    ]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({
      enabled: Boolean(rows[0].mfa_totp_enabled),
      confirmedAt: rows[0].mfa_totp_confirmed_at
    });
  } catch (error) {
    console.error('MFA status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// MFA setup (admins only)
app.post('/api/auth/mfa/setup', authenticateToken, requirePasswordChangeCleared, requireAdmin, async (req, res) => {
  try {
    const secret = generateSecret();
    const issuer = 'Tailshell';
    const otpauthUrl = generateURI({ issuer, label: req.user.username, secret });
    await pool.execute(
      'UPDATE users SET mfa_totp_secret = ?, mfa_totp_enabled = FALSE, mfa_totp_confirmed_at = NULL WHERE id = ?',
      [secret, req.user.userId]
    );
    await audit(pool, {
      userId: req.user.userId,
      action: 'mfa_setup_begin',
      details: { username: req.user.username },
      ip: req.ip,
      requestId: req.requestId
    }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
    res.json({ secret, otpauthUrl });
  } catch (error) {
    console.error('MFA setup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// MFA confirm (admins only)
app.post('/api/auth/mfa/confirm', authenticateToken, requirePasswordChangeCleared, requireAdmin, async (req, res) => {
  try {
    const token = String(req.body?.token || '').replace(/\s+/g, '');
    if (!token) return res.status(400).json({ error: 'MFA token required' });
    const [rows] = await pool.execute('SELECT mfa_totp_secret FROM users WHERE id = ?', [req.user.userId]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const secret = rows[0].mfa_totp_secret ? String(rows[0].mfa_totp_secret) : '';
    if (!isValidTotpToken(token, secret)) {
      await audit(pool, {
        userId: req.user.userId,
        action: 'mfa_confirm_failed',
        details: { username: req.user.username },
        ip: req.ip,
        requestId: req.requestId
      }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
      return res.status(401).json({ error: 'Invalid MFA token', code: 'MFA_INVALID' });
    }
    await pool.execute('UPDATE users SET mfa_totp_enabled = TRUE, mfa_totp_confirmed_at = NOW() WHERE id = ?', [
      req.user.userId
    ]);
    await audit(pool, {
      userId: req.user.userId,
      action: 'mfa_enabled',
      details: { username: req.user.username },
      ip: req.ip,
      requestId: req.requestId
    }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
    res.json({ success: true });
  } catch (error) {
    console.error('MFA confirm error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// MFA disable (admins only)
app.post('/api/auth/mfa/disable', authenticateToken, requirePasswordChangeCleared, requireAdmin, async (req, res) => {
  try {
    const token = String(req.body?.token || '').replace(/\s+/g, '');
    const password = String(req.body?.password || '');
    if (!token || !password) {
      return res.status(400).json({ error: 'Password and MFA token required' });
    }
    const [rows] = await pool.execute('SELECT password_hash, mfa_totp_secret FROM users WHERE id = ?', [
      req.user.userId
    ]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const passwordValid = await bcrypt.compare(password, rows[0].password_hash);
    if (!passwordValid) return res.status(401).json({ error: 'Password is incorrect' });
    const secret = rows[0].mfa_totp_secret ? String(rows[0].mfa_totp_secret) : '';
    if (!isValidTotpToken(token, secret)) {
      return res.status(401).json({ error: 'Invalid MFA token', code: 'MFA_INVALID' });
    }
    await pool.execute(
      'UPDATE users SET mfa_totp_secret = NULL, mfa_totp_enabled = FALSE, mfa_totp_confirmed_at = NULL WHERE id = ?',
      [req.user.userId]
    );
    await audit(pool, {
      userId: req.user.userId,
      action: 'mfa_disabled',
      details: { username: req.user.username },
      ip: req.ip,
      requestId: req.requestId
    }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
    res.json({ success: true });
  } catch (error) {
    console.error('MFA disable error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Session management
app.get('/api/auth/sessions', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, created_at, last_seen_at, expires_at, revoked, ip_address, user_agent
       FROM sessions
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      [req.user.userId]
    );
    res.json({
      currentSessionId: req.user.sessionId,
      sessions: rows.map((row) => ({
        id: row.id,
        created_at: row.created_at,
        last_seen_at: row.last_seen_at,
        expires_at: row.expires_at,
        revoked: Boolean(row.revoked),
        ip_address: row.ip_address,
        user_agent: row.user_agent
      }))
    });
  } catch (error) {
    console.error('List sessions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/sessions/revoke-others', authenticateToken, async (req, res) => {
  try {
    await pool.execute(
      'UPDATE sessions SET revoked = TRUE, refresh_token_hash = NULL, refresh_expires_at = NOW() WHERE user_id = ? AND id != ?',
      [req.user.userId, req.user.sessionId]
    );
    await audit(pool, {
      userId: req.user.userId,
      action: 'session_revoke_others',
      details: { username: req.user.username },
      ip: req.ip,
      requestId: req.requestId
    }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
    invalidateAuthCacheUser(req.user.userId);
    invalidateTerminalSessionsForUserExcept(req.user.userId, req.user.sessionId);
    res.json({ success: true });
  } catch (error) {
    console.error('Revoke other sessions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/sessions/:id/revoke', authenticateToken, async (req, res) => {
  try {
    const sessionId = String(req.params.id || '').trim();
    if (!sessionId) {
      return res.status(400).json({ error: 'Session id is required' });
    }

    const [rows] = await pool.execute('SELECT id FROM sessions WHERE id = ? AND user_id = ?', [
      sessionId,
      req.user.userId
    ]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }

    await pool.execute(
      'UPDATE sessions SET revoked = TRUE, refresh_token_hash = NULL, refresh_expires_at = NOW() WHERE id = ? AND user_id = ?',
      [sessionId, req.user.userId]
    );
    invalidateAuthCacheSession(sessionId);
    invalidateTerminalSession(sessionId);
    await audit(pool, {
      userId: req.user.userId,
      action: 'session_revoke',
      details: { sessionId },
      ip: req.ip,
      requestId: req.requestId
    }).catch((error) => console.warn('Audit log warning:', error?.message ?? error));
    res.json({ success: true });
  } catch (error) {
    console.error('Revoke session error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

function normalizeName(value, maxLen) {
  return String(value || '')
    .trim()
    .replace(/\s+/g, ' ')
    .slice(0, maxLen);
}

function normalizeEnum(value, allowed, fallback) {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return allowed.includes(normalized) ? normalized : fallback;
}

function parseOptionalInt(value) {
  if (value === null || value === undefined || value === '') return null;
  const parsed = parseInt(String(value), 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function toJson(value) {
  if (value === undefined) return null;
  if (value === null) return null;
  if (typeof value === 'string') {
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  }
  return value;
}

async function getOrCreateTags(conn, userId, tagNames) {
  const cleaned = Array.from(new Set(tagNames.map((name) => normalizeName(name, 50)).filter(Boolean)));
  if (cleaned.length === 0) return [];

  const placeholders = cleaned.map(() => '?').join(',');
  const [existing] = await conn.execute(
    `SELECT id, name FROM tags WHERE user_id = ? AND name IN (${placeholders}) ORDER BY name`,
    [userId, ...cleaned]
  );

  const existingByName = new Map(existing.map((row) => [String(row.name).toLowerCase(), Number(row.id)]));
  const missing = cleaned.filter((name) => !existingByName.has(name.toLowerCase()));

  if (missing.length > 0) {
    const insertTuples = missing.map(() => '(?, ?)').join(',');
    const insertParams = missing.flatMap((name) => [userId, name]);
    await conn.execute(`INSERT IGNORE INTO tags (user_id, name) VALUES ${insertTuples}`, insertParams);
  }

  const [all] = await conn.execute(
    `SELECT id, name FROM tags WHERE user_id = ? AND name IN (${placeholders}) ORDER BY name`,
    [userId, ...cleaned]
  );
  return all.map((row) => Number(row.id)).filter(Number.isFinite);
}

async function getOrCreatePromptFolders(conn, userId, folderNames) {
  const cleaned = Array.from(new Set(folderNames.map((name) => normalizeName(name, 80)).filter(Boolean)));
  if (cleaned.length === 0) return new Map();

  const placeholders = cleaned.map(() => '?').join(',');
  const [existing] = await conn.execute(
    `SELECT id, name FROM prompt_folders WHERE user_id = ? AND name IN (${placeholders}) ORDER BY name`,
    [userId, ...cleaned]
  );

  const existingByName = new Map(existing.map((row) => [String(row.name).toLowerCase(), Number(row.id)]));
  const missing = cleaned.filter((name) => !existingByName.has(name.toLowerCase()));

  if (missing.length > 0) {
    const insertTuples = missing.map(() => '(?, ?, 0)').join(',');
    const insertParams = missing.flatMap((name) => [userId, name]);
    await conn.execute(
      `INSERT IGNORE INTO prompt_folders (user_id, name, sort_order) VALUES ${insertTuples}`,
      insertParams
    );
  }

  const [all] = await conn.execute(
    `SELECT id, name FROM prompt_folders WHERE user_id = ? AND name IN (${placeholders}) ORDER BY name`,
    [userId, ...cleaned]
  );

  return new Map(all.map((row) => [String(row.name).toLowerCase(), Number(row.id)]));
}

async function replacePromptTags(conn, promptId, tagIds) {
  await conn.execute('DELETE FROM prompt_tags WHERE prompt_id = ?', [promptId]);
  const unique = Array.from(new Set(tagIds.map((id) => Number(id)).filter(Number.isFinite)));
  if (unique.length === 0) return;
  const tuples = unique.map(() => '(?, ?)').join(',');
  const params = unique.flatMap((tagId) => [promptId, tagId]);
  await conn.execute(`INSERT INTO prompt_tags (prompt_id, tag_id) VALUES ${tuples}`, params);
}

async function insertPromptWorkspaces(conn, promptId, workspaceIds) {
  const unique = Array.from(new Set(workspaceIds.map((id) => Number(id)).filter(Number.isFinite)));
  if (unique.length === 0) return;
  const tuples = unique.map(() => '(?, ?)').join(',');
  const params = unique.flatMap((workspaceId) => [promptId, workspaceId]);
  await conn.execute(`INSERT INTO prompt_workspaces (prompt_id, workspace_id) VALUES ${tuples}`, params);
}

async function replacePromptWorkspaces(conn, promptId, workspaceIds) {
  await conn.execute('DELETE FROM prompt_workspaces WHERE prompt_id = ?', [promptId]);
  await insertPromptWorkspaces(conn, promptId, workspaceIds);
}

async function insertPromptVersion(
  conn,
  { promptId, userId, label, command, description, status, visibility, metadata }
) {
  const [rows] = await conn.execute(
    'SELECT COALESCE(MAX(version_num), 0) AS max_version FROM prompt_versions WHERE prompt_id = ?',
    [promptId]
  );
  const nextVersion = Number(rows[0]?.max_version ?? 0) + 1;
  await conn.execute(
    `INSERT INTO prompt_versions
      (prompt_id, version_num, created_by, label, command, description, status, visibility, metadata)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      promptId,
      nextVersion,
      userId,
      label,
      command,
      description || null,
      status,
      visibility,
      metadata ? JSON.stringify(metadata) : null
    ]
  );
  return nextVersion;
}

async function emitEvent(conn, { userId, type, payload, ip, requestId }) {
  try {
    await conn.execute('INSERT INTO events (user_id, type, payload, ip_address, request_id) VALUES (?, ?, ?, ?, ?)', [
      userId ?? null,
      type,
      payload ? JSON.stringify(payload) : null,
      ip ?? null,
      requestId ?? null
    ]);
  } catch (error) {
    console.warn('Event log write warning:', error?.message ?? error);
  }
}

async function audit(conn, { userId, action, details, ip, requestId }) {
  return emitEvent(conn, {
    userId,
    type: action,
    payload: details ?? null,
    ip,
    requestId
  });
}

// Tags
app.get('/api/tags', authenticateToken, requirePasswordChangeCleared, async (req, res) => {
  try {
    return sendJsonWithEtagCached(req, res, metadataKey(req.user.userId, 'tags'), async () => {
      const [rows] = await pool.execute('SELECT id, name, created_at FROM tags WHERE user_id = ? ORDER BY name', [
        req.user.userId
      ]);
      return rows;
    });
  } catch (error) {
    console.error('Get tags error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/tags', authenticateToken, requirePasswordChangeCleared, requireWriteAccess, async (req, res) => {
  try {
    return await runIdempotentCreate(req, res, 'tags:create', async () => {
      const name = normalizeName(req.body?.name, 50);
      if (!name) return { status: 400, body: { error: 'Tag name is required (max 50 chars)' } };

      const [result] = await pool.execute('INSERT INTO tags (user_id, name) VALUES (?, ?)', [req.user.userId, name]);
      await audit(pool, { userId: req.user.userId, action: 'tag_create', details: { name }, ip: req.ip });
      invalidateMetadataCacheUser(req.user.userId);
      return { status: 201, body: { id: result.insertId, name } };
    });
  } catch (error) {
    if (error?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Tag already exists' });
    }
    console.error('Create tag error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/tags/:id', authenticateToken, requirePasswordChangeCleared, requireWriteAccess, async (req, res) => {
  try {
    const tagId = parseInt(req.params.id, 10);
    if (!Number.isFinite(tagId)) return res.status(400).json({ error: 'Invalid tag id' });
    const name = normalizeName(req.body?.name, 50);
    if (!name) return res.status(400).json({ error: 'Tag name is required (max 50 chars)' });

    const [result] = await pool.execute('UPDATE tags SET name = ? WHERE id = ? AND user_id = ?', [
      name,
      tagId,
      req.user.userId
    ]);
    if ((result.affectedRows ?? 0) === 0) return res.status(404).json({ error: 'Tag not found' });
    await audit(pool, { userId: req.user.userId, action: 'tag_update', details: { id: tagId, name }, ip: req.ip });
    invalidateMetadataCacheUser(req.user.userId);
    res.json({ success: true });
  } catch (error) {
    if (error?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Tag already exists' });
    }
    console.error('Update tag error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/tags/:id', authenticateToken, requirePasswordChangeCleared, requireWriteAccess, async (req, res) => {
  try {
    const tagId = parseInt(req.params.id, 10);
    if (!Number.isFinite(tagId)) return res.status(400).json({ error: 'Invalid tag id' });

    const [result] = await pool.execute('DELETE FROM tags WHERE id = ? AND user_id = ?', [tagId, req.user.userId]);
    if ((result.affectedRows ?? 0) === 0) return res.status(404).json({ error: 'Tag not found' });
    await audit(pool, { userId: req.user.userId, action: 'tag_delete', details: { id: tagId }, ip: req.ip });
    invalidateMetadataCacheUser(req.user.userId);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete tag error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Prompt folders
app.get('/api/prompt-folders', authenticateToken, requirePasswordChangeCleared, async (req, res) => {
  try {
    return sendJsonWithEtagCached(req, res, metadataKey(req.user.userId, 'prompt-folders'), async () => {
      const [rows] = await pool.execute(
        'SELECT id, name, sort_order, created_at, updated_at FROM prompt_folders WHERE user_id = ? ORDER BY sort_order, name',
        [req.user.userId]
      );
      return rows;
    });
  } catch (error) {
    console.error('Get folders error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post(
  '/api/prompt-folders',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      return await runIdempotentCreate(req, res, 'prompt-folders:create', async () => {
        const name = normalizeName(req.body?.name, 80);
        if (!name) return { status: 400, body: { error: 'Folder name is required (max 80 chars)' } };

        const [sortRows] = await pool.execute(
          'SELECT COALESCE(MAX(sort_order), 0) AS max_sort FROM prompt_folders WHERE user_id = ?',
          [req.user.userId]
        );
        const sortOrder = Number(sortRows[0]?.max_sort ?? 0) + 1;

        const [result] = await pool.execute('INSERT INTO prompt_folders (user_id, name, sort_order) VALUES (?, ?, ?)', [
          req.user.userId,
          name,
          sortOrder
        ]);
        await audit(pool, { userId: req.user.userId, action: 'folder_create', details: { name }, ip: req.ip });
        invalidateMetadataCacheUser(req.user.userId);
        return { status: 201, body: { id: result.insertId, name, sort_order: sortOrder } };
      });
    } catch (error) {
      if (error?.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'Folder already exists' });
      }
      console.error('Create folder error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.put(
  '/api/prompt-folders/:id',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      const folderId = parseInt(req.params.id, 10);
      if (!Number.isFinite(folderId)) return res.status(400).json({ error: 'Invalid folder id' });

      const updates = {};
      if (req.body?.name !== undefined) {
        const name = normalizeName(req.body?.name, 80);
        if (!name) return res.status(400).json({ error: 'Folder name is required (max 80 chars)' });
        updates.name = name;
      }
      if (req.body?.sort_order !== undefined) {
        const sortOrder = Number(req.body.sort_order);
        if (!Number.isFinite(sortOrder)) return res.status(400).json({ error: 'Invalid sort_order' });
        updates.sort_order = Math.max(0, Math.floor(sortOrder));
      }

      const keys = Object.keys(updates);
      if (keys.length === 0) return res.json({ success: true });

      const setClause = keys.map((key) => `${key} = ?`).join(', ');
      const params = keys.map((key) => updates[key]);
      params.push(folderId, req.user.userId);

      const [result] = await pool.execute(
        `UPDATE prompt_folders SET ${setClause} WHERE id = ? AND user_id = ?`,
        params
      );
      if ((result.affectedRows ?? 0) === 0) return res.status(404).json({ error: 'Folder not found' });
      await audit(pool, {
        userId: req.user.userId,
        action: 'folder_update',
        details: { id: folderId, ...updates },
        ip: req.ip
      });
      invalidateMetadataCacheUser(req.user.userId);
      res.json({ success: true });
    } catch (error) {
      if (error?.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'Folder already exists' });
      }
      console.error('Update folder error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.post(
  '/api/prompt-folders/reorder',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      const ids = Array.isArray(req.body?.ids)
        ? req.body.ids.map((id) => parseInt(id, 10)).filter(Number.isFinite)
        : [];
      if (ids.length === 0) return res.status(400).json({ error: 'ids array is required' });

      const [rows] = await pool.execute(
        `SELECT id FROM prompt_folders WHERE user_id = ? AND id IN (${ids.map(() => '?').join(',')})`,
        [req.user.userId, ...ids]
      );
      if (rows.length !== ids.length) return res.status(400).json({ error: 'One or more folders not found' });

      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        for (let i = 0; i < ids.length; i += 1) {
          await conn.execute('UPDATE prompt_folders SET sort_order = ? WHERE id = ? AND user_id = ?', [
            i,
            ids[i],
            req.user.userId
          ]);
        }
        await audit(conn, { userId: req.user.userId, action: 'folder_reorder', details: { ids }, ip: req.ip });
        await conn.commit();
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }

      invalidateMetadataCacheUser(req.user.userId);
      res.json({ success: true });
    } catch (error) {
      console.error('Reorder folders error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.delete(
  '/api/prompt-folders/:id',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      const folderId = parseInt(req.params.id, 10);
      if (!Number.isFinite(folderId)) return res.status(400).json({ error: 'Invalid folder id' });

      const [result] = await pool.execute('DELETE FROM prompt_folders WHERE id = ? AND user_id = ?', [
        folderId,
        req.user.userId
      ]);
      if ((result.affectedRows ?? 0) === 0) return res.status(404).json({ error: 'Folder not found' });
      await audit(pool, { userId: req.user.userId, action: 'folder_delete', details: { id: folderId }, ip: req.ip });
      invalidateMetadataCacheUser(req.user.userId);
      res.json({ success: true });
    } catch (error) {
      console.error('Delete folder error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Saved prompt filters
app.get('/api/prompt-filters', authenticateToken, requirePasswordChangeCleared, async (req, res) => {
  try {
    return sendJsonWithEtagCached(req, res, metadataKey(req.user.userId, 'prompt-filters'), async () => {
      const [rows] = await pool.execute(
        'SELECT id, name, filter_json, created_at, updated_at FROM prompt_filters WHERE user_id = ? ORDER BY name',
        [req.user.userId]
      );
      return rows.map((row) => {
        let filter = row.filter_json;
        if (typeof filter === 'string') {
          try {
            filter = JSON.parse(filter);
          } catch {
            filter = null;
          }
        }
        return { ...row, filter_json: filter };
      });
    });
  } catch (error) {
    console.error('Get filters error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post(
  '/api/prompt-filters',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      return await runIdempotentCreate(req, res, 'prompt-filters:create', async () => {
        const name = normalizeName(req.body?.name, 80);
        if (!name) return { status: 400, body: { error: 'Filter name is required (max 80 chars)' } };
        const filterJson = toJson(req.body?.filter_json);
        if (!filterJson || typeof filterJson !== 'object') {
          return { status: 400, body: { error: 'filter_json object is required' } };
        }

        const [result] = await pool.execute(
          'INSERT INTO prompt_filters (user_id, name, filter_json) VALUES (?, ?, ?)',
          [req.user.userId, name, JSON.stringify(filterJson)]
        );
        await audit(pool, { userId: req.user.userId, action: 'filter_create', details: { name }, ip: req.ip });
        invalidateMetadataCacheUser(req.user.userId);
        return { status: 201, body: { id: result.insertId, name, filter_json: filterJson } };
      });
    } catch (error) {
      if (error?.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'Filter name already exists' });
      }
      console.error('Create filter error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.put(
  '/api/prompt-filters/:id',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      const filterId = parseInt(req.params.id, 10);
      if (!Number.isFinite(filterId)) return res.status(400).json({ error: 'Invalid filter id' });

      const updates = {};
      if (req.body?.name !== undefined) {
        const name = normalizeName(req.body?.name, 80);
        if (!name) return res.status(400).json({ error: 'Filter name is required (max 80 chars)' });
        updates.name = name;
      }
      if (req.body?.filter_json !== undefined) {
        const filterJson = toJson(req.body?.filter_json);
        if (!filterJson || typeof filterJson !== 'object')
          return res.status(400).json({ error: 'filter_json object is required' });
        updates.filter_json = JSON.stringify(filterJson);
      }

      const keys = Object.keys(updates);
      if (keys.length === 0) return res.json({ success: true });

      const setClause = keys.map((key) => `${key} = ?`).join(', ');
      const params = keys.map((key) => updates[key]);
      params.push(filterId, req.user.userId);

      const [result] = await pool.execute(
        `UPDATE prompt_filters SET ${setClause} WHERE id = ? AND user_id = ?`,
        params
      );
      if ((result.affectedRows ?? 0) === 0) return res.status(404).json({ error: 'Filter not found' });
      await audit(pool, {
        userId: req.user.userId,
        action: 'filter_update',
        details: { id: filterId, ...updates },
        ip: req.ip
      });
      invalidateMetadataCacheUser(req.user.userId);
      res.json({ success: true });
    } catch (error) {
      if (error?.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'Filter name already exists' });
      }
      console.error('Update filter error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.delete(
  '/api/prompt-filters/:id',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      const filterId = parseInt(req.params.id, 10);
      if (!Number.isFinite(filterId)) return res.status(400).json({ error: 'Invalid filter id' });

      const [result] = await pool.execute('DELETE FROM prompt_filters WHERE id = ? AND user_id = ?', [
        filterId,
        req.user.userId
      ]);
      if ((result.affectedRows ?? 0) === 0) return res.status(404).json({ error: 'Filter not found' });
      await audit(pool, { userId: req.user.userId, action: 'filter_delete', details: { id: filterId }, ip: req.ip });
      invalidateMetadataCacheUser(req.user.userId);
      res.json({ success: true });
    } catch (error) {
      console.error('Delete filter error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

function hydratePromptRows(rows) {
  const byId = new Map();
  for (const row of rows) {
    const id = Number(row.id);
    if (!Number.isFinite(id)) continue;

    if (!byId.has(id)) {
      byId.set(id, {
        id,
        owner_user_id: row.owner_user_id,
        owner_username: row.owner_username,
        access: row.access,
        share_permission: row.share_permission ?? null,
        name: row.name,
        label: row.label,
        command: row.command,
        description: row.description,
        is_global: Boolean(row.is_global),
        sort_order: row.sort_order,
        folder_id: row.folder_id ?? null,
        is_favorite: Boolean(row.is_favorite),
        status: row.status,
        visibility: row.visibility,
        metadata: toJson(row.metadata),
        workspace_ids: [],
        tags: []
      });
    }

    if (row.workspace_id !== null && row.workspace_id !== undefined) {
      byId.get(id).workspace_ids.push(Number(row.workspace_id));
    }
    if (row.tag_id !== null && row.tag_id !== undefined) {
      byId.get(id).tags.push({ id: Number(row.tag_id), name: row.tag_name });
    }
  }

  for (const prompt of byId.values()) {
    prompt.tags = Array.from(new Map(prompt.tags.map((tag) => [tag.id, tag])).values()).sort((a, b) =>
      a.name.localeCompare(b.name)
    );
    if (prompt.access !== 'owned') {
      // Shared/public prompts are always shown as global for recipients.
      prompt.is_global = true;
      prompt.workspace_ids = [];
      prompt.folder_id = null;
      prompt.is_favorite = false;
    } else if (prompt.is_global) {
      // Enforce invariant: global prompts do not carry workspace ids.
      prompt.workspace_ids = [];
    } else {
      prompt.workspace_ids = Array.from(new Set(prompt.workspace_ids)).sort((a, b) => a - b);
    }
  }

  return Array.from(byId.values());
}

function parseTagIds(value) {
  const parts = Array.isArray(value) ? value.flatMap((v) => String(v).split(',')) : String(value || '').split(',');
  return Array.from(new Set(parts.map((v) => parseInt(v, 10)).filter((v) => Number.isFinite(v))));
}

// Get prompts (paginated + filterable)
app.get('/api/prompts', authenticateToken, requirePasswordChangeCleared, async (req, res) => {
  try {
    await ensureUserHasWorkspace(req.user.userId);

    const userId = req.user.userId;

    const limitRaw = parseInt(String(req.query?.limit ?? '500'), 10);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(1000, limitRaw)) : 500;
    const offsetRaw = parseInt(String(req.query?.offset ?? '0'), 10);
    const offset = Number.isFinite(offsetRaw) ? Math.max(0, offsetRaw) : 0;

    const q = String(req.query?.q ?? '').trim();
    const favoriteOnly = isTruthyEnv(req.query?.favorite_only);
    const access = normalizeEnum(req.query?.access, ['all', 'owned', 'shared', 'public'], 'all');
    const status = normalizeEnum(req.query?.status, ['all', 'draft', 'published'], 'all');
    const visibility = normalizeEnum(req.query?.visibility, ['all', 'private', 'shared', 'public'], 'all');
    const folderRaw = String(req.query?.folder_id ?? 'all')
      .trim()
      .toLowerCase();
    const folderId = folderRaw === 'none' || folderRaw === 'all' ? folderRaw : parseOptionalInt(folderRaw);
    const tagIds = parseTagIds(req.query?.tag_ids);

    const where = [];
    const whereParams = [];

    if (access === 'owned') {
      where.push('p.user_id = ?');
      whereParams.push(userId);
    } else if (access === 'shared') {
      where.push('p.user_id <> ?');
      whereParams.push(userId);
      where.push('ps.shared_with_user_id IS NOT NULL');
      where.push(`p.status = 'published'`);
    } else if (access === 'public') {
      where.push('p.user_id <> ?');
      whereParams.push(userId);
      where.push('ps.shared_with_user_id IS NULL');
      where.push(`p.visibility = 'public'`);
      where.push(`p.status = 'published'`);
    } else {
      where.push(
        `(p.user_id = ? OR (p.visibility = 'public' AND p.status = 'published') OR (ps.shared_with_user_id IS NOT NULL AND p.status = 'published'))`
      );
      whereParams.push(userId);
    }

    if (favoriteOnly) {
      where.push('p.user_id = ? AND p.is_favorite = TRUE');
      whereParams.push(userId);
    }

    if (folderId === 'none') {
      where.push('(p.user_id <> ? OR p.folder_id IS NULL)');
      whereParams.push(userId);
    } else if (typeof folderId === 'number') {
      where.push('p.user_id = ? AND p.folder_id = ?');
      whereParams.push(userId, folderId);
    }

    if (status !== 'all') {
      where.push('p.status = ?');
      whereParams.push(status);
    }

    if (visibility !== 'all') {
      where.push('p.visibility = ?');
      whereParams.push(visibility);
    }

    for (const tagId of tagIds) {
      where.push('EXISTS (SELECT 1 FROM prompt_tags pt WHERE pt.prompt_id = p.id AND pt.tag_id = ?)');
      whereParams.push(tagId);
    }

    if (q) {
      const like = `%${q}%`;
      where.push(
        `(p.label LIKE ? OR p.name LIKE ? OR p.command LIKE ? OR p.description LIKE ? OR EXISTS (
          SELECT 1 FROM prompt_tags pt2
          INNER JOIN tags t2 ON t2.id = pt2.tag_id
          WHERE pt2.prompt_id = p.id AND t2.name LIKE ?
        ))`
      );
      whereParams.push(like, like, like, like, like);
    }

    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
    const [idRows] = await pool.execute(
      `SELECT p.id,
              CASE
                WHEN p.user_id = ? THEN 0
                WHEN ps.shared_with_user_id IS NOT NULL THEN 1
                ELSE 2
              END AS access_rank
       FROM prompts p
       LEFT JOIN prompt_shares ps ON ps.prompt_id = p.id AND ps.shared_with_user_id = ?
       ${whereClause}
       ORDER BY access_rank, p.sort_order, p.label
       LIMIT ? OFFSET ?`,
      [userId, userId, ...whereParams, String(limit), String(offset)]
    );

    const pageIds = idRows.map((row) => Number(row.id)).filter((id) => Number.isFinite(id));
    if (pageIds.length === 0) return sendJsonWithEtag(req, res, []);

    const idPlaceholders = pageIds.map(() => '?').join(',');
    const [rows] = await pool.execute(
      `SELECT p.id,
              p.user_id AS owner_user_id,
              u.username AS owner_username,
              p.name,
              p.label,
              p.command,
              p.description,
              p.is_global,
              p.sort_order,
              p.folder_id,
              p.is_favorite,
              p.status,
              p.visibility,
              p.metadata,
              CASE WHEN p.user_id = ? THEN pw.workspace_id ELSE NULL END AS workspace_id,
              t.id AS tag_id,
              t.name AS tag_name,
              ps.permission AS share_permission,
              CASE
                WHEN p.user_id = ? THEN 'owned'
                WHEN ps.shared_with_user_id IS NOT NULL THEN 'shared'
                ELSE 'public'
              END AS access
       FROM prompts p
       INNER JOIN users u ON u.id = p.user_id
       LEFT JOIN prompt_workspaces pw ON pw.prompt_id = p.id AND p.user_id = ?
       LEFT JOIN prompt_tags pt ON pt.prompt_id = p.id
       LEFT JOIN tags t ON t.id = pt.tag_id
       LEFT JOIN prompt_shares ps ON ps.prompt_id = p.id AND ps.shared_with_user_id = ?
       WHERE p.id IN (${idPlaceholders})
       ORDER BY p.sort_order, p.name`,
      [userId, userId, userId, userId, ...pageIds]
    );

    const hydrated = hydratePromptRows(rows);
    const idToIndex = new Map(pageIds.map((id, index) => [id, index]));
    hydrated.sort((a, b) => (idToIndex.get(a.id) ?? 0) - (idToIndex.get(b.id) ?? 0));
    return sendJsonWithEtag(req, res, hydrated);
  } catch (error) {
    console.error('Get prompts error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/prompts/:id', authenticateToken, requirePasswordChangeCleared, async (req, res) => {
  try {
    const userId = req.user.userId;
    const promptId = parseInt(req.params.id, 10);
    if (!Number.isFinite(promptId)) return res.status(400).json({ error: 'Invalid prompt id' });

    const [rows] = await pool.execute(
      `SELECT p.id,
              p.user_id AS owner_user_id,
              u.username AS owner_username,
              p.name,
              p.label,
              p.command,
              p.description,
              p.is_global,
              p.sort_order,
              p.folder_id,
              p.is_favorite,
              p.status,
              p.visibility,
              p.metadata,
              CASE WHEN p.user_id = ? THEN pw.workspace_id ELSE NULL END AS workspace_id,
              t.id AS tag_id,
              t.name AS tag_name,
              ps.permission AS share_permission,
              CASE
                WHEN p.user_id = ? THEN 'owned'
                WHEN ps.shared_with_user_id IS NOT NULL THEN 'shared'
                ELSE 'public'
              END AS access
       FROM prompts p
       INNER JOIN users u ON u.id = p.user_id
       LEFT JOIN prompt_workspaces pw ON pw.prompt_id = p.id AND p.user_id = ?
       LEFT JOIN prompt_tags pt ON pt.prompt_id = p.id
       LEFT JOIN tags t ON t.id = pt.tag_id
       LEFT JOIN prompt_shares ps ON ps.prompt_id = p.id AND ps.shared_with_user_id = ?
       WHERE p.id = ?
          AND (
            p.user_id = ?
            OR (p.visibility = 'public' AND p.status = 'published')
            OR (ps.shared_with_user_id IS NOT NULL AND p.status = 'published')
          )`,
      [userId, userId, userId, userId, promptId, userId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Prompt not found' });

    const hydrated = hydratePromptRows(rows);
    return sendJsonWithEtag(req, res, hydrated[0]);
  } catch (error) {
    console.error('Get prompt error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Create prompt
app.post('/api/prompts', authenticateToken, requirePasswordChangeCleared, requireWriteAccess, async (req, res) => {
  try {
    return await runIdempotentCreate(req, res, 'prompts:create', async () => {
      const name = normalizeName(req.body?.name, 50);
      const label = normalizeName(req.body?.label, 100);
      const command = String(req.body?.command || '').trim();
      const description = req.body?.description !== undefined ? String(req.body.description).trim() : null;
      const folderId = parseOptionalInt(req.body?.folder_id);
      const isFavorite = Boolean(req.body?.is_favorite);
      const status = normalizeEnum(req.body?.status, ['draft', 'published'], 'published');
      let visibility = normalizeEnum(req.body?.visibility, ['private', 'shared', 'public'], 'private');
      const metadata = toJson(req.body?.metadata);
      const tagNames = Array.isArray(req.body?.tags) ? req.body.tags : [];
      const tagIdsRaw = Array.isArray(req.body?.tag_ids) ? req.body.tag_ids : [];
      const tagIdsInput = tagIdsRaw.map((value) => parseInt(value, 10)).filter((value) => Number.isFinite(value));

      const workspaceIdsRaw = Array.isArray(req.body?.workspace_ids) ? req.body.workspace_ids : [];
      const workspaceIds = workspaceIdsRaw
        .map((value) => parseInt(value, 10))
        .filter((value) => Number.isFinite(value));

      if (!name || !label || !command) {
        return { status: 400, body: { error: 'Name, label, and command required' } };
      }

      if (metadata !== null && metadata !== undefined && typeof metadata !== 'object') {
        return { status: 400, body: { error: 'metadata must be an object' } };
      }

      if (status !== 'published') {
        visibility = 'private';
      }

      await ensureUserHasWorkspace(req.user.userId);

      const isGlobal = workspaceIds.length === 0;

      if (!isGlobal) {
        const [wsRows] = await pool.execute(
          `SELECT id FROM workspaces
           WHERE user_id = ? AND id IN (${workspaceIds.map(() => '?').join(',')})`,
          [req.user.userId, ...workspaceIds]
        );
        if (wsRows.length !== workspaceIds.length) {
          return { status: 400, body: { error: 'One or more workspaces not found' } };
        }
      }

      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();

        if (folderId !== null) {
          const [folders] = await conn.execute('SELECT id FROM prompt_folders WHERE id = ? AND user_id = ?', [
            folderId,
            req.user.userId
          ]);
          if (folders.length === 0) {
            await conn.rollback();
            return { status: 400, body: { error: 'Folder not found' } };
          }
        }

        let sortOrder = parseOptionalInt(req.body?.sort_order);
        if (sortOrder === null) {
          const [sortRows] = await conn.execute(
            'SELECT COALESCE(MAX(sort_order), 0) AS max_sort FROM prompts WHERE user_id = ?',
            [req.user.userId]
          );
          sortOrder = Number(sortRows[0]?.max_sort ?? 0) + 1;
        }

        const [result] = await conn.execute(
          `INSERT INTO prompts
            (user_id, name, label, command, description, is_global, sort_order, folder_id, is_favorite, status, visibility, metadata)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            req.user.userId,
            name,
            label,
            command,
            description || null,
            isGlobal,
            sortOrder,
            folderId,
            isFavorite,
            status,
            visibility,
            metadata ? JSON.stringify(metadata) : null
          ]
        );

        const promptId = result.insertId;

        if (!isGlobal && workspaceIds.length > 0) {
          await insertPromptWorkspaces(conn, promptId, workspaceIds);
        }

        let tagIds = [];
        if (tagIdsInput.length > 0) {
          const [tagRows] = await conn.execute(
            `SELECT id FROM tags WHERE user_id = ? AND id IN (${tagIdsInput.map(() => '?').join(',')})`,
            [req.user.userId, ...tagIdsInput]
          );
          if (tagRows.length !== tagIdsInput.length) {
            await conn.rollback();
            return { status: 400, body: { error: 'One or more tags not found' } };
          }
          tagIds = tagIdsInput;
        } else if (tagNames.length > 0) {
          tagIds = await getOrCreateTags(conn, req.user.userId, tagNames);
        }
        if (tagIds.length > 0) {
          await replacePromptTags(conn, promptId, tagIds);
        }

        await insertPromptVersion(conn, {
          promptId,
          userId: req.user.userId,
          label,
          command,
          description,
          status,
          visibility,
          metadata
        });

        await audit(conn, {
          userId: req.user.userId,
          action: 'prompt_create',
          details: { promptId, label, status, visibility },
          ip: req.ip
        });

        await conn.commit();

        return {
          status: 201,
          body: {
            id: promptId,
            name,
            label,
            command,
            description,
            is_global: isGlobal,
            workspace_ids: isGlobal ? [] : Array.from(new Set(workspaceIds)).sort((a, b) => a - b),
            sort_order: sortOrder,
            folder_id: folderId,
            is_favorite: isFavorite,
            status,
            visibility,
            metadata
          }
        };
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }
    });
  } catch (error) {
    console.error('Create prompt error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update prompt
app.put('/api/prompts/:id', authenticateToken, requirePasswordChangeCleared, requireWriteAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const hasField = (key) => Object.prototype.hasOwnProperty.call(req.body ?? {}, key);

    const [existing] = await pool.execute(
      'SELECT id, user_id, name, label, command, description, sort_order, is_global, folder_id, is_favorite, status, visibility, metadata FROM prompts WHERE id = ?',
      [id]
    );

    if (existing.length === 0) {
      return res.status(404).json({ error: 'Prompt not found' });
    }

    const prompt = existing[0];
    if (prompt.user_id !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to edit this prompt' });
    }

    const currentMetadata = toJson(prompt.metadata);

    const name = hasField('name') ? normalizeName(req.body?.name, 50) : prompt.name;
    const label = hasField('label') ? normalizeName(req.body?.label, 100) : prompt.label;
    const command = hasField('command') ? String(req.body?.command || '').trim() : prompt.command;
    const description = hasField('description')
      ? req.body?.description !== null && req.body?.description !== undefined
        ? String(req.body.description).trim()
        : null
      : prompt.description;
    const sortOrder = hasField('sort_order')
      ? (parseOptionalInt(req.body?.sort_order) ?? 0)
      : Number(prompt.sort_order ?? 0);
    const isFavorite = hasField('is_favorite') ? Boolean(req.body?.is_favorite) : Boolean(prompt.is_favorite);
    const folderId = hasField('folder_id') ? parseOptionalInt(req.body?.folder_id) : (prompt.folder_id ?? null);
    const status = hasField('status')
      ? normalizeEnum(req.body?.status, ['draft', 'published'], prompt.status)
      : prompt.status;
    let visibility = hasField('visibility')
      ? normalizeEnum(req.body?.visibility, ['private', 'shared', 'public'], prompt.visibility)
      : prompt.visibility;
    const metadata = hasField('metadata') ? toJson(req.body?.metadata) : currentMetadata;

    const hasTagIds = hasField('tag_ids');
    const hasTags = hasField('tags');
    const tagNames = Array.isArray(req.body?.tags) ? req.body.tags : [];
    const tagIdsRaw = Array.isArray(req.body?.tag_ids) ? req.body.tag_ids : [];
    const tagIdsInput = tagIdsRaw.map((value) => parseInt(value, 10)).filter((value) => Number.isFinite(value));

    const hasWorkspaceIds = hasField('workspace_ids');
    const workspaceIdsRaw = Array.isArray(req.body?.workspace_ids) ? req.body.workspace_ids : [];
    const workspaceIds = workspaceIdsRaw.map((value) => parseInt(value, 10)).filter((value) => Number.isFinite(value));
    const isGlobal = hasWorkspaceIds ? workspaceIds.length === 0 : Boolean(prompt.is_global);

    if (!name || !label || !command) {
      return res.status(400).json({ error: 'Name, label, and command cannot be empty' });
    }

    if (metadata !== null && metadata !== undefined && typeof metadata !== 'object') {
      return res.status(400).json({ error: 'metadata must be an object' });
    }

    if (status !== 'published') {
      visibility = 'private';
    }

    await ensureUserHasWorkspace(req.user.userId);

    if (hasWorkspaceIds && !isGlobal) {
      const [wsRows] = await pool.execute(
        `SELECT id FROM workspaces
         WHERE user_id = ? AND id IN (${workspaceIds.map(() => '?').join(',')})`,
        [req.user.userId, ...workspaceIds]
      );
      if (wsRows.length !== workspaceIds.length) {
        return res.status(400).json({ error: 'One or more workspaces not found' });
      }
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      if (folderId !== null) {
        const [folders] = await conn.execute('SELECT id FROM prompt_folders WHERE id = ? AND user_id = ?', [
          folderId,
          req.user.userId
        ]);
        if (folders.length === 0) {
          await conn.rollback();
          return res.status(400).json({ error: 'Folder not found' });
        }
      }

      await conn.execute(
        `UPDATE prompts SET name = ?, label = ?, command = ?, description = ?, sort_order = ?, is_global = ?,
                            folder_id = ?, is_favorite = ?, status = ?, visibility = ?, metadata = ?
         WHERE id = ? AND user_id = ?`,
        [
          name,
          label,
          command,
          description || null,
          sortOrder,
          isGlobal,
          folderId,
          isFavorite,
          status,
          visibility,
          metadata ? JSON.stringify(metadata) : null,
          id,
          req.user.userId
        ]
      );

      if (hasWorkspaceIds) {
        await replacePromptWorkspaces(conn, id, isGlobal ? [] : workspaceIds);
      }

      let tagIds = [];
      if (tagIdsInput.length > 0 || hasTagIds) {
        if (tagIdsInput.length > 0) {
          const [tagRows] = await conn.execute(
            `SELECT id FROM tags WHERE user_id = ? AND id IN (${tagIdsInput.map(() => '?').join(',')})`,
            [req.user.userId, ...tagIdsInput]
          );
          if (tagRows.length !== tagIdsInput.length) {
            await conn.rollback();
            return res.status(400).json({ error: 'One or more tags not found' });
          }
          tagIds = tagIdsInput;
        } else {
          tagIds = [];
        }
      } else if (tagNames.length > 0 || hasTags) {
        if (tagNames.length > 0) {
          tagIds = await getOrCreateTags(conn, req.user.userId, tagNames);
        } else {
          tagIds = [];
        }
      }

      if (hasTagIds || hasTags) {
        await replacePromptTags(conn, id, tagIds);
      }

      await insertPromptVersion(conn, {
        promptId: id,
        userId: req.user.userId,
        label,
        command,
        description,
        status,
        visibility,
        metadata
      });

      await audit(conn, {
        userId: req.user.userId,
        action: 'prompt_update',
        details: { promptId: id, label, status, visibility },
        ip: req.ip
      });

      await conn.commit();
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }

    res.json({
      success: true,
      is_global: isGlobal,
      workspace_ids: hasWorkspaceIds
        ? isGlobal
          ? []
          : Array.from(new Set(workspaceIds)).sort((a, b) => a - b)
        : undefined
    });
  } catch (error) {
    console.error('Update prompt error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete prompt
app.delete(
  '/api/prompts/:id',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      const { id } = req.params;

      const [existing] = await pool.execute('SELECT user_id, label FROM prompts WHERE id = ?', [id]);

      if (existing.length === 0) {
        return res.status(404).json({ error: 'Prompt not found' });
      }

      const prompt = existing[0];
      if (prompt.user_id !== req.user.userId) {
        return res.status(403).json({ error: 'Not authorized to delete this prompt' });
      }

      await pool.execute('DELETE FROM prompts WHERE id = ? AND user_id = ?', [id, req.user.userId]);
      await audit(pool, {
        userId: req.user.userId,
        action: 'prompt_delete',
        details: { promptId: id, label: prompt.label },
        ip: req.ip
      });
      res.json({ success: true });
    } catch (error) {
      console.error('Delete prompt error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Prompt versions
app.get('/api/prompts/:id/versions', authenticateToken, requirePasswordChangeCleared, async (req, res) => {
  try {
    const promptId = parseInt(req.params.id, 10);
    if (!Number.isFinite(promptId)) return res.status(400).json({ error: 'Invalid prompt id' });

    const [owned] = await pool.execute('SELECT user_id FROM prompts WHERE id = ?', [promptId]);
    if (owned.length === 0) return res.status(404).json({ error: 'Prompt not found' });
    if (owned[0].user_id !== req.user.userId) return res.status(403).json({ error: 'Not authorized' });

    const limitRaw = parseInt(String(req.query?.limit ?? '50'), 10);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(200, limitRaw)) : 50;
    const offsetRaw = parseInt(String(req.query?.offset ?? '0'), 10);
    const offset = Number.isFinite(offsetRaw) ? Math.max(0, offsetRaw) : 0;

    const [rows] = await pool.execute(
      `SELECT pv.id, pv.version_num, pv.created_at,
              u.username AS created_by_username,
              pv.label, pv.command, pv.description, pv.status, pv.visibility, pv.metadata
       FROM prompt_versions pv
       INNER JOIN users u ON u.id = pv.created_by
       WHERE pv.prompt_id = ?
       ORDER BY pv.version_num DESC
       LIMIT ? OFFSET ?`,
      [promptId, String(limit), String(offset)]
    );

    const out = rows.map((row) => {
      let metadata = row.metadata;
      if (typeof metadata === 'string') {
        try {
          metadata = JSON.parse(metadata);
        } catch {
          metadata = null;
        }
      }
      return { ...row, metadata };
    });
    res.json(out);
  } catch (error) {
    console.error('Get prompt versions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post(
  '/api/prompts/:id/rollback',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      const promptId = parseInt(req.params.id, 10);
      if (!Number.isFinite(promptId)) return res.status(400).json({ error: 'Invalid prompt id' });
      const versionNum = parseOptionalInt(req.body?.version_num);
      const versionId = parseOptionalInt(req.body?.version_id);
      if (versionNum === null && versionId === null) {
        return res.status(400).json({ error: 'version_num or version_id is required' });
      }

      const [owned] = await pool.execute('SELECT user_id, label FROM prompts WHERE id = ?', [promptId]);
      if (owned.length === 0) return res.status(404).json({ error: 'Prompt not found' });
      if (owned[0].user_id !== req.user.userId) return res.status(403).json({ error: 'Not authorized' });

      const [versions] = await pool.execute(
        `SELECT id, version_num, label, command, description, status, visibility, metadata
       FROM prompt_versions
       WHERE prompt_id = ?
         AND (${versionId !== null ? 'id = ?' : 'version_num = ?'})
       LIMIT 1`,
        versionId !== null ? [promptId, versionId] : [promptId, versionNum]
      );
      if (versions.length === 0) return res.status(404).json({ error: 'Version not found' });

      const v = versions[0];
      const metadata = toJson(v.metadata);

      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();

        await conn.execute(
          `UPDATE prompts
         SET label = ?, command = ?, description = ?, status = ?, visibility = ?, metadata = ?
         WHERE id = ? AND user_id = ?`,
          [
            v.label,
            v.command,
            v.description || null,
            v.status,
            v.visibility,
            metadata ? JSON.stringify(metadata) : null,
            promptId,
            req.user.userId
          ]
        );

        const newVersionNum = await insertPromptVersion(conn, {
          promptId,
          userId: req.user.userId,
          label: v.label,
          command: v.command,
          description: v.description,
          status: v.status,
          visibility: v.visibility,
          metadata
        });

        await audit(conn, {
          userId: req.user.userId,
          action: 'prompt_rollback',
          details: { promptId, fromVersion: v.version_num, toVersion: newVersionNum },
          ip: req.ip
        });

        await conn.commit();
        res.json({ success: true, version_num: newVersionNum });
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }
    } catch (error) {
      console.error('Rollback prompt error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Prompt sharing
app.get('/api/prompts/:id/shares', authenticateToken, requirePasswordChangeCleared, async (req, res) => {
  try {
    const promptId = parseInt(req.params.id, 10);
    if (!Number.isFinite(promptId)) return res.status(400).json({ error: 'Invalid prompt id' });

    const [owned] = await pool.execute('SELECT user_id FROM prompts WHERE id = ?', [promptId]);
    if (owned.length === 0) return res.status(404).json({ error: 'Prompt not found' });
    if (owned[0].user_id !== req.user.userId) return res.status(403).json({ error: 'Not authorized' });

    const [rows] = await pool.execute(
      `SELECT ps.shared_with_user_id AS user_id,
              u.username,
              ps.permission,
              ps.created_at,
              ps.updated_at
       FROM prompt_shares ps
       INNER JOIN users u ON u.id = ps.shared_with_user_id
       WHERE ps.prompt_id = ?
       ORDER BY u.username`,
      [promptId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Get prompt shares error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post(
  '/api/prompts/:id/shares',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      const promptId = parseInt(req.params.id, 10);
      if (!Number.isFinite(promptId)) return res.status(400).json({ error: 'Invalid prompt id' });
      const username = normalizeName(req.body?.username, 50);
      const permission = normalizeEnum(req.body?.permission, ['view', 'copy'], 'view');
      if (!username) return res.status(400).json({ error: 'username is required' });

      const [owned] = await pool.execute('SELECT user_id, status, visibility FROM prompts WHERE id = ?', [promptId]);
      if (owned.length === 0) return res.status(404).json({ error: 'Prompt not found' });
      if (owned[0].user_id !== req.user.userId) return res.status(403).json({ error: 'Not authorized' });

      const [users] = await pool.execute('SELECT id FROM users WHERE username = ? LIMIT 1', [username]);
      if (users.length === 0) return res.status(404).json({ error: 'User not found' });
      const targetUserId = users[0].id;
      if (targetUserId === req.user.userId) return res.status(400).json({ error: 'Cannot share to yourself' });

      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        await conn.execute(
          `INSERT INTO prompt_shares (prompt_id, shared_with_user_id, permission)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE permission = VALUES(permission)`,
          [promptId, targetUserId, permission]
        );

        // If sharing a published prompt and it was private, flip it to "shared" automatically.
        if (owned[0].status === 'published' && owned[0].visibility === 'private') {
          await conn.execute('UPDATE prompts SET visibility = ? WHERE id = ? AND user_id = ?', [
            'shared',
            promptId,
            req.user.userId
          ]);
        }

        await audit(conn, {
          userId: req.user.userId,
          action: 'prompt_share_add',
          details: { promptId, shared_with: username, permission },
          ip: req.ip
        });

        await conn.commit();
        res.json({ success: true });
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }
    } catch (error) {
      console.error('Add prompt share error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.delete(
  '/api/prompts/:id/shares/:userId',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      const promptId = parseInt(req.params.id, 10);
      const sharedWithUserId = parseInt(req.params.userId, 10);
      if (!Number.isFinite(promptId) || !Number.isFinite(sharedWithUserId)) {
        return res.status(400).json({ error: 'Invalid id' });
      }

      const [owned] = await pool.execute('SELECT user_id FROM prompts WHERE id = ?', [promptId]);
      if (owned.length === 0) return res.status(404).json({ error: 'Prompt not found' });
      if (owned[0].user_id !== req.user.userId) return res.status(403).json({ error: 'Not authorized' });

      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        await conn.execute('DELETE FROM prompt_shares WHERE prompt_id = ? AND shared_with_user_id = ?', [
          promptId,
          sharedWithUserId
        ]);

        const [countRows] = await conn.execute('SELECT COUNT(*) AS count FROM prompt_shares WHERE prompt_id = ?', [
          promptId
        ]);
        const shareCount = Number(countRows[0]?.count ?? 0);

        const [promptRows] = await conn.execute('SELECT visibility FROM prompts WHERE id = ? AND user_id = ?', [
          promptId,
          req.user.userId
        ]);
        const visibility = promptRows[0]?.visibility ?? 'private';
        if (shareCount === 0 && visibility === 'shared') {
          await conn.execute('UPDATE prompts SET visibility = ? WHERE id = ? AND user_id = ?', [
            'private',
            promptId,
            req.user.userId
          ]);
        }

        await audit(conn, {
          userId: req.user.userId,
          action: 'prompt_share_remove',
          details: { promptId, shared_with_user_id: sharedWithUserId },
          ip: req.ip
        });

        await conn.commit();
        res.json({ success: true });
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }
    } catch (error) {
      console.error('Remove prompt share error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Copy shared/public prompt into your own library
app.post(
  '/api/prompts/:id/copy',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      return await runIdempotentCreate(req, res, 'prompts:copy', async () => {
        const promptId = parseInt(req.params.id, 10);
        if (!Number.isFinite(promptId)) return { status: 400, body: { error: 'Invalid prompt id' } };

        const [rows] = await pool.execute(
          `SELECT p.id,
                p.user_id AS owner_user_id,
                u.username AS owner_username,
                p.name, p.label, p.command, p.description, p.metadata, p.status, p.visibility,
                ps.permission AS share_permission
         FROM prompts p
         INNER JOIN users u ON u.id = p.user_id
         LEFT JOIN prompt_shares ps ON ps.prompt_id = p.id AND ps.shared_with_user_id = ?
         WHERE p.id = ?
           AND (
             p.user_id = ?
             OR (p.visibility = 'public' AND p.status = 'published')
             OR (ps.shared_with_user_id IS NOT NULL AND p.status = 'published')
           )
         LIMIT 1`,
          [req.user.userId, promptId, req.user.userId]
        );
        if (rows.length === 0) return { status: 404, body: { error: 'Prompt not found' } };
        const source = rows[0];
        if (source.owner_user_id === req.user.userId) {
          return { status: 400, body: { error: 'Cannot copy your own prompt' } };
        }

        const canCopy = source.visibility === 'public' || source.share_permission === 'copy';
        if (!canCopy) return { status: 403, body: { error: 'Copy not permitted' } };

        const sourceMetadata = toJson(source.metadata);

        const conn = await pool.getConnection();
        try {
          await conn.beginTransaction();

          const [sortRows] = await conn.execute(
            'SELECT COALESCE(MAX(sort_order), 0) AS max_sort FROM prompts WHERE user_id = ?',
            [req.user.userId]
          );
          const sortOrder = Number(sortRows[0]?.max_sort ?? 0) + 1;

          const baseLabel = normalizeName(source.label, 92) || 'Prompt';
          const label = `${baseLabel} (Copy)`.slice(0, 100);
          const name =
            normalizeName(source.name || baseLabel.toLowerCase().replace(/\s+/g, '-'), 50) || `prompt-${Date.now()}`;

          const [result] = await conn.execute(
            `INSERT INTO prompts
            (user_id, name, label, command, description, is_global, sort_order, folder_id, is_favorite, status, visibility, metadata, source_prompt_id)
           VALUES (?, ?, ?, ?, ?, TRUE, ?, NULL, FALSE, 'published', 'private', ?, ?)`,
            [
              req.user.userId,
              name,
              label,
              source.command,
              source.description || null,
              sortOrder,
              sourceMetadata ? JSON.stringify(sourceMetadata) : null,
              source.id
            ]
          );
          const newPromptId = result.insertId;

          const [tagRows] = await conn.execute(
            `SELECT t.name
           FROM prompt_tags pt
           INNER JOIN tags t ON t.id = pt.tag_id
           WHERE pt.prompt_id = ?`,
            [source.id]
          );
          const tagNames = tagRows.map((row) => row.name);
          const newTagIds = await getOrCreateTags(conn, req.user.userId, tagNames);
          if (newTagIds.length > 0) {
            await replacePromptTags(conn, newPromptId, newTagIds);
          }

          await insertPromptVersion(conn, {
            promptId: newPromptId,
            userId: req.user.userId,
            label,
            command: source.command,
            description: source.description,
            status: 'published',
            visibility: 'private',
            metadata: sourceMetadata
          });

          await audit(conn, {
            userId: req.user.userId,
            action: 'prompt_copy',
            details: { fromPromptId: source.id, fromOwner: source.owner_username, newPromptId },
            ip: req.ip
          });

          await conn.commit();
          return { status: 201, body: { id: newPromptId } };
        } catch (err) {
          await conn.rollback();
          throw err;
        } finally {
          conn.release();
        }
      });
    } catch (error) {
      console.error('Copy prompt error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Prompt import/export (owned prompts)
app.get('/api/prompts/export', authenticateToken, requirePasswordChangeCleared, async (req, res) => {
  try {
    const format = normalizeEnum(req.query?.format, ['json', 'yaml'], 'json');

    const [rows] = await pool.execute(
      `SELECT p.id, p.name, p.label, p.command, p.description, p.is_global, p.sort_order,
              p.folder_id, f.name AS folder_name,
              p.is_favorite, p.status, p.visibility, p.metadata,
              w.name AS workspace_name,
              t.name AS tag_name
       FROM prompts p
       LEFT JOIN prompt_folders f ON f.id = p.folder_id
       LEFT JOIN prompt_workspaces pw ON pw.prompt_id = p.id
       LEFT JOIN workspaces w ON w.id = pw.workspace_id
       LEFT JOIN prompt_tags pt ON pt.prompt_id = p.id
       LEFT JOIN tags t ON t.id = pt.tag_id
       WHERE p.user_id = ?
       ORDER BY p.sort_order, p.name`,
      [req.user.userId]
    );

    const byId = new Map();
    for (const row of rows) {
      if (!byId.has(row.id)) {
        byId.set(row.id, {
          name: row.name,
          label: row.label,
          command: row.command,
          description: row.description,
          is_global: Boolean(row.is_global),
          sort_order: Number(row.sort_order ?? 0),
          folder: row.folder_name ?? null,
          is_favorite: Boolean(row.is_favorite),
          status: row.status,
          visibility: row.visibility,
          metadata: toJson(row.metadata),
          workspaces: [],
          tags: []
        });
      }
      if (row.workspace_name) byId.get(row.id).workspaces.push(String(row.workspace_name));
      if (row.tag_name) byId.get(row.id).tags.push(String(row.tag_name));
    }

    const prompts = Array.from(byId.values()).map((p) => ({
      ...p,
      workspaces: p.is_global ? [] : Array.from(new Set(p.workspaces)).sort((a, b) => a.localeCompare(b)),
      tags: Array.from(new Set(p.tags)).sort((a, b) => a.localeCompare(b))
    }));

    const payload = {
      schema: 'Tailshell.prompts.export',
      version: 1,
      exported_at: new Date().toISOString(),
      prompts
    };

    const baseName = `tailshell-prompts-${new Date().toISOString().slice(0, 10)}`;
    if (format === 'yaml') {
      const text = yaml.dump(payload, { lineWidth: 120, noRefs: true });
      res.set('Content-Type', 'text/yaml; charset=utf-8');
      res.set('Content-Disposition', `attachment; filename="${baseName}.yml"`);
      return res.send(text);
    }

    const text = JSON.stringify(payload, null, 2);
    res.set('Content-Type', 'application/json; charset=utf-8');
    res.set('Content-Disposition', `attachment; filename="${baseName}.json"`);
    return res.send(text);
  } catch (error) {
    console.error('Export prompts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post(
  '/api/prompts/import',
  authenticateToken,
  requirePasswordChangeCleared,
  requireWriteAccess,
  async (req, res) => {
    try {
      return await runIdempotentCreate(req, res, 'prompts:import', async () => {
        const format = normalizeEnum(req.body?.format, ['json', 'yaml'], 'json');
        const data = req.body?.data ?? null;
        if (data === null || data === undefined) return { status: 400, body: { error: 'data is required' } };

        let parsed = null;
        if (format === 'yaml') {
          parsed = yaml.load(String(data));
        } else if (typeof data === 'string') {
          parsed = JSON.parse(data);
        } else {
          parsed = data;
        }

        const prompts = Array.isArray(parsed?.prompts) ? parsed.prompts : [];
        if (prompts.length === 0) return { status: 400, body: { error: 'No prompts found in import' } };

        await ensureUserHasWorkspace(req.user.userId);

        const conn = await pool.getConnection();
        let created = 0;
        try {
          await conn.beginTransaction();
          const normalizedPrompts = [];
          const folderNamesByKey = new Map();
          const tagNamesByKey = new Map();

          for (const p of prompts) {
            const label = normalizeName(p?.label, 100);
            const name = normalizeName(p?.name, 50) || (label ? label.toLowerCase().replace(/\s+/g, '-') : '');
            const command = String(p?.command || '').trim();
            const description =
              p?.description !== undefined && p?.description !== null ? String(p.description).trim() : null;
            const isGlobal = Boolean(p?.is_global ?? true);
            const isFavorite = Boolean(p?.is_favorite ?? false);
            const status = normalizeEnum(p?.status, ['draft', 'published'], 'published');
            let visibility = normalizeEnum(p?.visibility, ['private', 'shared', 'public'], 'private');
            const metadata = toJson(p?.metadata);
            if (!label || !name || !command) continue;
            if (metadata !== null && metadata !== undefined && typeof metadata !== 'object') continue;
            if (status !== 'published') visibility = 'private';

            const folderName = normalizeName(p?.folder, 80);
            const folderKey = folderName ? folderName.toLowerCase() : null;
            if (folderName && folderKey) folderNamesByKey.set(folderKey, folderName);

            const sortOrderValue = Number.isFinite(Number(p?.sort_order))
              ? Math.max(0, Math.floor(Number(p.sort_order)))
              : null;

            const promptTagNames = Array.isArray(p?.tags) ? p.tags : [];
            const tagKeys = [];
            for (const raw of promptTagNames) {
              const tagName = normalizeName(raw, 50);
              if (!tagName) continue;
              const key = tagName.toLowerCase();
              tagNamesByKey.set(key, tagName);
              tagKeys.push(key);
            }

            const workspaceNames = Array.isArray(p?.workspaces) ? p.workspaces : [];
            const workspaceKeys = workspaceNames
              .map((w) => normalizeName(w, 64))
              .filter(Boolean)
              .map((w) => w.toLowerCase());

            normalizedPrompts.push({
              label,
              name,
              command,
              description,
              isGlobal,
              isFavorite,
              status,
              visibility,
              metadata,
              folderKey,
              tagKeys,
              workspaceKeys,
              sortOrder: sortOrderValue
            });
          }

          const [workspaces] = await conn.execute('SELECT id, name FROM workspaces WHERE user_id = ?', [
            req.user.userId
          ]);
          const workspaceByName = new Map(workspaces.map((w) => [String(w.name).toLowerCase(), w.id]));

          const folderByName = await getOrCreatePromptFolders(
            conn,
            req.user.userId,
            Array.from(folderNamesByKey.values())
          );

          let tagByName = new Map();
          const importTagNames = Array.from(tagNamesByKey.values());
          if (importTagNames.length > 0) {
            await getOrCreateTags(conn, req.user.userId, importTagNames);

            const placeholders = importTagNames.map(() => '?').join(',');
            const [tagRows] = await conn.execute(
              `SELECT id, name FROM tags WHERE user_id = ? AND name IN (${placeholders})`,
              [req.user.userId, ...importTagNames]
            );
            tagByName = new Map(tagRows.map((t) => [String(t.name).toLowerCase(), Number(t.id)]));
          }

          const [sortRows] = await conn.execute(
            'SELECT COALESCE(MAX(sort_order), 0) AS max_sort FROM prompts WHERE user_id = ?',
            [req.user.userId]
          );
          let nextSort = Number(sortRows[0]?.max_sort ?? 0) + 1;

          for (const p of normalizedPrompts) {
            const folderId = p.folderKey ? (folderByName.get(p.folderKey) ?? null) : null;
            const sortOrder = typeof p.sortOrder === 'number' ? p.sortOrder : nextSort++;

            const [insert] = await conn.execute(
              `INSERT INTO prompts
              (user_id, name, label, command, description, is_global, sort_order, folder_id, is_favorite, status, visibility, metadata)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              [
                req.user.userId,
                p.name,
                p.label,
                p.command,
                p.description || null,
                p.isGlobal,
                sortOrder,
                folderId,
                p.isFavorite,
                p.status,
                p.visibility,
                p.metadata ? JSON.stringify(p.metadata) : null
              ]
            );
            const newPromptId = insert.insertId;

            if (p.tagKeys.length > 0) {
              const tagIds = Array.from(new Set(p.tagKeys.map((key) => tagByName.get(key)).filter(Number.isFinite)));
              if (tagIds.length > 0) await replacePromptTags(conn, newPromptId, tagIds);
            }

            if (!p.isGlobal && p.workspaceKeys.length > 0) {
              const ids = p.workspaceKeys.map((w) => workspaceByName.get(w)).filter(Number.isFinite);
              if (ids.length > 0) {
                await insertPromptWorkspaces(conn, newPromptId, ids);
              } else {
                await conn.execute('UPDATE prompts SET is_global = TRUE WHERE id = ? AND user_id = ?', [
                  newPromptId,
                  req.user.userId
                ]);
              }
            }

            await insertPromptVersion(conn, {
              promptId: newPromptId,
              userId: req.user.userId,
              label: p.label,
              command: p.command,
              description: p.description,
              status: p.status,
              visibility: p.visibility,
              metadata: p.metadata
            });
            created += 1;
          }

          await audit(conn, { userId: req.user.userId, action: 'prompt_import', details: { created }, ip: req.ip });
          await conn.commit();
          invalidateMetadataCacheUser(req.user.userId);
        } catch (err) {
          await conn.rollback();
          throw err;
        } finally {
          conn.release();
        }

        return { status: 200, body: { success: true, created } };
      });
    } catch (error) {
      console.error('Import prompts error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Bulk prompt operations (owned prompts only)
app.post('/api/prompts/bulk', authenticateToken, requirePasswordChangeCleared, requireWriteAccess, async (req, res) => {
  try {
    const action = String(req.body?.action || '')
      .trim()
      .toLowerCase();
    const ids = Array.isArray(req.body?.prompt_ids)
      ? req.body.prompt_ids.map((id) => parseInt(id, 10)).filter(Number.isFinite)
      : [];
    const promptIds = Array.from(new Set(ids));
    if (!action) return res.status(400).json({ error: 'action is required' });
    if (promptIds.length === 0) return res.status(400).json({ error: 'prompt_ids is required' });

    const [rows] = await pool.execute(
      `SELECT id FROM prompts WHERE user_id = ? AND id IN (${promptIds.map(() => '?').join(',')})`,
      [req.user.userId, ...promptIds]
    );
    if (rows.length !== promptIds.length) return res.status(400).json({ error: 'One or more prompts not found' });

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      if (action === 'delete') {
        await conn.execute(`DELETE FROM prompts WHERE user_id = ? AND id IN (${promptIds.map(() => '?').join(',')})`, [
          req.user.userId,
          ...promptIds
        ]);
        await audit(conn, {
          userId: req.user.userId,
          action: 'prompt_bulk_delete',
          details: { promptIds },
          ip: req.ip
        });
        await conn.commit();
        return res.json({ success: true });
      }

      if (action === 'set_folder') {
        const folderId = parseOptionalInt(req.body?.folder_id);
        if (folderId !== null) {
          const [folders] = await conn.execute('SELECT id FROM prompt_folders WHERE id = ? AND user_id = ?', [
            folderId,
            req.user.userId
          ]);
          if (folders.length === 0) return res.status(400).json({ error: 'Folder not found' });
        }
        await conn.execute(
          `UPDATE prompts SET folder_id = ? WHERE user_id = ? AND id IN (${promptIds.map(() => '?').join(',')})`,
          [folderId, req.user.userId, ...promptIds]
        );
        await audit(conn, {
          userId: req.user.userId,
          action: 'prompt_bulk_set_folder',
          details: { promptIds, folderId },
          ip: req.ip
        });
        await conn.commit();
        return res.json({ success: true });
      }

      if (action === 'set_favorite') {
        const value = Boolean(req.body?.is_favorite);
        await conn.execute(
          `UPDATE prompts SET is_favorite = ? WHERE user_id = ? AND id IN (${promptIds.map(() => '?').join(',')})`,
          [value, req.user.userId, ...promptIds]
        );
        await audit(conn, {
          userId: req.user.userId,
          action: 'prompt_bulk_set_favorite',
          details: { promptIds, is_favorite: value },
          ip: req.ip
        });
        await conn.commit();
        return res.json({ success: true });
      }

      if (action === 'set_status') {
        const status = normalizeEnum(req.body?.status, ['draft', 'published'], null);
        if (!status) return res.status(400).json({ error: 'status must be draft|published' });
        if (status !== 'published') {
          await conn.execute(
            `UPDATE prompts SET status = ?, visibility = 'private' WHERE user_id = ? AND id IN (${promptIds.map(() => '?').join(',')})`,
            [status, req.user.userId, ...promptIds]
          );
        } else {
          await conn.execute(
            `UPDATE prompts SET status = ? WHERE user_id = ? AND id IN (${promptIds.map(() => '?').join(',')})`,
            [status, req.user.userId, ...promptIds]
          );
        }
        await audit(conn, {
          userId: req.user.userId,
          action: 'prompt_bulk_set_status',
          details: { promptIds, status },
          ip: req.ip
        });
        await conn.commit();
        return res.json({ success: true });
      }

      if (action === 'set_visibility') {
        const visibility = normalizeEnum(req.body?.visibility, ['private', 'shared', 'public'], null);
        if (!visibility) return res.status(400).json({ error: 'visibility must be private|shared|public' });

        const [draftRows] = await conn.execute(
          `SELECT COUNT(*) AS count
           FROM prompts
           WHERE user_id = ? AND id IN (${promptIds.map(() => '?').join(',')}) AND status != 'published'`,
          [req.user.userId, ...promptIds]
        );
        const draftCount = Number(draftRows[0]?.count ?? 0);
        if (draftCount > 0 && visibility !== 'private') {
          return res.status(400).json({ error: 'Cannot set shared/public visibility on draft prompts' });
        }

        await conn.execute(
          `UPDATE prompts SET visibility = ? WHERE user_id = ? AND id IN (${promptIds.map(() => '?').join(',')})`,
          [visibility, req.user.userId, ...promptIds]
        );
        await audit(conn, {
          userId: req.user.userId,
          action: 'prompt_bulk_set_visibility',
          details: { promptIds, visibility },
          ip: req.ip
        });
        await conn.commit();
        return res.json({ success: true });
      }

      if (action === 'add_tags') {
        const tagNames = Array.isArray(req.body?.tags) ? req.body.tags : [];
        const tagIdsRaw = Array.isArray(req.body?.tag_ids) ? req.body.tag_ids : [];
        const tagIdsInput = tagIdsRaw.map((value) => parseInt(value, 10)).filter((value) => Number.isFinite(value));
        let tagIds = [];
        if (tagIdsInput.length > 0) {
          const [tagRows] = await conn.execute(
            `SELECT id FROM tags WHERE user_id = ? AND id IN (${tagIdsInput.map(() => '?').join(',')})`,
            [req.user.userId, ...tagIdsInput]
          );
          if (tagRows.length !== tagIdsInput.length)
            return res.status(400).json({ error: 'One or more tags not found' });
          tagIds = tagIdsInput;
        } else if (tagNames.length > 0) {
          tagIds = await getOrCreateTags(conn, req.user.userId, tagNames);
        }
        if (tagIds.length === 0) return res.status(400).json({ error: 'No tags provided' });

        const uniquePromptIds = Array.from(new Set(promptIds.map((id) => Number(id)).filter(Number.isFinite)));
        const uniqueTagIds = Array.from(new Set(tagIds.map((id) => Number(id)).filter(Number.isFinite)));
        const maxRowsPerInsert = 500;
        let tuples = [];
        let params = [];

        for (const promptId of uniquePromptIds) {
          for (const tagId of uniqueTagIds) {
            tuples.push('(?, ?)');
            params.push(promptId, tagId);
            if (tuples.length >= maxRowsPerInsert) {
              await conn.execute(
                `INSERT IGNORE INTO prompt_tags (prompt_id, tag_id) VALUES ${tuples.join(',')}`,
                params
              );
              tuples = [];
              params = [];
            }
          }
        }
        if (tuples.length > 0) {
          await conn.execute(`INSERT IGNORE INTO prompt_tags (prompt_id, tag_id) VALUES ${tuples.join(',')}`, params);
        }
        await audit(conn, {
          userId: req.user.userId,
          action: 'prompt_bulk_add_tags',
          details: { promptIds, tagIds },
          ip: req.ip
        });
        await conn.commit();
        return res.json({ success: true });
      }

      if (action === 'remove_tags') {
        const tagIdsRaw = Array.isArray(req.body?.tag_ids) ? req.body.tag_ids : [];
        const tagIds = Array.from(new Set(tagIdsRaw.map((value) => parseInt(value, 10)).filter(Number.isFinite)));
        if (tagIds.length === 0) return res.status(400).json({ error: 'tag_ids is required' });

        await conn.execute(
          `DELETE FROM prompt_tags
           WHERE prompt_id IN (${promptIds.map(() => '?').join(',')})
             AND tag_id IN (${tagIds.map(() => '?').join(',')})`,
          [...promptIds, ...tagIds]
        );
        await audit(conn, {
          userId: req.user.userId,
          action: 'prompt_bulk_remove_tags',
          details: { promptIds, tagIds },
          ip: req.ip
        });
        await conn.commit();
        return res.json({ success: true });
      }

      return res.status(400).json({ error: 'Unknown action' });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  } catch (error) {
    console.error('Bulk prompts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Activity (prompt usage / quick resume)
app.post('/api/activity/prompt', authenticateToken, requirePasswordChangeCleared, async (req, res) => {
  try {
    const promptId = parseOptionalInt(req.body?.prompt_id);
    if (promptId === null) return res.status(400).json({ error: 'prompt_id is required' });

    await audit(pool, {
      userId: req.user.userId,
      action: 'prompt_execute',
      details: { prompt_id: promptId },
      ip: req.ip
    });
    res.json({ success: true });
  } catch (error) {
    console.error('Prompt activity error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/activity/recent', authenticateToken, requirePasswordChangeCleared, async (req, res) => {
  try {
    const limitRaw = parseInt(String(req.query?.limit ?? '30'), 10);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(200, limitRaw)) : 30;
    const [rows] = await pool.execute(
      `SELECT id, type AS action, payload AS details, ip_address, created_at
       FROM events
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT ${limit}`,
      [req.user.userId]
    );
    const out = rows.map((row) => {
      let details = row.details;
      if (typeof details === 'string') {
        try {
          details = JSON.parse(details);
        } catch {
          details = null;
        }
      }
      return { ...row, details };
    });
    res.json(out);
  } catch (error) {
    console.error('Recent activity error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User management (admin only)
app.get('/api/users', authenticateToken, requirePasswordChangeCleared, requireAdmin, async (req, res) => {
  try {
    const limitRaw = parseInt(String(req.query?.limit ?? '200'), 10);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(500, limitRaw)) : 200;
    const offsetRaw = parseInt(String(req.query?.offset ?? '0'), 10);
    const offset = Number.isFinite(offsetRaw) ? Math.max(0, offsetRaw) : 0;

    const [rows] = await pool.execute(
      `SELECT id, username, role, active, must_change_password,
              failed_login_attempts, last_failed_login_at, locked_until,
              created_at, updated_at
       FROM users ORDER BY username LIMIT ? OFFSET ?`,
      [String(limit), String(offset)]
    );
    res.json(
      rows.map((row) => ({
        id: row.id,
        username: row.username,
        role: row.role,
        active: Boolean(row.active),
        must_change_password: Boolean(row.must_change_password),
        failed_login_attempts: Number(row.failed_login_attempts ?? 0),
        last_failed_login_at: row.last_failed_login_at,
        locked_until: row.locked_until,
        created_at: row.created_at,
        updated_at: row.updated_at
      }))
    );
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post(
  '/api/users',
  authenticateToken,
  requirePasswordChangeCleared,
  requireAdmin,
  requireWriteAccess,
  async (req, res) => {
    try {
      return await runIdempotentCreate(req, res, 'users:create', async () => {
        const username = normalizeName(req.body?.username, 50);
        const password = String(req.body?.password || '');
        const role = normalizeEnum(req.body?.role, ROLE_VALUES, 'user');
        const active = req.body?.active !== undefined ? Boolean(req.body.active) : true;
        const mustChangePassword =
          req.body?.must_change_password !== undefined ? Boolean(req.body.must_change_password) : false;

        if (!username || !password) {
          return { status: 400, body: { error: 'Username and password required' } };
        }

        const passwordError = validatePasswordPolicy(password);
        if (passwordError) {
          return { status: 400, body: { error: passwordError } };
        }

        const hash = await bcrypt.hash(password, PASSWORD_HASH_ROUNDS);
        const [result] = await pool.execute(
          'INSERT INTO users (username, password_hash, role, active, must_change_password) VALUES (?, ?, ?, ?, ?)',
          [username, hash, role, active, mustChangePassword]
        );

        await audit(pool, {
          userId: req.user.userId,
          action: 'user_create',
          details: { id: result.insertId, username, role },
          ip: req.ip
        });

        return {
          status: 201,
          body: { id: result.insertId, username, role, active, must_change_password: mustChangePassword }
        };
      });
    } catch (error) {
      if (error.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'Username already exists' });
      }
      console.error('Create user error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.put(
  '/api/users/:id',
  authenticateToken,
  requirePasswordChangeCleared,
  requireAdmin,
  requireWriteAccess,
  async (req, res) => {
    try {
      const userId = parseInt(req.params.id, 10);
      if (!Number.isFinite(userId)) return res.status(400).json({ error: 'Invalid user id' });

      // Prevent self-deactivation / self-demotion accidents
      if (userId === req.user.userId) {
        if (req.body?.active === false) return res.status(400).json({ error: 'Cannot deactivate your own account' });
        if (req.body?.role && String(req.body.role).trim().toLowerCase() !== 'admin') {
          return res.status(400).json({ error: 'Cannot change your own role' });
        }
      }

      const updates = {};
      if (Object.prototype.hasOwnProperty.call(req.body ?? {}, 'role')) {
        updates.role = normalizeEnum(req.body?.role, ROLE_VALUES, null);
        if (!updates.role) return res.status(400).json({ error: 'Invalid role' });
      }
      if (Object.prototype.hasOwnProperty.call(req.body ?? {}, 'active')) {
        updates.active = Boolean(req.body?.active);
      }
      if (Object.prototype.hasOwnProperty.call(req.body ?? {}, 'must_change_password')) {
        updates.must_change_password = Boolean(req.body?.must_change_password);
      }

      const keys = Object.keys(updates);
      if (keys.length === 0) return res.json({ success: true });

      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();

        const [existing] = await conn.execute('SELECT id, active FROM users WHERE id = ?', [userId]);
        if (existing.length === 0) {
          await conn.rollback();
          return res.status(404).json({ error: 'User not found' });
        }

        const setClause = keys.map((key) => `${key} = ?`).join(', ');
        const params = keys.map((key) => updates[key]);
        params.push(userId);

        await conn.execute(`UPDATE users SET ${setClause} WHERE id = ?`, params);
        invalidateAuthCacheUser(userId);

        // If deactivated, revoke all sessions immediately.
        if (Object.prototype.hasOwnProperty.call(updates, 'active') && updates.active === false) {
          await conn.execute('UPDATE sessions SET revoked = TRUE WHERE user_id = ?', [userId]);
          invalidateTerminalSessionsForUser(userId);
        }

        await audit(conn, {
          userId: req.user.userId,
          action: 'user_update',
          details: { id: userId, ...updates },
          ip: req.ip
        });
        await conn.commit();
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }

      res.json({ success: true });
    } catch (error) {
      console.error('Update user error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.delete('/api/users/:id', authenticateToken, requirePasswordChangeCleared, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Prevent self-deletion
    if (parseInt(id) === req.user.userId) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    await pool.execute('DELETE FROM users WHERE id = ?', [id]);
    await audit(pool, { userId: req.user.userId, action: 'user_delete', details: { id: parseInt(id) }, ip: req.ip });
    res.json({ success: true });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin: invites
app.get('/api/admin/invites', authenticateToken, requirePasswordChangeCleared, requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, token, role, expires_at, redeemed_at, redeemed_by_user_id, created_at
       FROM user_invites
       ORDER BY created_at DESC
       LIMIT 200`
    );
    res.json(rows);
  } catch (error) {
    console.error('List invites error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post(
  '/api/admin/invites',
  authenticateToken,
  requirePasswordChangeCleared,
  requireAdmin,
  requireWriteAccess,
  async (req, res) => {
    try {
      return await runIdempotentCreate(req, res, 'invites:create', async () => {
        const role = normalizeEnum(req.body?.role, ROLE_VALUES, 'user');
        const hoursRaw = parseInt(String(req.body?.expires_in_hours ?? '72'), 10);
        const hours = Number.isFinite(hoursRaw) ? Math.max(1, Math.min(24 * 30, hoursRaw)) : 72;
        const token = crypto.randomBytes(32).toString('base64url');
        const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000);

        const [result] = await pool.execute(
          'INSERT INTO user_invites (token, created_by, role, expires_at) VALUES (?, ?, ?, ?)',
          [token, req.user.userId, role, expiresAt]
        );
        await audit(pool, {
          userId: req.user.userId,
          action: 'invite_create',
          details: { id: result.insertId, role, hours },
          ip: req.ip
        });
        return {
          status: 201,
          body: { id: result.insertId, token, role, expires_at: expiresAt.toISOString() }
        };
      });
    } catch (error) {
      console.error('Create invite error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.delete(
  '/api/admin/invites/:id',
  authenticateToken,
  requirePasswordChangeCleared,
  requireAdmin,
  requireWriteAccess,
  async (req, res) => {
    try {
      const inviteId = parseInt(req.params.id, 10);
      if (!Number.isFinite(inviteId)) return res.status(400).json({ error: 'Invalid invite id' });

      const [result] = await pool.execute('DELETE FROM user_invites WHERE id = ?', [inviteId]);
      if ((result.affectedRows ?? 0) === 0) return res.status(404).json({ error: 'Invite not found' });
      await audit(pool, { userId: req.user.userId, action: 'invite_delete', details: { id: inviteId }, ip: req.ip });
      res.json({ success: true });
    } catch (error) {
      console.error('Delete invite error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Admin: password reset tokens
app.post(
  '/api/admin/users/:id/password-reset',
  authenticateToken,
  requirePasswordChangeCleared,
  requireAdmin,
  requireWriteAccess,
  async (req, res) => {
    try {
      const userId = parseInt(req.params.id, 10);
      if (!Number.isFinite(userId)) return res.status(400).json({ error: 'Invalid user id' });
      if (userId === req.user.userId)
        return res.status(400).json({ error: 'Use the change-password flow for your own account' });

      const hoursRaw = parseInt(String(req.body?.expires_in_hours ?? '2'), 10);
      const hours = Number.isFinite(hoursRaw) ? Math.max(1, Math.min(24 * 7, hoursRaw)) : 2;
      const token = crypto.randomBytes(32).toString('base64url');
      const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000);

      const [users] = await pool.execute('SELECT id FROM users WHERE id = ?', [userId]);
      if (users.length === 0) return res.status(404).json({ error: 'User not found' });

      const [result] = await pool.execute(
        'INSERT INTO password_reset_tokens (token, user_id, created_by, expires_at) VALUES (?, ?, ?, ?)',
        [token, userId, req.user.userId, expiresAt]
      );
      await audit(pool, {
        userId: req.user.userId,
        action: 'password_reset_create',
        details: { id: result.insertId, userId, hours },
        ip: req.ip
      });
      res.status(201).json({ id: result.insertId, token, user_id: userId, expires_at: expiresAt.toISOString() });
    } catch (error) {
      console.error('Create password reset token error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Admin: unlock a user account (login lockout reset)
app.post(
  '/api/admin/users/:id/unlock',
  authenticateToken,
  requirePasswordChangeCleared,
  requireAdmin,
  requireWriteAccess,
  async (req, res) => {
    try {
      const userId = parseInt(req.params.id, 10);
      if (!Number.isFinite(userId)) return res.status(400).json({ error: 'Invalid user id' });
      if (userId === req.user.userId)
        return res.status(400).json({ error: 'Cannot unlock your own account from this view' });

      const [result] = await pool.execute(
        'UPDATE users SET failed_login_attempts = 0, last_failed_login_at = NULL, locked_until = NULL WHERE id = ?',
        [userId]
      );
      if ((result.affectedRows ?? 0) === 0) return res.status(404).json({ error: 'User not found' });

      await audit(pool, { userId: req.user.userId, action: 'user_unlock', details: { id: userId }, ip: req.ip });
      res.json({ success: true });
    } catch (error) {
      console.error('Unlock user error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Admin: sessions + audit + health + rate-limit status
app.get('/api/admin/sessions', authenticateToken, requirePasswordChangeCleared, requireAdmin, async (req, res) => {
  try {
    const limitRaw = parseInt(String(req.query?.limit ?? '200'), 10);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(500, limitRaw)) : 200;

    const [rows] = await pool.execute(
      `SELECT s.id, s.user_id, u.username, u.role, u.active,
              s.created_at, s.last_seen_at, s.expires_at, s.revoked,
              s.ip_address, s.user_agent
       FROM sessions s
       INNER JOIN users u ON u.id = s.user_id
       ORDER BY s.created_at DESC
       LIMIT ?`,
      [String(limit)]
    );
    res.json(
      rows.map((row) => ({
        id: row.id,
        user_id: row.user_id,
        username: row.username,
        role: row.role,
        active: Boolean(row.active),
        created_at: row.created_at,
        last_seen_at: row.last_seen_at,
        expires_at: row.expires_at,
        revoked: Boolean(row.revoked),
        ip_address: row.ip_address,
        user_agent: row.user_agent
      }))
    );
  } catch (error) {
    console.error('Admin sessions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post(
  '/api/admin/sessions/:id/revoke',
  authenticateToken,
  requirePasswordChangeCleared,
  requireAdmin,
  requireWriteAccess,
  async (req, res) => {
    try {
      const sessionId = String(req.params.id || '').trim();
      if (!sessionId) return res.status(400).json({ error: 'Invalid session id' });
      await pool.execute(
        'UPDATE sessions SET revoked = TRUE, refresh_token_hash = NULL, refresh_expires_at = NOW() WHERE id = ?',
        [sessionId]
      );
      invalidateAuthCacheSession(sessionId);
      invalidateTerminalSession(sessionId);
      await audit(pool, { userId: req.user.userId, action: 'session_revoke', details: { sessionId }, ip: req.ip });
      res.json({ success: true });
    } catch (error) {
      console.error('Admin revoke session error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.get('/api/admin/audit', authenticateToken, requirePasswordChangeCleared, requireAuditAccess, async (req, res) => {
  try {
    const limitRaw = parseInt(String(req.query?.limit ?? '200'), 10);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(1000, limitRaw)) : 200;
    const [rows] = await pool.execute(
      `SELECT e.id, e.user_id, u.username, e.type AS action, e.payload AS details, e.ip_address, e.created_at
       FROM events e
       LEFT JOIN users u ON u.id = e.user_id
       ORDER BY e.created_at DESC
       LIMIT ?`,
      [String(limit)]
    );
    const out = rows.map((row) => {
      let details = row.details;
      if (typeof details === 'string') {
        try {
          details = JSON.parse(details);
        } catch {
          details = null;
        }
      }
      return { ...row, details };
    });
    res.json(out);
  } catch (error) {
    console.error('Admin audit error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/system', authenticateToken, requirePasswordChangeCleared, requireAuditAccess, async (req, res) => {
  try {
    const [[health]] = await pool.execute('SELECT 1 AS ok');
    const [[counts]] = await pool.execute(
      `SELECT
         (SELECT COUNT(*) FROM users) AS users,
         (SELECT COUNT(*) FROM prompts) AS prompts,
         (SELECT COUNT(*) FROM sessions WHERE revoked = FALSE AND expires_at > NOW()) AS active_sessions`
    );
    res.json({
      ok: Boolean(health?.ok),
      release: TAILSHELL_RELEASE,
      counts,
      now: new Date().toISOString(),
      db: getDbMetricsSnapshot()
    });
  } catch (error) {
    console.error('Admin system error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get(
  '/api/admin/rate-limit',
  authenticateToken,
  requirePasswordChangeCleared,
  requireAuditAccess,
  async (_req, res) => {
    res.json({
      auth: {
        windowMs: 15 * 60 * 1000,
        max: 5
      },
      stats: rateLimitStats
    });
  }
);

async function bootstrapFirstAdmin() {
  const [rows] = await pool.execute('SELECT COUNT(*) AS count FROM users');
  const userCount = rows[0]?.count ?? 0;
  if (userCount > 0) return;

  const envUsername = (process.env.TAILSHELL_ADMIN_USERNAME || '').trim();
  const username = envUsername.length > 0 ? envUsername : 'admin';

  let password = (process.env.TAILSHELL_ADMIN_PASSWORD || '').trim();
  const mustChangePassword = true;

  if (password.length === 0) {
    password = crypto.randomBytes(24).toString('base64url');
    console.log('=== Tailshell bootstrap admin created ===');
    console.log(`Username: ${username}`);
    console.log(`Password: ${password}`);
  } else {
    console.log('=== Tailshell bootstrap admin created ===');
    console.log(`Username: ${username}`);
    console.log('Password: (from TAILSHELL_ADMIN_PASSWORD)');
  }
  console.log('Password change is required on first login: http://localhost:8081/change-password');

  const hash = await bcrypt.hash(password, PASSWORD_HASH_ROUNDS);
  await pool.execute('INSERT INTO users (username, password_hash, must_change_password, role) VALUES (?, ?, ?, ?)', [
    username,
    hash,
    mustChangePassword,
    'admin'
  ]);
}

async function runMigrations() {
  const config = require('../knexfile.cjs');
  const migrator = knex(config);
  try {
    const [batch, log] = await migrator.migrate.latest();
    if (Array.isArray(log) && log.length > 0) {
      console.log(`Applied ${log.length} migrations (batch ${batch})`);
    }
  } finally {
    await migrator.destroy();
  }
}

async function init() {
  validateRuntimeConfig();

  // Verify DB connection first
  await pool.execute('SELECT 1');

  // Apply schema migrations before serving traffic.
  await runMigrations();

  // Ensure a secure first-admin bootstrap on fresh DBs
  await bootstrapFirstAdmin();

  // Cleanup expired sessions periodically
  cleanupInterval = setInterval(
    async () => {
      try {
        await pool.execute(
          'DELETE FROM sessions WHERE (refresh_expires_at IS NOT NULL AND refresh_expires_at < NOW()) OR expires_at < NOW()'
        );
        pruneTerminalSessions();
        if (IDEMPOTENCY_TTL_MS) {
          const cutoff = new Date(Date.now() - IDEMPOTENCY_TTL_MS);
          await pool.execute('DELETE FROM idempotency_keys WHERE created_at < ?', [cutoff]);
        }
      } catch (error) {
        console.error('Session cleanup error:', error);
      }
    },
    60 * 60 * 1000
  ); // Every hour

  const PORT = process.env.PORT || 3000;
  server = app.listen(PORT, () => {
    console.log(`API running on port ${PORT}`);
  });

  const keepAliveTimeoutMs = Math.max(0, parseInt(process.env.HTTP_KEEPALIVE_TIMEOUT_MS || '5000', 10) || 5000);
  const headersTimeoutMs = Math.max(1000, parseInt(process.env.HTTP_HEADERS_TIMEOUT_MS || '10000', 10) || 10000);
  const requestTimeoutMs = Math.max(1000, parseInt(process.env.HTTP_REQUEST_TIMEOUT_MS || '65000', 10) || 65000);

  server.keepAliveTimeout = keepAliveTimeoutMs;
  server.headersTimeout = Math.max(headersTimeoutMs, keepAliveTimeoutMs + 1000);
  server.requestTimeout = requestTimeoutMs;
  server.setTimeout(requestTimeoutMs);
}

init().catch((error) => {
  console.error('Fatal startup error:', error);
  process.exit(1);
});

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection:', reason);
  shutdown('unhandledRejection', { exitCode: 1 });
});
process.on('uncaughtException', (error) => {
  console.error('Uncaught exception:', error);
  shutdown('uncaughtException', { exitCode: 1 });
});
