'use strict';

const crypto = require('node:crypto');

const ALLOWED_OPERATOR_USERNAME = 'pavanreddy';
const BIND_COOKIE_NAME = 'sg_dash_bind';
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

function safeTimingEqualStrings(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function createScryptHash(plainPassword) {
  if (typeof plainPassword !== 'string' || plainPassword.length < 10) {
    throw new Error('Password must be at least 10 characters');
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(plainPassword, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

function verifyScryptPassword(plainPassword, encodedHash) {
  if (typeof plainPassword !== 'string' || typeof encodedHash !== 'string') {
    return false;
  }
  const parts = encodedHash.trim().split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') {
    return false;
  }
  const [, salt, expectedHex] = parts;
  if (!/^[a-f0-9]{16,128}$/i.test(salt) || !/^[a-f0-9]{128}$/i.test(expectedHex)) {
    return false;
  }

  try {
    const derivedBuf = crypto.scryptSync(plainPassword, salt, 64);
    const expectedBuf = Buffer.from(expectedHex, 'hex');
    if (derivedBuf.length !== expectedBuf.length) {
      return false;
    }
    return crypto.timingSafeEqual(derivedBuf, expectedBuf);
  } catch {
    return false;
  }
}

function parseCookies(cookieHeader) {
  const out = {};
  if (typeof cookieHeader !== 'string' || !cookieHeader) {
    return out;
  }
  for (const part of cookieHeader.split(';')) {
    const eqIdx = part.indexOf('=');
    if (eqIdx <= 0) continue;
    const key = part.slice(0, eqIdx).trim();
    const val = part.slice(eqIdx + 1).trim();
    if (key) {
      try {
        out[key] = decodeURIComponent(val);
      } catch {
        out[key] = val;
      }
    }
  }
  return out;
}

function createLoginRateLimiter({ maxAttempts = 5, windowMs = 15 * 60 * 1000, lockoutMs = 15 * 60 * 1000 } = {}) {
  const attempts = new Map();

  function prune(now) {
    if (attempts.size < 500) return;
    for (const [key, entry] of attempts) {
      if (entry.blockedUntil <= now && entry.resetAt <= now) {
        attempts.delete(key);
      }
    }
  }

  return {
    check(key) {
      const now = Date.now();
      const entry = attempts.get(key);
      if (!entry) return { allowed: true, retryAfterSec: 0 };
      if (entry.blockedUntil > now) {
        return {
          allowed: false,
          retryAfterSec: Math.max(1, Math.ceil((entry.blockedUntil - now) / 1000))
        };
      }
      if (entry.resetAt <= now) {
        attempts.delete(key);
        return { allowed: true, retryAfterSec: 0 };
      }
      return { allowed: true, retryAfterSec: 0 };
    },
    recordFailure(key) {
      const now = Date.now();
      prune(now);
      let entry = attempts.get(key);
      if (!entry || entry.resetAt <= now) {
        entry = { count: 0, resetAt: now + windowMs, blockedUntil: 0 };
      }
      entry.count += 1;
      if (entry.count >= maxAttempts) {
        entry.blockedUntil = now + lockoutMs;
      }
      attempts.set(key, entry);
      return entry;
    },
    recordSuccess(key) {
      attempts.delete(key);
    }
  };
}

function createSessionManager({
  sessionSecret,
  operatorUsername = ALLOWED_OPERATOR_USERNAME,
  operatorPasswordHash,
  ttlSeconds = 12 * 3600
} = {}) {
  if (typeof sessionSecret !== 'string' || sessionSecret.trim().length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters');
  }
  if (!safeTimingEqualStrings(operatorUsername, ALLOWED_OPERATOR_USERNAME)) {
    throw new Error('Only single-owner operator username pavanreddy is permitted');
  }
  if (typeof operatorPasswordHash !== 'string' || !operatorPasswordHash.startsWith('scrypt$')) {
    throw new Error('OPERATOR_PASSWORD_HASH must be a valid scrypt hash');
  }

  const signingKey = crypto.createHash('sha256').update(sessionSecret.trim(), 'utf8').digest();
  const revokedJtis = new Map();

  function pruneRevoked(nowSec) {
    for (const [jti, exp] of revokedJtis) {
      if (exp < nowSec) {
        revokedJtis.delete(jti);
      }
    }
  }

  function verifyOperatorCredentials(username, password) {
    if (!safeTimingEqualStrings(String(username || '').trim(), ALLOWED_OPERATOR_USERNAME)) {
      // Perform dummy scrypt work to avoid timing side-channel distinguishing username vs password failures
      verifyScryptPassword('dummy-invalid-check-value', operatorPasswordHash);
      return false;
    }
    return verifyScryptPassword(String(password || ''), operatorPasswordHash);
  }

  function issueSession() {
    const nowSec = Math.floor(Date.now() / 1000);
    const expSec = nowSec + ttlSeconds;
    const jti = crypto.randomUUID();
    const bindSecret = crypto.randomBytes(32).toString('base64url');
    const bindHash = crypto.createHash('sha256').update(bindSecret, 'utf8').digest('hex');

    const claims = {
      jti,
      sub: ALLOWED_OPERATOR_USERNAME,
      bh: bindHash,
      iat: nowSec,
      exp: expSec
    };

    const encodedClaims = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
    const signedInput = `sgop1.${encodedClaims}`;
    const sig = crypto.createHmac('sha256', signingKey).update(signedInput, 'utf8').digest('base64url');

    return {
      token: `${signedInput}.${sig}`,
      bindSecret,
      username: ALLOWED_OPERATOR_USERNAME,
      expiresAt: new Date(expSec * 1000).toISOString(),
      expiresInSeconds: ttlSeconds,
      jti
    };
  }

  function verifySession({ bearerToken, bindSecret }) {
    if (typeof bearerToken !== 'string' || typeof bindSecret !== 'string' || !bindSecret) {
      return { valid: false, code: 'DUAL_TOKEN_MISSING' };
    }

    const parts = bearerToken.trim().split('.');
    if (parts.length !== 3 || parts[0] !== 'sgop1' || !BASE64URL_RE.test(parts[1]) || !BASE64URL_RE.test(parts[2])) {
      return { valid: false, code: 'SESSION_TOKEN_MALFORMED' };
    }

    const signedInput = `${parts[0]}.${parts[1]}`;
    const expectedSig = crypto.createHmac('sha256', signingKey).update(signedInput, 'utf8').digest('base64url');
    if (!safeTimingEqualStrings(parts[2], expectedSig)) {
      return { valid: false, code: 'SESSION_SIGNATURE_INVALID' };
    }

    let claims;
    try {
      claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch {
      return { valid: false, code: 'SESSION_CLAIMS_MALFORMED' };
    }

    if (!claims || typeof claims !== 'object' || !safeTimingEqualStrings(claims.sub, ALLOWED_OPERATOR_USERNAME)) {
      return { valid: false, code: 'UNAUTHORIZED_OPERATOR' };
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (!Number.isInteger(claims.exp) || nowSec > claims.exp) {
      return { valid: false, code: 'SESSION_EXPIRED' };
    }

    if (typeof claims.jti !== 'string' || revokedJtis.has(claims.jti)) {
      return { valid: false, code: 'SESSION_REVOKED' };
    }

    const actualBindHash = crypto.createHash('sha256').update(bindSecret, 'utf8').digest('hex');
    if (!safeTimingEqualStrings(actualBindHash, claims.bh)) {
      return { valid: false, code: 'SESSION_BINDING_MISMATCH' };
    }

    return {
      valid: true,
      username: ALLOWED_OPERATOR_USERNAME,
      jti: claims.jti,
      expiresAt: new Date(claims.exp * 1000).toISOString()
    };
  }

  function revokeSession(jti, expiresAtIso) {
    if (typeof jti !== 'string' || !jti) return;
    const nowSec = Math.floor(Date.now() / 1000);
    pruneRevoked(nowSec);
    const expSec = expiresAtIso ? Math.floor(new Date(expiresAtIso).getTime() / 1000) : nowSec + ttlSeconds;
    revokedJtis.set(jti, Number.isFinite(expSec) ? expSec : nowSec + ttlSeconds);
  }

  return Object.freeze({
    verifyOperatorCredentials,
    issueSession,
    verifySession,
    revokeSession
  });
}

module.exports = {
  ALLOWED_OPERATOR_USERNAME,
  BIND_COOKIE_NAME,
  createScryptHash,
  verifyScryptPassword,
  parseCookies,
  createLoginRateLimiter,
  createSessionManager
};
