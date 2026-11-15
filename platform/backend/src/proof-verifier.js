'use strict';

const crypto = require('node:crypto');

const BASE64URL_PART = /^[A-Za-z0-9_-]+$/;
const SHA256_HEX = /^[a-f0-9]{64}$/i;
const VALID_JTI = /^[A-Za-z0-9._:-]{16,128}$/;
const VALID_APP_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/;

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function safeJsonParse(jsonString) {
  return JSON.parse(jsonString, (key, value) => {
    if (FORBIDDEN_KEYS.has(key)) {
      return undefined;
    }
    return value;
  });
}

function stableSortValue(value) {
  if (Array.isArray(value)) {
    return value.map(stableSortValue);
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      if (!FORBIDDEN_KEYS.has(key) && value[key] !== undefined) {
        out[key] = stableSortValue(value[key]);
      }
    }
    return out;
  }
  return value;
}

/**
 * Deterministic SHA-256 digest binding the cloud insert payload back to
 * the exact local verification verdict so fields cannot be altered in transit.
 */
function computeVerificationPayloadDigest({
  requestId,
  deviceId,
  decision,
  score,
  reasons,
  destinationHost,
  layersExecutedCount
}) {
  const canonical = stableSortValue({
    requestId: String(requestId || ''),
    deviceId: String(deviceId || ''),
    decision: String(decision || '').toUpperCase(),
    score: Number.isInteger(score) ? score : null,
    reasons: Array.isArray(reasons) ? reasons.map(String) : [],
    destinationHost: destinationHost ? String(destinationHost).toLowerCase() : null,
    layersExecutedCount: Number.isInteger(layersExecutedCount) ? layersExecutedCount : 0
  });

  return crypto
    .createHash('sha256')
    .update(JSON.stringify(canonical), 'utf8')
    .digest('hex');
}

function parseProofTokenSegments(rawToken) {
  if (typeof rawToken !== 'string') {
    return null;
  }

  const trimmed = rawToken.trim();
  if (!trimmed || trimmed.length > 4096) {
    return null;
  }

  const parts = trimmed.split('.');

  // Supports both:
  //   <encodedPayload>.<signature>
  //   sgp1.<encodedPayload>.<signature> (or alg prefix)
  if (parts.length === 2) {
    const [encodedPayload, signature] = parts;
    if (!BASE64URL_PART.test(encodedPayload) || !BASE64URL_PART.test(signature)) {
      return null;
    }
    return { prefix: null, encodedPayload, signature };
  }

  if (parts.length === 3) {
    const [prefix, encodedPayload, signature] = parts;
    if (
      !/^[A-Za-z0-9_-]{2,16}$/.test(prefix) ||
      !BASE64URL_PART.test(encodedPayload) ||
      !BASE64URL_PART.test(signature)
    ) {
      return null;
    }
    return { prefix, encodedPayload, signature };
  }

  return null;
}

function createProofVerifier({
  hmacSecret = null,
  publicKeyPem = null,
  maxTtlSeconds = 300,
  clockSkewSeconds = 30,
  allowedAppIds = ['com.safegate.app'],
  requirePayloadDigest = false
} = {}) {
  let currentHmacKey = null;

  function setHmacSecret(secret) {
    if (!secret || typeof secret !== 'string' || secret.trim().length < 32) {
      throw new Error('Proof HMAC secret must be at least 32 characters');
    }
    const nextKey = crypto
      .createHash('sha256')
      .update(secret.trim(), 'utf8')
      .digest();

    if (currentHmacKey) {
      currentHmacKey.fill(0);
    }
    currentHmacKey = nextKey;
  }

  let parsedPublicKey = null;

  if (hmacSecret) {
    setHmacSecret(hmacSecret);
  }

  if (publicKeyPem && typeof publicKeyPem === 'string' && publicKeyPem.trim()) {
    parsedPublicKey = crypto.createPublicKey(publicKeyPem.trim());
  }

  if (!currentHmacKey && !parsedPublicKey) {
    throw new Error('At least one proof verification key (HMAC secret or Ed25519 public key) is required');
  }

  const allowedApps = new Set(
    (Array.isArray(allowedAppIds) ? allowedAppIds : ['com.safegate.app'])
      .map(id => String(id || '').trim())
      .filter(id => VALID_APP_ID.test(id))
  );

  function verifySignature(signedInput, providedSignature) {
    const sigBuf = Buffer.from(providedSignature, 'base64url');
    if (sigBuf.length === 0) {
      return false;
    }

    // Try Ed25519 signature (64 bytes) if public key configured
    if (parsedPublicKey && sigBuf.length === 64) {
      try {
        if (crypto.verify(null, Buffer.from(signedInput, 'utf8'), parsedPublicKey, sigBuf)) {
          return 'Ed25519';
        }
      } catch {
        // Fall through if wrong key type
      }
    }

    // Try HMAC-SHA256 signature (32 bytes base64url)
    if (currentHmacKey) {
      const expected = crypto
        .createHmac('sha256', currentHmacKey)
        .update(signedInput, 'utf8')
        .digest('base64url');

      const expectedBuf = Buffer.from(expected, 'utf8');
      const providedUtf8 = Buffer.from(providedSignature, 'utf8');

      try {
        if (
          expectedBuf.length === providedUtf8.length &&
          crypto.timingSafeEqual(expectedBuf, providedUtf8)
        ) {
          return 'HMAC-SHA256';
        }
      } finally {
        expectedBuf.fill(0);
      }
    }

    return null;
  }

  function verify(rawToken, context = {}) {
    const parsedSegments = parseProofTokenSegments(rawToken);
    if (!parsedSegments) {
      return { valid: false, code: 'PROOF_TOKEN_MALFORMED', message: 'Invalid verification proof token format' };
    }

    const signedInput = parsedSegments.prefix
      ? `${parsedSegments.prefix}.${parsedSegments.encodedPayload}`
      : parsedSegments.encodedPayload;

    // Support prefix-excluded signing for two-part canonical signed payloads too
    const algorithm =
      verifySignature(signedInput, parsedSegments.signature) ||
      (parsedSegments.prefix ? verifySignature(parsedSegments.encodedPayload, parsedSegments.signature) : null);

    if (!algorithm) {
      return { valid: false, code: 'PROOF_SIGNATURE_INVALID', message: 'Verification proof signature is invalid' };
    }

    let claims;
    try {
      const rawJson = Buffer.from(parsedSegments.encodedPayload, 'base64url').toString('utf8');
      claims = safeJsonParse(rawJson);
    } catch {
      return { valid: false, code: 'PROOF_PAYLOAD_MALFORMED', message: 'Malformed verification proof payload' };
    }

    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
      return { valid: false, code: 'PROOF_PAYLOAD_MALFORMED', message: 'Malformed verification proof claims' };
    }

    // 1. Validate JTI (unique single-use replay ID)
    const jti = typeof claims.jti === 'string' ? claims.jti.trim() : '';
    if (!VALID_JTI.test(jti)) {
      return { valid: false, code: 'PROOF_JTI_INVALID', message: 'Verification proof jti is missing or invalid' };
    }

    // 2. Validate timestamps & maximum TTL window
    const nowSec = Math.floor(Date.now() / 1000);
    const iat = claims.iat;
    const exp = claims.exp;

    if (!Number.isInteger(iat) || !Number.isInteger(exp)) {
      return { valid: false, code: 'PROOF_TIMESTAMPS_INVALID', message: 'Verification proof timestamps are invalid' };
    }

    if (exp <= iat || exp - iat > maxTtlSeconds) {
      return { valid: false, code: 'PROOF_TTL_EXCEEDED', message: 'Verification proof lifetime exceeds allowed window' };
    }

    if (iat > nowSec + clockSkewSeconds) {
      return { valid: false, code: 'PROOF_NOT_YET_VALID', message: 'Verification proof issued-at time is invalid' };
    }

    if (nowSec > exp + clockSkewSeconds) {
      return { valid: false, code: 'PROOF_TOKEN_EXPIRED', message: 'Verification proof token has expired' };
    }

    // 3. Validate URL SHA-256 hash claim (proves a URL was hashed locally, zero raw URL leaked)
    const urlHash = typeof claims.uh === 'string' ? claims.uh.trim().toLowerCase() : '';
    if (!SHA256_HEX.test(urlHash)) {
      return { valid: false, code: 'PROOF_URL_HASH_INVALID', message: 'Verification proof URL digest is invalid' };
    }

    // 4. Bind requestId strictly
    const tokenRequestId = typeof claims.rid === 'string' ? claims.rid.trim() : '';
    if (!tokenRequestId || tokenRequestId !== context.requestId) {
      return { valid: false, code: 'PROOF_REQUEST_ID_MISMATCH', message: 'Verification proof does not match requestId' };
    }

    // 5. Bind deviceId if included in token claims
    if (claims.did !== undefined && claims.did !== null) {
      if (typeof claims.did !== 'string' || claims.did !== context.deviceId) {
        return { valid: false, code: 'PROOF_DEVICE_ID_MISMATCH', message: 'Verification proof does not match deviceId' };
      }
    }

    // 6. Bind appId if included or passed via header
    if (claims.app !== undefined && claims.app !== null) {
      if (typeof claims.app !== 'string' || !allowedApps.has(claims.app)) {
        return { valid: false, code: 'PROOF_APP_NOT_AUTHORIZED', message: 'Client application is not authorized' };
      }
    }

    // 7. Bind decision claim
    const tokenDecision = typeof claims.dec === 'string' ? claims.dec.toUpperCase() : '';
    const expectedDecision = String(context.decision || '').toUpperCase();
    const compatibleSafe =
      (tokenDecision === 'KNOWN_SAFE' || tokenDecision === 'SAFE' || tokenDecision === 'NO_KNOWN_THREAT') &&
      (expectedDecision === 'KNOWN_SAFE' || expectedDecision === 'SAFE' || expectedDecision === 'NO_KNOWN_THREAT');

    if (!tokenDecision || (tokenDecision !== expectedDecision && !compatibleSafe)) {
      return { valid: false, code: 'PROOF_DECISION_MISMATCH', message: 'Verification proof verdict does not match payload' };
    }

    // 8. Verify canonical payload digest when present (or mandatory when requirePayloadDigest=true)
    const expectedDigest = computeVerificationPayloadDigest(context);
    if (claims.ph !== undefined && claims.ph !== null) {
      const providedDigest = typeof claims.ph === 'string' ? claims.ph.trim().toLowerCase() : '';
      if (!SHA256_HEX.test(providedDigest)) {
        return { valid: false, code: 'PROOF_PAYLOAD_HASH_INVALID', message: 'Verification proof payload digest is malformed' };
      }
      const a = Buffer.from(providedDigest, 'utf8');
      const b = Buffer.from(expectedDigest, 'utf8');
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return { valid: false, code: 'PROOF_PAYLOAD_TAMPERED', message: 'Verification proof payload integrity check failed' };
      }
    } else if (requirePayloadDigest) {
      return { valid: false, code: 'PROOF_PAYLOAD_HASH_REQUIRED', message: 'Payload-bound verification proof is required' };
    }

    return {
      valid: true,
      algorithm,
      jti,
      urlHash,
      payloadHash: expectedDigest,
      expiresAt: exp
    };
  }

  function clear() {
    if (currentHmacKey) {
      currentHmacKey.fill(0);
      currentHmacKey = null;
    }
  }

  return Object.freeze({
    verify,
    setHmacSecret,
    hasPublicKey: Boolean(parsedPublicKey),
    hasHmacSecret: () => Boolean(currentHmacKey),
    allowedApps,
    clear
  });
}

module.exports = {
  createProofVerifier,
  computeVerificationPayloadDigest
};
