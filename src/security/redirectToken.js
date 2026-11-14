"use strict";

const crypto = require("node:crypto");
const env = require("../config/env");

/**
 * redirectToken.js
 *
 * Issues and verifies single-use short-lived HMAC-SHA256 verification tokens bound
 * to the SHA-256 digest of the checked URL and the SafeGate verdict.
 *
 * PRIVACY & REPLAY GUARANTEE:
 * - Uses Keystore-provisioned REDIRECT_SIGNING_SECRET when provided (>= 32 chars),
 *   or an in-memory random 256-bit key generated per process boot.
 * - Contains ONLY a SHA-256 hash of the URL + single-use jti, never the raw URL.
 * - Prevents frontend redirect bypass, URL swap attacks, and token replay.
 */

const HMAC_KEY =
  env.redirectSigningSecret && env.redirectSigningSecret.length >= 32
    ? crypto.createHash("sha256").update(env.redirectSigningSecret, "utf8").digest()
    : crypto.randomBytes(32);

const DEFAULT_TTL_SECONDS = 90;
const MAX_REPLAY_CACHE = 4096;

/** @type {Map<string, number>} */
const consumedJtis = new Map();

function pruneConsumedJtis(nowSec) {
  for (const [jti, exp] of consumedJtis) {
    if (exp < nowSec) consumedJtis.delete(jti);
  }
}

function hashUrlForBinding(url) {
  return crypto
    .createHash("sha256")
    .update(String(url || ""), "utf8")
    .digest("hex");
}

function signPayload(encodedPayload) {
  return crypto
    .createHmac("sha256", HMAC_KEY)
    .update(encodedPayload, "utf8")
    .digest("base64url");
}

function issueRedirectToken({ url, finalDecision, recommendedAction, requestId }) {
  const allowedToIssue =
    recommendedAction === "ALLOW" ||
    recommendedAction === "ALLOW_WITH_CAUTION" ||
    recommendedAction === "WARN_USER" ||
    recommendedAction === "HOLD";

  if (!allowedToIssue) {
    return null;
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const payload = {
    jti: crypto.randomUUID(),
    uh: hashUrlForBinding(url),
    dec: finalDecision,
    act: recommendedAction,
    rid: requestId || null,
    iat: nowSec,
    exp: nowSec + DEFAULT_TTL_SECONDS
  };

  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = signPayload(encoded);
  return `${encoded}.${signature}`;
}

function verifyRedirectToken({ url, token, userConfirmedWarning = false }) {
  if (typeof token !== "string" || !token.includes(".")) {
    return { authorized: false, reasonCode: "INVALID_VERIFICATION_TOKEN" };
  }

  const parts = token.split(".");
  if (parts.length !== 2) {
    return { authorized: false, reasonCode: "INVALID_VERIFICATION_TOKEN" };
  }

  const [encoded, providedSig] = parts;
  const expectedSig = signPayload(encoded);

  const providedBuf = Buffer.from(providedSig, "utf8");
  const expectedBuf = Buffer.from(expectedSig, "utf8");

  if (
    providedBuf.length !== expectedBuf.length ||
    !crypto.timingSafeEqual(providedBuf, expectedBuf)
  ) {
    return { authorized: false, reasonCode: "TOKEN_SIGNATURE_MISMATCH" };
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return { authorized: false, reasonCode: "MALFORMED_TOKEN_PAYLOAD" };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || nowSec > payload.exp) {
    return { authorized: false, reasonCode: "VERIFICATION_TOKEN_EXPIRED" };
  }

  const expectedHash = hashUrlForBinding(url);
  if (
    typeof payload.uh !== "string" ||
    payload.uh.length !== expectedHash.length ||
    !crypto.timingSafeEqual(
      Buffer.from(payload.uh, "utf8"),
      Buffer.from(expectedHash, "utf8")
    )
  ) {
    return { authorized: false, reasonCode: "URL_BINDING_MISMATCH" };
  }

  if (typeof payload.jti === "string" && consumedJtis.has(payload.jti)) {
    return { authorized: false, reasonCode: "VERIFICATION_TOKEN_ALREADY_CONSUMED" };
  }

  if (payload.act === "DO_NOT_OPEN" || payload.dec === "BLOCK") {
    return {
      authorized: false,
      reasonCode: "REDIRECT_BLOCKED_BY_VERDICT",
      finalDecision: payload.dec
    };
  }

  if (payload.act === "WARN_USER" && !userConfirmedWarning) {
    return {
      authorized: false,
      reasonCode: "USER_WARNING_CONFIRMATION_REQUIRED",
      finalDecision: payload.dec
    };
  }

  if ((payload.act === "HOLD" || payload.dec === "HOLD") && !userConfirmedWarning) {
    return {
      authorized: false,
      reasonCode: "HOLD_REPUTATION_UNAVAILABLE_CONFIRMATION_REQUIRED",
      finalDecision: payload.dec
    };
  }

  if (typeof payload.jti === "string") {
    pruneConsumedJtis(nowSec);
    if (consumedJtis.size >= MAX_REPLAY_CACHE) {
      const oldest = consumedJtis.keys().next().value;
      if (oldest !== undefined) consumedJtis.delete(oldest);
    }
    consumedJtis.set(payload.jti, payload.exp);
  }

  return {
    authorized: true,
    finalDecision: payload.dec,
    recommendedAction: payload.act,
    expiresInSeconds: Math.max(0, payload.exp - nowSec)
  };
}

module.exports = {
  issueRedirectToken,
  verifyRedirectToken,
  hashUrlForBinding
};
