
import { canonicalizeUrl } from "./googleHashing";

import {
  persistBlockedUrl,
  getBlockDetails,
} from "./blockStore";

const CONFIGURED_API_BASE =
  import.meta.env.VITE_SAFE_GATE_API_BASE ||
  "http://127.0.0.1:4317";

function validateLoopbackApiBase(value) {
  try {
    const parsed = new URL(value);

    const hostname = parsed.hostname
      .replace(/^\[|\]$/g, "")
      .toLowerCase();

    const loopback = new Set([
      "127.0.0.1",
      "localhost",
      "::1"
    ]);

    return (
      parsed.protocol === "http:" &&
      loopback.has(hostname) &&
      !parsed.username &&
      !parsed.password &&
      !parsed.search &&
      !parsed.hash
    );
  } catch {
    return false;
  }
}

// The URL is sent only to the local backend on this device.
const API_BASE = validateLoopbackApiBase(CONFIGURED_API_BASE)
  ? CONFIGURED_API_BASE.replace(/\/$/, "")
  : null;

const VERIFY_ENDPOINT = API_BASE
  ? `${API_BASE}/api/v1/verify`
  : null;

function createRequestId() {
  return globalThis.crypto?.randomUUID?.() ||
    `SG-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

async function createUrlFingerprint(input) {
  const canonical = canonicalizeUrl(input);
  const parsed = new URL(input);

  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.username ||
    parsed.password
  ) {
    throw new Error("Invalid destination URL");
  }

  // Full URL fingerprint is calculated locally and stored locally.
  const fingerprintInput = [
    parsed.protocol,
    parsed.host.toLowerCase(),
    canonical.pathname,
    canonical.search
  ].join("\0");

  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(fingerprintInput)
  );

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function buildHoldResponse(requestId, errorCode) {
  return {
    verificationStatus: "INCOMPLETE",
    requestId,

    localVerification: {
      decision: "HOLD",
      stage: "LOCAL_BACKEND_UNAVAILABLE",
      reasonCodes: [errorCode],
      indicators: [],
      destination: null,
      riskScore: null,
      reputationCheckRequired: false
    },

    reputationCheck: {
      attempted: false,
      completed: false,
      result: "NOT_STARTED"
    },

    googleVerification: {
      status: "NOT_STARTED",
      threatMatches: [],
      cacheHit: false
    },

    finalDecision: "HOLD",
    recommendedAction: "DO_NOT_OPEN",
    persistenceStatus: "UNAVAILABLE",
    finalReasonCodes: [errorCode]
  };
}

function buildPersistentBlockResponse(details, requestId) {
  const reasonCodes =
    Array.isArray(details?.reasonCodes) &&
    details.reasonCodes.length > 0
      ? details.reasonCodes
      : ["PREVIOUSLY_BLOCKED_URL"];

  return {
    verificationStatus: "COMPLETED",
    requestId: details?.requestId || requestId,

    localVerification: {
      decision: "BLOCK",
      stage: "PERSISTENT_DEVICE_BLOCKLIST",
      reasonCodes,
      indicators: [],
      destination: null,
      riskScore: null,
      reputationCheckRequired: false
    },

    reputationCheck: {
      attempted: false,
      completed: false,
      result: "SKIPPED_PERSISTENT_BLOCK"
    },

    googleVerification: {
      status: "SKIPPED_PERSISTENT_BLOCK",
      threatMatches: [],
      cacheHit: false
    },

    finalDecision: "BLOCK",
    recommendedAction: "DO_NOT_OPEN",
    persistenceStatus: "SAVED",
    finalReasonCodes: reasonCodes
  };
}

async function persistConfirmedBlock(
  fingerprint,
  result,
  requestId
) {
  const threat = result?.googleVerification?.threatMatches?.[0];

  try {
    await persistBlockedUrl(fingerprint, {
      requestId,

      reasonCodes:
        result.finalReasonCodes || ["SECURITY_BLOCK"],

      source:
        result.googleVerification?.status === "THREAT_FOUND"
          ? "GOOGLE_SAFE_BROWSING"
          : "LOCAL_ANALYZER",

      threatType: threat?.threatType || null
    });

    return "SAVED";
  } catch {
    // A storage failure must never turn BLOCK into ALLOW.
    return "FAILED";
  }
}

export async function verifyDestination(input) {
  const fallbackRequestId = createRequestId();

  if (!VERIFY_ENDPOINT) {
    return buildHoldResponse(
      fallbackRequestId,
      "LOCAL_API_BASE_MUST_BE_LOOPBACK"
    );
  }

  let fingerprint;

  try {
    fingerprint = await createUrlFingerprint(input);
  } catch {
    return buildHoldResponse(
      fallbackRequestId,
      "INVALID_OR_UNSUPPORTED_URL"
    );
  }

  // Stage 1: Check the persistent device blocklist locally.
  let existingBlock;

  try {
    existingBlock = await getBlockDetails(fingerprint);
  } catch {
    return buildHoldResponse(
      fallbackRequestId,
      "PERSISTENT_SECURITY_STORAGE_UNAVAILABLE"
    );
  }

  if (existingBlock) {
    return buildPersistentBlockResponse(
      existingBlock,
      fallbackRequestId
    );
  }

  // Stage 2: Submit the URL to the loopback backend only.
  let response;

  try {
    response = await fetch(VERIFY_ENDPOINT, {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },

      body: JSON.stringify({
        url: input
      }),

      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(12000)
    });
  } catch {
    return buildHoldResponse(
      fallbackRequestId,
      "LOCAL_VERIFICATION_SERVICE_UNAVAILABLE"
    );
  }

  let result;

  try {
    result = await response.json();
  } catch {
    return buildHoldResponse(
      fallbackRequestId,
      "INVALID_LOCAL_VERIFICATION_RESPONSE"
    );
  }

  if (!response.ok || !result || typeof result !== "object") {
    return buildHoldResponse(
      result?.requestId || fallbackRequestId,
      result?.error?.code || "LOCAL_VERIFICATION_FAILED"
    );
  }

  const allowedDecisions = new Set([
    "BLOCK",
    "SUSPICIOUS",
    "NO_KNOWN_THREAT",
    "HOLD"
  ]);

  if (!allowedDecisions.has(result.finalDecision)) {
    return buildHoldResponse(
      result.requestId || fallbackRequestId,
      "INVALID_VERIFICATION_DECISION"
    );
  }

  // Stage 3: Save only confirmed blocks to device storage.
  if (result.finalDecision === "BLOCK") {
    const persistenceStatus = await persistConfirmedBlock(
      fingerprint,
      result,
      result.requestId || fallbackRequestId
    );

    return {
      ...result,
      persistenceStatus
    };
  }

  return result;
}
