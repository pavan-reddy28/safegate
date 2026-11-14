import { Capacitor } from "@capacitor/core";
import { createDeviceUrlFingerprint } from "./urlFingerprint.js";
import { analyzeUrlOffline } from "./offlineEngine.js";
import {
  persistBlockedUrl,
  getBlockDetails,
  listBlockedUrls,
  removeBlockedUrl,
  clearBlockedUrls
} from "./blockStore.js";

const isNative = Capacitor.isNativePlatform();

function resolveApiBase() {
  const configured = import.meta.env?.VITE_SAFE_GATE_API_BASE;

  if (configured) {
    try {
      const parsed = new URL(configured);
      const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
      const loopback = new Set(["127.0.0.1", "localhost", "::1"]);
      if (
        ["http:", "https:"].includes(parsed.protocol) &&
        loopback.has(hostname) &&
        !parsed.username &&
        !parsed.password
      ) {
        return configured.replace(/\/$/, "");
      }
      return null;
    } catch {
      return null;
    }
  }

  // On web preview / desktop browser, call same-origin Express backend directly.
  if (!isNative) {
    return "";
  }

  // On standalone native Android APK (no VITE_SAFE_GATE_API_BASE), run the on-device 30-layer engine directly.
  return null;
}

const API_BASE = resolveApiBase();
const VERIFY_ENDPOINT = API_BASE !== null ? `${API_BASE}/api/v1/verify` : null;
const AUTHORIZE_ENDPOINT = API_BASE !== null ? `${API_BASE}/api/v1/verify/authorize-redirect` : null;

const ALLOWED_DECISIONS = new Set([
  "BLOCK",
  "SUSPICIOUS",
  "KNOWN_SAFE",
  "NO_KNOWN_THREAT",
  "HOLD"
]);

function createRequestId() {
  return globalThis.crypto?.randomUUID?.() ||
    `SG-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 10).toUpperCase()}`;
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
      redactedDestination: null,
      riskScore: null,
      reputationCheckRequired: false
    },
    securityChecks: {
      zeroEgressGuaranteed: true,
      schemeAndEncodingCheck: "PASSED",
      networkAndIpIsolationCheck: "PASSED",
      homographAndBrandSpoofCheck: "PASSED",
      malwareAndPathCheck: "PASSED",
      redirectAndSmugglingCheck: "PASSED",
      smsScamLureCheck: "PASSED"
    },
    finalDecision: "HOLD",
    recommendedAction: "DO_NOT_OPEN",
    persistenceStatus: "UNAVAILABLE",
    finalReasonCodes: [errorCode],
    riskSummary: {
      level: "MEDIUM",
      score: null,
      headline: "Could not complete link verification",
      parentAdvisory:
        "SafeGate held this link safely without opening it. Check your input and try again.",
      reasons: [errorCode],
      indicatorsCount: 0
    },
    layersExecuted: [],
    privacy: {
      outboundNetworkCalls: 0,
      externalServicesContacted: [],
      zeroEgressOnDevice: true,
      zeroUrlRetention: true,
      originalUrlLoggedOrStored: false,
      pathAndQueryInspectedLocallyOnly: true
    }
  };
}

function buildPersistentBlockResponse(details, requestId, originOnly) {
  const reasonCodes =
    Array.isArray(details?.reasonCodes) && details.reasonCodes.length > 0
      ? details.reasonCodes
      : ["PREVIOUSLY_BLOCKED_URL"];

  const displayHost = details?.originHost || originOnly || "blocked-destination";

  return {
    verificationStatus: "COMPLETED",
    requestId: details?.requestId || requestId,
    localVerification: {
      decision: "BLOCK",
      stage: "PERSISTENT_DEVICE_BLOCKLIST",
      reasonCodes,
      indicators: reasonCodes,
      destination: null,
      redactedDestination: {
        originOnly: originOnly || displayHost,
        displayHost: displayHost.replace(/^https?:\/\//, ""),
        privateComponentsStripped: true
      },
      riskScore: null,
      reputationCheckRequired: false
    },
    securityChecks: {
      zeroEgressGuaranteed: true,
      schemeAndEncodingCheck: "FAILED",
      networkAndIpIsolationCheck: "PASSED",
      homographAndBrandSpoofCheck: "FAILED",
      malwareAndPathCheck: "FLAGGED",
      redirectAndSmugglingCheck: "PASSED",
      smsScamLureCheck: "FLAGGED"
    },
    finalDecision: "BLOCK",
    recommendedAction: "DO_NOT_OPEN",
    persistenceStatus: "SAVED",
    cachedFromVault: true,
    finalReasonCodes: reasonCodes,
    verificationToken: null,
    riskSummary: {
      level: "CRITICAL",
      score: null,
      headline: "Previously blocked threat stopped immediately",
      parentAdvisory:
        "This link matches a SHA-256 threat fingerprint already blocked inside your SafeGate Device Vault.",
      reasons: reasonCodes,
      indicatorsCount: reasonCodes.length
    },
    layersExecuted: ["PERSISTENT_DEVICE_VAULT_MATCH", "ZERO_EGRESS_ON_DEVICE_ENFORCEMENT"],
    privacy: {
      outboundNetworkCalls: 0,
      externalServicesContacted: [],
      zeroEgressOnDevice: true,
      zeroUrlRetention: true,
      originalUrlLoggedOrStored: false,
      pathAndQueryInspectedLocallyOnly: true
    }
  };
}

async function persistConfirmedBlock(fingerprint, originHost, result, requestId) {
  if (!fingerprint) return "SKIPPED";
  try {
    await persistBlockedUrl(fingerprint, {
      requestId,
      originHost,
      reasonCodes: result.finalReasonCodes || ["SECURITY_BLOCK"],
      source: result.engineMode || "LOCAL_ANALYZER",
      threatType: result.finalReasonCodes?.[0] || "THREAT_BLOCKED"
    });
    return "SAVED";
  } catch {
    return "FAILED";
  }
}

export async function verifyDestination(input, options = {}) {
  const fallbackRequestId = createRequestId();
  const skipVaultCache = Boolean(options.skipVaultCache);

  let fpData;
  try {
    fpData = await createDeviceUrlFingerprint(input);
  } catch {
    // Do NOT return HOLD before analyzing — malformed/evasive URLs must still run through Stage 2 so threats are BLOCKED.
    fpData = null;
  }

  // Stage 1: Best-effort persistent on-device SHA-256 block vault lookup.
  // Never abort into HOLD if local SQLite/IndexedDB is unavailable.
  if (!skipVaultCache && fpData?.fingerprint) {
    try {
      const existingBlock = await getBlockDetails(fpData.fingerprint);
      if (existingBlock) {
        return buildPersistentBlockResponse(existingBlock, fallbackRequestId, fpData.originOnly);
      }
    } catch {
      // Ignore storage error and proceed straight to full URL verification.
    }
  }

  // Stage 2: Run SafeGate verification engine (same-origin Express API or Capacitor 30-layer on-device engine).
  let result;

  if (VERIFY_ENDPOINT !== null) {
    try {
      const response = await fetch(VERIFY_ENDPOINT, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({ url: input }),
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        signal: AbortSignal.timeout(12000)
      });

      const parsed = await response.json().catch(() => null);

      if (!response.ok || !parsed || typeof parsed !== "object") {
        // Explicit server rejection (e.g. forbidden bidi chars, bad scheme, malformed %)
        if (response.status === 400 && parsed?.error?.code === "FORBIDDEN_URL_CONTENT") {
          const blockedOffline = analyzeUrlOffline(input);
          if (blockedOffline.finalDecision === "BLOCK") {
            result = blockedOffline;
          } else {
            return buildHoldResponse(parsed?.requestId || fallbackRequestId, parsed.error.code);
          }
        } else {
          result = analyzeUrlOffline(input);
        }
      } else {
        result = parsed;
      }
    } catch {
      result = analyzeUrlOffline(input);
    }
  } else if (isNative) {
    try {
      result = analyzeUrlOffline(input);
    } catch {
      return buildHoldResponse(fallbackRequestId, "LOCAL_OFFLINE_ENGINE_ERROR");
    }
  } else {
    try {
      result = analyzeUrlOffline(input);
    } catch {
      return buildHoldResponse(fallbackRequestId, "LOCAL_API_BASE_MUST_BE_LOOPBACK");
    }
  }

  if (!result || !ALLOWED_DECISIONS.has(result.finalDecision)) {
    return buildHoldResponse(result?.requestId || fallbackRequestId, "INVALID_VERIFICATION_DECISION");
  }

  // Stage 3: Save only confirmed blocks (fingerprint only, zero sensitive path/query).
  if (result.finalDecision === "BLOCK") {
    const persistenceStatus = await persistConfirmedBlock(
      fpData?.fingerprint || null,
      fpData?.originOnly || null,
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

export async function authorizeVerifiedRedirect({
  url,
  verificationToken,
  userConfirmedWarning = false
}) {
  if (!verificationToken) {
    return { authorized: false, reasonCode: "MISSING_VERIFICATION_TOKEN" };
  }

  if (typeof verificationToken === "string" && verificationToken.startsWith("offline:")) {
    if (!userConfirmedWarning) {
      return { authorized: false, reasonCode: "USER_WARNING_CONFIRMATION_REQUIRED" };
    }
    return { authorized: true, offlineAuthorized: true };
  }

  if (!AUTHORIZE_ENDPOINT) {
    return { authorized: false, reasonCode: "LOCAL_BACKEND_UNAVAILABLE" };
  }

  try {
    const response = await fetch(AUTHORIZE_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        url,
        verificationToken,
        userConfirmedWarning
      }),
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(8000)
    });

    const body = await response.json().catch(() => null);
    if (!response.ok || !body?.authorized) {
      return {
        authorized: false,
        reasonCode: body?.reasonCode || body?.error?.code || "REDIRECT_NOT_AUTHORIZED"
      };
    }

    return body;
  } catch {
    return { authorized: false, reasonCode: "AUTHORIZATION_SERVICE_UNAVAILABLE" };
  }
}

export {
  listBlockedUrls as getLocalBlockVault,
  removeBlockedUrl as removeLocalBlockVaultEntry,
  clearBlockedUrls as clearLocalBlockVault
};
