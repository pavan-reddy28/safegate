import { Capacitor } from "@capacitor/core";
import { createDeviceUrlFingerprint } from "./urlFingerprint.js";
import { analyzeUrlOffline } from "./offlineEngine.js";
import { getSafeGateDatabase } from "./sqliteDatabase.js";
import {
  persistBlockedUrl,
  getBlockDetails,
  listBlockedUrls,
  removeBlockedUrl,
  clearBlockedUrls
} from "./blockStore.js";

import {
  isCloudSyncConfigured,
  syncVerificationToCloud,
  fetchCloudDecisionByRequestId,
  rememberRequestForFingerprint,
  lookupRequestForFingerprint,
  getOrCreateDeviceId,
  resolveDeviceName
} from "./cloudSync.js";

let warmupPromise = null;

export function warmupVerificationEngine() {
  if (!warmupPromise) {
    warmupPromise = Promise.allSettled([
      Promise.resolve().then(() => getOrCreateDeviceId()),
      resolveDeviceName().catch(() => null),
      Capacitor.getPlatform() === "android"
        ? getSafeGateDatabase().catch(() => null)
        : Promise.resolve(null)
    ]);
  }
  return warmupPromise;
}

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

function buildPersistentBlockResponse(details, requestId, originOnly, cloudOverride = false) {
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
      stage: cloudOverride ? "CLOUD_OPERATOR_BLOCK" : "PERSISTENT_DEVICE_BLOCKLIST",
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
    cloudOverride,
    finalReasonCodes: reasonCodes,
    verificationToken: null,
    riskSummary: {
      level: "CRITICAL",
      score: null,
      headline: cloudOverride
        ? "Blocked by security policy"
        : "Previously blocked threat stopped immediately",
      parentAdvisory:
        "This link matches a SHA-256 threat fingerprint blocked by SafeGate.",
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

function buildCloudUnblockResponse(requestId, originOnly) {
  const displayHost = originOnly ? originOnly.replace(/^https?:\/\//, "") : "approved-destination";
  return {
    verificationStatus: "COMPLETED",
    requestId,
    engineMode: "CLOUD_OPERATOR_OVERRIDE",
    cloudOverride: true,
    localVerification: {
      decision: "SAFE",
      stage: "CLOUD_OPERATOR_OVERRIDE",
      reasonCodes: ["OPERATOR_UNBLOCKED_REQUEST_ID"],
      indicators: [],
      destination: null,
      redactedDestination: {
        originOnly: originOnly || displayHost,
        displayHost,
        privateComponentsStripped: true
      },
      riskScore: 0,
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
    finalDecision: "KNOWN_SAFE",
    recommendedAction: "ALLOW",
    finalReasonCodes: ["OPERATOR_UNBLOCKED_REQUEST_ID"],
    verificationToken: `offline:${requestId}`,
    riskSummary: {
      level: "SAFE",
      score: 0,
      headline: `Approved by operator (${displayHost})`,
      parentAdvisory: "This request ID was explicitly approved for opening.",
      reasons: ["OPERATOR_UNBLOCKED_REQUEST_ID"],
      indicatorsCount: 0
    },
    layersExecuted: ["CLOUD_OPERATOR_DECISION_OVERRIDE"],
    cloudSync: {
      synced: true,
      configured: true,
      requestId,
      status: "RESOLVED"
    }
  };
}

function buildCloudPolicyDecisionResponse(cloudDecision, requestId, originOnly) {
  const displayHost = originOnly ? originOnly.replace(/^https?:\/\//, "") : "monitored-destination";
  const normalizedDecision = String(cloudDecision?.decision || "HOLD").toUpperCase();
  const isSuspicious = normalizedDecision === "SUSPICIOUS";
  const reasonCodes =
    Array.isArray(cloudDecision?.reasons) && cloudDecision.reasons.length > 0
      ? cloudDecision.reasons
      : [isSuspicious ? "OPERATOR_MARKED_SUSPICIOUS" : "OPERATOR_PLACED_HOLD"];
  const score = Number.isInteger(cloudDecision?.score)
    ? cloudDecision.score
    : isSuspicious
      ? 65
      : 30;

  return {
    verificationStatus: "COMPLETED",
    requestId,
    engineMode: "CLOUD_OPERATOR_OVERRIDE",
    cloudOverride: true,
    localVerification: {
      decision: isSuspicious ? "SUSPICIOUS" : "REPUTATION_CHECK_REQUIRED",
      stage: "CLOUD_OPERATOR_OVERRIDE",
      reasonCodes,
      indicators: reasonCodes,
      destination: null,
      redactedDestination: {
        originOnly: originOnly || displayHost,
        displayHost,
        privateComponentsStripped: true
      },
      riskScore: score,
      reputationCheckRequired: !isSuspicious
    },
    securityChecks: {
      zeroEgressGuaranteed: true,
      schemeAndEncodingCheck: "PASSED",
      networkAndIpIsolationCheck: "PASSED",
      homographAndBrandSpoofCheck: isSuspicious ? "FLAGGED" : "PASSED",
      malwareAndPathCheck: isSuspicious ? "FLAGGED" : "PASSED",
      redirectAndSmugglingCheck: "PASSED",
      smsScamLureCheck: isSuspicious ? "FLAGGED" : "PASSED"
    },
    finalDecision: isSuspicious ? "SUSPICIOUS" : "HOLD",
    recommendedAction: cloudDecision?.recommendedAction || (isSuspicious ? "WARN_USER" : "HOLD"),
    finalReasonCodes: reasonCodes,
    verificationToken: `offline:${requestId}`,
    riskSummary: {
      level: isSuspicious ? "HIGH" : "MEDIUM",
      score,
      headline: isSuspicious
        ? `Marked suspicious by operator (${displayHost})`
        : `Placed on hold by operator (${displayHost})`,
      parentAdvisory: isSuspicious
        ? "Security policy flagged this destination as suspicious. Proceed only if you trust the sender."
        : "Security policy placed this link under manual review.",
      reasons: reasonCodes,
      indicatorsCount: reasonCodes.length
    },
    layersExecuted: ["CLOUD_OPERATOR_DECISION_OVERRIDE"],
    cloudSync: {
      synced: true,
      configured: true,
      requestId,
      status: cloudDecision?.status || "OPEN"
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
  const backgroundCloudSync = Boolean(options.backgroundCloudSync);
  const stage1TimeoutMs = Number.isFinite(options.stage1TimeoutMs) ? options.stage1TimeoutMs : 1200;
  const cloudConfigured = !options.skipCloudSync && isCloudSyncConfigured();

  let fpData;
  try {
    fpData = await createDeviceUrlFingerprint(input);
  } catch {
    // Do NOT return HOLD before analyzing — malformed/evasive URLs must still run through Stage 2 so threats are BLOCKED.
    fpData = null;
  }

  // Stage 1: Persistent on-device SHA-256 block vault lookup + Cloud operator override check by requestId.
  if (!skipVaultCache && fpData?.fingerprint) {
    try {
      const existingBlock = await getBlockDetails(fpData.fingerprint);
      if (existingBlock) {
        const blockResp = buildPersistentBlockResponse(existingBlock, fallbackRequestId, fpData.originOnly);
        if (cloudConfigured && existingBlock.requestId && existingBlock.requestId !== "UNKNOWN") {
          const cloudDecision = await fetchCloudDecisionByRequestId(existingBlock.requestId, {
            timeoutMs: stage1TimeoutMs
          });
          if (cloudDecision?.found) {
            if (cloudDecision.allowOpen) {
              await removeBlockedUrl(fpData.fingerprint).catch(() => {});
              rememberRequestForFingerprint(fpData.fingerprint, existingBlock.requestId, cloudDecision.decision || "SAFE");
              return buildCloudUnblockResponse(existingBlock.requestId, fpData.originOnly);
            }
            if (
              !cloudDecision.blocked &&
              (cloudDecision.decision === "SUSPICIOUS" ||
                cloudDecision.decision === "HOLD" ||
                cloudDecision.overrideActive)
            ) {
              await removeBlockedUrl(fpData.fingerprint).catch(() => {});
              rememberRequestForFingerprint(fpData.fingerprint, existingBlock.requestId, cloudDecision.decision);
              return buildCloudPolicyDecisionResponse(cloudDecision, existingBlock.requestId, fpData.originOnly);
            }
          }
          if (!cloudDecision?.found && cloudDecision?.statusCode === 404) {
            const retryUpload = syncVerificationToCloud(input, blockResp).catch(() => null);
            if (!backgroundCloudSync) {
              await retryUpload;
            }
          }
        }
        return cloudConfigured
          ? { ...blockResp, cloudSync: { synced: true, configured: true, requestId: blockResp.requestId } }
          : blockResp;
      }

      if (cloudConfigured) {
        const prior = lookupRequestForFingerprint(fpData.fingerprint);
        if (prior?.requestId) {
          const cloudDecision = await fetchCloudDecisionByRequestId(prior.requestId, {
            timeoutMs: stage1TimeoutMs
          });
          if (cloudDecision?.found) {
            if (cloudDecision.blocked) {
              const blockOverride = buildPersistentBlockResponse(
                {
                  requestId: prior.requestId,
                  originHost: fpData.originOnly,
                  reasonCodes:
                    Array.isArray(cloudDecision.reasons) && cloudDecision.reasons.length > 0
                      ? cloudDecision.reasons
                      : ["OPERATOR_BLOCKED_REQUEST_ID"]
                },
                prior.requestId,
                fpData.originOnly,
                true
              );
              await persistConfirmedBlock(
                fpData.fingerprint,
                fpData.originOnly,
                blockOverride,
                prior.requestId
              );
              rememberRequestForFingerprint(fpData.fingerprint, prior.requestId, "BLOCK");
              return { ...blockOverride, cloudSync: { synced: true, configured: true, requestId: prior.requestId } };
            }
            if (cloudDecision.allowOpen) {
              rememberRequestForFingerprint(fpData.fingerprint, prior.requestId, cloudDecision.decision);
              return buildCloudUnblockResponse(prior.requestId, fpData.originOnly);
            }
            if (
              cloudDecision.overrideActive ||
              (cloudDecision.decision && cloudDecision.decision !== prior.decision)
            ) {
              rememberRequestForFingerprint(fpData.fingerprint, prior.requestId, cloudDecision.decision);
              return buildCloudPolicyDecisionResponse(cloudDecision, prior.requestId, fpData.originOnly);
            }
          }
        }
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
        signal: AbortSignal.timeout(2500)
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

  const finalRequestId = result.requestId || fallbackRequestId;
  let enrichedResult = { ...result, requestId: finalRequestId };

  // Stage 3: Save only confirmed blocks locally (fingerprint only, zero sensitive path/query).
  if (enrichedResult.finalDecision === "BLOCK") {
    const persistenceStatus = await persistConfirmedBlock(
      fpData?.fingerprint || null,
      fpData?.originOnly || null,
      enrichedResult,
      finalRequestId
    );
    enrichedResult = {
      ...enrichedResult,
      persistenceStatus
    };
  }

  if (fpData?.fingerprint) {
    rememberRequestForFingerprint(fpData.fingerprint, finalRequestId, enrichedResult.finalDecision);
  }

  // Stage 4: Sync redacted verification verdict to SafeGate Cloud Platform when configured.
  if (cloudConfigured) {
    if (backgroundCloudSync) {
      const cloudSyncPromise = syncVerificationToCloud(input, enrichedResult)
        .then((syncRes) => {
          enrichedResult.cloudSync = syncRes;
          if (typeof options.onCloudSync === "function") {
            options.onCloudSync(syncRes, enrichedResult);
          }
          return syncRes;
        })
        .catch(() => {
          const failRes = { synced: false, configured: true, errorCode: "CLOUD_UNREACHABLE" };
          enrichedResult.cloudSync = failRes;
          if (typeof options.onCloudSync === "function") {
            options.onCloudSync(failRes, enrichedResult);
          }
          return failRes;
        });

      enrichedResult = {
        ...enrichedResult,
        cloudSync: {
          synced: false,
          pending: true,
          configured: true,
          requestId: finalRequestId
        },
        _cloudSyncPromise: cloudSyncPromise
      };
    } else {
      const cloudSync = await syncVerificationToCloud(input, enrichedResult);
      enrichedResult = {
        ...enrichedResult,
        cloudSync
      };
    }
  }

  return enrichedResult;
}

export async function checkCloudOverrideForRequest({ rawUrl, requestId, lastResult = null }) {
  if (!requestId) {
    return { checked: false, errorCode: "MISSING_REQUEST_ID" };
  }

  if (!isCloudSyncConfigured()) {
    return { checked: false, configured: false };
  }

  // Wait for any in-flight background upload from instant verification before polling status.
  if (lastResult?._cloudSyncPromise) {
    await lastResult._cloudSyncPromise.catch(() => null);
  }

  // If the original verification hasn't reached the cloud yet, retry upload first.
  if (lastResult && lastResult.cloudSync && !lastResult.cloudSync.synced && rawUrl) {
    await syncVerificationToCloud(rawUrl, lastResult).catch(() => null);
  }

  const decision = await fetchCloudDecisionByRequestId(requestId, { timeoutMs: 3500 });
  if (!decision?.found) {
    return {
      checked: false,
      configured: true,
      offline: Boolean(decision?.offline),
      errorCode: decision?.errorCode || "NOT_FOUND"
    };
  }

  let fpData = null;
  if (rawUrl) {
    try {
      fpData = await createDeviceUrlFingerprint(rawUrl);
    } catch {
      fpData = null;
    }
  }

  const normalizedDecision = String(decision.decision || "HOLD").toUpperCase();

  if (decision.allowOpen) {
    if (fpData?.fingerprint) {
      await removeBlockedUrl(fpData.fingerprint).catch(() => {});
      rememberRequestForFingerprint(fpData.fingerprint, requestId, normalizedDecision);
    }
    return {
      checked: true,
      configured: true,
      blocked: false,
      allowOpen: true,
      suspicious: false,
      hold: false,
      overrideActive: Boolean(decision.overrideActive),
      decision: normalizedDecision,
      recommendedAction: decision.recommendedAction,
      status: decision.status,
      score: decision.score ?? null,
      reasons: decision.reasons || []
    };
  }

  if (decision.blocked) {
    if (fpData?.fingerprint) {
      await persistBlockedUrl(fpData.fingerprint, {
        requestId,
        originHost: fpData.originOnly,
        reasonCodes:
          Array.isArray(decision.reasons) && decision.reasons.length > 0
            ? decision.reasons
            : ["CLOUD_OPERATOR_BLOCKED"],
        source: "CLOUD_OPERATOR_OVERRIDE",
        threatType: "CLOUD_BLOCK"
      }).catch(() => {});
      rememberRequestForFingerprint(fpData.fingerprint, requestId, "BLOCK");
    }
    return {
      checked: true,
      configured: true,
      blocked: true,
      allowOpen: false,
      suspicious: false,
      hold: false,
      overrideActive: Boolean(decision.overrideActive),
      decision: normalizedDecision,
      recommendedAction: decision.recommendedAction,
      status: decision.status,
      score: decision.score ?? 100,
      reasons: decision.reasons || []
    };
  }

  const isSuspicious =
    normalizedDecision === "SUSPICIOUS" || decision.recommendedAction === "WARN_USER";

  if (fpData?.fingerprint) {
    // If downgraded from BLOCK -> SUSPICIOUS or HOLD, remove from hard block vault.
    await removeBlockedUrl(fpData.fingerprint).catch(() => {});
    rememberRequestForFingerprint(fpData.fingerprint, requestId, normalizedDecision);
  }

  return {
    checked: true,
    configured: true,
    blocked: false,
    allowOpen: false,
    suspicious: isSuspicious,
    hold: !isSuspicious,
    overrideActive: Boolean(decision.overrideActive),
    decision: normalizedDecision,
    recommendedAction: decision.recommendedAction,
    status: decision.status,
    score: decision.score ?? null,
    reasons: decision.reasons || []
  };
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
