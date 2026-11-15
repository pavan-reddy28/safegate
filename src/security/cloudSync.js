import { getNativeHardwareDeviceInfo } from "../native/externalBrowser.js";

const STORAGE_DEVICE_ID_KEY = "safegate.deviceId";
const STORAGE_DEVICE_NAME_KEY = "safegate.deviceName";
const STORAGE_REQUEST_MAP_KEY = "safegate.requestMap";
const MAX_REQUEST_MAP_ENTRIES = 128;

let memoryDeviceId = null;
let memoryDeviceName = null;
const memoryRequestMap = new Map();

function readViteEnv(name) {
  try {
    const val = import.meta?.env?.[name] ?? globalThis.__SAFEGATE_TEST_ENV__?.[name];
    return typeof val === "string" ? val.trim() : "";
  } catch {
    return "";
  }
}

export function getCloudConfig(overrides = {}) {
  const platformUrlRaw =
    overrides.platformUrl !== undefined
      ? String(overrides.platformUrl || "").trim()
      : readViteEnv("VITE_SAFEGATE_PLATFORM_URL");

  const appIngestKey =
    overrides.appIngestKey !== undefined
      ? String(overrides.appIngestKey || "").trim()
      : readViteEnv("VITE_APP_INGEST_KEY");

  const proofSecret =
    overrides.proofSecret !== undefined
      ? String(overrides.proofSecret || "").trim()
      : readViteEnv("VITE_EVENT_PROOF_HMAC_SECRET");

  const appId =
    overrides.appId !== undefined
      ? String(overrides.appId || "").trim()
      : readViteEnv("VITE_SAFEGATE_APP_ID") || "com.safegate.app";

  const platformUrl = platformUrlRaw.replace(/\/+$/, "");

  return {
    platformUrl,
    appIngestKey,
    proofSecret,
    appId
  };
}

export function isCloudSyncConfigured(overrides = {}) {
  const cfg = getCloudConfig(overrides);
  return Boolean(cfg.platformUrl && cfg.appIngestKey.length >= 32 && cfg.proofSecret.length >= 32);
}

export function getOrCreateDeviceId() {
  if (memoryDeviceId) return memoryDeviceId;

  try {
    const stored = globalThis.localStorage?.getItem(STORAGE_DEVICE_ID_KEY);
    if (stored && /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/.test(stored)) {
      memoryDeviceId = stored;
      return stored;
    }
  } catch {
    // Ignore storage unavailability
  }

  const randomUuid =
    globalThis.crypto?.randomUUID?.() ||
    `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`;
  const generated = `sgdev-${randomUuid}`;
  memoryDeviceId = generated;

  try {
    globalThis.localStorage?.setItem(STORAGE_DEVICE_ID_KEY, generated);
  } catch {
    // Ignore storage unavailability
  }

  return generated;
}

export function sanitizeDeviceNameForCloud(rawName) {
  if (typeof rawName !== "string") return null;
  const cleaned = rawName.trim().replace(/\s{2,}/g, " ");
  if (!cleaned || cleaned.length > 80) return null;
  if (
    cleaned.includes("@") ||
    cleaned.includes("://") ||
    cleaned.includes("?") ||
    cleaned.includes("#")
  ) {
    return null;
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9 ._()+/-]{0,79}$/.test(cleaned)) {
    return null;
  }
  return cleaned;
}

function detectWebHardwareLabel() {
  const nav = globalThis.navigator;
  if (!nav) return null;

  const platform = String(nav.userAgentData?.platform || nav.platform || "").trim();
  const isMobile = Boolean(nav.userAgentData?.mobile) || /Android/i.test(String(nav.userAgent || ""));

  if (platform) {
    const cleanPlatform = sanitizeDeviceNameForCloud(
      isMobile && !/android/i.test(platform) ? `Mobile ${platform}` : platform
    );
    if (cleanPlatform) return cleanPlatform;
  }

  return isMobile ? "Android Browser" : "Web Browser";
}

export async function resolveDeviceName(overrides = {}) {
  const explicit = sanitizeDeviceNameForCloud(overrides.deviceName);
  if (explicit) return explicit;

  if (memoryDeviceName) return memoryDeviceName;

  try {
    const stored = globalThis.localStorage?.getItem(STORAGE_DEVICE_NAME_KEY);
    const cleanStored = sanitizeDeviceNameForCloud(stored);
    if (cleanStored) {
      memoryDeviceName = cleanStored;
      return cleanStored;
    }
  } catch {
    // Ignore storage unavailability
  }

  let detected = null;

  const nativeInfo = await getNativeHardwareDeviceInfo().catch(() => null);
  if (nativeInfo?.deviceName) {
    detected = sanitizeDeviceNameForCloud(nativeInfo.deviceName);
  }

  if (!detected && globalThis.navigator?.userAgentData?.getHighEntropyValues) {
    try {
      const uaHints = await globalThis.navigator.userAgentData.getHighEntropyValues(["model", "platform"]);
      const model = sanitizeDeviceNameForCloud(uaHints?.model);
      if (model) {
        detected = model;
      }
    } catch {
      // Ignore UA-CH rejection
    }
  }

  if (!detected) {
    detected = detectWebHardwareLabel();
  }

  if (detected) {
    memoryDeviceName = detected;
    try {
      globalThis.localStorage?.setItem(STORAGE_DEVICE_NAME_KEY, detected);
    } catch {
      // Ignore storage unavailability
    }
  }

  return detected;
}

export function rememberRequestForFingerprint(fingerprint, requestId, decision) {
  if (!fingerprint || !requestId) return;
  const entry = {
    requestId: String(requestId),
    decision: String(decision || "HOLD").toUpperCase(),
    updatedAt: Date.now()
  };
  memoryRequestMap.set(fingerprint, entry);

  try {
    const raw = globalThis.localStorage?.getItem(STORAGE_REQUEST_MAP_KEY);
    const parsed = raw ? JSON.parse(raw) : {};
    const next = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    next[fingerprint] = entry;

    const keys = Object.keys(next);
    if (keys.length > MAX_REQUEST_MAP_ENTRIES) {
      keys
        .sort((a, b) => (next[a]?.updatedAt || 0) - (next[b]?.updatedAt || 0))
        .slice(0, keys.length - MAX_REQUEST_MAP_ENTRIES)
        .forEach((k) => delete next[k]);
    }
    globalThis.localStorage?.setItem(STORAGE_REQUEST_MAP_KEY, JSON.stringify(next));
  } catch {
    // Ignore storage unavailability
  }
}

export function lookupRequestForFingerprint(fingerprint) {
  if (!fingerprint) return null;
  if (memoryRequestMap.has(fingerprint)) {
    return memoryRequestMap.get(fingerprint);
  }

  try {
    const raw = globalThis.localStorage?.getItem(STORAGE_REQUEST_MAP_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    const entry = parsed?.[fingerprint];
    if (entry?.requestId) {
      memoryRequestMap.set(fingerprint, entry);
      return entry;
    }
  } catch {
    // Ignore storage parse failure
  }
  return null;
}

function stableSortValue(value) {
  if (Array.isArray(value)) {
    return value.map(stableSortValue);
  }
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      if (key !== "__proto__" && key !== "constructor" && key !== "prototype" && value[key] !== undefined) {
        out[key] = stableSortValue(value[key]);
      }
    }
    return out;
  }
  return value;
}

function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64Url(bytes) {
  const arr = new Uint8Array(bytes);
  let binary = "";
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return globalThis.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function utf8ToBytes(str) {
  return new TextEncoder().encode(String(str || ""));
}

async function sha256Bytes(text) {
  const buf = await globalThis.crypto.subtle.digest("SHA-256", utf8ToBytes(text));
  return new Uint8Array(buf);
}

async function sha256Hex(text) {
  return bytesToHex(await sha256Bytes(text));
}

export async function computeClientPayloadDigest({
  requestId,
  deviceId,
  decision,
  score,
  reasons,
  destinationHost,
  layersExecutedCount
}) {
  const canonical = stableSortValue({
    requestId: String(requestId || ""),
    deviceId: String(deviceId || ""),
    decision: String(decision || "").toUpperCase(),
    score: Number.isInteger(score) ? score : null,
    reasons: Array.isArray(reasons) ? reasons.map(String) : [],
    destinationHost: destinationHost ? String(destinationHost).toLowerCase() : null,
    layersExecutedCount: Number.isInteger(layersExecutedCount) ? layersExecutedCount : 0
  });

  return sha256Hex(JSON.stringify(canonical));
}

function sanitizeHostForCloud(rawHost) {
  if (typeof rawHost !== "string") return null;
  const trimmed = rawHost.trim().toLowerCase();
  if (
    !trimmed ||
    trimmed === "blocked-destination" ||
    trimmed.length > 253 ||
    trimmed.includes("/") ||
    trimmed.includes("?") ||
    trimmed.includes("#") ||
    trimmed.includes("@")
  ) {
    return null;
  }
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$|^\[[0-9a-f:]+\]$/i.test(
    trimmed
  )
    ? trimmed
    : null;
}

function sanitizeProtocolForCloud(rawProto) {
  return rawProto === "http:" || rawProto === "https:" ? rawProto : null;
}

function sanitizeLocalDecision(rawLocalDecision) {
  const allowed = new Set([
    "BLOCK",
    "SUSPICIOUS",
    "HOLD",
    "SAFE",
    "REPUTATION_CHECK_REQUIRED"
  ]);
  return allowed.has(rawLocalDecision) ? rawLocalDecision : null;
}

function sanitizeAction(rawAction, fallbackDecision) {
  const allowed = new Set(["DO_NOT_OPEN", "WARN_USER", "HOLD", "ALLOW", "ALLOW_WITH_CAUTION"]);
  if (allowed.has(rawAction)) return rawAction;
  switch (fallbackDecision) {
    case "BLOCK":
      return "DO_NOT_OPEN";
    case "SUSPICIOUS":
      return "WARN_USER";
    case "KNOWN_SAFE":
    case "SAFE":
      return "ALLOW";
    case "NO_KNOWN_THREAT":
      return "ALLOW_WITH_CAUTION";
    default:
      return "HOLD";
  }
}

export function buildPrivacySafeCloudPayload(result, deviceId, deviceName = null) {
  const requestId = String(result?.requestId || "").trim();
  const decision = String(result?.finalDecision || result?.decision || "HOLD").toUpperCase();
  const rawScore = result?.riskSummary?.score ?? result?.localVerification?.riskScore;
  const score =
    decision === "BLOCK"
      ? 100
      : Number.isInteger(rawScore)
        ? Math.min(100, Math.max(0, rawScore))
        : 0;

  const reasons = (
    Array.isArray(result?.finalReasonCodes)
      ? result.finalReasonCodes
      : Array.isArray(result?.localVerification?.reasonCodes)
        ? result.localVerification.reasonCodes
        : []
  ).slice(0, 30);

  const indicators = (
    Array.isArray(result?.localVerification?.indicators)
      ? result.localVerification.indicators
      : []
  ).slice(0, 40);

  const rawHost =
    result?.localVerification?.destination?.hostname ||
    result?.localVerification?.redactedDestination?.displayHost ||
    null;
  const destinationHost = sanitizeHostForCloud(rawHost);
  const registrableDomain = sanitizeHostForCloud(
    result?.localVerification?.destination?.registrableDomain || null
  );
  const protocol = sanitizeProtocolForCloud(result?.localVerification?.destination?.protocol);

  const layersExecuted = Array.isArray(result?.layersExecuted)
    ? result.layersExecuted.slice(0, 40)
    : [];

  const localVerification = {
    decision: sanitizeLocalDecision(result?.localVerification?.decision),
    stage: typeof result?.localVerification?.stage === "string" ? result.localVerification.stage : "LOCAL_OFFLINE",
    reasonCodes: reasons.slice(0, 30),
    indicators,
    destination: destinationHost
      ? {
          hostname: destinationHost,
          registrableDomain,
          protocol,
          nonStandardPort: Boolean(result?.localVerification?.destination?.nonStandardPort)
        }
      : null,
    redactedDestination: destinationHost
      ? {
          originOnly: `${protocol || "https:"}//${destinationHost}`,
          displayHost: destinationHost,
          privateComponentsStripped: true
        }
      : null,
    riskScore: score,
    reputationCheckRequired: Boolean(result?.localVerification?.reputationCheckRequired),
    privacy: {
      outboundNetworkCalls: 0,
      zeroEgressOnDevice: true
    }
  };

  if (result?.localVerification?.urlInspection && typeof result.localVerification.urlInspection === "object") {
    localVerification.urlInspection = result.localVerification.urlInspection;
  }

  const safeDeviceName = sanitizeDeviceNameForCloud(deviceName);

  const payload = {
    requestId,
    deviceId,
    verificationStatus: result?.verificationStatus === "INCOMPLETE" ? "INCOMPLETE" : "COMPLETED",
    localVerification,
    securityChecks: result?.securityChecks && typeof result.securityChecks === "object" ? result.securityChecks : undefined,
    finalDecision: decision,
    recommendedAction: sanitizeAction(result?.recommendedAction, decision),
    finalReasonCodes: reasons,
    riskSummary: {
      level: result?.riskSummary?.level || (decision === "BLOCK" ? "CRITICAL" : "MEDIUM"),
      score,
      reasons,
      indicatorsCount: indicators.length
    },
    layersExecuted,
    appVersion: "2.0.0"
  };

  if (safeDeviceName) {
    payload.deviceName = safeDeviceName;
  }

  return payload;
}

export async function createSignedProofToken(
  {
    rawUrl,
    requestId,
    deviceId,
    decision,
    score,
    reasons,
    destinationHost,
    layersExecutedCount
  },
  overrides = {}
) {
  const cfg = getCloudConfig(overrides);
  if (!cfg.proofSecret || cfg.proofSecret.length < 32) {
    throw new Error("EVENT_PROOF_HMAC_SECRET_MISSING");
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const uh = await sha256Hex(String(rawUrl || ""));
  const ph = await computeClientPayloadDigest({
    requestId,
    deviceId,
    decision,
    score,
    reasons,
    destinationHost,
    layersExecutedCount
  });

  const jti =
    globalThis.crypto?.randomUUID?.() ||
    `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 14)}-${Math.random().toString(36).slice(2, 10)}`;

  const claims = {
    jti: jti.length >= 16 ? jti : `sgp-${jti}-0000000000`,
    rid: requestId,
    did: deviceId,
    app: cfg.appId,
    dec: decision,
    uh,
    ph,
    iat: nowSec,
    exp: nowSec + 120
  };

  const encodedClaims = bytesToBase64Url(utf8ToBytes(JSON.stringify(claims)));
  const signedInput = `sgp1.${encodedClaims}`;

  const rawKeyBytes = await sha256Bytes(cfg.proofSecret);
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    rawKeyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signatureBytes = await globalThis.crypto.subtle.sign("HMAC", cryptoKey, utf8ToBytes(signedInput));
  return `${signedInput}.${bytesToBase64Url(signatureBytes)}`;
}

export async function syncVerificationToCloud(rawUrl, result, overrides = {}) {
  const cfg = getCloudConfig(overrides);
  if (!cfg.platformUrl || cfg.appIngestKey.length < 32 || cfg.proofSecret.length < 32) {
    return { synced: false, configured: false };
  }

  if (!result?.requestId) {
    return { synced: false, configured: true, errorCode: "MISSING_REQUEST_ID" };
  }

  const deviceId = overrides.deviceId || getOrCreateDeviceId();
  const deviceName = await resolveDeviceName(overrides);
  const payload = buildPrivacySafeCloudPayload(result, deviceId, deviceName);

  try {
    const verificationToken = await createSignedProofToken(
      {
        rawUrl,
        requestId: payload.requestId,
        deviceId,
        decision: payload.finalDecision,
        score: payload.riskSummary.score,
        reasons: payload.finalReasonCodes,
        destinationHost: payload.localVerification?.destination?.hostname || null,
        layersExecutedCount: payload.layersExecuted.length
      },
      cfg
    );

    payload.verificationToken = verificationToken;

    const response = await fetch(`${cfg.platformUrl}/api/v1/events`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "X-SafeGate-App": cfg.appId,
        "X-SafeGate-App-Key": cfg.appIngestKey
      },
      body: JSON.stringify(payload),
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(8000)
    });

    const parsed = await response.json().catch(() => null);
    if (!response.ok) {
      return {
        synced: false,
        configured: true,
        status: response.status,
        errorCode: parsed?.error?.code || "CLOUD_SYNC_REJECTED"
      };
    }

    return {
      synced: true,
      configured: true,
      requestId: payload.requestId,
      deviceId,
      status: parsed?.status || "OPEN"
    };
  } catch {
    return { synced: false, configured: true, errorCode: "CLOUD_UNREACHABLE" };
  }
}

export async function fetchCloudDecisionByRequestId(requestId, overrides = {}) {
  const cfg = getCloudConfig(overrides);
  if (!cfg.platformUrl || cfg.appIngestKey.length < 32) {
    return { found: false, configured: false };
  }

  const safeId = String(requestId || "").trim();
  if (!safeId) {
    return { found: false, configured: true, errorCode: "INVALID_REQUEST_ID" };
  }

  const deviceId = overrides.deviceId || getOrCreateDeviceId();

  try {
    const response = await fetch(
      `${cfg.platformUrl}/api/v1/app/events/${encodeURIComponent(safeId)}/decision?deviceId=${encodeURIComponent(deviceId)}`,
      {
        method: "GET",
        headers: {
          Accept: "application/json",
          "X-SafeGate-App": cfg.appId,
          "X-SafeGate-App-Key": cfg.appIngestKey
        },
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        signal: AbortSignal.timeout(8000)
      }
    );

    const parsed = await response.json().catch(() => null);
    if (!response.ok || !parsed) {
      return {
        found: false,
        configured: true,
        statusCode: response.status,
        errorCode: parsed?.error?.code || "DECISION_NOT_FOUND"
      };
    }

    return {
      found: true,
      configured: true,
      requestId: parsed.requestId,
      status: parsed.status,
      decision: parsed.decision,
      recommendedAction: parsed.recommendedAction,
      blocked: Boolean(parsed.blocked),
      allowOpen: Boolean(parsed.allowOpen),
      overrideActive: Boolean(parsed.overrideActive),
      updatedAt: parsed.updatedAt || null
    };
  } catch {
    return { found: false, configured: true, offline: true, errorCode: "CLOUD_UNREACHABLE" };
  }
}
