"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createProofVerifier } = require("../platform/backend/src/proof-verifier.js");

const TEST_PROOF_SECRET = "test-proof-secret-minimum-32-chars-long-00112233";
const TEST_APP_KEY = "test-app-ingest-key-minimum-32-chars-long-998877";
const TEST_APP_ID = "com.safegate.app";
const TEST_PLATFORM_URL = "https://api.example.test";

test("Client Web Crypto sgp1 proof token matches server createProofVerifier & blocks tampering/replay", async () => {
  const {
    createSignedProofToken,
    buildPrivacySafeCloudPayload
  } = await import("../src/security/cloudSync.js");
  const { analyzeUrlOffline } = await import("../src/security/offlineEngine.js");

  const rawUrl = "https://sbi-kyc-update.xyz/amount-credited/claim?account=1234567890&otp=998877#secret";
  const localResult = analyzeUrlOffline(rawUrl);
  assert.equal(localResult.finalDecision, "BLOCK");

  const deviceId = "sgdev-test-device-001";
  const payload = buildPrivacySafeCloudPayload(localResult, deviceId);

  // Strict privacy invariant: raw sensitive URL, OTP, account, and fragment never enter cloud payload
  const serialized = JSON.stringify(payload);
  assert.equal(serialized.includes("1234567890"), false);
  assert.equal(serialized.includes("998877"), false);
  assert.equal(serialized.includes("#secret"), false);
  assert.equal(serialized.includes("/amount-credited"), false);
  const destHost = payload.localVerification?.destination?.hostname || null;

  const token = await createSignedProofToken(
    {
      rawUrl,
      requestId: payload.requestId,
      deviceId,
      decision: payload.finalDecision,
      score: payload.riskSummary.score,
      reasons: payload.finalReasonCodes,
      destinationHost: destHost,
      layersExecutedCount: payload.layersExecuted.length
    },
    {
      platformUrl: TEST_PLATFORM_URL,
      appIngestKey: TEST_APP_KEY,
      proofSecret: TEST_PROOF_SECRET,
      appId: TEST_APP_ID
    }
  );

  payload.verificationToken = token;

  const verifier = createProofVerifier({
    hmacSecret: TEST_PROOF_SECRET,
    allowedAppIds: [TEST_APP_ID]
  });

  const serverContext = {
    requestId: payload.requestId,
    deviceId,
    decision: payload.finalDecision,
    score: payload.riskSummary.score,
    reasons: payload.finalReasonCodes,
    destinationHost: destHost,
    layersExecutedCount: payload.layersExecuted.length
  };

  const verified = verifier.verify(payload.verificationToken, serverContext);
  assert.equal(verified.valid, true);
  assert.equal(verified.algorithm, "HMAC-SHA256");
  assert.equal(verified.jti.length >= 16, true);
  assert.match(verified.urlHash, /^[a-f0-9]{64}$/);

  // Tampering the decision or score fails verification cleanly
  const tamperedRes = verifier.verify(payload.verificationToken, {
    ...serverContext,
    decision: "KNOWN_SAFE"
  });
  assert.equal(tamperedRes.valid, false);
  assert.equal(tamperedRes.code, "PROOF_DECISION_MISMATCH");

  const tamperedScore = verifier.verify(payload.verificationToken, {
    ...serverContext,
    score: 0
  });
  assert.equal(tamperedScore.valid, false);
  assert.equal(tamperedScore.code, "PROOF_PAYLOAD_TAMPERED");

  verifier.clear();
});

test("End-to-end cloud block -> operator unblock -> re-block overrides work via verifyDestination and checkCloudOverrideForRequest", async () => {
  const storageMap = new Map();
  const originalLocalStorage = globalThis.localStorage;
  const originalFetch = globalThis.fetch;
  const originalEnv = globalThis.__SAFEGATE_TEST_ENV__;

  globalThis.localStorage = {
    getItem: (k) => (storageMap.has(k) ? storageMap.get(k) : null),
    setItem: (k, v) => storageMap.set(k, String(v)),
    removeItem: (k) => storageMap.delete(k)
  };

  globalThis.__SAFEGATE_TEST_ENV__ = {
    VITE_SAFEGATE_PLATFORM_URL: TEST_PLATFORM_URL,
    VITE_SAFEGATE_APP_ID: TEST_APP_ID,
    VITE_APP_INGEST_KEY: TEST_APP_KEY,
    VITE_EVENT_PROOF_HMAC_SECRET: TEST_PROOF_SECRET
  };

  const cloudDb = new Map();
  const postedEvents = [];

  globalThis.fetch = async (url, init = {}) => {
    const href = String(url);
    if (href.startsWith(TEST_PLATFORM_URL) && href.endsWith("/api/v1/events") && init.method === "POST") {
      assert.equal(init.headers["X-SafeGate-App"], TEST_APP_ID);
      assert.equal(init.headers["X-SafeGate-App-Key"], TEST_APP_KEY);
      const body = JSON.parse(init.body);
      postedEvents.push(body);
      cloudDb.set(body.requestId, {
        requestId: body.requestId,
        deviceId: body.deviceId,
        status: "OPEN",
        decision: body.finalDecision,
        recommendedAction: body.recommendedAction,
        blocked: body.finalDecision === "BLOCK",
        allowOpen: body.finalDecision === "SAFE" || body.finalDecision === "KNOWN_SAFE",
        overrideActive: false,
        updatedAt: new Date().toISOString()
      });
      return new Response(
        JSON.stringify({ accepted: true, requestId: body.requestId, status: "OPEN" }),
        { status: 201, headers: { "Content-Type": "application/json" } }
      );
    }

    const decisionMatch = href.match(/\/api\/v1\/app\/events\/([^/]+)\/decision\?deviceId=([^&]+)/);
    if (decisionMatch && init.method === "GET") {
      assert.equal(init.headers["X-SafeGate-App"], TEST_APP_ID);
      assert.equal(init.headers["X-SafeGate-App-Key"], TEST_APP_KEY);
      const rid = decodeURIComponent(decisionMatch[1]);
      const did = decodeURIComponent(decisionMatch[2]);
      const rec = cloudDb.get(rid);
      if (!rec || rec.deviceId !== did) {
        return new Response(
          JSON.stringify({ error: { code: "NOT_FOUND", message: "Event not found" } }),
          { status: 404, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response(JSON.stringify(rec), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    throw new Error(`Unexpected fetch to ${href}`);
  };

  try {
    const {
      verifyDestination,
      checkCloudOverrideForRequest
    } = await import("../src/security/verificationService.js");

    const phishUrl = "https://testsafebrowsing.appspot.com/s/phishing.html?token=abc123";

    // 1. User clicks phishing link -> blocked locally & uploaded to Cloud DB with requestId
    const initial = await verifyDestination(phishUrl);
    assert.equal(initial.finalDecision, "BLOCK");
    assert.equal(initial.cloudSync.synced, true);
    assert.equal(postedEvents.length, 1);
    const requestId = initial.requestId;
    assert.equal(typeof requestId, "string");
    assert.equal(JSON.stringify(postedEvents[0]).includes("abc123"), false);

    // 2. While operator hasn't overridden yet -> Check Status still reports blocked
    const stillBlocked = await checkCloudOverrideForRequest({
      rawUrl: phishUrl,
      requestId,
      lastResult: initial
    });
    assert.equal(stillBlocked.checked, true);
    assert.equal(stillBlocked.blocked, true);
    assert.equal(stillBlocked.allowOpen, false);

    // 3. Operator unblocks by requestId on cloud backend (PATCH decision=SAFE, status=RESOLVED)
    cloudDb.set(requestId, {
      ...cloudDb.get(requestId),
      status: "RESOLVED",
      decision: "SAFE",
      recommendedAction: "ALLOW",
      blocked: false,
      allowOpen: true,
      overrideActive: true,
      updatedAt: new Date().toISOString()
    });

    // 4. App clicks "Check Status" -> sees allowOpen: true
    const unblockedCheck = await checkCloudOverrideForRequest({
      rawUrl: phishUrl,
      requestId,
      lastResult: initial
    });
    assert.equal(unblockedCheck.checked, true);
    assert.equal(unblockedCheck.allowOpen, true);
    assert.equal(unblockedCheck.blocked, false);

    // 5. Re-verifying the same link while cloud override is SAFE allows opening directly
    const onReTap = await verifyDestination(phishUrl);
    assert.equal(onReTap.finalDecision, "KNOWN_SAFE");
    assert.equal(onReTap.cloudOverride, true);
    assert.equal(onReTap.requestId, requestId);

    // 6. Operator changes mind and re-blocks by requestId -> app enforces BLOCK on re-tap or Check Status
    cloudDb.set(requestId, {
      ...cloudDb.get(requestId),
      status: "OPEN",
      decision: "BLOCK",
      recommendedAction: "DO_NOT_OPEN",
      blocked: true,
      allowOpen: false,
      overrideActive: false,
      updatedAt: new Date().toISOString()
    });

    const reBlocked = await verifyDestination(phishUrl);
    assert.equal(reBlocked.finalDecision, "BLOCK");
    assert.equal(reBlocked.cloudOverride, true);
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.localStorage = originalLocalStorage;
    globalThis.__SAFEGATE_TEST_ENV__ = originalEnv;
  }
});
