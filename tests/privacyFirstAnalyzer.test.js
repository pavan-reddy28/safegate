"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { analyzeUrl } = require("../src/security/urlAnalyzer");
const { verifyUrl } = require("../src/services/verification.service");

test("Normal OAuth redirect URLs are not suspicious only because of redirect_uri, state or code", () => {
  const url =
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc123&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&state=secret-state&code=temporary-code";

  const result = analyzeUrl(url);

  assert.equal(result.decision, "REPUTATION_CHECK_REQUIRED");
  assert.ok(result.indicators.includes("SENSITIVE_QUERY_PARAMETERS_DETECTED"));
  assert.ok(result.indicators.includes("REDIRECT_PARAMETER_PRESENT"));
  assert.equal(JSON.stringify(result).includes("secret-state"), false);
  assert.equal(JSON.stringify(result).includes("temporary-code"), false);
});

test("Secret-like path segments are detected locally but never returned", () => {
  const secret = "a".repeat(48);

  const result = analyzeUrl(`https://example.com/reset/${secret}`);

  assert.ok(result.indicators.includes("SENSITIVE_PATH_SEGMENT_DETECTED"));
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test("Dangerous redirect schemes are blocked locally", () => {
  const result = analyzeUrl(
    "https://example.com/redirect?next=javascript%3Aalert(1)"
  );

  assert.equal(result.decision, "BLOCK");
  assert.ok(result.reasonCodes.includes("DANGEROUS_REDIRECT_SCHEME"));
});

test("Private network IP destinations are blocked locally", () => {
  const result = analyzeUrl("http://192.168.1.10/admin");

  assert.equal(result.decision, "BLOCK");
  assert.ok(result.reasonCodes.includes("NON_PUBLIC_IP_ADDRESS"));
});

test("Ordinary HTTP alone does not become a phishing verdict", () => {
  const result = analyzeUrl("http://example.com/about");

  assert.equal(result.decision, "REPUTATION_CHECK_REQUIRED");
  assert.ok(result.indicators.includes("UNENCRYPTED_HTTP"));
});

test("Verification executes strictly on-device with zero outbound network requests", async () => {
  const originalFetch = global.fetch;
  let fetchCalled = false;
  global.fetch = async () => {
    fetchCalled = true;
    throw new Error("Unexpected outbound fetch");
  };

  try {
    const result = await verifyUrl(
      "https://www.sbi.co.in/personal/banking?otp=123456&secret=abcxyz#secret-fragment-9988",
      "privacy-check-1"
    );

    assert.equal(fetchCalled, false);
    assert.equal(result.privacy.outboundNetworkCalls, 0);
    assert.equal(result.privacy.zeroEgressOnDevice, true);
    assert.deepEqual(result.privacy.externalServicesContacted, []);
    assert.equal(JSON.stringify(result).includes("123456"), false);
    assert.equal(JSON.stringify(result).includes("abcxyz"), false);
    assert.equal(JSON.stringify(result).includes("secret-fragment-9988"), false);
  } finally {
    global.fetch = originalFetch;
  }
});
