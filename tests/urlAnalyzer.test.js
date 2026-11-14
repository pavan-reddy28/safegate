
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  analyzeUrl
} = require("../src/security/urlAnalyzer");

test("Microsoft OAuth authorization URL is not suspicious due to redirect_uri/state/code", () => {
  const url =
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=demo123&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&state=demo-state&code=demo-code";

  const result = analyzeUrl(url);

  assert.equal(result.decision, "REPUTATION_CHECK_REQUIRED");
  assert.equal(result.riskScore, 0);
  assert.equal(result.reputationCheckRequired, true);

  assert.ok(
    result.indicators.includes("REDIRECT_PARAMETER_PRESENT")
  );

  assert.ok(
    result.indicators.includes("SENSITIVE_QUERY_PARAMETER_PRESENT")
  );

  assert.ok(
    result.indicators.includes("NESTED_REDIRECT_DESTINATION_INSPECTED")
  );

  assert.equal(JSON.stringify(result).includes("demo-state"), false);
  assert.equal(JSON.stringify(result).includes("demo-code"), false);
  assert.equal(
    JSON.stringify(result).includes("app.example.com/callback"),
    false
  );
});

test("Normal HTTPS URL is structurally clean", () => {
  const result = analyzeUrl("https://www.google.com/");

  assert.equal(result.decision, "REPUTATION_CHECK_REQUIRED");
  assert.equal(result.riskScore, 0);
});

test("OAuth redirect parameter itself adds no risk", () => {
  const plain = analyzeUrl(
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
  );

  const withRedirect = analyzeUrl(
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&state=xyz"
  );

  assert.equal(plain.riskScore, withRedirect.riskScore);
  assert.equal(withRedirect.decision, "REPUTATION_CHECK_REQUIRED");
});

test("Dangerous javascript redirect is blocked locally", () => {
  const result = analyzeUrl(
    "https://example.org/redirect?next=javascript%3Aalert(1)"
  );

  assert.equal(result.decision, "BLOCK");
  assert.ok(
    result.reasonCodes.includes("DANGEROUS_REDIRECT_SCHEME")
  );
});

test("Dangerous data redirect is blocked locally", () => {
  const result = analyzeUrl(
    "https://example.org/redirect?return=data%3Atext%2Fhtml%2Chello"
  );

  assert.equal(result.decision, "BLOCK");
});

test("Nested dangerous redirect chain is blocked locally", () => {
  const result = analyzeUrl(
    "https://auth.example.org/login?next=https%3A%2F%2Fredirect.example.org%2Fgo%3Furl%3Djavascript%253Aalert(1)"
  );

  assert.equal(result.decision, "BLOCK");
  assert.ok(
    result.reasonCodes.includes("DANGEROUS_REDIRECT_SCHEME")
  );
});

test("URL credentials are blocked", () => {
  const result = analyzeUrl(
    "https://user:password@example.org/login"
  );

  assert.equal(result.decision, "BLOCK");
  assert.ok(
    result.reasonCodes.includes("URL_CONTAINS_CREDENTIALS")
  );
});

test("Private IPv4 destinations are blocked", () => {
  const result = analyzeUrl("http://192.168.1.25/login");

  assert.equal(result.decision, "BLOCK");
  assert.ok(
    result.reasonCodes.includes("NON_PUBLIC_IP_ADDRESS")
  );
});

test("Loopback IPv4 destinations are blocked", () => {
  const result = analyzeUrl("http://127.0.0.1:8080/admin");

  assert.equal(result.decision, "BLOCK");
});

test("HTTP alone is not an automatic phishing verdict", () => {
  const result = analyzeUrl("http://example.org/about");

  assert.equal(result.decision, "REPUTATION_CHECK_REQUIRED");
  assert.ok(result.indicators.includes("UNENCRYPTED_HTTP"));
});

test("Executable download is a signal, not an automatic block", () => {
  const result = analyzeUrl(
    "https://downloads.example.org/tool.exe"
  );

  assert.notEqual(result.decision, "BLOCK");
  assert.ok(
    result.indicators.includes("EXECUTABLE_DOWNLOAD_PATH")
  );
});

test("Sensitive query values are not included in analyzer output", () => {
  const secret = "private-reset-token-987654321";

  const result = analyzeUrl(
    `https://example.org/reset?token=${secret}&email=parent%40example.org`
  );

  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.equal(
    JSON.stringify(result).includes("parent@example.org"),
    false
  );
});

test("Cross-site OAuth callback is informational, not suspicious", () => {
  const result = analyzeUrl(
    "https://login.microsoftonline.com/authorize?redirect_uri=https%3A%2F%2Fmyapp.example.org%2Fcallback"
  );

  assert.equal(result.decision, "REPUTATION_CHECK_REQUIRED");
  assert.ok(
    result.indicators.includes("NESTED_REDIRECT_DESTINATION_INSPECTED")
  );
});

test("Common sign-in query parameters do not add risk", () => {
  const result = analyzeUrl(
    "https://accounts.google.com/o/oauth2/auth?client_id=abc&state=xyz&nonce=abc&redirect_uri=https%3A%2F%2Fapp.example.org%2Fcallback"
  );

  assert.equal(result.decision, "REPUTATION_CHECK_REQUIRED");
  assert.equal(result.riskScore, 0);
});

test("A close PayPal lookalike domain is suspicious", () => {
  const result = analyzeUrl(
    "https://secure.paypa1-login.example.net/"
  );

  assert.equal(result.decision, "SUSPICIOUS");
  assert.ok(
    result.indicators.includes("BRAND_NAME_IN_UNRELATED_DOMAIN")
  );
});
