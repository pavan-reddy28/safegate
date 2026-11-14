
const test = require("node:test");
const assert = require("node:assert/strict");

const {
  analyzeUrl
} = require("../src/security/urlAnalyzer");

const {
  createGoogleHashData
} = require("../src/security/googleUrlHashing");

test("Normal OAuth redirect URLs are not suspicious only because of redirect_uri, state or code", () => {
  const url =
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc123&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&state=secret-state&code=temporary-code";

  const result = analyzeUrl(url);

  assert.equal(
    result.decision,
    "REPUTATION_CHECK_REQUIRED"
  );

  assert.ok(
    result.indicators.includes(
      "SENSITIVE_QUERY_PARAMETERS_DETECTED"
    )
  );

  assert.ok(
    result.indicators.includes(
      "REDIRECT_PARAMETER_PRESENT"
    )
  );

  assert.equal(
    JSON.stringify(result).includes("secret-state"),
    false
  );

  assert.equal(
    JSON.stringify(result).includes("temporary-code"),
    false
  );
});

test("Sensitive query values never change Google hash prefixes", () => {
  const first = createGoogleHashData(
    "https://example.com/callback?access_token=FIRST_SECRET&email=a%40example.com"
  );

  const second = createGoogleHashData(
    "https://example.com/callback?access_token=SECOND_SECRET&email=b%40example.com"
  );

  assert.deepEqual(first, second);
});

test("Google lookup prefixes do not depend on URL path", () => {
  const first = createGoogleHashData(
    `https://example.com/reset/${"a".repeat(48)}`
  );

  const second = createGoogleHashData(
    "https://example.com/admin/private"
  );

  assert.deepEqual(first, second);
});

test("Secret-like path segments are detected but not returned", () => {
  const secret = "a".repeat(48);

  const result = analyzeUrl(
    `https://example.com/reset/${secret}`
  );

  assert.ok(
    result.indicators.includes(
      "SENSITIVE_PATH_SEGMENT_DETECTED"
    )
  );

  assert.equal(
    JSON.stringify(result).includes(secret),
    false
  );
});

test("Dangerous redirect schemes are blocked locally", () => {
  const result = analyzeUrl(
    "https://example.com/redirect?next=javascript%3Aalert(1)"
  );

  assert.equal(result.decision, "BLOCK");

  assert.ok(
    result.reasonCodes.includes(
      "DANGEROUS_REDIRECT_SCHEME"
    )
  );
});

test("Private network IP destinations are blocked locally", () => {
  const result = analyzeUrl(
    "http://192.168.1.10/admin"
  );

  assert.equal(result.decision, "BLOCK");

  assert.ok(
    result.reasonCodes.includes(
      "NON_PUBLIC_IP_ADDRESS"
    )
  );
});

test("Ordinary HTTP alone does not become a phishing verdict", () => {
  const result = analyzeUrl(
    "http://example.com/about"
  );

  assert.equal(
    result.decision,
    "REPUTATION_CHECK_REQUIRED"
  );

  assert.ok(
    result.indicators.includes("UNENCRYPTED_HTTP")
  );
});
