"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const app = require("../src/app");
const { analyzeUrl } = require("../src/security/urlAnalyzer");
const { createGoogleHashData } = require("../src/security/googleUrlHashing");
const { verifyNoPrivateUrlLeak } = require("../src/security/privacyGuard");
const {
  issueRedirectToken,
  verifyRedirectToken
} = require("../src/security/redirectToken");
const {
  calculateFinalDecision,
  verifyUrl
} = require("../src/services/verification.service");

// --------------------------------------------------
// 1. PARENTS SMS / WHATSAPP SCAM & MALWARE PROTECTION
// --------------------------------------------------

test("Blocks fake bank 'amount credited' + brand impersonation SMS phishing link", () => {
  const result = analyzeUrl(
    "https://sbi-kyc-update.xyz/amount-credited/claim?account=1234567890&otp=998877"
  );

  assert.equal(result.decision, "BLOCK");
  assert.ok(result.indicators.includes("BRAND_NAME_IN_UNRELATED_DOMAIN"));
  assert.ok(result.indicators.includes("SMS_FINANCIAL_SCAM_LURE"));
  assert.equal(JSON.stringify(result).includes("1234567890"), false);
  assert.equal(JSON.stringify(result).includes("998877"), false);
  assert.equal(JSON.stringify(result).includes("amount-credited"), false);
});

test("Blocks Android APK sideload malware delivered with SMS lure or HTTP", () => {
  const result = analyzeUrl(
    "http://rewards-claim.top/SBI_KYC_Update.apk"
  );

  assert.equal(result.decision, "BLOCK");
  assert.ok(result.indicators.includes("MOBILE_SIDELOAD_INSTALLER_PATH"));
});

test("Flags standalone Android APK download on HTTPS as SUSPICIOUS", () => {
  const result = analyzeUrl(
    "https://unknown-mirror.org/files/app-release.apk"
  );

  assert.equal(result.decision, "SUSPICIOUS");
  assert.ok(result.indicators.includes("MOBILE_SIDELOAD_INSTALLER_PATH"));
});

test("Flags URL shorteners that hide real destination without leaking via HTTP fetch", () => {
  const result = analyzeUrl("https://bit.ly/3xFakeBankSms");

  assert.equal(result.decision, "SUSPICIOUS");
  assert.ok(result.indicators.includes("URL_SHORTENER_HIDES_DESTINATION"));
});

test("Blocks Cyrillic homograph brand impersonation (mixed-script and pure-Cyrillic xn--)", () => {
  // Mixed-script "ѕbi.co.in" (Cyrillic 'ѕ' + Latin 'bi') -> xn--bi-doc.co.in
  const mixed = analyzeUrl("https://xn--bi-doc.co.in/login");
  assert.equal(mixed.decision, "BLOCK");
  assert.ok(
    mixed.indicators.includes("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION")
  );

  // Pure-Cyrillic "аpplе" lookalike using all Cyrillic letters: а р р ӏ е
  const { domainToASCII } = require("node:url");
  const pureCyrillicHost = domainToASCII("\u0430\u0440\u0440\u04CF\u0435.com");
  const pure = analyzeUrl(`https://${pureCyrillicHost}/signin`);
  assert.equal(pure.decision, "BLOCK");
  assert.ok(
    pure.indicators.includes("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION")
  );
});

test("Detects leet-speak brand lookalike domain (sb1-verify / paypa1)", () => {
  const result = analyzeUrl("https://hdfc-netbanking-verify.com/login");

  assert.equal(result.decision, "SUSPICIOUS");
  assert.ok(result.indicators.includes("BRAND_NAME_IN_UNRELATED_DOMAIN"));
});

test("Blocks dangerous UPI / intent deep-link inside redirect parameter", () => {
  const result = analyzeUrl(
    "https://example.org/claim?next=upi%3A%2F%2Fpay%3Fpa%3Dscammer%40upi%26am%3D15000"
  );

  assert.equal(result.decision, "BLOCK");
  assert.ok(result.reasonCodes.includes("DANGEROUS_REDIRECT_SCHEME"));
});

test("Blocks Base64-smuggled dangerous redirect targeting private IP", () => {
  // Base64 of "http://192.168.1.1/admin"
  const b64 = Buffer.from("http://192.168.1.1/admin", "utf8").toString("base64");
  const result = analyzeUrl(
    `https://example.org/go?u=${encodeURIComponent(b64)}`
  );

  assert.equal(result.decision, "BLOCK");
  assert.ok(result.indicators.includes("BASE64_SMUGGLED_REDIRECT"));
  assert.equal(JSON.stringify(result).includes("192.168.1.1"), false);
});

test("Blocks obfuscated decimal/hex IPv4 pointing to loopback or private network", () => {
  // 2130706433 === 127.0.0.1
  const decimalLoopback = analyzeUrl("http://2130706433/login");
  assert.equal(decimalLoopback.decision, "BLOCK");
  assert.equal(decimalLoopback.reasonCodes[0], "NON_PUBLIC_IP_ADDRESS");

  // 0xc0a80101 === 192.168.1.1
  const hexPrivate = analyzeUrl("http://0xc0a80101/admin");
  assert.equal(hexPrivate.decision, "BLOCK");
  assert.equal(hexPrivate.reasonCodes[0], "NON_PUBLIC_IP_ADDRESS");
});

test("Blocks AWS/cloud link-local metadata IP 169.254.169.254", () => {
  const result = analyzeUrl("http://169.254.169.254/latest/meta-data/");
  assert.equal(result.decision, "BLOCK");
  assert.equal(result.reasonCodes[0], "NON_PUBLIC_IP_ADDRESS");
});

test("Blocks dangerous non-web port (SSH port 22 / RDP 3389)", () => {
  const result = analyzeUrl("http://example.com:3389/connect");
  assert.equal(result.decision, "BLOCK");
  assert.equal(result.reasonCodes[0], "DANGEROUS_NON_WEB_PORT");
});

test("Blocks bidi override characters even when percent-encoded (%E2%80%AE)", () => {
  const result = analyzeUrl("https://example.com/invoice%E2%80%AEfdp.exe");
  assert.equal(result.decision, "BLOCK");
  assert.equal(result.reasonCodes[0], "ENCODED_SPOOF_OR_NULL_SEQUENCE");
});

test("Official Indian bank domain with normal path stays clean locally", () => {
  const result = analyzeUrl("https://www.hdfcbank.com/personal/pay/cards");

  assert.equal(result.decision, "REPUTATION_CHECK_REQUIRED");
  assert.equal(result.riskScore, 0);
  assert.equal(result.redactedDestination.originOnly, "https://www.hdfcbank.com");
  assert.equal(result.redactedDestination.privateComponentsStripped, true);
});

// --------------------------------------------------
// 2. ZERO-LEAKAGE PRIVACY GUARANTEES
// --------------------------------------------------

test("Sensitive UUID/token subdomain is excluded from outbound Google hash prefixes", () => {
  const secretSubdomain = "550e8400-e29b-41d4-a716-446655440000";
  const withSecret = createGoogleHashData(
    `https://${secretSubdomain}.example.com/reset?otp=123456`
  );
  const rootOnly = createGoogleHashData("https://example.com/");

  assert.deepEqual(withSecret, rootOnly);
});

test("verifyUrl never leaks path, query string, secret tokens, or fragments", async () => {
  const secretUrl =
    "https://www.sbi.co.in/private-account-view/statement?accountNo=987654321012&otp=445566#session-secret-xyz";

  const result = await verifyUrl(secretUrl, "test-req-1");

  assert.equal(verifyNoPrivateUrlLeak(secretUrl, result), true);
  assert.equal(JSON.stringify(result).includes("987654321012"), false);
  assert.equal(JSON.stringify(result).includes("445566"), false);
  assert.equal(JSON.stringify(result).includes("private-account-view"), false);
  assert.equal(JSON.stringify(result).includes("session-secret-xyz"), false);
  assert.equal(
    result.localVerification.redactedDestination.originOnly,
    "https://www.sbi.co.in"
  );
});

test("Offline known-safe fast-pass only activates when explicitly enabled", () => {
  const cleanLocal = { decision: "REPUTATION_CHECK_REQUIRED", riskScore: 0 };
  const offlineGoogle = { status: "OFFLINE_MODE_SKIPPED" };

  const held = calculateFinalDecision(cleanLocal, offlineGoogle, "sbi.co.in", {
    offlineAllowKnownSafe: false
  });
  assert.equal(held.finalDecision, "HOLD");

  const allowed = calculateFinalDecision(cleanLocal, offlineGoogle, "sbi.co.in", {
    offlineAllowKnownSafe: true
  });
  assert.equal(allowed.finalDecision, "KNOWN_SAFE");
  assert.equal(allowed.recommendedAction, "ALLOW");
});

// --------------------------------------------------
// 3. EPHEMERAL REDIRECT AUTHORIZATION TOKEN
// --------------------------------------------------

test("Redirect token binds strictly to URL and blocks tampering or unconfirmed warnings", () => {
  const safeUrl = "https://www.google.com/search?q=weather";
  const token = issueRedirectToken({
    url: safeUrl,
    finalDecision: "KNOWN_SAFE",
    recommendedAction: "ALLOW",
    requestId: "req-1"
  });

  assert.ok(token);

  const ok = verifyRedirectToken({ url: safeUrl, token });
  assert.equal(ok.authorized, true);

  // URL swap attack must fail
  const swapped = verifyRedirectToken({
    url: "https://evil-phish.xyz/steal",
    token
  });
  assert.equal(swapped.authorized, false);
  assert.equal(swapped.reasonCode, "URL_BINDING_MISMATCH");

  // Tampered token signature must fail
  const tampered = verifyRedirectToken({
    url: safeUrl,
    token: `${token.slice(0, -3)}AAA`
  });
  assert.equal(tampered.authorized, false);

  // BLOCK verdict never receives a token
  const blockedToken = issueRedirectToken({
    url: "https://evil.xyz/hack.apk",
    finalDecision: "BLOCK",
    recommendedAction: "DO_NOT_OPEN",
    requestId: "req-2"
  });
  assert.equal(blockedToken, null);

  // WARN_USER requires explicit confirmation
  const warnToken = issueRedirectToken({
    url: "https://bit.ly/abc",
    finalDecision: "SUSPICIOUS",
    recommendedAction: "WARN_USER",
    requestId: "req-3"
  });
  const unconfirmed = verifyRedirectToken({
    url: "https://bit.ly/abc",
    token: warnToken,
    userConfirmedWarning: false
  });
  assert.equal(unconfirmed.authorized, false);
  assert.equal(unconfirmed.reasonCode, "USER_WARNING_CONFIRMATION_REQUIRED");

  const confirmed = verifyRedirectToken({
    url: "https://bit.ly/abc",
    token: warnToken,
    userConfirmedWarning: true
  });
  assert.equal(confirmed.authorized, true);
});

// --------------------------------------------------
// 4. FULL HTTP API INTEGRATION CHECK (NO-LEAK & HEADERS)
// --------------------------------------------------

test("HTTP API blocks scam SMS link, sets strict no-store/no-referrer headers, and rejects forged input", async () => {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // Health endpoint
    const healthRes = await fetch(`${baseUrl}/api/v1/health`);
    assert.equal(healthRes.status, 200);
    const healthBody = await healthRes.json();
    assert.equal(healthBody.application, "SafeGate");
    assert.equal(healthBody.zeroUrlRetention, true);
    assert.equal(
      healthRes.headers.get("cache-control"),
      "no-store, no-cache, must-revalidate, private"
    );
    assert.equal(healthRes.headers.get("referrer-policy"), "no-referrer");

    // Verify malicious SMS phishing URL
    const scamRes = await fetch(`${baseUrl}/api/v1/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://sbi-alert.xyz/amount-credited/kyc?otp=882211"
      })
    });
    assert.equal(scamRes.status, 200);
    const scamBody = await scamRes.json();
    assert.equal(scamBody.finalDecision, "BLOCK");
    assert.equal(scamBody.recommendedAction, "DO_NOT_OPEN");
    assert.equal(scamBody.verificationToken, null);
    assert.equal(JSON.stringify(scamBody).includes("882211"), false);
    assert.equal(JSON.stringify(scamBody).includes("amount-credited"), false);

    // Reject dangerous javascript: scheme at boundary
    const xssRes = await fetch(`${baseUrl}/api/v1/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "javascript:alert(1)" })
    });
    assert.equal(xssRes.status, 400);

    // Reject extra unexpected fields
    const shapeRes = await fetch(`${baseUrl}/api/v1/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://google.com", extra: "bad" })
    });
    assert.equal(shapeRes.status, 400);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
