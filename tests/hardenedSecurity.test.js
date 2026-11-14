"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { domainToASCII } = require("node:url");

const app = require("../src/app");
const { analyzeUrl } = require("../src/security/urlAnalyzer");
const { verifyNoPrivateUrlLeak } = require("../src/security/privacyGuard");
const {
  issueRedirectToken,
  verifyRedirectToken
} = require("../src/security/redirectToken");
const { verifyUrl } = require("../src/services/verification.service");

// --------------------------------------------------
// 1. NEXT-LEVEL PARENTS SMS / WHATSAPP SCAM & MALWARE PROTECTION
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

test("Blocks brand domain spoofed inside subdomain (sbi.co.in.verify-login.com)", () => {
  const result = analyzeUrl("https://sbi.co.in.verify-login.com/auth");

  assert.equal(result.decision, "BLOCK");
  assert.ok(result.indicators.includes("BRAND_DOMAIN_SPOOFED_IN_SUBDOMAIN"));
});

test("Blocks double-extension masquerade malware (statement.pdf.apk / invoice.docx.exe)", () => {
  const apkMasq = analyzeUrl("https://example.org/files/statement.pdf.apk");
  assert.equal(apkMasq.decision, "BLOCK");
  assert.equal(apkMasq.reasonCodes[0], "DOUBLE_EXTENSION_MASQUERADE");

  const exeMasq = analyzeUrl("https://example.org/files/invoice.docx.exe");
  assert.equal(exeMasq.decision, "BLOCK");
  assert.equal(exeMasq.reasonCodes[0], "DOUBLE_EXTENSION_MASQUERADE");
});

test("Blocks phishing pages hosted on free UGC/cloud platforms (sites.google.com, ngrok, workers.dev)", () => {
  const sitesPhish = analyzeUrl(
    "https://sites.google.com/view/hdfc-kyc-update-alert/claim"
  );
  assert.equal(sitesPhish.decision, "BLOCK");
  assert.equal(sitesPhish.reasonCodes[0], "ABUSED_HOSTING_PHISHING_PATTERN");

  const tunnelPhish = analyzeUrl(
    "https://9a12-evil.ngrok-free.app/sbi/amount-credited"
  );
  assert.equal(tunnelPhish.decision, "BLOCK");
  assert.equal(tunnelPhish.reasonCodes[0], "TUNNEL_OR_IP_PHISHING_PATTERN");
});

test("Blocks Android APK sideload malware delivered with SMS lure or HTTP", () => {
  const result = analyzeUrl("http://rewards-claim.top/SBI_KYC_Update.apk");
  assert.equal(result.decision, "BLOCK");
  assert.ok(result.indicators.includes("MOBILE_SIDELOAD_INSTALLER_PATH"));
});

test("Flags standalone Android APK download on HTTPS as SUSPICIOUS", () => {
  const result = analyzeUrl("https://unknown-mirror.org/files/app-release.apk");
  assert.equal(result.decision, "SUSPICIOUS");
  assert.ok(result.indicators.includes("MOBILE_SIDELOAD_INSTALLER_PATH"));
});

test("Flags URL shorteners on HTTPS as SUSPICIOUS and blocks unencrypted HTTP shorteners", () => {
  const httpsShort = analyzeUrl("https://bit.ly/3xFakeBankSms");
  assert.equal(httpsShort.decision, "SUSPICIOUS");
  assert.ok(httpsShort.indicators.includes("URL_SHORTENER_HIDES_DESTINATION"));

  const httpShort = analyzeUrl("http://bit.ly/3xFakeBankSms");
  assert.equal(httpShort.decision, "BLOCK");
});

test("Blocks Cyrillic homograph brand impersonation (mixed-script and pure-Cyrillic xn--)", () => {
  const mixed = analyzeUrl("https://xn--bi-doc.co.in/login");
  assert.equal(mixed.decision, "BLOCK");
  assert.ok(mixed.indicators.includes("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION"));

  const pureCyrillicHost = domainToASCII("\u0430\u0440\u0440\u04CF\u0435.com");
  const pure = analyzeUrl(`https://${pureCyrillicHost}/signin`);
  assert.equal(pure.decision, "BLOCK");
  assert.ok(pure.indicators.includes("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION"));
});

test("Flags leet-speak / brand-in-unrelated-domain lookalikes", () => {
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

test("Blocks nested redirect targeting an Android APK payload", () => {
  const result = analyzeUrl(
    "https://example.org/go?next=https%3A%2F%2Fmirror.example.net%2Fupdate.apk"
  );
  assert.equal(result.decision, "BLOCK");
  assert.equal(result.reasonCodes[0], "NESTED_REDIRECT_TO_MOBILE_INSTALLER");
});

test("Blocks Base64-smuggled and Hex-smuggled dangerous redirects", () => {
  const b64 = Buffer.from("http://192.168.1.1/admin", "utf8").toString("base64");
  const b64Res = analyzeUrl(`https://example.org/go?u=${encodeURIComponent(b64)}`);
  assert.equal(b64Res.decision, "BLOCK");
  assert.ok(b64Res.indicators.includes("BASE64_SMUGGLED_REDIRECT"));
  assert.equal(JSON.stringify(b64Res).includes("192.168.1.1"), false);

  const hex = Buffer.from("javascript:alert(1)", "utf8").toString("hex");
  const hexRes = analyzeUrl(`https://example.org/go?u=${hex}`);
  assert.equal(hexRes.decision, "BLOCK");
  assert.ok(hexRes.indicators.includes("HEX_SMUGGLED_REDIRECT"));
});

test("Blocks obfuscated decimal/hex IPv4 pointing to loopback or private network", () => {
  const decimalLoopback = analyzeUrl("http://2130706433/login");
  assert.equal(decimalLoopback.decision, "BLOCK");
  assert.equal(decimalLoopback.reasonCodes[0], "NON_PUBLIC_IP_ADDRESS");

  const hexPrivate = analyzeUrl("http://0xc0a80101/admin");
  assert.equal(hexPrivate.decision, "BLOCK");
  assert.equal(hexPrivate.reasonCodes[0], "NON_PUBLIC_IP_ADDRESS");
});

test("Blocks AWS/cloud link-local metadata IP 169.254.169.254", () => {
  const result = analyzeUrl("http://169.254.169.254/latest/meta-data/");
  assert.equal(result.decision, "BLOCK");
  assert.equal(result.reasonCodes[0], "NON_PUBLIC_IP_ADDRESS");
});

test("Blocks dangerous non-web port (RDP 3389 / SSH 22)", () => {
  const result = analyzeUrl("http://example.com:3389/connect");
  assert.equal(result.decision, "BLOCK");
  assert.equal(result.reasonCodes[0], "DANGEROUS_NON_WEB_PORT");
});

test("Blocks bidi override characters even when percent-encoded (%E2%80%AE)", () => {
  const result = analyzeUrl("https://example.com/invoice%E2%80%AEfdp.exe");
  assert.equal(result.decision, "BLOCK");
  assert.equal(result.reasonCodes[0], "ENCODED_SPOOF_OR_NULL_SEQUENCE");
});

test("Blocks DGA high-entropy phishing domain on high-risk TLD", () => {
  const result = analyzeUrl("https://x8k2q9m4z7p1w3v5.xyz/login");
  assert.equal(result.decision, "BLOCK");
  assert.ok(result.indicators.includes("HIGH_ENTROPY_DGA_DOMAIN"));
});

// --------------------------------------------------
// 2. OFFICIAL BANKING & ZERO-EGRESS PRIVACY GUARANTEES
// --------------------------------------------------

test("Official Indian bank link verifies as KNOWN_SAFE / ALLOW on-device with zero leak", async () => {
  const secretUrl =
    "https://www.sbi.co.in/personal/dashboard?accountNo=987654321012&otp=445566#session-secret-xyz";

  const result = await verifyUrl(secretUrl, "test-req-sbi");

  assert.equal(result.finalDecision, "KNOWN_SAFE");
  assert.equal(result.recommendedAction, "ALLOW");
  assert.ok(result.verificationToken);
  assert.equal(result.privacy.outboundNetworkCalls, 0);
  assert.equal(result.privacy.zeroEgressOnDevice, true);
  assert.equal(verifyNoPrivateUrlLeak(secretUrl, result), true);
  assert.equal(JSON.stringify(result).includes("987654321012"), false);
  assert.equal(JSON.stringify(result).includes("445566"), false);
  assert.equal(JSON.stringify(result).includes("session-secret-xyz"), false);
  assert.equal(
    result.localVerification.redactedDestination.originOnly,
    "https://www.sbi.co.in"
  );
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

  const swapped = verifyRedirectToken({
    url: "https://evil-phish.xyz/steal",
    token
  });
  assert.equal(swapped.authorized, false);
  assert.equal(swapped.reasonCode, "URL_BINDING_MISMATCH");

  const tampered = verifyRedirectToken({
    url: safeUrl,
    token: `${token.slice(0, -3)}AAA`
  });
  assert.equal(tampered.authorized, false);

  const blockedToken = issueRedirectToken({
    url: "https://evil.xyz/hack.apk",
    finalDecision: "BLOCK",
    recommendedAction: "DO_NOT_OPEN",
    requestId: "req-2"
  });
  assert.equal(blockedToken, null);

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
// 4. FULL HTTP API INTEGRATION CHECK
// --------------------------------------------------

test("HTTP API verifies safe bank link, blocks scam SMS link, and never returns Google fields", async () => {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const healthRes = await fetch(`${baseUrl}/api/v1/health`);
    assert.equal(healthRes.status, 200);
    const healthBody = await healthRes.json();
    assert.equal(healthBody.privacyMode, "ZERO_EGRESS_ON_DEVICE_ONLY");
    assert.equal(healthBody.outboundNetworkCalls, 0);

    // Safe bank URL -> KNOWN_SAFE + token + authorize-redirect succeeds
    const safeRes = await fetch(`${baseUrl}/api/v1/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://www.hdfcbank.com/personal/pay?secret=mysecretvalue"
      })
    });
    assert.equal(safeRes.status, 200);
    const safeBody = await safeRes.json();
    assert.equal(safeBody.finalDecision, "KNOWN_SAFE");
    assert.equal(safeBody.recommendedAction, "ALLOW");
    assert.ok(safeBody.verificationToken);
    assert.equal("googleVerification" in safeBody, false);
    assert.equal(JSON.stringify(safeBody).includes("mysecretvalue"), false);

    const authRes = await fetch(`${baseUrl}/api/v1/verify/authorize-redirect`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://www.hdfcbank.com/personal/pay?secret=mysecretvalue",
        verificationToken: safeBody.verificationToken
      })
    });
    assert.equal(authRes.status, 200);
    const authBody = await authRes.json();
    assert.equal(authBody.authorized, true);

    // Scam SMS link -> BLOCK locally
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
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
