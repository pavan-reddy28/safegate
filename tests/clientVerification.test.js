"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { domainToASCII } = require("node:url");

test("Client offline 30-layer engine blocks phishing kits, allows official banks/Wiki, warns suspicious, and holds unknown", async () => {
  const { analyzeUrlOffline } = await import("../src/security/offlineEngine.js");

  // 1. Official trusted HTTPS URLs -> KNOWN_SAFE
  const bank = analyzeUrlOffline("https://www.sbi.co.in/personal?otp=112233");
  assert.equal(bank.finalDecision, "KNOWN_SAFE");
  assert.equal(bank.layersExecuted.length, 30);
  assert.equal(bank.privacy.outboundNetworkCalls, 0);
  assert.equal(JSON.stringify(bank).includes("112233"), false);

  const wikiPhishArticle = analyzeUrlOffline("https://en.wikipedia.org/wiki/Phishing");
  assert.equal(wikiPhishArticle.finalDecision, "KNOWN_SAFE");

  const dnsIp = analyzeUrlOffline("https://1.1.1.1/dns-query");
  assert.equal(dnsIp.finalDecision, "KNOWN_SAFE");

  // 2. Confirmed phishing / malware / spoofs -> BLOCK (never HOLD)
  const blockCases = [
    "https://testsafebrowsing.appspot.com/s/phishing.html",
    "http://rewards-claim.top/SBI_KYC_Update.apk",
    "https://sbi-kyc-update.xyz/amount-credited/claim?account=1234567890&otp=998877",
    "https://sbi.co.in.verify-login.com/auth",
    "https://myregionalbank.com.security-check-99.net/auth",
    "https://example.org/files/statement.pdf.apk",
    "https://sites.google.com/view/hdfc-kyc-update-alert/claim",
    "https://9a12-evil.ngrok-free.app/sbi/amount-credited",
    "http://bit.ly/3xFakeBankSms",
    "https://xn--bi-doc.co.in/login",
    `https://${domainToASCII("\u0430\u0440\u0440\u04CF\u0435.com")}/signin`,
    `https://${domainToASCII("p\u00E0ypal.com")}/verify-account`,
    "https://hdfc-netbanking-verify.com/login",
    "https://secure-verify-account-update-portal.xyz/signin",
    "https://local-bakery-shop.com/wp-content/uploads/2026/auth/update.php",
    "https://webmail-portal-access.com/auth/confirm.html#mom@gmail.com",
    "http://xkqpwzrtm.com/verify",
    "https://unseen-domain-example.com/portal/confirm-overdue-invoice-shipment",
    "http://45.133.1.2/verify-account/update.apk",
    "http://192.168.1.25/login",
    "http://169.254.169.254/latest/meta-data/",
    "http://2130706433/login",
    "https://93.184.216.34:8443/webmail",
    "https://example.org/go?next=https%3A%2F%2Fsbi-kyc-update.xyz%2Famount-credited",
    "https://example.org/go?next=https%3A%2F%2Fmirror.example.net%2Fupdate.apk",
    "https://example.org/redirect?next=javascript%3Aalert(1)",
    "https://example.org/go#Intent;scheme=upi;package=com.evil;end",
    "https://cashback-offer-2026.xyz/claim?pa=scammer@okaxis&am=19999",
    "https://example.org/login%ZZ"
  ];

  for (const url of blockCases) {
    const res = analyzeUrlOffline(url);
    assert.equal(res.finalDecision, "BLOCK", `Expected BLOCK for ${url}, got ${res.finalDecision} (${res.finalReasonCodes})`);
    assert.equal(res.verificationToken, null);
  }

  // 3. Base64 & Hex smuggled redirects in offline engine -> BLOCK without leaking decoded secret
  const b64 = Buffer.from("http://192.168.1.1/admin", "utf8").toString("base64");
  const b64Res = analyzeUrlOffline(`https://example.org/go?u=${encodeURIComponent(b64)}`);
  assert.equal(b64Res.finalDecision, "BLOCK");
  assert.equal(JSON.stringify(b64Res).includes("192.168.1.1"), false);

  const hex = Buffer.from("javascript:alert(1)", "utf8").toString("hex");
  const hexRes = analyzeUrlOffline(`https://example.org/go?u=${hex}`);
  assert.equal(hexRes.finalDecision, "BLOCK");

  // 4. Suspicious links -> SUSPICIOUS
  for (const warnUrl of [
    "https://bit.ly/3xFakeBankSms",
    "https://paypa1-mirror.com/home",
    "https://unknown-mirror.org/files/app-release.apk",
    "https://93.184.216.34/status"
  ]) {
    const res = analyzeUrlOffline(warnUrl);
    assert.equal(res.finalDecision, "SUSPICIOUS", `Expected SUSPICIOUS for ${warnUrl}, got ${res.finalDecision}`);
  }

  // 5. Truly unknown clean HTTPS domain -> HOLD
  const unknown = analyzeUrlOffline("https://example.org/docs/guide");
  assert.equal(unknown.finalDecision, "HOLD");
});

test("Local URL fingerprint canonicalizes URLs cleanly with zero private secret leakage", async () => {
  const { canonicalizeUrl, createDeviceUrlFingerprint } = await import("../src/security/urlFingerprint.js");

  const canonical = canonicalizeUrl("https://WWW.SBI.CO.IN/personal//banking?otp=9911");
  assert.equal(canonical.hostname, "www.sbi.co.in");
  assert.equal(canonical.pathname, "/personal/banking");
  assert.equal(canonical.originOnly, "https://www.sbi.co.in");

  const fp = await createDeviceUrlFingerprint("https://www.sbi.co.in/personal?otp=9911");
  assert.match(fp.fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(fp.originOnly, "https://www.sbi.co.in");
  assert.equal(JSON.stringify(fp).includes("9911"), false);
});

test("verificationService never degrades to HOLD on storage failure or malformed percent encoding", async () => {
  // Simulate Vite/Capacitor browser globals absent in Node test runner (no IndexedDB, no running backend)
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("Offline device daemon unavailable");
  };

  try {
    const { verifyDestination } = await import("../src/security/verificationService.js");

    const phishRes = await verifyDestination("https://testsafebrowsing.appspot.com/s/phishing.html");
    assert.equal(phishRes.finalDecision, "BLOCK");

    const malformedRes = await verifyDestination("https://evil.com/login%ZZ");
    assert.equal(malformedRes.finalDecision, "BLOCK");

    const safeRes = await verifyDestination("https://www.sbi.co.in/home");
    assert.equal(safeRes.finalDecision, "KNOWN_SAFE");

    const warnRes = await verifyDestination("https://bit.ly/3xFakeBankSms");
    assert.equal(warnRes.finalDecision, "SUSPICIOUS");

    const holdRes = await verifyDestination("https://example.org/docs/guide");
    assert.equal(holdRes.finalDecision, "HOLD");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("externalBrowser validates strict http/https URLs before launching Chrome or external browser", async () => {
  const { isValidExternalHttpUrl } = await import("../src/native/externalBrowser.js");

  assert.equal(isValidExternalHttpUrl("https://api.pavanserver.me/healthy"), true);
  assert.equal(isValidExternalHttpUrl("http://example.org/path"), true);
  assert.equal(isValidExternalHttpUrl("javascript:alert(1)"), false);
  assert.equal(isValidExternalHttpUrl("intent://scan/#Intent;end"), false);
  assert.equal(isValidExternalHttpUrl("https://user:pass@example.com/"), false);
  assert.equal(isValidExternalHttpUrl("file:///etc/passwd"), false);
});
