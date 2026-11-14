"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

test("Client offline analyzer blocks phishing kit, allows official bank, and holds unknown domain", async () => {
  const { analyzeUrlOffline } = await import("../src/security/offlineEngine.js");

  const bank = analyzeUrlOffline("https://www.sbi.co.in/personal?otp=112233");
  assert.equal(bank.finalDecision, "KNOWN_SAFE");
  assert.equal(bank.privacy.outboundNetworkCalls, 0);
  assert.equal(JSON.stringify(bank).includes("112233"), false);

  const phish = analyzeUrlOffline("https://testsafebrowsing.appspot.com/s/phishing.html");
  assert.equal(phish.finalDecision, "BLOCK");

  const apkScam = analyzeUrlOffline("http://rewards-claim.top/SBI_KYC_Update.apk");
  assert.equal(apkScam.finalDecision, "BLOCK");

  const shortener = analyzeUrlOffline("https://bit.ly/3xFakeBankSms");
  assert.equal(shortener.finalDecision, "SUSPICIOUS");

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
