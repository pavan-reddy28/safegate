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

test("Blocks bank+verify+login phishing and flags standalone brand lookalikes as SUSPICIOUS", () => {
  const bankPhish = analyzeUrl("https://hdfc-netbanking-verify.com/login");
  assert.equal(bankPhish.decision, "BLOCK");
  assert.ok(bankPhish.indicators.includes("BRAND_NAME_IN_UNRELATED_DOMAIN"));

  const standaloneLookalike = analyzeUrl("https://paypa1-mirror.com/home");
  assert.equal(standaloneLookalike.decision, "SUSPICIOUS");
  assert.ok(standaloneLookalike.indicators.includes("BRAND_NAME_IN_UNRELATED_DOMAIN"));
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

test("Auto-detects Google Safe Browsing test URL algorithmically without any hardcoded blocklist entry", () => {
  const gsbTest = analyzeUrl("https://testsafebrowsing.appspot.com/s/phishing.html");
  assert.equal(gsbTest.decision, "BLOCK");
  assert.notEqual(gsbTest.reasonCodes[0], "LOCAL_THREAT_LIST_MATCH");

  const genericAppEnginePhish = analyzeUrl("https://custom-phish-app-42.appspot.com/s/phishing.html");
  assert.equal(genericAppEnginePhish.decision, "BLOCK");

  const cloudLoginKit = analyzeUrl("https://client-portal-99.pages.dev/webmail/signin.html");
  assert.equal(cloudLoginKit.decision, "BLOCK");
  assert.equal(cloudLoginKit.reasonCodes[0], "ABUSED_HOSTING_PHISHING_PATTERN");
});

test("Blocks global parcel/customs, crypto seed/airdrop, tech-support, and account-lock scams", () => {
  const parcel = analyzeUrl("https://fedex-parcel-hold.top/customs-clearance/address-update");
  assert.equal(parcel.decision, "BLOCK");

  const crypto = analyzeUrl("https://metamask-reward.vip/airdrop/connect-wallet");
  assert.equal(crypto.decision, "BLOCK");

  const scareware = analyzeUrl("https://security-alert-support.club/virus-detected");
  assert.equal(scareware.decision, "BLOCK");

  const deceptiveHyphenKit = analyzeUrl("https://secure-verify-account-update-portal.xyz/signin");
  assert.equal(deceptiveHyphenKit.decision, "BLOCK");
});

test("Zero-day brand-agnostic engine blocks compromised CMS kits, subdomain TLD spoofing, fragment email prefills, and short DGAs", () => {
  // Compromised WordPress/asset folder dropping a static/php phishing kit on an unseen .com domain
  const wpKit = analyzeUrl("https://local-bakery-shop.com/wp-content/uploads/2026/auth/update.php");
  assert.equal(wpKit.decision, "BLOCK");
  assert.equal(wpKit.reasonCodes[0], "COMPROMISED_WEBSITE_PHISHING_KIT");

  // Unknown brand spoofed using embedded TLD in subdomain
  const subTldSpoof = analyzeUrl("https://myregionalbank.com.security-check-99.net/auth");
  assert.equal(subTldSpoof.decision, "BLOCK");
  assert.ok(subTldSpoof.indicators.includes("UNIVERSAL_SUBDOMAIN_TLD_MASQUERADING"));

  // Fragment email prefill phishing kit (#victim@email.com or Base64 email) never leaked
  const fragEmailKit = analyzeUrl("https://webmail-portal-access.com/auth/confirm.html#mom@gmail.com");
  assert.equal(fragEmailKit.decision, "BLOCK");
  assert.equal(JSON.stringify(fragEmailKit).includes("mom@gmail.com"), false);

  const b64Email = Buffer.from("dad@yahoo.com", "utf8").toString("base64");
  const fragB64Kit = analyzeUrl(`https://doc-view-access.net/invoice/signin.html#${b64Email}`);
  assert.equal(fragB64Kit.decision, "BLOCK");
  assert.equal(JSON.stringify(fragB64Kit).includes(b64Email), false);

  // Short random consonant-cluster DGA domain with lure path on unseen .com/.org
  const shortDga = analyzeUrl("http://xkqpwzrtm.com/verify");
  assert.equal(shortDga.decision, "BLOCK");
  assert.ok(shortDga.indicators.includes("ALGORITHMIC_DGA_HOST_ANOMALY"));

  // 3+ distinct social engineering intent vectors on an unknown clean .com
  const multiVector = analyzeUrl("https://unseen-domain-example.com/portal/confirm-overdue-invoice-shipment");
  assert.equal(multiVector.decision, "BLOCK");
  assert.equal(multiVector.reasonCodes[0], "MULTI_VECTOR_PHISHING_DETECTED");
});

test("Allows legitimate educational Wikipedia phishing article as KNOWN_SAFE", async () => {
  const wiki = await verifyUrl("https://en.wikipedia.org/wiki/Phishing", "req-wiki-safe");
  assert.equal(wiki.finalDecision, "KNOWN_SAFE");
  assert.equal(wiki.recommendedAction, "ALLOW");
});

test("Differentiates clean trusted public DNS IPs, suspicious unknown public IPs, obfuscated public IPs, and blocked private/mapped IPs", async () => {
  // Clean HTTPS trusted infrastructure IP -> KNOWN_SAFE / ALLOW
  const safeDnsIp = await verifyUrl("https://1.1.1.1/dns-query", "req-ip-dns");
  assert.equal(safeDnsIp.finalDecision, "KNOWN_SAFE");
  assert.equal(safeDnsIp.recommendedAction, "ALLOW");

  // Clean unknown public IP over HTTPS -> SUSPICIOUS / WARN_USER (not blindly blocked)
  const warnPublicIp = await verifyUrl("https://93.184.216.34/status", "req-ip-warn");
  assert.equal(warnPublicIp.finalDecision, "SUSPICIOUS");
  assert.equal(warnPublicIp.recommendedAction, "WARN_USER");

  // Phishing public IP over HTTP with lure/APK -> BLOCK
  const phishIp = await verifyUrl("http://45.133.1.2/verify-account/update.apk", "req-ip-phish");
  assert.equal(phishIp.finalDecision, "BLOCK");
  assert.equal(phishIp.recommendedAction, "DO_NOT_OPEN");

  // Obfuscated decimal public IP -> BLOCK (deliberate evasion)
  const obfPublicIp = analyzeUrl("http://134744072/");
  assert.equal(obfPublicIp.decision, "BLOCK");
  assert.equal(obfPublicIp.reasonCodes[0], "OBFUSCATED_IP_EVASION");

  // Private, CGNAT, IPv4-mapped loopback & NAT64 loopback -> BLOCK
  for (const badIpUrl of [
    "http://100.64.0.1/portal",
    "http://[::ffff:127.0.0.1]/admin",
    "http://[64:ff9b::7f00:1]/login"
  ]) {
    const res = analyzeUrl(badIpUrl);
    assert.equal(res.decision, "BLOCK");
    assert.equal(res.reasonCodes[0], "NON_PUBLIC_IP_ADDRESS");
  }
});

test("Differentiates clean HTTPS open-source APKs (SUSPICIOUS/WARN_USER) from malicious or query-smuggled APKs (BLOCK)", async () => {
  const cleanGithubApk = await verifyUrl(
    "https://github.com/myorg/open-app/releases/download/v1.0/open-app.apk",
    "req-apk-clean"
  );
  assert.equal(cleanGithubApk.finalDecision, "SUSPICIOUS");
  assert.equal(cleanGithubApk.recommendedAction, "WARN_USER");

  const scamGithubApk = await verifyUrl(
    "https://github.com/evil/sbi-kyc/releases/download/v1/SBI_KYC_Update.apk",
    "req-apk-scam"
  );
  assert.equal(scamGithubApk.finalDecision, "BLOCK");

  const httpApk = await verifyUrl("http://mirror.example.org/app-release.apk", "req-apk-http");
  assert.equal(httpApk.finalDecision, "BLOCK");

  const querySmuggledMasq = analyzeUrl("https://example.org/download?file=statement.pdf.apk");
  assert.equal(querySmuggledMasq.decision, "BLOCK");
  assert.equal(querySmuggledMasq.reasonCodes[0], "DOUBLE_EXTENSION_MASQUERADE");
});

test("Blocks custom-parameter redirects, backslash protocol-relative redirects, and multi-hop scam redirects", () => {
  const customParamPrivateIp = analyzeUrl("https://example.org/view?r=http%3A%2F%2F192.168.1.1%2Fadmin");
  assert.equal(customParamPrivateIp.decision, "BLOCK");

  const customParamJs = analyzeUrl("https://example.org/view?foo=javascript%3Aalert(1)");
  assert.equal(customParamJs.decision, "BLOCK");

  const backslashRedirect = analyzeUrl("https://example.org/go?next=%5C%5Cevil.com%2Flogin");
  assert.equal(backslashRedirect.decision, "BLOCK");

  const multiHopPhish = analyzeUrl(
    "https://example.org/go?next=https%3A%2F%2Fsbi-kyc-update.xyz%2Famount-credited"
  );
  assert.equal(multiHopPhish.decision, "BLOCK");
});

test("Unverified clean HTTPS site results in HOLD when reputation is unavailable and gates authorize-redirect", async () => {
  const held = await verifyUrl("https://small-local-shop-example.org/catalog", "req-hold-1");
  assert.equal(held.finalDecision, "HOLD");
  assert.equal(held.recommendedAction, "HOLD");
  assert.ok(held.verificationToken);

  const unconfirmed = verifyRedirectToken({
    url: "https://small-local-shop-example.org/catalog",
    token: held.verificationToken,
    userConfirmedWarning: false
  });
  assert.equal(unconfirmed.authorized, false);
  assert.equal(unconfirmed.reasonCode, "HOLD_REPUTATION_UNAVAILABLE_CONFIRMATION_REQUIRED");

  const confirmed = verifyRedirectToken({
    url: "https://small-local-shop-example.org/catalog",
    token: held.verificationToken,
    userConfirmedWarning: true
  });
  assert.equal(confirmed.authorized, true);
});

test("Blocks Android content://, payment deep-links, and tab-obfuscated javascript schemes at HTTP boundary", async () => {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    for (const badUri of [
      "content://sms/inbox",
      "paytmmp://pay?pa=fraud@paytm",
      "java\tscript:alert(1)"
    ]) {
      const res = await fetch(`${baseUrl}/api/v1/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Request-Source": "a1b2c3d4e5f60001"
        },
        body: JSON.stringify({ url: badUri })
      });
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.error.code, "FORBIDDEN_URL_CONTENT");
    }
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Blocks open-redirect bypass attempts via known-safe redirectors (google.com/url?q=...) and preserves Google search", async () => {
  const legitSearch = await verifyUrl("https://www.google.com/search?q=weather", "req-google-search");
  assert.equal(legitSearch.finalDecision, "KNOWN_SAFE");

  const openRedirectLookalike = await verifyUrl(
    "https://www.google.com/url?q=https%3A%2F%2Fpaypa1-mirror.com%2Fhome",
    "req-google-redir-warn"
  );
  assert.notEqual(openRedirectLookalike.finalDecision, "KNOWN_SAFE");
  assert.ok(["SUSPICIOUS", "BLOCK"].includes(openRedirectLookalike.finalDecision));

  const openRedirectKit = await verifyUrl(
    "https://www.google.com/url?q=https%3A%2F%2Funseen-domain-example.com%2Fwp-content%2Fuploads%2Flogin.php",
    "req-google-redir-kit"
  );
  assert.equal(openRedirectKit.finalDecision, "BLOCK");
});

test("Blocks fragment smuggling, triple-encoded redirects, and Base64 HTML-smuggling payloads", () => {
  const fragUrl = analyzeUrl("https://example.org/view#http://192.168.1.1/admin");
  assert.equal(fragUrl.decision, "BLOCK");

  const b64Html = Buffer.from("<script>window.location=atob('aHR0cDovL2V2aWwuY29t')</script>", "utf8").toString("base64");
  const htmlSmuggle = analyzeUrl(`https://example.org/doc?payload=${encodeURIComponent(b64Html)}`);
  assert.equal(htmlSmuggle.decision, "BLOCK");
  assert.equal(htmlSmuggle.reasonCodes[0], "HTML_SMUGGLING_PAYLOAD_DETECTED");

  const fragB64Redirect = Buffer.from("javascript:alert(document.cookie)", "utf8").toString("base64");
  const fragSmuggle = analyzeUrl(`https://example.org/viewer#${fragB64Redirect}`);
  assert.equal(fragSmuggle.decision, "BLOCK");

  const fragKeyPair = analyzeUrl("https://example.org/app#url=upi://pay?pa=scam@okicici&am=5000");
  assert.equal(fragKeyPair.decision, "BLOCK");
});

test("Blocks rogue mobileconfig / CA certs, RAT AnyDesk scams, Digital Arrest scams, and UPI web collect traps", () => {
  const rogueProfile = analyzeUrl("https://rewards-claim.top/vpn-update.mobileconfig");
  assert.equal(rogueProfile.decision, "BLOCK");

  const rogueCertIp = analyzeUrl("https://45.133.1.2/security/root-ca.crt");
  assert.equal(rogueCertIp.decision, "BLOCK");

  const ratScam = analyzeUrl("https://support-help-desk.top/anydesk-quicksupport/kyc-update");
  assert.equal(ratScam.decision, "BLOCK");

  const digitalArrest = analyzeUrl("https://cybercrime-notice-desk.top/digitalarrest/warrant-verify");
  assert.equal(digitalArrest.decision, "BLOCK");

  const upiWebCollect = analyzeUrl("https://cashback-offer-2026.xyz/claim?pa=scammer@okaxis&am=19999");
  assert.equal(upiWebCollect.decision, "BLOCK");
  assert.ok(upiWebCollect.indicators.includes("UPI_PAYMENT_REQUEST_SMUGGLING_IN_URL"));
});

test("Blocks mobile viewport subdomain spoofing, phishing kit endpoints, accented/Turkish homographs, Hangul fillers, and IP+port compound attacks", () => {
  const viewportSpoof = analyzeUrl(
    "https://www.sbi-online-netbanking-secure-verification-portal.attacker99.com/login"
  );
  assert.equal(viewportSpoof.decision, "BLOCK");
  assert.ok(viewportSpoof.indicators.includes("MOBILE_VIEWPORT_SUBDOMAIN_PADDING"));

  const kitEndpoint = analyzeUrl("https://unknown-merchant.org/cgi-bin/webscr?cmd=_login-run");
  assert.equal(kitEndpoint.decision, "BLOCK");
  assert.equal(kitEndpoint.reasonCodes[0], "PHISHING_KIT_ENDPOINT_FINGERPRINT");

  const accentedPayPal = analyzeUrl(`https://${domainToASCII("p\u00E0ypal.com")}/verify-account`);
  assert.equal(accentedPayPal.decision, "BLOCK");
  assert.ok(accentedPayPal.indicators.includes("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION"));

  const hangulEvasion = analyzeUrl("https://example.org/login\u3164verify");
  assert.equal(hangulEvasion.decision, "BLOCK");
  assert.equal(hangulEvasion.reasonCodes[0], "INVISIBLE_OR_BIDI_CHARACTERS_FOUND");

  const fullwidthScheme = analyzeUrl("ｊａｖａｓｃｒｉｐｔ:alert(1)");
  assert.equal(fullwidthScheme.decision, "BLOCK");

  const ipWebmail = analyzeUrl("https://93.184.216.34:8443/webmail");
  assert.equal(ipWebmail.decision, "BLOCK");

  const ipPortCompound = analyzeUrl("https://93.184.216.34:8443/status");
  assert.equal(ipPortCompound.decision, "BLOCK");
  assert.equal(ipPortCompound.reasonCodes[0], "COMPOUND_DIRECT_IP_ATTACK");
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
