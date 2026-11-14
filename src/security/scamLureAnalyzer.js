"use strict";

const { isKnownSafeDomain } = require("./knownSafeDomains");
const { isFreeUgcOrCloudHosting } = require("./localThreatList");

/**
 * scamLureAnalyzer.js
 *
 * 100% on-device Global Social-Engineering, Phishing-Kit & Malware Lure Engine.
 * Covers banking/UPI/KYC, global cloud/account-suspension alerts, parcel/customs/toll
 * scams, crypto wallet/seed/airdrop scams, tech-support scareware, tax/govt refunds,
 * fake invoices, and abused multi-tenant hosting patterns.
 *
 * Zero URL paths or query values are ever returned or logged.
 */

const FINANCIAL_CREDIT_LURE_TERMS = [
  "credited", "amountcredit", "creditamount", "claimamount", "claimreward",
  "cashback", "refund", "taxrefund", "irsrefund", "gstrefund", "itrrefund",
  "lottery", "prize", "jackpot", "winner", "rewardpoints", "redeempoints",
  "upiclaim", "upireward", "bonusclaim", "subsidy", "giveaway", "freemoney",
  "salarycredited", "instantloan", "loanapproved", "preapproved", "unclaimedfunds",
  "airdrop", "tokenclaim", "stakingreward", "presale", "doublebtc", "ethgiveaway"
];

const URGENCY_KYC_LURE_TERMS = [
  // Banking & KYC
  "kyc", "updatekyc", "kycupdate", "kycpending", "panupdate",
  "aadhaarupdate", "aadharupdate", "reverify", "accountblocked",
  // Global Account Compromise / Suspension / Billing Scams
  "accountsuspended", "accountlocked", "accountdisabled", "accountrestricted",
  "unblockaccount", "unlockaccount", "recoveraccount", "reactivate",
  "verifyaccount", "accountverify", "confirmidentity", "identityverify",
  "unusualsignin", "unusualactivity", "securityalert", "securitywarning",
  "passwordexpired", "billingupdate", "paymentfailed", "carddeclined",
  "subscriptionexpired", "copyrightviolation", "trademarknotice", "appealsuspension",
  // Utility, Traffic, Tax & Telecom Scams
  "billdue", "electricitybill", "powerdisconnect", "disconnection",
  "challan", "echallan", "trafficfine", "unpaidtoll", "tollfee", "fastag",
  "pmkisan", "simblock", "5gupgrade", "esim",
  // Global Postal / Courier / Customs Scams
  "customsduty", "customsclearance", "customsfee", "parcelhold",
  "packagedelivery", "deliveryfailed", "redelivery", "addressupdate",
  // Global Tech Support / Scareware Scams
  "virusdetected", "deviceinfected", "systemwarning", "windowsdefender",
  "techsupport", "browserupdate", "chromeupdate", "flashupdate", "trojanalert"
];

const CREDENTIAL_HARVEST_TERMS = [
  "upipin", "mpin", "atmpin", "enterpin", "verifypin", "pinverify",
  "cvv", "cardverify", "cardnumber", "verifyotp", "otpverify",
  "netbankinglogin", "webbanking", "signinverify", "loginverify",
  "2faverify", "mfaverify", "passcode", "webmaillogin", "ssnverify",
  "seedphrase", "recoveryphrase", "mnemonic", "privatekey",
  "secretphrase", "connectwallet", "walletconnect"
];

const PATH_BRAND_TERMS = [
  // Global Tech & Cloud
  "microsoft", "office365", "outlook", "google", "gmail", "apple", "icloud",
  "adobe", "docusign", "dropbox", "zoom", "slack", "linkedin", "cloudflare",
  // Social & Streaming
  "whatsapp", "facebook", "instagram", "telegram", "discord", "netflix", "spotify",
  // E-Commerce & Delivery
  "amazon", "flipkart", "ebay", "walmart", "fedex", "dhl", "ups", "usps",
  "royalmail", "indiapost", "bluedart", "delhivery",
  // Global Crypto & Fintech
  "paypal", "binance", "coinbase", "metamask", "trustwallet", "ledger",
  "trezor", "revolut", "cashapp", "venmo", "wise",
  // Global & Indian Banks / UPI / Govt
  "chase", "wellsfargo", "bankofamerica", "hsbc", "citibank", "barclays",
  "sbi", "onlinesbi", "hdfc", "hdfcbank", "icici", "icicibank",
  "axisbank", "kotak", "pnb", "canarabank", "bankofbaroda",
  "phonepe", "paytm", "bhim", "npci", "razorpay",
  "uidai", "aadhaar", "incometax", "epfo", "irctc", "digilocker"
];

const GENERIC_AUTH_OR_DOC_PATH_TERMS = new Set([
  "login", "signin", "auth", "verify", "confirm", "update", "secure",
  "webmail", "invoice", "statement", "document", "account", "wallet",
  "billing", "support", "portal", "phish", "phishing", "malware"
]);

function tokenizeCompact(value) {
  const raw = String(value || "").toLowerCase();
  const splitTokens = raw.split(/[^a-z0-9]+/).filter(Boolean);
  const compact = raw.replace(/[^a-z0-9]+/g, "");
  return { splitTokens, compact };
}

function findMatches(tokens, compact, termList) {
  const hits = new Set();
  for (const term of termList) {
    if (tokens.includes(term) || compact.includes(term)) {
      hits.add(term);
    }
  }
  return hits.size;
}

function analyzeScamLures({
  hostname,
  registrableDomain,
  pathSegments,
  parsedUrl,
  existingIndicators = []
}) {
  const hasMobileInstaller = existingIndicators.includes("MOBILE_SIDELOAD_INSTALLER_PATH");

  if (
    isKnownSafeDomain(registrableDomain) &&
    !isFreeUgcOrCloudHosting(hostname) &&
    !hasMobileInstaller
  ) {
    return {
      indicators: [],
      riskScore: 0,
      hardBlock: false,
      hardBlockReason: null
    };
  }

  const indicators = [];
  let riskScore = 0;

  const hostParts = String(hostname || "").split(".");
  const queryKeys = Array.from(parsedUrl?.searchParams?.keys() || []);

  const combinedText = [
    ...hostParts,
    ...(Array.isArray(pathSegments) ? pathSegments : []),
    ...queryKeys
  ].join(" ");

  const { splitTokens, compact } = tokenizeCompact(combinedText);

  const financialHits = findMatches(splitTokens, compact, FINANCIAL_CREDIT_LURE_TERMS);
  const kycHits = findMatches(splitTokens, compact, URGENCY_KYC_LURE_TERMS);
  const harvestHits = findMatches(splitTokens, compact, CREDENTIAL_HARVEST_TERMS);

  const pathJoined = (Array.isArray(pathSegments) ? pathSegments : []).join(" ");
  const pathTokenInfo = tokenizeCompact(pathJoined);
  const pathBrandHit = PATH_BRAND_TERMS.some((brand) =>
    pathTokenInfo.splitTokens.includes(brand)
  );
  const genericAuthPathHit = pathTokenInfo.splitTokens.some((token) =>
    GENERIC_AUTH_OR_DOC_PATH_TERMS.has(token)
  );

  if (financialHits > 0) {
    indicators.push("SMS_FINANCIAL_SCAM_LURE");
    riskScore += financialHits >= 2 ? 4 : 3;
  }

  if (kycHits > 0) {
    indicators.push("URGENCY_OR_KYC_SCAM_LURE");
    riskScore += kycHits >= 2 ? 4 : 3;
  }

  if (harvestHits > 0) {
    indicators.push("SENSITIVE_BANKING_CREDENTIAL_HARVEST_PATTERN");
    riskScore += 5;
  }

  if (pathBrandHit && (financialHits > 0 || kycHits > 0 || harvestHits > 0 || genericAuthPathHit)) {
    indicators.push("BRAND_IMPERSONATION_WITH_SCAM_LURE_IN_PATH");
    riskScore += 4;
  }

  const hasExplicitThreatKeyword =
    existingIndicators.includes("EXPLICIT_THREAT_KEYWORD_IN_PATH") ||
    /\b(?:phishing|malware|ransomware|trojan|keylogger|spyware)\b/i.test(hostname || "");

  const hasDomainImpersonation =
    existingIndicators.includes("BRAND_NAME_IN_UNRELATED_DOMAIN") ||
    existingIndicators.includes("POSSIBLE_BRAND_LOOKALIKE_DOMAIN") ||
    existingIndicators.includes("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION");

  const hasDeceptiveHostname =
    existingIndicators.includes("DECEPTIVE_MULTI_LURE_HOSTNAME") ||
    existingIndicators.includes("DECEPTIVE_AUTH_HOSTNAME_PATTERN") ||
    existingIndicators.includes("EXCESSIVE_HYPHEN_LURE_DOMAIN");

  const hasAndroidApk = existingIndicators.includes("MOBILE_SIDELOAD_INSTALLER_PATH");
  const hasArchive = existingIndicators.includes("ARCHIVE_DOWNLOAD_PATH");
  const hasTunnelOrIp =
    existingIndicators.includes("FREE_TUNNEL_OR_DYNAMIC_DNS_HOST") ||
    existingIndicators.includes("IP_LITERAL_HOST") ||
    existingIndicators.includes("OBFUSCATED_IP_HOST");
  const hasAbusedCloudHosting = existingIndicators.includes("FREE_UGC_OR_CLOUD_HOSTING");
  const hasHighRiskTld = existingIndicators.includes("HIGH_RISK_ABUSED_TLD");
  const hasShortener = existingIndicators.includes("URL_SHORTENER_HIDES_DESTINATION");
  const hasHttp = existingIndicators.includes("UNENCRYPTED_HTTP");
  const hasDga = existingIndicators.includes("HIGH_ENTROPY_DGA_DOMAIN");
  const hasSensitiveQuery = existingIndicators.includes("SENSITIVE_QUERY_PARAMETERS_DETECTED");

  const hasScamLure = financialHits > 0 || kycHits > 0 || harvestHits > 0;

  let hardBlock = false;
  let hardBlockReason = null;

  if (existingIndicators.includes("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION")) {
    hardBlock = true;
    hardBlockReason = "CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION";
  } else if (hasExplicitThreatKeyword) {
    hardBlock = true;
    hardBlockReason = "EXPLICIT_PHISHING_OR_MALWARE_INDICATOR";
  } else if (
    hasDomainImpersonation &&
    (hasScamLure || hasAndroidApk || hasArchive || hasHighRiskTld || hasHttp || hasTunnelOrIp || hasAbusedCloudHosting || pathBrandHit)
  ) {
    hardBlock = true;
    hardBlockReason = "PHISHING_BRAND_IMPERSONATION_CONFIRMED";
  } else if (hasAndroidApk && (hasScamLure || hasTunnelOrIp || hasAbusedCloudHosting || hasHighRiskTld || hasHttp || pathBrandHit)) {
    hardBlock = true;
    hardBlockReason = "MALICIOUS_APK_DELIVERY_PATTERN";
  } else if (hasArchive && (hasScamLure || hasHighRiskTld || hasTunnelOrIp || pathBrandHit || hasAbusedCloudHosting)) {
    hardBlock = true;
    hardBlockReason = "MALICIOUS_ARCHIVE_DELIVERY_PATTERN";
  } else if (hasAbusedCloudHosting && (hasScamLure || pathBrandHit || harvestHits > 0 || genericAuthPathHit || hasDeceptiveHostname)) {
    hardBlock = true;
    hardBlockReason = "ABUSED_HOSTING_PHISHING_PATTERN";
  } else if (hasTunnelOrIp && (hasScamLure || pathBrandHit || harvestHits > 0 || genericAuthPathHit || hasDeceptiveHostname)) {
    hardBlock = true;
    hardBlockReason = "TUNNEL_OR_IP_PHISHING_PATTERN";
  } else if (hasDeceptiveHostname && (hasScamLure || hasHighRiskTld || hasHttp || pathBrandHit)) {
    hardBlock = true;
    hardBlockReason = "DECEPTIVE_PHISHING_KIT_PATTERN";
  } else if (hasHighRiskTld && (hasScamLure || harvestHits > 0 || hasDga || pathBrandHit)) {
    hardBlock = true;
    hardBlockReason = "HIGH_RISK_TLD_SCAM_LURE_PATTERN";
  } else if (hasHttp && (hasScamLure || harvestHits > 0 || (hasSensitiveQuery && !existingIndicators.includes("REDIRECT_PARAMETER_PRESENT")))) {
    hardBlock = true;
    hardBlockReason = "INSECURE_HTTP_SCAM_OR_CREDENTIAL_RISK";
  } else if (hasShortener && hasHttp) {
    hardBlock = true;
    hardBlockReason = "INSECURE_HTTP_SHORTENER_LINK";
  }

  return {
    indicators: [...new Set(indicators)],
    riskScore,
    hardBlock,
    hardBlockReason
  };
}

module.exports = { analyzeScamLures };
