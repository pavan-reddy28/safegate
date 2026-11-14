"use strict";

const { isKnownSafeDomain } = require("./knownSafeDomains");

/**
 * scamLureAnalyzer.js
 *
 * Detects SMS / WhatsApp social-engineering lure patterns (e.g., "amount credited",
 * "KYC pending", "electricity disconnect", "claim reward", "PIN/OTP verify")
 * on untrusted / non-official domains.
 *
 * PRIVACY GUARANTEE:
 * Only structural indicators (e.g. "SMS_FINANCIAL_SCAM_LURE") are emitted.
 * Raw URL paths, words, and query values are NEVER returned or logged.
 */

const FINANCIAL_CREDIT_LURE_TERMS = [
  "credited",
  "amountcredit",
  "creditamount",
  "claimamount",
  "claimreward",
  "cashback",
  "refund",
  "lottery",
  "prize",
  "jackpot",
  "rewardpoints",
  "redeempoints",
  "upiclaim",
  "upireward",
  "bonusclaim"
];

const URGENCY_KYC_LURE_TERMS = [
  "kyc",
  "updatekyc",
  "kycupdate",
  "kycpending",
  "panupdate",
  "aadhaarupdate",
  "aadharupdate",
  "accountblocked",
  "accountsuspended",
  "unblockaccount",
  "reverify",
  "billdue",
  "electricitybill",
  "powerdisconnect",
  "disconnection",
  "challan",
  "pmkisan",
  "customsduty",
  "parcelhold"
];

const CREDENTIAL_HARVEST_TERMS = [
  "upipin",
  "mpin",
  "atmpin",
  "enterpin",
  "verifypin",
  "cvv",
  "cardverify",
  "verifyotp",
  "otpverify",
  "netbankinglogin"
];

// Brand keywords that should not appear in the path of unrelated non-official domains
// when paired with login/verify/kyc/credit actions
const PATH_BRAND_TERMS = [
  "sbi",
  "onlinesbi",
  "hdfc",
  "hdfcbank",
  "icici",
  "icicibank",
  "axisbank",
  "kotak",
  "phonepe",
  "paytm",
  "bhim",
  "npci",
  "uidai",
  "aadhaar",
  "incometax",
  "indiapost",
  "paypal",
  "amazon",
  "whatsapp"
];

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

/**
 * Inspect host labels, path segments, and query parameter keys (NOT raw query values)
 * for social-engineering scam lures.
 *
 * @param {object} opts
 * @param {string} opts.hostname
 * @param {string|null} opts.registrableDomain
 * @param {string[]} opts.pathSegments
 * @param {URL} opts.parsedUrl
 * @param {string[]} opts.existingIndicators
 */
function analyzeScamLures({
  hostname,
  registrableDomain,
  pathSegments,
  parsedUrl,
  existingIndicators = []
}) {
  // Never flag official verified first-party domains for routine keywords
  // like "/refund" on amazon.in or "/kyc" on sbi.co.in.
  if (isKnownSafeDomain(registrableDomain)) {
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

  const financialHits = findMatches(
    splitTokens,
    compact,
    FINANCIAL_CREDIT_LURE_TERMS
  );
  const kycHits = findMatches(
    splitTokens,
    compact,
    URGENCY_KYC_LURE_TERMS
  );
  const harvestHits = findMatches(
    splitTokens,
    compact,
    CREDENTIAL_HARVEST_TERMS
  );

  // Check if a banking/govt brand appears inside the URL path on an unrelated domain
  const pathJoined = (Array.isArray(pathSegments) ? pathSegments : []).join(" ");
  const pathTokenInfo = tokenizeCompact(pathJoined);
  const pathBrandHit = PATH_BRAND_TERMS.some((brand) =>
    pathTokenInfo.splitTokens.includes(brand)
  );

  if (financialHits > 0) {
    indicators.push("SMS_FINANCIAL_SCAM_LURE");
    riskScore += financialHits >= 2 ? 4 : 2;
  }

  if (kycHits > 0) {
    indicators.push("URGENCY_OR_KYC_SCAM_LURE");
    riskScore += kycHits >= 2 ? 4 : 3;
  }

  if (harvestHits > 0) {
    indicators.push("SENSITIVE_BANKING_CREDENTIAL_HARVEST_PATTERN");
    riskScore += 4;
  }

  if (pathBrandHit && (financialHits > 0 || kycHits > 0 || harvestHits > 0)) {
    indicators.push("BRAND_IMPERSONATION_WITH_SCAM_LURE_IN_PATH");
    riskScore += 4;
  }

  // Compound high-confidence phishing escalation -> immediate local hard block!
  const hasDomainImpersonation =
    existingIndicators.includes("BRAND_NAME_IN_UNRELATED_DOMAIN") ||
    existingIndicators.includes("POSSIBLE_BRAND_LOOKALIKE_DOMAIN") ||
    existingIndicators.includes("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION");

  const hasAndroidApk = existingIndicators.includes("MOBILE_SIDELOAD_INSTALLER_PATH");
  const hasTunnelOrIp =
    existingIndicators.includes("FREE_TUNNEL_OR_DYNAMIC_DNS_HOST") ||
    existingIndicators.includes("IP_LITERAL_HOST") ||
    existingIndicators.includes("OBFUSCATED_IP_HOST");
  const hasHighRiskTld = existingIndicators.includes("HIGH_RISK_ABUSED_TLD");
  const hasScamLure =
    financialHits > 0 || kycHits > 0 || harvestHits > 0;

  let hardBlock = false;
  let hardBlockReason = null;

  if (hasDomainImpersonation && (hasScamLure || hasAndroidApk || hasHighRiskTld)) {
    hardBlock = true;
    hardBlockReason = "PHISHING_BRAND_IMPERSONATION_CONFIRMED";
  } else if (hasAndroidApk && (hasScamLure || hasTunnelOrIp || existingIndicators.includes("UNENCRYPTED_HTTP"))) {
    hardBlock = true;
    hardBlockReason = "MALICIOUS_APK_DELIVERY_PATTERN";
  } else if (harvestHits > 0 && (hasTunnelOrIp || hasHighRiskTld || existingIndicators.includes("UNENCRYPTED_HTTP"))) {
    hardBlock = true;
    hardBlockReason = "HIGH_RISK_CREDENTIAL_HARVEST_PATTERN";
  } else if (existingIndicators.includes("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION")) {
    hardBlock = true;
    hardBlockReason = "CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION";
  }

  return {
    indicators: [...new Set(indicators)],
    riskScore,
    hardBlock,
    hardBlockReason
  };
}

module.exports = { analyzeScamLures };
