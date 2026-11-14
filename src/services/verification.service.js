"use strict";

/**
 * verification.service.js
 *
 * 100% On-Device Zero-Leakage Multi-Layer URL Verification Service.
 * Zero external network calls, zero Google API lookups, zero URL retention.
 */

const { analyzeUrl } = require("../security/urlAnalyzer");
const { isKnownSafeDomain } = require("../security/knownSafeDomains");
const { isFreeUgcOrCloudHosting } = require("../security/localThreatList");
const { issueRedirectToken, verifyRedirectToken } = require("../security/redirectToken");
const { verifyNoPrivateUrlLeak } = require("../security/privacyGuard");
const { writeAuditEvent } = require("../utils/auditLog");

function calculateFinalDecision(localAnalysis, registrableDomain) {
  if (localAnalysis.decision === "BLOCK") {
    return {
      finalDecision: "BLOCK",
      recommendedAction: "DO_NOT_OPEN",
      finalReasonCodes: localAnalysis.reasonCodes || ["LOCAL_SECURITY_BLOCK"]
    };
  }

  if (localAnalysis.decision === "SUSPICIOUS") {
    return {
      finalDecision: "SUSPICIOUS",
      recommendedAction: "WARN_USER",
      finalReasonCodes: ["LOCAL_SUSPICIOUS_URL_PATTERN"]
    };
  }

  const protocol = localAnalysis.destination?.protocol || "https:";
  const hostname = localAnalysis.destination?.hostname || "";
  const riskScore = localAnalysis.riskScore ?? 0;

  if (
    isKnownSafeDomain(registrableDomain) &&
    !isFreeUgcOrCloudHosting(hostname) &&
    riskScore === 0 &&
    protocol === "https:"
  ) {
    return {
      finalDecision: "KNOWN_SAFE",
      recommendedAction: "ALLOW",
      finalReasonCodes: [
        "ALL_LOCAL_SECURITY_LAYERS_PASSED",
        "HTTPS_TRANSPORT_VERIFIED",
        "KNOWN_SAFE_OFFICIAL_DOMAIN"
      ]
    };
  }

  return {
    finalDecision: "NO_KNOWN_THREAT",
    recommendedAction: "ALLOW_WITH_CAUTION",
    finalReasonCodes: [
      "ALL_LOCAL_SECURITY_LAYERS_PASSED",
      ...(protocol === "http:" ? ["UNENCRYPTED_HTTP_CAUTION"] : ["HTTPS_TRANSPORT_VERIFIED"])
    ]
  };
}

function buildSecurityChecksSummary(localAnalysis) {
  const indicators = localAnalysis.indicators || [];
  const isBlocked = localAnalysis.decision === "BLOCK";

  return {
    zeroEgressGuaranteed: true,
    schemeAndEncodingCheck: isBlocked && ["UNSUPPORTED_OR_DANGEROUS_SCHEME", "CONTROL_CHARACTERS_FOUND", "INVISIBLE_OR_BIDI_CHARACTERS_FOUND", "ENCODED_SPOOF_OR_NULL_SEQUENCE", "ENCODED_CONTROL_CHARACTER", "INJECTED_SCRIPT_IN_PATH"].includes(localAnalysis.reasonCodes?.[0])
      ? "FAILED"
      : "PASSED",
    networkAndIpIsolationCheck: isBlocked && ["NON_PUBLIC_IP_ADDRESS", "NON_PUBLIC_HOSTNAME", "DANGEROUS_NON_WEB_PORT", "LOCAL_THREAT_LIST_MATCH"].includes(localAnalysis.reasonCodes?.[0])
      ? "FAILED"
      : indicators.includes("OBFUSCATED_IP_HOST") || indicators.includes("IP_LITERAL_HOST")
        ? "FLAGGED"
        : "PASSED",
    homographAndBrandSpoofCheck: indicators.some((i) =>
      i.includes("BRAND") ||
      i.includes("HOMOGRAPH") ||
      i.includes("IDN") ||
      i.includes("PUNYCODE") ||
      i.includes("DECEPTIVE_") ||
      i.includes("HYPHEN_LURE") ||
      i === "UNIVERSAL_SUBDOMAIN_TLD_MASQUERADING"
    )
      ? (isBlocked ? "FAILED" : "FLAGGED")
      : "PASSED",
    malwareAndPathCheck: indicators.some((i) =>
      [
        "MOBILE_SIDELOAD_INSTALLER_PATH",
        "EXECUTABLE_DOWNLOAD_PATH",
        "ARCHIVE_DOWNLOAD_PATH",
        "DOUBLE_EXTENSION_MASQUERADE",
        "PATH_TRAVERSAL_PATTERN",
        "INJECTED_SCRIPT_IN_PATH",
        "EXPLICIT_THREAT_KEYWORD_IN_PATH",
        "LEXICAL_EXPLICIT_PHISHING_OR_MALWARE_STEM",
        "COMPROMISED_ASSET_DIR_PHISHING_KIT",
        "OBFUSCATED_SHORT_PATH_STATIC_KIT",
        "HEAVY_PERCENT_ENCODING_OBFUSCATION",
        "EMBEDDED_URL_IN_PATH"
      ].includes(i)
    )
      ? (isBlocked ? "FAILED" : "FLAGGED")
      : "PASSED",
    redirectAndSmugglingCheck: indicators.some((i) =>
      ["DANGEROUS_REDIRECT_SCHEME", "NESTED_REDIRECT_CONTAINS_CREDENTIALS", "NESTED_REDIRECT_DESTINATION_BLOCKED", "NESTED_REDIRECT_TO_MOBILE_INSTALLER", "BASE64_SMUGGLED_REDIRECT", "HEX_SMUGGLED_REDIRECT", "SUSPICIOUS_NESTED_REDIRECT_DOMAIN", "FRAGMENT_VICTIM_EMAIL_PREFILL_KIT"].includes(i)
    )
      ? (isBlocked ? "FAILED" : "FLAGGED")
      : "PASSED",
    smsScamLureCheck: indicators.some((i) =>
      i.includes("SCAM_LURE") ||
      i.includes("CREDENTIAL_HARVEST") ||
      i.includes("INTENT_VECTOR") ||
      i.startsWith("LURE_INTENT_") ||
      i === "MULTI_VECTOR_SOCIAL_ENGINEERING_ATTACK"
    )
      ? (isBlocked ? "FAILED" : "FLAGGED")
      : "PASSED"
  };
}

function buildRiskSummary({
  finalDecision,
  finalReasonCodes,
  indicators = [],
  riskScore = null,
  destination = null
}) {
  const host = destination?.hostname || "unknown destination";

  if (finalDecision === "BLOCK") {
    return {
      level: "CRITICAL",
      score: riskScore,
      headline: "Dangerous link blocked",
      parentAdvisory:
        "STOP! Do NOT open this link. SafeGate blocked it on your device because it shows strong signs of a phishing scam, compromised site kit, malware download, or unsafe redirect.",
      reasons: finalReasonCodes,
      indicatorsCount: indicators.length
    };
  }

  if (finalDecision === "SUSPICIOUS") {
    return {
      level: "HIGH",
      score: riskScore,
      headline: `Suspicious link detected (${host})`,
      parentAdvisory:
        "Be very careful. This link has suspicious traits (such as a lookalike domain, hidden shortened link, file download, or unverified hosting). Open your official bank or service app directly instead.",
      reasons: finalReasonCodes,
      indicatorsCount: indicators.length
    };
  }

  if (finalDecision === "KNOWN_SAFE") {
    return {
      level: "SAFE",
      score: riskScore ?? 0,
      headline: `Verified official website (${host})`,
      parentAdvisory:
        "This link points to an authoritative official domain over HTTPS and passed all on-device security checks with zero data leaving your phone.",
      reasons: finalReasonCodes,
      indicatorsCount: indicators.length
    };
  }

  return {
    level: "LOW",
    score: riskScore ?? 0,
    headline: `No local threats detected (${host})`,
    parentAdvisory:
      "All 21 on-device security checks passed with zero external network calls. Still never enter your UPI PIN, OTP, CVV, or password unless you are 100% sure you trust this website.",
    reasons: finalReasonCodes,
    indicatorsCount: indicators.length
  };
}

const LAYERS_EXECUTED = [
  "ZERO_EGRESS_ON_DEVICE_ENFORCEMENT",
  "HTTP_BOUNDARY_AND_HEADER_HARDENING",
  "ANTI_EVASION_URL_NORMALIZATION",
  "NON_PUBLIC_IP_AND_PORT_ISOLATION",
  "UNICODE_HOMOGRAPH_AND_CONFUSABLE_SKELETON",
  "SUBDOMAIN_AND_LEET_BRAND_SPOOF_DETECTION",
  "UNIVERSAL_SUBDOMAIN_TLD_MASQUERADE_SHIELD",
  "DGA_ENTROPY_AND_VOWEL_CONSONANT_SCORER",
  "ABUSED_TLD_SHORTENER_AND_TUNNEL_DETECTION",
  "PATH_SCRIPT_AND_DOUBLE_EXTENSION_SHIELD",
  "COMPROMISED_CMS_KIT_AND_STAGING_DETECTOR",
  "ANDROID_APK_AND_ARCHIVE_MALWARE_CHECK",
  "BASE64_AND_HEX_SMUGGLED_REDIRECT_DECODER",
  "MULTI_HOP_RECURSIVE_REDIRECT_INSPECTOR",
  "FRAGMENT_EMAIL_PREFILL_TRAP_DETECTOR",
  "SMS_SCAM_AND_UPI_CREDENTIAL_LURE_ENGINE",
  "MULTI_VECTOR_LEXICAL_INTENT_CLASSIFIER",
  "KNOWN_SAFE_OFFICIAL_DOMAIN_POLICY",
  "EPHEMERAL_HMAC_REDIRECT_TOKEN",
  "RUNTIME_ZERO_LEAKAGE_ASSERTION",
  "ZERO_URL_RETENTION_AUDIT_LOG"
];

async function verifyUrl(url, requestId) {
  const startMs = Date.now();

  const localAnalysis = analyzeUrl(url);
  const registrableDomain = localAnalysis.destination?.registrableDomain || null;

  const finalResult = calculateFinalDecision(localAnalysis, registrableDomain);

  const verificationToken = issueRedirectToken({
    url,
    finalDecision: finalResult.finalDecision,
    recommendedAction: finalResult.recommendedAction,
    requestId
  });

  const result = {
    verificationStatus: "COMPLETED",
    localVerification: localAnalysis,
    securityChecks: buildSecurityChecksSummary(localAnalysis),
    finalDecision: finalResult.finalDecision,
    recommendedAction: finalResult.recommendedAction,
    finalReasonCodes: finalResult.finalReasonCodes,
    verificationToken,
    riskSummary: buildRiskSummary({
      finalDecision: finalResult.finalDecision,
      finalReasonCodes: finalResult.finalReasonCodes,
      indicators: localAnalysis.indicators,
      riskScore: localAnalysis.riskScore,
      destination: localAnalysis.destination
    }),
    layersExecuted: LAYERS_EXECUTED,
    privacy: {
      outboundNetworkCalls: 0,
      externalServicesContacted: [],
      zeroEgressOnDevice: true,
      zeroUrlRetention: true,
      originalUrlLoggedOrStored: false,
      pathAndQueryInspectedLocallyOnly: true
    }
  };

  if (!verifyNoPrivateUrlLeak(url, result)) {
    throw new Error("PRIVACY_ASSERTION_FAILED");
  }

  writeAuditEvent({
    requestId,
    finalDecision: result.finalDecision,
    recommendedAction: result.recommendedAction,
    finalReasonCodes: result.finalReasonCodes,
    riskScore: localAnalysis.riskScore,
    indicators: localAnalysis.indicators,
    destination: localAnalysis.destination,
    durationMs: Date.now() - startMs
  });

  return result;
}

function authorizeRedirect({ url, verificationToken, userConfirmedWarning }) {
  return verifyRedirectToken({
    url,
    token: verificationToken,
    userConfirmedWarning
  });
}

module.exports = {
  verifyUrl,
  calculateFinalDecision,
  authorizeRedirect,
  buildRiskSummary,
  buildSecurityChecksSummary,
  LAYERS_EXECUTED
};
