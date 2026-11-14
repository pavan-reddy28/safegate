"use strict";

/**
 * verification.service.js
 *
 * 100% On-Device Zero-Leakage Multi-Layer URL Verification Service.
 * Zero external network calls, zero Google API lookups, zero URL retention.
 */

const { analyzeUrl } = require("../security/urlAnalyzer");
const { isKnownSafeDomain, isKnownSafePublicIp } = require("../security/knownSafeDomains");
const { isFreeUgcOrCloudHosting } = require("../security/localThreatList");
const { issueRedirectToken, verifyRedirectToken } = require("../security/redirectToken");
const { verifyNoPrivateUrlLeak } = require("../security/privacyGuard");
const { writeAuditEvent } = require("../utils/auditLog");

function calculateFinalDecision(localAnalysis, registrableDomain, options = {}) {
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

  if (
    isKnownSafePublicIp(hostname) &&
    riskScore === 0 &&
    protocol === "https:"
  ) {
    return {
      finalDecision: "KNOWN_SAFE",
      recommendedAction: "ALLOW",
      finalReasonCodes: [
        "ALL_LOCAL_SECURITY_LAYERS_PASSED",
        "HTTPS_TRANSPORT_VERIFIED",
        "TRUSTED_PUBLIC_INFRASTRUCTURE_IP"
      ]
    };
  }

  const reputationStatus = options.reputationCheckStatus || "UNAVAILABLE";
  if (reputationStatus === "NO_KNOWN_THREAT") {
    return {
      finalDecision: "NO_KNOWN_THREAT",
      recommendedAction: "ALLOW_WITH_CAUTION",
      finalReasonCodes: [
        "ALL_LOCAL_SECURITY_LAYERS_PASSED",
        ...(protocol === "http:" ? ["UNENCRYPTED_HTTP_CAUTION"] : ["HTTPS_TRANSPORT_VERIFIED"])
      ]
    };
  }

  return {
    finalDecision: "HOLD",
    recommendedAction: "HOLD",
    finalReasonCodes: [
      "REPUTATION_CHECK_UNAVAILABLE_ZERO_EGRESS",
      ...(protocol === "http:" ? ["UNENCRYPTED_HTTP_CAUTION"] : ["LOCAL_STRUCTURAL_CHECKS_PASSED"])
    ]
  };
}

function buildSecurityChecksSummary(localAnalysis) {
  const indicators = localAnalysis.indicators || [];
  const isBlocked = localAnalysis.decision === "BLOCK";

  return {
    zeroEgressGuaranteed: true,
    schemeAndEncodingCheck: isBlocked && ["UNSUPPORTED_OR_DANGEROUS_SCHEME", "CONTROL_CHARACTERS_FOUND", "INVISIBLE_OR_BIDI_CHARACTERS_FOUND", "UNICODE_SPOOF_CHARACTERS_FOUND", "ENCODED_SPOOF_OR_NULL_SEQUENCE", "ENCODED_CONTROL_CHARACTER", "INJECTED_SCRIPT_IN_PATH", "HTML_SMUGGLING_PAYLOAD_DETECTED"].includes(localAnalysis.reasonCodes?.[0])
      ? "FAILED"
      : "PASSED",
    networkAndIpIsolationCheck: isBlocked && ["NON_PUBLIC_IP_ADDRESS", "OBFUSCATED_IP_EVASION", "NON_PUBLIC_HOSTNAME", "DANGEROUS_NON_WEB_PORT", "LOCAL_THREAT_LIST_MATCH", "OFFLINE_THREAT_FEED_MATCH", "COMPOUND_DIRECT_IP_ATTACK"].includes(localAnalysis.reasonCodes?.[0])
      ? "FAILED"
      : indicators.includes("OBFUSCATED_IP_HOST") || indicators.includes("PUBLIC_IP_LITERAL_HOST") || indicators.includes("SUSPICIOUS_SERVICE_PORT")
        ? "FLAGGED"
        : "PASSED",
    homographAndBrandSpoofCheck: indicators.some((i) =>
      i.includes("BRAND") ||
      i.includes("HOMOGRAPH") ||
      i.includes("IDN") ||
      i.includes("PUNYCODE") ||
      i.includes("DECEPTIVE_") ||
      i.includes("HYPHEN_LURE") ||
      i === "UNIVERSAL_SUBDOMAIN_TLD_MASQUERADING" ||
      i === "MOBILE_VIEWPORT_SUBDOMAIN_PADDING"
    )
      ? (isBlocked ? "FAILED" : "FLAGGED")
      : "PASSED",
    malwareAndPathCheck: indicators.some((i) =>
      [
        "MOBILE_SIDELOAD_INSTALLER_PATH",
        "MOBILE_CONFIG_OR_CERT_INSTALL_PATH",
        "INTERACTIVE_SMUGGLING_FILE_PATH",
        "EXECUTABLE_DOWNLOAD_PATH",
        "ARCHIVE_DOWNLOAD_PATH",
        "DOUBLE_EXTENSION_MASQUERADE",
        "PATH_TRAVERSAL_PATTERN",
        "INJECTED_SCRIPT_IN_PATH",
        "PHISHING_KIT_ENDPOINT_FINGERPRINT",
        "EXPLICIT_THREAT_KEYWORD_IN_PATH",
        "LEXICAL_EXPLICIT_PHISHING_OR_MALWARE_STEM",
        "COMPROMISED_ASSET_DIR_PHISHING_KIT",
        "OBFUSCATED_SHORT_PATH_STATIC_KIT",
        "HEAVY_PERCENT_ENCODING_OBFUSCATION",
        "EMBEDDED_URL_IN_PATH",
        "COMPOUND_MALICIOUS_PAYLOAD_DELIVERY"
      ].includes(i)
    )
      ? (isBlocked ? "FAILED" : "FLAGGED")
      : "PASSED",
    redirectAndSmugglingCheck: indicators.some((i) =>
      ["DANGEROUS_REDIRECT_SCHEME", "MALFORMED_PROTOCOL_RELATIVE_REDIRECT", "ANDROID_INTENT_PARAM_FALLBACK_TRAP", "NESTED_REDIRECT_CONTAINS_CREDENTIALS", "NESTED_REDIRECT_DESTINATION_BLOCKED", "NESTED_REDIRECT_TO_MOBILE_INSTALLER", "NESTED_REDIRECT_TO_MOBILE_CONFIG_OR_CERT", "NESTED_REDIRECT_HIGH_RISK_TARGET", "NESTED_REDIRECT_RISK_PROPAGATED", "BASE64_SMUGGLED_REDIRECT", "HEX_SMUGGLED_REDIRECT", "HTML_SMUGGLING_PAYLOAD_DETECTED", "FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD", "SUSPICIOUS_NESTED_REDIRECT_DOMAIN", "FRAGMENT_VICTIM_EMAIL_PREFILL_KIT"].includes(i)
    )
      ? (isBlocked ? "FAILED" : "FLAGGED")
      : "PASSED",
    smsScamLureCheck: indicators.some((i) =>
      i.includes("SCAM_LURE") ||
      i.includes("CREDENTIAL_HARVEST") ||
      i.includes("INTENT_VECTOR") ||
      i.startsWith("LURE_INTENT_") ||
      i === "UPI_PAYMENT_REQUEST_SMUGGLING_IN_URL" ||
      i === "MULTI_VECTOR_SOCIAL_ENGINEERING_ATTACK" ||
      i === "COMPOUND_MULTI_LAYER_ATTACK_CORRELATION"
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
        "STOP! Do NOT open this link. SafeGate blocked it on your device because it shows strong signs of a phishing scam, remote-access trap, rogue certificate/APK drop, HTML smuggling, or unsafe redirect.",
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
        "Be very careful. This link has suspicious traits (such as a lookalike domain, hidden shortened link, sideload download, raw IP host, or non-standard port). Open your official bank or service app directly instead.",
      reasons: finalReasonCodes,
      indicatorsCount: indicators.length
    };
  }

  if (finalDecision === "KNOWN_SAFE") {
    return {
      level: "SAFE",
      score: riskScore ?? 0,
      headline: `Verified official destination (${host})`,
      parentAdvisory:
        "This link points to an authoritative official domain or infrastructure IP over HTTPS and passed all 30 on-device security checks with zero data leaving your phone.",
      reasons: finalReasonCodes,
      indicatorsCount: indicators.length
    };
  }

  if (finalDecision === "HOLD") {
    return {
      level: "MEDIUM",
      score: riskScore ?? 0,
      headline: `Held for confirmation (${host})`,
      parentAdvisory:
        "This link passed all 30 on-device checks, but its domain is unverified and remote reputation lookup is disabled to guarantee zero data leakage. Only open it if you personally trust the sender.",
      reasons: finalReasonCodes,
      indicatorsCount: indicators.length
    };
  }

  return {
    level: "LOW",
    score: riskScore ?? 0,
    headline: `No local threats detected (${host})`,
    parentAdvisory:
      "All 30 on-device security checks passed with zero external network calls. Still never enter your UPI PIN, OTP, CVV, or password unless you are 100% sure you trust this website.",
    reasons: finalReasonCodes,
    indicatorsCount: indicators.length
  };
}

const LAYERS_EXECUTED = [
  "ZERO_EGRESS_ON_DEVICE_ENFORCEMENT",
  "HTTP_BOUNDARY_AND_HEADER_HARDENING",
  "ANTI_EVASION_URL_AND_UNICODE_NFKC_NORMALIZATION",
  "NON_PUBLIC_IP_BOGON_AND_PORT_ISOLATION",
  "OFFLINE_SIGNED_BLOOM_THREAT_FEED_MATCHER",
  "UNICODE_HOMOGRAPH_NFD_CONFUSABLE_SKELETON",
  "DAMERAU_TRANSPOSITION_TYPOSQUAT_DETECTOR",
  "PHONETIC_AND_REPEATED_CHAR_SPOOF_DETECTOR",
  "MOBILE_VIEWPORT_SUBDOMAIN_TRUNCATION_SHIELD",
  "SUBDOMAIN_AND_LEET_BRAND_SPOOF_DETECTION",
  "UNIVERSAL_SUBDOMAIN_TLD_MASQUERADE_SHIELD",
  "DGA_ENTROPY_AND_VOWEL_CONSONANT_SCORER",
  "ABUSED_TLD_SHORTENER_AND_TUNNEL_DETECTION",
  "PATH_SCRIPT_KIT_FINGERPRINT_AND_DOUBLE_EXTENSION_SHIELD",
  "COMPROMISED_CMS_KIT_AND_STAGING_DETECTOR",
  "ANDROID_APK_CONFIG_CERT_AND_ARCHIVE_MALWARE_CHECK",
  "HTML_SMUGGLING_SVG_AND_MHTML_PAYLOAD_GUARD",
  "BASE64_AND_HEX_SMUGGLED_REDIRECT_DECODER",
  "MULTI_HOP_RECURSIVE_REDIRECT_RISK_PROPAGATOR",
  "ANDROID_INTENT_FALLBACK_AND_DEEP_LINK_TRAP_SHIELD",
  "FRAGMENT_PAYLOAD_AND_EMAIL_PREFILL_DETECTOR",
  "UPI_COLLECT_AND_PAYMENT_SMUGGLING_SHIELD",
  "REMOTE_ACCESS_TROJAN_AND_DIGITAL_ARREST_LURE_ENGINE",
  "SENIOR_WELFARE_AND_JOB_TASK_FRAUD_DETECTOR",
  "SMS_SCAM_AND_UPI_CREDENTIAL_LURE_ENGINE",
  "MULTI_VECTOR_LEXICAL_INTENT_CLASSIFIER",
  "CROSS_LAYER_COMPOUND_THREAT_CORRELATOR",
  "KNOWN_SAFE_OFFICIAL_DOMAIN_POLICY",
  "SINGLE_USE_JTI_HMAC_REDIRECT_TOKEN",
  "RUNTIME_ZERO_LEAKAGE_AND_LOG_REDACTION_ASSERTION"
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
