"use strict";

/**
 * verification.service.js
 *
 * Orchestrates the 12-layer privacy-first URL verification pipeline:
 *
 *   Layer 1  — Strict HTTP boundary & input sanitization      (strictInputGuard / burstGuard)
 *   Layer 2  — URL normalization & anti-evasion               (urlNormalizer)
 *   Layer 3  — Domain, IP, homograph & brand impersonation    (domainAnalyzer)
 *   Layer 4  — Path, script-injection & APK/exe inspection    (pathAnalyzer)
 *   Layer 5  — Query, Base64 smuggling & redirect chain       (queryAnalyzer)
 *   Layer 6  — SMS/WhatsApp social-engineering scam lures     (scamLureAnalyzer)
 *   Layer 7  — Google Safe Browsing v5 (4-byte host prefix)   (googleSafeBrowsing.service)
 *   Layer 8  — Authoritative known-safe allow-list            (knownSafeDomains)
 *   Layer 9  — Ephemeral HMAC redirect authorization token    (redirectToken)
 *   Layer 10 — Zero-leakage runtime assertion & redaction     (privacyGuard)
 *   Layer 11 — Parent-friendly risk summary & guidance        (buildRiskSummary)
 *   Layer 12 — Privacy-safe structured audit logging          (auditLog)
 */

const env = require("../config/env");
const { analyzeUrl } = require("../security/urlAnalyzer");
const { checkGoogleReputation } = require("./googleSafeBrowsing.service");
const { isKnownSafeDomain } = require("../security/knownSafeDomains");
const { issueRedirectToken, verifyRedirectToken } = require("../security/redirectToken");
const { verifyNoPrivateUrlLeak } = require("../security/privacyGuard");
const { writeAuditEvent } = require("../utils/auditLog");

function calculateFinalDecision(local, google, registrableDomain, options = {}) {
  // Hard local block takes absolute priority.
  if (local.decision === "BLOCK") {
    return {
      finalDecision: "BLOCK",
      recommendedAction: "DO_NOT_OPEN",
      finalReasonCodes: local.reasonCodes || ["LOCAL_SECURITY_BLOCK"]
    };
  }

  // Google found a known threat -> block regardless of local verdict.
  if (google.status === "THREAT_FOUND") {
    return {
      finalDecision: "BLOCK",
      recommendedAction: "DO_NOT_OPEN",
      finalReasonCodes: ["GOOGLE_KNOWN_THREAT_MATCH"]
    };
  }

  // Local analysis flagged suspicious patterns.
  if (local.decision === "SUSPICIOUS") {
    return {
      finalDecision: "SUSPICIOUS",
      recommendedAction: "WARN_USER",
      finalReasonCodes: [
        "LOCAL_SUSPICIOUS_URL_PATTERN",
        google.status === "NO_THREAT_FOUND"
          ? "GOOGLE_NO_KNOWN_MATCH"
          : "GOOGLE_RESULT_NOT_CONFIRMED"
      ]
    };
  }

  // Google confirmed no threat.
  if (google.status === "NO_THREAT_FOUND") {
    if (isKnownSafeDomain(registrableDomain)) {
      return {
        finalDecision: "KNOWN_SAFE",
        recommendedAction: "ALLOW",
        finalReasonCodes: [
          "LOCAL_STRUCTURAL_CHECK_PASSED",
          "GOOGLE_NO_KNOWN_MATCH",
          "KNOWN_SAFE_DOMAIN"
        ]
      };
    }

    return {
      finalDecision: "NO_KNOWN_THREAT",
      recommendedAction: "ALLOW_WITH_CAUTION",
      finalReasonCodes: [
        "LOCAL_STRUCTURAL_CHECK_PASSED",
        "GOOGLE_NO_KNOWN_MATCH"
      ]
    };
  }

  // Optional 100%-offline allow-list fast-pass when explicitly opted in via env
  if (
    options.offlineAllowKnownSafe &&
    ["NOT_CONFIGURED", "OFFLINE_MODE_SKIPPED"].includes(google.status) &&
    isKnownSafeDomain(registrableDomain) &&
    (local.riskScore ?? 0) === 0
  ) {
    return {
      finalDecision: "KNOWN_SAFE",
      recommendedAction: "ALLOW",
      finalReasonCodes: [
        "LOCAL_STRUCTURAL_CHECK_PASSED",
        "KNOWN_SAFE_DOMAIN",
        "OFFLINE_KNOWN_SAFE_VERIFIED"
      ]
    };
  }

  // Fail closed when reputation lookup could not be confirmed.
  return {
    finalDecision: "HOLD",
    recommendedAction: "DO_NOT_OPEN",
    finalReasonCodes: ["GOOGLE_VERIFICATION_NOT_CONFIRMED"]
  };
}

function buildRiskSummary({
  finalDecision,
  recommendedAction,
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
        "Do NOT open this link. SafeGate blocked it because it shows strong signs of a phishing scam, malicious file download, or unsafe redirect.",
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
        "Be very careful. This link has suspicious traits (such as a brand lookalike, hidden shortened link, APK download, or scam wording). Verify directly in your official bank/service app instead.",
      reasons: finalReasonCodes,
      indicatorsCount: indicators.length
    };
  }

  if (finalDecision === "HOLD") {
    return {
      level: "MEDIUM",
      score: riskScore,
      headline: `Verification incomplete — held for safety (${host})`,
      parentAdvisory:
        "Local checks passed, but online threat reputation could not be confirmed. Avoid opening unexpected SMS or WhatsApp links until verified.",
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
        "This link points to an authoritative official domain and passed all local and reputation checks.",
      reasons: finalReasonCodes,
      indicatorsCount: indicators.length
    };
  }

  return {
    level: "LOW",
    score: riskScore ?? 0,
    headline: `No known threats found (${host})`,
    parentAdvisory:
      "No known threats were found, and no private data left your device. Still avoid entering banking PINs, OTPs, or passwords unless you trust this site.",
    reasons: finalReasonCodes,
    indicatorsCount: indicators.length
  };
}

async function verifyUrl(url, requestId) {
  const startMs = Date.now();

  // Local layers 2-6
  const localAnalysis = analyzeUrl(url);

  // Hard local blocks skip Google network lookups completely.
  if (localAnalysis.decision === "BLOCK") {
    const finalReasonCodes =
      localAnalysis.reasonCodes || ["LOCAL_SECURITY_BLOCK"];

    const result = {
      verificationStatus: "COMPLETED",
      localVerification: localAnalysis,
      reputationCheck: {
        requiredByLocalAnalyzer: false,
        attempted: false,
        completed: false,
        provider: "GOOGLE_SAFE_BROWSING_V5",
        result: "SKIPPED_LOCAL_BLOCK"
      },
      googleVerification: {
        status: "SKIPPED_LOCAL_BLOCK",
        threatMatches: [],
        cacheHit: false
      },
      finalDecision: "BLOCK",
      recommendedAction: "DO_NOT_OPEN",
      finalReasonCodes,
      verificationToken: null,
      riskSummary: buildRiskSummary({
        finalDecision: "BLOCK",
        recommendedAction: "DO_NOT_OPEN",
        finalReasonCodes,
        indicators: localAnalysis.indicators,
        riskScore: localAnalysis.riskScore,
        destination: null
      }),
      layersExecuted: [
        "INPUT_BOUNDARY_GUARD",
        "URL_NORMALIZER_ANTI_EVASION",
        "DOMAIN_HOMOGRAPH_BRAND_INTEL",
        "PATH_AND_MALWARE_INSPECTION",
        "QUERY_AND_REDIRECT_CHAIN_INSPECTION",
        "SMS_SCAM_LURE_ANALYZER",
        "ZERO_LEAK_PRIVACY_GUARD"
      ],
      privacy: {
        originalUrlSentToGoogle: false,
        pathSentToGoogle: false,
        queryStringSentToGoogle: false,
        fragmentSentToGoogle: false,
        zeroRetentionInPlace: true,
        googleLookupScope: "No Google request — URL blocked locally"
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
      googleContacted: false,
      googleStatus: "SKIPPED_LOCAL_BLOCK",
      cacheHit: false,
      durationMs: Date.now() - startMs
    });

    return result;
  }

  // Layer 7: Google Safe Browsing (4-byte host-prefix only, skipped if STRICT_OFFLINE_MODE=true)
  const googleAnalysis = await checkGoogleReputation(url);

  const registrableDomain =
    localAnalysis.destination?.registrableDomain || null;

  // Layer 8: Final Decision
  const finalResult = calculateFinalDecision(
    localAnalysis,
    googleAnalysis,
    registrableDomain,
    { offlineAllowKnownSafe: env.offlineAllowKnownSafe }
  );

  const googleCompleted = ["THREAT_FOUND", "NO_THREAT_FOUND"].includes(
    googleAnalysis.status
  );

  const googleAttempted = ![
    "NOT_CONFIGURED",
    "OFFLINE_MODE_SKIPPED",
    "INVALID_URL",
    "INVALID_HASH_DATA"
  ].includes(googleAnalysis.status);

  // Layer 9: Ephemeral HMAC redirect token for allowed/warned decisions
  const verificationToken = issueRedirectToken({
    url,
    finalDecision: finalResult.finalDecision,
    recommendedAction: finalResult.recommendedAction,
    requestId
  });

  const result = {
    verificationStatus:
      googleCompleted ||
      (env.offlineAllowKnownSafe && finalResult.finalDecision === "KNOWN_SAFE")
        ? "COMPLETED"
        : "INCOMPLETE",

    localVerification: {
      decision: localAnalysis.decision,
      stage: localAnalysis.stage,
      reasonCodes: localAnalysis.reasonCodes,
      indicators: localAnalysis.indicators,
      destination: localAnalysis.destination,
      redactedDestination: localAnalysis.redactedDestination,
      riskScore: localAnalysis.riskScore,
      urlInspection: localAnalysis.urlInspection,
      reputationCheckRequired: localAnalysis.reputationCheckRequired,
      privacy: localAnalysis.privacy
    },

    reputationCheck: {
      requiredByLocalAnalyzer: localAnalysis.reputationCheckRequired,
      attempted: googleAttempted,
      completed: googleCompleted,
      provider: "GOOGLE_SAFE_BROWSING_V5",
      result: googleAnalysis.status
    },

    googleVerification: {
      status: googleAnalysis.status,
      threatMatches: googleAnalysis.threatMatches || [],
      cacheHit: Boolean(googleAnalysis.cacheHit)
    },

    ...(googleAnalysis.cacheDurationSeconds !== undefined
      ? { googleCacheDurationSeconds: googleAnalysis.cacheDurationSeconds }
      : {}),

    ...(googleAnalysis.errorCode
      ? { googleErrorCode: googleAnalysis.errorCode }
      : {}),

    finalDecision: finalResult.finalDecision,
    recommendedAction: finalResult.recommendedAction,
    finalReasonCodes: finalResult.finalReasonCodes,
    verificationToken,
    riskSummary: buildRiskSummary({
      finalDecision: finalResult.finalDecision,
      recommendedAction: finalResult.recommendedAction,
      finalReasonCodes: finalResult.finalReasonCodes,
      indicators: localAnalysis.indicators,
      riskScore: localAnalysis.riskScore,
      destination: localAnalysis.destination
    }),

    layersExecuted: [
      "INPUT_BOUNDARY_GUARD",
      "URL_NORMALIZER_ANTI_EVASION",
      "DOMAIN_HOMOGRAPH_BRAND_INTEL",
      "PATH_AND_MALWARE_INSPECTION",
      "QUERY_AND_REDIRECT_CHAIN_INSPECTION",
      "SMS_SCAM_LURE_ANALYZER",
      googleAttempted
        ? "GOOGLE_SAFE_BROWSING_HASH_PREFIX"
        : "GOOGLE_SAFE_BROWSING_SKIPPED",
      "KNOWN_SAFE_DOMAIN_POLICY",
      "EPHEMERAL_REDIRECT_TOKEN",
      "ZERO_LEAK_PRIVACY_GUARD"
    ],

    privacy: {
      originalUrlSentToGoogle: false,
      pathSentToGoogle: false,
      queryStringSentToGoogle: false,
      fragmentSentToGoogle: false,
      zeroRetentionInPlace: true,
      googleLookupScope: env.strictOfflineMode
        ? "Strict offline mode active — zero external network requests made"
        : "Four-byte SHA-256 prefixes of non-sensitive hostname variants at root path only"
    }
  };

  // Layer 10: Runtime zero-leakage verification
  if (!verifyNoPrivateUrlLeak(url, result)) {
    throw new Error("PRIVACY_ASSERTION_FAILED");
  }

  // Layer 12: Zero-URL audit log
  writeAuditEvent({
    requestId,
    finalDecision: result.finalDecision,
    recommendedAction: result.recommendedAction,
    finalReasonCodes: result.finalReasonCodes,
    riskScore: localAnalysis.riskScore,
    indicators: localAnalysis.indicators,
    destination: localAnalysis.destination,
    googleContacted: googleAttempted,
    googleStatus: googleAnalysis.status,
    cacheHit: Boolean(googleAnalysis.cacheHit),
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
  buildRiskSummary
};
