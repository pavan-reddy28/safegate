
"use strict";

/**
 * verification.service.js  (enhanced)
 *
 * Orchestrates the full multi-layer URL verification pipeline:
 *
 *   Layer 1  — URL normalization & structural validation   (urlAnalyzer)
 *   Layer 2  — Domain / host intelligence                  (domainAnalyzer via urlAnalyzer)
 *   Layer 3  — Path analysis                               (pathAnalyzer via urlAnalyzer)
 *   Layer 4  — Query / nested-redirect analysis            (queryAnalyzer via urlAnalyzer)
 *   Layer 5  — Google Safe Browsing v5 (hash-prefix only)  (googleSafeBrowsing.service)
 *   Layer 6  — Known-safe domain fast-pass                 (knownSafeDomains)
 *   Layer 7  — Privacy-safe audit logging                  (auditLog)
 *
 * PRIVACY GUARANTEES (enforced here and in every sub-module)
 * ----------------------------------------------------------
 *   • The original URL is NEVER logged, stored or returned.
 *   • Only 4-byte SHA-256 hash prefixes of hostname variants are sent to Google.
 *   • No path, query string or fragment ever leaves this device.
 *   • Query parameter VALUES are inspected locally only; they are never returned.
 *   • Sensitive path segments are detected locally; they are never returned.
 *   • The audit log records only: timestamp, request UUID, decision, reason codes,
 *     risk score, structural indicators, destination hostname, and Google status.
 */

const { analyzeUrl } = require("../security/urlAnalyzer");
const { checkGoogleReputation } = require("./googleSafeBrowsing.service");
const { isKnownSafeDomain } = require("../security/knownSafeDomains");
const { writeAuditEvent } = require("../utils/auditLog");

// ─────────────────────────────────────────────
// DECISION LOGIC
// ─────────────────────────────────────────────

/**
 * Combine local heuristic result with Google Safe Browsing result into a
 * single final verdict.
 *
 * @param {object} local   — result from analyzeUrl()
 * @param {object} google  — result from checkGoogleReputation()
 * @param {string|null} registrableDomain
 * @returns {{ finalDecision, recommendedAction, finalReasonCodes }}
 */
function calculateFinalDecision(local, google, registrableDomain) {

  // Hard local block takes absolute priority.
  if (local.decision === "BLOCK") {
    return {
      finalDecision: "BLOCK",
      recommendedAction: "DO_NOT_OPEN",
      finalReasonCodes: local.reasonCodes || ["LOCAL_SECURITY_BLOCK"]
    };
  }

  // Google found a known threat → block regardless of local verdict.
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
    // Upgrade to KNOWN_SAFE when the domain is on the allow-list.
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

  // Google was unavailable or unconfigured — do not allow silently.
  return {
    finalDecision: "HOLD",
    recommendedAction: "DO_NOT_OPEN",
    finalReasonCodes: ["GOOGLE_VERIFICATION_NOT_CONFIRMED"]
  };
}

// ─────────────────────────────────────────────
// MAIN ENTRY POINT
// ─────────────────────────────────────────────

/**
 * Full verification pipeline.
 *
 * @param {string} url        — the raw URL submitted by the client
 * @param {string} requestId  — UUID for audit correlation
 * @returns {Promise<object>}
 */
async function verifyUrl(url, requestId) {
  const startMs = Date.now();

  // ── Layer 1–4: local analysis ──────────────────────────────────────────
  const localAnalysis = analyzeUrl(url);

  // Hard local blocks skip the Google network request entirely.
  if (localAnalysis.decision === "BLOCK") {
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
      finalReasonCodes: localAnalysis.reasonCodes || ["LOCAL_SECURITY_BLOCK"],

      privacy: {
        originalUrlSentToGoogle: false,
        pathSentToGoogle: false,
        queryStringSentToGoogle: false,
        fragmentSentToGoogle: false,
        googleLookupScope: "No Google request — URL blocked locally"
      }
    };

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

  // ── Layer 5: Google Safe Browsing (hash-prefix only) ───────────────────
  const googleAnalysis = await checkGoogleReputation(url);

  const registrableDomain =
    localAnalysis.destination?.registrableDomain || null;

  // ── Layer 6: final decision (includes known-safe fast-pass) ───────────
  const finalResult = calculateFinalDecision(
    localAnalysis,
    googleAnalysis,
    registrableDomain
  );

  const googleCompleted = ["THREAT_FOUND", "NO_THREAT_FOUND"]
    .includes(googleAnalysis.status);

  const googleAttempted = !["NOT_CONFIGURED", "INVALID_URL", "INVALID_HASH_DATA"]
    .includes(googleAnalysis.status);

  const result = {
    verificationStatus: googleCompleted ? "COMPLETED" : "INCOMPLETE",

    localVerification: {
      decision: localAnalysis.decision,
      stage: localAnalysis.stage,
      reasonCodes: localAnalysis.reasonCodes,
      indicators: localAnalysis.indicators,
      destination: localAnalysis.destination,
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

    privacy: {
      originalUrlSentToGoogle: false,
      pathSentToGoogle: false,
      queryStringSentToGoogle: false,
      fragmentSentToGoogle: false,
      googleLookupScope:
        "Four-byte SHA-256 prefixes of hostname variants at root path only"
    }
  };

  // ── Layer 7: audit log ─────────────────────────────────────────────────
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

module.exports = { verifyUrl, calculateFinalDecision };
