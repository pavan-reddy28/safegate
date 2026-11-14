"use strict";

const { normalizeUrl } = require("./urlNormalizer");
const { analyzeDomain } = require("./domainAnalyzer");
const { analyzePath } = require("./pathAnalyzer");
const { analyzeQuery } = require("./queryAnalyzer");
const { analyzeScamLures } = require("./scamLureAnalyzer");
const { buildRedactedDestination } = require("./privacyGuard");

const SUSPICIOUS_RISK_THRESHOLD = 4;

function blocked(reasonCode, indicators = []) {
  return {
    decision: "BLOCK",
    stage: "LOCAL",
    reasonCodes: [reasonCode],
    indicators: [...new Set(indicators)],
    destination: null,
    redactedDestination: null,
    urlInspection: null,
    riskScore: null,
    reputationCheckRequired: false,
    privacy: {
      sensitiveQueryValuesDetected: false,
      sensitivePathSegmentsDetected: false,
      googleQueryStringExcluded: true,
      googleFragmentExcluded: true
    }
  };
}

function analyzeUrl(input) {
  // Layer 1: Normalize, reject control/bidi/obfuscation tricks, and parse URL locally.
  const normalized = normalizeUrl(input);

  if (!normalized.ok) {
    return blocked(normalized.reasonCode);
  }

  const { parsedUrl, hostname, rawPath, obfuscatedIpHost } = normalized;

  // Layer 2: Domain, IP-range, homograph, shortener, tunnel, and brand-impersonation analysis.
  const domainAnalysis = analyzeDomain(hostname, parsedUrl, {
    obfuscatedIpHost
  });

  if (domainAnalysis.blocked) {
    return blocked(domainAnalysis.reasonCode, domainAnalysis.indicators);
  }

  // Layer 3: Path, encoding, script-injection, and mobile/desktop executable inspection.
  const pathAnalysis = analyzePath(rawPath, parsedUrl.pathname);

  if (pathAnalysis.hardBlock) {
    return blocked(
      pathAnalysis.hardBlockReason || "MALICIOUS_PATH_PATTERN",
      [...domainAnalysis.indicators, ...pathAnalysis.indicators]
    );
  }

  // Layer 4: Query, fragment, Base64-smuggling, and multi-hop nested redirect inspection.
  const queryAnalysis = analyzeQuery(parsedUrl);

  if (queryAnalysis.hardBlockReason) {
    return blocked(queryAnalysis.hardBlockReason, [
      ...domainAnalysis.indicators,
      ...pathAnalysis.indicators,
      ...queryAnalysis.indicators
    ]);
  }

  const preLureIndicators = [
    ...new Set([
      ...domainAnalysis.indicators,
      ...pathAnalysis.indicators,
      ...queryAnalysis.indicators
    ])
  ];

  // Layer 5: SMS / WhatsApp social-engineering lure & compound phishing escalation.
  const scamAnalysis = analyzeScamLures({
    hostname,
    registrableDomain: domainAnalysis.destination?.registrableDomain || null,
    pathSegments: pathAnalysis.segments,
    parsedUrl,
    existingIndicators: preLureIndicators
  });

  const allIndicators = [
    ...new Set([...preLureIndicators, ...scamAnalysis.indicators])
  ];

  if (scamAnalysis.hardBlock) {
    return blocked(scamAnalysis.hardBlockReason, allIndicators);
  }

  const riskScore =
    domainAnalysis.riskScore +
    pathAnalysis.riskScore +
    queryAnalysis.riskScore +
    scamAnalysis.riskScore;

  // High cumulative risk score -> immediate local block
  if (riskScore >= 10) {
    return blocked("HIGH_RISK_SCORE_LOCAL_BLOCK", allIndicators);
  }

  const suspicious = riskScore >= SUSPICIOUS_RISK_THRESHOLD;
  const decision = suspicious ? "SUSPICIOUS" : "REPUTATION_CHECK_REQUIRED";

  return {
    decision,
    stage: "LOCAL",
    reasonCodes: suspicious
      ? ["LOCAL_SUSPICIOUS_URL_PATTERN"]
      : ["LOCAL_STRUCTURAL_CHECK_PASSED"],
    indicators: allIndicators,
    destination: domainAnalysis.destination,
    redactedDestination: buildRedactedDestination(parsedUrl),
    riskScore,
    urlInspection: {
      path: {
        segmentCount: pathAnalysis.segmentCount,
        extension: pathAnalysis.extension,
        originalPathLength: pathAnalysis.originalPathLength,
        sensitivePathSegmentCount: pathAnalysis.sensitivePathSegmentCount,
        indicators: pathAnalysis.indicators
      },
      query: {
        parameterCount: queryAnalysis.parameterCount,
        redirectParameterCount: queryAnalysis.redirectParameterCount,
        nestedDestinationCount: queryAnalysis.nestedDestinationCount,
        sensitiveParameterCount: queryAnalysis.sensitiveParameterCount,
        fragmentPresent: queryAnalysis.fragmentPresent,
        fragmentHasUrl: queryAnalysis.fragmentHasUrl,
        fragmentContainsSensitiveMaterial:
          queryAnalysis.fragmentContainsSensitiveMaterial,
        indicators: queryAnalysis.indicators
      }
    },
    reputationCheckRequired: true,
    privacy: {
      sensitiveQueryValuesDetected: queryAnalysis.sensitiveParameterCount > 0,
      sensitivePathSegmentsDetected: pathAnalysis.sensitivePathSegmentCount > 0,
      googleQueryStringExcluded: true,
      googleFragmentExcluded: true
    }
  };
}

function getGoogleSafePath() {
  return "/";
}

module.exports = {
  analyzeUrl,
  getGoogleSafePath
};