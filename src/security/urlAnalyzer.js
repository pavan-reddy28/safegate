"use strict";

const { normalizeUrl } = require("./urlNormalizer");
const { analyzeDomain } = require("./domainAnalyzer");
const { analyzePath } = require("./pathAnalyzer");
const { analyzeQuery } = require("./queryAnalyzer");
const { analyzeScamLures } = require("./scamLureAnalyzer");
const { buildRedactedDestination } = require("./privacyGuard");
const { isKnownSafeDomain } = require("./knownSafeDomains");
const { isFreeUgcOrCloudHosting } = require("./localThreatList");

const SUSPICIOUS_RISK_THRESHOLD = 3;
const LOCAL_BLOCK_SCORE_THRESHOLD = 8;

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
      outboundNetworkCalls: 0,
      zeroEgressOnDevice: true
    }
  };
}

function analyzeUrl(input) {
  // Layer 1: Anti-evasion URL normalization & boundary checks
  const normalized = normalizeUrl(input);
  if (!normalized.ok) {
    return blocked(normalized.reasonCode);
  }

  const { parsedUrl, hostname, rawPath, obfuscatedIpHost } = normalized;

  // Layer 2: Domain, IP, homograph, subdomain-spoof, DGA, shortener, hosting & brand analysis
  const domainAnalysis = analyzeDomain(hostname, parsedUrl, {
    obfuscatedIpHost
  });

  if (domainAnalysis.blocked) {
    return blocked(domainAnalysis.reasonCode, domainAnalysis.indicators);
  }

  const registrableDomain = domainAnalysis.destination?.registrableDomain || null;
  const isSafeFirstParty =
    isKnownSafeDomain(registrableDomain) && !isFreeUgcOrCloudHosting(hostname);

  // Layer 3: Path, encoding, script injection, double-extension & malware download inspection
  const pathAnalysis = analyzePath(rawPath, parsedUrl.pathname);

  if (pathAnalysis.hardBlock) {
    return blocked(
      pathAnalysis.hardBlockReason || "MALICIOUS_PATH_PATTERN",
      [...domainAnalysis.indicators, ...pathAnalysis.indicators]
    );
  }

  const effectivePathIndicators = isSafeFirstParty
    ? pathAnalysis.indicators.filter((i) => i !== "EXPLICIT_THREAT_KEYWORD_IN_PATH")
    : pathAnalysis.indicators;
  const effectivePathRiskScore =
    isSafeFirstParty && pathAnalysis.indicators.includes("EXPLICIT_THREAT_KEYWORD_IN_PATH")
      ? Math.max(0, pathAnalysis.riskScore - 5)
      : pathAnalysis.riskScore;

  // Layer 4: Query, fragment, Base64/Hex smuggling & multi-hop nested redirect inspection
  const queryAnalysis = analyzeQuery(parsedUrl);

  if (queryAnalysis.hardBlockReason) {
    return blocked(queryAnalysis.hardBlockReason, [
      ...domainAnalysis.indicators,
      ...effectivePathIndicators,
      ...queryAnalysis.indicators
    ]);
  }

  const preLureIndicators = [
    ...new Set([
      ...domainAnalysis.indicators,
      ...effectivePathIndicators,
      ...queryAnalysis.indicators
    ])
  ];

  // Layer 5: Global social-engineering scam lure & compound escalation engine
  const scamAnalysis = analyzeScamLures({
    hostname,
    registrableDomain,
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
    effectivePathRiskScore +
    queryAnalysis.riskScore +
    scamAnalysis.riskScore;

  if (riskScore >= LOCAL_BLOCK_SCORE_THRESHOLD) {
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
        trackingParameterCount: queryAnalysis.trackingParameterCount,
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
      outboundNetworkCalls: 0,
      zeroEgressOnDevice: true
    }
  };
}

module.exports = {
  analyzeUrl
};