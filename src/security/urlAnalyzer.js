"use strict";

const {
    normalizeUrl
} = require("./urlNormalizer");

const {
    analyzeDomain
} = require("./domainAnalyzer");

const {
    analyzePath
} = require("./pathAnalyzer");

const {
    analyzeQuery
} = require("./queryAnalyzer");

function blocked(reasonCode) {

    return {
        decision: "BLOCK",
        stage: "LOCAL",
        reasonCodes: [reasonCode],
        indicators: [],
        destination: null,
        urlInspection: null,
        riskScore: null,
        reputationCheckRequired: false
    };
}

function analyzeUrl(input) {

    // Layer 1: Normalize and validate full URL.
    const normalized = normalizeUrl(input);

    if (!normalized.ok) {
        return blocked(normalized.reasonCode);
    }

    const {
        parsedUrl,
        hostname,
        rawPath
    } = normalized;

    // Layer 2: Analyze hostname and domain.
    const domainAnalysis = analyzeDomain(
        hostname,
        parsedUrl
    );

    if (domainAnalysis.blocked) {
        return blocked(domainAnalysis.reasonCode);
    }

    // Layer 3: Analyze complete path.
    const pathAnalysis = analyzePath(
        rawPath,
        parsedUrl.pathname
    );

    // Layer 4: Analyze query parameters and fragments.
    const queryAnalysis = analyzeQuery(parsedUrl);

    const indicators = [
        ...domainAnalysis.indicators,
        ...pathAnalysis.indicators,
        ...queryAnalysis.indicators
    ];

    const uniqueIndicators = [...new Set(indicators)];

    const riskScore =
        domainAnalysis.riskScore +
        pathAnalysis.riskScore +
        queryAnalysis.riskScore;

    // This is an initial conservative heuristic,
    // not a trained or statistically validated phishing model.
    const suspicious = riskScore >= 3;

    const decision = suspicious
        ? "SUSPICIOUS"
        : "REPUTATION_CHECK_REQUIRED";

    return {

        decision,

        stage: "LOCAL",

        reasonCodes: suspicious
            ? ["LOCAL_SUSPICIOUS_URL_PATTERN"]
            : ["LOCAL_STRUCTURAL_CHECK_PASSED"],

        indicators: uniqueIndicators,

        destination: domainAnalysis.destination,

        riskScore,

        urlInspection: {

            path: {
                segmentCount: pathAnalysis.segmentCount,
                extension: pathAnalysis.extension,
                originalPathLength: pathAnalysis.originalPathLength,
                indicators: pathAnalysis.indicators
            },

            query: {
                parameterCount: queryAnalysis.parameterCount,
                redirectParameterCount:
                    queryAnalysis.redirectParameterCount,
                nestedDestinationCount:
                    queryAnalysis.nestedDestinationCount,
                fragmentPresent:
                    queryAnalysis.fragmentPresent,
                fragmentHasUrl:
                    queryAnalysis.fragmentHasUrl,
                indicators: queryAnalysis.indicators
            }
        },

        reputationCheckRequired: !suspicious

    };
}
module.exports = require("./privacyFirstAnalyzer");
module.exports = {
    analyzeUrl
};