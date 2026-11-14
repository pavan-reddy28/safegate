
import ipaddr from "ipaddr.js";
import { parse as parseDomain } from "tldts";

const MAX_URL_LENGTH = 4096;

const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/;
const MALFORMED_PERCENT_ENCODING = /%(?![0-9a-fA-F]{2})/;

const RESERVED_SUFFIXES = [
    "localhost",
    "local",
    "internal",
    "test",
    "invalid",
    "example"
];

const EXECUTABLE_EXTENSIONS = new Set([
    "exe", "msi", "apk", "aab", "bat", "cmd",
    "com", "scr", "ps1", "sh", "jar", "vbs",
    "dmg", "pkg", "deb", "rpm", "iso"
]);

const REDIRECT_PARAMETERS = new Set([
    "url", "uri", "u", "redirect", "redirecturl",
    "redirecturi", "redirectto", "return", "returnto",
    "returnurl", "next", "nexturl", "continue",
    "dest", "destination", "target", "goto",
    "callback", "forward"
]);

function blocked(reasonCode) {
    return {
        decision: "BLOCK",
        stage: "LOCAL",
        reasonCodes: [reasonCode],
        indicators: [],
        destination: null,
        riskScore: null,
        urlInspection: null,
        reputationCheckRequired: false
    };
}

/* ========================================
   URL NORMALIZATION
======================================== */

function normalizeUrl(input) {
    if (typeof input !== "string") {
        return { ok: false, reasonCode: "INVALID_URL_TYPE" };
    }

    if (CONTROL_CHARACTERS.test(input)) {
        return { ok: false, reasonCode: "CONTROL_CHARACTERS_FOUND" };
    }

    const candidate = input.trim();

    if (!candidate) {
        return { ok: false, reasonCode: "EMPTY_URL" };
    }

    if (candidate.length > MAX_URL_LENGTH) {
        return { ok: false, reasonCode: "URL_TOO_LONG" };
    }

    if (/\s/.test(candidate)) {
        return { ok: false, reasonCode: "WHITESPACE_IN_URL" };
    }

    if (candidate.includes("\\")) {
        return { ok: false, reasonCode: "BACKSLASH_IN_URL" };
    }

    if (MALFORMED_PERCENT_ENCODING.test(candidate)) {
        return {
            ok: false,
            reasonCode: "MALFORMED_PERCENT_ENCODING"
        };
    }

    if (!/^https?:\/\//i.test(candidate)) {
        return {
            ok: false,
            reasonCode: "ABSOLUTE_HTTP_URL_REQUIRED"
        };
    }

    let parsedUrl;

    try {
        parsedUrl = new URL(candidate);
    } catch {
        return { ok: false, reasonCode: "MALFORMED_URL" };
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
        return { ok: false, reasonCode: "UNSUPPORTED_PROTOCOL" };
    }

    if (parsedUrl.username || parsedUrl.password) {
        return {
            ok: false,
            reasonCode: "URL_CONTAINS_CREDENTIALS"
        };
    }

    const hostname = parsedUrl.hostname
        .toLowerCase()
        .replace(/\.$/, "");

    if (!hostname || hostname.length > 253) {
        return { ok: false, reasonCode: "INVALID_HOSTNAME" };
    }

    const authorityMatch = candidate.match(
        /^https?:\/\/[^/?#]*(\/[^?#]*)?/i
    );

    return {
        ok: true,
        parsedUrl,
        hostname,
        rawPath: authorityMatch?.[1] || "/"
    };
}

/* ========================================
   DOMAIN ANALYSIS
======================================== */

function isReservedHostname(hostname) {
    return RESERVED_SUFFIXES.some(
        suffix =>
            hostname === suffix ||
            hostname.endsWith(`.${suffix}`)
    );
}

function isBlockedHost(hostname, blockedDomains = []) {
    const host = hostname.toLowerCase();

    return blockedDomains.some(domain => {
        const blocked = domain.toLowerCase();

        return (
            host === blocked ||
            host.endsWith(`.${blocked}`)
        );
    });
}

function analyzeDomain(hostname, parsedUrl, blockedDomains) {
    const indicators = [];
    let riskScore = 0;

    if (isReservedHostname(hostname)) {
        return {
            blocked: true,
            reasonCode: "NON_PUBLIC_HOSTNAME",
            indicators,
            riskScore
        };
    }

    if (isBlockedHost(hostname, blockedDomains)) {
        return {
            blocked: true,
            reasonCode: "LOCAL_THREAT_LIST_MATCH",
            indicators,
            riskScore
        };
    }

    const ipCandidate = hostname
        .replace(/^\[/, "")
        .replace(/\]$/, "");

    if (ipaddr.isValid(ipCandidate)) {
        let address;

        try {
            address = ipaddr.process(ipCandidate);
        } catch {
            return {
                blocked: true,
                reasonCode: "INVALID_IP_ADDRESS",
                indicators,
                riskScore
            };
        }

        if (address.range() !== "unicast") {
            return {
                blocked: true,
                reasonCode: "NON_PUBLIC_IP_ADDRESS",
                indicators,
                riskScore
            };
        }

        indicators.push("IP_LITERAL_HOST");
        riskScore += 2;

    } else {
        const domainInfo = parseDomain(hostname);

        if (
            !domainInfo ||
            !domainInfo.domain ||
            !domainInfo.publicSuffix
        ) {
            return {
                blocked: true,
                reasonCode: "INVALID_OR_UNKNOWN_PUBLIC_SUFFIX",
                indicators,
                riskScore
            };
        }

        const labels = hostname.split(".");

        if (labels.some(label => label.startsWith("xn--"))) {
            indicators.push("PUNYCODE_HOSTNAME");
            riskScore += 2;
        }

        if (labels.length > 5) {
            indicators.push("MANY_SUBDOMAINS");
            riskScore += 1;
        }
    }

    if (parsedUrl.protocol === "http:") {
        indicators.push("UNENCRYPTED_HTTP");
        riskScore += 1;
    }

    if (parsedUrl.port) {
        indicators.push("NON_STANDARD_PORT");
        riskScore += 1;
    }

    return {
        blocked: false,
        indicators,
        riskScore,
        destination: {
            hostname,
            registrableDomain: ipaddr.isValid(ipCandidate)
                ? null
                : parseDomain(hostname).domain,
            protocol: parsedUrl.protocol,
            nonStandardPort: Boolean(parsedUrl.port)
        }
    };
}

/* ========================================
   PATH ANALYSIS
======================================== */

function analyzePath(rawPath) {
    const indicators = [];
    let riskScore = 0;

    let decodedPath = rawPath;
    let decodingFailed = false;

    try {
        decodedPath = decodeURIComponent(rawPath);
    } catch {
        decodingFailed = true;
        indicators.push("UNDECODABLE_PATH_ENCODING");
        riskScore += 3;
    }

    if (/%25(?:2e|2f|5c|00|0a|0d)/i.test(rawPath)) {
        indicators.push("DOUBLE_ENCODED_PATH");
        riskScore += 3;
    }

    if (/%(?:2f|5c)/i.test(rawPath)) {
        indicators.push("ENCODED_PATH_SEPARATOR");
        riskScore += 2;
    }

    if (/(?:^|\/)(?:(?:%2e|\.){2})(?:\/|$)/i.test(rawPath)) {
        indicators.push("DOT_SEGMENT_PATTERN");
        riskScore += 3;
    }

    if (/%(?:00|0a|0d|09)/i.test(rawPath)) {
        indicators.push("ENCODED_CONTROL_CHARACTER");
        riskScore += 4;
    }

    if (rawPath.length > 1024) {
        indicators.push("VERY_LONG_PATH");
        riskScore += 1;
    }

    const pathForInspection = decodingFailed
        ? rawPath
        : decodedPath;

    const segments = pathForInspection
        .split("/")
        .filter(Boolean);

    if (segments.length > 20) {
        indicators.push("MANY_PATH_SEGMENTS");
        riskScore += 1;
    }

    const finalSegment = segments.at(-1) || "";

    const extensionMatch = finalSegment.match(
        /\.([a-z0-9]{1,10})$/i
    );

    const extension = extensionMatch
        ? extensionMatch[1].toLowerCase()
        : null;

    if (extension && EXECUTABLE_EXTENSIONS.has(extension)) {
        indicators.push("EXECUTABLE_DOWNLOAD_PATH");
        riskScore += 3;
    }

    return {
        indicators,
        riskScore,
        segmentCount: segments.length,
        extension,
        originalPathLength: rawPath.length
    };
}

/* ========================================
   QUERY ANALYSIS
======================================== */

function decodeRepeatedly(value) {
    let current = value;
    let additionalDecodes = 0;

    for (let i = 0; i < 2; i++) {
        try {
            const decoded = decodeURIComponent(current);

            if (decoded === current) {
                break;
            }

            current = decoded;
            additionalDecodes++;

        } catch {
            return {
                value: current,
                decodingFailed: true,
                additionalDecodes
            };
        }
    }

    return {
        value: current,
        decodingFailed: false,
        additionalDecodes
    };
}

function analyzeNestedDestination(value) {
    const candidate = value.trim();

    if (!/^(https?:\/\/|\/\/)/i.test(candidate)) {
        return null;
    }

    let nestedUrl;

    try {
        nestedUrl = candidate.startsWith("//")
            ? new URL(`https:${candidate}`)
            : new URL(candidate);
    } catch {
        return { invalid: true };
    }

    if (!["http:", "https:"].includes(nestedUrl.protocol)) {
        return { invalid: true };
    }

    return {
        invalid: false,
        hostname: nestedUrl.hostname.toLowerCase(),
        hasCredentials: Boolean(
            nestedUrl.username || nestedUrl.password
        )
    };
}

function analyzeQuery(parsedUrl) {
    const indicators = [];
    let riskScore = 0;

    const params = Array.from(
        parsedUrl.searchParams.entries()
    );

    let redirectParameterCount = 0;
    let nestedDestinationCount = 0;

    if (parsedUrl.search.length > 2048) {
        indicators.push("LONG_QUERY_STRING");
        riskScore += 1;
    }

    if (params.length > 30) {
        indicators.push("EXCESSIVE_QUERY_PARAMETERS");
        riskScore += 1;
    }

    for (const [key, value] of params) {
        const normalizedKey = key
            .toLowerCase()
            .replace(/[^a-z0-9]/g, "");

        const isRedirectParameter =
            REDIRECT_PARAMETERS.has(normalizedKey);

        if (isRedirectParameter) {
            redirectParameterCount++;
            indicators.push("REDIRECT_PARAMETER_PRESENT");
            riskScore += 1;
        }

        const decoded = decodeRepeatedly(value);

        if (decoded.decodingFailed) {
            indicators.push("QUERY_VALUE_ENCODING_ERROR");
            riskScore += 2;
        }

        if (decoded.additionalDecodes > 0) {
            indicators.push("DOUBLE_ENCODED_QUERY_VALUE");
            riskScore += 2;
        }

        const inspectedValue = decoded.value.trim();

        if (
            isRedirectParameter &&
            /^(javascript:|data:|file:)/i.test(inspectedValue)
        ) {
            indicators.push("DANGEROUS_REDIRECT_SCHEME");
            riskScore += 4;
            continue;
        }

        const nested = analyzeNestedDestination(inspectedValue);

        if (nested) {
            nestedDestinationCount++;

            if (nested.invalid) {
                indicators.push("INVALID_NESTED_DESTINATION");
                riskScore += 2;
                continue;
            }

            if (nested.hasCredentials) {
                indicators.push("NESTED_URL_CONTAINS_CREDENTIALS");
                riskScore += 2;
            }

            if (isRedirectParameter) {
                indicators.push("NESTED_URL_IN_REDIRECT_PARAMETER");
                riskScore += 2;
            }
        }
    }

    let fragmentHasUrl = false;

    if (parsedUrl.hash) {
        const fragment = decodeRepeatedly(
            parsedUrl.hash.slice(1)
        );

        fragmentHasUrl = /https?:\/\//i.test(fragment.value);

        if (fragmentHasUrl) {
            indicators.push("URL_IN_FRAGMENT");
            riskScore += 1;
        }
    }

    return {
        indicators: [...new Set(indicators)],
        riskScore,
        parameterCount: params.length,
        redirectParameterCount,
        nestedDestinationCount,
        fragmentPresent: Boolean(parsedUrl.hash),
        fragmentHasUrl
    };
}

/* ========================================
   MAIN LOCAL ANALYZER
======================================== */

/**
 * All URL inspection is performed locally.
 *
 * blockedDomains are device-side blocked domains.
 * Never pass the original URL to the relay.
 */
export function analyzeUrl(input, options = {}) {
    const normalized = normalizeUrl(input);

    if (!normalized.ok) {
        return blocked(normalized.reasonCode);
    }

    const {
        parsedUrl,
        hostname,
        rawPath
    } = normalized;

    const blockedDomains = Array.isArray(options.blockedDomains)
        ? options.blockedDomains
        : [];

    const domainAnalysis = analyzeDomain(
        hostname,
        parsedUrl,
        blockedDomains
    );

    if (domainAnalysis.blocked) {
        return blocked(domainAnalysis.reasonCode);
    }

    const pathAnalysis = analyzePath(
        rawPath
    );

    const queryAnalysis = analyzeQuery(
        parsedUrl
    );

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

    const suspicious = riskScore >= 3;

    return {
        decision: suspicious
            ? "SUSPICIOUS"
            : "REPUTATION_CHECK_REQUIRED",

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
                originalPathLength:
                    pathAnalysis.originalPathLength,
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
