
"use strict";

const ipaddr = require("ipaddr.js");
const { parse: parseDomain } = require("tldts");
const { isBlockedHost } = require("./localThreatList");

const MAX_URL_LENGTH = 4096;

const RESERVED_SUFFIXES = new Set([
  "localhost",
  "local",
  "internal",
  "test",
  "invalid",
  "example"
]);

const EXECUTABLE_EXTENSIONS = new Set([
  "exe", "msi", "apk", "aab", "bat", "cmd", "com",
  "scr", "ps1", "sh", "jar", "vbs", "dmg", "pkg",
  "deb", "rpm", "iso"
]);

const REDIRECT_KEYS = new Set([
  "url", "uri", "u", "redirect", "redirecturl",
  "redirecturi", "redirectto", "return", "returnto",
  "returnurl", "next", "nexturl", "continue", "dest",
  "destination", "target", "goto", "callback",
  "forward", "redirect_uri", "return_url"
]);

const SENSITIVE_KEYS = new Set([
  "password", "passwd", "pwd", "passphrase",
  "token", "accesstoken", "access_token",
  "refreshtoken", "refresh_token", "idtoken", "id_token",
  "authorization", "auth", "secret", "clientsecret",
  "client_secret", "code", "state", "session", "sessionid",
  "sid", "jwt", "apikey", "api_key", "key", "signature",
  "sig", "otp", "pin", "email", "phone", "mobile",
  "account", "card", "cc", "ssn", "dob", "username",
  "user", "credential", "credentials", "samlrequest",
  "samlresponse", "assertion", "ticket", "nonce",
  "csrf", "xsrf", "cookie"
]);

const DANGEROUS_SCHEME =
  /^(?:javascript|data|file|vbscript):/i;

const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/;
const BAD_PERCENT = /%(?![0-9a-f]{2})/i;

// --------------------------------------------------
// GENERIC BLOCK RESPONSE
// Never include the supplied URL or secret values.
// --------------------------------------------------

function blocked(reasonCode, indicators = []) {
  return {
    decision: "BLOCK",
    stage: "LOCAL",
    reasonCodes: [reasonCode],
    indicators,
    destination: null,
    riskScore: null,
    urlInspection: null,
    reputationCheckRequired: false,
    privacy: {
      sensitiveQueryValuesDetected: false,
      googleQueryStringExcluded: true,
      googleFragmentExcluded: true
    }
  };
}

// --------------------------------------------------
// URL NORMALIZATION
// --------------------------------------------------

function normalizeUrl(input) {
  if (typeof input !== "string") {
    return {
      ok: false,
      reasonCode: "INVALID_URL_TYPE"
    };
  }

  if (CONTROL_CHARACTERS.test(input)) {
    return {
      ok: false,
      reasonCode: "CONTROL_CHARACTERS_FOUND"
    };
  }

  const candidate = input.trim();

  if (!candidate) {
    return {
      ok: false,
      reasonCode: "EMPTY_URL"
    };
  }

  if (candidate.length > MAX_URL_LENGTH) {
    return {
      ok: false,
      reasonCode: "URL_TOO_LONG"
    };
  }

  if (/\s/.test(candidate)) {
    return {
      ok: false,
      reasonCode: "WHITESPACE_IN_URL"
    };
  }

  if (candidate.includes("\\")) {
    return {
      ok: false,
      reasonCode: "BACKSLASH_IN_URL"
    };
  }

  if (BAD_PERCENT.test(candidate)) {
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
    return {
      ok: false,
      reasonCode: "MALFORMED_URL"
    };
  }

  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    return {
      ok: false,
      reasonCode: "UNSUPPORTED_PROTOCOL"
    };
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
    return {
      ok: false,
      reasonCode: "INVALID_HOSTNAME"
    };
  }

  // Keep the original path in memory for local inspection only.
  // Never log or return the raw path.
  const authorityMatch = candidate.match(
    /^https?:\/\/[^/?#]*(\/[^?#]*)?/i
  );

  const rawPath = authorityMatch?.[1] || "/";

  return {
    ok: true,
    parsedUrl,
    hostname,
    rawPath
  };
}

// --------------------------------------------------
// DOMAIN HELPERS
// --------------------------------------------------

function isReservedHostname(hostname) {
  const host = hostname.toLowerCase();

  return [...RESERVED_SUFFIXES].some(suffix =>
    host === suffix || host.endsWith(`.${suffix}`)
  );
}

function validDnsHostname(hostname) {
  if (hostname.length > 253 || !hostname.includes(".")) {
    return false;
  }

  return hostname.split(".").every(label =>
    label.length >= 1 &&
    label.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
  );
}

function labelEntropy(value) {
  if (!value) return 0;

  const counts = new Map();

  for (const character of value) {
    counts.set(
      character,
      (counts.get(character) || 0) + 1
    );
  }

  let entropy = 0;

  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

// --------------------------------------------------
// DOMAIN ANALYSIS
// --------------------------------------------------

function analyzeDomain(hostname, parsedUrl) {
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

  if (isBlockedHost(hostname)) {
    return {
      blocked: true,
      reasonCode: "LOCAL_THREAT_LIST_MATCH",
      indicators,
      riskScore
    };
  }

  const ipCandidate = hostname.replace(/^\[|\]$/g, "");
  let registrableDomain = null;

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

    // Private, loopback, link-local, multicast, reserved
    // and non-global IP ranges are blocked.
    if (address.range() !== "unicast") {
      return {
        blocked: true,
        reasonCode: "NON_PUBLIC_IP_ADDRESS",
        indicators,
        riskScore
      };
    }

    indicators.push("PUBLIC_IP_LITERAL_HOST");
    riskScore += 2;
  } else {
    if (!validDnsHostname(hostname)) {
      return {
        blocked: true,
        reasonCode: "INVALID_HOSTNAME",
        indicators,
        riskScore
      };
    }

    const info = parseDomain(hostname);
    registrableDomain = info?.domain || null;

    // An unrecognized local suffix is uncertainty,
    // not an automatic phishing verdict.
    if (!info?.publicSuffix || !registrableDomain) {
      indicators.push("PUBLIC_SUFFIX_NOT_RECOGNIZED_LOCALLY");
      riskScore += 1;
    }

    const labels = hostname.split(".");

    if (labels.some(label => label.startsWith("xn--"))) {
      indicators.push("PUNYCODE_HOSTNAME");
      riskScore += 1;
    }

    if (labels.length > 5) {
      indicators.push("MANY_SUBDOMAINS");
      riskScore += labels.length > 8 ? 2 : 1;
    }

    const longestLabel = Math.max(
      ...labels.map(label => label.length)
    );

    if (longestLabel >= 40) {
      indicators.push("VERY_LONG_HOST_LABEL");
      riskScore += 1;
    }

    const suspiciousLabel = labels.some(label =>
      label.length >= 18 &&
      labelEntropy(label) >= 3.7 &&
      /[0-9]/.test(label)
    );

    if (suspiciousLabel) {
      indicators.push("HIGH_ENTROPY_HOST_LABEL");
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
      registrableDomain,
      protocol: parsedUrl.protocol,
      nonStandardPort: Boolean(parsedUrl.port)
    }
  };
}

// --------------------------------------------------
// SAFE REPEATED DECODING
// --------------------------------------------------

function decodeRepeatedly(value, maxPasses = 2) {
  let current = value;
  let additionalDecodes = 0;

  for (let index = 0; index < maxPasses; index++) {
    try {
      const next = decodeURIComponent(current);

      if (next === current) break;

      current = next;
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

// --------------------------------------------------
// SENSITIVE PATH DETECTION
// Values are inspected locally, never returned.
// --------------------------------------------------

function isSensitivePathSegment(segment, previousSegment = "") {
  const decoded = decodeRepeatedly(
    String(segment || ""),
    3
  );

  const value = decoded.value;
  const lower = value.toLowerCase();
  const previous = String(previousSegment || "").toLowerCase();

  if (/^eyj[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}$/i.test(value)) {
    return true;
  }

  if (/^[a-f0-9]{32,}$/i.test(value)) {
    return true;
  }

  if (
    /^[a-z0-9_-]{40,}$/i.test(value) &&
    /[a-z]/i.test(value) &&
    /[0-9]/.test(value)
  ) {
    return true;
  }

  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    return true;
  }

  if (value.length >= 64 && labelEntropy(value) >= 3.5) {
    return true;
  }

  const secretRouteWords = new Set([
    "token", "access-token", "reset", "reset-password",
    "verify", "verification", "magic-link", "invite",
    "invitation", "session", "authorization", "assertion",
    "ticket", "sso"
  ]);

  if (secretRouteWords.has(previous) && value.length >= 12) {
    return true;
  }

  if (/^(?:token|secret|password|code|auth|session|ticket)=[^/]+$/i.test(lower)) {
    return true;
  }

  return false;
}

// --------------------------------------------------
// PATH ANALYSIS
// --------------------------------------------------

function analyzePath(rawPath) {
  const indicators = [];
  let riskScore = 0;

  const decoded = decodeRepeatedly(rawPath, 2);
  const decodedPath = decoded.value;

  if (decoded.decodingFailed) {
    indicators.push("UNDECODABLE_PATH_ENCODING");
    riskScore += 2;
  }

  if (decoded.additionalDecodes > 0) {
    indicators.push("REPEATED_PATH_ENCODING");
    riskScore += 1;
  }

  if (/%(?:00|0a|0d|09)/i.test(decodedPath)) {
    indicators.push("ENCODED_CONTROL_CHARACTER");
    riskScore += 5;
  }

  if (/(?:^|\/)(?:\.\.|%2e%2e)(?:\/|$)/i.test(decodedPath)) {
    indicators.push("PATH_TRAVERSAL_PATTERN");
    riskScore += 3;
  }

  if (/%(?:2f|5c)/i.test(rawPath)) {
    indicators.push("ENCODED_PATH_SEPARATOR");
    riskScore += 1;
  }

  if (rawPath.length > 2048) {
    indicators.push("VERY_LONG_PATH");
    riskScore += 1;
  }

  const segments = decodedPath.split("/").filter(Boolean);

  if (segments.length > 20) {
    indicators.push("MANY_PATH_SEGMENTS");
    riskScore += 1;
  }

  let sensitivePathSegmentCount = 0;

  for (let index = 0; index < segments.length; index++) {
    if (
      isSensitivePathSegment(
        segments[index],
        segments[index - 1] || ""
      )
    ) {
      sensitivePathSegmentCount++;
    }
  }

  if (sensitivePathSegmentCount > 0) {
    indicators.push("SENSITIVE_PATH_SEGMENT_DETECTED");
  }

  const finalSegment = segments.at(-1) || "";
  const extensionMatch = finalSegment.match(/\.([a-z0-9]{1,10})$/i);
  const extension = extensionMatch
    ? extensionMatch[1].toLowerCase()
    : null;

  // A downloadable executable is a warning indicator,
  // not proof that the file is malicious.
  if (extension && EXECUTABLE_EXTENSIONS.has(extension)) {
    indicators.push("EXECUTABLE_DOWNLOAD_PATH");
    riskScore += 1;
  }

  return {
    indicators: [...new Set(indicators)],
    riskScore,
    segmentCount: segments.length,
    extension,
    originalPathLength: rawPath.length,
    sensitivePathSegmentCount
  };
}

// --------------------------------------------------
// QUERY ANALYSIS
// Important: query values are never returned or sent to Google.
// --------------------------------------------------

function normalizeQueryKey(key) {
  return String(key || "")
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "");
}

function registrable(hostname) {
  return parseDomain(String(hostname || ""))?.domain ||
    String(hostname || "").toLowerCase();
}

function analyzeQuery(parsedUrl) {
  const indicators = [];

  let riskScore = 0;
  let sensitiveParameterCount = 0;
  let redirectParameterCount = 0;
  let nestedDestinationCount = 0;
  let dangerousRedirectCount = 0;
  let doubleEncodedValueCount = 0;
  let nestedBlockedReason = null;

  const params = [...parsedUrl.searchParams.entries()];

  if (parsedUrl.search.length > 4096) {
    indicators.push("LONG_QUERY_STRING");
    riskScore += 1;
  }

  if (params.length > 50) {
    indicators.push("EXCESSIVE_QUERY_PARAMETERS");
    riskScore += 1;
  }

  for (const [key, value] of params) {
    const normalizedKey = normalizeQueryKey(key);
    const compactKey = normalizedKey.replace(/_/g, "");

    const isRedirect =
      REDIRECT_KEYS.has(normalizedKey) ||
      REDIRECT_KEYS.has(compactKey);

    const isSensitive =
      SENSITIVE_KEYS.has(normalizedKey) ||
      SENSITIVE_KEYS.has(compactKey);

    if (isSensitive) {
      sensitiveParameterCount++;
    }

    if (isRedirect) {
      redirectParameterCount++;
    }

    const decoded = decodeRepeatedly(value, 2);

    if (decoded.decodingFailed && isRedirect) {
      indicators.push("REDIRECT_VALUE_ENCODING_ERROR");
      riskScore += 2;
    }

    if (decoded.additionalDecodes > 0 && isRedirect) {
      doubleEncodedValueCount++;
      indicators.push("ENCODED_REDIRECT_VALUE");
      riskScore += 1;
    }

    const candidate = decoded.value.trim();

    // A dangerous nested scheme is blocked locally.
    if (isRedirect && DANGEROUS_SCHEME.test(candidate)) {
      dangerousRedirectCount++;
      indicators.push("DANGEROUS_REDIRECT_SCHEME");
      riskScore += 6;
      continue;
    }

    if (
      isRedirect &&
      /^(?:https?:\/\/|\/\/)/i.test(candidate)
    ) {
      nestedDestinationCount++;

      let nested;

      try {
        nested = candidate.startsWith("//")
          ? new URL(`https:${candidate}`)
          : new URL(candidate);
      } catch {
        indicators.push("INVALID_NESTED_REDIRECT_URL");
        riskScore += 2;
        continue;
      }

      if (nested.username || nested.password) {
        indicators.push("NESTED_REDIRECT_CONTAINS_CREDENTIALS");
        riskScore += 4;
      }

      if (!["http:", "https:"].includes(nested.protocol)) {
        indicators.push("UNSUPPORTED_NESTED_REDIRECT_SCHEME");
        riskScore += 5;
      }

      const nestedDomain = analyzeDomain(
        nested.hostname.toLowerCase().replace(/\.$/, ""),
        nested
      );

      if (nestedDomain.blocked) {
        nestedBlockedReason = nestedDomain.reasonCode;
        indicators.push("NESTED_REDIRECT_DESTINATION_BLOCKED");
      }

      // OAuth cross-site redirects are common. Their presence alone
      // does not increase the phishing risk score.
      if (
        registrable(nested.hostname) !==
        registrable(parsedUrl.hostname)
      ) {
        indicators.push("CROSS_SITE_REDIRECT_PARAMETER");
      }
    }
  }

  let fragmentContainsSensitiveMaterial = false;

  if (parsedUrl.hash) {
    const fragment = decodeRepeatedly(
      parsedUrl.hash.slice(1),
      2
    ).value;

    fragmentContainsSensitiveMaterial =
      /(?:access_token|id_token|token|code|state)=/i.test(fragment) ||
      /^eyj[a-z0-9_-]{8,}\./i.test(fragment);

    if (fragmentContainsSensitiveMaterial) {
      indicators.push("SENSITIVE_FRAGMENT_DETECTED");
    }
  }

  if (sensitiveParameterCount > 0) {
    indicators.push("SENSITIVE_QUERY_PARAMETERS_DETECTED");
  }

  if (redirectParameterCount > 0) {
    indicators.push("REDIRECT_PARAMETER_PRESENT");
  }

  return {
    indicators: [...new Set(indicators)],
    riskScore,
    parameterCount: params.length,
    redirectParameterCount,
    nestedDestinationCount,
    sensitiveParameterCount,
    dangerousRedirectCount,
    doubleEncodedValueCount,
    nestedBlockedReason,
    fragmentPresent: Boolean(parsedUrl.hash),
    fragmentContainsSensitiveMaterial
  };
}

// --------------------------------------------------
// MAIN LOCAL ANALYZER
// --------------------------------------------------

function analyzeUrl(input) {
  const normalized = normalizeUrl(input);

  if (!normalized.ok) {
    return blocked(normalized.reasonCode);
  }

  const {
    parsedUrl,
    hostname,
    rawPath
  } = normalized;

  const domain = analyzeDomain(hostname, parsedUrl);

  if (domain.blocked) {
    return blocked(domain.reasonCode, domain.indicators);
  }

  const path = analyzePath(rawPath);
  const query = analyzeQuery(parsedUrl);

  const indicators = [...new Set([
    ...domain.indicators,
    ...path.indicators,
    ...query.indicators
  ])];

  const riskScore =
    domain.riskScore +
    path.riskScore +
    query.riskScore;

  if (indicators.includes("ENCODED_CONTROL_CHARACTER")) {
    return blocked("ENCODED_CONTROL_CHARACTER", indicators);
  }

  if (indicators.includes("DANGEROUS_REDIRECT_SCHEME")) {
    return blocked("DANGEROUS_REDIRECT_SCHEME", indicators);
  }

  if (indicators.includes("NESTED_REDIRECT_CONTAINS_CREDENTIALS")) {
    return blocked(
      "NESTED_REDIRECT_CONTAINS_CREDENTIALS",
      indicators
    );
  }

  if (query.nestedBlockedReason) {
    return blocked(
      "NESTED_REDIRECT_DESTINATION_BLOCKED",
      indicators
    );
  }

  // Do not penalize ordinary HTTP, OAuth state/code parameters,
  // normal redirect_uri values or a single punycode signal alone.
  const suspicious = riskScore >= 5;

  return {
    decision: suspicious
      ? "SUSPICIOUS"
      : "REPUTATION_CHECK_REQUIRED",

    stage: "LOCAL",

    reasonCodes: suspicious
      ? ["LOCAL_SUSPICIOUS_URL_PATTERN"]
      : ["LOCAL_STRUCTURAL_CHECK_PASSED"],

    indicators,

    destination: domain.destination,

    riskScore,

    urlInspection: {
      path: {
        segmentCount: path.segmentCount,
        extension: path.extension,
        originalPathLength: path.originalPathLength,
        sensitivePathSegmentCount: path.sensitivePathSegmentCount,
        indicators: path.indicators
      },

      query: {
        parameterCount: query.parameterCount,
        redirectParameterCount: query.redirectParameterCount,
        nestedDestinationCount: query.nestedDestinationCount,
        sensitiveParameterCount: query.sensitiveParameterCount,
        fragmentPresent: query.fragmentPresent,
        fragmentContainsSensitiveMaterial:
          query.fragmentContainsSensitiveMaterial,
        indicators: query.indicators
      }
    },

    reputationCheckRequired: true,

    privacy: {
      sensitiveQueryValuesDetected:
        query.sensitiveParameterCount > 0,

      sensitivePathSegmentsDetected:
        path.sensitivePathSegmentCount > 0,

      googleQueryStringExcluded: true,
      googleFragmentExcluded: true
    }
  };
}

// --------------------------------------------------
// GOOGLE PRIVACY POLICY
// NEVER send any path, query or fragment.
// --------------------------------------------------

function getGoogleSafePath() {
  return "/";
}

module.exports = {
  analyzeUrl,
  normalizeUrl,
  analyzeDomain,
  analyzePath,
  analyzeQuery,
  isSensitivePathSegment,
  getGoogleSafePath
};
