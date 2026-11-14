"use strict";

const { analyzeDomain } = require("./domainAnalyzer");
const { analyzePath } = require("./pathAnalyzer");
const { isBlockedHost } = require("./localThreatList");

const REDIRECT_PARAMETERS = new Set([
  "url", "uri", "u", "redirect", "redirecturl", "redirecturi",
  "redirectto", "return", "returnto", "returnurl", "next", "nexturl",
  "continue", "dest", "destination", "target", "goto", "callback",
  "forward", "postlogoutredirecturi", "logouturi",
  "canceluri", "continueurl", "link", "href"
]);

const SENSITIVE_PARAMETERS = new Set([
  "password", "passwd", "pwd", "passphrase", "token", "accesstoken",
  "refreshtoken", "idtoken", "auth", "authorization", "secret",
  "clientsecret", "code", "state", "session", "sessionid", "sid",
  "jwt", "apikey", "signature", "sig", "otp", "pin", "email",
  "phone", "mobile", "account", "card", "cc", "ssn", "dob", "username",
  "user", "credential", "credentials", "samlrequest", "samlresponse",
  "assertion", "ticket", "nonce", "csrf", "xsrf", "cookie",
  "pan", "aadhaar", "aadhar", "upi", "pa", "cvv"
]);

const TRACKING_PARAMETERS = new Set([
  "utmsource", "utmmedium", "utmcampaign", "utmterm", "utmcontent",
  "fbclid", "gclid", "dclid", "msclkid", "mc_eid", "mceid",
  "igshid", "si", "yclid", "wickedid", "oly_enc_id"
]);

const DANGEROUS_SCHEME =
  /^(?:javascript|data|vbscript|file|intent|upi|tel|sms|smsto|mmsto|market|blob|filesystem|about|view-source):/i;

function normalizeKey(key) {
  return String(key || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

function decodeRepeatedly(value, maximumPasses = 2) {
  let current = String(value ?? "");
  let additionalDecodes = 0;

  for (let index = 0; index < maximumPasses; index++) {
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) break;
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

function tryDecodeSmuggledUrl(value) {
  const trimmed = String(value || "").trim();
  if (trimmed.length < 12 || trimmed.length > 2048) return null;

  // Base64 / Base64URL smuggling
  if (/^[A-Za-z0-9+/_-]{12,}={0,2}$/.test(trimmed)) {
    try {
      const normalized = trimmed.replace(/-/g, "+").replace(/_/g, "/");
      const decoded = Buffer.from(normalized, "base64").toString("utf8").trim();
      if (
        /^(?:https?:\/\/|\/\/)/i.test(decoded) ||
        DANGEROUS_SCHEME.test(decoded.replace(/[\u0000-\u0020\u007f]/g, ""))
      ) {
        return { decoded, kind: "BASE64" };
      }
    } catch {
      // ignore
    }
  }

  // Hex smuggling (e.g., 68747470733a2f2f...)
  if (trimmed.length >= 24 && trimmed.length % 2 === 0 && /^[0-9a-f]+$/i.test(trimmed)) {
    try {
      const decoded = Buffer.from(trimmed, "hex").toString("utf8").trim();
      if (
        /^(?:https?:\/\/|\/\/)/i.test(decoded) ||
        DANGEROUS_SCHEME.test(decoded.replace(/[\u0000-\u0020\u007f]/g, ""))
      ) {
        return { decoded, kind: "HEX" };
      }
    } catch {
      // ignore
    }
  }

  return null;
}

function parseNestedHttpUrl(value) {
  const candidate = String(value || "").trim();

  if (!/^(?:https?:\/\/|\/\/)/i.test(candidate)) {
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
    hostname: nestedUrl.hostname.toLowerCase().replace(/\.$/, ""),
    hasCredentials: Boolean(nestedUrl.username || nestedUrl.password),
    protocol: nestedUrl.protocol,
    parsedUrl: nestedUrl
  };
}

function inspectRedirectCandidate(candidate, state, depth = 0) {
  const value = String(candidate || "").trim();
  const schemeProbe = value.replace(/[\u0000-\u0020\u007f]/g, "");

  if (DANGEROUS_SCHEME.test(schemeProbe)) {
    state.indicators.push("DANGEROUS_REDIRECT_SCHEME");
    state.hardBlockReason = "DANGEROUS_REDIRECT_SCHEME";
    return;
  }

  const smuggled = tryDecodeSmuggledUrl(value);
  if (smuggled) {
    state.indicators.push(
      smuggled.kind === "HEX" ? "HEX_SMUGGLED_REDIRECT" : "BASE64_SMUGGLED_REDIRECT"
    );
    state.riskScore += 2;
    inspectRedirectCandidate(smuggled.decoded, state, depth + 1);
    return;
  }

  const nested = parseNestedHttpUrl(value);
  if (!nested) return;

  if (nested.invalid) {
    state.indicators.push("INVALID_NESTED_REDIRECT_URL");
    state.riskScore += 1;
    return;
  }

  state.nestedDestinationCount++;

  if (nested.hasCredentials) {
    state.indicators.push("NESTED_REDIRECT_CONTAINS_CREDENTIALS");
    state.hardBlockReason = "NESTED_REDIRECT_CONTAINS_CREDENTIALS";
    return;
  }

  if (isBlockedHost(nested.hostname)) {
    state.indicators.push("NESTED_REDIRECT_MATCHES_LOCAL_BLOCKLIST");
    state.blockedNestedDestinationCount++;
    state.hardBlockReason = "NESTED_REDIRECT_MATCHES_LOCAL_BLOCKLIST";
    return;
  }

  // Run full local domain analysis on nested redirect hop
  const nestedDomainAnalysis = analyzeDomain(nested.hostname, nested.parsedUrl);
  if (nestedDomainAnalysis.blocked) {
    state.indicators.push("NESTED_REDIRECT_DESTINATION_BLOCKED");
    state.blockedNestedDestinationCount++;
    state.hardBlockReason = nestedDomainAnalysis.reasonCode;
    return;
  }

  // Run full path analysis on nested redirect hop (catches redirects to .apk, double-ext, etc.)
  const nestedPathAnalysis = analyzePath(nested.parsedUrl.pathname || "/");
  if (nestedPathAnalysis.hardBlock) {
    state.indicators.push("NESTED_REDIRECT_MALICIOUS_PATH");
    state.hardBlockReason = nestedPathAnalysis.hardBlockReason;
    return;
  }

  if (nestedPathAnalysis.indicators.includes("MOBILE_SIDELOAD_INSTALLER_PATH")) {
    state.indicators.push("NESTED_REDIRECT_TO_MOBILE_INSTALLER");
    state.hardBlockReason = "NESTED_REDIRECT_TO_MOBILE_INSTALLER";
    return;
  }

  if (nestedDomainAnalysis.riskScore >= 4) {
    state.indicators.push("SUSPICIOUS_NESTED_REDIRECT_DOMAIN");
    state.riskScore += nestedDomainAnalysis.riskScore;
  }

  state.indicators.push("NESTED_REDIRECT_DESTINATION_INSPECTED");

  if (depth >= 3) {
    if ([...nested.parsedUrl.searchParams.keys()].length > 0) {
      state.indicators.push("REDIRECT_CHAIN_DEPTH_LIMIT_REACHED");
      state.riskScore += 1;
    }
    return;
  }

  const identity = nested.parsedUrl.href;
  if (state.seenNested.has(identity)) return;
  state.seenNested.add(identity);

  for (const [nestedKey, nestedValue] of nested.parsedUrl.searchParams.entries()) {
    if (!REDIRECT_PARAMETERS.has(normalizeKey(nestedKey))) {
      continue;
    }

    const decoded = decodeRepeatedly(nestedValue, 2);
    if (decoded.decodingFailed) {
      state.indicators.push("NESTED_REDIRECT_ENCODING_ERROR");
      state.riskScore += 1;
      continue;
    }

    inspectRedirectCandidate(decoded.value, state, depth + 1);
  }
}

function analyzeQuery(parsedUrl) {
  const state = {
    indicators: [],
    riskScore: 0,
    hardBlockReason: null,
    nestedDestinationCount: 0,
    blockedNestedDestinationCount: 0,
    seenNested: new Set()
  };

  const params = Array.from(parsedUrl.searchParams.entries());

  let redirectParameterCount = 0;
  let sensitiveParameterCount = 0;
  let trackingParameterCount = 0;
  let malformedRedirectCount = 0;
  let doubleEncodedValueCount = 0;

  if (parsedUrl.search.length > 4096) {
    state.indicators.push("LONG_QUERY_STRING");
    state.riskScore += 1;
  }

  if (params.length > 50) {
    state.indicators.push("EXCESSIVE_QUERY_PARAMETERS");
    state.riskScore += 1;
  }

  for (const [key, value] of params) {
    const normalizedKey = normalizeKey(key);

    const isRedirect = REDIRECT_PARAMETERS.has(normalizedKey);
    const isSensitive = SENSITIVE_PARAMETERS.has(normalizedKey);
    const isTracking = TRACKING_PARAMETERS.has(normalizedKey);

    if (isRedirect) {
      redirectParameterCount++;
      state.indicators.push("REDIRECT_PARAMETER_PRESENT");
    }

    if (isSensitive) {
      sensitiveParameterCount++;
      state.indicators.push("SENSITIVE_QUERY_PARAMETER_PRESENT");
      state.indicators.push("SENSITIVE_QUERY_PARAMETERS_DETECTED");
    }

    if (isTracking) {
      trackingParameterCount++;
    }

    const decoded = decodeRepeatedly(value, 2);

    if (decoded.decodingFailed) {
      state.indicators.push("QUERY_VALUE_ENCODING_ERROR");
      if (isRedirect) {
        malformedRedirectCount++;
        state.riskScore += 1;
      }
      continue;
    }

    if (decoded.additionalDecodes > 0) {
      doubleEncodedValueCount++;
      state.indicators.push("ADDITIONAL_QUERY_ENCODING");
    }

    if (isRedirect) {
      inspectRedirectCandidate(decoded.value, state, 0);
    } else {
      const trimmedVal = decoded.value.trim();
      if (DANGEROUS_SCHEME.test(trimmedVal)) {
        state.indicators.push("DANGEROUS_SCHEME_TEXT_IN_QUERY_VALUE");
      } else {
        const smuggled = tryDecodeSmuggledUrl(trimmedVal);
        if (smuggled) {
          state.indicators.push(
            smuggled.kind === "HEX" ? "HEX_SMUGGLED_URL_IN_QUERY" : "BASE64_SMUGGLED_URL_IN_QUERY"
          );
          state.riskScore += 2;
          inspectRedirectCandidate(smuggled.decoded, state, 1);
        }
      }
    }
  }

  if (trackingParameterCount > 0) {
    state.indicators.push("TRACKING_PARAMETERS_DETECTED");
  }

  let fragmentHasUrl = false;
  let fragmentHasSensitiveMaterial = false;

  if (parsedUrl.hash) {
    const fragment = decodeRepeatedly(parsedUrl.hash.slice(1), 2);
    fragmentHasUrl = /https?:\/\//i.test(fragment.value);
    fragmentHasSensitiveMaterial =
      /(?:access_token|id_token|token|code|state|session)=/i.test(fragment.value) ||
      /^eyj[a-z0-9_-]{8,}\./i.test(fragment.value);

    if (fragmentHasUrl) {
      state.indicators.push("URL_PRESENT_IN_FRAGMENT");
    }

    if (fragmentHasSensitiveMaterial) {
      state.indicators.push("SENSITIVE_FRAGMENT_PARAMETER_PRESENT");
      state.indicators.push("SENSITIVE_FRAGMENT_DETECTED");
    }
  }

  return {
    indicators: [...new Set(state.indicators)],
    riskScore: state.riskScore,
    hardBlockReason: state.hardBlockReason,
    parameterCount: params.length,
    redirectParameterCount,
    nestedDestinationCount: state.nestedDestinationCount,
    sensitiveParameterCount,
    trackingParameterCount,
    malformedRedirectCount,
    doubleEncodedValueCount,
    blockedNestedDestinationCount: state.blockedNestedDestinationCount,
    fragmentPresent: Boolean(parsedUrl.hash),
    fragmentHasUrl,
    fragmentContainsSensitiveMaterial: fragmentHasSensitiveMaterial,
    fragmentHasSensitiveMaterial
  };
}

module.exports = {
  analyzeQuery,
  decodeRepeatedly,
  normalizeKey,
  tryDecodeSmuggledUrl
};
