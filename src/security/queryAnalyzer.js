"use strict";

const { analyzeDomain } = require("./domainAnalyzer");
const { analyzePath, hasDoubleExtensionMasquerade } = require("./pathAnalyzer");
const { analyzeScamLures } = require("./scamLureAnalyzer");
const { evaluateLexicalAndStructuralRisk } = require("./lexicalRiskEngine");
const { isBlockedHost } = require("./localThreatList");

const REDIRECT_PARAMETERS = new Set([
  "url", "uri", "u", "r", "q", "rd", "redirect", "redirecturl", "redirecturi",
  "redirectto", "redir", "redirurl", "return", "returnto", "returnurl", "ret", "returl",
  "next", "nexturl", "continue", "continueurl", "dest", "desturl", "destination",
  "target", "targeturl", "goto", "go", "jump", "callback", "out", "to",
  "forward", "fallback", "successurl", "failurl", "clickurl", "adurl", "linkurl",
  "postlogoutredirecturi", "logouturi", "canceluri", "link", "href"
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
  /^(?:javascript|data|vbscript|file|content|android-app|intent|upi|paytmmp|phonepe|tez|gpay|bhim|whatsapp|tg|tel|sms|smsto|mmsto|mailto|callto|facetime|geo|market|blob|filesystem|about|view-source|smb|sftp):/i;

function normalizeKey(key) {
  return String(key || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

function decodeRepeatedly(value, maximumPasses = 3) {
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

const HTML_SMUGGLING_CODE_PATTERN =
  /<script\b|<form\b|atob\s*\(|createObjectURL|document\.write|window\.location|location\.replace|fromCharCode/i;

function classifyDecodedPayload(decodedRaw, kind) {
  const trimmed = String(decodedRaw || "").trim();
  const decodedUri = decodeRepeatedly(trimmed, 2).value.trim();
  const candidates = [trimmed, decodedUri];

  for (const cand of candidates) {
    if (HTML_SMUGGLING_CODE_PATTERN.test(cand)) {
      return { decoded: cand, kind, htmlSmuggling: true };
    }
    if (
      /^(?:https?:\/\/|\/\/|\\\\[a-z0-9])/i.test(cand) ||
      DANGEROUS_SCHEME.test(cand.replace(/[\u0000-\u0020\u200B-\u200F\uFEFF\u007f]/g, ""))
    ) {
      return { decoded: cand, kind, htmlSmuggling: false };
    }
  }
  return null;
}

function tryDecodeSmuggledUrl(value) {
  const trimmed = String(value || "").trim();
  if (trimmed.length < 12 || trimmed.length > 2048) return null;

  // Base64 / Base64URL smuggling
  if (/^[A-Za-z0-9+/_-]{12,}={0,2}$/.test(trimmed)) {
    try {
      const normalized = trimmed.replace(/-/g, "+").replace(/_/g, "/");
      const decoded = Buffer.from(normalized, "base64").toString("utf8").trim();
      const match = classifyDecodedPayload(decoded, "BASE64");
      if (match) return match;
    } catch {
      // ignore
    }
  }

  // Hex smuggling (e.g., 68747470733a2f2f...)
  if (trimmed.length >= 24 && trimmed.length % 2 === 0 && /^[0-9a-f]+$/i.test(trimmed)) {
    try {
      const decoded = Buffer.from(trimmed, "hex").toString("utf8").trim();
      const match = classifyDecodedPayload(decoded, "HEX");
      if (match) return match;
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
  const schemeProbe = value.replace(/[\u0000-\u0020\u200B-\u200F\uFEFF\u007f]/g, "");

  if (DANGEROUS_SCHEME.test(schemeProbe)) {
    state.indicators.push("DANGEROUS_REDIRECT_SCHEME");
    state.hardBlockReason = "DANGEROUS_REDIRECT_SCHEME";
    return;
  }

  // Catch backslash protocol-relative smuggling (e.g. \\evil.com) or scheme without //
  if (/^\\\\[a-z0-9]/i.test(value) || /^https?:[^/]/i.test(value)) {
    state.indicators.push("MALFORMED_PROTOCOL_RELATIVE_REDIRECT");
    state.hardBlockReason = "MALFORMED_PROTOCOL_RELATIVE_REDIRECT";
    return;
  }

  const smuggled = tryDecodeSmuggledUrl(value);
  if (smuggled) {
    state.indicators.push(
      smuggled.kind === "HEX" ? "HEX_SMUGGLED_REDIRECT" : "BASE64_SMUGGLED_REDIRECT"
    );
    if (smuggled.htmlSmuggling) {
      state.indicators.push("HTML_SMUGGLING_PAYLOAD_DETECTED");
      state.hardBlockReason = "HTML_SMUGGLING_PAYLOAD_DETECTED";
      return;
    }
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

  // Run full path analysis on nested redirect hop (catches redirects to .apk, double-ext, certs, etc.)
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

  if (nestedPathAnalysis.indicators.includes("MOBILE_CONFIG_OR_CERT_INSTALL_PATH")) {
    state.indicators.push("NESTED_REDIRECT_TO_MOBILE_CONFIG_OR_CERT");
    state.hardBlockReason = "NESTED_REDIRECT_TO_MOBILE_CONFIG_OR_CERT";
    return;
  }

  // Run full scam-lure and lexical phishing-kit checks on nested redirect hop
  const nestedIndicators = [
    ...new Set([
      ...nestedDomainAnalysis.indicators,
      ...nestedPathAnalysis.indicators
    ])
  ];
  const nestedRegDomain = nestedDomainAnalysis.destination?.registrableDomain || null;

  const nestedScam = analyzeScamLures({
    hostname: nested.hostname,
    registrableDomain: nestedRegDomain,
    pathSegments: nestedPathAnalysis.segments,
    parsedUrl: nested.parsedUrl,
    existingIndicators: nestedIndicators
  });

  if (nestedScam.hardBlock) {
    state.indicators.push("NESTED_REDIRECT_SCAM_OR_PHISHING");
    state.blockedNestedDestinationCount++;
    state.hardBlockReason = nestedScam.hardBlockReason;
    return;
  }

  const nestedLexical = evaluateLexicalAndStructuralRisk({
    hostname: nested.hostname,
    registrableDomain: nestedRegDomain,
    parsedUrl: nested.parsedUrl,
    rawPath: nested.parsedUrl.pathname || "/",
    pathSegments: nestedPathAnalysis.segments,
    existingIndicators: [...nestedIndicators, ...nestedScam.indicators]
  });

  if (nestedLexical.hardBlock) {
    state.indicators.push("NESTED_REDIRECT_PHISHING_KIT");
    state.blockedNestedDestinationCount++;
    state.hardBlockReason = nestedLexical.hardBlockReason;
    return;
  }

  // Propagate aggregate nested risk score across domain, path, scam, and lexical layers
  // (prevents open redirects on safe domains like google.com/url?q= from scrubbing threat scores)
  const nestedTotalScore =
    nestedDomainAnalysis.riskScore +
    nestedPathAnalysis.riskScore +
    nestedScam.riskScore +
    nestedLexical.riskScore;

  if (nestedTotalScore >= 7) {
    state.indicators.push("NESTED_REDIRECT_HIGH_RISK_TARGET");
    state.blockedNestedDestinationCount++;
    state.hardBlockReason = "NESTED_REDIRECT_HIGH_RISK_TARGET";
    return;
  }

  if (nestedDomainAnalysis.riskScore >= 4) {
    state.indicators.push("SUSPICIOUS_NESTED_REDIRECT_DOMAIN");
  }

  if (nestedTotalScore >= 3) {
    state.indicators.push("NESTED_REDIRECT_RISK_PROPAGATED");
    state.riskScore += nestedTotalScore;
    for (const nestedInd of [...nestedIndicators, ...nestedScam.indicators, ...nestedLexical.indicators]) {
      if (nestedInd !== "SENSITIVE_QUERY_PARAMETERS_DETECTED" && nestedInd !== "SENSITIVE_QUERY_PARAMETER_PRESENT") {
        state.indicators.push(nestedInd);
      }
    }
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

    const decoded = decodeRepeatedly(value, 3);

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
      const schemeProbe = trimmedVal.replace(/[\u0000-\u0020\u200B-\u200F\uFEFF\u007f]/g, "");

      if (DANGEROUS_SCHEME.test(schemeProbe)) {
        state.indicators.push("DANGEROUS_REDIRECT_SCHEME");
        state.hardBlockReason = "DANGEROUS_REDIRECT_SCHEME";
      } else if (/^(?:https?:\/\/|\/\/|\\\\[a-z0-9])/i.test(trimmedVal)) {
        // Inspect URLs hidden inside non-standard parameter names (?foo=http://192.168.1.1)
        inspectRedirectCandidate(trimmedVal, state, 1);
      } else {
        const smuggled = tryDecodeSmuggledUrl(trimmedVal);
        if (smuggled) {
          state.indicators.push(
            smuggled.kind === "HEX" ? "HEX_SMUGGLED_URL_IN_QUERY" : "BASE64_SMUGGLED_URL_IN_QUERY"
          );
          if (smuggled.htmlSmuggling) {
            state.indicators.push("HTML_SMUGGLING_PAYLOAD_DETECTED");
            state.hardBlockReason = "HTML_SMUGGLING_PAYLOAD_DETECTED";
          } else {
            state.riskScore += 2;
            inspectRedirectCandidate(smuggled.decoded, state, 1);
          }
        } else if (hasDoubleExtensionMasquerade(trimmedVal)) {
          state.indicators.push("DOUBLE_EXTENSION_MASQUERADE");
          state.hardBlockReason = "DOUBLE_EXTENSION_MASQUERADE";
        } else if (/\.(?:apk|aab|xapk|apks|ipa)(?:$|[?#])/i.test(trimmedVal)) {
          state.indicators.push("MOBILE_SIDELOAD_INSTALLER_PATH");
          state.indicators.push("QUERY_MOBILE_INSTALLER_PAYLOAD");
          state.riskScore += 5;
        }
      }
    }
  }

  // Detect UPI collect-request / mandate smuggling parameters inside a web URL query (pa=<vpa@bank> + am/pn/mc/tr)
  const paVal = parsedUrl.searchParams.get("pa");
  if (
    paVal &&
    /^[a-z0-9._-]+@[a-z0-9.-]+$/i.test(paVal.trim()) &&
    (parsedUrl.searchParams.has("am") || parsedUrl.searchParams.has("pn") || parsedUrl.searchParams.has("tr"))
  ) {
    state.indicators.push("UPI_PAYMENT_REQUEST_SMUGGLING_IN_URL");
    state.riskScore += 5;
  }

  if (trackingParameterCount > 0) {
    state.indicators.push("TRACKING_PARAMETERS_DETECTED");
  }

  let fragmentHasUrl = false;
  let fragmentHasSensitiveMaterial = false;

  if (parsedUrl.hash) {
    const rawFragment = parsedUrl.hash.slice(1);
    const fragment = decodeRepeatedly(rawFragment, 3);
    const fragTrimmed = fragment.value.trim();

    fragmentHasUrl = /https?:\/\//i.test(fragTrimmed);
    fragmentHasSensitiveMaterial =
      /(?:access_token|id_token|token|code|state|session)=/i.test(fragTrimmed) ||
      /^eyj[a-z0-9_-]{8,}\./i.test(fragTrimmed);

    if (fragmentHasUrl) {
      state.indicators.push("URL_PRESENT_IN_FRAGMENT");
    }

    if (fragmentHasSensitiveMaterial) {
      state.indicators.push("SENSITIVE_FRAGMENT_PARAMETER_PRESENT");
      state.indicators.push("SENSITIVE_FRAGMENT_DETECTED");
    }

    // Inspect dangerous schemes, URLs, or Base64/Hex smuggling hidden in #fragment
    const fragSchemeProbe = fragTrimmed.replace(/[\u0000-\u0020\u200B-\u200F\uFEFF\u007f]/g, "");
    if (DANGEROUS_SCHEME.test(fragSchemeProbe)) {
      state.indicators.push("FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD");
      state.indicators.push("DANGEROUS_REDIRECT_SCHEME");
      state.hardBlockReason = "DANGEROUS_REDIRECT_SCHEME";
    } else if (/^(?:https?:\/\/|\/\/|\\\\[a-z0-9])/i.test(fragTrimmed)) {
      state.indicators.push("FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD");
      inspectRedirectCandidate(fragTrimmed, state, 1);
    } else {
      const smuggledFrag = tryDecodeSmuggledUrl(fragTrimmed);
      if (smuggledFrag) {
        state.indicators.push("FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD");
        if (smuggledFrag.htmlSmuggling) {
          state.indicators.push("HTML_SMUGGLING_PAYLOAD_DETECTED");
          state.hardBlockReason = "HTML_SMUGGLING_PAYLOAD_DETECTED";
        } else {
          state.riskScore += 3;
          inspectRedirectCandidate(smuggledFrag.decoded, state, 1);
        }
      } else if (fragTrimmed.includes("=")) {
        try {
          const fragParams = new URLSearchParams(fragTrimmed);
          for (const [fKey, fVal] of fragParams.entries()) {
            const normFKey = normalizeKey(fKey);
            const fValTrimmed = String(fVal || "").trim();
            if (
              REDIRECT_PARAMETERS.has(normFKey) ||
              /^(?:https?:\/\/|\/\/)/i.test(fValTrimmed) ||
              DANGEROUS_SCHEME.test(fValTrimmed.replace(/[\u0000-\u0020\u200B-\u200F\uFEFF\u007f]/g, ""))
            ) {
              state.indicators.push("FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD");
              inspectRedirectCandidate(fValTrimmed, state, 1);
            }
          }
        } catch {
          // ignore malformed fragment pairs
        }
      }
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
