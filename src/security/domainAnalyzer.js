
"use strict";

const ipaddr = require("ipaddr.js");
const { domainToUnicode } = require("node:url");
const { parse: parseDomain } = require("tldts");

const { isBlockedHost } = require("./localThreatList");

const RESERVED_SUFFIXES = new Set([
  "localhost",
  "local",
  "internal",
  "test",
  "invalid",
  "example"
]);

const BRAND_DOMAINS = {
  microsoft: new Set([
    "microsoft.com",
    "microsoftonline.com",
    "live.com",
    "outlook.com",
    "office.com",
    "office365.com",
    "sharepoint.com",
    "onmicrosoft.com"
  ]),

  google: new Set([
    "google.com",
    "google.co.in",
    "googleapis.com",
    "googleusercontent.com",
    "googlemail.com",
    "gmail.com",
    "g.co"
  ]),

  apple: new Set([
    "apple.com",
    "icloud.com"
  ]),

  paypal: new Set([
    "paypal.com"
  ]),

  amazon: new Set([
    "amazon.com",
    "amazon.in",
    "amazon.co.uk",
    "amazonaws.com"
  ]),

  whatsapp: new Set([
    "whatsapp.com",
    "whatsapp.net"
  ]),

  facebook: new Set([
    "facebook.com",
    "fb.com",
    "meta.com",
    "messenger.com"
  ]),

  instagram: new Set([
    "instagram.com"
  ]),

  sbi: new Set([
    "sbi.co.in",
    "onlinesbi.sbi"
  ]),

  hdfc: new Set([
    "hdfcbank.com"
  ]),

  icici: new Set([
    "icicibank.com"
  ]),

  axisbank: new Set([
    "axisbank.com"
  ]),

  kotak: new Set([
    "kotak.com"
  ])
};

function isReservedHostname(hostname) {
  const host = String(hostname || "").toLowerCase();

  return [...RESERVED_SUFFIXES].some(suffix =>
    host === suffix || host.endsWith(`.${suffix}`)
  );
}

function hasValidDnsLabels(hostname) {
  if (!hostname || hostname.length > 253) {
    return false;
  }

  return hostname.split(".").every(label =>
    label.length >= 1 &&
    label.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
  );
}

function hasMixedScripts(hostname) {
  const unicode = domainToUnicode(hostname) || hostname;
  const scripts = new Set();

  for (const character of unicode) {
    if (/\p{Script=Latin}/u.test(character)) scripts.add("Latin");
    if (/\p{Script=Cyrillic}/u.test(character)) scripts.add("Cyrillic");
    if (/\p{Script=Greek}/u.test(character)) scripts.add("Greek");
    if (/\p{Script=Arabic}/u.test(character)) scripts.add("Arabic");
    if (/\p{Script=Han}/u.test(character)) scripts.add("Han");
    if (/\p{Script=Hiragana}/u.test(character)) scripts.add("Hiragana");
    if (/\p{Script=Katakana}/u.test(character)) scripts.add("Katakana");
  }

  const securityRelevant = [...scripts].filter(script =>
    ["Latin", "Cyrillic", "Greek"].includes(script)
  );

  return securityRelevant.length > 1;
}

function editDistanceAtMostTwo(a, b) {
  if (Math.abs(a.length - b.length) > 2 || a === b) {
    return false;
  }

  let previous = Array.from(
    { length: b.length + 1 },
    (_, index) => index
  );

  for (let i = 1; i <= a.length; i++) {
    const current = [i];
    let rowMinimum = current[0];

    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;

      current[j] = Math.min(
        current[j - 1] + 1,
        previous[j] + 1,
        previous[j - 1] + cost
      );

      rowMinimum = Math.min(rowMinimum, current[j]);
    }

    if (rowMinimum > 2) return false;

    previous = current;
  }

  return previous[b.length] > 0 && previous[b.length] <= 2;
}

function analyzeBrandImpersonation(hostname, registrableDomain) {
  const labels = hostname.toLowerCase().split(".");
  const baseDomain = (registrableDomain || hostname).toLowerCase();

  const indicators = [];
  let riskScore = 0;

  for (const [brand, officialDomains] of Object.entries(BRAND_DOMAINS)) {
    if (officialDomains.has(baseDomain)) {
      continue;
    }

    const brandTokens = labels.flatMap(label =>
      label.split(/[^a-z0-9]+/).filter(Boolean)
    );

    const matchingLabel = brandTokens.find(token =>
      token.includes(brand) ||
      editDistanceAtMostTwo(token, brand)
    );

    if (matchingLabel) {
      indicators.push("BRAND_NAME_IN_UNRELATED_DOMAIN");
      riskScore += 4;
      break;
    }

    const candidateTokens = [
      ...brandTokens,
      baseDomain.split(".")[0].replace(/[^a-z0-9]/g, "")
    ];

    if (
      candidateTokens.some(candidate =>
        candidate.length >= 4 &&
        editDistanceAtMostTwo(candidate, brand)
      )
    ) {
      indicators.push("POSSIBLE_BRAND_LOOKALIKE_DOMAIN");
      riskScore += 4;
      break;
    }
  }

  return {
    indicators,
    riskScore
  };
}

function analyzeDomain(hostname, parsedUrl) {
  const indicators = [];
  let riskScore = 0;

  const host = String(hostname || "")
    .toLowerCase()
    .replace(/\.$/, "");

  if (!host || host.length > 253) {
    return {
      blocked: true,
      reasonCode: "INVALID_HOSTNAME",
      indicators,
      riskScore
    };
  }

  if (isReservedHostname(host)) {
    return {
      blocked: true,
      reasonCode: "NON_PUBLIC_HOSTNAME",
      indicators,
      riskScore
    };
  }

  if (isBlockedHost(host)) {
    return {
      blocked: true,
      reasonCode: "LOCAL_THREAT_LIST_MATCH",
      indicators,
      riskScore
    };
  }

  const ipCandidate = host.replace(/^\[|\]$/g, "");
  const isIp = ipaddr.isValid(ipCandidate);

  let registrableDomain = null;

  if (isIp) {
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
    if (!hasValidDnsLabels(host)) {
      return {
        blocked: true,
        reasonCode: "INVALID_HOSTNAME",
        indicators,
        riskScore
      };
    }

    const domainInfo = parseDomain(host);

    registrableDomain = domainInfo?.domain || null;

    // Public-suffix databases can lag behind new TLDs.
    // An unknown suffix is uncertainty, not proof of phishing.
    if (!domainInfo?.publicSuffix || !registrableDomain) {
      indicators.push("PUBLIC_SUFFIX_NOT_RECOGNIZED_LOCALLY");
      riskScore += 1;
      registrableDomain = host;
    }

    if (host.split(".").some(label => label.startsWith("xn--"))) {
      indicators.push("PUNYCODE_HOSTNAME");
      riskScore += 1;

      if (hasMixedScripts(host)) {
        indicators.push("MIXED_SCRIPT_IDN_HOSTNAME");
        riskScore += 3;
      }
    }

    const labels = host.split(".");

    if (labels.length > 5) {
      indicators.push("MANY_SUBDOMAINS");
      riskScore += 1;
    }

    if (labels.some(label => label.length >= 40)) {
      indicators.push("VERY_LONG_HOST_LABEL");
      riskScore += 1;
    }

    const brandAnalysis = analyzeBrandImpersonation(
      host,
      registrableDomain
    );

    indicators.push(...brandAnalysis.indicators);
    riskScore += brandAnalysis.riskScore;
  }

  if (parsedUrl.protocol === "http:") {
    indicators.push("UNENCRYPTED_HTTP");
    riskScore += 1;
  }

  if (parsedUrl.port) {
    indicators.push("NON_STANDARD_PORT");
    riskScore += 2;
  }

  return {
    blocked: false,
    indicators: [...new Set(indicators)],
    riskScore,

    destination: {
      hostname: host,
      registrableDomain,
      protocol: parsedUrl.protocol,
      nonStandardPort: Boolean(parsedUrl.port)
    }
  };
}

module.exports = {
  analyzeDomain,
  isReservedHostname,
  hasMixedScripts,
  analyzeBrandImpersonation
};
