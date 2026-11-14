"use strict";

const ipaddr = require("ipaddr.js");
const { domainToUnicode } = require("node:url");
const { parse: parseDomain } = require("tldts");

const {
  isBlockedHost,
  isUrlShortener,
  isTunnelOrDynamicDns,
  hasHighRiskTld
} = require("./localThreatList");

const RESERVED_SUFFIXES = new Set([
  "localhost",
  "local",
  "internal",
  "test",
  "invalid",
  "example",
  "lan",
  "home",
  "arpa",
  "onion"
]);

const DANGEROUS_PORTS = new Set([
  "21", "22", "23", "25", "110", "143", "445",
  "1433", "3306", "3389", "4444", "5432", "5900", "6379"
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
    "g.co",
    "youtube.com"
  ]),
  apple: new Set(["apple.com", "icloud.com"]),
  paypal: new Set(["paypal.com"]),
  amazon: new Set(["amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"]),
  flipkart: new Set(["flipkart.com"]),
  whatsapp: new Set(["whatsapp.com", "whatsapp.net"]),
  facebook: new Set(["facebook.com", "fb.com", "meta.com", "messenger.com"]),
  instagram: new Set(["instagram.com"]),
  netflix: new Set(["netflix.com"]),

  // Indian Banks & Payments (prime targets of "amount credited" SMS scams)
  sbi: new Set(["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"]),
  hdfc: new Set(["hdfcbank.com"]),
  hdfcbank: new Set(["hdfcbank.com"]),
  icici: new Set(["icicibank.com"]),
  icicibank: new Set(["icicibank.com"]),
  axisbank: new Set(["axisbank.com"]),
  kotak: new Set(["kotak.com"]),
  pnb: new Set(["pnbindia.in"]),
  canarabank: new Set(["canarabank.com"]),
  bankofbaroda: new Set(["bankofbaroda.in"]),
  unionbank: new Set(["unionbankofindia.co.in"]),
  indusind: new Set(["indusind.com"]),
  yesbank: new Set(["yesbank.in"]),
  idfc: new Set(["idfcfirstbank.com"]),
  phonepe: new Set(["phonepe.com"]),
  paytm: new Set(["paytm.com"]),
  bhim: new Set(["bhimupi.org.in"]),
  npci: new Set(["npci.org.in"]),
  razorpay: new Set(["razorpay.com"]),

  // Global Banks
  chase: new Set(["chase.com"]),
  bankofamerica: new Set(["bankofamerica.com"]),
  wellsfargo: new Set(["wellsfargo.com"]),
  hsbc: new Set(["hsbc.com"]),

  // Telecom, Govt & Delivery
  airtel: new Set(["airtel.in"]),
  jio: new Set(["jio.com"]),
  bsnl: new Set(["bsnl.co.in"]),
  incometax: new Set(["incometax.gov.in"]),
  uidai: new Set(["uidai.gov.in"]),
  aadhaar: new Set(["uidai.gov.in"]),
  epfo: new Set(["epfindia.gov.in"]),
  digilocker: new Set(["digilocker.gov.in"]),
  indiapost: new Set(["indiapost.gov.in"]),
  irctc: new Set(["irctc.co.in"]),
  fedex: new Set(["fedex.com"]),
  bluedart: new Set(["bluedart.com"]),
  delhivery: new Set(["delhivery.com"])
};

// Confusable Unicode -> Latin ASCII skeleton map (Cyrillic, Greek, etc.)
const CONFUSABLE_CHAR_MAP = {
  // Cyrillic lowercase & uppercase mapped to visually identical Latin
  "\u0430": "a", "\u0410": "a",
  "\u0432": "b", "\u0412": "b",
  "\u0435": "e", "\u0415": "e",
  "\u0451": "e", "\u0401": "e",
  "\u043A": "k", "\u041A": "k",
  "\u043C": "m", "\u041C": "m",
  "\u043D": "h", "\u041D": "h",
  "\u043E": "o", "\u041E": "o",
  "\u0440": "p", "\u0420": "p",
  "\u0441": "c", "\u0421": "c",
  "\u0442": "t", "\u0422": "t",
  "\u0443": "y", "\u0423": "y",
  "\u0445": "x", "\u0425": "x",
  "\u0456": "i", "\u0406": "i",
  "\u0455": "s", "\u0405": "s",
  "\u0458": "j", "\u0408": "j",
  "\u04BB": "h", "\u04BA": "h",
  "\u0501": "d", "\u04CF": "l", "\u04C0": "l",
  "\u0578": "n", "\u0570": "h", "\u0585": "o",
  // Greek lookalikes
  "\u03B1": "a", "\u0391": "a",
  "\u03B2": "b", "\u0392": "b",
  "\u03B5": "e", "\u0395": "e",
  "\u03B6": "z", "\u0396": "z",
  "\u03B7": "n", "\u0397": "h",
  "\u03B9": "i", "\u0399": "i",
  "\u03BA": "k", "\u039A": "k",
  "\u03BC": "m", "\u039C": "m",
  "\u03BD": "v", "\u039D": "n",
  "\u03BF": "o", "\u039F": "o",
  "\u03C1": "p", "\u03A1": "p",
  "\u03C4": "t", "\u03A4": "t",
  "\u03C5": "u", "\u03A5": "y",
  "\u03C7": "x", "\u03A7": "x"
};

function toConfusableSkeleton(hostname) {
  const unicode = domainToUnicode(hostname) || hostname;
  let out = "";
  let hadConfusable = false;

  for (const ch of unicode.toLowerCase()) {
    if (CONFUSABLE_CHAR_MAP[ch]) {
      out += CONFUSABLE_CHAR_MAP[ch];
      hadConfusable = true;
    } else {
      out += ch;
    }
  }

  return { skeleton: out, hadConfusable };
}

function toLeetVariants(token) {
  const single = token
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/8/g, "b");

  const oneAsI = token
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/8/g, "b");

  const digraph = oneAsI.replace(/rn/g, "m").replace(/vv/g, "w");
  const digraphL = single.replace(/rn/g, "m").replace(/vv/g, "w");

  return [...new Set([token, single, oneAsI, digraph, digraphL])];
}

function isReservedHostname(hostname) {
  const host = String(hostname || "").toLowerCase();

  return [...RESERVED_SUFFIXES].some(
    (suffix) => host === suffix || host.endsWith(`.${suffix}`)
  );
}

function hasValidDnsLabels(hostname) {
  if (!hostname || hostname.length > 253 || !hostname.includes(".")) {
    return false;
  }

  return hostname.split(".").every(
    (label) =>
      label.length >= 1 &&
      label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
  );
}

function labelEntropy(value) {
  if (!value) return 0;

  const counts = new Map();
  for (const character of value) {
    counts.set(character, (counts.get(character) || 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
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

  const securityRelevant = [...scripts].filter((script) =>
    ["Latin", "Cyrillic", "Greek"].includes(script)
  );

  return securityRelevant.length > 1;
}

function editDistance(a, b) {
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);

  for (let i = 1; i <= a.length; i++) {
    const current = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min(
        current[j - 1] + 1,
        previous[j] + 1,
        previous[j - 1] + cost
      );
    }
    previous = current;
  }

  return previous[b.length];
}

function editDistanceAtMost(a, b, maxDist) {
  if (Math.abs(a.length - b.length) > maxDist || a === b) {
    return false;
  }
  const dist = editDistance(a, b);
  return dist > 0 && dist <= maxDist;
}

function analyzeBrandImpersonation(hostname, registrableDomain) {
  const { skeleton, hadConfusable } = toConfusableSkeleton(hostname);
  const rawLower = hostname.toLowerCase();
  const baseDomain = (registrableDomain || hostname).toLowerCase();

  const labels = rawLower.split(".");
  const skeletonLabels = skeleton.split(".");

  const indicators = [];
  let riskScore = 0;

  const extractTokens = (lbls) =>
    lbls.flatMap((label) => label.split(/[^a-z0-9]+/).filter(Boolean));

  const rawTokens = extractTokens(labels);
  const skeletonTokens = extractTokens(skeletonLabels);
  const allTokenVariants = [...new Set([...rawTokens, ...skeletonTokens])].flatMap(
    toLeetVariants
  );

  for (const [brand, officialDomains] of Object.entries(BRAND_DOMAINS)) {
    if (officialDomains.has(baseDomain)) {
      continue;
    }

    // Also avoid flagging legitimate subdomains/domains that are official under another entry
    // when checking skeleton match.
    const maxTypos = brand.length >= 6 ? 2 : brand.length >= 4 ? 1 : 0;

    const directOrSubMatch = allTokenVariants.some((token) => {
      if (token === brand) return true;
      if (brand.length >= 4 && token.includes(brand)) return true;
      if (maxTypos > 0 && token.length >= 4 && editDistanceAtMost(token, brand, maxTypos)) {
        return true;
      }
      return false;
    });

    const baseFirstLabel = baseDomain.split(".")[0].replace(/[^a-z0-9]/g, "");
    const baseVariants = toLeetVariants(baseFirstLabel);

    const lookalikeBase =
      maxTypos > 0 &&
      baseVariants.some(
        (cand) =>
          cand.length >= 4 &&
          (cand === brand || editDistanceAtMost(cand, brand, maxTypos))
      );

    if (directOrSubMatch) {
      indicators.push("BRAND_NAME_IN_UNRELATED_DOMAIN");
      riskScore += 4;
      if (hadConfusable) {
        indicators.push("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION");
        riskScore += 4;
      }
      break;
    }

    if (lookalikeBase) {
      indicators.push("POSSIBLE_BRAND_LOOKALIKE_DOMAIN");
      riskScore += 4;
      if (hadConfusable) {
        indicators.push("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION");
        riskScore += 4;
      }
      break;
    }
  }

  return {
    indicators: [...new Set(indicators)],
    riskScore
  };
}

function analyzeDomain(hostname, parsedUrl, options = {}) {
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

  if (parsedUrl.port && DANGEROUS_PORTS.has(String(parsedUrl.port))) {
    return {
      blocked: true,
      reasonCode: "DANGEROUS_NON_WEB_PORT",
      indicators: ["DANGEROUS_NON_WEB_PORT"],
      riskScore: 10
    };
  }

  if (options.obfuscatedIpHost) {
    indicators.push("OBFUSCATED_IP_HOST");
    riskScore += 4;
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

    // Blocks private, loopback, link-local (169.254/16 cloud metadata),
    // carrier-grade NAT (100.64/10), multicast, reserved, and unspecified IPs.
    if (address.range() !== "unicast") {
      return {
        blocked: true,
        reasonCode: "NON_PUBLIC_IP_ADDRESS",
        indicators,
        riskScore
      };
    }

    indicators.push("IP_LITERAL_HOST");
    indicators.push("PUBLIC_IP_LITERAL_HOST");
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

    if (!domainInfo?.publicSuffix || !registrableDomain) {
      indicators.push("PUBLIC_SUFFIX_NOT_RECOGNIZED_LOCALLY");
      riskScore += 1;
      registrableDomain = host;
    }

    const labels = host.split(".");

    if (labels.some((label) => label.startsWith("xn--"))) {
      indicators.push("PUNYCODE_HOSTNAME");
      riskScore += 1;

      if (hasMixedScripts(host)) {
        indicators.push("MIXED_SCRIPT_IDN_HOSTNAME");
        riskScore += 3;
      } else {
        const { hadConfusable } = toConfusableSkeleton(host);
        if (hadConfusable) {
          indicators.push("NON_LATIN_CONFUSABLE_IDN_HOSTNAME");
          riskScore += 2;
        }
      }
    }

    if (labels.length > 5) {
      indicators.push("MANY_SUBDOMAINS");
      riskScore += labels.length > 8 ? 2 : 1;
    }

    if (labels.some((label) => label.length >= 40)) {
      indicators.push("VERY_LONG_HOST_LABEL");
      riskScore += 1;
    }

    const suspiciousLabel = labels.some(
      (label) =>
        label.length >= 18 &&
        labelEntropy(label) >= 3.7 &&
        /[0-9]/.test(label)
    );

    if (suspiciousLabel) {
      indicators.push("HIGH_ENTROPY_HOST_LABEL");
      riskScore += 1;
    }

    if (isUrlShortener(host)) {
      indicators.push("URL_SHORTENER_HIDES_DESTINATION");
      riskScore += 4;
    }

    if (isTunnelOrDynamicDns(host)) {
      indicators.push("FREE_TUNNEL_OR_DYNAMIC_DNS_HOST");
      riskScore += 3;
    }

    if (hasHighRiskTld(host)) {
      indicators.push("HIGH_RISK_ABUSED_TLD");
      riskScore += 2;
    }

    const brandAnalysis = analyzeBrandImpersonation(host, registrableDomain);
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
  analyzeBrandImpersonation,
  toConfusableSkeleton,
  toLeetVariants
};
