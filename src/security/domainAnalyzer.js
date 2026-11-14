"use strict";

const ipaddr = require("ipaddr.js");
const { domainToUnicode } = require("node:url");
const { parse: parseDomain } = require("tldts");

const {
  isBlockedHost,
  isUrlShortener,
  isTunnelOrDynamicDns,
  isFreeUgcOrCloudHosting,
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
  "onion",
  "intranet",
  "corp"
]);

const DANGEROUS_PORTS = new Set([
  "21", "22", "23", "25", "110", "143", "445",
  "1433", "3306", "3389", "4444", "5432", "5900",
  "6379", "6667", "31337"
]);

const BRAND_DOMAINS = {
  // Global Tech, Cloud, Email & Collaboration
  microsoft: new Set([
    "microsoft.com", "microsoftonline.com", "live.com",
    "outlook.com", "office.com", "office365.com",
    "sharepoint.com", "onmicrosoft.com", "azure.com", "bing.com"
  ]),
  google: new Set([
    "google.com", "google.co.in", "googleapis.com",
    "googleusercontent.com", "googlemail.com", "gmail.com",
    "g.co", "youtube.com", "accounts.google.com"
  ]),
  apple: new Set(["apple.com", "icloud.com", "me.com"]),
  adobe: new Set(["adobe.com", "acrobat.com"]),
  docusign: new Set(["docusign.com", "docusign.net"]),
  dropbox: new Set(["dropbox.com"]),
  zoom: new Set(["zoom.us", "zoom.com"]),
  slack: new Set(["slack.com"]),
  github: new Set(["github.com"]),
  linkedin: new Set(["linkedin.com"]),
  cloudflare: new Set(["cloudflare.com"]),
  godaddy: new Set(["godaddy.com"]),
  namecheap: new Set(["namecheap.com"]),

  // Social, Messaging, Streaming & Gaming
  whatsapp: new Set(["whatsapp.com", "whatsapp.net"]),
  facebook: new Set(["facebook.com", "fb.com", "meta.com", "messenger.com"]),
  instagram: new Set(["instagram.com"]),
  telegram: new Set(["telegram.org", "t.me"]),
  discord: new Set(["discord.com", "discord.gg"]),
  snapchat: new Set(["snapchat.com"]),
  tiktok: new Set(["tiktok.com"]),
  twitter: new Set(["twitter.com", "x.com"]),
  netflix: new Set(["netflix.com"]),
  spotify: new Set(["spotify.com"]),
  disneyplus: new Set(["disneyplus.com"]),
  steam: new Set(["steampowered.com", "steamcommunity.com"]),
  roblox: new Set(["roblox.com"]),
  playstation: new Set(["playstation.com", "sony.com"]),

  // Global E-Commerce & Marketplaces
  amazon: new Set(["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com"]),
  flipkart: new Set(["flipkart.com"]),
  ebay: new Set(["ebay.com", "ebay.in", "ebay.co.uk"]),
  walmart: new Set(["walmart.com"]),
  alibaba: new Set(["alibaba.com", "aliexpress.com"]),
  shopify: new Set(["shopify.com"]),
  myntra: new Set(["myntra.com"]),
  meesho: new Set(["meesho.com"]),
  zomato: new Set(["zomato.com"]),
  swiggy: new Set(["swiggy.com"]),

  // Global Crypto, Wallets & Fintech
  paypal: new Set(["paypal.com"]),
  binance: new Set(["binance.com", "binance.us"]),
  coinbase: new Set(["coinbase.com"]),
  metamask: new Set(["metamask.io"]),
  trustwallet: new Set(["trustwallet.com"]),
  ledger: new Set(["ledger.com"]),
  trezor: new Set(["trezor.io"]),
  kraken: new Set(["kraken.com"]),
  blockchain: new Set(["blockchain.com"]),
  opensea: new Set(["opensea.io"]),
  revolut: new Set(["revolut.com"]),
  stripe: new Set(["stripe.com"]),
  cashapp: new Set(["cash.app"]),
  venmo: new Set(["venmo.com"]),
  wise: new Set(["wise.com"]),

  // Global Postal, Courier & Logistics
  fedex: new Set(["fedex.com"]),
  dhl: new Set(["dhl.com"]),
  ups: new Set(["ups.com"]),
  usps: new Set(["usps.com"]),
  royalmail: new Set(["royalmail.com"]),
  canadapost: new Set(["canadapost-postescanada.ca", "canadapost.ca"]),
  auspost: new Set(["auspost.com.au"]),
  bluedart: new Set(["bluedart.com"]),
  delhivery: new Set(["delhivery.com"]),
  dtdc: new Set(["dtdc.in", "dtdc.com"]),
  indiapost: new Set(["indiapost.gov.in"]),

  // Global Banks & Card Networks
  chase: new Set(["chase.com"]),
  bankofamerica: new Set(["bankofamerica.com"]),
  wellsfargo: new Set(["wellsfargo.com"]),
  citibank: new Set(["citi.com", "citibank.com"]),
  hsbc: new Set(["hsbc.com", "hsbc.co.uk"]),
  barclays: new Set(["barclays.co.uk", "barclays.com"]),
  santander: new Set(["santander.co.uk", "santander.com"]),
  capitalone: new Set(["capitalone.com"]),
  americanexpress: new Set(["americanexpress.com"]),
  visa: new Set(["visa.com", "visa.co.in"]),
  mastercard: new Set(["mastercard.com"]),

  // Indian Banks & Payments
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
  bajajfinserv: new Set(["bajajfinserv.in"]),

  // Telecom & Government Portals
  airtel: new Set(["airtel.in"]),
  jio: new Set(["jio.com"]),
  bsnl: new Set(["bsnl.co.in"]),
  verizon: new Set(["verizon.com"]),
  tmobile: new Set(["t-mobile.com"]),
  incometax: new Set(["incometax.gov.in"]),
  uidai: new Set(["uidai.gov.in"]),
  aadhaar: new Set(["uidai.gov.in"]),
  epfo: new Set(["epfindia.gov.in"]),
  digilocker: new Set(["digilocker.gov.in"]),
  irctc: new Set(["irctc.co.in"]),
  irs: new Set(["irs.gov"]),
  hmrc: new Set(["gov.uk"])
};

const DECEPTIVE_DOMAIN_LURE_WORDS = new Set([
  "verify", "verification", "secure", "security", "login", "signin",
  "account", "update", "support", "helpdesk", "billing", "confirm",
  "wallet", "recover", "recovery", "suspend", "suspended", "unlock",
  "alert", "auth", "authenticate", "webmail", "portal", "identity",
  "validation", "claim", "refund", "kyc", "parcel", "delivery",
  "airdrop", "seed", "phish", "phishing", "malware"
]);

const CONFUSABLE_CHAR_MAP = {
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

  const digraph = oneAsI.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d");
  const digraphL = single.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d");

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

/**
 * Detect if an entire official domain (e.g. "sbi.co.in", "paypal.com", "hdfcbank.com")
 * is embedded inside the subdomain prefix of an unrelated domain:
 * e.g., https://sbi.co.in.verify-login.com/ or https://paypal.com.ngrok-free.app/
 */
function hasSpoofedBrandDomainInSubdomain(hostname, registrableDomain) {
  const host = String(hostname || "").toLowerCase();
  const baseDomain = String(registrableDomain || "").toLowerCase();
  if (!baseDomain || host === baseDomain) return false;

  const subdomainPrefix = host.slice(0, Math.max(0, host.length - baseDomain.length - 1));
  if (!subdomainPrefix) return false;

  for (const officialDomains of Object.values(BRAND_DOMAINS)) {
    if (officialDomains.has(baseDomain)) continue;

    for (const official of officialDomains) {
      if (
        subdomainPrefix === official ||
        subdomainPrefix.endsWith(`.${official}`) ||
        subdomainPrefix.includes(`${official}.`) ||
        subdomainPrefix.includes(official.replace(/\./g, "-"))
      ) {
        return true;
      }
    }
  }

  return false;
}

function analyzeBrandImpersonation(hostname, registrableDomain) {
  const { skeleton, hadConfusable } = toConfusableSkeleton(hostname);
  const rawLower = hostname.toLowerCase();
  const baseDomain = (registrableDomain || hostname).toLowerCase();

  const labels = rawLower.split(".");
  const skeletonLabels = skeleton.split(".");

  const indicators = [];
  let riskScore = 0;

  if (hasSpoofedBrandDomainInSubdomain(rawLower, baseDomain)) {
    indicators.push("BRAND_DOMAIN_SPOOFED_IN_SUBDOMAIN");
    riskScore += 8;
  }

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

function isDgaLikeLabel(label) {
  if (!label || label.length < 12) return false;
  const clean = label.replace(/-/g, "");
  if (clean.length < 12) return false;

  const digits = (clean.match(/\d/g) || []).length;
  const digitRatio = digits / clean.length;
  const ent = labelEntropy(clean);

  // Typical random DGA / disposable phishing domain: long, mixed digits, high entropy
  return (ent >= 3.6 && digitRatio >= 0.2) || (clean.length >= 18 && ent >= 3.9);
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

    if (address.range() !== "unicast") {
      return {
        blocked: true,
        reasonCode: "NON_PUBLIC_IP_ADDRESS",
        indicators,
        riskScore
      };
    }

    if (options.obfuscatedIpHost) {
      return {
        blocked: true,
        reasonCode: "OBFUSCATED_IP_EVASION",
        indicators: [...indicators, "IP_LITERAL_HOST", "OBFUSCATED_IP_HOST"],
        riskScore: 10
      };
    }

    const { isKnownSafePublicIp } = require("./knownSafeDomains");
    const normalizedIp = address.toNormalizedString();

    indicators.push("IP_LITERAL_HOST");

    if (isKnownSafePublicIp(normalizedIp) && parsedUrl.protocol === "https:") {
      indicators.push("TRUSTED_PUBLIC_INFRASTRUCTURE_IP");
    } else {
      indicators.push("PUBLIC_IP_LITERAL_HOST");
      riskScore += 4;
    }
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

    const mainDomainLabel = (registrableDomain || host).split(".")[0];
    if (isDgaLikeLabel(mainDomainLabel)) {
      indicators.push("HIGH_ENTROPY_DGA_DOMAIN");
      riskScore += 3;
    }

    if (isUrlShortener(host)) {
      indicators.push("URL_SHORTENER_HIDES_DESTINATION");
      riskScore += 4;
    }

    if (isTunnelOrDynamicDns(host)) {
      indicators.push("FREE_TUNNEL_OR_DYNAMIC_DNS_HOST");
      riskScore += 4;
    }

    if (isFreeUgcOrCloudHosting(host)) {
      indicators.push("FREE_UGC_OR_CLOUD_HOSTING");
      riskScore += 3;
    }

    if (hasHighRiskTld(host)) {
      indicators.push("HIGH_RISK_ABUSED_TLD");
      riskScore += 2;
    }

    const brandAnalysis = analyzeBrandImpersonation(host, registrableDomain);
    indicators.push(...brandAnalysis.indicators);
    riskScore += brandAnalysis.riskScore;

    // Hyphenated IP pattern in subdomain (e.g. 192-168-1-1.auth-update.com)
    if (/(?:^|\.)\d{1,3}(?:-\d{1,3}){3}(?:-|\.)/.test(host)) {
      indicators.push("DASHED_IP_PATTERN_IN_HOSTNAME");
      riskScore += 3;
    }

    // Multiple deceptive auth/security lure words chained in an unrecognized hostname
    // (catches generic global phishing kits targeting brands not in any static list)
    const { isKnownSafeDomain } = require("./knownSafeDomains");
    if (!isKnownSafeDomain(registrableDomain) || isFreeUgcOrCloudHosting(host)) {
      const hostWordTokens = host
        .split(/[.-]+/)
        .filter((t) => t.length >= 3);
      const deceptiveMatches = new Set(
        hostWordTokens.filter((t) => DECEPTIVE_DOMAIN_LURE_WORDS.has(t))
      );

      if (deceptiveMatches.size >= 3) {
        indicators.push("DECEPTIVE_MULTI_LURE_HOSTNAME");
        riskScore += 4;
      } else if (deceptiveMatches.size === 2 && !indicators.includes("BRAND_NAME_IN_UNRELATED_DOMAIN")) {
        indicators.push("DECEPTIVE_AUTH_HOSTNAME_PATTERN");
        riskScore += 3;
      }

      const hyphenCount = (mainDomainLabel.match(/-/g) || []).length;
      if (hyphenCount >= 3 && deceptiveMatches.size >= 1) {
        indicators.push("EXCESSIVE_HYPHEN_LURE_DOMAIN");
        riskScore += 3;
      }
    }
  }

  if (parsedUrl.protocol === "http:") {
    indicators.push("UNENCRYPTED_HTTP");
    riskScore += 1;
  }

  if (parsedUrl.port) {
    indicators.push("NON_STANDARD_PORT");
    riskScore += 2;
  }

  const uniqueIndicators = [...new Set(indicators)];

  if (uniqueIndicators.includes("BRAND_DOMAIN_SPOOFED_IN_SUBDOMAIN")) {
    return {
      blocked: true,
      reasonCode: "BRAND_DOMAIN_SPOOFED_IN_SUBDOMAIN",
      indicators: uniqueIndicators,
      riskScore
    };
  }

  return {
    blocked: false,
    indicators: uniqueIndicators,
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
  hasSpoofedBrandDomainInSubdomain,
  toConfusableSkeleton,
  toLeetVariants
};
