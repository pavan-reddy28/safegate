"use strict";

const { domainToUnicode } = require("node:url");
const { isKnownSafeDomain } = require("./knownSafeDomains");
const { isFreeUgcOrCloudHosting } = require("./localThreatList");

/**
 * lexicalRiskEngine.js
 *
 * 100% on-device heuristic, structural & intent-classification phishing engine.
 * Designed to automatically detect ZERO-DAY / UNSEEN phishing kits, compromised
 * site drops, DGA domains, subdomain TLD-masquerading, fragment email-prefill traps,
 * and multi-vector social engineering WITHOUT relying on any static bad-URL blocklist.
 *
 * Zero URL paths, query values, or fragments are ever logged or returned.
 */

// 7 independent social-engineering & threat intent vectors (stem/prefix-aware)
const INTENT_VECTORS = {
  AUTH_IDENTITY: [
    "login", "signin", "logon", "auth", "sso", "webmail", "cpanel", "roundcube",
    "zimbra", "portal", "account", "passwd", "password", "passcode", "credential",
    "2fa", "mfa", "otp", "pin", "cvv", "kyc", "aadhaar", "aadhar", "ssn", "pan"
  ],
  URGENCY_THREAT: [
    "verify", "verif", "confirm", "validat", "reverify", "update", "renew",
    "reactivat", "recover", "unlock", "unblock", "suspend", "restrict", "lock",
    "disabl", "expir", "alert", "warn", "urgent", "appeal", "dispute", "unusual",
    "overdue", "failed", "declined", "blocked", "disconnect", "termination"
  ],
  FINANCIAL_LURE: [
    "pay", "payment", "billing", "invoice", "receipt", "refund", "tax", "rebate",
    "claim", "reward", "bonus", "cashback", "credit", "credited", "prize", "winner",
    "lottery", "jackpot", "gift", "giveaway", "subsidy", "loan", "payout", "upi",
    "pension", "taskreward", "guaranteedreturn", "workfromhome", "scholarship"
  ],
  DELIVERY_LOGISTICS: [
    "parcel", "package", "delivery", "redeliver", "customs", "postage",
    "shipping", "courier", "shipment", "tracking", "freight", "consignment",
    "challan", "toll", "fastag"
  ],
  CRYPTO_WEB3: [
    "wallet", "seed", "mnemonic", "airdrop", "presale", "staking", "mint",
    "claimtoken", "connectwallet", "walletconnect", "web3", "privatekey", "dapp"
  ],
  TECH_SCAREWARE: [
    "virus", "infected", "trojan", "scareware", "defender", "antivirus",
    "techsupport", "helpdesk", "sysadmin", "cleanphone", "browserupdate"
  ],
  DOC_PHISH_KIT: [
    "docusign", "esign", "document", "sharedfile", "viewdoc", "attachment",
    "statement", "taxform", "remittance", "remit", "payroll", "hrdoc"
  ],
  REMOTE_ACCESS_TROJAN: [
    "anydesk", "teamviewer", "quicksupport", "rustdesk", "airdroid",
    "screenshare", "remotesupport", "remotedesktop", "accessibility",
    "unknownsources", "playprotect"
  ],
  GOVT_EXTORTION: [
    "digitalarrest", "cybercrime", "warrant", "courtnotice", "simdeactivate",
    "trai", "aadhaarlock", "panlink", "collectrequest", "upimandate", "autopay",
    "jeevanpramaan", "lifecertificate", "ayushman", "rationcard"
  ]
};

const EXPLICIT_MALICE_STEMS = [
  "phish", "malware", "ransomware", "trojan", "keylog", "spyware",
  "stealer", "botnet", "exploit", "webinject", "credharvest"
];

const EMBEDDED_TLD_SUBDOMAIN_PATTERN =
  /(?:^|\.)[a-z0-9-]{2,}\.(?:com|net|org|info|biz|gov|edu|co\.in|co\.uk|com\.au|org\.in|gov\.in|bank)(?:\.|$)/i;

const COMPROMISED_ASSET_DIR_KIT =
  /\/(?:wp-content|wp-includes|wp-admin|images|img|css|js|fonts|assets|static|media|cgi-bin|\.well-known)\/.*\.(?:php|html?|hta|phtml|asp|aspx)$/i;

const OBFUSCATED_SHORT_DIR_KIT =
  /^\/[a-z0-9]{1,2}\/[a-z0-9._-]{3,}\.(?:html?|php|hta)$/i;

function shannonEntropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const ch of value) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  let ent = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    ent -= p * Math.log2(p);
  }
  return ent;
}

function deLeet(str) {
  return String(str || "")
    .toLowerCase()
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/8/g, "b")
    .replace(/\$/g, "s");
}

function safeDecode(value, passes = 3) {
  let curr = String(value || "");
  for (let i = 0; i < passes; i++) {
    try {
      const next = decodeURIComponent(curr);
      if (next === curr) break;
      curr = next;
    } catch {
      break;
    }
  }
  return curr;
}

function extractNormalizedTokens(rawSegments) {
  const tokens = new Set();
  for (const seg of rawSegments) {
    const decoded = safeDecode(seg).toLowerCase();
    for (const part of decoded.split(/[^a-z0-9]+/).filter(Boolean)) {
      tokens.add(part);
      tokens.add(deLeet(part));
    }
    const compact = deLeet(decoded).replace(/[^a-z0-9]+/g, "");
    if (compact) tokens.add(compact);
  }
  return [...tokens];
}

function matchVector(tokens, stems) {
  for (const stem of stems) {
    for (const tok of tokens) {
      if (
        tok === stem ||
        (stem.length >= 5 && (tok.includes(stem) || tok.startsWith(stem)))
      ) {
        return true;
      }
    }
  }
  return false;
}

function hasDgaVowelOrConsonantAnomaly(label) {
  const alphaOnly = String(label || "").toLowerCase().replace(/[^a-z]/g, "");
  if (alphaOnly.length < 8) return false;

  const vowels = (alphaOnly.match(/[aeiouy]/g) || []).length;
  const vowelRatio = vowels / alphaOnly.length;
  const maxConsonantRun = Math.max(
    0,
    ...(alphaOnly.match(/[^aeiouy]+/g) || []).map((m) => m.length)
  );
  const digits = (String(label).match(/\d/g) || []).length;
  const digitRatio = digits / Math.max(1, label.length);
  const ent = shannonEntropy(String(label).toLowerCase().replace(/-/g, ""));

  if (maxConsonantRun >= 6 && ent >= 3.0) return true;
  if (alphaOnly.length >= 9 && vowelRatio < 0.14 && ent >= 3.1) return true;
  if (label.length >= 9 && digitRatio >= 0.3 && ent >= 3.1) return true;
  return false;
}

function hasFragmentVictimEmailPrefill(parsedUrl) {
  const hash = String(parsedUrl?.hash || "").replace(/^#/, "").trim();
  if (!hash) return false;
  const decodedHash = safeDecode(hash, 2);

  if (/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(decodedHash)) {
    return true;
  }

  // Check Base64-encoded email prefill in URL fragment (common Microsoft/webmail phish kit trick)
  const b64Candidate = decodedHash.replace(/^[^a-zA-Z0-9+/=_-]+/, "").trim();
  if (/^[A-Za-z0-9+/_-]{12,160}={0,2}$/.test(b64Candidate)) {
    try {
      const normalized = b64Candidate.replace(/-/g, "+").replace(/_/g, "/");
      const decoded = Buffer.from(normalized, "base64").toString("utf8");
      if (/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(decoded.trim())) {
        return true;
      }
    } catch {
      // ignore
    }
  }

  return false;
}

function evaluateLexicalAndStructuralRisk({
  hostname,
  registrableDomain,
  parsedUrl,
  rawPath,
  pathSegments,
  existingIndicators = []
}) {
  const hasRiskyArtifact =
    existingIndicators.includes("MOBILE_SIDELOAD_INSTALLER_PATH") ||
    existingIndicators.includes("MOBILE_CONFIG_OR_CERT_INSTALL_PATH") ||
    existingIndicators.includes("INTERACTIVE_SMUGGLING_FILE_PATH") ||
    existingIndicators.includes("FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD") ||
    existingIndicators.includes("HTML_SMUGGLING_PAYLOAD_DETECTED");

  const isSafeFirstParty =
    isKnownSafeDomain(registrableDomain) &&
    !isFreeUgcOrCloudHosting(hostname) &&
    !hasRiskyArtifact;

  if (isSafeFirstParty) {
    return {
      indicators: [],
      riskScore: 0,
      hardBlock: false,
      hardBlockReason: null,
      matchedVectors: []
    };
  }

  const indicators = [];
  let riskScore = 0;

  const unicodeHost = domainToUnicode(hostname) || hostname;
  const decodedPath = safeDecode(rawPath || parsedUrl.pathname || "/");
  const queryKeys = Array.from(parsedUrl?.searchParams?.keys() || []);

  const allTokens = extractNormalizedTokens([
    unicodeHost,
    hostname,
    ...(Array.isArray(pathSegments) ? pathSegments : []),
    decodedPath,
    ...queryKeys
  ]);

  // 1. Explicit malware/phishing stems anywhere (after percent-decoding & de-leeting)
  if (matchVector(allTokens, EXPLICIT_MALICE_STEMS)) {
    indicators.push("LEXICAL_EXPLICIT_PHISHING_OR_MALWARE_STEM");
    riskScore += 6;
  }

  // 2. Multi-vector social-engineering intent scoring (brand-agnostic!)
  const matchedVectors = [];
  for (const [vectorName, stems] of Object.entries(INTENT_VECTORS)) {
    if (matchVector(allTokens, stems)) {
      matchedVectors.push(vectorName);
    }
  }

  if (matchedVectors.length >= 3) {
    indicators.push("MULTI_VECTOR_SOCIAL_ENGINEERING_ATTACK");
    riskScore += 6;
  } else if (matchedVectors.length === 2) {
    // Only score when 2 genuinely risky vectors combine; avoid noisy single-auth resets
    indicators.push("COMPOUND_DECEPTIVE_INTENT_VECTORS");
    riskScore += 4;
  } else if (matchedVectors.length === 1 && !matchedVectors.includes("AUTH_IDENTITY")) {
    indicators.push(`LURE_INTENT_${matchedVectors[0]}`);
    riskScore += 2;
  }

  // 3. Universal subdomain TLD-masquerade check (e.g. anybank.com.attacker.net)
  const subdomainPart =
    registrableDomain && hostname.length > registrableDomain.length
      ? hostname.slice(0, hostname.length - registrableDomain.length - 1)
      : "";

  if (subdomainPart && EMBEDDED_TLD_SUBDOMAIN_PATTERN.test(subdomainPart)) {
    indicators.push("UNIVERSAL_SUBDOMAIN_TLD_MASQUERADING");
    riskScore += 8;
  }

  // 4. Algorithmic DGA / unpronounceable random host check
  const mainLabel = (registrableDomain || hostname).split(".")[0];
  if (hasDgaVowelOrConsonantAnomaly(mainLabel)) {
    indicators.push("ALGORITHMIC_DGA_HOST_ANOMALY");
    riskScore += 3;
  }

  // 5. Compromised-site phishing kit path & obfuscated short-folder HTML kit
  if (COMPROMISED_ASSET_DIR_KIT.test(decodedPath)) {
    indicators.push("COMPROMISED_ASSET_DIR_PHISHING_KIT");
    riskScore += 6;
  }

  if (OBFUSCATED_SHORT_DIR_KIT.test(decodedPath)) {
    indicators.push("OBFUSCATED_SHORT_PATH_STATIC_KIT");
    riskScore += 3;
  }

  // 6. Excessive percent-encoding obfuscation density in path (evasion tactic)
  const rawPctMatches = (String(rawPath || "").match(/%[0-9a-f]{2}/gi) || []).length;
  if (rawPath && rawPath.length >= 12 && (rawPctMatches * 3) / rawPath.length >= 0.38) {
    indicators.push("HEAVY_PERCENT_ENCODING_OBFUSCATION");
    riskScore += 3;
  }

  // 7. Fragment victim-email prefill detection (#victim@domain.com or Base64 email)
  if (hasFragmentVictimEmailPrefill(parsedUrl)) {
    indicators.push("FRAGMENT_VICTIM_EMAIL_PREFILL_KIT");
    riskScore += 6;
  }

  // Escalation logic without needing static domain blocklists
  const hasHighRiskInfra =
    existingIndicators.includes("FREE_UGC_OR_CLOUD_HOSTING") ||
    existingIndicators.includes("FREE_TUNNEL_OR_DYNAMIC_DNS_HOST") ||
    existingIndicators.includes("HIGH_RISK_ABUSED_TLD") ||
    existingIndicators.includes("IP_LITERAL_HOST") ||
    existingIndicators.includes("OBFUSCATED_IP_HOST") ||
    existingIndicators.includes("URL_SHORTENER_HIDES_DESTINATION") ||
    existingIndicators.includes("UNENCRYPTED_HTTP");

  const hasBrandLookalike =
    existingIndicators.includes("BRAND_NAME_IN_UNRELATED_DOMAIN") ||
    existingIndicators.includes("POSSIBLE_BRAND_LOOKALIKE_DOMAIN");

  let hardBlock = false;
  let hardBlockReason = null;

  if (existingIndicators.includes("MIXED_SCRIPT_IDN_HOSTNAME")) {
    hardBlock = true;
    hardBlockReason = "MIXED_SCRIPT_HOMOGRAPH_ATTACK";
  } else if (indicators.includes("UNIVERSAL_SUBDOMAIN_TLD_MASQUERADING")) {
    hardBlock = true;
    hardBlockReason = "SUBDOMAIN_TLD_MASQUERADE_PHISHING";
  } else if (indicators.includes("LEXICAL_EXPLICIT_PHISHING_OR_MALWARE_STEM")) {
    hardBlock = true;
    hardBlockReason = "LEXICAL_PHISHING_OR_MALWARE_DETECTED";
  } else if (indicators.includes("COMPROMISED_ASSET_DIR_PHISHING_KIT")) {
    hardBlock = true;
    hardBlockReason = "COMPROMISED_WEBSITE_PHISHING_KIT";
  } else if (indicators.includes("FRAGMENT_VICTIM_EMAIL_PREFILL_KIT") && (matchedVectors.length >= 1 || hasHighRiskInfra || hasBrandLookalike)) {
    hardBlock = true;
    hardBlockReason = "CREDENTIAL_PREFILL_PHISHING_KIT";
  } else if (matchedVectors.length >= 3) {
    hardBlock = true;
    hardBlockReason = "MULTI_VECTOR_PHISHING_DETECTED";
  } else if (matchedVectors.length === 2 && (hasHighRiskInfra || hasBrandLookalike || indicators.includes("OBFUSCATED_SHORT_PATH_STATIC_KIT") || indicators.includes("HEAVY_PERCENT_ENCODING_OBFUSCATION"))) {
    hardBlock = true;
    hardBlockReason = "HIGH_CONFIDENCE_PHISHING_INTENT";
  } else if (
    matchedVectors.length >= 1 &&
    existingIndicators.includes("FREE_UGC_OR_CLOUD_HOSTING") &&
    (indicators.includes("OBFUSCATED_SHORT_PATH_STATIC_KIT") || matchedVectors.some((v) => v !== "AUTH_IDENTITY"))
  ) {
    hardBlock = true;
    hardBlockReason = "ABUSED_CLOUD_HOSTING_PHISHING_KIT";
  } else if (
    (existingIndicators.includes("IP_LITERAL_HOST") || existingIndicators.includes("OBFUSCATED_IP_HOST")) &&
    (matchedVectors.length >= 1 || existingIndicators.includes("EXECUTABLE_DOWNLOAD_PATH"))
  ) {
    hardBlock = true;
    hardBlockReason = "DIRECT_IP_PHISHING_OR_MALWARE_DROP";
  } else if (
    indicators.includes("ALGORITHMIC_DGA_HOST_ANOMALY") &&
    (hasHighRiskInfra || matchedVectors.length >= 1 || existingIndicators.includes("EXECUTABLE_DOWNLOAD_PATH"))
  ) {
    hardBlock = true;
    hardBlockReason = "DGA_MALICIOUS_INFRASTRUCTURE_DETECTED";
  }

  return {
    indicators: [...new Set(indicators)],
    riskScore,
    hardBlock,
    hardBlockReason,
    matchedVectors
  };
}

module.exports = {
  evaluateLexicalAndStructuralRisk,
  hasDgaVowelOrConsonantAnomaly,
  hasFragmentVictimEmailPrefill
};
