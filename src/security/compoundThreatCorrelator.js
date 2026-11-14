"use strict";

/**
 * compoundThreatCorrelator.js
 *
 * Layer 7 Cross-Layer Threat Correlation Engine.
 * Detects hybrid / evasive phone-hacking links where an attacker stays just
 * below single-rule block thresholds by combining multiple distinct attack
 * tactics across domain, transport, path, query/fragment, and social-engineering.
 */

const INFRASTRUCTURE_SIGNALS = new Set([
  "FREE_TUNNEL_OR_DYNAMIC_DNS_HOST",
  "FREE_UGC_OR_CLOUD_HOSTING",
  "HIGH_RISK_ABUSED_TLD",
  "URL_SHORTENER_HIDES_DESTINATION",
  "PUBLIC_IP_LITERAL_HOST",
  "OBFUSCATED_IP_HOST",
  "DASHED_IP_PATTERN_IN_HOSTNAME",
  "HIGH_ENTROPY_DGA_DOMAIN",
  "ALGORITHMIC_DGA_HOST_ANOMALY",
  "PUBLIC_SUFFIX_NOT_RECOGNIZED_LOCALLY"
]);

const SPOOFING_SIGNALS = new Set([
  "BRAND_DOMAIN_SPOOFED_IN_SUBDOMAIN",
  "BRAND_NAME_IN_UNRELATED_DOMAIN",
  "POSSIBLE_BRAND_LOOKALIKE_DOMAIN",
  "CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION",
  "MIXED_SCRIPT_IDN_HOSTNAME",
  "NON_LATIN_CONFUSABLE_IDN_HOSTNAME",
  "PUNYCODE_HOSTNAME",
  "UNIVERSAL_SUBDOMAIN_TLD_MASQUERADING",
  "MOBILE_VIEWPORT_SUBDOMAIN_PADDING",
  "DECEPTIVE_MULTI_LURE_HOSTNAME",
  "DECEPTIVE_AUTH_HOSTNAME_PATTERN",
  "EXCESSIVE_HYPHEN_LURE_DOMAIN"
]);

const PAYLOAD_SIGNALS = new Set([
  "MOBILE_SIDELOAD_INSTALLER_PATH",
  "MOBILE_CONFIG_OR_CERT_INSTALL_PATH",
  "EXECUTABLE_DOWNLOAD_PATH",
  "INTERACTIVE_SMUGGLING_FILE_PATH",
  "ARCHIVE_DOWNLOAD_PATH",
  "DOUBLE_EXTENSION_MASQUERADE",
  "COMPROMISED_ASSET_DIR_PHISHING_KIT",
  "PHISHING_KIT_ENDPOINT_FINGERPRINT",
  "OBFUSCATED_SHORT_PATH_STATIC_KIT",
  "QUERY_MOBILE_INSTALLER_PAYLOAD",
  "HTML_SMUGGLING_PAYLOAD_DETECTED"
]);

const SMUGGLING_SIGNALS = new Set([
  "REPEATED_PATH_ENCODING",
  "UNDECODABLE_PATH_ENCODING",
  "HEAVY_PERCENT_ENCODING_OBFUSCATION",
  "ENCODED_PATH_SEPARATOR",
  "PATH_TRAVERSAL_PATTERN",
  "EMBEDDED_URL_IN_PATH",
  "BASE64_SMUGGLED_REDIRECT",
  "HEX_SMUGGLED_REDIRECT",
  "BASE64_SMUGGLED_URL_IN_QUERY",
  "HEX_SMUGGLED_URL_IN_QUERY",
  "FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD",
  "FRAGMENT_VICTIM_EMAIL_PREFILL_KIT",
  "SUSPICIOUS_NESTED_REDIRECT_DOMAIN",
  "NESTED_REDIRECT_RISK_PROPAGATED",
  "ADDITIONAL_QUERY_ENCODING",
  "URL_PRESENT_IN_FRAGMENT"
]);

const LURE_SIGNALS = new Set([
  "SMS_FINANCIAL_SCAM_LURE",
  "URGENCY_OR_KYC_SCAM_LURE",
  "SENSITIVE_BANKING_CREDENTIAL_HARVEST_PATTERN",
  "BRAND_IMPERSONATION_WITH_SCAM_LURE_IN_PATH",
  "REMOTE_ACCESS_TROJAN_SCAM_LURE",
  "DIGITAL_ARREST_OR_EXTORTION_SCAM_LURE",
  "UPI_PAYMENT_REQUEST_SMUGGLING_IN_URL",
  "MULTI_VECTOR_SOCIAL_ENGINEERING_ATTACK",
  "COMPOUND_DECEPTIVE_INTENT_VECTORS",
  "LURE_INTENT_REMOTE_ACCESS_TROJAN",
  "LURE_INTENT_GOVT_EXTORTION",
  "LURE_INTENT_DELIVERY_LOGISTICS",
  "LURE_INTENT_FINANCIAL_LURE",
  "LURE_INTENT_URGENCY_THREAT",
  "LURE_INTENT_CRYPTO_WEB3",
  "LURE_INTENT_TECH_SCAREWARE",
  "LURE_INTENT_DOC_PHISH_KIT"
]);

const TRANSPORT_SIGNALS = new Set([
  "UNENCRYPTED_HTTP",
  "NON_STANDARD_PORT",
  "SUSPICIOUS_SERVICE_PORT"
]);

function hasAny(indicatorSet, groupSet) {
  for (const item of indicatorSet) {
    if (groupSet.has(item)) return true;
  }
  return false;
}

function correlateCrossLayerThreats({
  indicators = [],
  totalRiskScore = 0,
  isSafeFirstParty = false
}) {
  const unique = new Set(indicators);
  const families = [];

  if (hasAny(unique, INFRASTRUCTURE_SIGNALS)) families.push("INFRASTRUCTURE");
  if (hasAny(unique, SPOOFING_SIGNALS)) families.push("SPOOFING");
  if (hasAny(unique, PAYLOAD_SIGNALS)) families.push("PAYLOAD");
  if (hasAny(unique, SMUGGLING_SIGNALS)) families.push("OBFUSCATION_OR_SMUGGLING");
  if (hasAny(unique, LURE_SIGNALS)) families.push("SOCIAL_ENGINEERING");
  if (hasAny(unique, TRANSPORT_SIGNALS)) families.push("TRANSPORT_OR_PORT");

  const addedIndicators = [];
  let addedScore = 0;
  let hardBlock = false;
  let hardBlockReason = null;

  // Rule 1: Unknown public IP + any secondary malicious tactic (port, HTTP, payload, lure, spoof, smuggling)
  if (
    unique.has("PUBLIC_IP_LITERAL_HOST") &&
    (families.includes("PAYLOAD") ||
      families.includes("SOCIAL_ENGINEERING") ||
      families.includes("SPOOFING") ||
      families.includes("OBFUSCATION_OR_SMUGGLING") ||
      unique.has("UNENCRYPTED_HTTP") ||
      unique.has("NON_STANDARD_PORT") ||
      unique.has("SUSPICIOUS_SERVICE_PORT"))
  ) {
    addedIndicators.push("COMPOUND_DIRECT_IP_ATTACK");
    addedScore += 4;
    hardBlock = true;
    hardBlockReason = "COMPOUND_DIRECT_IP_ATTACK";
  }

  // Rule 2: Rogue mobile configuration profile / CA certificate / RAT / interactive SVG/MHTML payload with risky context
  if (
    !hardBlock &&
    (unique.has("MOBILE_CONFIG_OR_CERT_INSTALL_PATH") ||
      unique.has("INTERACTIVE_SMUGGLING_FILE_PATH") ||
      unique.has("HTML_SMUGGLING_PAYLOAD_DETECTED")) &&
    (families.includes("INFRASTRUCTURE") ||
      families.includes("SOCIAL_ENGINEERING") ||
      families.includes("SPOOFING") ||
      families.includes("OBFUSCATION_OR_SMUGGLING") ||
      unique.has("UNENCRYPTED_HTTP") ||
      unique.has("SUSPICIOUS_SERVICE_PORT"))
  ) {
    addedIndicators.push("COMPOUND_MALICIOUS_PAYLOAD_DELIVERY");
    addedScore += 4;
    hardBlock = true;
    hardBlockReason = "COMPOUND_MALICIOUS_PAYLOAD_DELIVERY";
  }

  // Rule 3: Explicit mobile viewport truncation padding + any lure or risky infra
  if (
    !hardBlock &&
    unique.has("MOBILE_VIEWPORT_SUBDOMAIN_PADDING") &&
    (families.includes("SOCIAL_ENGINEERING") ||
      families.includes("PAYLOAD") ||
      families.includes("INFRASTRUCTURE") ||
      unique.has("UNENCRYPTED_HTTP"))
  ) {
    addedIndicators.push("MOBILE_VIEWPORT_SPOOFING_ATTACK");
    addedScore += 4;
    hardBlock = true;
    hardBlockReason = "MOBILE_VIEWPORT_SPOOFING_ATTACK";
  }

  // Rule 4: Non-safe domain combining 3+ independent threat tactic families (classic low-and-slow evasion)
  // Exclude plain HTTP alone when counting non-safe multi-vector unless >= 3 OTHER or total >= 3 with score >= 6
  const coreFamilies = families.filter((f) => f !== "TRANSPORT_OR_PORT");
  if (
    !hardBlock &&
    !isSafeFirstParty &&
    (coreFamilies.length >= 3 || (families.length >= 3 && totalRiskScore >= 5))
  ) {
    addedIndicators.push("COMPOUND_MULTI_LAYER_ATTACK_CORRELATION");
    addedScore += 3;
    hardBlock = true;
    hardBlockReason = "COMPOUND_MULTI_LAYER_ATTACK_CORRELATION";
  }

  return {
    indicators: addedIndicators,
    riskScore: addedScore,
    hardBlock,
    hardBlockReason,
    threatFamiliesTriggered: families
  };
}

module.exports = {
  correlateCrossLayerThreats
};
