"use strict";

const MAX_URL_LENGTH = 4096;

// C0/C1 control characters
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F-\u009F]/;

// Invisible zero-width and Unicode bidi override spoofing characters
const INVISIBLE_OR_BIDI_CHARS =
  /[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF\u00AD\u061C]/;

// Percent-encoded null/CRLF or UTF-8 bidi overrides (%E2%80%AA..%E2%80%AE, %E2%81%A6..%E2%81%A9)
const ENCODED_SPOOF_SEQUENCES =
  /(?:%00|%e2%80%8[b-f]|%e2%80%a[a-e]|%e2%81%a[6-9]|%ef%bb%bf)/i;

const MALFORMED_PERCENT_ENCODING = /%(?![0-9a-fA-F]{2})/;

const DANGEROUS_EXPLICIT_SCHEME =
  /^(?:javascript|data|vbscript|file|content|android-app|intent|upi|paytmmp|phonepe|tez|gpay|bhim|whatsapp|tg|tel|sms|smsto|mmsto|mailto|callto|facetime|geo|market|blob|filesystem|about|view-source|smb|sftp|chrome|edge|ftp|ws|wss):/i;

function reject(reasonCode) {
  return {
    ok: false,
    reasonCode
  };
}

/**
 * Detect non-standard IP obfuscations in the raw authority before Node's URL
 * parser silently converts them (e.g. decimal 2130706433, hex 0x7f000001,
 * octal 0177.0.0.1, or shorthand IPv4 like 127.1).
 */
function detectObfuscatedIpAuthority(rawAuthority) {
  if (!rawAuthority || rawAuthority.startsWith("[")) {
    return false;
  }

  const hostOnly = rawAuthority.split(":")[0].toLowerCase().replace(/\.$/, "");
  if (!hostOnly) return false;

  // Single integer decimal or hex IP (e.g. 2130706433 or 0x7f000001)
  if (/^(?:0x[0-9a-f]+|\d+)$/i.test(hostOnly)) {
    return true;
  }

  const parts = hostOnly.split(".");
  // Dotted numeric host with fewer than 4 parts (e.g. 127.1 or 192.168.1)
  if (
    parts.length >= 2 &&
    parts.length < 4 &&
    parts.every((p) => /^(?:0x[0-9a-f]+|0[0-7]*|[1-9]\d*)$/i.test(p))
  ) {
    return true;
  }

  // 4-part numeric IP containing hex or leading-zero octal octets
  if (
    parts.length === 4 &&
    parts.every((p) => /^(?:0x[0-9a-f]+|\d+)$/i.test(p)) &&
    parts.some((p) => /^0x/i.test(p) || (p.length > 1 && p.startsWith("0")))
  ) {
    return true;
  }

  return false;
}

function normalizeUrl(input) {
  if (typeof input !== "string") {
    return reject("INVALID_URL_TYPE");
  }

  // Never silently strip control characters.
  if (CONTROL_CHARACTERS.test(input)) {
    return reject("CONTROL_CHARACTERS_FOUND");
  }

  if (INVISIBLE_OR_BIDI_CHARS.test(input)) {
    return reject("INVISIBLE_OR_BIDI_CHARACTERS_FOUND");
  }

  const candidate = input.trim();

  if (!candidate) {
    return reject("EMPTY_URL");
  }

  if (candidate.length > MAX_URL_LENGTH) {
    return reject("URL_TOO_LONG");
  }

  // Reject embedded whitespace rather than guessing how a browser parses it.
  if (/\s/.test(candidate)) {
    return reject("WHITESPACE_IN_URL");
  }

  // Prevent parser differential attacks using backslashes.
  if (candidate.includes("\\")) {
    return reject("BACKSLASH_IN_URL");
  }

  // Reject malformed percent sequences.
  if (MALFORMED_PERCENT_ENCODING.test(candidate)) {
    return reject("MALFORMED_PERCENT_ENCODING");
  }

  // Reject percent-encoded null bytes / bidi direction overrides / zero-width chars.
  if (ENCODED_SPOOF_SEQUENCES.test(candidate)) {
    return reject("ENCODED_SPOOF_OR_NULL_SEQUENCE");
  }

  // Block dangerous schemes explicitly with a clear reason code.
  if (DANGEROUS_EXPLICIT_SCHEME.test(candidate)) {
    return reject("UNSUPPORTED_OR_DANGEROUS_SCHEME");
  }

  // Require an explicit HTTP or HTTPS URL.
  if (!/^https?:\/\//i.test(candidate)) {
    return reject("ABSOLUTE_HTTP_URL_REQUIRED");
  }

  // Extract raw authority before URL() normalization.
  const authorityMatch = candidate.match(
    /^https?:\/\/([^/?#]*)(\/[^?#]*)?/i
  );
  const rawAuthority = authorityMatch?.[1] || "";

  if (!rawAuthority) {
    return reject("INVALID_HOSTNAME");
  }

  // Reject userinfo/authority confusion immediately (including percent-encoded @ in userinfo).
  if (rawAuthority.includes("@") || /%40/i.test(rawAuthority)) {
    return reject("URL_CONTAINS_CREDENTIALS");
  }

  let parsedUrl;

  try {
    parsedUrl = new URL(candidate);
  } catch {
    return reject("MALFORMED_URL");
  }

  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    return reject("UNSUPPORTED_PROTOCOL");
  }

  if (parsedUrl.username || parsedUrl.password) {
    return reject("URL_CONTAINS_CREDENTIALS");
  }

  const hostname = parsedUrl.hostname.toLowerCase().replace(/\.$/, "");

  if (!hostname || hostname.length > 253) {
    return reject("INVALID_HOSTNAME");
  }

  const obfuscatedIpHost = detectObfuscatedIpAuthority(rawAuthority);

  // Keep rawPath privately in memory for encoding inspection only.
  // Never return or log it.
  const rawPath = authorityMatch?.[2] || "/";

  return {
    ok: true,
    parsedUrl,
    hostname,
    rawPath,
    obfuscatedIpHost
  };
}

module.exports = {
  normalizeUrl,
  detectObfuscatedIpAuthority
};