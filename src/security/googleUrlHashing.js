
"use strict";

const crypto = require("node:crypto");
const net = require("node:net");
const ipaddr = require("ipaddr.js");
const { getDomain } = require("tldts");

const MAX_URL_LENGTH = 8192;
const MAX_HASH_EXPRESSIONS = 5;

function fullyUnescapeComponent(value) {
  let current = value;

  for (let index = 0; index < 64; index++) {
    if (!/%[0-9a-f]{2}/i.test(current)) {
      return current;
    }

    try {
      const next = current.replace(
        /(?:%[0-9a-f]{2})+/gi,
        sequence => decodeURIComponent(sequence)
      );

      if (next === current) return current;

      current = next;
    } catch {
      throw new Error("Invalid percent encoding");
    }
  }

  throw new Error("Excessively nested URL encoding");
}

function escapeForHash(value) {
  let result = "";

  for (const character of value) {
    const codePoint = character.codePointAt(0);

    if (
      codePoint <= 32 ||
      codePoint >= 127 ||
      character === "#" ||
      character === "%"
    ) {
      for (const byte of Buffer.from(character, "utf8")) {
        result += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
      }
    } else {
      result += character;
    }
  }

  return result;
}

function normalizeHostname(hostname) {
  let host = String(hostname || "")
    .replace(/^\[|\]$/g, "");

  const ipVersion = net.isIP(host);

  if (ipVersion === 4) {
    return host;
  }

  if (ipVersion === 6) {
    const address = ipaddr.parse(host);

    if (address.isIPv4MappedAddress()) {
      return address.toIPv4Address().toString();
    }

    const nat64Prefix = ipaddr.IPv6.parse("64:ff9b::");

    if (address.match(nat64Prefix, 96)) {
      return ipaddr.IPv4.fromByteArray(
        address.toByteArray().slice(12)
      ).toString();
    }

    return `[${address.toString().toLowerCase()}]`;
  }

  host = host
    .replace(/^\.+|\.+$/g, "")
    .toLowerCase();

  if (!host) {
    throw new Error("Invalid hostname");
  }

  return host;
}

function canonicalizeUrl(input) {
  if (
    typeof input !== "string" ||
    input.length === 0 ||
    input.length > MAX_URL_LENGTH
  ) {
    throw new Error("Invalid URL input");
  }

  const cleaned = input.replace(/[\t\r\n]/g, "");

  let parsed;

  try {
    parsed = new URL(cleaned);
  } catch {
    throw new Error("URL could not be parsed");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported");
  }

  if (parsed.username || parsed.password) {
    throw new Error("URL credentials are not accepted");
  }

  const hostname = normalizeHostname(parsed.hostname);

  const pathname = fullyUnescapeComponent(
    parsed.pathname || "/"
  ).replace(/\/{2,}/g, "/");

  const search = fullyUnescapeComponent(
    parsed.search || ""
  );

  // Local-only canonical expression.
  // Never use this expression for the Google request.
  const canonicalExpression = escapeForHash(
    `${hostname}${pathname}${search}`
  );

  return {
    hostname,
    pathname,
    search,
    canonicalExpression
  };
}

function buildHostCandidates(hostname) {
  const host = normalizeHostname(hostname);
  const unbracketed = host.replace(/^\[|\]$/g, "");

  if (net.isIP(unbracketed)) {
    return [host];
  }

  const registrableDomain = getDomain(host) || host;

  const hostnameParts = host.split(".");
  const domainParts = registrableDomain.split(".");

  const leadingParts = hostnameParts.slice(
    0,
    hostnameParts.length - domainParts.length
  );

  const candidates = [registrableDomain];

  for (
    let count = 1;
    count <= Math.min(3, leadingParts.length);
    count++
  ) {
    candidates.push([
      ...leadingParts.slice(-count),
      ...domainParts
    ].join("."));
  }

  candidates.push(host);

  return [...new Set(candidates)].slice(
    0,
    MAX_HASH_EXPRESSIONS
  );
}

// Retained for compatibility with existing tests and callers.
// This helper is NOT used to generate Google's outbound prefixes.
function buildPathCandidates(pathname, search) {
  const candidates = [
    `${pathname}${search}`,
    pathname,
    "/"
  ];

  const segments = String(pathname || "/")
    .split("/")
    .filter(Boolean);

  for (
    let count = 1;
    count <= Math.min(4, segments.length - 1);
    count++
  ) {
    candidates.push(
      `/${segments.slice(0, count).join("/")}/`
    );
  }

  return [...new Set(candidates)].slice(0, 6);
}

function isSensitiveHostLabel(label) {
  const value = String(label || "");
  if (/^[a-f0-9]{32,}$/i.test(value)) return true;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    return true;
  }
  if (/^[a-z0-9_-]{36,}$/i.test(value) && /[a-z]/i.test(value) && /[0-9]/.test(value)) {
    return true;
  }
  return false;
}

function createGoogleHashData(input) {
  const canonical = canonicalizeUrl(input);

  const rawHosts = buildHostCandidates(canonical.hostname);
  const registrable = getDomain(canonical.hostname) || canonical.hostname;

  // Extra privacy guard: omit host candidates containing secret/UUID/token-like
  // subdomain labels so even 4-byte prefixes of user-specific subdomains never leave the device.
  const hosts = rawHosts.filter((candidateHost) => {
    if (candidateHost === registrable) return true;
    const subParts = candidateHost.slice(0, Math.max(0, candidateHost.length - registrable.length)).split(".").filter(Boolean);
    return !subParts.some(isSensitiveHostLabel);
  });

  const safeHosts = hosts.length > 0 ? hosts : [registrable];

  // Strict privacy mode:
  // Only hostname variants plus "/" are hashed for Google.
  // No original path, query string or fragment is included.
  const expressions = safeHosts.map(host => `${host}/`);

  const uniqueExpressions = [...new Set(expressions)].slice(
    0,
    MAX_HASH_EXPRESSIONS
  );

  const fullHashes = new Set();
  const prefixes = new Set();

  for (const expression of uniqueExpressions) {
    const digest = crypto
      .createHash("sha256")
      .update(escapeForHash(expression), "utf8")
      .digest();

    // Full hashes remain in local backend memory.
    fullHashes.add(digest.toString("hex"));

    // Only the first four bytes go to Google.
    prefixes.add(
      digest.subarray(0, 4).toString("base64")
    );
  }

  return {
    fullHashes: [...fullHashes],
    hashPrefixes: [...prefixes]
  };
}

module.exports = {
  canonicalizeUrl,
  buildHostCandidates,
  buildPathCandidates,
  createGoogleHashData,
  normalizeHostname,
  escapeForHash
};
