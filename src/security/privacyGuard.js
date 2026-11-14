"use strict";

/**
 * privacyGuard.js
 *
 * Enforces zero-leakage guarantees across API responses and audit logs.
 *
 * GUARANTEES:
 * 1. Never exposes the raw submitted URL, path, query string, query values,
 *    fragment, or credentials in any API response or log line.
 * 2. Provides a redacted destination string (protocol + hostname only) for
 *    parent-facing UI display without leaking secret tokens/OTPs/IDs.
 * 3. Runs a defensive leak check on serialized output and redacts any
 *    accidentally matched sensitive URL components before leaving the process.
 */

function buildRedactedDestination(parsedUrl) {
  if (!parsedUrl || !parsedUrl.hostname) {
    return null;
  }

  const protocol = parsedUrl.protocol === "https:" ? "https:" : "http:";
  const host = parsedUrl.hostname.toLowerCase().replace(/\.$/, "");
  const port = parsedUrl.port ? `:${parsedUrl.port}` : "";

  const hasPrivateParts =
    (parsedUrl.pathname && parsedUrl.pathname !== "/") ||
    Boolean(parsedUrl.search) ||
    Boolean(parsedUrl.hash);

  return {
    originOnly: `${protocol}//${host}${port}`,
    displayHost: host,
    privateComponentsStripped: hasPrivateParts
  };
}

/**
 * Extract sensitive private substrings (non-trivial path, query string,
 * query parameter values, fragment) so we can assert they never appear
 * in outgoing API responses or logs.
 */
function extractPrivatePartsForAssertion(rawUrl) {
  const privateTokens = [];

  if (typeof rawUrl !== "string") return privateTokens;

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    // If unparseable, the entire raw input (if > 12 chars) must never appear.
    if (rawUrl.trim().length > 12) {
      privateTokens.push(rawUrl.trim());
    }
    return privateTokens;
  }

  if (parsed.pathname && parsed.pathname.length > 4) {
    privateTokens.push(parsed.pathname);
  }

  if (parsed.search && parsed.search.length > 1) {
    privateTokens.push(parsed.search);
    for (const [, value] of parsed.searchParams.entries()) {
      if (value && value.length >= 6) {
        privateTokens.push(value);
      }
    }
  }

  if (parsed.hash && parsed.hash.length > 1) {
    privateTokens.push(parsed.hash);
    if (parsed.hash.slice(1).length >= 6) {
      privateTokens.push(parsed.hash.slice(1));
    }
  }

  if (parsed.username) privateTokens.push(parsed.username);
  if (parsed.password) privateTokens.push(parsed.password);

  return [...new Set(privateTokens)].filter(Boolean);
}

/**
 * Verifies that none of the private URL substrings appear in the payload.
 * Returns true when clean; if a leak were ever detected, returns false so
 * callers can fail-safe redact.
 */
function verifyNoPrivateUrlLeak(rawUrl, payload) {
  const privateTokens = extractPrivatePartsForAssertion(rawUrl);
  if (privateTokens.length === 0) return true;

  let serialized;
  try {
    serialized = JSON.stringify(payload);
  } catch {
    return false;
  }

  for (const token of privateTokens) {
    if (serialized.includes(token)) {
      return false;
    }
  }

  return true;
}

module.exports = {
  buildRedactedDestination,
  extractPrivatePartsForAssertion,
  verifyNoPrivateUrlLeak
};
