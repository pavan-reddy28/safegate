"use strict";

/**
 * auditLog.js
 *
 * Privacy-safe, structured audit logging for every verification request.
 *
 * WHAT IS LOGGED (never the submitted URL or any URL fragment):
 *   - ISO-8601 timestamp
 *   - request UUID
 *   - final decision  (BLOCK / SUSPICIOUS / KNOWN_SAFE / NO_KNOWN_THREAT / HOLD)
 *   - recommended action
 *   - final reason codes
 *   - risk score
 *   - indicators (structural flags, never values)
 *   - destination hostname and registrable domain ONLY (no path/query/fragment)
 *   - whether Google was contacted (true/false)
 *   - Google result status
 *   - cache hit flag
 *
 * WHAT IS NEVER LOGGED:
 *   - The original URL
 *   - Any URL path, query string or fragment
 *   - Any query parameter values
 *   - API keys or secrets
 *
 * OUTPUT
 *   Logs go to stdout as newline-delimited JSON (NDJSON).
 *   On Android / local Node the caller can redirect stdout to a rotating file.
 *   Each log line is a self-contained JSON object for easy grepping.
 */

const MAX_INDICATORS = 30;

function sanitizeString(value, maxLen = 128) {
  if (typeof value !== "string") return null;
  return value.slice(0, maxLen).replace(/[\r\n\t]/g, " ");
}

function sanitizeIndicators(indicators) {
  if (!Array.isArray(indicators)) return [];
  return indicators
    .slice(0, MAX_INDICATORS)
    .map(i => sanitizeString(i, 64))
    .filter(Boolean);
}

/**
 * Write one structured audit event.
 *
 * @param {object} opts
 * @param {string}        opts.requestId
 * @param {string}        opts.finalDecision
 * @param {string}        opts.recommendedAction
 * @param {string[]}      opts.finalReasonCodes
 * @param {number|null}   opts.riskScore
 * @param {string[]}      opts.indicators
 * @param {object|null}   opts.destination      — {hostname, registrableDomain, protocol}
 * @param {boolean}       opts.googleContacted
 * @param {string}        opts.googleStatus
 * @param {boolean}       opts.cacheHit
 * @param {number}        opts.durationMs
 */
function writeAuditEvent(opts) {
  const event = {
    t: new Date().toISOString(),
    reqId: sanitizeString(opts.requestId, 36),
    decision: sanitizeString(opts.finalDecision, 32),
    action: sanitizeString(opts.recommendedAction, 32),
    reasonCodes: Array.isArray(opts.finalReasonCodes)
      ? opts.finalReasonCodes.slice(0, 10).map(c => sanitizeString(c, 64)).filter(Boolean)
      : [],
    riskScore: typeof opts.riskScore === "number" ? opts.riskScore : null,
    indicators: sanitizeIndicators(opts.indicators),
    dest: opts.destination
      ? {
          hostname: sanitizeString(opts.destination.hostname, 253),
          registrableDomain: sanitizeString(opts.destination.registrableDomain, 253),
          protocol: sanitizeString(opts.destination.protocol, 10)
        }
      : null,
    googleContacted: Boolean(opts.googleContacted),
    googleStatus: sanitizeString(opts.googleStatus, 32),
    cacheHit: Boolean(opts.cacheHit),
    durationMs: typeof opts.durationMs === "number"
      ? Math.round(opts.durationMs)
      : null
  };

  // Intentionally synchronous console.log so logs are never dropped.
  // On local Node this is cheap; stdout is buffered by the OS.
  try {
    console.log(JSON.stringify(event));
  } catch {
    // JSON serialization failure must never crash the server.
  }
}

module.exports = { writeAuditEvent };
