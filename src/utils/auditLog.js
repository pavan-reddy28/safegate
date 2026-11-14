"use strict";

/**
 * auditLog.js
 *
 * Privacy-safe, structured audit logging for every verification request.
 * Zero original URLs, paths, query strings, or fragments are ever logged.
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
    .map((i) => sanitizeString(i, 64))
    .filter(Boolean);
}

function writeAuditEvent(opts) {
  const event = {
    t: new Date().toISOString(),
    reqId: sanitizeString(opts.requestId, 36),
    decision: sanitizeString(opts.finalDecision, 32),
    action: sanitizeString(opts.recommendedAction, 32),
    reasonCodes: Array.isArray(opts.finalReasonCodes)
      ? opts.finalReasonCodes
          .slice(0, 10)
          .map((c) => sanitizeString(c, 64))
          .filter(Boolean)
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
    outboundNetworkCalls: 0,
    durationMs: typeof opts.durationMs === "number" ? Math.round(opts.durationMs) : null
  };

  try {
    console.log(JSON.stringify(event));
  } catch {
    // Serialization failure must never crash the server.
  }
}

module.exports = { writeAuditEvent };
