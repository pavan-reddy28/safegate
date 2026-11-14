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

function redactSensitiveSubdomains(hostname, registrableDomain) {
  const host = sanitizeString(hostname, 253);
  if (!host) return null;
  if (!registrableDomain || host === registrableDomain) return host;

  const suffix = `.${registrableDomain}`;
  if (!host.endsWith(suffix)) return host;

  const sub = host.slice(0, host.length - suffix.length);
  const maskedSub = sub
    .split(".")
    .map((label) =>
      label.length >= 24 || /^[a-f0-9-]{16,}$/i.test(label)
        ? "[redacted]"
        : label
    )
    .join(".");

  return `${maskedSub}${suffix}`;
}

function writeAuditEvent(opts) {
  const regDomain = opts.destination
    ? sanitizeString(opts.destination.registrableDomain, 253)
    : null;

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
          hostname: redactSensitiveSubdomains(opts.destination.hostname, regDomain),
          registrableDomain: regDomain,
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
