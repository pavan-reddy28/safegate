"use strict";

/**
 * strictInputGuard.js
 *
 * Boundary input sanitization middleware running before verification controllers.
 * Never logs any submitted URL data.
 */

const MAX_URL_BYTES = 4096;

const FORBIDDEN_URL_PATTERNS = [
  // Dangerous web & mobile deep-link schemes (even with zero-width / whitespace padding)
  /^[\s\u200B-\u200D\uFEFF]*(?:javascript|data|vbscript|file|intent|upi|tel|sms|smsto|mmsto|market|blob|filesystem|about|view-source):/i,

  // Null bytes (raw or percent-encoded)
  /\x00|%00/i,

  // RTL / bidi override & zero-width spoofing characters (raw or UTF-8 percent-encoded)
  /[\u202A-\u202E\u2066-\u2069\u200F\u061C]/,
  /%e2%80%(?:8[b-f]|a[a-e])|%e2%81%a[6-9]|%ef%bb%bf/i,

  // C1 control characters
  /[\x80-\x9F]/
];

function validateUrlString(req, res, url) {
  if (typeof url !== "string") {
    res.status(400).json({
      requestId: req.requestId,
      error: {
        code: "INVALID_URL_TYPE",
        message: "\"url\" must be a string."
      }
    });
    return false;
  }

  if (url.length === 0 || Buffer.byteLength(url, "utf8") > MAX_URL_BYTES) {
    res.status(400).json({
      requestId: req.requestId,
      error: {
        code: "URL_LENGTH_OUT_OF_RANGE",
        message: `"url" must be between 1 and ${MAX_URL_BYTES} bytes.`
      }
    });
    return false;
  }

  for (const pattern of FORBIDDEN_URL_PATTERNS) {
    if (pattern.test(url)) {
      res.status(400).json({
        requestId: req.requestId,
        error: {
          code: "FORBIDDEN_URL_CONTENT",
          message: "The submitted value contains forbidden characters or patterns."
        }
      });
      return false;
    }
  }

  return true;
}

function strictInputGuard(req, res, next) {
  const contentType = (req.headers["content-type"] || "").toLowerCase();

  if (!contentType.includes("application/json")) {
    return res.status(415).json({
      requestId: req.requestId,
      error: {
        code: "UNSUPPORTED_MEDIA_TYPE",
        message: "Content-Type must be application/json."
      }
    });
  }

  const body = req.body;

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return res.status(400).json({
      requestId: req.requestId,
      error: {
        code: "INVALID_REQUEST_BODY",
        message: "Request body must be a JSON object."
      }
    });
  }

  const keys = Object.keys(body);

  // /authorize-redirect accepts { url, verificationToken, userConfirmedWarning? }
  if (req.path === "/authorize-redirect") {
    const allowedKeys = new Set(["url", "verificationToken", "userConfirmedWarning"]);
    if (
      !Object.prototype.hasOwnProperty.call(body, "url") ||
      !Object.prototype.hasOwnProperty.call(body, "verificationToken") ||
      keys.some((k) => !allowedKeys.has(k))
    ) {
      return res.status(400).json({
        requestId: req.requestId,
        error: {
          code: "INVALID_REQUEST_SHAPE",
          message: "Provide \"url\" and \"verificationToken\"."
        }
      });
    }

    if (!validateUrlString(req, res, body.url)) {
      return;
    }

    if (typeof body.verificationToken !== "string" || body.verificationToken.length > 1024) {
      return res.status(400).json({
        requestId: req.requestId,
        error: {
          code: "INVALID_VERIFICATION_TOKEN",
          message: "Provide a valid verificationToken string."
        }
      });
    }

    return next();
  }

  if (keys.length !== 1 || keys[0] !== "url") {
    return res.status(400).json({
      requestId: req.requestId,
      error: {
        code: "INVALID_REQUEST_SHAPE",
        message: "Request body must contain exactly one field: \"url\"."
      }
    });
  }

  if (!validateUrlString(req, res, body.url)) {
    return;
  }

  next();
}

module.exports = { strictInputGuard };
