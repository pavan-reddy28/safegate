"use strict";

/**
 * strictInputGuard.js
 *
 * Final-line input sanitization middleware that runs before any controller.
 *
 * CHECKS PERFORMED
 * ----------------
 * 1. Content-Type must be application/json (no multipart, no form-data).
 * 2. The parsed body must be a plain object — no arrays, strings, numbers.
 * 3. The body must have exactly one key: "url".
 * 4. The url value must be a string.
 * 5. The url string must not contain Unicode null bytes, RTL override
 *    characters, or any C0/C1 control characters.
 * 6. The url string must not start with a dangerous scheme (javascript:,
 *    data:, vbscript:, file:) even when wrapped in whitespace.
 * 7. Length must be between 1 and 4096 bytes.
 *
 * None of the URL data is logged.
 */

const MAX_URL_BYTES = 4096;

const FORBIDDEN_URL_PATTERNS = [
  // Dangerous schemes (even with leading whitespace / zero-width chars)
  /^[\s\u200B-\u200D\uFEFF]*(?:javascript|data|vbscript|file):/i,

  // Null bytes
  /\x00/,

  // RTL / bidi override characters that can disguise URLs
  /[\u202A-\u202E\u2066-\u2069\u200F\u061C]/,

  // C1 control characters
  /[\x80-\x9F]/
];

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

  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body)
  ) {
    return res.status(400).json({
      requestId: req.requestId,
      error: {
        code: "INVALID_REQUEST_BODY",
        message: "Request body must be a JSON object."
      }
    });
  }

  const keys = Object.keys(body);

  if (keys.length !== 1 || keys[0] !== "url") {
    return res.status(400).json({
      requestId: req.requestId,
      error: {
        code: "INVALID_REQUEST_SHAPE",
        message: "Request body must contain exactly one field: \"url\"."
      }
    });
  }

  const url = body.url;

  if (typeof url !== "string") {
    return res.status(400).json({
      requestId: req.requestId,
      error: {
        code: "INVALID_URL_TYPE",
        message: "\"url\" must be a string."
      }
    });
  }

  if (url.length === 0 || url.length > MAX_URL_BYTES) {
    return res.status(400).json({
      requestId: req.requestId,
      error: {
        code: "URL_LENGTH_OUT_OF_RANGE",
        message: `"url" must be between 1 and ${MAX_URL_BYTES} characters.`
      }
    });
  }

  for (const pattern of FORBIDDEN_URL_PATTERNS) {
    if (pattern.test(url)) {
      return res.status(400).json({
        requestId: req.requestId,
        error: {
          code: "FORBIDDEN_URL_CONTENT",
          message: "The submitted value contains forbidden characters or patterns."
        }
      });
    }
  }

  next();
}

module.exports = { strictInputGuard };
