
"use strict";

const express = require("express");
const helmet  = require("helmet");
const cors    = require("cors");
const rateLimit = require("express-rate-limit");

const env = require("./config/env");

const { requestIdMiddleware } = require("./middleware/requestId");
const { notFoundHandler, errorHandler } = require("./middleware/errorHandler");
const { burstGuardMiddleware } = require("./middleware/burstGuard");
const { strictInputGuard } = require("./middleware/strictInputGuard");

const healthRoutes       = require("./routes/health.routes");
const verificationRoutes = require("./routes/verification.routes");

const app = express();

// ─────────────────────────────────────────────────────────────────────────────
// HARDENING: remove Express fingerprint header
// ─────────────────────────────────────────────────────────────────────────────
app.disable("x-powered-by");

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST ID + NO-CACHE POLICY
// Every response carries a UUID and must never be cached by an intermediary.
// ─────────────────────────────────────────────────────────────────────────────
app.use(requestIdMiddleware);

// ─────────────────────────────────────────────────────────────────────────────
// SECURITY HEADERS (Helmet)
// Adds: X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security,
// Content-Security-Policy, Referrer-Policy, etc.
// ─────────────────────────────────────────────────────────────────────────────
app.use(helmet({
  // This API is never embedded in a frame.
  frameguard: { action: "deny" },
  // No browser should sniff the content type.
  noSniff: true,
  // No content to XSS-filter, but we set it anyway.
  xssFilter: true,
  // Hide that this is an Express server.
  hidePoweredBy: true,
  // Never leak referrers.
  referrerPolicy: { policy: "no-referrer" },
  crossOriginResourcePolicy: { policy: "same-origin" },
  // Tight CSP — this is a JSON API, not a web app.
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));

// ─────────────────────────────────────────────────────────────────────────────
// CORS
// Only allow the local frontend origin set at startup.
// Native Android / command-line callers send no Origin header — that's fine.
// ─────────────────────────────────────────────────────────────────────────────
app.use(cors({
  origin: (origin, callback) => {
    // No origin = native app or CLI tool — always allow.
    if (!origin) return callback(null, true);

    if (env.frontendOrigins.includes(origin)) {
      return callback(null, true);
    }

    const error = new Error("Origin not allowed");
    error.code  = "CORS_ORIGIN_DENIED";
    return callback(error);
  },

  methods:        ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-Request-Source"],
  credentials:    false,
  maxAge:         600
}));

// ─────────────────────────────────────────────────────────────────────────────
// WINDOW RATE LIMITER  (express-rate-limit)
// Caps the total number of requests per source per time window.
// ─────────────────────────────────────────────────────────────────────────────
const windowLimiter = rateLimit({
  windowMs: env.rateLimitWindowMs,
  limit:    env.rateLimitMax,
  standardHeaders: true,
  legacyHeaders:   false,

  handler: (req, res) => {
    return res.status(429).json({
      requestId: req.requestId,
      error: {
        code:    "RATE_LIMITED",
        message: "Too many requests. Please try again later."
      }
    });
  }
});

app.use("/api/v1", windowLimiter);

// ─────────────────────────────────────────────────────────────────────────────
// BURST GUARD  (token bucket)
// Prevents rapid-fire URL probing within the rate-limit window.
// ─────────────────────────────────────────────────────────────────────────────
app.use("/api/v1/verify", burstGuardMiddleware);

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST BODY PARSER
// Hard limit: 8 KB.  Reject non-JSON content types at this layer.
// ─────────────────────────────────────────────────────────────────────────────
app.use(express.json({
  limit:  "8kb",
  strict: true
}));

// ─────────────────────────────────────────────────────────────────────────────
// STRICT INPUT GUARD
// Validates shape, character set, and forbidden patterns before the controller.
// ─────────────────────────────────────────────────────────────────────────────
app.use("/api/v1/verify", strictInputGuard);

// ─────────────────────────────────────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────────────────────────────────────
app.use("/api/v1/health", healthRoutes);
app.use("/api/v1/verify", verificationRoutes);
app.use("/", healthRoutes);

// ─────────────────────────────────────────────────────────────────────────────
// ERROR HANDLERS
// ─────────────────────────────────────────────────────────────────────────────
app.use(notFoundHandler);
app.use(errorHandler);

module.exports = app;
