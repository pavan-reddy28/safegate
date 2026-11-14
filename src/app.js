
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

function createBaseApp(options = {}) {
  const {
    attachErrorHandlers = true,
    mountRootHealth = true,
    scopeCspToApi = false
  } = options;

  const app = express();

  app.disable("x-powered-by");
  app.use(requestIdMiddleware);

  const apiHelmet = helmet({
    frameguard: { action: "deny" },
    noSniff: true,
    xssFilter: true,
    hidePoweredBy: true,
    referrerPolicy: { policy: "no-referrer" },
    crossOriginResourcePolicy: { policy: "same-origin" },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"]
      }
    }
  });

  if (scopeCspToApi) {
    app.use("/api/v1", apiHelmet);
    app.use(
      helmet({
        frameguard: { action: "deny" },
        noSniff: true,
        xssFilter: true,
        hidePoweredBy: true,
        referrerPolicy: { policy: "no-referrer" },
        crossOriginResourcePolicy: { policy: "same-origin" },
        crossOriginOpenerPolicy: { policy: "same-origin" },
        contentSecurityPolicy: false
      })
    );
  } else {
    app.use(apiHelmet);
  }

  app.use((_req, res, next) => {
    res.setHeader(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=()"
    );
    next();
  });

  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin) return callback(null, true);

        if (env.frontendOrigins.includes(origin)) {
          return callback(null, true);
        }

        // Allow same-host localhost preview or AI Studio preview origins safely without ever sending credentials.
        try {
          const parsed = new URL(origin);
          if (
            ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname) ||
            parsed.protocol === "capacitor:"
          ) {
            return callback(null, true);
          }
        } catch {
          // fall through to deny
        }

        const error = new Error("Origin not allowed");
        error.code = "CORS_ORIGIN_DENIED";
        return callback(error);
      },

      methods: ["GET", "POST", "OPTIONS"],
      allowedHeaders: ["Content-Type", "X-Request-Source"],
      credentials: false,
      maxAge: 600
    })
  );

  const windowLimiter = rateLimit({
    windowMs: env.rateLimitWindowMs,
    limit: env.rateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,

    handler: (req, res) => {
      return res.status(429).json({
        requestId: req.requestId,
        error: {
          code: "RATE_LIMITED",
          message: "Too many requests. Please try again later."
        }
      });
    }
  });

  app.use("/api/v1", windowLimiter);
  app.use("/api/v1/verify", burstGuardMiddleware);

  app.use(
    express.json({
      limit: "8kb",
      strict: true
    })
  );

  app.use("/api/v1/verify", strictInputGuard);

  app.use("/api/v1/health", healthRoutes);
  app.use("/api/v1/verify", verificationRoutes);
  app.use("/health", healthRoutes);

  if (mountRootHealth) {
    app.use("/", healthRoutes);
  }

  if (attachErrorHandlers) {
    app.use(notFoundHandler);
    app.use(errorHandler);
  }

  return app;
}

const defaultApp = createBaseApp();
defaultApp.createBaseApp = createBaseApp;
defaultApp.notFoundHandler = notFoundHandler;
defaultApp.errorHandler = errorHandler;

module.exports = defaultApp;
