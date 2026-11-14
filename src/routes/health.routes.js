"use strict";

const express = require("express");
const env = require("../config/env");

const router = express.Router();

router.get("/", (req, res) => {
  return res.status(200).json({
    status: "OK",
    application: "SafeGate",
    service: "Local Privacy-First Verification API",
    privacyMode: env.strictOfflineMode ? "STRICT_OFFLINE" : "HASH_PREFIX_ONLY",
    zeroUrlRetention: true,
    endpoints: {
      health: "GET /api/v1/health",
      verify: "POST /api/v1/verify",
      authorizeRedirect: "POST /api/v1/verify/authorize-redirect"
    }
  });
});

module.exports = router;