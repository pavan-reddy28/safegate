"use strict";

const express = require("express");

const router = express.Router();

router.get("/", (req, res) => {
  return res.status(200).json({
    status: "OK",
    application: "SafeGate",
    service: "100% On-Device Zero-Leakage URL Verification API",
    privacyMode: "ZERO_EGRESS_ON_DEVICE_ONLY",
    outboundNetworkCalls: 0,
    zeroUrlRetention: true,
    endpoints: {
      health: "GET /api/v1/health",
      verify: "POST /api/v1/verify",
      authorizeRedirect: "POST /api/v1/verify/authorize-redirect"
    }
  });
});

module.exports = router;