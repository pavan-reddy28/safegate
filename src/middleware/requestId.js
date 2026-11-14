"use strict";

const { randomUUID } = require("node:crypto");

function requestIdMiddleware(req, res, next) {
  req.requestId = randomUUID();

  // Security-sensitive verification responses must never be cached or leak referrers.
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Referrer-Policy", "no-referrer");

  next();
}

module.exports = {
  requestIdMiddleware
};