"use strict";

/**
 * burstGuard.js
 *
 * Per-request-source burst guard layered on top of the existing
 * express-rate-limit window limiter.
 *
 * WHY A SECOND LAYER?
 * -------------------
 * express-rate-limit counts all requests inside a fixed window (e.g. 60 s / 30
 * requests).  An attacker can still probe 30 URLs in the first millisecond of
 * every window.  This module adds a TOKEN-BUCKET per source that smooths
 * traffic within the window and blocks short-interval floods.
 *
 * SOURCE IDENTITY
 * ---------------
 * The app only listens on 127.0.0.1 (loopback).  Every request therefore
 * comes from the local Android WebView / browser.  We use the X-Request-Source
 * header (set by the mobile app) if present; otherwise we fall back to the IP.
 * No user-identifiable data is stored.
 *
 * TOKEN BUCKET SETTINGS
 * ---------------------
 *   capacity    — maximum burst size (tokens)
 *   refillRate  — tokens added per second
 *   costPerReq  — tokens consumed per request
 *
 * With defaults (capacity = 5, refillRate = 1 token/s):
 *   - A burst of 5 requests is allowed instantly.
 *   - After that, only 1 request per second is allowed until the bucket refills.
 *   - A fresh batch of 5 more requests can be sent after 5 seconds of silence.
 */

const HEADER_BUCKET_CAPACITY = 5;
const IP_BUCKET_CAPACITY     = 20;
const REFILL_RATE            = 1;        // tokens per second
const COST_PER_REQUEST       = 1;
const MAX_BUCKETS            = 256;      // prevent unbounded memory growth
const PRUNE_INTERVAL_MS      = 60_000;   // remove stale buckets every minute

/** @type {Map<string, {tokens: number, lastRefill: number, capacity: number}>} */
const buckets = new Map();

function pruneStale() {
  const now = Date.now();
  for (const [key, bucket] of buckets) {
    const idleSec = (now - bucket.lastRefill) / 1000;
    if (idleSec > (bucket.capacity / REFILL_RATE) * 2) {
      buckets.delete(key);
    }
  }
}

setInterval(pruneStale, PRUNE_INTERVAL_MS).unref();

function getSourceKeys(req) {
  const ipKey = `ip:${req.ip || "unknown"}`;
  const header = req.headers["x-request-source"];
  if (header && /^[a-f0-9]{8,64}$/i.test(header)) {
    return [
      { key: `hdr:${header.slice(0, 64).toLowerCase()}`, capacity: HEADER_BUCKET_CAPACITY },
      { key: ipKey, capacity: IP_BUCKET_CAPACITY }
    ];
  }
  return [{ key: ipKey, capacity: HEADER_BUCKET_CAPACITY }];
}

function refill(bucket) {
  const now = Date.now();
  const elapsed = (now - bucket.lastRefill) / 1000;
  bucket.tokens = Math.min(
    bucket.capacity,
    bucket.tokens + elapsed * REFILL_RATE
  );
  bucket.lastRefill = now;
}

function takeToken(key, capacity) {
  let bucket = buckets.get(key);
  if (!bucket) {
    if (buckets.size >= MAX_BUCKETS) {
      const oldest = buckets.keys().next().value;
      if (oldest !== undefined) buckets.delete(oldest);
    }
    bucket = { tokens: capacity, lastRefill: Date.now(), capacity };
    buckets.set(key, bucket);
  }

  refill(bucket);
  if (bucket.tokens < COST_PER_REQUEST) {
    return false;
  }
  bucket.tokens -= COST_PER_REQUEST;
  return true;
}

/**
 * Express middleware. Responds 429 when either the source-header or IP token bucket is exhausted.
 */
function burstGuardMiddleware(req, res, next) {
  const keys = getSourceKeys(req);
  for (const { key, capacity } of keys) {
    if (!takeToken(key, capacity)) {
      return res.status(429).json({
        requestId: req.requestId,
        error: {
          code: "BURST_RATE_LIMITED",
          message: "Too many requests in a short time. Please wait a moment."
        }
      });
    }
  }
  next();
}

module.exports = { burstGuardMiddleware };
