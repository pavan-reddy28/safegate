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

const BUCKET_CAPACITY   = 5;
const REFILL_RATE       = 1;        // tokens per second
const COST_PER_REQUEST  = 1;
const MAX_BUCKETS       = 256;      // prevent unbounded memory growth
const PRUNE_INTERVAL_MS = 60_000;   // remove stale buckets every minute

/** @type {Map<string, {tokens: number, lastRefill: number}>} */
const buckets = new Map();

function pruneStale() {
  const now = Date.now();
  for (const [key, bucket] of buckets) {
    // A bucket idle for more than 2× the window is considered stale.
    const idleSec = (now - bucket.lastRefill) / 1000;
    if (idleSec > BUCKET_CAPACITY / REFILL_RATE * 2) {
      buckets.delete(key);
    }
  }
}

setInterval(pruneStale, PRUNE_INTERVAL_MS).unref();

function getSourceKey(req) {
  // The Android app may send X-Request-Source: <device-id-hash>.
  // We accept it only if it looks like a hex string (no raw identifiers).
  const header = req.headers["x-request-source"];
  if (header && /^[a-f0-9]{8,64}$/i.test(header)) {
    return `hdr:${header.slice(0, 64).toLowerCase()}`;
  }
  return `ip:${req.ip || "unknown"}`;
}

function refill(bucket) {
  const now = Date.now();
  const elapsed = (now - bucket.lastRefill) / 1000;
  bucket.tokens = Math.min(
    BUCKET_CAPACITY,
    bucket.tokens + elapsed * REFILL_RATE
  );
  bucket.lastRefill = now;
}

/**
 * Express middleware.  Responds 429 when the per-source token bucket is empty.
 */
function burstGuardMiddleware(req, res, next) {
  const key = getSourceKey(req);

  let bucket = buckets.get(key);

  if (!bucket) {
    if (buckets.size >= MAX_BUCKETS) {
      // Evict the first (oldest inserted) entry.
      const oldest = buckets.keys().next().value;
      if (oldest !== undefined) buckets.delete(oldest);
    }

    bucket = { tokens: BUCKET_CAPACITY, lastRefill: Date.now() };
    buckets.set(key, bucket);
  }

  refill(bucket);

  if (bucket.tokens < COST_PER_REQUEST) {
    return res.status(429).json({
      requestId: req.requestId,
      error: {
        code: "BURST_RATE_LIMITED",
        message: "Too many requests in a short time. Please wait a moment."
      }
    });
  }

  bucket.tokens -= COST_PER_REQUEST;
  next();
}

module.exports = { burstGuardMiddleware };
