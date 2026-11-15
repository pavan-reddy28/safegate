'use strict';

const crypto = require('node:crypto');

const TOKEN_PATTERN = /^[a-fA-F0-9]{64}$/;

function toExpiryMilliseconds(value) {
  const timestamp = value instanceof Date
    ? value.getTime()
    : new Date(value).getTime();

  return Number.isFinite(timestamp) ? timestamp : null;
}

/**
 * In-memory SHA-256 digest store for rotating Azure Key Vault Bearer tokens.
 * Supports retaining a short-lived previous generation per profile during rotation
 * grace windows while automatically purging expired digests and wiping memory.
 */
function createApiTokenStore({ graceOverlapMs = 5 * 60 * 1000 } = {}) {
  const entries = new Map();

  function zeroEntry(entry) {
    if (entry?.current?.digest) {
      entry.current.digest.fill(0);
    }
    if (entry?.previous?.digest) {
      entry.previous.digest.fill(0);
    }
  }

  function removeExpired(now = Date.now()) {
    for (const [profile, entry] of entries) {
      if (entry.previous && entry.previous.expiresAt <= now) {
        entry.previous.digest.fill(0);
        entry.previous = null;
      }

      if (entry.current && entry.current.expiresAt <= now) {
        entry.current.digest.fill(0);
        entry.current = null;
      }

      if (!entry.current && !entry.previous) {
        entries.delete(profile);
      }
    }
  }

  function set(profile, token, expiresAt) {
    if (
      typeof profile !== 'string' ||
      !/^[A-Za-z0-9_-]{1,32}$/.test(profile) ||
      typeof token !== 'string' ||
      !TOKEN_PATTERN.test(token)
    ) {
      throw new Error('Invalid API token update');
    }

    const now = Date.now();
    const expiry = toExpiryMilliseconds(expiresAt);

    if (expiry === null || expiry <= now) {
      throw new Error('API token expiry is invalid');
    }

    const digest = crypto.createHash('sha256')
      .update(token, 'utf8')
      .digest();

    const existing = entries.get(profile);

    let previous = null;
    if (existing?.current && existing.current.expiresAt > now) {
      // Keep the prior active token valid only across the configured rotation grace window
      if (!crypto.timingSafeEqual(existing.current.digest, digest)) {
        const graceLimit = graceOverlapMs > 0
          ? Math.min(existing.current.expiresAt, now + graceOverlapMs)
          : now;

        if (graceLimit > now) {
          previous = {
            digest: existing.current.digest,
            expiresAt: graceLimit
          };
        } else {
          existing.current.digest.fill(0);
        }
      } else {
        existing.current.digest.fill(0);
      }
    }

    if (existing?.previous) {
      existing.previous.digest.fill(0);
    }

    entries.set(profile, {
      current: { digest, expiresAt: expiry },
      previous
    });
  }

  function matches(token) {
    if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) {
      return false;
    }

    removeExpired();

    const candidate = crypto.createHash('sha256')
      .update(token, 'utf8')
      .digest();

    let matched = false;

    try {
      for (const entry of entries.values()) {
        if (entry.current) {
          const hit = crypto.timingSafeEqual(candidate, entry.current.digest);
          matched = hit || matched;
        }
        if (entry.previous) {
          const hitPrev = crypto.timingSafeEqual(candidate, entry.previous.digest);
          matched = hitPrev || matched;
        }
      }
    } finally {
      candidate.fill(0);
    }

    return matched;
  }

  function activeCount() {
    removeExpired();
    let count = 0;
    for (const entry of entries.values()) {
      if (entry.current) count += 1;
    }
    return count;
  }

  function clear() {
    for (const entry of entries.values()) {
      zeroEntry(entry);
    }
    entries.clear();
  }

  return Object.freeze({
    set,
    matches,
    activeCount,
    clear
  });
}

module.exports = { createApiTokenStore };
