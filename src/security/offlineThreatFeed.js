"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

/**
 * offlineThreatFeed.js
 *
 * 100% Zero-Egress Offline Threat Intelligence Engine (Bloom Filter + Hash Index).
 * Allows SafeGate to match known phishing domains and malicious URL hashes
 * locally on-device with zero per-click outbound network calls.
 *
 * Supports loading a locally cached (optionally HMAC/Ed25519 signed) JSON manifest
 * containing domain names, SHA-256 hashes, or compact Bloom filter bitsets.
 */

function normalizeDomain(host) {
  return String(host || "").toLowerCase().trim().replace(/\.$/, "");
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value || ""), "utf8").digest("hex");
}

class OfflineBloomFilter {
  constructor(bitSize = 8192, hashCount = 4) {
    this.bitSize = Math.max(64, bitSize);
    this.hashCount = Math.max(2, Math.min(8, hashCount));
    this.bytes = Buffer.alloc(Math.ceil(this.bitSize / 8));
  }

  _positions(item) {
    const digest = crypto.createHash("sha256").update(String(item), "utf8").digest();
    const h1 = digest.readUInt32BE(0);
    const h2 = digest.readUInt32BE(4) || 1;
    const out = [];
    for (let i = 0; i < this.hashCount; i++) {
      // Double hashing across 32-bit unsigned space
      const combined = (h1 + i * h2) >>> 0;
      out.push(combined % this.bitSize);
    }
    return out;
  }

  add(item) {
    for (const bitIdx of this._positions(item)) {
      const byteIdx = bitIdx >>> 3;
      const mask = 1 << (bitIdx & 7);
      this.bytes[byteIdx] |= mask;
    }
  }

  mightContain(item) {
    for (const bitIdx of this._positions(item)) {
      const byteIdx = bitIdx >>> 3;
      const mask = 1 << (bitIdx & 7);
      if ((this.bytes[byteIdx] & mask) === 0) {
        return false;
      }
    }
    return true;
  }

  static fromBase64(base64, bitSize, hashCount) {
    const buf = Buffer.from(base64, "base64");
    const filter = new OfflineBloomFilter(bitSize || buf.length * 8, hashCount || 4);
    buf.copy(filter.bytes, 0, 0, Math.min(buf.length, filter.bytes.length));
    return filter;
  }
}

class OfflineThreatFeedStore {
  constructor() {
    this.blockedDomainHashes = new Set();
    this.blockedUrlHashes = new Set();
    this.bloomFilter = null;
    this.feedVersion = "builtin-empty";
    this.signatureVerified = false;
  }

  clear() {
    this.blockedDomainHashes.clear();
    this.blockedUrlHashes.clear();
    this.bloomFilter = null;
    this.feedVersion = "builtin-empty";
    this.signatureVerified = false;
  }

  /**
   * Load domains/URL hashes directly in memory (e.g. from unit tests or local Android asset).
   */
  loadManifest(manifest, options = {}) {
    if (!manifest || typeof manifest !== "object") {
      throw new Error("INVALID_OFFLINE_FEED_MANIFEST");
    }

    let sigVerified = false;
    if (options.publicKeyPem || options.hmacSecret) {
      if (!manifest.signature || typeof manifest.signature !== "string") {
        throw new Error("OFFLINE_FEED_MISSING_SIGNATURE");
      }
      const canonical = JSON.stringify({
        version: manifest.version || 1,
        domains: manifest.domains || [],
        domainHashes: manifest.domainHashes || [],
        urlHashes: manifest.urlHashes || []
      });

      if (options.publicKeyPem) {
        sigVerified = crypto.verify(
          null,
          Buffer.from(canonical, "utf8"),
          options.publicKeyPem,
          Buffer.from(manifest.signature, "base64")
        );
      } else if (options.hmacSecret) {
        const expected = crypto
          .createHmac("sha256", options.hmacSecret)
          .update(canonical, "utf8")
          .digest();
        const provided = Buffer.from(manifest.signature, "base64");
        sigVerified =
          expected.length === provided.length &&
          crypto.timingSafeEqual(expected, provided);
      }

      if (!sigVerified) {
        throw new Error("OFFLINE_FEED_SIGNATURE_INVALID");
      }
    }

    const nextDomainHashes = new Set();
    const nextUrlHashes = new Set();

    const domains = Array.isArray(manifest.domains) ? manifest.domains : [];
    for (const d of domains) {
      const norm = normalizeDomain(d);
      if (norm) nextDomainHashes.add(sha256Hex(norm));
    }

    const domainHashes = Array.isArray(manifest.domainHashes) ? manifest.domainHashes : [];
    for (const h of domainHashes) {
      if (/^[a-f0-9]{64}$/i.test(String(h))) {
        nextDomainHashes.add(String(h).toLowerCase());
      }
    }

    const urlHashes = Array.isArray(manifest.urlHashes) ? manifest.urlHashes : [];
    for (const h of urlHashes) {
      if (/^[a-f0-9]{64}$/i.test(String(h))) {
        nextUrlHashes.add(String(h).toLowerCase());
      }
    }

    let nextBloom = null;
    if (manifest.bloom && manifest.bloom.bitsBase64) {
      nextBloom = OfflineBloomFilter.fromBase64(
        manifest.bloom.bitsBase64,
        manifest.bloom.bitSize,
        manifest.bloom.hashCount
      );
    }

    this.blockedDomainHashes = nextDomainHashes;
    this.blockedUrlHashes = nextUrlHashes;
    this.bloomFilter = nextBloom;
    this.feedVersion = String(manifest.version || "1");
    this.signatureVerified = sigVerified;

    return this.getStats();
  }

  loadFromFile(filePath, options = {}) {
    const resolved = path.resolve(filePath);
    const raw = fs.readFileSync(resolved, "utf8");
    const parsed = JSON.parse(raw);
    return this.loadManifest(parsed, options);
  }

  matchesDomain(hostname) {
    const norm = normalizeDomain(hostname);
    if (!norm) return false;

    const labels = norm.split(".");
    for (let i = 0; i < labels.length - 1; i++) {
      const candidate = labels.slice(i).join(".");
      const hash = sha256Hex(candidate);
      if (this.blockedDomainHashes.has(hash)) {
        return true;
      }
      if (this.bloomFilter && this.bloomFilter.mightContain(candidate)) {
        // If paired with exact hashes, require confirmation; if bloom-only manifest, treat match as hit.
        if (this.blockedDomainHashes.size === 0 || this.blockedDomainHashes.has(hash)) {
          return true;
        }
      }
    }
    return false;
  }

  matchesUrl(urlString) {
    if (!urlString || this.blockedUrlHashes.size === 0) return false;
    return this.blockedUrlHashes.has(sha256Hex(String(urlString).trim()));
  }

  getStats() {
    return {
      version: this.feedVersion,
      domainHashesCount: this.blockedDomainHashes.size,
      urlHashesCount: this.blockedUrlHashes.size,
      hasBloomFilter: Boolean(this.bloomFilter),
      signatureVerified: this.signatureVerified
    };
  }
}

const defaultOfflineFeed = new OfflineThreatFeedStore();

// Auto-load local offline threat feed file if configured via env
if (process.env.OFFLINE_THREAT_FEED_PATH) {
  try {
    defaultOfflineFeed.loadFromFile(process.env.OFFLINE_THREAT_FEED_PATH, {
      hmacSecret: process.env.OFFLINE_THREAT_FEED_HMAC_SECRET || undefined
    });
  } catch (err) {
    console.error("[SafeGate] Failed to load offline threat feed:", err.message);
  }
}

module.exports = {
  OfflineBloomFilter,
  OfflineThreatFeedStore,
  defaultOfflineFeed,
  sha256Hex
};
