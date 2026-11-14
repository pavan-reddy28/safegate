"use strict";

/**
 * knownSafeDomains.js
 *
 * Locally maintained set of authoritative first-party domains.
 *
 * SECURITY RULE:
 * Never add multi-tenant UGC/hosting platforms, CDNs, or link shorteners
 * (e.g. googleusercontent.com, sites.google.com, amazonaws.com, bit.ly),
 * because attackers host phishing pages on those domains.
 *
 * PRIVACY GUARANTEE:
 * Only the registrable domain (e.g. "sbi.co.in") is checked here.
 * No path, query string, or fragment is ever seen by this module.
 */

const KNOWN_SAFE_REGISTRABLE_DOMAINS = new Set([
  // Google (first-party web properties only — NOT googleusercontent.com)
  "google.com",
  "google.co.in",
  "gmail.com",
  "youtube.com",

  // Microsoft
  "microsoft.com",
  "microsoftonline.com",
  "live.com",
  "outlook.com",
  "office.com",
  "office365.com",

  // Apple
  "apple.com",
  "icloud.com",

  // Meta / WhatsApp / Instagram
  "facebook.com",
  "fb.com",
  "instagram.com",
  "whatsapp.com",
  "whatsapp.net",

  // E-Commerce
  "amazon.in",
  "amazon.com",
  "flipkart.com",

  // Indian Banks (official first-party domains)
  "sbi.co.in",
  "onlinesbi.sbi",
  "sbi.bank.in",
  "hdfcbank.com",
  "icicibank.com",
  "axisbank.com",
  "kotak.com",
  "pnbindia.in",
  "canarabank.com",
  "bankofbaroda.in",
  "unionbankofindia.co.in",
  "indusind.com",
  "yesbank.in",
  "idfcfirstbank.com",

  // Global Banks
  "chase.com",
  "bankofamerica.com",
  "wellsfargo.com",
  "citi.com",
  "hsbc.com",
  "paypal.com",

  // UPI / Payments
  "npci.org.in",
  "bhimupi.org.in",
  "phonepe.com",
  "paytm.com",
  "razorpay.com",

  // Indian Telecom
  "jio.com",
  "airtel.in",
  "myvi.in",
  "bsnl.co.in",

  // Government of India / Public Services
  "gov.in",
  "nic.in",
  "india.gov.in",
  "mca.gov.in",
  "incometax.gov.in",
  "uidai.gov.in",
  "epfindia.gov.in",
  "digilocker.gov.in",
  "parivahan.gov.in",
  "indiapost.gov.in",
  "irctc.co.in",

  // Global & Indian Tech, Developer, Reference & Utilities
  "github.com",
  "gitlab.com",
  "stackoverflow.com",
  "mozilla.org",
  "w3.org",
  "cloudflare.com",
  "zoom.us",
  "linkedin.com",
  "adobe.com",
  "python.org",
  "nodejs.org",
  "npmjs.com",
  "f-droid.org",
  "wikipedia.org",
  "wikimedia.org",
  "openai.com",
  "netflix.com",

  // Indian E-Commerce, Fintech & Trusted Services
  "myntra.com",
  "zomato.com",
  "swiggy.com",
  "cred.club",
  "zerodha.com",
  "groww.in",
  "rbi.org.in",
  "sebi.gov.in",
  "nseindia.com",
  "bseindia.com",

  // Authoritative News & Global Govt
  "bbc.com",
  "bbc.co.uk",
  "reuters.com",
  "gov.uk",
  "usa.gov",
  "irs.gov",
  "who.int"
]);

// Safe first-party domains that also host user-created files, redirects, or forms
// (clean HTTPS pages are KNOWN_SAFE, but downloads, forms & query redirects are NEVER skipped).
const USER_CONTENT_BEARING_SAFE_DOMAINS = new Set([
  "github.com",
  "gitlab.com",
  "google.com",
  "google.co.in",
  "youtube.com",
  "facebook.com",
  "fb.com",
  "linkedin.com",
  "adobe.com",
  "office.com",
  "live.com"
]);

// Well-known, authoritative public infrastructure/DNS IPs (HTTPS clean requests only).
const KNOWN_SAFE_PUBLIC_IPS = new Set([
  "1.1.1.1",
  "1.0.0.1",
  "8.8.8.8",
  "8.8.4.4",
  "9.9.9.9",
  "149.112.112.112",
  "2606:4700:4700::1111",
  "2606:4700:4700::1001",
  "2001:4860:4860::8888",
  "2001:4860:4860::8844"
]);

// Authoritative software-release hosts where HTTPS .apk downloads should warn rather than auto-block.
const TRUSTED_SOFTWARE_RELEASE_DOMAINS = new Set([
  "f-droid.org",
  "github.com",
  "gitlab.com"
]);

/**
 * Returns true when the registrable domain is on the authoritative allow-list.
 *
 * @param {string|null} registrableDomain
 * @returns {boolean}
 */
function isKnownSafeDomain(registrableDomain) {
  if (!registrableDomain || typeof registrableDomain !== "string") {
    return false;
  }

  return KNOWN_SAFE_REGISTRABLE_DOMAINS.has(
    registrableDomain.toLowerCase().trim()
  );
}

function isKnownSafePublicIp(ip) {
  if (!ip || typeof ip !== "string") return false;
  return KNOWN_SAFE_PUBLIC_IPS.has(ip.toLowerCase().trim().replace(/^\[|\]$/g, ""));
}

function isTrustedSoftwareReleaseDomain(registrableDomain) {
  if (!registrableDomain || typeof registrableDomain !== "string") return false;
  return TRUSTED_SOFTWARE_RELEASE_DOMAINS.has(registrableDomain.toLowerCase().trim());
}

function isUserContentSafeDomain(registrableDomain) {
  if (!registrableDomain || typeof registrableDomain !== "string") return false;
  return USER_CONTENT_BEARING_SAFE_DOMAINS.has(registrableDomain.toLowerCase().trim());
}

module.exports = {
  isKnownSafeDomain,
  isKnownSafePublicIp,
  isTrustedSoftwareReleaseDomain,
  isUserContentSafeDomain,
  KNOWN_SAFE_REGISTRABLE_DOMAINS,
  KNOWN_SAFE_PUBLIC_IPS,
  TRUSTED_SOFTWARE_RELEASE_DOMAINS,
  USER_CONTENT_BEARING_SAFE_DOMAINS
};
