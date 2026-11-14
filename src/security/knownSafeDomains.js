"use strict";

/**
 * knownSafeDomains.js
 *
 * A locally maintained set of well-known, authoritative domains that are
 * almost universally safe for ordinary link navigation.
 *
 * PURPOSE
 * -------
 * When the full analysis pipeline (local heuristics + Google Safe Browsing)
 * returns NO_KNOWN_THREAT for a URL whose registrable domain is on this list,
 * the response is upgraded to KNOWN_SAFE.  This short-circuits any residual
 * "open with caution" friction for genuinely routine links.
 *
 * PRIVACY GUARANTEE
 * -----------------
 * This module never receives or stores the full URL.  Only the registrable
 * domain (e.g. "google.com") extracted by the domain analyzer is passed here.
 * No path, query string or fragment is ever seen by this module.
 *
 * MAINTENANCE
 * -----------
 * Add entries only for official first-party domains.  Do NOT add CDNs, link
 * shorteners, URL-redirect services, or any domain that hosts user-generated
 * content, because those can still carry malicious paths even if the domain
 * itself is legitimate.
 */

const KNOWN_SAFE_REGISTRABLE_DOMAINS = new Set([
  // Google
  "google.com",
  "google.co.in",
  "googleapis.com",
  "googleusercontent.com",
  "gmail.com",
  "g.co",
  "youtube.com",

  // Microsoft
  "microsoft.com",
  "microsoftonline.com",
  "live.com",
  "outlook.com",
  "office.com",
  "office365.com",
  "sharepoint.com",

  // Apple
  "apple.com",
  "icloud.com",

  // Meta / WhatsApp / Instagram
  "facebook.com",
  "fb.com",
  "instagram.com",
  "whatsapp.com",
  "whatsapp.net",

  // Amazon
  "amazon.in",
  "amazon.com",

  // Indian Banks (official first-party)
  "sbi.co.in",
  "onlinesbi.sbi",
  "hdfcbank.com",
  "icicibank.com",
  "axisbank.com",
  "kotak.com",
  "pnbindia.in",
  "canarabank.com",

  // UPI / Payments
  "npci.org.in",
  "upi.one",
  "bhimupi.org.in",
  "phonepe.com",
  "paytm.com",

  // Government of India
  "gov.in",
  "nic.in",
  "india.gov.in",
  "mca.gov.in",
  "incometax.gov.in",

  // Utilities
  "wikipedia.org",
  "wikimedia.org",
  "openai.com"
]);

/**
 * Returns true when the registrable domain is on the allow-list.
 *
 * @param {string|null} registrableDomain  — e.g. "sbi.co.in"
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

module.exports = { isKnownSafeDomain };
