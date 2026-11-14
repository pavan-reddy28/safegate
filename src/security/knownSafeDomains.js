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

  // Utilities
  "wikipedia.org",
  "wikimedia.org",
  "openai.com",
  "netflix.com"
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

module.exports = { isKnownSafeDomain, KNOWN_SAFE_REGISTRABLE_DOMAINS };
