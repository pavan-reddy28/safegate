"use strict";

const { localBlockedDomains } = require("../config/env");

const blockedDomains = new Set(
  localBlockedDomains.map((domain) => domain.toLowerCase())
);

// Known URL shorteners that hide the true destination from the user & local analyzer.
const URL_SHORTENER_DOMAINS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "rb.gy",
  "cutt.ly",
  "is.gd",
  "v.gd",
  "ow.ly",
  "shorturl.at",
  "tiny.cc",
  "rebrand.ly",
  "s.id",
  "bl.ink",
  "clk.sh",
  "t.ly",
  "lnkd.in",
  "buff.ly",
  "adf.ly",
  "short.io",
  "urlz.fr",
  "snip.ly",
  "clck.ru",
  "soo.gd",
  "trib.al",
  "bit.do",
  "mcaf.ee",
  "shorte.st"
]);

// Free dynamic DNS, disposable tunneling, and abused free-tier hosting suffixes.
const TUNNEL_OR_DYNAMIC_DNS_DOMAINS = new Set([
  "ngrok.io",
  "ngrok-free.app",
  "ngrok-free.dev",
  "trycloudflare.com",
  "loca.lt",
  "localtunnel.me",
  "serveo.net",
  "duckdns.org",
  "no-ip.org",
  "no-ip.biz",
  "hopto.org",
  "zapto.org",
  "ddns.net",
  "000webhostapp.com",
  "weeblysite.com",
  "glitch.me",
  "bplaced.net",
  "rf.gd",
  "epizy.com"
]);

// Multi-tenant UGC / static / form platforms frequently abused for phishing landing pages.
// Not malicious by default, but high risk when paired with banking/KYC/login/scam lures.
const FREE_UGC_OR_CLOUD_HOSTING_DOMAINS = new Set([
  "sites.google.com",
  "storage.googleapis.com",
  "firebasestorage.googleapis.com",
  "blogspot.com",
  "wordpress.com",
  "weebly.com",
  "wixsite.com",
  "pages.dev",
  "workers.dev",
  "vercel.app",
  "netlify.app",
  "github.io",
  "web.app",
  "firebaseapp.com",
  "herokuapp.com",
  "onrender.com",
  "azurewebsites.net",
  "cloudfront.net",
  "s3.amazonaws.com"
]);

// High-abuse TLDs frequently seen in automated SMS scam campaigns.
const HIGH_RISK_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq",
  "cfd", "sbs", "icu", "cam", "top",
  "xyz", "click", "loan", "win", "buzz",
  "rest", "bar", "vip", "work", "monster",
  "zip", "mov", "autos", "cyou", "beauty",
  "quest", "hair", "skin", "boats", "mom"
]);

function matchesDomainSet(hostname, domainSet) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
  if (!host) return false;

  for (const domain of domainSet) {
    if (host === domain || host.endsWith(`.${domain}`)) {
      return true;
    }
  }
  return false;
}

function isBlockedHost(hostname) {
  return matchesDomainSet(hostname, blockedDomains);
}

function isUrlShortener(hostname) {
  return matchesDomainSet(hostname, URL_SHORTENER_DOMAINS);
}

function isTunnelOrDynamicDns(hostname) {
  return matchesDomainSet(hostname, TUNNEL_OR_DYNAMIC_DNS_DOMAINS);
}

function isFreeUgcOrCloudHosting(hostname) {
  return matchesDomainSet(hostname, FREE_UGC_OR_CLOUD_HOSTING_DOMAINS);
}

function hasHighRiskTld(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
  const parts = host.split(".");
  if (parts.length < 2) return false;
  const tld = parts[parts.length - 1];
  return HIGH_RISK_TLDS.has(tld);
}

module.exports = {
  isBlockedHost,
  isUrlShortener,
  isTunnelOrDynamicDns,
  isFreeUgcOrCloudHosting,
  hasHighRiskTld,
  URL_SHORTENER_DOMAINS,
  TUNNEL_OR_DYNAMIC_DNS_DOMAINS,
  FREE_UGC_OR_CLOUD_HOSTING_DOMAINS,
  HIGH_RISK_TLDS
};