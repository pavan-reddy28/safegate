"use strict";

const { localBlockedDomains } = require("../config/env");

// Dynamically configured blocked domains + built-in known malicious test/sinkhole domains
const blockedDomains = new Set(
  localBlockedDomains.map((domain) => domain.toLowerCase())
);

// Known URL shorteners that hide the true destination from the user & local analyzer
// without making a privacy-leaking outbound HTTP request.
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
  "soo.gd"
]);

// Free dynamic DNS, disposable tunneling, and abused free-tier hosting suffixes
// heavily exploited in SMS banking/KYC phishing campaigns.
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
  "weeblysite.com"
]);

// High-abuse TLDs frequently seen in automated SMS scam campaigns.
// Never an automatic block alone, used as a risk signal when combined with other indicators.
const HIGH_RISK_TLDS = new Set([
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "cfd",
  "sbs",
  "icu",
  "cam",
  "top",
  "xyz",
  "click",
  "loan",
  "win",
  "buzz",
  "rest",
  "bar",
  "vip",
  "work"
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
  hasHighRiskTld,
  URL_SHORTENER_DOMAINS,
  TUNNEL_OR_DYNAMIC_DNS_DOMAINS,
  HIGH_RISK_TLDS
};