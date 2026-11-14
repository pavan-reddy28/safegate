"use strict";

const { localBlockedDomains } = require("../config/env");
const { defaultOfflineFeed } = require("./offlineThreatFeed");

// Optional user-configured domain blocklist loaded strictly from local .env (no hardcoded URL cheats)
const blockedDomains = new Set(
  localBlockedDomains.map((domain) => domain.toLowerCase())
);

// Known URL shorteners that hide the true destination from the user & local analyzer.
const URL_SHORTENER_DOMAINS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly",
  "is.gd", "v.gd", "ow.ly", "shorturl.at", "shorturl.asia", "tiny.cc",
  "rebrand.ly", "s.id", "bl.ink", "clk.sh", "t.ly", "lnkd.in",
  "buff.ly", "adf.ly", "short.io", "urlz.fr", "snip.ly", "clck.ru",
  "soo.gd", "trib.al", "bit.do", "mcaf.ee", "shorte.st", "dub.sh",
  "kutt.it", "shrtco.de", "x.co", "x.gd", "u.nu", "han.gl",
  "me2.do", "vo.la", "qr.ae", "linklyhq.com", "switchy.io", "clc.to"
]);

// Free dynamic DNS, disposable tunneling, and abused free-tier hosting suffixes.
const TUNNEL_OR_DYNAMIC_DNS_DOMAINS = new Set([
  "ngrok.io", "ngrok.app", "ngrok.dev", "ngrok-free.app", "ngrok-free.dev",
  "trycloudflare.com", "loca.lt", "localtunnel.me", "serveo.net",
  "pinggy.link", "zrok.io", "bore.pub",
  "duckdns.org", "no-ip.org", "no-ip.biz", "hopto.org", "zapto.org",
  "ddns.net", "dynu.net", "afraid.org", "dyndns.org", "sytes.net",
  "servehttp.com", "redirectme.net", "bounceme.net", "myftp.org",
  "000webhostapp.com", "weeblysite.com", "glitch.me", "bplaced.net",
  "rf.gd", "epizy.com", "infinityfreeapp.com", "byethost.com"
]);

// Multi-tenant UGC, cloud serverless, storage, form builders & paste platforms
// frequently abused worldwide for phishing kits, credential harvesters & malware drops.
const FREE_UGC_OR_CLOUD_HOSTING_DOMAINS = new Set([
  // Cloud App Engines / Serverless / Containers
  "appspot.com", "run.app", "cloudfunctions.net", "web.app", "firebaseapp.com",
  "pages.dev", "workers.dev", "r2.dev", "vercel.app", "netlify.app",
  "github.io", "gitlab.io", "herokuapp.com", "onrender.com", "fly.dev",
  "railway.app", "replit.app", "repl.co", "surge.sh", "deno.dev", "val.run",
  "azurewebsites.net", "web.core.windows.net", "blob.core.windows.net",
  // Cloud Storage & CDNs abused for HTML smuggling / phishing kits / malware drops
  "sites.google.com", "storage.googleapis.com", "firebasestorage.googleapis.com",
  "raw.githubusercontent.com", "cdn.discordapp.com",
  "cloudfront.net", "s3.amazonaws.com", "digitaloceanspaces.com", "backblazeb2.com",
  "ipfs.io", "dweb.link", "cf-ipfs.com", "fleek.co",
  // Website / Form / Paste builders heavily used in global phishing
  "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "notion.site",
  "canva.site", "carrd.co", "framer.website", "webflow.io", "strikingly.com",
  "godaddysites.com", "jimdosite.com", "site123.me", "ucoz.com",
  "forms.gle", "jotform.com", "formstack.com", "typeform.com", "tally.so",
  "wufoo.com", "cognitoforms.com", "telegra.ph", "pastebin.com", "paste.ee",
  "rentry.co", "mailchi.mp", "hubspotpagebuilder.com"
]);

// High-abuse TLDs frequently seen in global phishing, crypto scams, malware & SMS spam.
const HIGH_RISK_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq",
  "cfd", "sbs", "icu", "cam", "top",
  "xyz", "click", "loan", "win", "buzz",
  "rest", "bar", "vip", "work", "monster",
  "zip", "mov", "autos", "cyou", "beauty",
  "quest", "hair", "skin", "boats", "mom",
  "pw", "cc", "club", "online", "site",
  "website", "space", "bond", "xin", "bid",
  "trade", "stream", "download", "racing", "party",
  "review", "faith", "date", "science", "gdn",
  "men", "life", "world", "today", "support",
  "cloud", "su", "ru"
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

function isOfflineFeedMatch(hostname, rawUrl = "") {
  return defaultOfflineFeed.matchesDomain(hostname) || (rawUrl ? defaultOfflineFeed.matchesUrl(rawUrl) : false);
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
  isOfflineFeedMatch,
  isUrlShortener,
  isTunnelOrDynamicDns,
  isFreeUgcOrCloudHosting,
  hasHighRiskTld,
  URL_SHORTENER_DOMAINS,
  TUNNEL_OR_DYNAMIC_DNS_DOMAINS,
  FREE_UGC_OR_CLOUD_HOSTING_DOMAINS,
  HIGH_RISK_TLDS
};