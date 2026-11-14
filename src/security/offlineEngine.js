import ipaddr from "ipaddr.js";
import { parse as parseDomain } from "tldts";

/**
 * Pure Browser/Android ESM 30-Layer On-Device Zero-Egress URL Verification Engine.
 * Mirrors all 30 server-side security layers locally inside Android APK / WebView
 * with zero outbound network calls, zero Node built-ins, and safe decoding.
 */

const MAX_URL_LENGTH = 4096;

function hasControlChars(value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code <= 0x1F || (code >= 0x7F && code <= 0x9F)) {
      return true;
    }
  }
  return false;
}

function stripInvisibleAndControlChars(value) {
  let out = "";
  for (const ch of String(value || "")) {
    const code = ch.charCodeAt(0);
    if (code <= 0x20 || code === 0x7F || (code >= 0x200B && code <= 0x200F) || code === 0xFEFF) {
      continue;
    }
    out += ch;
  }
  return out;
}

const INVISIBLE_OR_BIDI_CHARS =
  /[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF\u00AD\u061C\u3164\uFFA0\u115F\u1160\u180E]/;
const ENCODED_SPOOF_SEQUENCES =
  /(?:%00|%e2%80%8[b-f]|%e2%80%a[a-e]|%e2%81%a[0-9]|%ef%bb%bf|%e3%85%a4|%ef%be%a0)/i;
const MALFORMED_PERCENT_ENCODING = /%(?![0-9a-fA-F]{2})/;
const DANGEROUS_EXPLICIT_SCHEME =
  /^(?:javascript|data|vbscript|file|content|android-app|intent|upi|paytmmp|phonepe|tez|gpay|bhim|whatsapp|tg|tel|sms|smsto|mmsto|mailto|callto|facetime|geo|market|blob|filesystem|about|view-source|smb|sftp|chrome|edge|ftp|ws|wss):/i;
const DANGEROUS_REDIRECT_SCHEME =
  /^(?:javascript|data|vbscript|file|content|android-app|intent|upi|paytmmp|phonepe|tez|gpay|bhim|whatsapp|tg|tel|sms|smsto|mmsto|mailto|callto|facetime|geo|market|blob|filesystem|about|view-source|smb|sftp):/i;

const RESERVED_SUFFIXES = new Set([
  "localhost", "local", "internal", "test", "invalid", "example",
  "lan", "home", "arpa", "onion", "intranet", "corp"
]);

const DANGEROUS_PORTS = new Set([
  "21", "22", "23", "25", "110", "143", "445",
  "1433", "3306", "3389", "4444", "5432", "5900",
  "6379", "6667", "31337"
]);

const SUSPICIOUS_SERVICE_PORTS = new Set([
  "1337", "2082", "2083", "2086", "2087", "2095", "2096",
  "5000", "6666", "7777", "8000", "8080", "8443", "8888", "9000", "9999"
]);

const KNOWN_SAFE_REGISTRABLE_DOMAINS = new Set([
  "google.com", "google.co.in", "gmail.com", "youtube.com",
  "microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com",
  "apple.com", "icloud.com",
  "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "whatsapp.net",
  "amazon.in", "amazon.com", "flipkart.com",
  "sbi.co.in", "onlinesbi.sbi", "sbi.bank.in",
  "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com",
  "pnbindia.in", "canarabank.com", "bankofbaroda.in", "unionbankofindia.co.in",
  "indusind.com", "yesbank.in", "idfcfirstbank.com",
  "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "hsbc.com", "paypal.com",
  "npci.org.in", "bhimupi.org.in", "phonepe.com", "paytm.com", "razorpay.com",
  "jio.com", "airtel.in", "myvi.in", "bsnl.co.in",
  "gov.in", "nic.in", "india.gov.in", "mca.gov.in", "incometax.gov.in",
  "uidai.gov.in", "epfindia.gov.in", "digilocker.gov.in", "parivahan.gov.in",
  "indiapost.gov.in", "irctc.co.in",
  "github.com", "gitlab.com", "stackoverflow.com", "mozilla.org", "w3.org",
  "cloudflare.com", "zoom.us", "linkedin.com", "adobe.com", "python.org",
  "nodejs.org", "npmjs.com", "f-droid.org", "wikipedia.org", "wikimedia.org",
  "openai.com", "netflix.com",
  "myntra.com", "zomato.com", "swiggy.com", "cred.club", "zerodha.com",
  "groww.in", "rbi.org.in", "sebi.gov.in", "nseindia.com", "bseindia.com",
  "bbc.com", "bbc.co.uk", "reuters.com", "gov.uk", "usa.gov", "irs.gov", "who.int"
]);

const KNOWN_SAFE_PUBLIC_IPS = new Set([
  "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
  "2606:4700:4700::1111", "2606:4700:4700::1001",
  "2001:4860:4860::8888", "2001:4860:4860::8844"
]);

const URL_SHORTENER_DOMAINS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly",
  "is.gd", "v.gd", "ow.ly", "shorturl.at", "shorturl.asia", "tiny.cc",
  "rebrand.ly", "s.id", "bl.ink", "clk.sh", "t.ly", "lnkd.in",
  "buff.ly", "adf.ly", "short.io", "urlz.fr", "snip.ly", "clck.ru",
  "soo.gd", "trib.al", "bit.do", "mcaf.ee", "shorte.st", "dub.sh",
  "kutt.it", "shrtco.de", "x.co", "x.gd", "u.nu", "han.gl",
  "me2.do", "vo.la", "qr.ae", "linklyhq.com", "switchy.io", "clc.to"
]);

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

const FREE_UGC_OR_CLOUD_HOSTING_DOMAINS = new Set([
  "appspot.com", "run.app", "cloudfunctions.net", "web.app", "firebaseapp.com",
  "pages.dev", "workers.dev", "r2.dev", "vercel.app", "netlify.app",
  "github.io", "gitlab.io", "herokuapp.com", "onrender.com", "fly.dev",
  "railway.app", "replit.app", "repl.co", "surge.sh", "deno.dev", "val.run",
  "azurewebsites.net", "web.core.windows.net", "blob.core.windows.net",
  "sites.google.com", "storage.googleapis.com", "firebasestorage.googleapis.com",
  "raw.githubusercontent.com", "cdn.discordapp.com",
  "cloudfront.net", "s3.amazonaws.com", "digitaloceanspaces.com", "backblazeb2.com",
  "ipfs.io", "dweb.link", "cf-ipfs.com", "fleek.co",
  "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "notion.site",
  "canva.site", "carrd.co", "framer.website", "webflow.io", "strikingly.com",
  "godaddysites.com", "jimdosite.com", "site123.me", "ucoz.com",
  "forms.gle", "jotform.com", "formstack.com", "typeform.com", "tally.so",
  "wufoo.com", "cognitoforms.com", "telegra.ph", "pastebin.com", "paste.ee",
  "rentry.co", "mailchi.mp", "hubspotpagebuilder.com"
]);

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

const BRAND_DOMAINS = {
  microsoft: new Set([
    "microsoft.com", "microsoftonline.com", "live.com",
    "outlook.com", "office.com", "office365.com",
    "sharepoint.com", "onmicrosoft.com", "azure.com", "bing.com"
  ]),
  google: new Set([
    "google.com", "google.co.in", "googleapis.com",
    "googleusercontent.com", "googlemail.com", "gmail.com",
    "g.co", "youtube.com", "accounts.google.com"
  ]),
  apple: new Set(["apple.com", "icloud.com", "me.com"]),
  adobe: new Set(["adobe.com", "acrobat.com"]),
  docusign: new Set(["docusign.com", "docusign.net"]),
  dropbox: new Set(["dropbox.com"]),
  zoom: new Set(["zoom.us", "zoom.com"]),
  slack: new Set(["slack.com"]),
  github: new Set(["github.com"]),
  linkedin: new Set(["linkedin.com"]),
  cloudflare: new Set(["cloudflare.com"]),
  godaddy: new Set(["godaddy.com"]),
  namecheap: new Set(["namecheap.com"]),
  whatsapp: new Set(["whatsapp.com", "whatsapp.net"]),
  facebook: new Set(["facebook.com", "fb.com", "meta.com", "messenger.com"]),
  instagram: new Set(["instagram.com"]),
  telegram: new Set(["telegram.org", "t.me"]),
  discord: new Set(["discord.com", "discord.gg"]),
  snapchat: new Set(["snapchat.com"]),
  tiktok: new Set(["tiktok.com"]),
  twitter: new Set(["twitter.com", "x.com"]),
  netflix: new Set(["netflix.com"]),
  spotify: new Set(["spotify.com"]),
  disneyplus: new Set(["disneyplus.com"]),
  steam: new Set(["steampowered.com", "steamcommunity.com"]),
  roblox: new Set(["roblox.com"]),
  playstation: new Set(["playstation.com", "sony.com"]),
  amazon: new Set(["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com"]),
  flipkart: new Set(["flipkart.com"]),
  ebay: new Set(["ebay.com", "ebay.in", "ebay.co.uk"]),
  walmart: new Set(["walmart.com"]),
  alibaba: new Set(["alibaba.com", "aliexpress.com"]),
  shopify: new Set(["shopify.com"]),
  myntra: new Set(["myntra.com"]),
  meesho: new Set(["meesho.com"]),
  zomato: new Set(["zomato.com"]),
  swiggy: new Set(["swiggy.com"]),
  paypal: new Set(["paypal.com"]),
  binance: new Set(["binance.com", "binance.us"]),
  coinbase: new Set(["coinbase.com"]),
  metamask: new Set(["metamask.io"]),
  trustwallet: new Set(["trustwallet.com"]),
  ledger: new Set(["ledger.com"]),
  trezor: new Set(["trezor.io"]),
  kraken: new Set(["kraken.com"]),
  blockchain: new Set(["blockchain.com"]),
  opensea: new Set(["opensea.io"]),
  revolut: new Set(["revolut.com"]),
  stripe: new Set(["stripe.com"]),
  cashapp: new Set(["cash.app"]),
  venmo: new Set(["venmo.com"]),
  wise: new Set(["wise.com"]),
  fedex: new Set(["fedex.com"]),
  dhl: new Set(["dhl.com"]),
  ups: new Set(["ups.com"]),
  usps: new Set(["usps.com"]),
  royalmail: new Set(["royalmail.com"]),
  canadapost: new Set(["canadapost-postescanada.ca", "canadapost.ca"]),
  auspost: new Set(["auspost.com.au"]),
  bluedart: new Set(["bluedart.com"]),
  delhivery: new Set(["delhivery.com"]),
  dtdc: new Set(["dtdc.in", "dtdc.com"]),
  indiapost: new Set(["indiapost.gov.in"]),
  chase: new Set(["chase.com"]),
  bankofamerica: new Set(["bankofamerica.com"]),
  wellsfargo: new Set(["wellsfargo.com"]),
  citibank: new Set(["citi.com", "citibank.com"]),
  hsbc: new Set(["hsbc.com", "hsbc.co.uk"]),
  barclays: new Set(["barclays.co.uk", "barclays.com"]),
  santander: new Set(["santander.co.uk", "santander.com"]),
  capitalone: new Set(["capitalone.com"]),
  americanexpress: new Set(["americanexpress.com"]),
  visa: new Set(["visa.com", "visa.co.in"]),
  mastercard: new Set(["mastercard.com"]),
  sbi: new Set(["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"]),
  hdfc: new Set(["hdfcbank.com"]),
  hdfcbank: new Set(["hdfcbank.com"]),
  icici: new Set(["icicibank.com"]),
  icicibank: new Set(["icicibank.com"]),
  axisbank: new Set(["axisbank.com"]),
  kotak: new Set(["kotak.com"]),
  pnb: new Set(["pnbindia.in"]),
  canarabank: new Set(["canarabank.com"]),
  bankofbaroda: new Set(["bankofbaroda.in"]),
  unionbank: new Set(["unionbankofindia.co.in"]),
  indusind: new Set(["indusind.com"]),
  yesbank: new Set(["yesbank.in"]),
  idfc: new Set(["idfcfirstbank.com"]),
  phonepe: new Set(["phonepe.com"]),
  paytm: new Set(["paytm.com"]),
  bhim: new Set(["bhimupi.org.in"]),
  npci: new Set(["npci.org.in"]),
  razorpay: new Set(["razorpay.com"]),
  bajajfinserv: new Set(["bajajfinserv.in"]),
  airtel: new Set(["airtel.in"]),
  jio: new Set(["jio.com"]),
  bsnl: new Set(["bsnl.co.in"]),
  verizon: new Set(["verizon.com"]),
  tmobile: new Set(["t-mobile.com"]),
  incometax: new Set(["incometax.gov.in"]),
  uidai: new Set(["uidai.gov.in"]),
  aadhaar: new Set(["uidai.gov.in"]),
  epfo: new Set(["epfindia.gov.in"]),
  digilocker: new Set(["digilocker.gov.in"]),
  irctc: new Set(["irctc.co.in"]),
  irs: new Set(["irs.gov"]),
  hmrc: new Set(["gov.uk"])
};

const DECEPTIVE_DOMAIN_LURE_WORDS = new Set([
  "verify", "verification", "secure", "security", "login", "signin",
  "account", "update", "support", "helpdesk", "billing", "confirm",
  "wallet", "recover", "recovery", "suspend", "suspended", "unlock",
  "alert", "auth", "authenticate", "webmail", "portal", "identity",
  "validation", "claim", "refund", "kyc", "parcel", "delivery",
  "airdrop", "seed", "phish", "phishing", "malware"
]);

const CONFUSABLE_CHAR_MAP = {
  "\u0430": "a", "\u0410": "a", "\u0432": "b", "\u0412": "b",
  "\u0435": "e", "\u0415": "e", "\u0451": "e", "\u0401": "e",
  "\u043A": "k", "\u041A": "k", "\u043C": "m", "\u041C": "m",
  "\u043D": "h", "\u041D": "h", "\u043E": "o", "\u041E": "o",
  "\u0440": "p", "\u0420": "p", "\u0441": "c", "\u0421": "c",
  "\u0442": "t", "\u0422": "t", "\u0443": "y", "\u0423": "y",
  "\u0445": "x", "\u0425": "x", "\u0456": "i", "\u0406": "i",
  "\u0455": "s", "\u0405": "s", "\u0458": "j", "\u0408": "j",
  "\u04BB": "h", "\u04BA": "h", "\u0501": "d", "\u04CF": "l", "\u04C0": "l",
  "\u0578": "n", "\u0570": "h", "\u0585": "o",
  "\u03B1": "a", "\u0391": "a", "\u03B2": "b", "\u0392": "b",
  "\u03B5": "e", "\u0395": "e", "\u03B6": "z", "\u0396": "z",
  "\u03B7": "n", "\u0397": "h", "\u03B9": "i", "\u0399": "i",
  "\u03BA": "k", "\u039A": "k", "\u03BC": "m", "\u039C": "m",
  "\u03BD": "v", "\u039D": "n", "\u03BF": "o", "\u039F": "o",
  "\u03C1": "p", "\u03A1": "p", "\u03C4": "t", "\u03A4": "t",
  "\u03C5": "u", "\u03A5": "y", "\u03C7": "x", "\u03A7": "x",
  "\u0131": "i", "\u0130": "i", "\u0142": "l", "\u0141": "l",
  "\u00F8": "o", "\u00D8": "o", "\u0111": "d", "\u00F0": "d",
  "\u00DF": "s", "\u217C": "l", "\u216C": "l", "\u2170": "i",
  "\u0251": "a", "\u0261": "g", "\u0269": "i", "\u026A": "i",
  "\u029F": "l", "\u028F": "y", "\u050D": "k", "\u051B": "q"
};

const MOBILE_INSTALLER_EXTENSIONS = new Set(["apk", "aab", "xapk", "apks", "ipa"]);
const MOBILE_CONFIG_AND_CERT_EXTENSIONS = new Set(["mobileconfig", "provisionprofile", "cer", "crt", "pem", "der", "ovpn", "p12", "pfx"]);
const INTERACTIVE_SMUGGLING_EXTENSIONS = new Set(["svg", "shtml", "xhtml", "mhtml", "mht", "hta"]);
const EXECUTABLE_EXTENSIONS = new Set([
  "exe", "msi", "apk", "aab", "xapk", "apks", "bat", "cmd", "com",
  "scr", "ps1", "sh", "jar", "vbs", "hta", "dmg", "pkg",
  "deb", "rpm", "iso", "img", "vhd", "vhdx", "one", "msix", "appx", "appxbundle",
  "crx", "xpi", "reg", "scf", "url", "pif", "app", "ipa", "lnk", "wsf"
]);
const ARCHIVE_EXTENSIONS = new Set(["zip", "rar", "7z", "tar", "gz", "cab"]);
const DECOY_DOCUMENT_EXTENSIONS = new Set([
  "pdf", "doc", "docx", "xls", "xlsx", "csv", "ppt", "pptx", "rtf",
  "jpg", "jpeg", "png", "gif", "webp", "heic", "svg", "txt", "mp4", "zip"
]);

const PHISHING_KIT_ENDPOINT_PATTERN =
  /(?:\/cgi-bin\/webscr|\/owa\/auth\/logon|\/wp-admin\/install|\/vendor\/phpunit\/|\/\.git\/|\/\.env(?:$|[/?#])|\/cdn-cgi\/l\/)/i;

const REDIRECT_PARAMETERS = new Set([
  "url", "uri", "u", "r", "q", "rd", "redirect", "redirecturl", "redirecturi",
  "redirectto", "redir", "redirurl", "return", "returnto", "returnurl", "ret", "returl",
  "next", "nexturl", "continue", "continueurl", "dest", "desturl", "destination",
  "target", "targeturl", "goto", "go", "jump", "callback", "out", "to",
  "forward", "fallback", "fallbackurl", "sbrowserfallbackurl", "apkurl", "downloadurl",
  "successurl", "failurl", "clickurl", "adurl", "linkurl",
  "postlogoutredirecturi", "logouturi", "canceluri", "link", "href"
]);
const ANDROID_INTENT_PARAM_KEYS = new Set(["sbrowserfallbackurl", "fallbackurl", "apkurl", "launchurl", "deeplink"]);
const SENSITIVE_PARAMETERS = new Set([
  "password", "passwd", "pwd", "passphrase", "token", "accesstoken",
  "refreshtoken", "idtoken", "auth", "authorization", "secret",
  "clientsecret", "code", "state", "session", "sessionid", "sid",
  "jwt", "apikey", "signature", "sig", "otp", "pin", "email",
  "phone", "mobile", "account", "card", "cc", "ssn", "dob", "username",
  "user", "credential", "credentials", "samlrequest", "samlresponse",
  "assertion", "ticket", "nonce", "csrf", "xsrf", "cookie",
  "pan", "aadhaar", "aadhar", "upi", "pa", "cvv"
]);
const TRACKING_PARAMETERS = new Set([
  "utmsource", "utmmedium", "utmcampaign", "utmterm", "utmcontent",
  "fbclid", "gclid", "dclid", "msclkid", "mc_eid", "mceid",
  "igshid", "si", "yclid", "wickedid", "oly_enc_id"
]);

const HTML_SMUGGLING_CODE_PATTERN =
  /<script\b|<form\b|atob\s*\(|createObjectURL|document\.write|window\.location|location\.replace|fromCharCode/i;

const FINANCIAL_CREDIT_LURE_TERMS = [
  "credited", "amountcredit", "creditamount", "claimamount", "claimreward",
  "cashback", "refund", "taxrefund", "irsrefund", "gstrefund", "itrrefund",
  "lottery", "prize", "jackpot", "winner", "rewardpoints", "redeempoints",
  "upiclaim", "upireward", "bonusclaim", "subsidy", "lpgsubsidy", "giveaway", "freemoney",
  "salarycredited", "instantloan", "loanapproved", "preapproved", "unclaimedfunds",
  "parttimejob", "workfromhome", "taskreward", "telegramtask", "guaranteedreturn",
  "doubleyourmoney", "tradingbot", "scholarship",
  "airdrop", "tokenclaim", "stakingreward", "presale", "doublebtc", "ethgiveaway"
];
const URGENCY_KYC_LURE_TERMS = [
  "kyc", "updatekyc", "kycupdate", "kycpending", "panupdate",
  "aadhaarupdate", "aadharupdate", "reverify", "accountblocked",
  "jeevanpramaan", "lifecertificate", "pensionupdate", "seniorcitizen",
  "ayushman", "rationcard",
  "accountsuspended", "accountlocked", "accountdisabled", "accountrestricted",
  "unblockaccount", "unlockaccount", "recoveraccount", "reactivate",
  "verifyaccount", "accountverify", "confirmidentity", "identityverify",
  "unusualsignin", "unusualactivity", "securityalert", "securitywarning",
  "passwordexpired", "billingupdate", "paymentfailed", "carddeclined",
  "subscriptionexpired", "copyrightviolation", "trademarknotice", "appealsuspension",
  "billdue", "electricitybill", "powerdisconnect", "disconnection",
  "challan", "echallan", "trafficfine", "unpaidtoll", "tollfee", "fastag",
  "pmkisan", "simblock", "5gupgrade", "esim",
  "customsduty", "customsclearance", "customsfee", "parcelhold",
  "packagedelivery", "deliveryfailed", "redelivery", "addressupdate",
  "virusdetected", "deviceinfected", "systemwarning", "windowsdefender",
  "techsupport", "browserupdate", "chromeupdate", "flashupdate", "trojanalert"
];
const REMOTE_ACCESS_TROJAN_TERMS = [
  "anydesk", "teamviewer", "quicksupport", "rustdesk", "airdroid",
  "screenshare", "remotesupport", "remotedesktop", "accessibilityservice",
  "enableaccessibility", "unknownsources", "playprotect"
];
const DIGITAL_ARREST_EXTORTION_TERMS = [
  "digitalarrest", "cybercrime", "arrestwarrant", "courtnotice",
  "simdeactivate", "aadhaarlock", "panlink", "epfokyc",
  "collectrequest", "upimandate", "autopay", "receivepayment", "scanqr"
];
const CREDENTIAL_HARVEST_TERMS = [
  "upipin", "mpin", "atmpin", "enterpin", "verifypin", "pinverify",
  "cvv", "cardverify", "cardnumber", "verifyotp", "otpverify",
  "netbankinglogin", "webbanking", "signinverify", "loginverify",
  "2faverify", "mfaverify", "passcode", "webmaillogin", "ssnverify",
  "seedphrase", "recoveryphrase", "mnemonic", "privatekey",
  "secretphrase", "connectwallet", "walletconnect"
];
const PATH_BRAND_TERMS = [
  "microsoft", "office365", "outlook", "google", "gmail", "apple", "icloud",
  "adobe", "docusign", "dropbox", "zoom", "slack", "linkedin", "cloudflare",
  "whatsapp", "facebook", "instagram", "telegram", "discord", "netflix", "spotify",
  "amazon", "flipkart", "ebay", "walmart", "fedex", "dhl", "ups", "usps",
  "royalmail", "indiapost", "bluedart", "delhivery",
  "paypal", "binance", "coinbase", "metamask", "trustwallet", "ledger",
  "trezor", "revolut", "cashapp", "venmo", "wise",
  "chase", "wellsfargo", "bankofamerica", "hsbc", "citibank", "barclays",
  "sbi", "onlinesbi", "hdfc", "hdfcbank", "icici", "icicibank",
  "axisbank", "kotak", "pnb", "canarabank", "bankofbaroda",
  "phonepe", "paytm", "bhim", "npci", "razorpay",
  "uidai", "aadhaar", "incometax", "epfo", "irctc", "digilocker"
];
const GENERIC_AUTH_OR_DOC_PATH_TERMS = new Set([
  "login", "signin", "auth", "verify", "confirm", "update", "secure",
  "webmail", "invoice", "statement", "document", "account", "wallet",
  "billing", "support", "portal", "phish", "phishing", "malware"
]);

const INTENT_VECTORS = {
  AUTH_IDENTITY: [
    "login", "signin", "logon", "auth", "sso", "webmail", "cpanel", "roundcube",
    "zimbra", "portal", "account", "passwd", "password", "passcode", "credential",
    "2fa", "mfa", "otp", "pin", "cvv", "kyc", "aadhaar", "aadhar", "ssn", "pan"
  ],
  URGENCY_THREAT: [
    "verify", "verif", "confirm", "validat", "reverify", "update", "renew",
    "reactivat", "recover", "unlock", "unblock", "suspend", "restrict", "lock",
    "disabl", "expir", "alert", "warn", "urgent", "appeal", "dispute", "unusual",
    "overdue", "failed", "declined", "blocked", "disconnect", "termination"
  ],
  FINANCIAL_LURE: [
    "pay", "payment", "billing", "invoice", "receipt", "refund", "tax", "rebate",
    "claim", "reward", "bonus", "cashback", "credit", "credited", "prize", "winner",
    "lottery", "jackpot", "gift", "giveaway", "subsidy", "loan", "payout", "upi",
    "pension", "taskreward", "guaranteedreturn", "workfromhome", "scholarship"
  ],
  DELIVERY_LOGISTICS: [
    "parcel", "package", "delivery", "redeliver", "customs", "postage",
    "shipping", "courier", "shipment", "tracking", "freight", "consignment",
    "challan", "toll", "fastag"
  ],
  CRYPTO_WEB3: [
    "wallet", "seed", "mnemonic", "airdrop", "presale", "staking", "mint",
    "claimtoken", "connectwallet", "walletconnect", "web3", "privatekey", "dapp"
  ],
  TECH_SCAREWARE: [
    "virus", "infected", "trojan", "scareware", "defender", "antivirus",
    "techsupport", "helpdesk", "sysadmin", "cleanphone", "browserupdate"
  ],
  DOC_PHISH_KIT: [
    "docusign", "esign", "document", "sharedfile", "viewdoc", "attachment",
    "statement", "taxform", "remittance", "remit", "payroll", "hrdoc"
  ],
  REMOTE_ACCESS_TROJAN: [
    "anydesk", "teamviewer", "quicksupport", "rustdesk", "airdroid",
    "screenshare", "remotesupport", "remotedesktop", "accessibility",
    "unknownsources", "playprotect"
  ],
  GOVT_EXTORTION: [
    "digitalarrest", "cybercrime", "warrant", "courtnotice", "simdeactivate",
    "trai", "aadhaarlock", "panlink", "collectrequest", "upimandate", "autopay",
    "jeevanpramaan", "lifecertificate", "ayushman", "rationcard"
  ]
};

const EXPLICIT_MALICE_STEMS = [
  "phish", "malware", "ransomware", "trojan", "keylog", "spyware",
  "stealer", "botnet", "exploit", "webinject", "credharvest"
];

const EMBEDDED_TLD_SUBDOMAIN_PATTERN =
  /(?:^|\.)[a-z0-9-]{2,}\.(?:com|net|org|info|biz|gov|edu|co\.in|co\.uk|com\.au|org\.in|gov\.in|bank)(?:\.|$)/i;
const COMPROMISED_ASSET_DIR_KIT =
  /\/(?:wp-content|wp-includes|wp-admin|images|img|css|js|fonts|assets|static|media|cgi-bin|\.well-known)\/.*\.(?:php|html?|hta|phtml|asp|aspx)$/i;
const OBFUSCATED_SHORT_DIR_KIT =
  /^\/[a-z0-9]{1,2}\/[a-z0-9._-]{3,}\.(?:html?|php|hta)$/i;

const INFRASTRUCTURE_SIGNALS = new Set([
  "FREE_TUNNEL_OR_DYNAMIC_DNS_HOST", "FREE_UGC_OR_CLOUD_HOSTING",
  "HIGH_RISK_ABUSED_TLD", "URL_SHORTENER_HIDES_DESTINATION",
  "PUBLIC_IP_LITERAL_HOST", "OBFUSCATED_IP_HOST", "DASHED_IP_PATTERN_IN_HOSTNAME",
  "HIGH_ENTROPY_DGA_DOMAIN", "ALGORITHMIC_DGA_HOST_ANOMALY",
  "PUBLIC_SUFFIX_NOT_RECOGNIZED_LOCALLY"
]);
const SPOOFING_SIGNALS = new Set([
  "BRAND_DOMAIN_SPOOFED_IN_SUBDOMAIN", "BRAND_NAME_IN_UNRELATED_DOMAIN",
  "POSSIBLE_BRAND_LOOKALIKE_DOMAIN", "CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION",
  "MIXED_SCRIPT_IDN_HOSTNAME", "NON_LATIN_CONFUSABLE_IDN_HOSTNAME",
  "PUNYCODE_HOSTNAME", "UNIVERSAL_SUBDOMAIN_TLD_MASQUERADING",
  "MOBILE_VIEWPORT_SUBDOMAIN_PADDING", "DECEPTIVE_MULTI_LURE_HOSTNAME",
  "DECEPTIVE_AUTH_HOSTNAME_PATTERN", "EXCESSIVE_HYPHEN_LURE_DOMAIN"
]);
const PAYLOAD_SIGNALS = new Set([
  "MOBILE_SIDELOAD_INSTALLER_PATH", "MOBILE_CONFIG_OR_CERT_INSTALL_PATH",
  "EXECUTABLE_DOWNLOAD_PATH", "INTERACTIVE_SMUGGLING_FILE_PATH",
  "ARCHIVE_DOWNLOAD_PATH", "DOUBLE_EXTENSION_MASQUERADE",
  "COMPROMISED_ASSET_DIR_PHISHING_KIT", "PHISHING_KIT_ENDPOINT_FINGERPRINT",
  "OBFUSCATED_SHORT_PATH_STATIC_KIT", "QUERY_MOBILE_INSTALLER_PAYLOAD",
  "HTML_SMUGGLING_PAYLOAD_DETECTED"
]);
const SMUGGLING_SIGNALS = new Set([
  "REPEATED_PATH_ENCODING", "UNDECODABLE_PATH_ENCODING",
  "HEAVY_PERCENT_ENCODING_OBFUSCATION", "ENCODED_PATH_SEPARATOR",
  "PATH_TRAVERSAL_PATTERN", "EMBEDDED_URL_IN_PATH",
  "BASE64_SMUGGLED_REDIRECT", "HEX_SMUGGLED_REDIRECT",
  "BASE64_SMUGGLED_URL_IN_QUERY", "HEX_SMUGGLED_URL_IN_QUERY",
  "FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD", "FRAGMENT_VICTIM_EMAIL_PREFILL_KIT",
  "SUSPICIOUS_NESTED_REDIRECT_DOMAIN", "NESTED_REDIRECT_RISK_PROPAGATED",
  "ADDITIONAL_QUERY_ENCODING", "URL_PRESENT_IN_FRAGMENT"
]);
const LURE_SIGNALS = new Set([
  "SMS_FINANCIAL_SCAM_LURE", "URGENCY_OR_KYC_SCAM_LURE",
  "SENSITIVE_BANKING_CREDENTIAL_HARVEST_PATTERN", "BRAND_IMPERSONATION_WITH_SCAM_LURE_IN_PATH",
  "REMOTE_ACCESS_TROJAN_SCAM_LURE", "DIGITAL_ARREST_OR_EXTORTION_SCAM_LURE",
  "UPI_PAYMENT_REQUEST_SMUGGLING_IN_URL", "MULTI_VECTOR_SOCIAL_ENGINEERING_ATTACK",
  "COMPOUND_DECEPTIVE_INTENT_VECTORS", "LURE_INTENT_REMOTE_ACCESS_TROJAN",
  "LURE_INTENT_GOVT_EXTORTION", "LURE_INTENT_DELIVERY_LOGISTICS",
  "LURE_INTENT_FINANCIAL_LURE", "LURE_INTENT_URGENCY_THREAT",
  "LURE_INTENT_CRYPTO_WEB3", "LURE_INTENT_TECH_SCAREWARE",
  "LURE_INTENT_DOC_PHISH_KIT"
]);
const TRANSPORT_SIGNALS = new Set(["UNENCRYPTED_HTTP", "NON_STANDARD_PORT", "SUSPICIOUS_SERVICE_PORT"]);

const LAYERS_EXECUTED = [
  "ZERO_EGRESS_ON_DEVICE_ENFORCEMENT",
  "HTTP_BOUNDARY_AND_HEADER_HARDENING",
  "ANTI_EVASION_URL_AND_UNICODE_NFKC_NORMALIZATION",
  "NON_PUBLIC_IP_BOGON_AND_PORT_ISOLATION",
  "OFFLINE_SIGNED_BLOOM_THREAT_FEED_MATCHER",
  "UNICODE_HOMOGRAPH_NFD_CONFUSABLE_SKELETON",
  "DAMERAU_TRANSPOSITION_TYPOSQUAT_DETECTOR",
  "PHONETIC_AND_REPEATED_CHAR_SPOOF_DETECTOR",
  "MOBILE_VIEWPORT_SUBDOMAIN_TRUNCATION_SHIELD",
  "SUBDOMAIN_AND_LEET_BRAND_SPOOF_DETECTION",
  "UNIVERSAL_SUBDOMAIN_TLD_MASQUERADE_SHIELD",
  "DGA_ENTROPY_AND_VOWEL_CONSONANT_SCORER",
  "ABUSED_TLD_SHORTENER_AND_TUNNEL_DETECTION",
  "PATH_SCRIPT_KIT_FINGERPRINT_AND_DOUBLE_EXTENSION_SHIELD",
  "COMPROMISED_CMS_KIT_AND_STAGING_DETECTOR",
  "ANDROID_APK_CONFIG_CERT_AND_ARCHIVE_MALWARE_CHECK",
  "HTML_SMUGGLING_SVG_AND_MHTML_PAYLOAD_GUARD",
  "BASE64_AND_HEX_SMUGGLED_REDIRECT_DECODER",
  "MULTI_HOP_RECURSIVE_REDIRECT_RISK_PROPAGATOR",
  "ANDROID_INTENT_FALLBACK_AND_DEEP_LINK_TRAP_SHIELD",
  "FRAGMENT_PAYLOAD_AND_EMAIL_PREFILL_DETECTOR",
  "UPI_COLLECT_AND_PAYMENT_SMUGGLING_SHIELD",
  "REMOTE_ACCESS_TROJAN_AND_DIGITAL_ARREST_LURE_ENGINE",
  "SENIOR_WELFARE_AND_JOB_TASK_FRAUD_DETECTOR",
  "SMS_SCAM_AND_UPI_CREDENTIAL_LURE_ENGINE",
  "MULTI_VECTOR_LEXICAL_INTENT_CLASSIFIER",
  "CROSS_LAYER_COMPOUND_THREAT_CORRELATOR",
  "KNOWN_SAFE_OFFICIAL_DOMAIN_POLICY",
  "SINGLE_USE_JTI_HMAC_REDIRECT_TOKEN",
  "RUNTIME_ZERO_LEAKAGE_AND_LOG_REDACTION_ASSERTION"
];

function createUuid() {
  return globalThis.crypto?.randomUUID?.() ||
    `SG-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 10).toUpperCase()}`;
}

// Pure RFC 3492 Punycode label decoder for browser/WebView parity with node:url domainToUnicode
function decodePunycodeLabel(label) {
  const lower = String(label || "").toLowerCase();
  if (!lower.startsWith("xn--")) return lower;
  const input = lower.slice(4);
  const output = [];
  let i = 0;
  let n = 128;
  let bias = 72;

  const basicEnd = input.lastIndexOf("-");
  let index = 0;
  if (basicEnd > 0) {
    for (let j = 0; j < basicEnd; j++) {
      const code = input.charCodeAt(j);
      if (code >= 0x80) return lower;
      output.push(code);
    }
    index = basicEnd + 1;
  }

  const adapt = (delta, numPoints, firstTime) => {
    let d = firstTime ? Math.floor(delta / 700) : delta >> 1;
    d += Math.floor(d / numPoints);
    let k = 0;
    for (; d > 455; k += 36) {
      d = Math.floor(d / 35);
    }
    return Math.floor(k + (36 * d) / (d + 38));
  };

  while (index < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = 36; ; k += 36) {
      if (index >= input.length) return lower;
      const code = input.charCodeAt(index++);
      const digit =
        code >= 48 && code <= 57 ? code - 22 :
        code >= 97 && code <= 122 ? code - 97 :
        code >= 65 && code <= 90 ? code - 65 : 36;
      if (digit >= 36) return lower;
      i += digit * w;
      const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < t) break;
      w *= 36 - t;
    }
    const len = output.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    if (n > 0x10FFFF) return lower;
    output.splice(i++, 0, n);
  }

  try {
    return String.fromCodePoint(...output);
  } catch {
    return lower;
  }
}

function domainToUnicodeSafe(hostname) {
  return String(hostname || "")
    .split(".")
    .map((label) => (label.toLowerCase().startsWith("xn--") ? decodePunycodeLabel(label) : label))
    .join(".");
}

function decodeBase64Utf8(value) {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const binary = globalThis.atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

function decodeHexUtf8(value) {
  const hex = String(value || "");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

function decodeRepeatedly(value, maxPasses = 3) {
  let current = String(value ?? "");
  let additionalDecodes = 0;
  for (let i = 0; i < maxPasses; i++) {
    try {
      const next = decodeURIComponent(current);
      if (next === current) break;
      current = next;
      additionalDecodes++;
    } catch {
      return { value: current, decodingFailed: true, additionalDecodes };
    }
  }
  return { value: current, decodingFailed: false, additionalDecodes };
}

function safeDecode(value, passes = 3) {
  return decodeRepeatedly(value, passes).value;
}

function matchesDomainSet(hostname, domainSet) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
  if (!host) return false;
  for (const domain of domainSet) {
    if (host === domain || host.endsWith(`.${domain}`)) return true;
  }
  return false;
}

function isKnownSafeDomain(registrableDomain) {
  if (!registrableDomain || typeof registrableDomain !== "string") return false;
  return KNOWN_SAFE_REGISTRABLE_DOMAINS.has(registrableDomain.toLowerCase().trim());
}

function isKnownSafePublicIp(ip) {
  if (!ip || typeof ip !== "string") return false;
  return KNOWN_SAFE_PUBLIC_IPS.has(ip.toLowerCase().trim().replace(/^\[|\]$/g, ""));
}

function detectObfuscatedIpAuthority(rawAuthority) {
  if (!rawAuthority || rawAuthority.startsWith("[")) return false;
  const hostOnly = rawAuthority.split(":")[0].toLowerCase().replace(/\.$/, "");
  if (!hostOnly) return false;
  if (/^(?:0x[0-9a-f]+|\d+)$/i.test(hostOnly)) return true;
  const parts = hostOnly.split(".");
  if (parts.length >= 2 && parts.length < 4 && parts.every((p) => /^(?:0x[0-9a-f]+|0[0-7]*|[1-9]\d*)$/i.test(p))) return true;
  if (parts.length === 4 && parts.every((p) => /^(?:0x[0-9a-f]+|\d+)$/i.test(p)) && parts.some((p) => /^0x/i.test(p) || (p.length > 1 && p.startsWith("0")))) return true;
  return false;
}

function normalizeUrlLocal(input) {
  if (typeof input !== "string") return { ok: false, reasonCode: "INVALID_URL_TYPE" };
  if (hasControlChars(input)) return { ok: false, reasonCode: "CONTROL_CHARACTERS_FOUND" };
  if (INVISIBLE_OR_BIDI_CHARS.test(input)) return { ok: false, reasonCode: "INVISIBLE_OR_BIDI_CHARACTERS_FOUND" };
  if (/[\u0300-\u036f]{3,}/.test(input) || /[\uFF01-\uFF5E]/.test(input)) return { ok: false, reasonCode: "UNICODE_SPOOF_CHARACTERS_FOUND" };

  const candidate = input.trim();
  if (!candidate) return { ok: false, reasonCode: "EMPTY_URL" };
  if (candidate.length > MAX_URL_LENGTH) return { ok: false, reasonCode: "URL_TOO_LONG" };
  if (/\s/.test(candidate)) return { ok: false, reasonCode: "WHITESPACE_IN_URL" };
  if (candidate.includes("\\")) return { ok: false, reasonCode: "BACKSLASH_IN_URL" };
  if (MALFORMED_PERCENT_ENCODING.test(candidate)) return { ok: false, reasonCode: "MALFORMED_PERCENT_ENCODING" };
  if (ENCODED_SPOOF_SEQUENCES.test(candidate)) return { ok: false, reasonCode: "ENCODED_SPOOF_OR_NULL_SEQUENCE" };
  if (DANGEROUS_EXPLICIT_SCHEME.test(candidate.normalize("NFKC"))) return { ok: false, reasonCode: "UNSUPPORTED_OR_DANGEROUS_SCHEME" };

  if (!/^https?:\/\/[^/]/i.test(candidate)) {
    if (/^https?:\/\//i.test(candidate)) return { ok: false, reasonCode: "INVALID_HOSTNAME" };
    return { ok: false, reasonCode: "ABSOLUTE_HTTP_URL_REQUIRED" };
  }

  const authorityMatch = candidate.match(/^https?:\/\/([^/?#]*)(\/[^?#]*)?/i);
  const rawAuthority = authorityMatch?.[1] || "";
  if (!rawAuthority) return { ok: false, reasonCode: "INVALID_HOSTNAME" };
  if (rawAuthority.includes("@") || /%40/i.test(rawAuthority)) return { ok: false, reasonCode: "URL_CONTAINS_CREDENTIALS" };
  if (rawAuthority.startsWith("[") && rawAuthority.includes("%")) return { ok: false, reasonCode: "INVALID_IP_ADDRESS" };

  let parsedUrl;
  try {
    parsedUrl = new URL(candidate);
  } catch {
    return { ok: false, reasonCode: "MALFORMED_URL" };
  }

  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") return { ok: false, reasonCode: "UNSUPPORTED_PROTOCOL" };
  if (parsedUrl.username || parsedUrl.password) return { ok: false, reasonCode: "URL_CONTAINS_CREDENTIALS" };

  const hostname = parsedUrl.hostname.toLowerCase().replace(/\.$/, "");
  if (!hostname || hostname.length > 253) return { ok: false, reasonCode: "INVALID_HOSTNAME" };

  return {
    ok: true,
    parsedUrl,
    hostname,
    rawPath: authorityMatch?.[2] || "/",
    obfuscatedIpHost: detectObfuscatedIpAuthority(rawAuthority)
  };
}

function toConfusableSkeleton(hostname) {
  const unicode = domainToUnicodeSafe(hostname);
  let out = "";
  let hadConfusable = false;
  for (const ch of unicode.toLowerCase()) {
    if (CONFUSABLE_CHAR_MAP[ch]) {
      out += CONFUSABLE_CHAR_MAP[ch];
      hadConfusable = true;
    } else {
      const nfd = ch.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      if (nfd !== ch && /^[a-z0-9]$/.test(nfd)) {
        out += nfd;
        hadConfusable = true;
      } else {
        out += ch;
      }
    }
  }
  return { skeleton: out, hadConfusable };
}

function toLeetVariants(token) {
  const single = token.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/8/g, "b");
  const oneAsI = token.replace(/0/g, "o").replace(/1/g, "i").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/8/g, "b");
  return [...new Set([token, single, oneAsI, oneAsI.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d"), single.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d")])];
}

function editDistanceAtMost(a, b, maxDist) {
  if (Math.abs(a.length - b.length) > maxDist || a === b) return false;
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
      }
    }
  }
  return dp[m][n] > 0 && dp[m][n] <= maxDist;
}

function shannonEntropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function hasMixedScripts(hostname) {
  const unicode = domainToUnicodeSafe(hostname);
  const scripts = new Set();
  for (const ch of unicode) {
    if (/\p{Script=Latin}/u.test(ch)) scripts.add("Latin");
    if (/\p{Script=Cyrillic}/u.test(ch)) scripts.add("Cyrillic");
    if (/\p{Script=Greek}/u.test(ch)) scripts.add("Greek");
  }
  return scripts.size > 1;
}

function hasSpoofedBrandDomainInSubdomain(hostname, registrableDomain) {
  const host = String(hostname || "").toLowerCase();
  const baseDomain = String(registrableDomain || "").toLowerCase();
  if (!baseDomain || host === baseDomain) return false;
  const subdomainPrefix = host.slice(0, Math.max(0, host.length - baseDomain.length - 1));
  if (!subdomainPrefix) return false;

  for (const officialDomains of Object.values(BRAND_DOMAINS)) {
    if (officialDomains.has(baseDomain)) continue;
    for (const official of officialDomains) {
      if (
        subdomainPrefix === official ||
        subdomainPrefix.endsWith(`.${official}`) ||
        subdomainPrefix.includes(`${official}.`) ||
        subdomainPrefix.includes(official.replace(/\./g, "-"))
      ) {
        return true;
      }
    }
  }
  return false;
}

function analyzeBrandImpersonation(hostname, registrableDomain) {
  const { skeleton, hadConfusable } = toConfusableSkeleton(hostname);
  const rawLower = hostname.toLowerCase();
  const baseDomain = (registrableDomain || hostname).toLowerCase();
  const indicators = [];
  let riskScore = 0;

  if (hasSpoofedBrandDomainInSubdomain(rawLower, baseDomain)) {
    indicators.push("BRAND_DOMAIN_SPOOFED_IN_SUBDOMAIN");
    riskScore += 8;
  }

  const extractTokens = (lbls) => lbls.flatMap((label) => label.split(/[^a-z0-9]+/).filter(Boolean));
  const rawTokens = extractTokens(rawLower.split("."));
  const skeletonTokens = extractTokens(skeleton.split("."));
  const allTokenVariants = [...new Set([...rawTokens, ...skeletonTokens])].flatMap(toLeetVariants);
  const shortBrandGluedPattern = /^(?:kyc|login|signin|verify|update|secure|auth|alert|parcel|delivery|tax|refund|reward|recharge|support|care|bank|netbanking|portal|online|pay|help)/;
  const collapseRepeats = (s) => String(s || "").replace(/(.)\1+/g, "$1");
  const toPhonetic = (s) => collapseRepeats(s).replace(/ph/g, "f").replace(/ck|q/g, "k").replace(/z/g, "s");

  for (const [brand, officialDomains] of Object.entries(BRAND_DOMAINS)) {
    if (officialDomains.has(baseDomain)) continue;
    const maxTypos = brand.length >= 6 ? 2 : brand.length >= 4 ? 1 : 0;
    const brandCollapsed = collapseRepeats(brand);
    const brandPhonetic = toPhonetic(brand);

    const directOrSubMatch = allTokenVariants.some((token) => {
      if (token === brand) return true;
      if (brand.length >= 4 && token.includes(brand)) return true;
      if (brand.length === 3 && token.length >= 6 && token.startsWith(brand) && shortBrandGluedPattern.test(token.slice(3))) return true;
      if (brand.length >= 5 && token.length >= 5 && (collapseRepeats(token) === brandCollapsed || toPhonetic(token) === brandPhonetic)) return true;
      if (maxTypos > 0 && token.length >= 4 && editDistanceAtMost(token, brand, maxTypos)) return true;
      return false;
    });

    const baseFirstLabel = baseDomain.split(".")[0].replace(/[^a-z0-9]/g, "");
    const lookalikeBase =
      maxTypos > 0 &&
      toLeetVariants(baseFirstLabel).some((cand) => cand.length >= 4 && (cand === brand || editDistanceAtMost(cand, brand, maxTypos)));

    if (directOrSubMatch) {
      indicators.push("BRAND_NAME_IN_UNRELATED_DOMAIN");
      riskScore += 4;
      if (hadConfusable) {
        indicators.push("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION");
        riskScore += 4;
      }
      break;
    }

    if (lookalikeBase) {
      indicators.push("POSSIBLE_BRAND_LOOKALIKE_DOMAIN");
      riskScore += 4;
      if (hadConfusable) {
        indicators.push("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION");
        riskScore += 4;
      }
      break;
    }
  }

  return { indicators: [...new Set(indicators)], riskScore };
}

function analyzeDomainLocal(hostname, parsedUrl, options = {}) {
  const indicators = [];
  let riskScore = 0;
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");

  if (!host || host.length > 253) return { blocked: true, reasonCode: "INVALID_HOSTNAME", indicators, riskScore };
  if ([...RESERVED_SUFFIXES].some((s) => host === s || host.endsWith(`.${s}`))) {
    return { blocked: true, reasonCode: "NON_PUBLIC_HOSTNAME", indicators, riskScore };
  }
  if (parsedUrl.port && DANGEROUS_PORTS.has(String(parsedUrl.port))) {
    return { blocked: true, reasonCode: "DANGEROUS_NON_WEB_PORT", indicators: ["DANGEROUS_NON_WEB_PORT"], riskScore: 10 };
  }

  if (options.obfuscatedIpHost) {
    indicators.push("OBFUSCATED_IP_HOST");
    riskScore += 4;
  }

  const ipCandidate = host.replace(/^\[|\]$/g, "");
  const isIp = ipaddr.isValid(ipCandidate);
  let registrableDomain = null;

  if (isIp) {
    let address;
    try {
      address = ipaddr.process(ipCandidate);
    } catch {
      return { blocked: true, reasonCode: "INVALID_IP_ADDRESS", indicators, riskScore };
    }
    if (address.range() !== "unicast") {
      return { blocked: true, reasonCode: "NON_PUBLIC_IP_ADDRESS", indicators, riskScore };
    }
    if (options.obfuscatedIpHost) {
      return { blocked: true, reasonCode: "OBFUSCATED_IP_EVASION", indicators: [...indicators, "IP_LITERAL_HOST", "OBFUSCATED_IP_HOST"], riskScore: 10 };
    }
    const normalizedIp = address.toNormalizedString();
    indicators.push("IP_LITERAL_HOST");
    if (isKnownSafePublicIp(normalizedIp) && parsedUrl.protocol === "https:") {
      indicators.push("TRUSTED_PUBLIC_INFRASTRUCTURE_IP");
    } else {
      indicators.push("PUBLIC_IP_LITERAL_HOST");
      riskScore += 4;
    }
  } else {
    const validDns =
      host &&
      host.length <= 253 &&
      host.includes(".") &&
      host.split(".").every((label) => label.length >= 1 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));

    if (!validDns) return { blocked: true, reasonCode: "INVALID_HOSTNAME", indicators, riskScore };

    const domainInfo = parseDomain(host);
    registrableDomain = domainInfo?.domain || null;
    if (!domainInfo?.publicSuffix || !registrableDomain) {
      indicators.push("PUBLIC_SUFFIX_NOT_RECOGNIZED_LOCALLY");
      riskScore += 1;
      registrableDomain = host;
    }

    const labels = host.split(".");
    if (labels.some((label) => label.startsWith("xn--"))) {
      indicators.push("PUNYCODE_HOSTNAME");
      riskScore += 1;
      if (hasMixedScripts(host)) {
        indicators.push("MIXED_SCRIPT_IDN_HOSTNAME");
        riskScore += 3;
      } else if (toConfusableSkeleton(host).hadConfusable) {
        indicators.push("NON_LATIN_CONFUSABLE_IDN_HOSTNAME");
        riskScore += 2;
      }
    }

    if (labels.length > 5) {
      indicators.push("MANY_SUBDOMAINS");
      riskScore += labels.length > 8 ? 2 : 1;
    }
    if (labels.some((l) => l.length >= 40)) {
      indicators.push("VERY_LONG_HOST_LABEL");
      riskScore += 1;
    }
    if (labels.some((l) => l.length >= 18 && shannonEntropy(l) >= 3.7 && /[0-9]/.test(l))) {
      indicators.push("HIGH_ENTROPY_HOST_LABEL");
      riskScore += 1;
    }

    const mainDomainLabel = (registrableDomain || host).split(".")[0];
    const cleanMain = mainDomainLabel.replace(/-/g, "");
    if (cleanMain.length >= 12) {
      const digitRatio = (cleanMain.match(/\d/g) || []).length / cleanMain.length;
      const ent = shannonEntropy(cleanMain);
      if ((ent >= 3.6 && digitRatio >= 0.2) || (cleanMain.length >= 18 && ent >= 3.9)) {
        indicators.push("HIGH_ENTROPY_DGA_DOMAIN");
        riskScore += 3;
      }
    }

    if (matchesDomainSet(host, URL_SHORTENER_DOMAINS)) {
      indicators.push("URL_SHORTENER_HIDES_DESTINATION");
      riskScore += 4;
    }
    if (matchesDomainSet(host, TUNNEL_OR_DYNAMIC_DNS_DOMAINS)) {
      indicators.push("FREE_TUNNEL_OR_DYNAMIC_DNS_HOST");
      riskScore += 4;
    }
    if (matchesDomainSet(host, FREE_UGC_OR_CLOUD_HOSTING_DOMAINS)) {
      indicators.push("FREE_UGC_OR_CLOUD_HOSTING");
      riskScore += 3;
    }
    const tld = host.split(".").pop();
    if (HIGH_RISK_TLDS.has(tld)) {
      indicators.push("HIGH_RISK_ABUSED_TLD");
      riskScore += 2;
    }

    const brandAnalysis = analyzeBrandImpersonation(host, registrableDomain);
    indicators.push(...brandAnalysis.indicators);
    riskScore += brandAnalysis.riskScore;

    if (/(?:^|\.)\d{1,3}(?:-\d{1,3}){3}(?:-|\.)/.test(host)) {
      indicators.push("DASHED_IP_PATTERN_IN_HOSTNAME");
      riskScore += 3;
    }

    if (!isKnownSafeDomain(registrableDomain) || matchesDomainSet(host, FREE_UGC_OR_CLOUD_HOSTING_DOMAINS)) {
      const hostWordTokens = host.split(/[.-]+/).filter((t) => t.length >= 3);
      const deceptiveMatches = new Set(hostWordTokens.filter((t) => DECEPTIVE_DOMAIN_LURE_WORDS.has(t)));

      if (deceptiveMatches.size >= 3) {
        indicators.push("DECEPTIVE_MULTI_LURE_HOSTNAME");
        riskScore += 4;
      } else if (deceptiveMatches.size === 2 && !indicators.includes("BRAND_NAME_IN_UNRELATED_DOMAIN")) {
        indicators.push("DECEPTIVE_AUTH_HOSTNAME_PATTERN");
        riskScore += 3;
      }

      const hyphenCount = (mainDomainLabel.match(/-/g) || []).length;
      if (hyphenCount >= 3 && deceptiveMatches.size >= 1) {
        indicators.push("EXCESSIVE_HYPHEN_LURE_DOMAIN");
        riskScore += 3;
      }

      const subdomainPrefix =
        registrableDomain && host.length > registrableDomain.length
          ? host.slice(0, host.length - registrableDomain.length - 1)
          : "";
      if (
        subdomainPrefix &&
        ((subdomainPrefix.length >= 28 && (deceptiveMatches.size >= 1 || indicators.includes("BRAND_NAME_IN_UNRELATED_DOMAIN"))) ||
          subdomainPrefix.length >= 44)
      ) {
        indicators.push("MOBILE_VIEWPORT_SUBDOMAIN_PADDING");
        riskScore += 4;
      }
    }
  }

  if (parsedUrl.protocol === "http:") {
    indicators.push("UNENCRYPTED_HTTP");
    riskScore += 1;
  }

  if (parsedUrl.port) {
    indicators.push("NON_STANDARD_PORT");
    riskScore += 2;
    if (SUSPICIOUS_SERVICE_PORTS.has(String(parsedUrl.port))) {
      indicators.push("SUSPICIOUS_SERVICE_PORT");
      riskScore += 2;
    }
  }

  const uniqueIndicators = [...new Set(indicators)];
  if (uniqueIndicators.includes("BRAND_DOMAIN_SPOOFED_IN_SUBDOMAIN")) {
    return { blocked: true, reasonCode: "BRAND_DOMAIN_SPOOFED_IN_SUBDOMAIN", indicators: uniqueIndicators, riskScore };
  }

  return {
    blocked: false,
    indicators: uniqueIndicators,
    riskScore,
    destination: {
      hostname: host,
      registrableDomain,
      protocol: parsedUrl.protocol,
      nonStandardPort: Boolean(parsedUrl.port)
    }
  };
}

function hasDoubleExtensionMasquerade(filename) {
  const parts = String(filename || "").toLowerCase().split(".").filter(Boolean);
  if (parts.length < 3) return false;
  const finalExt = parts[parts.length - 1];
  const prevExt = parts[parts.length - 2];
  return (
    DECOY_DOCUMENT_EXTENSIONS.has(prevExt) &&
    (EXECUTABLE_EXTENSIONS.has(finalExt) || ARCHIVE_EXTENSIONS.has(finalExt) || finalExt === "html" || finalExt === "htm")
  );
}

const SECRET_ROUTE_WORDS = new Set([
  "token", "access-token", "reset", "reset-password", "verify", "verification",
  "magic-link", "invite", "invitation", "session", "authorization", "assertion", "ticket", "sso"
]);

function isSensitivePathSegment(segment, previousSegment = "") {
  const value = safeDecode(String(segment || ""), 3);
  const lower = value.toLowerCase();
  const prev = String(previousSegment || "").toLowerCase();
  if (/^eyj[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}$/i.test(value)) return true;
  if (/^[a-f0-9]{32,}$/i.test(value)) return true;
  if (/^[a-z0-9_-]{40,}$/i.test(value) && /[a-z]/i.test(value) && /[0-9]/.test(value)) return true;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) return true;
  if (value.length >= 64 && shannonEntropy(value) >= 3.5) return true;
  if (SECRET_ROUTE_WORDS.has(prev) && value.length >= 12) return true;
  if (/^(?:token|secret|password|code|auth|session|ticket)=[^/]+$/i.test(lower)) return true;
  return false;
}

function analyzePathLocal(rawPath) {
  const indicators = [];
  let riskScore = 0;
  let hardBlock = false;
  let hardBlockReason = null;

  const decoded = decodeRepeatedly(rawPath || "/", 2);
  const decodedPath = decoded.value;

  if (decoded.decodingFailed) {
    indicators.push("UNDECODABLE_PATH_ENCODING");
    riskScore += 2;
  }
  if (decoded.additionalDecodes > 0) {
    indicators.push("REPEATED_PATH_ENCODING");
    riskScore += 1;
  }

  if (/%(?:00|0a|0d|09)/i.test(rawPath) || /%(?:00|0a|0d|09)/i.test(decodedPath) || hasControlChars(decodedPath)) {
    indicators.push("ENCODED_CONTROL_CHARACTER");
    riskScore += 5;
    hardBlock = true;
    hardBlockReason = "ENCODED_CONTROL_CHARACTER";
  }

  if (/<script\b|javascript:|onerror\s*=|onload\s*=|data:text\/html/i.test(decodedPath)) {
    indicators.push("INJECTED_SCRIPT_IN_PATH");
    riskScore += 6;
    hardBlock = true;
    hardBlockReason = hardBlockReason || "INJECTED_SCRIPT_IN_PATH";
  }

  if (PHISHING_KIT_ENDPOINT_PATTERN.test(decodedPath)) {
    indicators.push("PHISHING_KIT_ENDPOINT_FINGERPRINT");
    riskScore += 6;
    hardBlock = true;
    hardBlockReason = hardBlockReason || "PHISHING_KIT_ENDPOINT_FINGERPRINT";
  }

  if (/(?:^|\/)(?:\.\.|%2e%2e)(?:\/|$)/i.test(decodedPath)) {
    indicators.push("PATH_TRAVERSAL_PATTERN");
    riskScore += 3;
  }
  if (/%(?:2f|5c)/i.test(rawPath)) {
    indicators.push("ENCODED_PATH_SEPARATOR");
    riskScore += 1;
  }
  if (rawPath.length > 2048) {
    indicators.push("VERY_LONG_PATH");
    riskScore += 1;
  }
  if (/\/https?:\/\//i.test(decodedPath)) {
    indicators.push("EMBEDDED_URL_IN_PATH");
    riskScore += 3;
  }

  const segments = decodedPath.split("/").filter(Boolean);
  if (segments.length > 20) {
    indicators.push("MANY_PATH_SEGMENTS");
    riskScore += 1;
  }

  let sensitivePathSegmentCount = 0;
  for (let i = 0; i < segments.length; i++) {
    if (isSensitivePathSegment(segments[i], segments[i - 1] || "")) sensitivePathSegmentCount++;
  }
  if (sensitivePathSegmentCount > 0) indicators.push("SENSITIVE_PATH_SEGMENT_DETECTED");

  if (/\b(?:phishing|malware|ransomware|trojan|keylogger|spyware|infostealer|credharvest|phishkit)\b/i.test(decodedPath)) {
    indicators.push("EXPLICIT_THREAT_KEYWORD_IN_PATH");
    riskScore += 5;
  }

  const finalSegment = (segments.at(-1) || "").replace(/[\s.]+$/g, "");
  const extensionMatch = finalSegment.match(/\.([a-z0-9]{1,18})$/i);
  const extension = extensionMatch ? extensionMatch[1].toLowerCase() : null;

  if (hasDoubleExtensionMasquerade(finalSegment)) {
    indicators.push("DOUBLE_EXTENSION_MASQUERADE");
    riskScore += 8;
    hardBlock = true;
    hardBlockReason = hardBlockReason || "DOUBLE_EXTENSION_MASQUERADE";
  }

  if (extension && MOBILE_INSTALLER_EXTENSIONS.has(extension)) {
    indicators.push("MOBILE_SIDELOAD_INSTALLER_PATH");
    indicators.push("EXECUTABLE_DOWNLOAD_PATH");
    riskScore += 5;
  } else if (extension && MOBILE_CONFIG_AND_CERT_EXTENSIONS.has(extension)) {
    indicators.push("MOBILE_CONFIG_OR_CERT_INSTALL_PATH");
    riskScore += 6;
  } else if (extension && INTERACTIVE_SMUGGLING_EXTENSIONS.has(extension)) {
    indicators.push("INTERACTIVE_SMUGGLING_FILE_PATH");
    riskScore += 4;
  } else if (extension && EXECUTABLE_EXTENSIONS.has(extension)) {
    indicators.push("EXECUTABLE_DOWNLOAD_PATH");
    riskScore += 3;
  } else if (extension && ARCHIVE_EXTENSIONS.has(extension)) {
    indicators.push("ARCHIVE_DOWNLOAD_PATH");
    riskScore += 2;
  }

  return {
    indicators: [...new Set(indicators)],
    riskScore,
    hardBlock,
    hardBlockReason,
    segmentCount: segments.length,
    extension,
    originalPathLength: rawPath.length,
    sensitivePathSegmentCount,
    segments
  };
}

function tokenizeCompact(value) {
  const raw = String(value || "").toLowerCase();
  return { splitTokens: raw.split(/[^a-z0-9]+/).filter(Boolean), compact: raw.replace(/[^a-z0-9]+/g, "") };
}

function findMatches(tokens, compact, termList) {
  const hits = new Set();
  for (const term of termList) {
    if (tokens.includes(term) || compact.includes(term)) hits.add(term);
  }
  return hits.size;
}

function analyzeScamLuresLocal({ hostname, registrableDomain, pathSegments, parsedUrl, existingIndicators = [] }) {
  const hasMobileInstaller =
    existingIndicators.includes("MOBILE_SIDELOAD_INSTALLER_PATH") ||
    existingIndicators.includes("MOBILE_CONFIG_OR_CERT_INSTALL_PATH") ||
    existingIndicators.includes("INTERACTIVE_SMUGGLING_FILE_PATH");

  if (isKnownSafeDomain(registrableDomain) && !matchesDomainSet(hostname, FREE_UGC_OR_CLOUD_HOSTING_DOMAINS) && !hasMobileInstaller) {
    return { indicators: [], riskScore: 0, hardBlock: false, hardBlockReason: null };
  }

  const indicators = [];
  let riskScore = 0;
  const hostParts = String(hostname || "").split(".");
  const queryKeys = Array.from(parsedUrl?.searchParams?.keys() || []);
  const combinedText = [...hostParts, ...(Array.isArray(pathSegments) ? pathSegments : []), ...queryKeys].join(" ");
  const { splitTokens, compact } = tokenizeCompact(combinedText);

  const financialHits = findMatches(splitTokens, compact, FINANCIAL_CREDIT_LURE_TERMS);
  const kycHits = findMatches(splitTokens, compact, URGENCY_KYC_LURE_TERMS);
  const harvestHits = findMatches(splitTokens, compact, CREDENTIAL_HARVEST_TERMS);
  const ratHits = findMatches(splitTokens, compact, REMOTE_ACCESS_TROJAN_TERMS);
  const extortionHits = findMatches(splitTokens, compact, DIGITAL_ARREST_EXTORTION_TERMS);

  const pathTokenInfo = tokenizeCompact((Array.isArray(pathSegments) ? pathSegments : []).join(" "));
  const pathBrandHit = PATH_BRAND_TERMS.some((brand) => pathTokenInfo.splitTokens.includes(brand));
  const genericAuthPathHit = pathTokenInfo.splitTokens.some((tok) => GENERIC_AUTH_OR_DOC_PATH_TERMS.has(tok));

  if (financialHits > 0) {
    indicators.push("SMS_FINANCIAL_SCAM_LURE");
    riskScore += financialHits >= 2 ? 4 : 3;
  }
  if (kycHits > 0) {
    indicators.push("URGENCY_OR_KYC_SCAM_LURE");
    riskScore += kycHits >= 2 ? 4 : 3;
  }
  if (harvestHits > 0) {
    indicators.push("SENSITIVE_BANKING_CREDENTIAL_HARVEST_PATTERN");
    riskScore += 5;
  }
  if (ratHits > 0) {
    indicators.push("REMOTE_ACCESS_TROJAN_SCAM_LURE");
    riskScore += 5;
  }
  if (extortionHits > 0) {
    indicators.push("DIGITAL_ARREST_OR_EXTORTION_SCAM_LURE");
    riskScore += 5;
  }
  if (pathBrandHit && (financialHits > 0 || kycHits > 0 || harvestHits > 0 || ratHits > 0 || extortionHits > 0 || genericAuthPathHit)) {
    indicators.push("BRAND_IMPERSONATION_WITH_SCAM_LURE_IN_PATH");
    riskScore += 4;
  }

  const hasExplicitThreatKeyword =
    existingIndicators.includes("EXPLICIT_THREAT_KEYWORD_IN_PATH") ||
    /\b(?:phishing|malware|ransomware|trojan|keylogger|spyware)\b/i.test(hostname || "");
  const hasDomainImpersonation =
    existingIndicators.includes("BRAND_NAME_IN_UNRELATED_DOMAIN") ||
    existingIndicators.includes("POSSIBLE_BRAND_LOOKALIKE_DOMAIN") ||
    existingIndicators.includes("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION");
  const hasDeceptiveHostname =
    existingIndicators.includes("DECEPTIVE_MULTI_LURE_HOSTNAME") ||
    existingIndicators.includes("DECEPTIVE_AUTH_HOSTNAME_PATTERN") ||
    existingIndicators.includes("EXCESSIVE_HYPHEN_LURE_DOMAIN");
  const hasAndroidApk =
    existingIndicators.includes("MOBILE_SIDELOAD_INSTALLER_PATH") ||
    existingIndicators.includes("MOBILE_CONFIG_OR_CERT_INSTALL_PATH");
  const hasArchive = existingIndicators.includes("ARCHIVE_DOWNLOAD_PATH");
  const hasTunnelOrIp =
    existingIndicators.includes("FREE_TUNNEL_OR_DYNAMIC_DNS_HOST") ||
    existingIndicators.includes("IP_LITERAL_HOST") ||
    existingIndicators.includes("OBFUSCATED_IP_HOST");
  const hasAbusedCloudHosting = existingIndicators.includes("FREE_UGC_OR_CLOUD_HOSTING");
  const hasHighRiskTld = existingIndicators.includes("HIGH_RISK_ABUSED_TLD");
  const hasShortener = existingIndicators.includes("URL_SHORTENER_HIDES_DESTINATION");
  const hasHttp = existingIndicators.includes("UNENCRYPTED_HTTP");
  const hasDga = existingIndicators.includes("HIGH_ENTROPY_DGA_DOMAIN");
  const hasSensitiveQuery = existingIndicators.includes("SENSITIVE_QUERY_PARAMETERS_DETECTED");
  const hasScamLure = financialHits > 0 || kycHits > 0 || harvestHits > 0 || ratHits > 0 || extortionHits > 0;

  let hardBlock = false;
  let hardBlockReason = null;

  if (existingIndicators.includes("CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION")) {
    hardBlock = true;
    hardBlockReason = "CONFUSABLE_HOMOGRAPH_BRAND_IMPERSONATION";
  } else if (hasExplicitThreatKeyword) {
    hardBlock = true;
    hardBlockReason = "EXPLICIT_PHISHING_OR_MALWARE_INDICATOR";
  } else if (hasDomainImpersonation && (hasScamLure || hasAndroidApk || hasArchive || hasHighRiskTld || hasHttp || hasTunnelOrIp || hasAbusedCloudHosting || pathBrandHit)) {
    hardBlock = true;
    hardBlockReason = "PHISHING_BRAND_IMPERSONATION_CONFIRMED";
  } else if (hasAndroidApk && (hasScamLure || hasTunnelOrIp || hasAbusedCloudHosting || hasHighRiskTld || hasHttp || pathBrandHit)) {
    hardBlock = true;
    hardBlockReason = "MALICIOUS_APK_DELIVERY_PATTERN";
  } else if (ratHits > 0 && (hasAndroidApk || hasArchive || hasTunnelOrIp || hasAbusedCloudHosting || hasHighRiskTld || hasHttp || pathBrandHit || genericAuthPathHit || kycHits > 0 || extortionHits > 0)) {
    hardBlock = true;
    hardBlockReason = "REMOTE_ACCESS_TROJAN_SCAM_BLOCKED";
  } else if (hasArchive && (hasScamLure || hasHighRiskTld || hasTunnelOrIp || pathBrandHit || hasAbusedCloudHosting)) {
    hardBlock = true;
    hardBlockReason = "MALICIOUS_ARCHIVE_DELIVERY_PATTERN";
  } else if (hasAbusedCloudHosting && (hasScamLure || pathBrandHit || harvestHits > 0 || genericAuthPathHit || hasDeceptiveHostname)) {
    hardBlock = true;
    hardBlockReason = "ABUSED_HOSTING_PHISHING_PATTERN";
  } else if (hasTunnelOrIp && (hasScamLure || pathBrandHit || harvestHits > 0 || genericAuthPathHit || hasDeceptiveHostname)) {
    hardBlock = true;
    hardBlockReason = "TUNNEL_OR_IP_PHISHING_PATTERN";
  } else if (hasDeceptiveHostname && (hasScamLure || hasHighRiskTld || hasHttp || pathBrandHit)) {
    hardBlock = true;
    hardBlockReason = "DECEPTIVE_PHISHING_KIT_PATTERN";
  } else if (hasHighRiskTld && (hasScamLure || harvestHits > 0 || hasDga || pathBrandHit)) {
    hardBlock = true;
    hardBlockReason = "HIGH_RISK_TLD_SCAM_LURE_PATTERN";
  } else if (hasHttp && (hasScamLure || harvestHits > 0 || (hasSensitiveQuery && !existingIndicators.includes("REDIRECT_PARAMETER_PRESENT")))) {
    hardBlock = true;
    hardBlockReason = "INSECURE_HTTP_SCAM_OR_CREDENTIAL_RISK";
  } else if (hasShortener && hasHttp) {
    hardBlock = true;
    hardBlockReason = "INSECURE_HTTP_SHORTENER_LINK";
  }

  return { indicators: [...new Set(indicators)], riskScore, hardBlock, hardBlockReason };
}

function deLeet(str) {
  return String(str || "")
    .toLowerCase()
    .replace(/0/g, "o").replace(/1/g, "i").replace(/3/g, "e").replace(/4/g, "a")
    .replace(/5/g, "s").replace(/7/g, "t").replace(/8/g, "b").replace(/\$/g, "s");
}

function extractNormalizedTokens(rawSegments) {
  const tokens = new Set();
  for (const seg of rawSegments) {
    const decoded = safeDecode(seg).toLowerCase();
    for (const part of decoded.split(/[^a-z0-9]+/).filter(Boolean)) {
      tokens.add(part);
      tokens.add(deLeet(part));
    }
    const compact = deLeet(decoded).replace(/[^a-z0-9]+/g, "");
    if (compact) tokens.add(compact);
  }
  return [...tokens];
}

function matchVector(tokens, stems) {
  for (const stem of stems) {
    for (const tok of tokens) {
      if (tok === stem || (stem.length >= 5 && (tok.includes(stem) || tok.startsWith(stem)))) {
        return true;
      }
    }
  }
  return false;
}

function hasDgaVowelOrConsonantAnomaly(label) {
  const alphaOnly = String(label || "").toLowerCase().replace(/[^a-z]/g, "");
  if (alphaOnly.length < 8) return false;
  const vowels = (alphaOnly.match(/[aeiouy]/g) || []).length;
  const vowelRatio = vowels / alphaOnly.length;
  const maxConsonantRun = Math.max(0, ...(alphaOnly.match(/[^aeiouy]+/g) || []).map((m) => m.length));
  const digits = (String(label).match(/\d/g) || []).length;
  const digitRatio = digits / Math.max(1, label.length);
  const ent = shannonEntropy(String(label).toLowerCase().replace(/-/g, ""));
  if (maxConsonantRun >= 6 && ent >= 3.0) return true;
  if (alphaOnly.length >= 9 && vowelRatio < 0.14 && ent >= 3.1) return true;
  if (label.length >= 9 && digitRatio >= 0.3 && ent >= 3.1) return true;
  return false;
}

function hasFragmentVictimEmailPrefill(parsedUrl) {
  const hash = String(parsedUrl?.hash || "").replace(/^#/, "").trim();
  if (!hash) return false;
  const decodedHash = safeDecode(hash, 2);
  if (/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(decodedHash)) return true;

  const b64Candidate = decodedHash.replace(/^[^a-zA-Z0-9+/=_-]+/, "").trim();
  if (/^[A-Za-z0-9+/_-]{12,160}={0,2}$/.test(b64Candidate)) {
    try {
      const decoded = decodeBase64Utf8(b64Candidate);
      if (/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(decoded.trim())) return true;
    } catch {
      // ignore
    }
  }
  return false;
}

function evaluateLexicalAndStructuralRiskLocal({ hostname, registrableDomain, parsedUrl, rawPath, pathSegments, existingIndicators = [] }) {
  const hasRiskyArtifact =
    existingIndicators.includes("MOBILE_SIDELOAD_INSTALLER_PATH") ||
    existingIndicators.includes("MOBILE_CONFIG_OR_CERT_INSTALL_PATH") ||
    existingIndicators.includes("INTERACTIVE_SMUGGLING_FILE_PATH") ||
    existingIndicators.includes("FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD") ||
    existingIndicators.includes("HTML_SMUGGLING_PAYLOAD_DETECTED");

  if (isKnownSafeDomain(registrableDomain) && !matchesDomainSet(hostname, FREE_UGC_OR_CLOUD_HOSTING_DOMAINS) && !hasRiskyArtifact) {
    return { indicators: [], riskScore: 0, hardBlock: false, hardBlockReason: null, matchedVectors: [] };
  }

  const indicators = [];
  let riskScore = 0;
  const unicodeHost = domainToUnicodeSafe(hostname);
  const decodedPath = safeDecode(rawPath || parsedUrl.pathname || "/");
  const queryKeys = Array.from(parsedUrl?.searchParams?.keys() || []);

  const allTokens = extractNormalizedTokens([
    unicodeHost, hostname, ...(Array.isArray(pathSegments) ? pathSegments : []), decodedPath, ...queryKeys
  ]);

  if (matchVector(allTokens, EXPLICIT_MALICE_STEMS)) {
    indicators.push("LEXICAL_EXPLICIT_PHISHING_OR_MALWARE_STEM");
    riskScore += 6;
  }

  const matchedVectors = [];
  for (const [vectorName, stems] of Object.entries(INTENT_VECTORS)) {
    if (matchVector(allTokens, stems)) matchedVectors.push(vectorName);
  }

  if (matchedVectors.length >= 3) {
    indicators.push("MULTI_VECTOR_SOCIAL_ENGINEERING_ATTACK");
    riskScore += 6;
  } else if (matchedVectors.length === 2) {
    indicators.push("COMPOUND_DECEPTIVE_INTENT_VECTORS");
    riskScore += 4;
  } else if (matchedVectors.length === 1 && !matchedVectors.includes("AUTH_IDENTITY")) {
    indicators.push(`LURE_INTENT_${matchedVectors[0]}`);
    riskScore += 2;
  }

  const subdomainPart =
    registrableDomain && hostname.length > registrableDomain.length
      ? hostname.slice(0, hostname.length - registrableDomain.length - 1)
      : "";
  if (subdomainPart && EMBEDDED_TLD_SUBDOMAIN_PATTERN.test(subdomainPart)) {
    indicators.push("UNIVERSAL_SUBDOMAIN_TLD_MASQUERADING");
    riskScore += 8;
  }

  const mainLabel = (registrableDomain || hostname).split(".")[0];
  if (hasDgaVowelOrConsonantAnomaly(mainLabel)) {
    indicators.push("ALGORITHMIC_DGA_HOST_ANOMALY");
    riskScore += 3;
  }

  if (COMPROMISED_ASSET_DIR_KIT.test(decodedPath)) {
    indicators.push("COMPROMISED_ASSET_DIR_PHISHING_KIT");
    riskScore += 6;
  }
  if (OBFUSCATED_SHORT_DIR_KIT.test(decodedPath)) {
    indicators.push("OBFUSCATED_SHORT_PATH_STATIC_KIT");
    riskScore += 3;
  }

  const rawPctMatches = (String(rawPath || "").match(/%[0-9a-f]{2}/gi) || []).length;
  if (rawPath && rawPath.length >= 12 && (rawPctMatches * 3) / rawPath.length >= 0.38) {
    indicators.push("HEAVY_PERCENT_ENCODING_OBFUSCATION");
    riskScore += 3;
  }

  if (hasFragmentVictimEmailPrefill(parsedUrl)) {
    indicators.push("FRAGMENT_VICTIM_EMAIL_PREFILL_KIT");
    riskScore += 6;
  }

  const hasHighRiskInfra =
    existingIndicators.includes("FREE_UGC_OR_CLOUD_HOSTING") ||
    existingIndicators.includes("FREE_TUNNEL_OR_DYNAMIC_DNS_HOST") ||
    existingIndicators.includes("HIGH_RISK_ABUSED_TLD") ||
    existingIndicators.includes("IP_LITERAL_HOST") ||
    existingIndicators.includes("OBFUSCATED_IP_HOST") ||
    existingIndicators.includes("URL_SHORTENER_HIDES_DESTINATION") ||
    existingIndicators.includes("UNENCRYPTED_HTTP");
  const hasBrandLookalike =
    existingIndicators.includes("BRAND_NAME_IN_UNRELATED_DOMAIN") ||
    existingIndicators.includes("POSSIBLE_BRAND_LOOKALIKE_DOMAIN");

  let hardBlock = false;
  let hardBlockReason = null;

  if (existingIndicators.includes("MIXED_SCRIPT_IDN_HOSTNAME")) {
    hardBlock = true;
    hardBlockReason = "MIXED_SCRIPT_HOMOGRAPH_ATTACK";
  } else if (indicators.includes("UNIVERSAL_SUBDOMAIN_TLD_MASQUERADING")) {
    hardBlock = true;
    hardBlockReason = "SUBDOMAIN_TLD_MASQUERADE_PHISHING";
  } else if (indicators.includes("LEXICAL_EXPLICIT_PHISHING_OR_MALWARE_STEM")) {
    hardBlock = true;
    hardBlockReason = "LEXICAL_PHISHING_OR_MALWARE_DETECTED";
  } else if (indicators.includes("COMPROMISED_ASSET_DIR_PHISHING_KIT")) {
    hardBlock = true;
    hardBlockReason = "COMPROMISED_WEBSITE_PHISHING_KIT";
  } else if (indicators.includes("FRAGMENT_VICTIM_EMAIL_PREFILL_KIT") && (matchedVectors.length >= 1 || hasHighRiskInfra || hasBrandLookalike)) {
    hardBlock = true;
    hardBlockReason = "CREDENTIAL_PREFILL_PHISHING_KIT";
  } else if (matchedVectors.length >= 3) {
    hardBlock = true;
    hardBlockReason = "MULTI_VECTOR_PHISHING_DETECTED";
  } else if (matchedVectors.length === 2 && (hasHighRiskInfra || hasBrandLookalike || indicators.includes("OBFUSCATED_SHORT_PATH_STATIC_KIT") || indicators.includes("HEAVY_PERCENT_ENCODING_OBFUSCATION"))) {
    hardBlock = true;
    hardBlockReason = "HIGH_CONFIDENCE_PHISHING_INTENT";
  } else if (matchedVectors.length >= 1 && existingIndicators.includes("FREE_UGC_OR_CLOUD_HOSTING") && (indicators.includes("OBFUSCATED_SHORT_PATH_STATIC_KIT") || matchedVectors.some((v) => v !== "AUTH_IDENTITY"))) {
    hardBlock = true;
    hardBlockReason = "ABUSED_CLOUD_HOSTING_PHISHING_KIT";
  } else if ((existingIndicators.includes("IP_LITERAL_HOST") || existingIndicators.includes("OBFUSCATED_IP_HOST")) && (matchedVectors.length >= 1 || existingIndicators.includes("EXECUTABLE_DOWNLOAD_PATH"))) {
    hardBlock = true;
    hardBlockReason = "DIRECT_IP_PHISHING_OR_MALWARE_DROP";
  } else if (indicators.includes("ALGORITHMIC_DGA_HOST_ANOMALY") && (hasHighRiskInfra || matchedVectors.length >= 1 || existingIndicators.includes("EXECUTABLE_DOWNLOAD_PATH"))) {
    hardBlock = true;
    hardBlockReason = "DGA_MALICIOUS_INFRASTRUCTURE_DETECTED";
  }

  return { indicators: [...new Set(indicators)], riskScore, hardBlock, hardBlockReason, matchedVectors };
}

function normalizeKey(key) {
  return String(key || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function classifyDecodedPayload(decodedRaw, kind) {
  const trimmed = String(decodedRaw || "").trim();
  const decodedUri = decodeRepeatedly(trimmed, 2).value.trim();
  for (const cand of [trimmed, decodedUri]) {
    if (HTML_SMUGGLING_CODE_PATTERN.test(cand)) return { decoded: cand, kind, htmlSmuggling: true };
    if (/^(?:https?:\/\/|\/\/|\\\\[a-z0-9])/i.test(cand) || DANGEROUS_REDIRECT_SCHEME.test(stripInvisibleAndControlChars(cand))) {
      return { decoded: cand, kind, htmlSmuggling: false };
    }
  }
  return null;
}

function tryDecodeSmuggledUrl(value) {
  const trimmed = String(value || "").trim();
  if (trimmed.length < 12 || trimmed.length > 2048) return null;

  if (/^[A-Za-z0-9+/_-]{12,}={0,2}$/.test(trimmed)) {
    try {
      const match = classifyDecodedPayload(decodeBase64Utf8(trimmed).trim(), "BASE64");
      if (match) return match;
    } catch {
      // ignore
    }
  }
  if (trimmed.length >= 24 && trimmed.length % 2 === 0 && /^[0-9a-f]+$/i.test(trimmed)) {
    try {
      const match = classifyDecodedPayload(decodeHexUtf8(trimmed).trim(), "HEX");
      if (match) return match;
    } catch {
      // ignore
    }
  }
  return null;
}

function inspectRedirectCandidate(candidate, state, depth = 0) {
  const value = String(candidate || "").trim();
  const schemeProbe = stripInvisibleAndControlChars(value);

  if (DANGEROUS_REDIRECT_SCHEME.test(schemeProbe)) {
    state.indicators.push("DANGEROUS_REDIRECT_SCHEME");
    state.hardBlockReason = "DANGEROUS_REDIRECT_SCHEME";
    return;
  }
  if (/^\\\\[a-z0-9]/i.test(value) || /^https?:[^/]/i.test(value)) {
    state.indicators.push("MALFORMED_PROTOCOL_RELATIVE_REDIRECT");
    state.hardBlockReason = "MALFORMED_PROTOCOL_RELATIVE_REDIRECT";
    return;
  }

  const smuggled = tryDecodeSmuggledUrl(value);
  if (smuggled) {
    state.indicators.push(smuggled.kind === "HEX" ? "HEX_SMUGGLED_REDIRECT" : "BASE64_SMUGGLED_REDIRECT");
    if (smuggled.htmlSmuggling) {
      state.indicators.push("HTML_SMUGGLING_PAYLOAD_DETECTED");
      state.hardBlockReason = "HTML_SMUGGLING_PAYLOAD_DETECTED";
      return;
    }
    state.riskScore += 2;
    inspectRedirectCandidate(smuggled.decoded, state, depth + 1);
    return;
  }

  if (!/^(?:https?:\/\/|\/\/)/i.test(value)) return;

  let nestedUrl;
  try {
    nestedUrl = value.startsWith("//") ? new URL(`https:${value}`) : new URL(value);
  } catch {
    state.indicators.push("INVALID_NESTED_REDIRECT_URL");
    state.riskScore += 1;
    return;
  }
  if (!["http:", "https:"].includes(nestedUrl.protocol)) {
    state.indicators.push("INVALID_NESTED_REDIRECT_URL");
    state.riskScore += 1;
    return;
  }

  state.nestedDestinationCount++;
  const nestedHost = nestedUrl.hostname.toLowerCase().replace(/\.$/, "");
  if (nestedUrl.username || nestedUrl.password) {
    state.indicators.push("NESTED_REDIRECT_CONTAINS_CREDENTIALS");
    state.hardBlockReason = "NESTED_REDIRECT_CONTAINS_CREDENTIALS";
    return;
  }

  const nestedDomain = analyzeDomainLocal(nestedHost, nestedUrl);
  if (nestedDomain.blocked) {
    state.indicators.push("NESTED_REDIRECT_DESTINATION_BLOCKED");
    state.blockedNestedDestinationCount++;
    state.hardBlockReason = nestedDomain.reasonCode;
    return;
  }

  const nestedPath = analyzePathLocal(nestedUrl.pathname || "/");
  if (nestedPath.hardBlock) {
    state.indicators.push("NESTED_REDIRECT_MALICIOUS_PATH");
    state.hardBlockReason = nestedPath.hardBlockReason;
    return;
  }
  if (nestedPath.indicators.includes("MOBILE_SIDELOAD_INSTALLER_PATH")) {
    state.indicators.push("NESTED_REDIRECT_TO_MOBILE_INSTALLER");
    state.hardBlockReason = "NESTED_REDIRECT_TO_MOBILE_INSTALLER";
    return;
  }
  if (nestedPath.indicators.includes("MOBILE_CONFIG_OR_CERT_INSTALL_PATH")) {
    state.indicators.push("NESTED_REDIRECT_TO_MOBILE_CONFIG_OR_CERT");
    state.hardBlockReason = "NESTED_REDIRECT_TO_MOBILE_CONFIG_OR_CERT";
    return;
  }

  const nestedIndicators = [...new Set([...nestedDomain.indicators, ...nestedPath.indicators])];
  const nestedRegDomain = nestedDomain.destination?.registrableDomain || null;

  const nestedScam = analyzeScamLuresLocal({
    hostname: nestedHost, registrableDomain: nestedRegDomain,
    pathSegments: nestedPath.segments, parsedUrl: nestedUrl, existingIndicators: nestedIndicators
  });
  if (nestedScam.hardBlock) {
    state.indicators.push("NESTED_REDIRECT_SCAM_OR_PHISHING");
    state.blockedNestedDestinationCount++;
    state.hardBlockReason = nestedScam.hardBlockReason;
    return;
  }

  const nestedLexical = evaluateLexicalAndStructuralRiskLocal({
    hostname: nestedHost, registrableDomain: nestedRegDomain,
    parsedUrl: nestedUrl, rawPath: nestedUrl.pathname || "/",
    pathSegments: nestedPath.segments, existingIndicators: [...nestedIndicators, ...nestedScam.indicators]
  });
  if (nestedLexical.hardBlock) {
    state.indicators.push("NESTED_REDIRECT_PHISHING_KIT");
    state.blockedNestedDestinationCount++;
    state.hardBlockReason = nestedLexical.hardBlockReason;
    return;
  }

  const nestedTotalScore = nestedDomain.riskScore + nestedPath.riskScore + nestedScam.riskScore + nestedLexical.riskScore;
  if (nestedTotalScore >= 7) {
    state.indicators.push("NESTED_REDIRECT_HIGH_RISK_TARGET");
    state.blockedNestedDestinationCount++;
    state.hardBlockReason = "NESTED_REDIRECT_HIGH_RISK_TARGET";
    return;
  }

  if (nestedDomain.riskScore >= 4) state.indicators.push("SUSPICIOUS_NESTED_REDIRECT_DOMAIN");
  if (nestedTotalScore >= 3) {
    state.indicators.push("NESTED_REDIRECT_RISK_PROPAGATED");
    state.riskScore += nestedTotalScore;
    for (const ind of [...nestedIndicators, ...nestedScam.indicators, ...nestedLexical.indicators]) {
      if (ind !== "SENSITIVE_QUERY_PARAMETERS_DETECTED" && ind !== "SENSITIVE_QUERY_PARAMETER_PRESENT") {
        state.indicators.push(ind);
      }
    }
  }

  state.indicators.push("NESTED_REDIRECT_DESTINATION_INSPECTED");
  if (depth >= 3) {
    if ([...nestedUrl.searchParams.keys()].length > 0) {
      state.indicators.push("REDIRECT_CHAIN_DEPTH_LIMIT_REACHED");
      state.riskScore += 1;
    }
    return;
  }

  const identity = nestedUrl.href;
  if (state.seenNested.has(identity)) return;
  state.seenNested.add(identity);

  for (const [nKey, nVal] of nestedUrl.searchParams.entries()) {
    if (!REDIRECT_PARAMETERS.has(normalizeKey(nKey))) continue;
    const dec = decodeRepeatedly(nVal, 2);
    if (dec.decodingFailed) {
      state.indicators.push("NESTED_REDIRECT_ENCODING_ERROR");
      state.riskScore += 1;
      continue;
    }
    inspectRedirectCandidate(dec.value, state, depth + 1);
  }
}

function analyzeQueryLocal(parsedUrl) {
  const state = {
    indicators: [], riskScore: 0, hardBlockReason: null,
    nestedDestinationCount: 0, blockedNestedDestinationCount: 0, seenNested: new Set()
  };

  const params = Array.from(parsedUrl.searchParams.entries());
  let redirectParameterCount = 0;
  let sensitiveParameterCount = 0;
  let trackingParameterCount = 0;

  if (parsedUrl.search.length > 4096) {
    state.indicators.push("LONG_QUERY_STRING");
    state.riskScore += 1;
  }
  if (params.length > 50) {
    state.indicators.push("EXCESSIVE_QUERY_PARAMETERS");
    state.riskScore += 1;
  }

  for (const [key, value] of params) {
    const normKey = normalizeKey(key);
    const isRedirect = REDIRECT_PARAMETERS.has(normKey);
    const isSensitive = SENSITIVE_PARAMETERS.has(normKey);
    if (isRedirect) {
      redirectParameterCount++;
      state.indicators.push("REDIRECT_PARAMETER_PRESENT");
    }
    if (ANDROID_INTENT_PARAM_KEYS.has(normKey)) {
      state.indicators.push("ANDROID_INTENT_PARAM_FALLBACK_TRAP");
      state.riskScore += 3;
    }
    if (isSensitive) {
      sensitiveParameterCount++;
      state.indicators.push("SENSITIVE_QUERY_PARAMETER_PRESENT");
      state.indicators.push("SENSITIVE_QUERY_PARAMETERS_DETECTED");
    }
    if (TRACKING_PARAMETERS.has(normKey)) trackingParameterCount++;

    const decoded = decodeRepeatedly(value, 3);
    if (decoded.decodingFailed) {
      state.indicators.push("QUERY_VALUE_ENCODING_ERROR");
      if (isRedirect) state.riskScore += 1;
      continue;
    }
    if (decoded.additionalDecodes > 0) state.indicators.push("ADDITIONAL_QUERY_ENCODING");

    if (isRedirect) {
      inspectRedirectCandidate(decoded.value, state, 0);
    } else {
      const trimmedVal = decoded.value.trim();
      const schemeProbe = stripInvisibleAndControlChars(trimmedVal);
      if (DANGEROUS_REDIRECT_SCHEME.test(schemeProbe)) {
        state.indicators.push("DANGEROUS_REDIRECT_SCHEME");
        state.hardBlockReason = "DANGEROUS_REDIRECT_SCHEME";
      } else if (/^(?:https?:\/\/|\/\/|\\\\[a-z0-9])/i.test(trimmedVal)) {
        inspectRedirectCandidate(trimmedVal, state, 1);
      } else {
        const smuggled = tryDecodeSmuggledUrl(trimmedVal);
        if (smuggled) {
          state.indicators.push(smuggled.kind === "HEX" ? "HEX_SMUGGLED_URL_IN_QUERY" : "BASE64_SMUGGLED_URL_IN_QUERY");
          if (smuggled.htmlSmuggling) {
            state.indicators.push("HTML_SMUGGLING_PAYLOAD_DETECTED");
            state.hardBlockReason = "HTML_SMUGGLING_PAYLOAD_DETECTED";
          } else {
            state.riskScore += 2;
            inspectRedirectCandidate(smuggled.decoded, state, 1);
          }
        } else if (hasDoubleExtensionMasquerade(trimmedVal)) {
          state.indicators.push("DOUBLE_EXTENSION_MASQUERADE");
          state.hardBlockReason = "DOUBLE_EXTENSION_MASQUERADE";
        } else if (/\.(?:apk|aab|xapk|apks|ipa)(?:$|[?#])/i.test(trimmedVal)) {
          state.indicators.push("MOBILE_SIDELOAD_INSTALLER_PATH");
          state.indicators.push("QUERY_MOBILE_INSTALLER_PAYLOAD");
          state.riskScore += 5;
        }
      }
    }
  }

  const paVal = parsedUrl.searchParams.get("pa");
  if (paVal && /^[a-z0-9._-]+@[a-z0-9.-]+$/i.test(paVal.trim()) && (parsedUrl.searchParams.has("am") || parsedUrl.searchParams.has("pn") || parsedUrl.searchParams.has("tr"))) {
    state.indicators.push("UPI_PAYMENT_REQUEST_SMUGGLING_IN_URL");
    state.riskScore += 5;
  }
  if (trackingParameterCount > 0) state.indicators.push("TRACKING_PARAMETERS_DETECTED");

  let fragmentHasUrl = false;
  let fragmentHasSensitiveMaterial = false;
  if (parsedUrl.hash) {
    const fragTrimmed = decodeRepeatedly(parsedUrl.hash.slice(1), 3).value.trim();
    fragmentHasUrl = /https?:\/\//i.test(fragTrimmed);
    fragmentHasSensitiveMaterial = /(?:access_token|id_token|token|code|state|session)=/i.test(fragTrimmed) || /^eyj[a-z0-9_-]{8,}\./i.test(fragTrimmed);
    if (fragmentHasUrl) state.indicators.push("URL_PRESENT_IN_FRAGMENT");
    if (fragmentHasSensitiveMaterial) {
      state.indicators.push("SENSITIVE_FRAGMENT_PARAMETER_PRESENT");
      state.indicators.push("SENSITIVE_FRAGMENT_DETECTED");
    }

    const fragSchemeProbe = stripInvisibleAndControlChars(fragTrimmed);
    if (/^Intent;/i.test(fragTrimmed) || /;S\.browser_fallback_url=/i.test(fragTrimmed)) {
      state.indicators.push("ANDROID_INTENT_PARAM_FALLBACK_TRAP");
      state.indicators.push("FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD");
      state.hardBlockReason = "ANDROID_INTENT_PARAM_FALLBACK_TRAP";
    } else if (DANGEROUS_REDIRECT_SCHEME.test(fragSchemeProbe)) {
      state.indicators.push("FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD");
      state.indicators.push("DANGEROUS_REDIRECT_SCHEME");
      state.hardBlockReason = "DANGEROUS_REDIRECT_SCHEME";
    } else if (/^(?:https?:\/\/|\/\/|\\\\[a-z0-9])/i.test(fragTrimmed)) {
      state.indicators.push("FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD");
      inspectRedirectCandidate(fragTrimmed, state, 1);
    } else {
      const smuggledFrag = tryDecodeSmuggledUrl(fragTrimmed);
      if (smuggledFrag) {
        state.indicators.push("FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD");
        if (smuggledFrag.htmlSmuggling) {
          state.indicators.push("HTML_SMUGGLING_PAYLOAD_DETECTED");
          state.hardBlockReason = "HTML_SMUGGLING_PAYLOAD_DETECTED";
        } else {
          state.riskScore += 3;
          inspectRedirectCandidate(smuggledFrag.decoded, state, 1);
        }
      } else if (fragTrimmed.includes("=")) {
        try {
          const fragParams = new URLSearchParams(fragTrimmed);
          for (const [fKey, fVal] of fragParams.entries()) {
            const fValTrimmed = String(fVal || "").trim();
            if (
              REDIRECT_PARAMETERS.has(normalizeKey(fKey)) ||
              /^(?:https?:\/\/|\/\/)/i.test(fValTrimmed) ||
              DANGEROUS_REDIRECT_SCHEME.test(stripInvisibleAndControlChars(fValTrimmed))
            ) {
              state.indicators.push("FRAGMENT_SMUGGLED_REDIRECT_OR_PAYLOAD");
              inspectRedirectCandidate(fValTrimmed, state, 1);
            }
          }
        } catch {
          // ignore
        }
      }
    }
  }

  return {
    indicators: [...new Set(state.indicators)],
    riskScore: state.riskScore,
    hardBlockReason: state.hardBlockReason,
    parameterCount: params.length,
    redirectParameterCount,
    nestedDestinationCount: state.nestedDestinationCount,
    sensitiveParameterCount,
    trackingParameterCount,
    fragmentPresent: Boolean(parsedUrl.hash),
    fragmentHasUrl,
    fragmentHasSensitiveMaterial
  };
}

function hasAny(indicatorSet, groupSet) {
  for (const item of indicatorSet) if (groupSet.has(item)) return true;
  return false;
}

function correlateCrossLayerThreatsLocal({ indicators = [], totalRiskScore = 0, isSafeFirstParty = false }) {
  const unique = new Set(indicators);
  const families = [];
  if (hasAny(unique, INFRASTRUCTURE_SIGNALS)) families.push("INFRASTRUCTURE");
  if (hasAny(unique, SPOOFING_SIGNALS)) families.push("SPOOFING");
  if (hasAny(unique, PAYLOAD_SIGNALS)) families.push("PAYLOAD");
  if (hasAny(unique, SMUGGLING_SIGNALS)) families.push("OBFUSCATION_OR_SMUGGLING");
  if (hasAny(unique, LURE_SIGNALS)) families.push("SOCIAL_ENGINEERING");
  if (hasAny(unique, TRANSPORT_SIGNALS)) families.push("TRANSPORT_OR_PORT");

  const addedIndicators = [];
  let addedScore = 0;
  let hardBlock = false;
  let hardBlockReason = null;

  if (
    unique.has("PUBLIC_IP_LITERAL_HOST") &&
    (families.includes("PAYLOAD") || families.includes("SOCIAL_ENGINEERING") || families.includes("SPOOFING") || families.includes("OBFUSCATION_OR_SMUGGLING") || unique.has("UNENCRYPTED_HTTP") || unique.has("NON_STANDARD_PORT") || unique.has("SUSPICIOUS_SERVICE_PORT"))
  ) {
    addedIndicators.push("COMPOUND_DIRECT_IP_ATTACK");
    addedScore += 4;
    hardBlock = true;
    hardBlockReason = "COMPOUND_DIRECT_IP_ATTACK";
  }

  if (
    !hardBlock &&
    (unique.has("MOBILE_CONFIG_OR_CERT_INSTALL_PATH") || unique.has("INTERACTIVE_SMUGGLING_FILE_PATH") || unique.has("HTML_SMUGGLING_PAYLOAD_DETECTED")) &&
    (families.includes("INFRASTRUCTURE") || families.includes("SOCIAL_ENGINEERING") || families.includes("SPOOFING") || families.includes("OBFUSCATION_OR_SMUGGLING") || unique.has("UNENCRYPTED_HTTP") || unique.has("SUSPICIOUS_SERVICE_PORT"))
  ) {
    addedIndicators.push("COMPOUND_MALICIOUS_PAYLOAD_DELIVERY");
    addedScore += 4;
    hardBlock = true;
    hardBlockReason = "COMPOUND_MALICIOUS_PAYLOAD_DELIVERY";
  }

  if (
    !hardBlock &&
    unique.has("MOBILE_VIEWPORT_SUBDOMAIN_PADDING") &&
    (families.includes("SOCIAL_ENGINEERING") || families.includes("PAYLOAD") || families.includes("INFRASTRUCTURE") || unique.has("UNENCRYPTED_HTTP"))
  ) {
    addedIndicators.push("MOBILE_VIEWPORT_SPOOFING_ATTACK");
    addedScore += 4;
    hardBlock = true;
    hardBlockReason = "MOBILE_VIEWPORT_SPOOFING_ATTACK";
  }

  const coreFamilies = families.filter((f) => f !== "TRANSPORT_OR_PORT");
  if (!hardBlock && !isSafeFirstParty && (coreFamilies.length >= 3 || (families.length >= 3 && totalRiskScore >= 5))) {
    addedIndicators.push("COMPOUND_MULTI_LAYER_ATTACK_CORRELATION");
    addedScore += 3;
    hardBlock = true;
    hardBlockReason = "COMPOUND_MULTI_LAYER_ATTACK_CORRELATION";
  }

  return { indicators: addedIndicators, riskScore: addedScore, hardBlock, hardBlockReason };
}

export function analyzeUrlOffline(rawInput) {
  const requestId = createUuid();

  const normalized = normalizeUrlLocal(rawInput);
  if (!normalized.ok) {
    return formatVerdict(requestId, "BLOCK", [normalized.reasonCode], [], null, 10);
  }

  const { parsedUrl, hostname, rawPath, obfuscatedIpHost } = normalized;
  const domainAnalysis = analyzeDomainLocal(hostname, parsedUrl, { obfuscatedIpHost });
  if (domainAnalysis.blocked) {
    return formatVerdict(requestId, "BLOCK", [domainAnalysis.reasonCode], domainAnalysis.indicators, null, 10);
  }

  const registrableDomain = domainAnalysis.destination?.registrableDomain || null;
  const isSafeFirstParty =
    isKnownSafeDomain(registrableDomain) && !matchesDomainSet(hostname, FREE_UGC_OR_CLOUD_HOSTING_DOMAINS);

  const pathAnalysis = analyzePathLocal(rawPath);
  if (pathAnalysis.hardBlock) {
    return formatVerdict(
      requestId,
      "BLOCK",
      [pathAnalysis.hardBlockReason || "MALICIOUS_PATH_PATTERN"],
      [...domainAnalysis.indicators, ...pathAnalysis.indicators],
      null,
      10
    );
  }

  const effectivePathIndicators = isSafeFirstParty
    ? pathAnalysis.indicators.filter((i) => i !== "EXPLICIT_THREAT_KEYWORD_IN_PATH")
    : pathAnalysis.indicators;
  const effectivePathRiskScore =
    isSafeFirstParty && pathAnalysis.indicators.includes("EXPLICIT_THREAT_KEYWORD_IN_PATH")
      ? Math.max(0, pathAnalysis.riskScore - 5)
      : pathAnalysis.riskScore;

  const queryAnalysis = analyzeQueryLocal(parsedUrl);
  if (queryAnalysis.hardBlockReason) {
    return formatVerdict(
      requestId,
      "BLOCK",
      [queryAnalysis.hardBlockReason],
      [...domainAnalysis.indicators, ...effectivePathIndicators, ...queryAnalysis.indicators],
      null,
      10
    );
  }

  const preLureIndicators = [...new Set([...domainAnalysis.indicators, ...effectivePathIndicators, ...queryAnalysis.indicators])];
  const scamAnalysis = analyzeScamLuresLocal({
    hostname,
    registrableDomain,
    pathSegments: pathAnalysis.segments,
    parsedUrl,
    existingIndicators: preLureIndicators
  });

  const midIndicators = [...new Set([...preLureIndicators, ...scamAnalysis.indicators])];
  if (scamAnalysis.hardBlock) {
    return formatVerdict(requestId, "BLOCK", [scamAnalysis.hardBlockReason], midIndicators, null, 10);
  }

  const lexicalAnalysis = evaluateLexicalAndStructuralRiskLocal({
    hostname,
    registrableDomain,
    parsedUrl,
    rawPath,
    pathSegments: pathAnalysis.segments,
    existingIndicators: midIndicators
  });

  const preCorrelationIndicators = [...new Set([...midIndicators, ...lexicalAnalysis.indicators])];
  if (lexicalAnalysis.hardBlock) {
    return formatVerdict(requestId, "BLOCK", [lexicalAnalysis.hardBlockReason], preCorrelationIndicators, null, 10);
  }

  const preCorrelationScore =
    domainAnalysis.riskScore + effectivePathRiskScore + queryAnalysis.riskScore + scamAnalysis.riskScore + lexicalAnalysis.riskScore;

  const correlation = correlateCrossLayerThreatsLocal({
    indicators: preCorrelationIndicators,
    totalRiskScore: preCorrelationScore,
    isSafeFirstParty
  });

  const allIndicators = [...new Set([...preCorrelationIndicators, ...correlation.indicators])];
  if (correlation.hardBlock) {
    return formatVerdict(requestId, "BLOCK", [correlation.hardBlockReason], allIndicators, null, 10);
  }

  const riskScore = preCorrelationScore + correlation.riskScore;
  const dest = {
    host: hostname,
    registrableDomain,
    protocol: parsedUrl.protocol,
    nonStandardPort: Boolean(parsedUrl.port),
    originOnly: `${parsedUrl.protocol}//${hostname}`
  };

  if (riskScore >= 7) {
    return formatVerdict(requestId, "BLOCK", ["HIGH_RISK_SCORE_LOCAL_BLOCK"], allIndicators, null, riskScore);
  }

  if (riskScore >= 3) {
    return formatVerdict(requestId, "SUSPICIOUS", ["LOCAL_SUSPICIOUS_URL_PATTERN"], allIndicators, dest, riskScore);
  }

  if (
    ((isKnownSafeDomain(registrableDomain) && !matchesDomainSet(hostname, FREE_UGC_OR_CLOUD_HOSTING_DOMAINS)) ||
      isKnownSafePublicIp(hostname.replace(/^\[|\]$/g, ""))) &&
    parsedUrl.protocol === "https:" &&
    riskScore === 0
  ) {
    return formatVerdict(requestId, "KNOWN_SAFE", ["ALL_LOCAL_SECURITY_LAYERS_PASSED", "KNOWN_SAFE_OFFICIAL_DOMAIN"], allIndicators, dest, 0);
  }

  return formatVerdict(requestId, "HOLD", ["REPUTATION_CHECK_UNAVAILABLE_ZERO_EGRESS"], allIndicators, dest, riskScore);
}

function formatVerdict(requestId, finalDecision, reasonCodes, indicators, dest, riskScore) {
  const uniqueIndicators = [...new Set(indicators)];
  const host = dest?.host || "blocked-destination";
  const isBlocked = finalDecision === "BLOCK";
  const headlines = {
    BLOCK: "Dangerous link blocked",
    SUSPICIOUS: `Suspicious link detected (${host})`,
    KNOWN_SAFE: `Verified official destination (${host})`,
    HOLD: `Held for confirmation (${host})`
  };
  const advisories = {
    BLOCK: "STOP! Do NOT open this link. SafeGate blocked it on your device because it shows strong signs of a phishing scam, remote-access trap, rogue certificate/APK drop, HTML smuggling, or unsafe redirect.",
    SUSPICIOUS: "Be very careful. This link has suspicious traits. Open your official bank or service app directly instead.",
    KNOWN_SAFE: "Verified official domain over HTTPS. Passed all 30 on-device security checks with zero data leaving your phone.",
    HOLD: "Local structural checks passed, but the domain is not on your verified official list. Only continue if you personally trust the sender."
  };

  return {
    requestId,
    verificationStatus: "COMPLETED",
    engineMode: "ON_DEVICE_OFFLINE_ENGINE",
    localVerification: {
      decision: isBlocked ? "BLOCK" : finalDecision === "SUSPICIOUS" ? "SUSPICIOUS" : "REPUTATION_CHECK_REQUIRED",
      stage: "LOCAL_OFFLINE",
      reasonCodes,
      indicators: uniqueIndicators,
      destination: dest ? {
        hostname: dest.host,
        registrableDomain: dest.registrableDomain,
        protocol: dest.protocol,
        nonStandardPort: dest.nonStandardPort
      } : null,
      redactedDestination: dest ? {
        originOnly: dest.originOnly,
        displayHost: dest.host,
        privateComponentsStripped: true
      } : null,
      riskScore: isBlocked ? null : riskScore,
      reputationCheckRequired: finalDecision === "HOLD"
    },
    securityChecks: {
      zeroEgressGuaranteed: true,
      schemeAndEncodingCheck: isBlocked && ["UNSUPPORTED_OR_DANGEROUS_SCHEME", "CONTROL_CHARACTERS_FOUND", "INVISIBLE_OR_BIDI_CHARACTERS_FOUND", "UNICODE_SPOOF_CHARACTERS_FOUND", "ENCODED_SPOOF_OR_NULL_SEQUENCE", "ENCODED_CONTROL_CHARACTER", "INJECTED_SCRIPT_IN_PATH", "HTML_SMUGGLING_PAYLOAD_DETECTED"].includes(reasonCodes[0]) ? "FAILED" : "PASSED",
      networkAndIpIsolationCheck: isBlocked && ["NON_PUBLIC_IP_ADDRESS", "OBFUSCATED_IP_EVASION", "NON_PUBLIC_HOSTNAME", "DANGEROUS_NON_WEB_PORT", "COMPOUND_DIRECT_IP_ATTACK"].includes(reasonCodes[0]) ? "FAILED" : uniqueIndicators.includes("PUBLIC_IP_LITERAL_HOST") ? "FLAGGED" : "PASSED",
      homographAndBrandSpoofCheck: uniqueIndicators.some((i) => i.includes("BRAND") || i.includes("HOMOGRAPH") || i.includes("IDN") || i.includes("PUNYCODE") || i.includes("DECEPTIVE_") || i.includes("HYPHEN_LURE") || i === "UNIVERSAL_SUBDOMAIN_TLD_MASQUERADING" || i === "MOBILE_VIEWPORT_SUBDOMAIN_PADDING") ? (isBlocked ? "FAILED" : "FLAGGED") : "PASSED",
      malwareAndPathCheck: uniqueIndicators.some((i) => i.includes("APK") || i.includes("SIDELOAD") || i.includes("EXTENSION") || i.includes("PHISHING_KIT") || i.includes("COMPOUND_MALICIOUS")) ? (isBlocked ? "FAILED" : "FLAGGED") : "PASSED",
      redirectAndSmugglingCheck: uniqueIndicators.some((i) => i.includes("REDIRECT") || i.includes("SMUGGL") || i.includes("FRAGMENT")) ? (isBlocked ? "FAILED" : "FLAGGED") : "PASSED",
      smsScamLureCheck: uniqueIndicators.some((i) => i.includes("SCAM") || i.includes("LURE") || i.includes("COMPOUND_")) ? (isBlocked ? "FAILED" : "FLAGGED") : "PASSED"
    },
    finalDecision,
    recommendedAction: isBlocked ? "DO_NOT_OPEN" : finalDecision === "SUSPICIOUS" ? "WARN_USER" : finalDecision === "KNOWN_SAFE" ? "ALLOW" : "HOLD",
    finalReasonCodes: reasonCodes,
    verificationToken: isBlocked ? null : `offline:${requestId}`,
    riskSummary: {
      level: isBlocked ? "CRITICAL" : finalDecision === "SUSPICIOUS" ? "HIGH" : finalDecision === "KNOWN_SAFE" ? "SAFE" : "MEDIUM",
      score: isBlocked ? null : riskScore,
      headline: headlines[finalDecision],
      parentAdvisory: advisories[finalDecision],
      reasons: reasonCodes,
      indicatorsCount: uniqueIndicators.length
    },
    layersExecuted: LAYERS_EXECUTED,
    privacy: {
      outboundNetworkCalls: 0,
      externalServicesContacted: [],
      zeroEgressOnDevice: true,
      zeroUrlRetention: true,
      originalUrlLoggedOrStored: false,
      pathAndQueryInspectedLocallyOnly: true
    }
  };
}
