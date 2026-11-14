"use strict";

/**
 * pathAnalyzer.js
 *
 * Deep local structural inspection of URL path segments.
 * No path content is ever returned or logged.
 */

const MOBILE_INSTALLER_EXTENSIONS = new Set([
  "apk", "aab", "xapk", "apks", "ipa"
]);

const EXECUTABLE_EXTENSIONS = new Set([
  "exe", "msi", "apk", "aab", "xapk", "apks", "bat", "cmd", "com",
  "scr", "ps1", "sh", "jar", "vbs", "hta", "dmg", "pkg",
  "deb", "rpm", "iso", "pif", "app", "ipa", "lnk", "wsf"
]);

const ARCHIVE_EXTENSIONS = new Set([
  "zip", "rar", "7z", "tar", "gz", "cab"
]);

const DECOY_DOCUMENT_EXTENSIONS = new Set([
  "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "mp4"
]);

function labelEntropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const ch of value) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function decodeRepeatedly(value, maxPasses = 2) {
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

const SECRET_ROUTE_WORDS = new Set([
  "token", "access-token", "reset", "reset-password",
  "verify", "verification", "magic-link", "invite",
  "invitation", "session", "authorization", "assertion",
  "ticket", "sso"
]);

function isSensitivePathSegment(segment, previousSegment = "") {
  const decoded = decodeRepeatedly(String(segment || ""), 3);
  const value = decoded.value;
  const lower = value.toLowerCase();
  const prev = String(previousSegment || "").toLowerCase();

  if (/^eyj[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}$/i.test(value)) return true;
  if (/^[a-f0-9]{32,}$/i.test(value)) return true;
  if (/^[a-z0-9_-]{40,}$/i.test(value) && /[a-z]/i.test(value) && /[0-9]/.test(value)) return true;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) return true;
  if (value.length >= 64 && labelEntropy(value) >= 3.5) return true;
  if (SECRET_ROUTE_WORDS.has(prev) && value.length >= 12) return true;
  if (/^(?:token|secret|password|code|auth|session|ticket)=[^/]+$/i.test(lower)) return true;

  return false;
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

function analyzePath(rawPath, _pathname) {
  const indicators = [];
  let riskScore = 0;
  let hardBlock = false;
  let hardBlockReason = null;

  const decoded = decodeRepeatedly(rawPath, 2);
  const decodedPath = decoded.value;

  if (decoded.decodingFailed) {
    indicators.push("UNDECODABLE_PATH_ENCODING");
    riskScore += 2;
  }

  if (decoded.additionalDecodes > 0) {
    indicators.push("REPEATED_PATH_ENCODING");
    riskScore += 1;
  }

  // Encoded null / LF / CR / TAB — hard block
  if (
    /%(?:00|0a|0d|09)/i.test(rawPath) ||
    /%(?:00|0a|0d|09)/i.test(decodedPath) ||
    /[\u0000-\u001F\u007F]/.test(decodedPath)
  ) {
    indicators.push("ENCODED_CONTROL_CHARACTER");
    riskScore += 5;
    hardBlock = true;
    hardBlockReason = "ENCODED_CONTROL_CHARACTER";
  }

  // Encoded XSS / HTML script injection in path
  if (/<script\b|javascript:|onerror\s*=|onload\s*=/i.test(decodedPath)) {
    indicators.push("INJECTED_SCRIPT_IN_PATH");
    riskScore += 6;
    hardBlock = true;
    hardBlockReason = hardBlockReason || "INJECTED_SCRIPT_IN_PATH";
  }

  // Path traversal
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
    if (isSensitivePathSegment(segments[i], segments[i - 1] || "")) {
      sensitivePathSegmentCount++;
    }
  }

  if (sensitivePathSegmentCount > 0) {
    indicators.push("SENSITIVE_PATH_SEGMENT_DETECTED");
  }

  if (
    /\b(?:phishing|malware|ransomware|trojan|keylogger|spyware|infostealer|credharvest|phishkit)\b/i.test(
      decodedPath
    )
  ) {
    indicators.push("EXPLICIT_THREAT_KEYWORD_IN_PATH");
    riskScore += 5;
  }

  const finalSegment = segments.at(-1) || "";
  const extensionMatch = finalSegment.match(/\.([a-z0-9]{1,10})$/i);
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

module.exports = {
  analyzePath,
  isSensitivePathSegment,
  hasDoubleExtensionMasquerade
};
