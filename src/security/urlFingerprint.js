import ipaddr from "ipaddr.js";

const MAX_URL_LENGTH = 8192;

function fullyUnescapeComponent(value) {
  let current = value;

  for (let i = 0; i < 64; i++) {
    if (!/%[0-9a-f]{2}/i.test(current)) {
      return current;
    }

    try {
      const next = current.replace(
        /(?:%[0-9a-f]{2})+/gi,
        (sequence) => decodeURIComponent(sequence)
      );

      if (next === current) {
        return current;
      }

      current = next;
    } catch {
      throw new Error("Invalid percent encoding");
    }
  }

  throw new Error("Excessively nested URL encoding");
}

function normalizeHostname(hostname) {
  let host = hostname.replace(/^\[|\]$/g, "");

  if (ipaddr.isValid(host)) {
    const address = ipaddr.parse(host);

    if (address.kind() === "ipv4") {
      return address.toString();
    }

    if (address.isIPv4MappedAddress()) {
      return address.toIPv4Address().toString();
    }

    if (address.kind() === "ipv6") {
      return `[${address.toString().toLowerCase()}]`;
    }
  }

  host = host
    .replace(/^\.+|\.+$/g, "")
    .replace(/\.{2,}/g, ".")
    .toLowerCase();

  if (!host) {
    throw new Error("Invalid hostname");
  }

  return host;
}

export function canonicalizeUrl(input) {
  if (
    typeof input !== "string" ||
    input.length === 0 ||
    input.length > MAX_URL_LENGTH
  ) {
    throw new Error("Invalid URL");
  }

  const cleaned = input.replace(/[\t\r\n]/g, "");

  let parsed;
  try {
    parsed = new URL(cleaned);
  } catch {
    throw new Error("Malformed URL");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Unsupported URL protocol");
  }

  if (parsed.username || parsed.password) {
    throw new Error("URL credentials are not allowed");
  }

  const hostname = normalizeHostname(parsed.hostname);
  let pathname = fullyUnescapeComponent(parsed.pathname || "/");
  const search = fullyUnescapeComponent(parsed.search || "");

  pathname = pathname.replace(/\/{2,}/g, "/");
  if (!pathname.startsWith("/")) {
    pathname = `/${pathname}`;
  }

  return {
    hostname,
    pathname,
    search,
    originOnly: `${parsed.protocol}//${hostname}`
  };
}

export async function createDeviceUrlFingerprint(input) {
  const canonical = canonicalizeUrl(input);
  const parsed = new URL(input.trim());

  const fingerprintInput = [
    parsed.protocol,
    parsed.host.toLowerCase(),
    canonical.pathname,
    canonical.search
  ].join("\0");

  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(fingerprintInput)
  );

  return {
    fingerprint: Array.from(new Uint8Array(digest))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join(""),
    originOnly: canonical.originOnly
  };
}
