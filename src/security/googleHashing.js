
import { getDomain } from "tldts";
import ipaddr from "ipaddr.js";

const MAX_URL_LENGTH = 8192;
const MAX_HASH_EXPRESSIONS = 30;

const encoder = new TextEncoder();

/**
 * Repeatedly decode percent-encoded sequences.
 */
function fullyUnescapeComponent(value) {
    let current = value;

    for (let i = 0; i < 64; i++) {
        if (!/%[0-9a-f]{2}/i.test(current)) {
            return current;
        }

        try {
            const next = current.replace(
                /(?:%[0-9a-f]{2})+/gi,
                sequence => decodeURIComponent(sequence)
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

/**
 * Escape canonical expressions according to the
 * current SafeGate backend implementation.
 */
function escapeForHash(value) {
    let result = "";

    for (const character of value) {
        const codePoint = character.codePointAt(0);

        if (
            codePoint <= 32 ||
            codePoint >= 127 ||
            character === "#" ||
            character === "%"
        ) {
            for (const byte of encoder.encode(character)) {
                result +=
                    "%" +
                    byte.toString(16).toUpperCase().padStart(2, "0");
            }
        } else {
            result += character;
        }
    }

    return result;
}

/**
 * Normalize hostname and IP address.
 */
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
            const nat64Prefix = ipaddr.IPv6.parse("64:ff9b::");

            if (address.match(nat64Prefix, 96)) {
                const bytes = address.toByteArray().slice(12);

                return ipaddr.IPv4
                    .fromByteArray(bytes)
                    .toString();
            }

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

/**
 * Canonicalize HTTP/HTTPS URLs locally.
 *
 * Never sends the input URL to the relay.
 */
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

    let pathname = fullyUnescapeComponent(
        parsed.pathname || "/"
    );

    const search = fullyUnescapeComponent(
        parsed.search || ""
    );

    pathname = pathname.replace(/\/{2,}/g, "/");

    if (!pathname.startsWith("/")) {
        pathname = `/${pathname}`;
    }

    return {
        hostname,
        pathname,
        search,
        canonicalExpression: escapeForHash(
            `${hostname}${pathname}${search}`
        )
    };
}

/**
 * Generate hostname candidates.
 */
export function buildHostCandidates(hostname) {
    const unbracketed = hostname.replace(/^\[|\]$/g, "");

    if (ipaddr.isValid(unbracketed)) {
        return [hostname];
    }

    const registrableDomain = getDomain(hostname) || hostname;

    const hostnameParts = hostname.split(".");
    const domainParts = registrableDomain.split(".");

    const leadingParts = hostnameParts.slice(
        0,
        hostnameParts.length - domainParts.length
    );

    const candidates = [registrableDomain];

    for (
        let count = 1;
        count <= Math.min(3, leadingParts.length);
        count++
    ) {
        candidates.push(
            [
                ...leadingParts.slice(-count),
                ...domainParts
            ].join(".")
        );
    }

    candidates.push(hostname);

    return [...new Set(candidates)].slice(0, 5);
}

/**
 * Generate path candidates.
 */
export function buildPathCandidates(pathname, search) {
    const candidates = [
        `${pathname}${search}`,
        pathname,
        "/"
    ];

    const segments = pathname
        .split("/")
        .filter(Boolean);

    for (
        let count = 1;
        count <= Math.min(4, segments.length - 1);
        count++
    ) {
        candidates.push(
            `/${segments.slice(0, count).join("/")}/`
        );
    }

    return [...new Set(candidates)].slice(0, 6);
}

/**
 * Convert four bytes to Base64 without Node.js Buffer.
 */
function bytesToBase64(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

/**
 * Convert a SHA-256 result into lowercase hexadecimal.
 */
function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

/**
 * Generate SHA-256 hashes on the device.
 *
 * Returns:
 * - fullHashes: kept locally.
 * - hashPrefixes: safe lookup candidates sent to backend.
 */
export async function createGoogleHashData(input) {
    const canonical = canonicalizeUrl(input);

    const hosts = buildHostCandidates(canonical.hostname);

    const paths = buildPathCandidates(
        canonical.pathname,
        canonical.search
    );

    const expressions = [];

    for (const host of hosts) {
        for (const path of paths) {
            expressions.push(`${host}${path}`);
        }
    }

    const uniqueExpressions = [
        ...new Set(expressions)
    ].slice(0, MAX_HASH_EXPRESSIONS);

    const fullHashes = new Set();
    const prefixes = new Set();

    for (const expression of uniqueExpressions) {
        const escapedExpression = escapeForHash(expression);

        const hashBuffer = await crypto.subtle.digest(
            "SHA-256",
            encoder.encode(escapedExpression)
        );

        const hashBytes = new Uint8Array(hashBuffer);

        // Full hash never leaves the device.
        fullHashes.add(bytesToHex(hashBytes));

        // Only the first four bytes are sent to the relay.
        const prefix = hashBytes.slice(0, 4);

        prefixes.add(bytesToBase64(prefix));
    }

    return {
        fullHashes: [...fullHashes],
        hashPrefixes: [...prefixes]
    };
}

/**
 * Compare Google's returned full-hash candidates
 * against full hashes generated locally.
 */
export function matchGoogleFullHashes(
    localFullHashes,
    googleFullHashes
) {
    const localSet = new Set(
        localFullHashes.map(hash => hash.toLowerCase())
    );

    const matches = [];

    for (const record of googleFullHashes) {
        if (!record || typeof record.fullHash !== "string") {
            continue;
        }

        let decoded;

        try {
            decoded = atob(record.fullHash);
        } catch {
            continue;
        }

        const bytes = Uint8Array.from(
            decoded,
            character => character.charCodeAt(0)
        );

        if (bytes.length !== 32) {
            continue;
        }

        const hex = bytesToHex(bytes);

        if (!localSet.has(hex)) {
            continue;
        }

        const details = Array.isArray(record.fullHashDetails)
            ? record.fullHashDetails
            : [];

        for (const detail of details) {
            matches.push({
                threatType: detail.threatType,
                attributes: detail.attributes || []
            });
        }
    }

    return matches;
}
