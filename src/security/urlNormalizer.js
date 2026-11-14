const MAX_URL_LENGTH = 4096;

const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/;

const MALFORMED_PERCENT_ENCODING = /%(?![0-9a-fA-F]{2})/;

function reject(reasonCode) {
    return {
        ok: false,
        reasonCode
    };
}

function normalizeUrl(input) {

    if (typeof input !== "string") {
        return reject("INVALID_URL_TYPE");
    }

    // Never silently remove control characters.
    if (CONTROL_CHARACTERS.test(input)) {
        return reject("CONTROL_CHARACTERS_FOUND");
    }

    const candidate = input.trim();

    if (!candidate) {
        return reject("EMPTY_URL");
    }

    if (candidate.length > MAX_URL_LENGTH) {
        return reject("URL_TOO_LONG");
    }

    // Reject embedded whitespace rather than guessing how it should parse.
    if (/\s/.test(candidate)) {
        return reject("WHITESPACE_IN_URL");
    }

    // Prevent differences between URL parsers.
    if (candidate.includes("\\")) {
        return reject("BACKSLASH_IN_URL");
    }

    // Reject malformed percent sequences.
    if (MALFORMED_PERCENT_ENCODING.test(candidate)) {
        return reject("MALFORMED_PERCENT_ENCODING");
    }

    // Require an explicit HTTP or HTTPS URL.
    if (!/^https?:\/\//i.test(candidate)) {
        return reject("ABSOLUTE_HTTP_URL_REQUIRED");
    }

    let parsedUrl;

    try {
        parsedUrl = new URL(candidate);
    } catch {
        return reject("MALFORMED_URL");
    }

    if (
        parsedUrl.protocol !== "http:" &&
        parsedUrl.protocol !== "https:"
    ) {
        return reject("UNSUPPORTED_PROTOCOL");
    }

    if (parsedUrl.username || parsedUrl.password) {
        return reject("URL_CONTAINS_CREDENTIALS");
    }

    const hostname = parsedUrl.hostname
        .toLowerCase()
        .replace(/\.$/, "");

    if (!hostname || hostname.length > 253) {
        return reject("INVALID_HOSTNAME");
    }

    // Keep the original path privately for encoding inspection.
    // Do not return it in API responses or logs.
    const authorityMatch = candidate.match(
        /^https?:\/\/[^/?#]*(\/[^?#]*)?/i
    );

    const rawPath = authorityMatch?.[1] || "/";

    return {
        ok: true,
        parsedUrl,
        hostname,
        rawPath
    };
}

module.exports = {
    normalizeUrl
};