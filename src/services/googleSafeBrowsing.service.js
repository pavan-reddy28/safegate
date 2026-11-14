
const crypto = require("node:crypto");
const { createGoogleHashData } = require("../security/googleUrlHashing");

const GOOGLE_ENDPOINT =
    "https://safebrowsing.googleapis.com/v5/hashes:search";

const REQUEST_TIMEOUT_MS = 10000;
const MAX_CACHE_ENTRIES = 500;
const MAX_CACHE_DURATION_SECONDS = 86400;
const MAX_RESPONSE_BYTES = 1024 * 1024;

// In-memory cache. No original URLs or raw hash prefixes are stored.
const responseCache = new Map();

const THREAT_TYPES = {
    1: "MALWARE",
    2: "SOCIAL_ENGINEERING",
    3: "UNWANTED_SOFTWARE",
    4: "POTENTIALLY_HARMFUL_APPLICATION"
};

const THREAT_ATTRIBUTES = {
    1: "CANARY",
    2: "FRAME_ONLY"
};

const VALID_THREAT_NAMES = new Set(
    Object.values(THREAT_TYPES)
);

/* =========================================================
   PROTOBUF DECODING
========================================================= */

/**
 * Read a protobuf varint.
 */
function readVarint(buffer, offset) {
    let value = 0n;

    for (let index = 0; index < 10; index++) {
        if (offset >= buffer.length) {
            throw new Error("Truncated protobuf varint");
        }

        const byte = buffer[offset++];

        if (index === 9 && byte > 1) {
            throw new Error("Invalid protobuf varint");
        }

        value |= BigInt(byte & 0x7f) << BigInt(index * 7);

        if ((byte & 0x80) === 0) {
            return { value, offset };
        }
    }

    throw new Error("Invalid protobuf varint");
}

/**
 * Read a length-delimited protobuf field.
 */
function readBytes(buffer, offset) {
    const lengthResult = readVarint(buffer, offset);
    const length = Number(lengthResult.value);

    if (
        !Number.isSafeInteger(length) ||
        length < 0 ||
        length > buffer.length - lengthResult.offset
    ) {
        throw new Error("Invalid protobuf field length");
    }

    const start = lengthResult.offset;
    const end = start + length;

    return {
        value: buffer.subarray(start, end),
        offset: end
    };
}

/**
 * Read a protobuf field key.
 */
function readFieldKey(buffer, offset) {
    const result = readVarint(buffer, offset);
    const key = Number(result.value);

    const fieldNumber = Math.floor(key / 8);
    const wireType = key & 7;

    if (
        !Number.isSafeInteger(key) ||
        fieldNumber <= 0
    ) {
        throw new Error("Invalid protobuf field key");
    }

    return {
        fieldNumber,
        wireType,
        offset: result.offset
    };
}

/**
 * Skip an unknown protobuf field.
 */
function skipField(buffer, offset, wireType) {
    switch (wireType) {
        case 0:
            return readVarint(buffer, offset).offset;

        case 1:
            if (offset + 8 > buffer.length) {
                throw new Error("Invalid fixed64 field");
            }
            return offset + 8;

        case 2:
            return readBytes(buffer, offset).offset;

        case 5:
            if (offset + 4 > buffer.length) {
                throw new Error("Invalid fixed32 field");
            }
            return offset + 4;

        default:
            throw new Error("Unsupported protobuf wire type");
    }
}

/**
 * Decode packed repeated protobuf enum values.
 */
function decodePackedEnums(buffer) {
    const values = [];
    let offset = 0;

    while (offset < buffer.length) {
        const result = readVarint(buffer, offset);
        offset = result.offset;

        if (result.value > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error("Invalid protobuf enum");
        }

        values.push(Number(result.value));
    }

    return values;
}

/* =========================================================
   DURATION DECODING
========================================================= */

/**
 * Decode Google protobuf Duration.
 *
 * field 1 = seconds
 * field 2 = nanos
 */
function decodeDuration(buffer) {
    let seconds = 0n;
    let nanos = 0n;

    let offset = 0;

    while (offset < buffer.length) {
        const field = readFieldKey(buffer, offset);
        offset = field.offset;

        if (
            field.fieldNumber === 1 ||
            field.fieldNumber === 2
        ) {
            if (field.wireType !== 0) {
                throw new Error("Invalid duration field");
            }

            const result = readVarint(buffer, offset);
            offset = result.offset;

            if (field.fieldNumber === 1) {
                seconds = result.value;
            } else {
                nanos = result.value;
            }
        } else {
            offset = skipField(
                buffer,
                offset,
                field.wireType
            );
        }
    }

    if (
        seconds > BigInt(MAX_CACHE_DURATION_SECONDS) ||
        nanos < 0n ||
        nanos >= 1000000000n
    ) {
        throw new Error("Invalid Google cache duration");
    }

    const duration =
        Number(seconds) + Number(nanos) / 1e9;

    if (
        !Number.isFinite(duration) ||
        duration < 0 ||
        duration > MAX_CACHE_DURATION_SECONDS
    ) {
        throw new Error("Invalid Google cache duration");
    }

    return duration;
}

/**
 * Decode JSON duration format, e.g. 300s or 3.5s.
 */
function parseJsonDuration(value) {
    if (typeof value !== "string") {
        throw new Error("Missing Google cache duration");
    }

    const match = value.match(
        /^(\d+(?:\.\d{1,9})?)s$/
    );

    if (!match) {
        throw new Error("Invalid Google cache duration");
    }

    const seconds = Number(match[1]);

    if (
        !Number.isFinite(seconds) ||
        seconds < 0 ||
        seconds > MAX_CACHE_DURATION_SECONDS
    ) {
        throw new Error("Invalid Google cache duration");
    }

    return seconds;
}

/* =========================================================
   THREAT DETAIL DECODING
========================================================= */

/**
 * Decode FullHashDetail.
 *
 * field 1 = threat type enum
 * field 2 = repeated attributes enum
 */
function decodeProtobufThreatDetail(buffer) {
    let threatType = null;
    const attributeValues = [];

    let invalid = false;
    let offset = 0;

    while (offset < buffer.length) {
        const field = readFieldKey(buffer, offset);
        offset = field.offset;

        if (field.fieldNumber === 1) {
            if (field.wireType !== 0) {
                throw new Error("Invalid threat type field");
            }

            const result = readVarint(buffer, offset);
            offset = result.offset;

            if (result.value > BigInt(Number.MAX_SAFE_INTEGER)) {
                invalid = true;
            } else {
                threatType = Number(result.value);
            }
        } else if (field.fieldNumber === 2) {
            if (field.wireType === 0) {
                const result = readVarint(buffer, offset);
                offset = result.offset;

                if (result.value > BigInt(Number.MAX_SAFE_INTEGER)) {
                    invalid = true;
                } else {
                    attributeValues.push(Number(result.value));
                }
            } else if (field.wireType === 2) {
                const result = readBytes(buffer, offset);
                offset = result.offset;

                attributeValues.push(
                    ...decodePackedEnums(result.value)
                );
            } else {
                throw new Error("Invalid threat attribute field");
            }
        } else {
            offset = skipField(
                buffer,
                offset,
                field.wireType
            );
        }
    }

    const threatName = THREAT_TYPES[threatType];

    if (!threatName) {
        invalid = true;
    }

    const attributes = [];

    for (const value of attributeValues) {
        const name = THREAT_ATTRIBUTES[value];

        // Unknown attributes invalidate the entire detail.
        if (!name) {
            invalid = true;
            break;
        }

        attributes.push(name);
    }

    if (invalid) {
        return null;
    }

    // These attributes are not enforceable for ordinary
    // top-level link navigation.
    if (
        attributes.includes("CANARY") ||
        attributes.includes("FRAME_ONLY")
    ) {
        return null;
    }

    return {
        threatType: threatName,
        attributes
    };
}

/**
 * Decode FullHash.
 *
 * field 1 = 32-byte SHA-256 hash
 * field 2 = repeated FullHashDetail
 */
function decodeProtobufFullHash(buffer) {
    let fullHash = null;
    const fullHashDetails = [];

    let offset = 0;

    while (offset < buffer.length) {
        const field = readFieldKey(buffer, offset);
        offset = field.offset;

        if (field.fieldNumber === 1) {
            if (field.wireType !== 2 || fullHash !== null) {
                throw new Error("Invalid full hash field");
            }

            const result = readBytes(buffer, offset);
            offset = result.offset;

            fullHash = result.value;
        } else if (field.fieldNumber === 2) {
            if (field.wireType !== 2) {
                throw new Error("Invalid full hash detail field");
            }

            const result = readBytes(buffer, offset);
            offset = result.offset;

            const detail = decodeProtobufThreatDetail(
                result.value
            );

            if (detail) {
                fullHashDetails.push(detail);
            }
        } else {
            offset = skipField(
                buffer,
                offset,
                field.wireType
            );
        }
    }

    if (!fullHash || fullHash.length !== 32) {
        throw new Error("Invalid Google SHA-256 full hash");
    }

    return {
        fullHashHex: fullHash.toString("hex"),
        threatDetails: fullHashDetails
    };
}

/**
 * Decode SearchHashesResponse.
 *
 * field 1 = repeated FullHash
 * field 2 = cacheDuration
 */
function decodeGoogleProtobuf(buffer) {
    const googleRecords = [];

    let cacheDurationSeconds = null;
    let offset = 0;

    while (offset < buffer.length) {
        const field = readFieldKey(buffer, offset);
        offset = field.offset;

        if (field.fieldNumber === 1) {
            if (field.wireType !== 2) {
                throw new Error("Invalid full hashes field");
            }

            const result = readBytes(buffer, offset);
            offset = result.offset;

            googleRecords.push(
                decodeProtobufFullHash(result.value)
            );
        } else if (field.fieldNumber === 2) {
            if (field.wireType !== 2) {
                throw new Error("Invalid cache duration field");
            }

            const result = readBytes(buffer, offset);
            offset = result.offset;

            cacheDurationSeconds = decodeDuration(
                result.value
            );
        } else {
            offset = skipField(
                buffer,
                offset,
                field.wireType
            );
        }
    }

    if (cacheDurationSeconds === null) {
        throw new Error("Google response has no cache duration");
    }

    return {
        googleRecords,
        cacheDurationSeconds
    };
}

/* =========================================================
   JSON RESPONSE DECODING
========================================================= */

/**
 * Convert Base64 SHA-256 full hash into hex.
 */
function decodeJsonFullHash(value) {
    if (
        typeof value !== "string" ||
        !/^[A-Za-z0-9+/]{43}=$/.test(value)
    ) {
        return null;
    }

    const buffer = Buffer.from(value, "base64");

    if (
        buffer.length !== 32 ||
        buffer.toString("base64") !== value
    ) {
        return null;
    }

    return buffer.toString("hex");
}

/**
 * Validate JSON FullHashDetail.
 */
function validateJsonThreatDetails(details) {
    if (!Array.isArray(details)) {
        return [];
    }

    const results = [];

    for (const detail of details) {
        if (
            !detail ||
            !VALID_THREAT_NAMES.has(detail.threatType)
        ) {
            continue;
        }

        const attributes = detail.attributes ?? [];

        if (!Array.isArray(attributes)) {
            continue;
        }

        const validAttributes = attributes.every(
            attribute =>
                attribute === "CANARY" ||
                attribute === "FRAME_ONLY"
        );

        if (!validAttributes) {
            continue;
        }

        if (
            attributes.includes("CANARY") ||
            attributes.includes("FRAME_ONLY")
        ) {
            continue;
        }

        results.push({
            threatType: detail.threatType,
            attributes
        });
    }

    return results;
}

/**
 * Decode Google's JSON response.
 */
function decodeGoogleJson(buffer) {
    let body;

    try {
        body = JSON.parse(buffer.toString("utf8"));
    } catch {
        throw new Error("Invalid Google JSON response");
    }

    if (!body || typeof body !== "object") {
        throw new Error("Invalid Google JSON structure");
    }

    // Empty repeated fields may be omitted in JSON.
    const fullHashes = body.fullHashes ?? [];

    if (!Array.isArray(fullHashes)) {
        throw new Error("Invalid Google fullHashes field");
    }

    const googleRecords = [];

    for (const item of fullHashes) {
        const fullHashHex = decodeJsonFullHash(
            item?.fullHash
        );

        if (!fullHashHex) {
            continue;
        }

        googleRecords.push({
            fullHashHex,
            threatDetails: validateJsonThreatDetails(
                item.fullHashDetails
            )
        });
    }

    return {
        googleRecords,
        cacheDurationSeconds: parseJsonDuration(
            body.cacheDuration
        )
    };
}

/**
 * Select the response decoder based on content type.
 */
function decodeGoogleResponse(contentType, buffer) {
    if (contentType.includes("application/json")) {
        return decodeGoogleJson(buffer);
    }

    if (
        contentType.includes("application/x-protobuf") ||
        contentType.includes("application/protobuf")
    ) {
        return decodeGoogleProtobuf(buffer);
    }

    throw new Error("Unsupported Google response format");
}

/* =========================================================
   CACHE
========================================================= */

function getCacheKey(prefixes) {
    return crypto
        .createHash("sha256")
        .update([...prefixes].sort().join("|"))
        .digest("hex");
}

function matchLocalHashes(localFullHashes, googleRecords) {
    const localSet = new Set(localFullHashes);
    const matches = [];

    for (const record of googleRecords) {
        if (!localSet.has(record.fullHashHex)) {
            continue;
        }

        for (const detail of record.threatDetails) {
            matches.push({
                threatType: detail.threatType,
                attributes: detail.attributes
            });
        }
    }

    return matches;
}

function getCachedResponse(cacheKey, localFullHashes) {
    const entry = responseCache.get(cacheKey);

    if (!entry) {
        return null;
    }

    if (Date.now() >= entry.expiresAt) {
        responseCache.delete(cacheKey);
        return null;
    }

    // Refresh insertion order for LRU-style eviction.
    responseCache.delete(cacheKey);
    responseCache.set(cacheKey, entry);

    return matchLocalHashes(
        localFullHashes,
        entry.googleRecords
    );
}

function saveCachedResponse(
    cacheKey,
    googleRecords,
    durationSeconds
) {
    if (durationSeconds <= 0) {
        return;
    }

    while (responseCache.size >= MAX_CACHE_ENTRIES) {
        const oldestKey = responseCache.keys().next().value;

        if (oldestKey === undefined) {
            break;
        }

        responseCache.delete(oldestKey);
    }

    responseCache.set(cacheKey, {
        googleRecords,
        expiresAt: Date.now() + durationSeconds * 1000
    });
}

/* =========================================================
   MAIN GOOGLE SAFE BROWSING SERVICE
========================================================= */

async function checkGoogleReputation(inputUrl) {
    let hashData;

    try {
        // All URL processing and full hashing happens locally.
        hashData = createGoogleHashData(inputUrl);
    } catch {
        return {
            status: "INVALID_URL",
            threatMatches: [],
            cacheHit: false
        };
    }

    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

    if (!apiKey) {
        return {
            status: "NOT_CONFIGURED",
            threatMatches: [],
            cacheHit: false
        };
    }

    const prefixes = [...new Set(hashData.hashPrefixes)];

    if (
        prefixes.length === 0 ||
        prefixes.length > 30 ||
        prefixes.some(
            prefix => Buffer.from(prefix, "base64").length !== 4
        )
    ) {
        return {
            status: "INVALID_HASH_DATA",
            threatMatches: [],
            cacheHit: false
        };
    }

    const cacheKey = getCacheKey(prefixes);

    const cachedMatches = getCachedResponse(
        cacheKey,
        hashData.fullHashes
    );

    if (cachedMatches !== null) {
        return {
            status: cachedMatches.length > 0
                ? "THREAT_FOUND"
                : "NO_THREAT_FOUND",
            threatMatches: cachedMatches,
            cacheHit: true
        };
    }

    try {
        const googleUrl = new URL(GOOGLE_ENDPOINT);


        for (const prefix of prefixes) {
            googleUrl.searchParams.append(
                "hashPrefixes",
                prefix
            );
        }

        const response = await fetch(googleUrl, {
            method: "GET",
            headers: {
                Accept: "application/x-protobuf, application/json;q=0.9",
                "X-Goog-Api-Key": apiKey
            },
            redirect: "error",
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
        });

        if (!response.ok) {
            return {
                status: "UNAVAILABLE",
                threatMatches: [],
                cacheHit: false,
                errorCode: `GOOGLE_HTTP_${response.status}`
            };
        }

        const contentLength = Number(
            response.headers.get("content-length") || 0
        );

        if (
            Number.isFinite(contentLength) &&
            contentLength > MAX_RESPONSE_BYTES
        ) {
            return {
                status: "UNAVAILABLE",
                threatMatches: [],
                cacheHit: false,
                errorCode: "GOOGLE_RESPONSE_TOO_LARGE"
            };
        }

        const buffer = Buffer.from(
            await response.arrayBuffer()
        );

        if (buffer.length > MAX_RESPONSE_BYTES) {
            return {
                status: "UNAVAILABLE",
                threatMatches: [],
                cacheHit: false,
                errorCode: "GOOGLE_RESPONSE_TOO_LARGE"
            };
        }

        const contentType = (
            response.headers.get("content-type") || ""
        ).toLowerCase();

        const decoded = decodeGoogleResponse(
            contentType,
            buffer
        );

        const threatMatches = matchLocalHashes(
            hashData.fullHashes,
            decoded.googleRecords
        );

        // Cache both positive and negative results.
        saveCachedResponse(
            cacheKey,
            decoded.googleRecords,
            decoded.cacheDurationSeconds
        );

        return {
            status: threatMatches.length > 0
                ? "THREAT_FOUND"
                : "NO_THREAT_FOUND",
            threatMatches,
            cacheHit: false,
            cacheDurationSeconds: decoded.cacheDurationSeconds
        };
    } catch (error) {
        let errorCode = "GOOGLE_LOOKUP_FAILED";

        if (
            error.name === "TimeoutError" ||
            error.name === "AbortError"
        ) {
            errorCode = "GOOGLE_REQUEST_TIMEOUT";
        }

        return {
            status: "UNAVAILABLE",
            threatMatches: [],
            cacheHit: false,
            errorCode
        };
    }
}

module.exports = {
    checkGoogleReputation
};
