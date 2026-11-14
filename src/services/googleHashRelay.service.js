
const crypto = require("node:crypto");

const GOOGLE_ENDPOINT =
    "https://safebrowsing.googleapis.com/v5/hashes:search";

const REQUEST_TIMEOUT_MS = 10000;
const MAX_CACHE_ENTRIES = 500;
const MAX_CACHE_DURATION_SECONDS = 86400;
const MAX_RESPONSE_BYTES = 1024 * 1024;

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

const VALID_THREAT_TYPES = new Set(
    Object.values(THREAT_TYPES)
);

const VALID_THREAT_ATTRIBUTES = new Set(
    Object.values(THREAT_ATTRIBUTES)
);

/* =====================================================
   PREFIX VALIDATION
===================================================== */

function validateHashPrefixes(prefixes) {
    if (
        !Array.isArray(prefixes) ||
        prefixes.length < 1 ||
        prefixes.length > 30
    ) {
        return false;
    }

    if (new Set(prefixes).size !== prefixes.length) {
        return false;
    }

    return prefixes.every((prefix) => {
        if (
            typeof prefix !== "string" ||
            prefix.length !== 8
        ) {
            return false;
        }

        const decoded = Buffer.from(prefix, "base64");

        return (
            decoded.length === 4 &&
            decoded.toString("base64") === prefix
        );
    });
}

/* =====================================================
   PROTOBUF READER
===================================================== */

function readVarint(buffer, offset) {
    let value = 0n;

    for (let index = 0; index < 10; index++) {
        if (offset >= buffer.length) {
            throw new Error("Truncated protobuf");
        }

        const byte = buffer[offset++];

        if (index === 9 && byte > 1) {
            throw new Error("Invalid protobuf varint");
        }

        value |= BigInt(byte & 0x7f) <<
            BigInt(index * 7);

        if ((byte & 0x80) === 0) {
            return { value, offset };
        }
    }

    throw new Error("Invalid protobuf varint");
}

function readFieldKey(buffer, offset) {
    const result = readVarint(buffer, offset);
    const key = Number(result.value);

    if (
        !Number.isSafeInteger(key) ||
        key <= 0
    ) {
        throw new Error("Invalid protobuf field key");
    }

    return {
        fieldNumber: Math.floor(key / 8),
        wireType: key % 8,
        offset: result.offset
    };
}

function readBytes(buffer, offset) {
    const result = readVarint(buffer, offset);
    const length = Number(result.value);

    if (
        !Number.isSafeInteger(length) ||
        length < 0 ||
        length > buffer.length - result.offset
    ) {
        throw new Error("Invalid protobuf length");
    }

    const start = result.offset;
    const end = start + length;

    return {
        value: buffer.subarray(start, end),
        offset: end
    };
}

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

/* =====================================================
   ENUM DECODING
===================================================== */

function decodePackedEnums(buffer) {
    const values = [];
    let offset = 0;

    while (offset < buffer.length) {
        const result = readVarint(buffer, offset);
        offset = result.offset;

        if (
            result.value >
            BigInt(Number.MAX_SAFE_INTEGER)
        ) {
            throw new Error("Invalid enum value");
        }

        values.push(Number(result.value));
    }

    return values;
}

function decodeThreatDetail(buffer) {
    let threatType = null;
    const attributeValues = [];

    let valid = true;
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

            if (
                result.value >
                BigInt(Number.MAX_SAFE_INTEGER)
            ) {
                valid = false;
            } else {
                threatType = Number(result.value);
            }

        } else if (field.fieldNumber === 2) {

            if (field.wireType === 0) {
                const result = readVarint(buffer, offset);
                offset = result.offset;

                if (
                    result.value >
                    BigInt(Number.MAX_SAFE_INTEGER)
                ) {
                    valid = false;
                } else {
                    attributeValues.push(
                        Number(result.value)
                    );
                }

            } else if (field.wireType === 2) {
                const result = readBytes(buffer, offset);
                offset = result.offset;

                attributeValues.push(
                    ...decodePackedEnums(result.value)
                );

            } else {
                throw new Error("Invalid threat attributes");
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
        valid = false;
    }

    const attributes = [];

    for (const value of attributeValues) {
        const name = THREAT_ATTRIBUTES[value];

        if (!name) {
            valid = false;
            break;
        }

        attributes.push(name);
    }

    if (!valid) {
        return null;
    }

    return {
        threatType: threatName,
        attributes
    };
}

/* =====================================================
   FULL HASH DECODING
===================================================== */

function decodeFullHash(buffer) {
    let fullHash = null;
    const fullHashDetails = [];

    let offset = 0;

    while (offset < buffer.length) {
        const field = readFieldKey(buffer, offset);
        offset = field.offset;

        if (field.fieldNumber === 1) {
            if (
                field.wireType !== 2 ||
                fullHash !== null
            ) {
                throw new Error("Invalid full hash field");
            }

            const result = readBytes(buffer, offset);
            offset = result.offset;

            fullHash = result.value;

        } else if (field.fieldNumber === 2) {
            if (field.wireType !== 2) {
                throw new Error("Invalid full hash detail");
            }

            const result = readBytes(buffer, offset);
            offset = result.offset;

            const detail = decodeThreatDetail(
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
        throw new Error("Invalid SHA-256 full hash");
    }

    return {
        fullHash: fullHash.toString("base64"),
        fullHashDetails
    };
}

/* =====================================================
   CACHE DURATION
===================================================== */

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
        seconds < 0n ||
        seconds > BigInt(MAX_CACHE_DURATION_SECONDS) ||
        nanos < 0n ||
        nanos >= 1000000000n
    ) {
        throw new Error("Invalid cache duration");
    }

    return Number(seconds) + Number(nanos) / 1e9;
}

function parseJsonDuration(value) {
    if (typeof value !== "string") {
        throw new Error("Missing cache duration");
    }

    const match = value.match(
        /^(\d+(?:\.\d{1,9})?)s$/
    );

    if (!match) {
        throw new Error("Invalid cache duration");
    }

    const seconds = Number(match[1]);

    if (
        !Number.isFinite(seconds) ||
        seconds < 0 ||
        seconds > MAX_CACHE_DURATION_SECONDS
    ) {
        throw new Error("Invalid cache duration");
    }

    return seconds;
}

/* =====================================================
   GOOGLE RESPONSE DECODING
===================================================== */

function decodeProtobufResponse(buffer) {
    const fullHashes = [];

    let cacheDurationSeconds = null;
    let offset = 0;

    while (offset < buffer.length) {
        const field = readFieldKey(buffer, offset);
        offset = field.offset;

        if (field.fieldNumber === 1) {
            if (field.wireType !== 2) {
                throw new Error("Invalid fullHashes field");
            }

            const result = readBytes(buffer, offset);
            offset = result.offset;

            fullHashes.push(
                decodeFullHash(result.value)
            );

        } else if (field.fieldNumber === 2) {
            if (field.wireType !== 2) {
                throw new Error("Invalid cacheDuration field");
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
        throw new Error("Missing Google cache duration");
    }

    return {
        fullHashes,
        cacheDurationSeconds
    };
}

function decodeJsonFullHash(value) {
    if (
        typeof value !== "string" ||
        !/^[A-Za-z0-9+/]{43}=$/.test(value)
    ) {
        return null;
    }

    const decoded = Buffer.from(value, "base64");

    if (
        decoded.length !== 32 ||
        decoded.toString("base64") !== value
    ) {
        return null;
    }

    return value;
}

function decodeJsonThreatDetails(details) {
    if (details === undefined) {
        return [];
    }

    if (!Array.isArray(details)) {
        throw new Error("Invalid threat details");
    }

    const result = [];

    for (const detail of details) {
        if (
            !detail ||
            !VALID_THREAT_TYPES.has(detail.threatType)
        ) {
            continue;
        }

        const attributes = detail.attributes ?? [];

        if (!Array.isArray(attributes)) {
            throw new Error("Invalid threat attributes");
        }

        if (
            !attributes.every(attribute =>
                VALID_THREAT_ATTRIBUTES.has(attribute)
            )
        ) {
            continue;
        }

        result.push({
            threatType: detail.threatType,
            attributes
        });
    }

    return result;
}

function decodeJsonResponse(buffer) {
    let body;

    try {
        body = JSON.parse(buffer.toString("utf8"));
    } catch {
        throw new Error("Invalid Google JSON response");
    }

    if (!body || typeof body !== "object") {
        throw new Error("Invalid JSON structure");
    }

    const entries = body.fullHashes ?? [];

    if (!Array.isArray(entries)) {
        throw new Error("Invalid fullHashes array");
    }

    const fullHashes = [];

    for (const entry of entries) {
        const fullHash = decodeJsonFullHash(
            entry?.fullHash
        );

        if (!fullHash) {
            continue;
        }

        fullHashes.push({
            fullHash,
            fullHashDetails: decodeJsonThreatDetails(
                entry.fullHashDetails
            )
        });
    }

    return {
        fullHashes,
        cacheDurationSeconds: parseJsonDuration(
            body.cacheDuration
        )
    };
}

function decodeGoogleResponse(contentType, buffer) {
    if (contentType.includes("application/json")) {
        return decodeJsonResponse(buffer);
    }

    if (
        contentType.includes("application/x-protobuf") ||
        contentType.includes("application/protobuf")
    ) {
        return decodeProtobufResponse(buffer);
    }

    throw new Error("Unsupported Google response format");
}

/* =====================================================
   SAFE RESPONSE READER
===================================================== */

async function readLimitedResponse(response) {
    if (!response.body) {
        throw new Error("Empty Google response");
    }

    const reader = response.body.getReader();
    const chunks = [];

    let totalBytes = 0;

    try {
        while (true) {
            const { done, value } = await reader.read();

            if (done) {
                break;
            }

            totalBytes += value.byteLength;

            if (totalBytes > MAX_RESPONSE_BYTES) {
                await reader.cancel();
                throw new Error("Google response too large");
            }

            chunks.push(Buffer.from(value));
        }
    } finally {
        reader.releaseLock();
    }

    return Buffer.concat(chunks, totalBytes);
}

/* =====================================================
   CACHE
===================================================== */

function getCacheKey(prefixes) {
    return crypto
        .createHash("sha256")
        .update([...prefixes].sort().join("|"))
        .digest("hex");
}

function getCachedResult(cacheKey) {
    const entry = responseCache.get(cacheKey);

    if (!entry) {
        return null;
    }

    if (Date.now() >= entry.expiresAt) {
        responseCache.delete(cacheKey);
        return null;
    }

    responseCache.delete(cacheKey);
    responseCache.set(cacheKey, entry);

    return {
        fullHashes: entry.fullHashes,
        cacheDurationSeconds: entry.cacheDurationSeconds,
        cacheHit: true
    };
}

function saveCache(cacheKey, result) {
    if (result.cacheDurationSeconds <= 0) {
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
        fullHashes: result.fullHashes,
        cacheDurationSeconds: result.cacheDurationSeconds,
        expiresAt: Date.now() +
            result.cacheDurationSeconds * 1000
    });
}

/* =====================================================
   MAIN HASH RELAY FUNCTION
===================================================== */

async function searchGoogleHashPrefixes(prefixes) {
    if (!validateHashPrefixes(prefixes)) {
        return {
            ok: false,
            status: "INVALID_HASH_PREFIXES",
            errorCode: "INVALID_HASH_PREFIXES"
        };
    }

    const apiKey =
        process.env.GOOGLE_SAFE_BROWSING_API_KEY;

    if (!apiKey) {
        return {
            ok: false,
            status: "NOT_CONFIGURED",
            errorCode: "GOOGLE_NOT_CONFIGURED"
        };
    }

    const cacheKey = getCacheKey(prefixes);
    const cached = getCachedResult(cacheKey);

    if (cached) {
        return {
            ok: true,
            status: "LOOKUP_COMPLETED",
            ...cached
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

            signal: AbortSignal.timeout(
                REQUEST_TIMEOUT_MS
            )
        });

        if (!response.ok) {
            return {
                ok: false,
                status: "UNAVAILABLE",
                errorCode: `GOOGLE_HTTP_${response.status}`
            };
        }

        const rawBuffer = await readLimitedResponse(response);

        const contentType = (
            response.headers.get("content-type") || ""
        ).toLowerCase();

        const decoded = decodeGoogleResponse(
            contentType,
            rawBuffer
        );

        saveCache(cacheKey, decoded);

        return {
            ok: true,
            status: "LOOKUP_COMPLETED",
            fullHashes: decoded.fullHashes,
            cacheDurationSeconds:
                decoded.cacheDurationSeconds,
            cacheHit: false
        };

    } catch (error) {
        let errorCode = "GOOGLE_LOOKUP_FAILED";

        if (
            error.name === "TimeoutError" ||
            error.name === "AbortError"
        ) {
            errorCode = "GOOGLE_REQUEST_TIMEOUT";
        }

        if (error.message === "Google response too large") {
            errorCode = "GOOGLE_RESPONSE_TOO_LARGE";
        }

        return {
            ok: false,
            status: "UNAVAILABLE",
            errorCode
        };
    }
}

module.exports = {
    searchGoogleHashPrefixes,
    validateHashPrefixes
};
