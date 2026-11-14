
const { z } = require("zod");

const {
    searchGoogleHashPrefixes,
    validateHashPrefixes
} = require("../services/googleHashRelay.service");

const requestSchema = z.object({
    hashPrefixes: z.array(
        z.string().min(8).max(8)
    ).min(1).max(30)
}).strict();

async function googleHashRelayController(req, res, next) {

    const validation = requestSchema.safeParse(req.body);

    if (!validation.success) {
        return res.status(400).json({
            requestId: req.requestId,
            status: "INVALID_REQUEST",
            error: {
                code: "INVALID_HASH_PREFIX_REQUEST",
                message: "Provide between 1 and 30 valid four-byte Base64 hash prefixes."
            }
        });
    }

    const prefixes = validation.data.hashPrefixes;

    if (!validateHashPrefixes(prefixes)) {
        return res.status(400).json({
            requestId: req.requestId,
            status: "INVALID_REQUEST",
            error: {
                code: "INVALID_HASH_PREFIXES",
                message: "One or more hash prefixes are invalid."
            }
        });
    }

    try {
        const result = await searchGoogleHashPrefixes(prefixes);

        if (!result.ok) {

            const statusCode =
                result.status === "NOT_CONFIGURED" ? 503 :
                result.status === "INVALID_HASH_PREFIXES" ? 400 :
                502;

            return res.status(statusCode).json({
                requestId: req.requestId,
                status: result.status,
                error: {
                    code: result.errorCode,
                    message: result.status === "NOT_CONFIGURED"
                        ? "Google verification is not configured."
                        : "Google reputation lookup could not be completed."
                }
            });
        }

        return res.status(200).json({
            requestId: req.requestId,
            status: result.status,
            fullHashes: result.fullHashes,
            cacheDurationSeconds: result.cacheDurationSeconds,
            cacheHit: result.cacheHit
        });

    } catch (error) {

        // Never log prefixes, URLs, full hashes or API keys.
        next(error);
    }
}

module.exports = {
    googleHashRelayController
};
