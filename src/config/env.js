require("dotenv").config();

const { z } = require("zod");

const envSchema = z.object({
    NODE_ENV: z
        .enum(["development", "test", "production"])
        .default("development"),

    HOST: z
        .string()
        .default("0.0.0.0"),

    PORT: z
        .coerce.number()
        .int()
        .min(1024)
        .max(65535)
        .default(3000),

    FRONTEND_ORIGINS: z
        .string()
        .default(
            "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173"
        ),

    LOCAL_BLOCKED_DOMAINS: z
        .string()
        .default(""),

    RATE_LIMIT_WINDOW_MS: z
        .coerce.number()
        .int()
        .min(1000)
        .max(3600000)
        .default(60000),

    RATE_LIMIT_MAX: z
        .coerce.number()
        .int()
        .min(1)
        .max(1000)
        .default(30),

    STRICT_OFFLINE_MODE: z
        .enum(["true", "false"])
        .default("false"),

    OFFLINE_ALLOW_KNOWN_SAFE: z
        .enum(["true", "false"])
        .default("false"),

    // Optional: leave empty to run without Google Safe Browsing lookups.
    GOOGLE_SAFE_BROWSING_API_KEY: z
        .string()
        .optional()
        .default("")
});

const result = envSchema.safeParse(process.env);

if (!result.success) {
    console.error(
        "[SafeGate] Invalid environment configuration:",
        result.error.issues.map(issue => ({
            field: issue.path.join("."),
            message: issue.message
        }))
    );

    process.exit(1);
}

const config = result.data;

// Restrict bind host to loopback or explicit 0.0.0.0 container interface.
const allowedHosts = new Set([
    "127.0.0.1",
    "::1",
    "localhost",
    "0.0.0.0"
]);

if (!allowedHosts.has(config.HOST)) {
    console.error(
        "[SafeGate] HOST must be a loopback address or 0.0.0.0."
    );

    process.exit(1);
}

// Restrict browser access to local frontend origins.
const frontendOrigins = config.FRONTEND_ORIGINS
    .split(",")
    .map(origin => origin.trim())
    .filter(Boolean);

for (const origin of frontendOrigins) {
    let parsed;

    try {
        parsed = new URL(origin);
    } catch {
        console.error(
            "[SafeGate] Invalid frontend origin configured."
        );

        process.exit(1);
    }

    const hostname = parsed.hostname.replace(/^\[|\]$/g, "");

    const isLocalHost = new Set([
        "localhost",
        "127.0.0.1",
        "::1"
    ]).has(hostname);

    if (
        !["http:", "https:"].includes(parsed.protocol) ||
        !isLocalHost
    ) {
        console.error(
            "[SafeGate] Only local frontend origins are allowed."
        );

        process.exit(1);
    }
}

// Validate manually configured blocked domains.
const localBlockedDomains = config.LOCAL_BLOCKED_DOMAINS
    .split(",")
    .map(domain => domain.trim().toLowerCase())
    .filter(Boolean);

const domainPattern =
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

for (const domain of localBlockedDomains) {
    if (!domainPattern.test(domain)) {
        console.error(
            "[SafeGate] Invalid domain in LOCAL_BLOCKED_DOMAINS."
        );

        process.exit(1);
    }
}

const strictOfflineMode = config.STRICT_OFFLINE_MODE === "true";
const offlineAllowKnownSafe = config.OFFLINE_ALLOW_KNOWN_SAFE === "true";

// Warn (do not crash) when Google Safe Browsing is not configured.
if (!config.GOOGLE_SAFE_BROWSING_API_KEY && !strictOfflineMode) {
    console.warn(
        "[SafeGate] WARNING: GOOGLE_SAFE_BROWSING_API_KEY is not set. " +
        "Google reputation checks will be skipped. " +
        "Local heuristics still run."
    );
}

module.exports = {
    nodeEnv: config.NODE_ENV,
    host: config.HOST,
    port: config.PORT,
    frontendOrigins,
    localBlockedDomains,
    rateLimitWindowMs: config.RATE_LIMIT_WINDOW_MS,
    rateLimitMax: config.RATE_LIMIT_MAX,
    strictOfflineMode,
    offlineAllowKnownSafe,
    googleSafeBrowsingApiKey: strictOfflineMode
        ? null
        : (config.GOOGLE_SAFE_BROWSING_API_KEY || null)
};
