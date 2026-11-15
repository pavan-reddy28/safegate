'use strict';

const fs = require('node:fs');
const dotenv = require('dotenv');

function required(name) {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error('Required runtime configuration is missing');
  }

  return value;
}

function positiveInteger(name, defaultValue, allowZero = false) {
  const raw = process.env[name];

  const value = raw === undefined
    ? defaultValue
    : Number(raw);

  if (
    !Number.isSafeInteger(value) ||
    value < (allowZero ? 0 : 1)
  ) {
    throw new Error('Invalid runtime configuration');
  }

  return value;
}

function parseBoolean(name, defaultValue = false) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return defaultValue;
  const norm = String(raw).trim().toLowerCase();
  if (norm === 'true' || norm === '1' || norm === 'yes') return true;
  if (norm === 'false' || norm === '0' || norm === 'no') return false;
  throw new Error('Invalid boolean runtime configuration');
}

function loadConfig(logger) {
  const envFile = process.env.ENV_FILE || '/run/secrets/platform_env';

  logger.info('Credential loading started', {
    source: 'Docker secret'
  });

  if (!fs.existsSync(envFile)) {
    throw new Error('Required credential file is missing');
  }

  let fileEnvironment;

  try {
    fileEnvironment = dotenv.parse(fs.readFileSync(envFile));
  } catch {
    throw new Error('Credential loading failed');
  }

  // Only load settings required by this service.
  const allowedEnvironment = [
    'AZURE_TENANT_ID',
    'AZURE_CLIENT_ID',
    'AZURE_CLIENT_SECRET',
    'KEYVAULT_URL',
    'TOKEN_1H_SECRET_NAME',
    'TOKEN_6H_SECRET_NAME',
    'TOKEN_1H_ROTATION_MINUTES',
    'TOKEN_6H_ROTATION_MINUTES',
    'TOKEN_EXPIRY_GRACE_MINUTES',
    'TOKEN_RETRY_BASE_SECONDS',
    'TOKEN_RETRY_MAX_SECONDS',
    'APP_INGEST_KEY',
    'APP_INGEST_SECRET_NAME',
    'EVENT_PROOF_HMAC_SECRET',
    'EVENT_PROOF_PUBLIC_KEY_PEM',
    'EVENT_PROOF_SECRET_NAME',
    'EVENT_PROOF_MAX_TTL_SECONDS',
    'EVENT_PROOF_CLOCK_SKEW_SECONDS',
    'REQUIRE_PAYLOAD_HASH_BINDING',
    'REQUIRE_APP_HEADER',
    'ALLOWED_APP_IDS',
    'PORT',
    'DB_PATH',
    'LOG_LEVEL'
  ];

  for (const name of allowedEnvironment) {
    if (
      process.env[name] === undefined &&
      Object.prototype.hasOwnProperty.call(fileEnvironment, name)
    ) {
      process.env[name] = fileEnvironment[name];
    }
  }

  // Static bearer authentication is never permitted.
  delete process.env.PLATFORM_API_TOKEN;
  delete process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  // Vault connection configuration (for GET/PATCH/DELETE operator tokens & optional Vault secrets).
  const tenantId = required('AZURE_TENANT_ID');
  const clientId = required('AZURE_CLIENT_ID');
  const clientSecret = required('AZURE_CLIENT_SECRET');
  const vaultUrl = required('KEYVAULT_URL');

  let parsedUrl;

  try {
    parsedUrl = new URL(vaultUrl);
  } catch {
    throw new Error('Invalid vault endpoint');
  }

  if (
    parsedUrl.protocol !== 'https:' ||
    !parsedUrl.hostname.endsWith('.vault.azure.net')
  ) {
    throw new Error('Invalid vault endpoint');
  }

  // Operator token secret names (GET / PATCH / DELETE).
  const name1h =
    process.env.TOKEN_1H_SECRET_NAME ||
    'safegate-platform-token-1h';

  const name6h =
    process.env.TOKEN_6H_SECRET_NAME ||
    'safegate-platform-token-6h';

  const appIngestSecretName =
    process.env.APP_INGEST_SECRET_NAME?.trim() || null;

  const proofSecretName =
    process.env.EVENT_PROOF_SECRET_NAME?.trim() || null;

  const validName = /^[A-Za-z0-9-]{1,127}$/;

  if (
    !validName.test(name1h) ||
    !validName.test(name6h) ||
    name1h === name6h ||
    (proofSecretName && (!validName.test(proofSecretName) || proofSecretName === name1h || proofSecretName === name6h)) ||
    (appIngestSecretName && (!validName.test(appIngestSecretName) || appIngestSecretName === name1h || appIngestSecretName === name6h))
  ) {
    throw new Error('Invalid vault entry configuration');
  }

  // Dedicated App-Only Ingest credential (separate from Key Vault 1h/6h admin tokens).
  const appIngestKey = process.env.APP_INGEST_KEY?.trim() || null;

  if (!appIngestKey && !appIngestSecretName) {
    throw new Error('App ingest authentication credential is missing');
  }

  if (appIngestKey && appIngestKey.length < 32) {
    throw new Error('App ingest key length is insufficient');
  }

  // Event verification proof configuration (fail-closed: at least one must be configured)
  const proofHmacSecret = process.env.EVENT_PROOF_HMAC_SECRET?.trim() || null;
  const proofPublicKeyPem = process.env.EVENT_PROOF_PUBLIC_KEY_PEM?.trim()
    ? process.env.EVENT_PROOF_PUBLIC_KEY_PEM.replace(/\\n/g, '\n')
    : null;

  if (!proofHmacSecret && !proofPublicKeyPem && !proofSecretName) {
    throw new Error('Event proof verification key configuration is missing');
  }

  if (proofHmacSecret && proofHmacSecret.length < 32) {
    throw new Error('Event proof HMAC secret length is insufficient');
  }

  // Ensure app ingest key is distinct from operator secrets & proof HMAC secret
  if (appIngestKey && proofHmacSecret && appIngestKey === proofHmacSecret) {
    throw new Error('App ingest key must be distinct from proof signing secret');
  }

  // Rotation intervals.
  const interval1h = positiveInteger(
    'TOKEN_1H_ROTATION_MINUTES',
    60
  );

  const interval6h = positiveInteger(
    'TOKEN_6H_ROTATION_MINUTES',
    360
  );

  const graceMinutes = positiveInteger(
    'TOKEN_EXPIRY_GRACE_MINUTES',
    5,
    true
  );

  const retryBaseMs = positiveInteger(
    'TOKEN_RETRY_BASE_SECONDS',
    30
  ) * 1000;

  const retryMaxMs = positiveInteger(
    'TOKEN_RETRY_MAX_SECONDS',
    300
  ) * 1000;

  if (retryMaxMs < retryBaseMs) {
    throw new Error('Invalid retry configuration');
  }

  const proofMaxTtlSeconds = positiveInteger(
    'EVENT_PROOF_MAX_TTL_SECONDS',
    300
  );

  const proofClockSkewSeconds = positiveInteger(
    'EVENT_PROOF_CLOCK_SKEW_SECONDS',
    30,
    true
  );

  const requirePayloadHashBinding = parseBoolean(
    'REQUIRE_PAYLOAD_HASH_BINDING',
    true
  );

  const requireAppHeader = parseBoolean(
    'REQUIRE_APP_HEADER',
    true
  );

  const allowedAppIds = (process.env.ALLOWED_APP_IDS || 'com.safegate.app')
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);

  if (allowedAppIds.length === 0) {
    throw new Error('At least one allowed app identifier is required');
  }

  const port = Number(process.env.PORT || 4317);

  if (
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535
  ) {
    throw new Error('Invalid server port');
  }

  const dbPath =
    process.env.DB_PATH || '/app/data/safegate.sqlite';

  logger.info('Vault configuration validated', {
    tokenSchedules: ['1h', '6h'],
    appIngestAuth: 'SEPARATE_FAIL_CLOSED',
    proofVerification: 'ENABLED',
    vault: 'CONFIGURED'
  });

  return Object.freeze({
    port,
    dbPath,

    idleIntervalMs: 60000,
    nodeEnv: 'production',

    appIngest: Object.freeze({
      key: appIngestKey,
      vaultSecretName: appIngestSecretName
    }),

    eventProof: Object.freeze({
      hmacSecret: proofHmacSecret,
      publicKeyPem: proofPublicKeyPem,
      vaultSecretName: proofSecretName,
      maxTtlSeconds: proofMaxTtlSeconds,
      clockSkewSeconds: proofClockSkewSeconds,
      requirePayloadHashBinding,
      requireAppHeader,
      allowedAppIds: Object.freeze(allowedAppIds)
    }),

    vault: Object.freeze({
      url: vaultUrl,
      tenantId,
      clientId,
      clientSecret,

      expiryGraceMs: graceMinutes * 60 * 1000,

      retryBaseMs,
      retryMaxMs,

      schedules: Object.freeze([
        Object.freeze({
          id: '1h',
          entryName: name1h,
          intervalMinutes: interval1h,
          intervalMs: interval1h * 60 * 1000
        }),

        Object.freeze({
          id: '6h',
          entryName: name6h,
          intervalMinutes: interval6h,
          intervalMs: interval6h * 60 * 1000
        })
      ])
    })
  });
}

module.exports = { loadConfig };
