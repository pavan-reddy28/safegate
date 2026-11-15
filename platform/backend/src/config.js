
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
    'GOOGLE_SAFE_BROWSING_API_KEY',
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

  // Static authentication is not used.
  // All API authentication is performed using rotating Vault tokens.
  delete process.env.PLATFORM_API_TOKEN;

  const googleKey =
    process.env.GOOGLE_SAFE_BROWSING_API_KEY || null;

  logger.info(
    googleKey
      ? 'Google Safe Browsing credential detected'
      : 'Google Safe Browsing integration not configured'
  );

  // Vault connection configuration.
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

  // Token secret names.
  const name1h =
    process.env.TOKEN_1H_SECRET_NAME ||
    'safegate-platform-token-1h';

  const name6h =
    process.env.TOKEN_6H_SECRET_NAME ||
    'safegate-platform-token-6h';

  const validName = /^[A-Za-z0-9-]{1,127}$/;

  if (
    !validName.test(name1h) ||
    !validName.test(name6h) ||
    name1h === name6h
  ) {
    throw new Error('Invalid vault entry configuration');
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
    vault: 'CONFIGURED'
  });

  return Object.freeze({
    googleSafeBrowsingApiKey: googleKey,

    port,
    dbPath,

    idleIntervalMs: 60000,
    nodeEnv: 'production',

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

