'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createSessionManager } = require('./auth');
const { createVaultTokenClient } = require('./vault-client');
const { createDashboardApp } = require('./app');

function loadEnvFileIfPresent() {
  const candidates = [
    process.env.ENV_FILE,
    '/run/secrets/dashboard_env',
    path.join(__dirname, '..', '.env')
  ].filter(Boolean);

  for (const filePath of candidates) {
    if (!fs.existsSync(filePath)) continue;
    const raw = fs.readFileSync(filePath, 'utf8');
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq <= 0) continue;
      const key = trimmed.slice(0, eq).trim();
      const val = trimmed.slice(eq + 1).trim();
      if (process.env[key] === undefined) {
        process.env[key] = val;
      }
    }
  }
}

async function bootstrap() {
  loadEnvFileIfPresent();

  const port = Number(process.env.PORT || 4318);
  const platformBaseUrl = process.env.PLATFORM_BASE_URL || 'http://platform:4317';
  const keyVaultName = process.env.KEYVAULT_URL || process.env.KEY_VAULT_NAME || '';
  const staticToken = process.env.PLATFORM_API_TOKEN || '';
  const operatorUsername = process.env.OPERATOR_USERNAME || 'pavanreddy';
  const operatorPasswordHash = process.env.OPERATOR_PASSWORD_HASH || '';
  const sessionSecret = process.env.SESSION_SECRET || '';
  const ttlSeconds = Number(process.env.SESSION_TTL_SECONDS || 12 * 3600);
  const cookieSecure = String(process.env.COOKIE_SECURE ?? (process.env.NODE_ENV === 'production' ? 'true' : 'false')).toLowerCase() === 'true';
  const trustProxy = String(process.env.TRUST_PROXY || 'false').toLowerCase() === 'true';

  if (!keyVaultName && !staticToken) {
    throw new Error('KEYVAULT_URL or KEY_VAULT_NAME (or local PLATFORM_API_TOKEN) is required for Layer 1 Vault auth');
  }

  const sessionManager = createSessionManager({
    sessionSecret,
    operatorUsername,
    operatorPasswordHash,
    ttlSeconds
  });

  const vaultClient = createVaultTokenClient({
    keyVaultName,
    secretName: process.env.VAULT_OPERATOR_SECRET_NAME || process.env.TOKEN_1H_SECRET_NAME || 'safegate-api-token-1h',
    staticToken
  });

  await vaultClient.start();

  const app = createDashboardApp({
    platformBaseUrl,
    vaultClient,
    sessionManager,
    cookieSecure,
    trustProxy,
    logger: {
      info: (msg, meta) => console.log(JSON.stringify({ level: 'INFO', service: 'safegate-dashboard', msg, ...meta })),
      warn: (msg, meta) => console.warn(JSON.stringify({ level: 'WARN', service: 'safegate-dashboard', msg, ...meta })),
      error: (msg, meta) => console.error(JSON.stringify({ level: 'ERROR', service: 'safegate-dashboard', msg, ...meta }))
    }
  });

  const server = app.listen(port, '0.0.0.0', () => {
    console.log(JSON.stringify({
      level: 'INFO',
      service: 'safegate-dashboard',
      msg: 'SafeGate Dashboard BFF listening',
      port,
      layer1VaultReady: vaultClient.isReady()
    }));
  });

  const shutdown = () => {
    vaultClient.stop();
    server.close(() => process.exit(0));
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}

bootstrap().catch(err => {
  console.error(JSON.stringify({
    level: 'FATAL',
    service: 'safegate-dashboard',
    msg: err?.message || 'Bootstrap failed'
  }));
  process.exit(1);
});
