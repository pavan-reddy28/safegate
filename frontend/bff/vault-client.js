'use strict';

function normalizeVaultBaseUrl(vaultNameOrUri) {
  const trimmed = String(vaultNameOrUri || '').trim();
  if (!trimmed) return '';
  if (/^https:\/\//i.test(trimmed)) {
    return trimmed.replace(/\/+$/, '');
  }
  return `https://${trimmed}.vault.azure.net`;
}

function createVaultTokenClient({
  keyVaultName = '',
  secretName = 'safegate-api-token-1h',
  refreshIntervalMs = 5 * 60 * 1000,
  staticToken = '',
  logger = console
} = {}) {
  let activeToken = typeof staticToken === 'string' && /^[a-f0-9]{64}$/i.test(staticToken.trim())
    ? staticToken.trim()
    : null;
  let lastRefreshedAt = activeToken ? new Date().toISOString() : null;
  let timer = null;
  let secretClient = null;

  async function initAzureClientIfNeeded() {
    if (secretClient || !keyVaultName) return;
    const { DefaultAzureCredential } = require('@azure/identity');
    const { SecretClient } = require('@azure/keyvault-secrets');
    const credential = new DefaultAzureCredential();
    secretClient = new SecretClient(normalizeVaultBaseUrl(keyVaultName), credential);
  }

  async function refresh() {
    if (!keyVaultName) {
      return Boolean(activeToken);
    }
    await initAzureClientIfNeeded();
    const secret = await secretClient.getSecret(secretName);
    const val = typeof secret?.value === 'string' ? secret.value.trim() : '';
    if (!/^[a-f0-9]{64}$/i.test(val)) {
      throw new Error('Azure Key Vault token format invalid');
    }
    activeToken = val;
    lastRefreshedAt = new Date().toISOString();
    return true;
  }

  async function start() {
    await refresh();
    if (!activeToken) {
      throw new Error('Layer 1 Vault token could not be loaded on startup');
    }
    if (keyVaultName && refreshIntervalMs > 0) {
      timer = setInterval(() => {
        refresh().catch(err => {
          if (logger && typeof logger.error === 'function') {
            logger.error(JSON.stringify({
              level: 'ERROR',
              service: 'safegate-dashboard-bff',
              message: 'Layer 1 Vault token refresh failed',
              errorName: err?.name || 'Error'
            }));
          }
        });
      }, refreshIntervalMs);
      timer.unref();
    }
  }

  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    activeToken = null;
  }

  return Object.freeze({
    start,
    refresh,
    stop,
    isReady: () => Boolean(activeToken),
    getActiveToken: () => activeToken,
    getLastRefreshedAt: () => lastRefreshedAt
  });
}

module.exports = {
  createVaultTokenClient
};
