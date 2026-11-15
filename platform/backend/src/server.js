'use strict';

const crypto = require('node:crypto');
const logger = require('./logger');
const { loadConfig } = require('./config');
const { initializeDatabase } = require('./database');
const { createApp } = require('./app');
const { createApiTokenStore } = require('./api-token-store');
const { createProofVerifier } = require('./proof-verifier');
const { createTokenRotator } = require('./token-rotator');

let server = null;
let database = null;
let heartbeat = null;
let tokenRotator = null;
let apiTokenStore = null;
let appIngestDigest = null;
let proofVerifier = null;
let shuttingDown = false;

function getErrorDetails(error) {
  return {
    errorName: error?.name || 'Error',
    errorCode: error?.code || 'INTERNAL_ERROR'
  };
}

function makeAppIngestAuthenticator(initialKey) {
  function setKey(rawKey) {
    if (!rawKey || typeof rawKey !== 'string' || rawKey.trim().length < 32) {
      throw new Error('App ingest key must be at least 32 characters');
    }
    const nextDigest = crypto
      .createHash('sha256')
      .update(rawKey.trim(), 'utf8')
      .digest();

    if (appIngestDigest) {
      appIngestDigest.fill(0);
    }
    appIngestDigest = nextDigest;
  }

  if (initialKey) {
    setKey(initialKey);
  }

  function matches(candidateKey) {
    if (!appIngestDigest || typeof candidateKey !== 'string') {
      return false;
    }
    const trimmed = candidateKey.trim();
    if (trimmed.length < 32 || trimmed.length > 512) {
      return false;
    }
    const candidateDigest = crypto
      .createHash('sha256')
      .update(trimmed, 'utf8')
      .digest();

    try {
      return (
        candidateDigest.length === appIngestDigest.length &&
        crypto.timingSafeEqual(candidateDigest, appIngestDigest)
      );
    } finally {
      candidateDigest.fill(0);
    }
  }

  function clear() {
    if (appIngestDigest) {
      appIngestDigest.fill(0);
      appIngestDigest = null;
    }
  }

  return Object.freeze({ setKey, matches, clear });
}

async function closeDatabase(exitCode) {
  let finalExitCode = exitCode;

  try {
    if (tokenRotator) {
      await tokenRotator.stop();
      logger.info('Rotation service stopped');
    }
  } catch (error) {
    logger.error('Rotation service shutdown failed', getErrorDetails(error));
    finalExitCode = 1;
  }

  try {
    if (apiTokenStore) {
      apiTokenStore.clear();
      apiTokenStore = null;
    }

    if (appIngestDigest) {
      appIngestDigest.fill(0);
      appIngestDigest = null;
    }

    if (proofVerifier) {
      proofVerifier.clear();
      proofVerifier = null;
    }

    if (database && typeof database.close === 'function') {
      database.close();
      logger.info('SQLite connection closed');
    }

    logger.info('Platform shutdown completed');
  } catch (error) {
    logger.error('Database shutdown failed', getErrorDetails(error));
    finalExitCode = 1;
  }

  process.exit(finalExitCode);
}

function shutdown(signal, exitCode = 0) {
  if (shuttingDown) return;

  shuttingDown = true;

  logger.warn('Shutdown initiated', {
    signal,
    state: 'SHUTTING_DOWN'
  });

  if (heartbeat) {
    clearInterval(heartbeat);
    heartbeat = null;
  }

  if (tokenRotator) {
    tokenRotator.stop().catch(error => {
      logger.error('Rotation stop failed', getErrorDetails(error));
    });
  }

  if (server && server.listening) {
    server.close(error => {
      if (error) {
        logger.error('HTTP service shutdown failed', getErrorDetails(error));
        void closeDatabase(1);
        return;
      }

      void closeDatabase(exitCode);
    });

    return;
  }

  void closeDatabase(exitCode);
}

async function bootstrap() {
  logger.info('================================================');
  logger.info('SafeGate Platform | Starting application');
  logger.info('================================================');

  logger.info('Platform bootstrap initiated', {
    state: 'INITIALIZING'
  });

  // 1. Load configuration.
  const config = loadConfig(logger);

  // 2. Initialize SQLite & schema migrations.
  database = initializeDatabase(config, logger);

  // 3. Initialize operator Key Vault token store + dedicated App Ingest authenticator.
  apiTokenStore = createApiTokenStore({
    graceOverlapMs: config.vault.expiryGraceMs
  });

  const appIngestAuth = makeAppIngestAuthenticator(config.appIngest.key);
  let vaultProofSecret = null;

  tokenRotator = createTokenRotator(
    config.vault,
    logger,
    {
      onToken: ({ profile, token, expiresAt }) => {
        apiTokenStore.set(profile, token, expiresAt);
      },
      onProofSecret: secret => {
        vaultProofSecret = secret;
        if (proofVerifier) {
          proofVerifier.setHmacSecret(secret);
        }
      },
      onAppIngestKey: key => {
        appIngestAuth.setKey(key);
      }
    }
  );

  await tokenRotator.start();

  if (config.appIngest.vaultSecretName) {
    await tokenRotator.loadAppIngestKeyFromVault(config.appIngest.vaultSecretName);
  }

  if (config.eventProof.vaultSecretName) {
    await tokenRotator.loadProofSecretFromVault(config.eventProof.vaultSecretName);
  }

  // Fail closed: require at least one active operator Vault token AND configured app ingest credential.
  if (apiTokenStore.activeCount() < 1) {
    throw new Error('No active operator Vault credentials are available');
  }

  if (!appIngestDigest) {
    throw new Error('No active app ingest credential is available');
  }

  logger.info('Active credentials loaded', {
    operatorProfiles: apiTokenStore.activeCount(),
    appIngestAuth: 'READY'
  });

  // 4. Initialize cryptographic local-verification proof verifier (fail closed).
  proofVerifier = createProofVerifier({
    hmacSecret: vaultProofSecret || config.eventProof.hmacSecret,
    publicKeyPem: config.eventProof.publicKeyPem,
    maxTtlSeconds: config.eventProof.maxTtlSeconds,
    clockSkewSeconds: config.eventProof.clockSkewSeconds,
    allowedAppIds: config.eventProof.allowedAppIds,
    requirePayloadDigest: config.eventProof.requirePayloadHashBinding
  });

  vaultProofSecret = null;

  logger.info('Proof verification initialized', {
    hasPublicKey: proofVerifier.hasPublicKey,
    hasHmacVerifier: proofVerifier.hasHmacSecret(),
    requirePayloadDigest: config.eventProof.requirePayloadHashBinding
  });

  // 5. Initialize application.
  const metrics = {
    requestsSinceHeartbeat: 0
  };

  const app = createApp({
    config,
    db: database,
    logger,
    metrics,
    apiTokenStore,
    appIngestAuth,
    proofVerifier
  });

  // 6. Start HTTP server.
  server = app.listen(
    config.port,
    '0.0.0.0',
    () => {
      logger.info('HTTP service initialized', {
        environment: config.nodeEnv,
        status: 'READY'
      });

      logger.info('Application initialization completed');

      logger.info('Platform status: READY', {
        health: 'READY',
        database: 'CONNECTED',
        vaultRotation: 'INITIALIZED',
        appIngestGate: 'ENFORCED',
        proofGate: 'ENFORCED'
      });
    }
  );

  server.on('error', error => {
    logger.fatal('HTTP service encountered a fatal error', getErrorDetails(error));
    shutdown('HTTP_SERVER_ERROR', 1);
  });

  heartbeat = setInterval(() => {
    const requests = metrics.requestsSinceHeartbeat || 0;
    metrics.requestsSinceHeartbeat = 0;

    if (requests === 0) {
      logger.idle(
        'Runtime idle | Service healthy; no API activity detected',
        {
          state: 'IDLE',
          health: 'READY',
          database: 'CONNECTED',
          requests: 0
        }
      );
      return;
    }

    logger.info(
      'Runtime heartbeat | API activity observed',
      {
        state: 'ACTIVE',
        requests
      }
    );
  }, config.idleIntervalMs);

  heartbeat.unref();

  logger.info('Runtime monitoring initialized', {
    state: 'ACTIVE',
    heartbeat: 'ENABLED',
    vaultRotation: 'ENABLED'
  });

  process.once('SIGTERM', () => shutdown('SIGTERM', 0));
  process.once('SIGINT', () => shutdown('SIGINT', 0));
}

process.on('uncaughtException', error => {
  logger.fatal('Uncaught application exception', getErrorDetails(error));
  shutdown('UNCAUGHT_EXCEPTION', 1);
});

process.on('unhandledRejection', reason => {
  logger.fatal('Unhandled promise rejection', getErrorDetails(reason));
  shutdown('UNHANDLED_REJECTION', 1);
});

bootstrap().catch(error => {
  logger.fatal('Platform bootstrap failed', getErrorDetails(error));
  shutdown('BOOTSTRAP_FAILURE', 1);
});
