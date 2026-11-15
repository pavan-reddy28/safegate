'use strict';

const crypto = require('node:crypto');

const {
  ClientSecretCredential
} = require('@azure/identity');

const {
  SecretClient
} = require('@azure/keyvault-secrets');

function createTokenRotator(config, logger, { onToken, onProofSecret, onAppIngestKey } = {}) {
  if (
    !config ||
    !logger ||
    typeof onToken !== 'function'
  ) {
    throw new Error('Vault token callback configuration is required');
  }

  // CONNECTION
  const credential = new ClientSecretCredential(
    config.tenantId,
    config.clientId,
    config.clientSecret
  );

  const client = new SecretClient(
    config.url,
    credential
  );

  // RUNTIME STATE
  const timers = new Map();
  const inFlight = new Set();

  let started = false;
  let stopping = false;
  let stopPromise = null;

  function log(level, message, metadata = {}) {
    const fn = logger[level] || logger.info;

    fn(message, {
      component: 'TOKEN_ROTATOR',
      ...metadata
    });
  }

  function errorMetadata(error) {
    return {
      errorName: error?.name || 'Error',
      errorCode: error?.code || 'UNKNOWN',
      statusCode: error?.statusCode || null,
      requestId: error?.requestId || null
    };
  }

  function generateToken() {
    return crypto.randomBytes(32);
  }

  function verifyToken(expectedValue, actualValue) {
    if (typeof actualValue !== 'string') {
      return false;
    }

    const expected = Buffer.from(expectedValue, 'utf8');
    const actual = Buffer.from(actualValue, 'utf8');

    try {
      return (
        expected.length === actual.length &&
        crypto.timingSafeEqual(expected, actual)
      );
    } finally {
      expected.fill(0);
      actual.fill(0);
    }
  }

  async function getLatestEntryByName(entryName) {
    try {
      return await client.getSecret(entryName);
    } catch (error) {
      if (
        Number(error?.statusCode) === 404 ||
        error?.code === 'SecretNotFound'
      ) {
        return null;
      }

      throw error;
    }
  }

  function getTimestamp(value) {
    if (!value) return null;
    const timestamp = new Date(value).getTime();
    return Number.isFinite(timestamp) ? timestamp : null;
  }

  function isUsable(entry) {
    if (
      !entry ||
      typeof entry.value !== 'string' ||
      !/^[a-fA-F0-9]{64}$/.test(entry.value) ||
      entry.properties?.enabled === false
    ) {
      return false;
    }

    const expiry = getTimestamp(entry.properties?.expiresOn);
    return expiry !== null && expiry > Date.now();
  }

  function retryDelay(attempt) {
    return Math.min(
      config.retryBaseMs *
        Math.pow(2, Math.min(attempt - 1, 10)),
      config.retryMaxMs
    );
  }

  function scheduleNext(schedule, delayMs, retryAttempt = 0) {
    if (stopping) return;

    const existing = timers.get(schedule.id);
    if (existing) {
      clearTimeout(existing);
    }

    log('info', 'Token rotation scheduled', {
      tokenProfile: schedule.id,
      intervalMinutes: schedule.intervalMinutes,
      retryAttempt
    });

    const timer = setTimeout(() => {
      timers.delete(schedule.id);
      void launchRotation(schedule, retryAttempt);
    }, delayMs);

    timers.set(schedule.id, timer);
  }

  async function rotateToken(schedule) {
    const tokenBuffer = generateToken();
    let tokenValue;

    const expiresAt = new Date(
      Date.now() +
      schedule.intervalMs +
      config.expiryGraceMs
    );

    log('info', 'Token generation started', {
      tokenProfile: schedule.id,
      algorithm: 'CSPRNG_256_BIT'
    });

    try {
      tokenValue = tokenBuffer.toString('hex');

      const saved = await client.setSecret(
        schedule.entryName,
        tokenValue,
        {
          enabled: true,
          expiresOn: expiresAt,
          contentType: 'text/plain',
          tags: {
            application: 'SafeGate',
            purpose: 'platform-token',
            tokenProfile: schedule.id,
            rotationMinutes: String(schedule.intervalMinutes)
          }
        }
      );

      const version = saved.properties?.version;
      if (!version) {
        throw new Error('Storage version unavailable');
      }

      log('info', 'Token stored successfully', {
        tokenProfile: schedule.id,
        entryVersion: version
      });

      const readBack = await client.getSecret(schedule.entryName, { version });
      const verified = verifyToken(tokenValue, readBack.value);
      const verifiedExpiry = getTimestamp(readBack.properties?.expiresOn);

      if (
        !verified ||
        readBack.properties?.enabled === false ||
        verifiedExpiry === null ||
        verifiedExpiry <= Date.now()
      ) {
        throw new Error('Stored token verification failed');
      }

      onToken({
        profile: schedule.id,
        token: tokenValue,
        expiresAt: new Date(verifiedExpiry)
      });

      log('info', 'Vault verification successful', {
        tokenProfile: schedule.id,
        entryVersion: version,
        verification: 'SUCCESS',
        tokenValueLogged: false
      });

      return { version };
    } finally {
      tokenBuffer.fill(0);
      tokenValue = undefined;
    }
  }

  async function performRotation(schedule, retryAttempt = 0) {
    if (stopping) return;

    try {
      const result = await rotateToken(schedule);

      log('info', 'Token rotation completed', {
        tokenProfile: schedule.id,
        entryVersion: result.version,
        status: 'SUCCESS'
      });

      scheduleNext(schedule, schedule.intervalMs, 0);
    } catch (error) {
      const nextAttempt = retryAttempt + 1;
      const delay = retryDelay(nextAttempt);

      log('error', 'Token rotation failed', {
        tokenProfile: schedule.id,
        retryAttempt: nextAttempt,
        retryDelaySeconds: Math.ceil(delay / 1000),
        ...errorMetadata(error)
      });

      scheduleNext(schedule, delay, nextAttempt);
    }
  }

  function launchRotation(schedule, attempt = 0) {
    const task = performRotation(schedule, attempt);
    inFlight.add(task);
    task.finally(() => {
      inFlight.delete(task);
    });
    return task;
  }

  async function loadProofSecretFromVault(entryName) {
    if (!entryName || typeof onProofSecret !== 'function') {
      return false;
    }

    const entry = await getLatestEntryByName(entryName);
    if (
      !entry ||
      typeof entry.value !== 'string' ||
      entry.value.trim().length < 32 ||
      entry.properties?.enabled === false
    ) {
      throw new Error('Vault proof verification secret is missing or invalid');
    }

    onProofSecret(entry.value.trim());

    log('info', 'Proof verification secret loaded from Vault', {
      entryVersion: entry.properties?.version || null
    });

    return true;
  }

  async function loadAppIngestKeyFromVault(entryName) {
    if (!entryName || typeof onAppIngestKey !== 'function') {
      return false;
    }

    const entry = await getLatestEntryByName(entryName);
    if (
      !entry ||
      typeof entry.value !== 'string' ||
      entry.value.trim().length < 32 ||
      entry.properties?.enabled === false
    ) {
      throw new Error('Vault app ingest credential is missing or invalid');
    }

    onAppIngestKey(entry.value.trim());

    log('info', 'App ingest credential loaded from Vault', {
      entryVersion: entry.properties?.version || null
    });

    return true;
  }

  async function initializeSchedule(schedule) {
    try {
      const current = await getLatestEntryByName(schedule.entryName);
      if (stopping) return;

      const now = Date.now();

      if (isUsable(current)) {
        const properties = current.properties || {};

        onToken({
          profile: schedule.id,
          token: current.value,
          expiresAt: properties.expiresOn
        });

        const lastGenerated =
          getTimestamp(properties.updatedOn) ??
          getTimestamp(properties.createdOn);

        if (lastGenerated !== null) {
          const nextRun = lastGenerated + schedule.intervalMs;
          if (nextRun > now) {
            log('info', 'Existing token retained', {
              tokenProfile: schedule.id,
              entryVersion: properties.version
            });

            scheduleNext(schedule, nextRun - now, 0);
            return;
          }
        }
      }

      await launchRotation(schedule, 0);
    } catch (error) {
      log('error', 'Rotation initialization failed', {
        tokenProfile: schedule.id,
        ...errorMetadata(error)
      });

      scheduleNext(schedule, retryDelay(1), 1);
    }
  }

  async function start() {
    if (started) return;

    if (stopping) {
      throw new Error('Rotation service is stopping');
    }

    started = true;

    log('info', 'Token rotation starting', {
      profiles: config.schedules.map(s => s.id)
    });

    await Promise.all(
      config.schedules.map(initializeSchedule)
    );

    log('info', 'Token rotation initialized', {
      schedules: config.schedules.length,
      status: 'READY'
    });
  }

  function stop() {
    if (stopPromise) return stopPromise;

    stopping = true;

    for (const timer of timers.values()) {
      clearTimeout(timer);
    }

    timers.clear();

    stopPromise = (async () => {
      await Promise.allSettled([...inFlight]);
      log('info', 'Token rotation stopped');
    })();

    return stopPromise;
  }

  return Object.freeze({
    start,
    stop,
    loadProofSecretFromVault,
    loadAppIngestKeyFromVault
  });
}

module.exports = {
  createTokenRotator
};
