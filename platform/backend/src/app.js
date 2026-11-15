'use strict';

const crypto = require('node:crypto');
const net = require('node:net');
const express = require('express');
const helmet = require('helmet');

const VALID_DECISIONS = new Set([
  'BLOCK',
  'SUSPICIOUS',
  'HOLD',
  'SAFE',
  'KNOWN_SAFE',
  'NO_KNOWN_THREAT'
]);

const VALID_STATUSES = new Set([
  'OPEN',
  'REVIEWED',
  'RESOLVED',
  'ARCHIVED'
]);

const VALID_LOCAL_DECISIONS = new Set([
  'BLOCK',
  'SUSPICIOUS',
  'HOLD',
  'SAFE',
  'REPUTATION_CHECK_REQUIRED'
]);

const VALID_ACTIONS = new Set([
  'DO_NOT_OPEN',
  'WARN_USER',
  'HOLD',
  'ALLOW',
  'ALLOW_WITH_CAUTION'
]);

const VALID_CHECK_STATUSES = new Set([
  'PASSED',
  'FAILED',
  'FLAGGED',
  'SKIPPED'
]);

const VALID_RISK_LEVELS = new Set([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'SAFE'
]);

const VALID_CODE = /^[A-Z0-9][A-Z0-9_.:-]{0,63}$/;
const VALID_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;
const VALID_APP_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/;
const VALID_HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$|^\[[0-9a-f:]+\]$/i;

const FORBIDDEN_PRIVACY_KEYS = new Set([
  'rawurl',
  'fullurl',
  'url',
  'originalurl',
  'querystring',
  'queryparams',
  'rawpath',
  'fullpath',
  'otp',
  'password',
  'passwd',
  'secret',
  'cookie',
  'cookies',
  'authorization',
  'email',
  'phone',
  'sql',
  'query'
]);

const ALLOWED_POST_KEYS = new Set([
  'requestId',
  'deviceId',
  'deviceName',
  'eventTime',
  'decision',
  'score',
  'reasons',
  'verificationStatus',
  'engineMode',
  'localVerification',
  'securityChecks',
  'finalDecision',
  'recommendedAction',
  'finalReasonCodes',
  'verificationToken',
  'riskSummary',
  'layersExecuted',
  'privacy',
  'appVersion',
  'persistenceStatus',
  'cachedFromVault'
]);

const ALLOWED_PATCH_KEYS = new Set([
  'deviceName',
  'status',
  'decision',
  'localDecision',
  'score',
  'reasons',
  'indicators',
  'recommendedAction',
  'riskLevel',
  'verificationStatus',
  'destinationHost',
  'registrableDomain',
  'protocol',
  'notes'
]);

const DEFAULT_ACTION_FOR_DECISION = {
  BLOCK: 'DO_NOT_OPEN',
  SUSPICIOUS: 'WARN_USER',
  HOLD: 'HOLD',
  SAFE: 'ALLOW',
  KNOWN_SAFE: 'ALLOW',
  NO_KNOWN_THREAT: 'ALLOW_WITH_CAUTION'
};

const CAPACITOR_APP_ORIGINS = new Set([
  'https://localhost',
  'http://localhost',
  'capacitor://localhost',
  'ionic://localhost'
]);

function isTrustedProxyAddress(address) {
  if (!address || typeof address !== 'string') return false;
  const cleaned = address.replace(/^::ffff:/, '').trim();
  if (cleaned === '127.0.0.1' || cleaned === '::1') return true;
  if (!net.isIPv4(cleaned)) return false;
  const parts = cleaned.split('.').map(Number);
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  return false;
}

function findPrivacyViolation(value, depth = 0, pathPrefix = '') {
  if (depth > 8 || value === null || value === undefined) {
    return null;
  }

  if (typeof value === 'string') {
    if (/\?(?:[^=]+=[^&]*&?){1,}/.test(value) || /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(value)) {
      return 'RAW_QUERY_OR_PII_DETECTED';
    }
    return null;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const violation = findPrivacyViolation(item, depth + 1, pathPrefix);
      if (violation) return violation;
    }
    return null;
  }

  if (typeof value === 'object') {
    for (const [key, nested] of Object.entries(value)) {
      const fullPath = pathPrefix ? `${pathPrefix}.${key}` : key;
      const normalizedKey = key.replace(/[_-]/g, '').toLowerCase();
      const isSafeInspectionQueryMetrics =
        fullPath === 'localVerification.urlInspection.query' &&
        nested !== null &&
        typeof nested === 'object' &&
        !Array.isArray(nested);

      if (!isSafeInspectionQueryMetrics && FORBIDDEN_PRIVACY_KEYS.has(normalizedKey)) {
        return `FORBIDDEN_FIELD_${key.toUpperCase().slice(0, 24)}`;
      }
      const violation = findPrivacyViolation(nested, depth + 1, fullPath);
      if (violation) return violation;
    }
  }

  return null;
}

function parseCodeArray(value, maxItems = 40) {
  if (!Array.isArray(value) || value.length > maxItems) {
    return null;
  }

  const out = [];
  for (const item of value) {
    if (typeof item !== 'string' || !VALID_CODE.test(item)) {
      return null;
    }
    out.push(item);
  }

  return [...new Set(out)];
}

function parseJsonSafely(raw, fallback) {
  try {
    const parsed = JSON.parse(raw);
    return parsed ?? fallback;
  } catch {
    return fallback;
  }
}

function sanitizeHost(value) {
  if (value === undefined || value === null || value === '') {
    return null;
  }
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim().toLowerCase();
  if (!trimmed || trimmed.length > 253) {
    return undefined;
  }
  if (
    trimmed.includes('/') ||
    trimmed.includes('?') ||
    trimmed.includes('#') ||
    trimmed.includes('@') ||
    !VALID_HOSTNAME.test(trimmed)
  ) {
    return undefined;
  }
  return trimmed;
}

function sanitizeSecurityChecks(rawChecks) {
  if (rawChecks === undefined || rawChecks === null) {
    return {};
  }
  if (typeof rawChecks !== 'object' || Array.isArray(rawChecks)) {
    return null;
  }

  const out = {};
  const allowedKeys = [
    'zeroEgressGuaranteed',
    'schemeAndEncodingCheck',
    'networkAndIpIsolationCheck',
    'homographAndBrandSpoofCheck',
    'malwareAndPathCheck',
    'redirectAndSmugglingCheck',
    'smsScamLureCheck'
  ];

  for (const [key, value] of Object.entries(rawChecks)) {
    if (!allowedKeys.includes(key)) {
      return null;
    }
    if (key === 'zeroEgressGuaranteed') {
      if (typeof value !== 'boolean') return null;
      out[key] = value;
    } else {
      if (typeof value !== 'string' || !VALID_CHECK_STATUSES.has(value)) return null;
      out[key] = value;
    }
  }

  return out;
}

function sanitizeUrlInspection(rawInspection) {
  if (rawInspection === undefined || rawInspection === null) {
    return {};
  }
  if (typeof rawInspection !== 'object' || Array.isArray(rawInspection)) {
    return null;
  }

  const out = {};

  if (rawInspection.path !== undefined) {
    const p = rawInspection.path;
    if (!p || typeof p !== 'object' || Array.isArray(p)) return null;
    const pathSafe = {};
    for (const numKey of ['segmentCount', 'originalPathLength', 'sensitivePathSegmentCount']) {
      if (p[numKey] !== undefined) {
        if (!Number.isInteger(p[numKey]) || p[numKey] < 0 || p[numKey] > 10000) return null;
        pathSafe[numKey] = p[numKey];
      }
    }
    if (p.extension !== undefined && p.extension !== null) {
      if (typeof p.extension !== 'string' || !/^\.?[a-z0-9]{1,16}$/i.test(p.extension)) return null;
      pathSafe.extension = p.extension.toLowerCase();
    }
    if (p.indicators !== undefined) {
      const parsed = parseCodeArray(p.indicators, 20);
      if (!parsed) return null;
      pathSafe.indicators = parsed;
    }
    out.path = pathSafe;
  }

  if (rawInspection.query !== undefined) {
    const q = rawInspection.query;
    if (!q || typeof q !== 'object' || Array.isArray(q)) return null;
    const querySafe = {};
    for (const numKey of [
      'parameterCount',
      'redirectParameterCount',
      'nestedDestinationCount',
      'sensitiveParameterCount',
      'trackingParameterCount'
    ]) {
      if (q[numKey] !== undefined) {
        if (!Number.isInteger(q[numKey]) || q[numKey] < 0 || q[numKey] > 1000) return null;
        querySafe[numKey] = q[numKey];
      }
    }
    for (const boolKey of [
      'fragmentPresent',
      'fragmentHasUrl',
      'fragmentContainsSensitiveMaterial'
    ]) {
      if (q[boolKey] !== undefined) {
        if (typeof q[boolKey] !== 'boolean') return null;
        querySafe[boolKey] = q[boolKey];
      }
    }
    if (q.indicators !== undefined) {
      const parsed = parseCodeArray(q.indicators, 20);
      if (!parsed) return null;
      querySafe.indicators = parsed;
    }
    out.query = querySafe;
  }

  return out;
}

function hasControlChars(text) {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if ((code <= 0x1F && code !== 0x0A) || (code >= 0x7F && code <= 0x9F)) {
      return true;
    }
  }
  return false;
}

function sanitizeDeviceName(value) {
  if (value === undefined || value === null || value === '') {
    return null;
  }
  if (typeof value !== 'string') {
    return undefined;
  }
  const normalized = value.trim().replace(/\s{2,}/g, ' ');
  if (!normalized || normalized.length > 80 || hasControlChars(normalized)) {
    return undefined;
  }
  if (
    normalized.includes('@') ||
    normalized.includes('://') ||
    normalized.includes('?') ||
    normalized.includes('#') ||
    !/^[A-Za-z0-9][A-Za-z0-9 ._()+/-]{0,79}$/.test(normalized)
  ) {
    return undefined;
  }
  return normalized;
}

function createApp({
  db,
  config = {},
  logger = null,
  metrics = null,
  apiTokenStore,
  appIngestAuth,
  proofVerifier
} = {}) {
  if (!db) {
    throw new Error('SQLite database connection is required');
  }

  if (!apiTokenStore || typeof apiTokenStore.matches !== 'function') {
    throw new Error('Key Vault API token store is required');
  }

  if (!appIngestAuth || typeof appIngestAuth.matches !== 'function') {
    throw new Error('Dedicated app ingest authenticator is required');
  }

  if (!proofVerifier || typeof proofVerifier.verify !== 'function') {
    throw new Error('Cryptographic event proof verifier is required');
  }

  const requireAppHeader = config?.eventProof?.requireAppHeader !== false;
  const allowedApps = new Set(
    Array.isArray(config?.eventProof?.allowedAppIds) && config.eventProof.allowedAppIds.length > 0
      ? config.eventProof.allowedAppIds
      : ['com.safegate.app']
  );

  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', false);

  function writeLog(level, message, metadata = {}) {
    if (logger && typeof logger[level] === 'function') {
      logger[level](message, metadata);
      return;
    }

    console.log(JSON.stringify({
      level: level.toUpperCase(),
      service: 'safegateway.platform',
      message,
      ...metadata
    }));
  }

  function sendError(res, status, code, message, requestId) {
    const safeMessage = String(message || 'Request failed');

    res.locals.apiError = {
      code: String(code || 'REQUEST_FAILED'),
      message: safeMessage
    };

    return res.status(status).json({
      error: {
        code,
        message: safeMessage,
        requestId
      }
    });
  }

  function isValidId(value) {
    return typeof value === 'string' && VALID_ID.test(value);
  }

  function formatEvent(row) {
    const reasons = parseJsonSafely(row.reasons_json, []);
    const indicators = parseJsonSafely(row.indicators_json || '[]', []);
    const securityChecks = parseJsonSafely(row.security_checks_json || '{}', {});
    const urlInspection = parseJsonSafely(row.url_inspection_json || '{}', {});

    return {
      requestId: row.request_id,
      deviceId: row.device_id,
      deviceName: row.device_name || null,
      eventTime: row.event_time,
      decision: row.decision,
      score: row.score,
      reasons: Array.isArray(reasons) ? reasons : [],
      status: row.status,
      verificationStatus: row.verification_status || 'COMPLETED',
      localDecision: row.local_decision || null,
      stage: row.stage || null,
      recommendedAction: row.recommended_action || null,
      destinationHost: row.destination_host || null,
      registrableDomain: row.registrable_domain || null,
      protocol: row.protocol || null,
      indicators: Array.isArray(indicators) ? indicators : [],
      securityChecks: securityChecks && typeof securityChecks === 'object' ? securityChecks : {},
      urlInspection: urlInspection && typeof urlInspection === 'object' ? urlInspection : {},
      riskLevel: row.risk_level || null,
      layersExecutedCount: Number.isInteger(row.layers_executed_count) ? row.layers_executed_count : 0,
      zeroEgress: row.zero_egress !== 0,
      appVersion: row.app_version || null,
      notes: row.operator_notes || null,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  // --------------------------------------------------
  // HTTP REQUEST AUDIT MIDDLEWARE
  // --------------------------------------------------

  function safeAuditEndpoint(req) {
    const matchedRoute = req.route && req.route.path;

    if (typeof matchedRoute === 'string') {
      return `${req.baseUrl || ''}${matchedRoute}`.slice(0, 256);
    }

    const pathname = req.path || '/';

    if (pathname === '/health') return '/health';
    if (pathname === '/ready') return '/ready';
    if (pathname === '/api/v1/events') return '/api/v1/events';
    if (/^\/api\/v1\/app\/events\/[^/]+\/decision$/.test(pathname)) return '/api/v1/app/events/:requestId/decision';
    if (/^\/api\/v1\/events\/[^/]+$/.test(pathname)) return '/api/v1/events/:requestId';

    return String(pathname).slice(0, 256);
  }

  function resolveOperation(method) {
    switch (method) {
      case 'GET':
      case 'HEAD':
        return 'READ';
      case 'POST':
        return 'CREATE';
      case 'PUT':
      case 'PATCH':
        return 'UPDATE';
      case 'DELETE':
        return 'DELETE';
      default:
        return 'OTHER';
    }
  }

  const insertApiAudit = db.prepare(`
    INSERT INTO api_request_logs (
      request_id,
      method,
      endpoint,
      status_code,
      error_code,
      duration_ms,
      occurred_at,
      auth_outcome,
      operation
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  app.use((req, res, next) => {
    const startedAt = process.hrtime.bigint();

    req.requestId = crypto.randomUUID();
    res.setHeader('X-Request-ID', req.requestId);

    const initialPath = String(req.path || '/');
    const isApiRequest =
      initialPath === '/api/v1' ||
      initialPath.startsWith('/api/v1/');

    req.authOutcome = isApiRequest ? 'NOT_CHECKED' : 'NOT_REQUIRED';

    if (isApiRequest && metrics) {
      metrics.requestsSinceHeartbeat = (metrics.requestsSinceHeartbeat || 0) + 1;
    }

    let recorded = false;

    function persistAudit(aborted = false) {
      if (recorded) return;
      recorded = true;

      const statusCode = aborted ? 499 : res.statusCode;
      const method = String(req.method || 'UNKNOWN').toUpperCase().slice(0, 20);
      const endpoint = safeAuditEndpoint(req);
      const elapsedNanoseconds = process.hrtime.bigint() - startedAt;
      const durationMs = Number(elapsedNanoseconds) / 1e6;

      const apiError = res.locals?.apiError || null;
      const internalError = res.locals?.internalError || null;

      let errorCode = null;
      if (statusCode >= 400) {
        errorCode =
          internalError?.errorCode ||
          apiError?.code ||
          (aborted ? 'REQUEST_ABORTED' : `HTTP_${statusCode}`);

        if (typeof errorCode !== 'string' || !/^[A-Z0-9_.:-]{1,64}$/.test(errorCode)) {
          errorCode = `HTTP_${statusCode}`;
        }
      }

      const allowedAuthOutcomes = ['NOT_REQUIRED', 'NOT_CHECKED', 'SUCCESS', 'FAILED'];
      const authOutcome = allowedAuthOutcomes.includes(req.authOutcome)
        ? req.authOutcome
        : 'NOT_CHECKED';

      const operation = res.locals?.auditOperation || resolveOperation(method);
      const occurredAt = new Date().toISOString();

      try {
        insertApiAudit.run(
          req.requestId,
          method,
          endpoint,
          statusCode,
          errorCode,
          Math.max(0, durationMs),
          occurredAt,
          authOutcome,
          operation
        );
      } catch (error) {
        const safeErrorCode =
          typeof error?.code === 'string' && /^[A-Z0-9_]+$/.test(error.code)
            ? error.code
            : 'AUDIT_WRITE_FAILED';

        writeLog('error', 'API audit persistence failed', {
          requestId: req.requestId,
          errorCode: safeErrorCode
        });
      }

      const logLevel =
        statusCode >= 500
          ? 'error'
          : statusCode >= 400
            ? 'warn'
            : 'info';

      writeLog(logLevel, 'API request completed', {
        requestId: req.requestId,
        method,
        endpoint,
        statusCode,
        errorCode,
        durationMs: Math.round(durationMs * 1000) / 1000,
        authOutcome,
        operation
      });
    }

    res.once('finish', () => persistAudit(false));
    res.once('close', () => {
      if (!res.writableFinished) {
        persistAudit(true);
      }
    });

    next();
  });

  // --------------------------------------------------
  // SECURITY HEADERS & ANTI-CACHING
  // --------------------------------------------------

  app.use(helmet({
    frameguard: { action: 'deny' },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"]
      }
    },
    referrerPolicy: { policy: 'no-referrer' }
  }));

  app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    next();
  });

  app.use('/api/v1', (req, res, next) => {
    const origin = req.get('origin');
    if (origin && CAPACITOR_APP_ORIGINS.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization, X-SafeGate-App, X-SafeGate-App-Key, X-SafeGate-Proof, X-SafeGate-Device-Id'
      );
      res.setHeader('Access-Control-Max-Age', '600');
      if (req.method === 'OPTIONS') {
        return res.status(204).end();
      }
    }
    next();
  });

  // --------------------------------------------------
  // HEALTH & READINESS CHECKS
  // --------------------------------------------------

  app.get('/health', (req, res) => {
    return res.status(200).json({
      status: 'ok',
      application: 'safegate-platform'
    });
  });

  app.get('/ready', (req, res) => {
    try {
      const integrity = db.pragma('quick_check');

      if (!integrity.length || integrity[0].quick_check !== 'ok') {
        return res.status(503).json({ status: 'not-ready' });
      }

      if (apiTokenStore.activeCount() < 1) {
        return res.status(503).json({ status: 'not-ready' });
      }

      return res.status(200).json({
        status: 'ready',
        database: 'connected'
      });
    } catch {
      return res.status(503).json({ status: 'not-ready' });
    }
  });

  // --------------------------------------------------
  // HARDENED RATE LIMITING (IP + PER-DEVICE)
  // --------------------------------------------------

  const apiRateBuckets = new Map();
  const deviceRateBuckets = new Map();

  const API_RATE_WINDOW_MS = 60 * 1000;
  const API_RATE_MAX_REQUESTS = 1200;
  const DEVICE_RATE_MAX_REQUESTS = 120;
  const API_RATE_MAX_BUCKETS = 10000;

  function resolveRateLimitKey(req) {
    const peerIp = req.socket?.remoteAddress || 'internal';
    if (isTrustedProxyAddress(peerIp)) {
      const forwardedAddress = req.get('x-real-ip') || '';
      if (
        forwardedAddress.length > 0 &&
        forwardedAddress.length <= 64 &&
        /^[0-9a-fA-F:.]+$/.test(forwardedAddress)
      ) {
        return forwardedAddress;
      }
    }
    return peerIp;
  }

  function consumeBucket(bucketMap, key, maxRequests, now) {
    let bucket = bucketMap.get(key);

    if (!bucket || bucket.resetAt <= now) {
      if (bucketMap.size >= API_RATE_MAX_BUCKETS) {
        for (const [k, b] of bucketMap) {
          if (b.resetAt <= now) bucketMap.delete(k);
        }
      }

      if (bucketMap.size >= API_RATE_MAX_BUCKETS && !bucketMap.has(key)) {
        return { limited: true, retryAfter: 60 };
      }

      bucket = { count: 0, resetAt: now + API_RATE_WINDOW_MS };
      bucketMap.set(key, bucket);
    }

    bucket.count += 1;
    if (bucket.count > maxRequests) {
      return {
        limited: true,
        retryAfter: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))
      };
    }

    return { limited: false, retryAfter: 0 };
  }

  function rateLimitApiRequests(req, res, next) {
    const now = Date.now();
    const key = resolveRateLimitKey(req);
    const outcome = consumeBucket(apiRateBuckets, key, API_RATE_MAX_REQUESTS, now);

    if (outcome.limited) {
      res.setHeader('Retry-After', String(outcome.retryAfter));
      return sendError(
        res,
        429,
        'RATE_LIMITED',
        'Request rate is temporarily limited',
        req.requestId
      );
    }

    next();
  }

  // --------------------------------------------------
  // STRICT TWO-PLANE AUTHENTICATION
  // Plane A (App Only -> POST /api/v1/events):
  //   X-SafeGate-App + X-SafeGate-App-Key (or Authorization: App <key>) + single-use cryptographic proof
  // Plane B (Operator Key Vault Only -> GET / PATCH / DELETE):
  //   Authorization: Bearer <64-hex Key Vault 1h/6h token>
  // --------------------------------------------------

  function authenticateAppIngest(req, res, next) {
    req.authOutcome = 'FAILED';

    if (requireAppHeader) {
      const appHeader = (req.get('x-safegate-app') || '').trim();
      if (!VALID_APP_ID.test(appHeader) || !allowedApps.has(appHeader)) {
        writeLog('warn', 'Unauthorized app client header on insert', {
          requestId: req.requestId
        });
        return sendError(
          res,
          403,
          'APP_CLIENT_NOT_AUTHORIZED',
          'Client application is not authorized to insert events',
          req.requestId
        );
      }
    }

    const headerKey = (req.get('x-safegate-app-key') || '').trim();
    const authHeader = req.get('authorization') || '';
    const appAuthMatch = authHeader.match(/^App ([A-Za-z0-9._~+/-]{32,512})$/i);
    const providedAppKey = headerKey || (appAuthMatch ? appAuthMatch[1] : '');

    if (!providedAppKey || !appIngestAuth.matches(providedAppKey)) {
      writeLog('warn', 'App ingest authentication rejected', {
        requestId: req.requestId
      });

      return sendError(
        res,
        401,
        'APP_INGEST_AUTH_REQUIRED',
        'Valid app ingest authentication is required',
        req.requestId
      );
    }

    req.authOutcome = 'SUCCESS';
    next();
  }

  function authenticateOperatorVault(req, res, next) {
    req.authOutcome = 'FAILED';

    const authorization = req.get('authorization') || '';
    const match = authorization.match(/^Bearer ([a-fA-F0-9]{64})$/i);

    if (!match || !apiTokenStore.matches(match[1])) {
      writeLog('warn', 'Operator Key Vault authentication rejected', {
        requestId: req.requestId
      });

      return sendError(
        res,
        401,
        'UNAUTHORIZED',
        'Valid Key Vault Bearer authentication is required',
        req.requestId
      );
    }

    req.authOutcome = 'SUCCESS';
    next();
  }

  function requireJsonContentType(req, res, next) {
    if (
      (req.method === 'POST' || req.method === 'PATCH') &&
      !req.is('application/json')
    ) {
      return sendError(
        res,
        415,
        'UNSUPPORTED_MEDIA_TYPE',
        'Content-Type must be application/json',
        req.requestId
      );
    }
    next();
  }

  app.use('/api/v1', rateLimitApiRequests);
  app.use('/api/v1', requireJsonContentType);
  app.use('/api/v1', express.json({
    limit: '32kb',
    strict: true
  }));

  // --------------------------------------------------
  // PLANE A: APP-ONLY VERIFIED EVENT INSERT
  // POST /api/v1/events
  // --------------------------------------------------

  const insertEventStmt = db.prepare(`
    INSERT INTO security_events (
      request_id,
      device_id,
      device_name,
      event_time,
      decision,
      score,
      reasons_json,
      status,
      verification_status,
      local_decision,
      stage,
      recommended_action,
      destination_host,
      registrable_domain,
      protocol,
      indicators_json,
      security_checks_json,
      url_inspection_json,
      risk_level,
      layers_executed_count,
      zero_egress,
      proof_jti,
      payload_hash,
      app_version,
      operator_notes,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
  `);

  const upsertDeviceStmt = db.prepare(`
    INSERT INTO devices (
      device_id,
      device_name,
      status,
      first_seen_at,
      last_seen_at
    )
    VALUES (?, ?, 'ACTIVE', ?, ?)
    ON CONFLICT(device_id)
    DO UPDATE SET
      device_name = COALESCE(excluded.device_name, devices.device_name),
      status = 'ACTIVE',
      last_seen_at = excluded.last_seen_at
  `);

  const insertProofTokenStmt = db.prepare(`
    INSERT INTO consumed_proof_tokens (
      jti,
      request_id,
      device_id,
      payload_hash,
      expires_at,
      consumed_at
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const pruneExpiredProofsStmt = db.prepare(`
    DELETE FROM consumed_proof_tokens
    WHERE expires_at < ?
  `);

  let ingestCountSincePrune = 0;

  app.post('/api/v1/events', authenticateAppIngest, (req, res, next) => {
    try {
      const body = req.body;

      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        return sendError(res, 400, 'INVALID_BODY', 'A JSON object is required', req.requestId);
      }

      if (Object.keys(body).some(key => !ALLOWED_POST_KEYS.has(key))) {
        return sendError(res, 400, 'INVALID_FIELDS', 'Unsupported fields are not accepted', req.requestId);
      }

      const privacyViolation = findPrivacyViolation(body);
      if (privacyViolation) {
        return sendError(
          res,
          400,
          'PRIVACY_VIOLATION_REJECTED',
          'Raw URLs, query parameters, and personal data must stay on-device',
          req.requestId
        );
      }

      const { requestId, deviceId, eventTime, appVersion } = body;

      if (!isValidId(requestId)) {
        return sendError(res, 400, 'INVALID_REQUEST_ID', 'A valid requestId is required', req.requestId);
      }

      if (!isValidId(deviceId)) {
        return sendError(res, 400, 'INVALID_DEVICE_ID', 'A valid deviceId is required', req.requestId);
      }

      const deviceName = sanitizeDeviceName(body.deviceName);
      if (deviceName === undefined) {
        return sendError(res, 400, 'INVALID_DEVICE_NAME', 'Invalid deviceName format', req.requestId);
      }

      const deviceLimit = consumeBucket(deviceRateBuckets, deviceId, DEVICE_RATE_MAX_REQUESTS, Date.now());
      if (deviceLimit.limited) {
        res.setHeader('Retry-After', String(deviceLimit.retryAfter));
        return sendError(res, 429, 'DEVICE_RATE_LIMITED', 'Device event rate exceeded', req.requestId);
      }

      const decision = String(body.finalDecision || body.decision || '').toUpperCase();
      if (!VALID_DECISIONS.has(decision)) {
        return sendError(res, 400, 'INVALID_DECISION', 'Invalid security decision', req.requestId);
      }

      const localVerif = body.localVerification;
      if (localVerif !== undefined && (localVerif === null || typeof localVerif !== 'object' || Array.isArray(localVerif))) {
        return sendError(res, 400, 'INVALID_LOCAL_VERIFICATION', 'Invalid localVerification object', req.requestId);
      }

      const riskSummary = body.riskSummary;
      if (riskSummary !== undefined && (riskSummary === null || typeof riskSummary !== 'object' || Array.isArray(riskSummary))) {
        return sendError(res, 400, 'INVALID_RISK_SUMMARY', 'Invalid riskSummary object', req.requestId);
      }

      const rawScore =
        body.score ??
        (localVerif?.riskScore === null && decision === 'BLOCK' ? 100 : localVerif?.riskScore) ??
        (riskSummary?.score === null && decision === 'BLOCK' ? 100 : riskSummary?.score);

      const score = rawScore === undefined || rawScore === null
        ? (decision === 'BLOCK' ? 100 : 0)
        : rawScore;

      if (!Number.isInteger(score) || score < 0 || score > 100) {
        return sendError(res, 400, 'INVALID_SCORE', 'Score must be an integer between 0 and 100', req.requestId);
      }

      const rawReasons = body.finalReasonCodes ?? body.reasons ?? localVerif?.reasonCodes ?? [];
      const reasons = parseCodeArray(rawReasons, 30);
      if (reasons === null) {
        return sendError(res, 400, 'INVALID_REASONS', 'Invalid reason codes', req.requestId);
      }

      const rawIndicators = localVerif?.indicators ?? [];
      const indicators = parseCodeArray(rawIndicators, 40);
      if (indicators === null) {
        return sendError(res, 400, 'INVALID_INDICATORS', 'Invalid threat indicators', req.requestId);
      }

      const destObj = localVerif?.destination;
      if (destObj !== undefined && destObj !== null && (typeof destObj !== 'object' || Array.isArray(destObj))) {
        return sendError(res, 400, 'INVALID_DESTINATION', 'Invalid destination object', req.requestId);
      }

      const rawHost = destObj?.hostname ?? localVerif?.redactedDestination?.displayHost ?? null;
      const destinationHost = sanitizeHost(rawHost);
      if (destinationHost === undefined) {
        return sendError(res, 400, 'INVALID_DESTINATION_HOST', 'Destination must be a clean hostname without paths or queries', req.requestId);
      }

      const registrableDomain = sanitizeHost(destObj?.registrableDomain ?? null);
      if (registrableDomain === undefined) {
        return sendError(res, 400, 'INVALID_REGISTRABLE_DOMAIN', 'Registrable domain is invalid', req.requestId);
      }

      const protocol = destObj?.protocol ?? null;
      if (protocol !== null && protocol !== 'http:' && protocol !== 'https:') {
        return sendError(res, 400, 'INVALID_PROTOCOL', 'Protocol must be http: or https:', req.requestId);
      }

      const verificationStatus = body.verificationStatus || 'COMPLETED';
      if (verificationStatus !== 'COMPLETED' && verificationStatus !== 'INCOMPLETE') {
        return sendError(res, 400, 'INVALID_VERIFICATION_STATUS', 'Invalid verificationStatus', req.requestId);
      }

      const localDecision = localVerif?.decision ?? null;
      if (localDecision !== null && !VALID_LOCAL_DECISIONS.has(localDecision)) {
        return sendError(res, 400, 'INVALID_LOCAL_DECISION', 'Invalid localVerification decision', req.requestId);
      }

      const stage = localVerif?.stage ?? null;
      if (stage !== null && (typeof stage !== 'string' || !VALID_CODE.test(stage))) {
        return sendError(res, 400, 'INVALID_STAGE', 'Invalid local verification stage', req.requestId);
      }

      const recommendedAction = body.recommendedAction ?? null;
      if (recommendedAction !== null && !VALID_ACTIONS.has(recommendedAction)) {
        return sendError(res, 400, 'INVALID_ACTION', 'Invalid recommendedAction', req.requestId);
      }

      const riskLevel = riskSummary?.level ?? null;
      if (riskLevel !== null && !VALID_RISK_LEVELS.has(riskLevel)) {
        return sendError(res, 400, 'INVALID_RISK_LEVEL', 'Invalid risk level', req.requestId);
      }

      const securityChecks = sanitizeSecurityChecks(body.securityChecks);
      if (securityChecks === null) {
        return sendError(res, 400, 'INVALID_SECURITY_CHECKS', 'Invalid securityChecks summary', req.requestId);
      }

      const urlInspection = sanitizeUrlInspection(localVerif?.urlInspection);
      if (urlInspection === null) {
        return sendError(res, 400, 'INVALID_URL_INSPECTION', 'Invalid urlInspection metrics', req.requestId);
      }

      let layersExecutedCount = 0;
      if (body.layersExecuted !== undefined) {
        const layers = parseCodeArray(body.layersExecuted, 40);
        if (!layers) {
          return sendError(res, 400, 'INVALID_LAYERS', 'Invalid layersExecuted list', req.requestId);
        }
        layersExecutedCount = layers.length;
      }

      let normalizedEventTime = new Date().toISOString();
      if (eventTime !== undefined) {
        if (typeof eventTime !== 'string') {
          return sendError(res, 400, 'INVALID_EVENT_TIME', 'eventTime must be a date string', req.requestId);
        }
        const parsedDate = new Date(eventTime);
        if (Number.isNaN(parsedDate.getTime())) {
          return sendError(res, 400, 'INVALID_EVENT_TIME', 'Invalid event timestamp', req.requestId);
        }
        normalizedEventTime = parsedDate.toISOString();
      }

      if (appVersion !== undefined && (typeof appVersion !== 'string' || !/^[A-Za-z0-9._-]{1,32}$/.test(appVersion))) {
        return sendError(res, 400, 'INVALID_APP_VERSION', 'Invalid appVersion format', req.requestId);
      }

      const proofToken = req.get('x-safegate-proof') || body.verificationToken;
      if (!proofToken) {
        req.authOutcome = 'FAILED';
        return sendError(
          res,
          401,
          'PROOF_TOKEN_MISSING',
          'A valid verification proof token is required to insert events',
          req.requestId
        );
      }

      const proofResult = proofVerifier.verify(proofToken, {
        requestId,
        deviceId,
        decision,
        score,
        reasons,
        destinationHost,
        layersExecutedCount
      });

      if (!proofResult.valid) {
        req.authOutcome = 'FAILED';
        writeLog('warn', 'Event proof verification rejected', {
          requestId: req.requestId,
          errorCode: proofResult.code
        });

        return sendError(res, 403, proofResult.code, proofResult.message, req.requestId);
      }

      const zeroEgress =
        body.privacy?.zeroEgressOnDevice === false ||
        securityChecks.zeroEgressGuaranteed === false
          ? 0
          : 1;

      const now = new Date().toISOString();
      const nowEpochSec = Math.floor(Date.now() / 1000);

      const transaction = db.transaction(() => {
        upsertDeviceStmt.run(deviceId, deviceName, now, now);

        insertProofTokenStmt.run(
          proofResult.jti,
          requestId,
          deviceId,
          proofResult.payloadHash,
          proofResult.expiresAt,
          now
        );

        insertEventStmt.run(
          requestId,
          deviceId,
          deviceName,
          normalizedEventTime,
          decision,
          score,
          JSON.stringify(reasons),
          verificationStatus,
          localDecision,
          stage,
          recommendedAction,
          destinationHost,
          registrableDomain,
          protocol,
          JSON.stringify(indicators),
          JSON.stringify(securityChecks),
          JSON.stringify(urlInspection),
          riskLevel,
          layersExecutedCount,
          zeroEgress,
          proofResult.jti,
          proofResult.payloadHash,
          appVersion || null,
          now,
          now
        );

        ingestCountSincePrune += 1;
        if (ingestCountSincePrune >= 200) {
          ingestCountSincePrune = 0;
          pruneExpiredProofsStmt.run(nowEpochSec - 60);
        }
      });

      try {
        transaction();
      } catch (dbErr) {
        if (dbErr.code && dbErr.code.startsWith('SQLITE_CONSTRAINT')) {
          const isReplay =
            String(dbErr.message || '').includes('consumed_proof_tokens') ||
            String(dbErr.message || '').includes('jti');

          if (isReplay) {
            req.authOutcome = 'FAILED';
            return sendError(
              res,
              409,
              'PROOF_TOKEN_REPLAYED',
              'Verification proof token has already been used',
              req.requestId
            );
          }

          return sendError(
            res,
            409,
            'RECORD_CONFLICT',
            'Record already exists or violates database constraints',
            req.requestId
          );
        }
        throw dbErr;
      }

      writeLog('info', 'Verified security event stored', {
        requestId,
        decision,
        proofAlgorithm: proofResult.algorithm
      });

      return res.status(201).json({
        message: 'Event stored successfully',
        requestId,
        status: 'OPEN',
        payloadHash: proofResult.payloadHash
      });
    } catch (error) {
      next(error);
    }
  });

  // --------------------------------------------------
  // PLANE B: OPERATOR KEY VAULT API (GET / PATCH / DELETE)
  // Uses existing Azure Key Vault 1h/6h rotating Bearer token.
  // --------------------------------------------------

  const EVENT_SELECT_COLUMNS = `
    request_id,
    device_id,
    device_name,
    event_time,
    decision,
    score,
    reasons_json,
    status,
    verification_status,
    local_decision,
    stage,
    recommended_action,
    destination_host,
    registrable_domain,
    protocol,
    indicators_json,
    security_checks_json,
    url_inspection_json,
    risk_level,
    layers_executed_count,
    zero_egress,
    app_version,
    operator_notes,
    created_at,
    updated_at
  `;

  const insertAdminActionStmt = db.prepare(`
    INSERT INTO admin_actions (
      request_id,
      device_id,
      actor_id,
      action,
      created_at
    )
    VALUES (?, ?, ?, ?, ?)
  `);

  app.get('/api/v1/events', authenticateOperatorVault, (req, res, next) => {
    try {
      const deviceId = req.query.deviceId;
      const deviceNameQuery = req.query.deviceName;
      const status = req.query.status;
      const decision = req.query.decision;
      const registrableDomain = req.query.registrableDomain;

      if (deviceId !== undefined && !isValidId(deviceId)) {
        return sendError(res, 400, 'INVALID_DEVICE_ID', 'Invalid deviceId', req.requestId);
      }

      let safeDeviceNameFilter = null;
      if (deviceNameQuery !== undefined) {
        safeDeviceNameFilter = sanitizeDeviceName(deviceNameQuery);
        if (!safeDeviceNameFilter) {
          return sendError(res, 400, 'INVALID_DEVICE_NAME', 'Invalid deviceName filter', req.requestId);
        }
      }

      if (status !== undefined && !VALID_STATUSES.has(status)) {
        return sendError(res, 400, 'INVALID_STATUS', 'Invalid status filter', req.requestId);
      }

      if (decision !== undefined && !VALID_DECISIONS.has(String(decision).toUpperCase())) {
        return sendError(res, 400, 'INVALID_DECISION', 'Invalid decision filter', req.requestId);
      }

      let safeDomainFilter = null;
      if (registrableDomain !== undefined) {
        safeDomainFilter = sanitizeHost(registrableDomain);
        if (!safeDomainFilter) {
          return sendError(res, 400, 'INVALID_DOMAIN', 'Invalid registrableDomain filter', req.requestId);
        }
      }

      const limit = Number(req.query.limit ?? 50);
      const offset = Number(req.query.offset ?? 0);

      if (
        !Number.isSafeInteger(limit) ||
        limit < 1 ||
        limit > 100 ||
        !Number.isSafeInteger(offset) ||
        offset < 0
      ) {
        return sendError(res, 400, 'INVALID_PAGINATION', 'Invalid limit or offset', req.requestId);
      }

      const conditions = [];
      const parameters = [];

      if (deviceId !== undefined) {
        conditions.push('device_id = ?');
        parameters.push(deviceId);
      }

      if (safeDeviceNameFilter !== null) {
        conditions.push('device_name = ?');
        parameters.push(safeDeviceNameFilter);
      }

      if (status !== undefined) {
        conditions.push('status = ?');
        parameters.push(status);
      }

      if (decision !== undefined) {
        conditions.push('decision = ?');
        parameters.push(String(decision).toUpperCase());
      }

      if (safeDomainFilter !== null) {
        conditions.push('registrable_domain = ?');
        parameters.push(safeDomainFilter);
      }

      const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

      const rows = db.prepare(`
        SELECT ${EVENT_SELECT_COLUMNS}
        FROM security_events
        ${whereClause}
        ORDER BY event_time DESC
        LIMIT ? OFFSET ?
      `).all(...parameters, limit, offset);

      return res.status(200).json({
        count: rows.length,
        limit,
        offset,
        events: rows.map(formatEvent)
      });
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/v1/events/:requestId', authenticateOperatorVault, (req, res, next) => {
    try {
      const { requestId } = req.params;

      if (!isValidId(requestId)) {
        return sendError(res, 400, 'INVALID_REQUEST_ID', 'Invalid requestId', req.requestId);
      }

      const row = db.prepare(`
        SELECT ${EVENT_SELECT_COLUMNS}
        FROM security_events
        WHERE request_id = ?
      `).get(requestId);

      if (!row) {
        return sendError(res, 404, 'EVENT_NOT_FOUND', 'Event not found', req.requestId);
      }

      return res.status(200).json({
        event: formatEvent(row)
      });
    } catch (error) {
      next(error);
    }
  });

  // PATCH /api/v1/events/:requestId
  // Key Vault token holders can edit any mutable event data safely.
  app.patch('/api/v1/events/:requestId', authenticateOperatorVault, (req, res, next) => {
    try {
      const { requestId } = req.params;
      const body = req.body;

      if (!isValidId(requestId)) {
        return sendError(res, 400, 'INVALID_REQUEST_ID', 'Invalid requestId', req.requestId);
      }

      if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length === 0) {
        return sendError(res, 400, 'INVALID_UPDATE', 'At least one editable field is required', req.requestId);
      }

      if (Object.keys(body).some(key => !ALLOWED_PATCH_KEYS.has(key))) {
        return sendError(res, 400, 'INVALID_FIELDS', 'One or more fields cannot be modified', req.requestId);
      }

      const privacyViolation = findPrivacyViolation(body);
      if (privacyViolation) {
        return sendError(
          res,
          400,
          'PRIVACY_VIOLATION_REJECTED',
          'Raw URLs, query parameters, and personal data are not permitted',
          req.requestId
        );
      }

      const existing = db.prepare(`
        SELECT request_id, device_id
        FROM security_events
        WHERE request_id = ?
      `).get(requestId);

      if (!existing) {
        return sendError(res, 404, 'EVENT_NOT_FOUND', 'Event not found', req.requestId);
      }

      const setClauses = [];
      const values = [];

      if (body.deviceName !== undefined) {
        const nextDeviceName = sanitizeDeviceName(body.deviceName);
        if (nextDeviceName === undefined) {
          return sendError(res, 400, 'INVALID_DEVICE_NAME', 'Invalid deviceName format', req.requestId);
        }
        setClauses.push('device_name = ?');
        values.push(nextDeviceName);
      }

      if (body.status !== undefined) {
        if (!VALID_STATUSES.has(body.status)) {
          return sendError(res, 400, 'INVALID_STATUS', 'Invalid status value', req.requestId);
        }
        setClauses.push('status = ?');
        values.push(body.status);
      }

      if (body.decision !== undefined) {
        const nextDecision = String(body.decision).toUpperCase();
        if (!VALID_DECISIONS.has(nextDecision)) {
          return sendError(res, 400, 'INVALID_DECISION', 'Invalid security decision', req.requestId);
        }
        setClauses.push('decision = ?');
        values.push(nextDecision);

        if (body.recommendedAction === undefined && DEFAULT_ACTION_FOR_DECISION[nextDecision]) {
          setClauses.push('recommended_action = ?');
          values.push(DEFAULT_ACTION_FOR_DECISION[nextDecision]);
        }
      }

      if (body.localDecision !== undefined) {
        if (body.localDecision !== null && !VALID_LOCAL_DECISIONS.has(body.localDecision)) {
          return sendError(res, 400, 'INVALID_LOCAL_DECISION', 'Invalid localDecision', req.requestId);
        }
        setClauses.push('local_decision = ?');
        values.push(body.localDecision);
      }

      if (body.score !== undefined) {
        if (!Number.isInteger(body.score) || body.score < 0 || body.score > 100) {
          return sendError(res, 400, 'INVALID_SCORE', 'Score must be an integer between 0 and 100', req.requestId);
        }
        setClauses.push('score = ?');
        values.push(body.score);
      }

      if (body.reasons !== undefined) {
        const parsedReasons = parseCodeArray(body.reasons, 30);
        if (parsedReasons === null) {
          return sendError(res, 400, 'INVALID_REASONS', 'Invalid reason codes', req.requestId);
        }
        setClauses.push('reasons_json = ?');
        values.push(JSON.stringify(parsedReasons));
      }

      if (body.indicators !== undefined) {
        const parsedIndicators = parseCodeArray(body.indicators, 40);
        if (parsedIndicators === null) {
          return sendError(res, 400, 'INVALID_INDICATORS', 'Invalid threat indicators', req.requestId);
        }
        setClauses.push('indicators_json = ?');
        values.push(JSON.stringify(parsedIndicators));
      }

      if (body.recommendedAction !== undefined) {
        if (body.recommendedAction !== null && !VALID_ACTIONS.has(body.recommendedAction)) {
          return sendError(res, 400, 'INVALID_ACTION', 'Invalid recommendedAction', req.requestId);
        }
        setClauses.push('recommended_action = ?');
        values.push(body.recommendedAction);
      }

      if (body.riskLevel !== undefined) {
        if (body.riskLevel !== null && !VALID_RISK_LEVELS.has(body.riskLevel)) {
          return sendError(res, 400, 'INVALID_RISK_LEVEL', 'Invalid riskLevel', req.requestId);
        }
        setClauses.push('risk_level = ?');
        values.push(body.riskLevel);
      }

      if (body.verificationStatus !== undefined) {
        if (body.verificationStatus !== 'COMPLETED' && body.verificationStatus !== 'INCOMPLETE') {
          return sendError(res, 400, 'INVALID_VERIFICATION_STATUS', 'Invalid verificationStatus', req.requestId);
        }
        setClauses.push('verification_status = ?');
        values.push(body.verificationStatus);
      }

      if (body.destinationHost !== undefined) {
        const host = sanitizeHost(body.destinationHost);
        if (host === undefined) {
          return sendError(res, 400, 'INVALID_DESTINATION_HOST', 'Invalid destinationHost', req.requestId);
        }
        setClauses.push('destination_host = ?');
        values.push(host);
      }

      if (body.registrableDomain !== undefined) {
        const domain = sanitizeHost(body.registrableDomain);
        if (domain === undefined) {
          return sendError(res, 400, 'INVALID_REGISTRABLE_DOMAIN', 'Invalid registrableDomain', req.requestId);
        }
        setClauses.push('registrable_domain = ?');
        values.push(domain);
      }

      if (body.protocol !== undefined) {
        if (body.protocol !== null && body.protocol !== 'http:' && body.protocol !== 'https:') {
          return sendError(res, 400, 'INVALID_PROTOCOL', 'Invalid protocol', req.requestId);
        }
        setClauses.push('protocol = ?');
        values.push(body.protocol);
      }

      if (body.notes !== undefined) {
        if (body.notes !== null) {
          if (typeof body.notes !== 'string' || body.notes.length > 500 || hasControlChars(body.notes)) {
            return sendError(res, 400, 'INVALID_NOTES', 'Notes must be a clean string up to 500 characters', req.requestId);
          }
        }
        setClauses.push('operator_notes = ?');
        values.push(body.notes);
      }

      const now = new Date().toISOString();
      setClauses.push('updated_at = ?');
      values.push(now);

      const updateTransaction = db.transaction(() => {
        db.prepare(`
          UPDATE security_events
          SET ${setClauses.join(', ')}
          WHERE request_id = ?
        `).run(...values, requestId);

        insertAdminActionStmt.run(
          requestId,
          existing.device_id,
          'keyvault-operator',
          `PATCH:${Object.keys(body).sort().join(',')}`,
          now
        );
      });

      updateTransaction();

      const updatedRow = db.prepare(`
        SELECT ${EVENT_SELECT_COLUMNS}
        FROM security_events
        WHERE request_id = ?
      `).get(requestId);

      writeLog('info', 'Security event updated by operator', {
        requestId,
        fieldsCount: Object.keys(body).length
      });

      return res.status(200).json({
        message: 'Event updated successfully',
        requestId,
        event: formatEvent(updatedRow)
      });
    } catch (error) {
      next(error);
    }
  });

  app.delete('/api/v1/events/:requestId', authenticateOperatorVault, (req, res, next) => {
    try {
      const { requestId } = req.params;
      const archiveOnly = req.query.archive === 'true';

      if (!isValidId(requestId)) {
        return sendError(res, 400, 'INVALID_REQUEST_ID', 'Invalid requestId', req.requestId);
      }

      const existing = db.prepare(`
        SELECT device_id, status
        FROM security_events
        WHERE request_id = ?
      `).get(requestId);

      if (!existing) {
        return sendError(res, 404, 'EVENT_NOT_FOUND', 'Event not found', req.requestId);
      }

      const now = new Date().toISOString();

      if (archiveOnly) {
        if (existing.status !== 'ARCHIVED') {
          const archiveTx = db.transaction(() => {
            db.prepare(`
              UPDATE security_events
              SET status = 'ARCHIVED', updated_at = ?
              WHERE request_id = ?
            `).run(now, requestId);

            insertAdminActionStmt.run(
              requestId,
              existing.device_id,
              'keyvault-operator',
              'DELETE:ARCHIVED',
              now
            );
          });
          archiveTx();
        }

        writeLog('info', 'Security event archived by operator', { requestId });

        return res.status(200).json({
          message: 'Event archived successfully',
          requestId,
          status: 'ARCHIVED'
        });
      }

      const deleteTx = db.transaction(() => {
        db.prepare(`
          DELETE FROM security_events
          WHERE request_id = ?
        `).run(requestId);

        insertAdminActionStmt.run(
          requestId,
          existing.device_id,
          'keyvault-operator',
          'DELETE:PURGED',
          now
        );
      });
      deleteTx();

      writeLog('info', 'Security event deleted from database by operator', { requestId });

      return res.status(200).json({
        message: 'Event deleted from database successfully',
        requestId,
        deleted: true
      });
    } catch (error) {
      next(error);
    }
  });

  // --------------------------------------------------
  // PLANE A (READ-ONLY SELF-CHECK): APP-ONLY OVERRIDE STATUS BY REQUEST ID
  // Allows the app to check if an operator unblocked or blocked a specific requestId.
  // Requires App auth + matching deviceId (no cross-device data exposure).
  // --------------------------------------------------

  app.get('/api/v1/app/events/:requestId/decision', authenticateAppIngest, (req, res, next) => {
    try {
      const { requestId } = req.params;
      const deviceId = String(req.query.deviceId || req.get('x-safegate-device-id') || '').trim();

      if (!isValidId(requestId)) {
        return sendError(res, 400, 'INVALID_REQUEST_ID', 'Invalid requestId', req.requestId);
      }

      if (!isValidId(deviceId)) {
        return sendError(res, 400, 'INVALID_DEVICE_ID', 'Valid deviceId is required', req.requestId);
      }

      const row = db.prepare(`
        SELECT request_id, device_id, decision, recommended_action, status, updated_at
        FROM security_events
        WHERE request_id = ? AND device_id = ?
      `).get(requestId, deviceId);

      if (!row) {
        return sendError(res, 404, 'EVENT_NOT_FOUND', 'Event not found', req.requestId);
      }

      const decision = String(row.decision || 'HOLD').toUpperCase();
      const recommendedAction = row.recommended_action || DEFAULT_ACTION_FOR_DECISION[decision] || 'HOLD';
      const status = row.status || 'OPEN';

      const blocked =
        decision === 'BLOCK' ||
        recommendedAction === 'DO_NOT_OPEN';

      const allowOpen =
        !blocked &&
        (
          decision === 'SAFE' ||
          decision === 'KNOWN_SAFE' ||
          decision === 'NO_KNOWN_THREAT' ||
          recommendedAction === 'ALLOW' ||
          recommendedAction === 'ALLOW_WITH_CAUTION'
        );

      return res.status(200).json({
        requestId: row.request_id,
        status,
        decision,
        recommendedAction,
        blocked,
        allowOpen,
        overrideActive: status !== 'OPEN' || allowOpen,
        updatedAt: row.updated_at
      });
    } catch (error) {
      next(error);
    }
  });

  // Unsupported method handlers
  app.all('/api/v1/events', (req, res) => {
    res.setHeader('Allow', 'GET, POST, OPTIONS');
    return sendError(res, 405, 'METHOD_NOT_ALLOWED', 'Method not allowed for this endpoint', req.requestId);
  });

  app.all('/api/v1/events/:requestId', (req, res) => {
    res.setHeader('Allow', 'GET, PATCH, DELETE, OPTIONS');
    return sendError(res, 405, 'METHOD_NOT_ALLOWED', 'Method not allowed for this endpoint', req.requestId);
  });

  app.all('/api/v1/app/events/:requestId/decision', (req, res) => {
    res.setHeader('Allow', 'GET, OPTIONS');
    return sendError(res, 405, 'METHOD_NOT_ALLOWED', 'Method not allowed for this endpoint', req.requestId);
  });

  // Unknown routes (including removed /api/v1/admin/db/query)
  app.use((req, res) => {
    return sendError(res, 404, 'ROUTE_NOT_FOUND', 'API endpoint not found', req.requestId);
  });

  app.use((error, req, res, next) => {
    if (res.headersSent) {
      return next(error);
    }

    if (error.type === 'entity.too.large') {
      return sendError(res, 413, 'PAYLOAD_TOO_LARGE', 'Request body exceeds the allowed size', req.requestId);
    }

    if (error instanceof SyntaxError && error.status === 400) {
      return sendError(res, 400, 'INVALID_JSON', 'Invalid JSON request body', req.requestId);
    }

    res.locals.internalError = {
      errorName: error?.name || 'Error',
      errorCode: error?.code || 'INTERNAL_ERROR'
    };

    return sendError(res, 500, 'INTERNAL_SERVER_ERROR', 'An internal server error occurred', req.requestId);
  });

  return app;
}

module.exports = createApp;
module.exports.createApp = createApp;
