'use strict';

const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const {
  ALLOWED_OPERATOR_USERNAME,
  BIND_COOKIE_NAME,
  parseCookies,
  createLoginRateLimiter
} = require('./auth');

const VALID_REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;

function createDashboardApp({
  platformBaseUrl = 'http://platform:4317',
  vaultClient,
  sessionManager,
  distDir = path.join(__dirname, '..', 'dist'),
  cookieSecure = true,
  trustProxy = false,
  logger = null
} = {}) {
  if (!vaultClient || typeof vaultClient.getActiveToken !== 'function') {
    throw new Error('Layer 1 vaultClient is required');
  }
  if (!sessionManager || typeof sessionManager.verifySession !== 'function') {
    throw new Error('Layer 2 sessionManager is required');
  }

  const normalizedPlatformBase = String(platformBaseUrl || 'http://platform:4317').replace(/\/+$/, '');
  const loginLimiter = createLoginRateLimiter();

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', Boolean(trustProxy));

  app.use(helmet({
    frameguard: { action: 'deny' },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"]
      }
    },
    referrerPolicy: { policy: 'no-referrer' }
  }));

  app.use('/bff', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    next();
  });

  app.use('/bff', express.json({ limit: '32kb', strict: true }));

  function logSafe(level, message, meta = {}) {
    if (logger && typeof logger[level] === 'function') {
      logger[level](message, meta);
    }
  }

  function setBindCookie(res, bindSecret, maxAgeSec) {
    const attrs = [
      `${BIND_COOKIE_NAME}=${encodeURIComponent(bindSecret)}`,
      'Path=/bff',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${Math.max(60, maxAgeSec)}`
    ];
    if (cookieSecure) {
      attrs.push('Secure');
    }
    res.setHeader('Set-Cookie', attrs.join('; '));
  }

  function clearBindCookie(res) {
    const attrs = [
      `${BIND_COOKIE_NAME}=`,
      'Path=/bff',
      'HttpOnly',
      'SameSite=Strict',
      'Max-Age=0'
    ];
    if (cookieSecure) {
      attrs.push('Secure');
    }
    res.setHeader('Set-Cookie', attrs.join('; '));
  }

  function extractClientIp(req) {
    return req.get('x-real-ip') || req.ip || req.socket?.remoteAddress || 'unknown';
  }

  function requireDualLayerAuth(req, res, next) {
    const layer1Token = vaultClient.getActiveToken();
    if (!layer1Token) {
      return res.status(503).json({
        error: { code: 'LAYER1_VAULT_UNAVAILABLE', message: 'Platform vault credential is not active' }
      });
    }

    const authHeader = req.get('authorization') || '';
    const match = authHeader.match(/^Bearer\s+([A-Za-z0-9._-]+)$/i);
    const bearerToken = match ? match[1] : '';
    const cookies = parseCookies(req.get('cookie') || '');
    const bindSecret = cookies[BIND_COOKIE_NAME] || '';

    const check = sessionManager.verifySession({ bearerToken, bindSecret });
    if (!check.valid) {
      return res.status(401).json({
        error: { code: check.code || 'UNAUTHORIZED', message: 'Dual-layer operator authentication required' }
      });
    }

    req.operator = check;
    req.vaultBearerToken = layer1Token;
    next();
  }

  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok', service: 'safegate-dashboard' });
  });

  app.get('/ready', (_req, res) => {
    if (!vaultClient.isReady()) {
      return res.status(503).json({ status: 'not-ready', layer1VaultReady: false });
    }
    return res.status(200).json({ status: 'ready', layer1VaultReady: true });
  });

  // Layer 1 readiness preflight when frontend loads (NEVER returns any Key Vault secret!)
  app.get('/bff/bootstrap', (_req, res) => {
    const ready = vaultClient.isReady();
    if (!ready) {
      return res.status(503).json({
        ready: false,
        layer1VaultReady: false,
        operatorAccount: ALLOWED_OPERATOR_USERNAME
      });
    }
    return res.status(200).json({
      ready: true,
      layer1VaultReady: true,
      operatorAccount: ALLOWED_OPERATOR_USERNAME
    });
  });

  // Layer 2 single-owner login (pavanreddy only)
  app.post('/bff/auth/login', (req, res) => {
    if (!vaultClient.isReady()) {
      return res.status(503).json({
        error: { code: 'LAYER1_VAULT_UNAVAILABLE', message: 'Vault credential not ready yet' }
      });
    }

    const clientKey = extractClientIp(req);
    const rate = loginLimiter.check(clientKey);
    if (!rate.allowed) {
      res.setHeader('Retry-After', String(rate.retryAfterSec));
      return res.status(429).json({
        error: { code: 'LOGIN_RATE_LIMITED', message: 'Too many failed attempts. Try again later.' }
      });
    }

    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({
        error: { code: 'INVALID_LOGIN_BODY', message: 'Username and password are required' }
      });
    }

    const { username, password } = body;
    if (!sessionManager.verifyOperatorCredentials(username, password)) {
      loginLimiter.recordFailure(clientKey);
      logSafe('warn', 'Dashboard login rejected');
      return res.status(401).json({
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid operator username or password' }
      });
    }

    loginLimiter.recordSuccess(clientKey);
    const issued = sessionManager.issueSession();
    setBindCookie(res, issued.bindSecret, issued.expiresInSeconds);
    logSafe('info', 'Dashboard operator signed in', { username: issued.username });

    return res.status(200).json({
      authenticated: true,
      username: issued.username,
      token: issued.token,
      expiresAt: issued.expiresAt
    });
  });

  app.get('/bff/auth/session', requireDualLayerAuth, (req, res) => {
    return res.status(200).json({
      authenticated: true,
      username: req.operator.username,
      expiresAt: req.operator.expiresAt,
      layer1VaultReady: true
    });
  });

  app.post('/bff/auth/logout', (req, res) => {
    const authHeader = req.get('authorization') || '';
    const match = authHeader.match(/^Bearer\s+([A-Za-z0-9._-]+)$/i);
    const cookies = parseCookies(req.get('cookie') || '');
    if (match && cookies[BIND_COOKIE_NAME]) {
      const check = sessionManager.verifySession({
        bearerToken: match[1],
        bindSecret: cookies[BIND_COOKIE_NAME]
      });
      if (check.valid) {
        sessionManager.revokeSession(check.jti, check.expiresAt);
      }
    }
    clearBindCookie(res);
    return res.status(200).json({ loggedOut: true });
  });

  async function forwardToPlatform(req, res, targetPath, { method = 'GET', body = null } = {}) {
    const tryCall = async (vaultToken) => {
      const init = {
        method,
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${vaultToken}`
        },
        signal: AbortSignal.timeout(10000)
      };
      if (body !== null) {
        init.headers['Content-Type'] = 'application/json';
        init.body = JSON.stringify(body);
      }
      return fetch(`${normalizedPlatformBase}${targetPath}`, init);
    };

    try {
      let response = await tryCall(req.vaultBearerToken);

      // If platform just rotated its 1h Key Vault token ahead of BFF timer, refresh Layer-1 Vault token once transparently
      if (response.status === 401 && typeof vaultClient.refresh === 'function') {
        const refreshed = await vaultClient.refresh().catch(() => false);
        if (refreshed && vaultClient.getActiveToken()) {
          response = await tryCall(vaultClient.getActiveToken());
        }
      }

      const rawText = await response.text();
      let parsed = null;
      try {
        parsed = rawText ? JSON.parse(rawText) : {};
      } catch {
        parsed = { message: rawText || 'Upstream returned non-JSON response' };
      }

      return res.status(response.status).json(parsed);
    } catch {
      return res.status(502).json({
        error: { code: 'PLATFORM_UNREACHABLE', message: 'SafeGate platform API could not be reached' }
      });
    }
  }

  app.get('/bff/api/v1/events', requireDualLayerAuth, async (req, res) => {
    const params = new URLSearchParams();
    for (const key of ['deviceId', 'deviceName', 'status', 'decision', 'registrableDomain', 'limit', 'offset']) {
      if (req.query[key] !== undefined && String(req.query[key]).trim() !== '') {
        params.set(key, String(req.query[key]).trim());
      }
    }
    const qs = params.toString();
    await forwardToPlatform(req, res, `/api/v1/events${qs ? `?${qs}` : ''}`);
  });

  app.get('/bff/api/v1/events/:requestId', requireDualLayerAuth, async (req, res) => {
    const { requestId } = req.params;
    if (!VALID_REQUEST_ID.test(requestId)) {
      return res.status(400).json({ error: { code: 'INVALID_REQUEST_ID', message: 'Invalid requestId' } });
    }
    await forwardToPlatform(req, res, `/api/v1/events/${encodeURIComponent(requestId)}`);
  });

  app.patch('/bff/api/v1/events/:requestId', requireDualLayerAuth, async (req, res) => {
    const { requestId } = req.params;
    if (!VALID_REQUEST_ID.test(requestId)) {
      return res.status(400).json({ error: { code: 'INVALID_REQUEST_ID', message: 'Invalid requestId' } });
    }
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return res.status(400).json({ error: { code: 'INVALID_BODY', message: 'JSON object required' } });
    }
    await forwardToPlatform(req, res, `/api/v1/events/${encodeURIComponent(requestId)}`, {
      method: 'PATCH',
      body: req.body
    });
  });

  app.delete('/bff/api/v1/events/:requestId', requireDualLayerAuth, async (req, res) => {
    const { requestId } = req.params;
    if (!VALID_REQUEST_ID.test(requestId)) {
      return res.status(400).json({ error: { code: 'INVALID_REQUEST_ID', message: 'Invalid requestId' } });
    }
    const archiveSuffix = req.query.archive === 'true' ? '?archive=true' : '';
    await forwardToPlatform(req, res, `/api/v1/events/${encodeURIComponent(requestId)}${archiveSuffix}`, {
      method: 'DELETE'
    });
  });

  app.use('/bff', (_req, res) => {
    return res.status(404).json({ error: { code: 'BFF_ROUTE_NOT_FOUND', message: 'Endpoint not found' } });
  });

  if (fs.existsSync(distDir)) {
    app.use(express.static(distDir, {
      index: false,
      maxAge: '1h',
      setHeaders: (res, filePath) => {
        if (filePath.endsWith('index.html')) {
          res.setHeader('Cache-Control', 'no-store');
        }
      }
    }));

    app.use((req, res, next) => {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        return next();
      }
      res.setHeader('Cache-Control', 'no-store');
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.use((error, _req, res, _next) => {
    if (error?.type === 'entity.too.large') {
      return res.status(413).json({ error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body too large' } });
    }
    if (error instanceof SyntaxError && error.status === 400) {
      return res.status(400).json({ error: { code: 'INVALID_JSON', message: 'Malformed JSON body' } });
    }
    return res.status(500).json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Unexpected server error' } });
  });

  return app;
}

module.exports = {
  createDashboardApp
};
