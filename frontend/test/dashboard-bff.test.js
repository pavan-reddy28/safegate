'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const path = require('node:path');
const express = require('express');

const {
  createScryptHash,
  verifyScryptPassword,
  createSessionManager,
  BIND_COOKIE_NAME
} = require('../bff/auth');
const { createDashboardApp } = require('../bff/app');

function createPlatformStub({ initialVaultToken }) {
  let validVaultToken = initialVaultToken;
  const rows = new Map([
    [
      'vivo-event-001',
      {
        requestId: 'vivo-event-001',
        deviceId: 'sgdev-5a366ac3-d5c3-4fe9-8e1e-802625816bd3',
        deviceName: 'Vivo V2355',
        eventTime: '2026-11-15T12:47:40.333Z',
        decision: 'BLOCK',
        score: 100,
        reasons: ['BRAND_DOMAIN_SPOOFED_IN_SUBDOMAIN'],
        status: 'OPEN',
        verificationStatus: 'COMPLETED',
        localDecision: 'BLOCK',
        stage: 'LOCAL_OFFLINE',
        recommendedAction: 'DO_NOT_OPEN',
        destinationHost: null,
        registrableDomain: null,
        protocol: null,
        indicators: ['NON_STANDARD_PORT', 'BRAND_DOMAIN_SPOOFED_IN_SUBDOMAIN'],
        securityChecks: {
          zeroEgressGuaranteed: true,
          homographAndBrandSpoofCheck: 'FAILED'
        },
        urlInspection: {},
        riskLevel: 'CRITICAL',
        layersExecutedCount: 30,
        zeroEgress: true,
        appVersion: '2.0.0',
        notes: null,
        createdAt: '2026-11-15T12:47:40.336Z',
        updatedAt: '2026-11-15T12:47:40.336Z'
      }
    ]
  ]);

  const app = express();
  app.use(express.json());

  app.use('/api/v1/events', (req, res, next) => {
    const auth = req.get('authorization') || '';
    if (auth !== `Bearer ${validVaultToken}`) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid Vault Bearer token' } });
    }
    next();
  });

  app.get('/api/v1/events', (_req, res) => {
    const events = [...rows.values()];
    return res.status(200).json({ count: events.length, limit: 100, offset: 0, events });
  });

  app.get('/api/v1/events/:requestId', (req, res) => {
    const ev = rows.get(req.params.requestId);
    if (!ev) return res.status(404).json({ error: { code: 'EVENT_NOT_FOUND' } });
    return res.status(200).json({ event: ev });
  });

  app.patch('/api/v1/events/:requestId', (req, res) => {
    const existing = rows.get(req.params.requestId);
    if (!existing) return res.status(404).json({ error: { code: 'EVENT_NOT_FOUND' } });
    const updated = {
      ...existing,
      ...req.body,
      updatedAt: new Date().toISOString()
    };
    rows.set(req.params.requestId, updated);
    return res.status(200).json({ event: updated });
  });

  app.delete('/api/v1/events/:requestId', (req, res) => {
    const existing = rows.get(req.params.requestId);
    if (!existing) return res.status(404).json({ error: { code: 'EVENT_NOT_FOUND' } });
    if (req.query.archive === 'true') {
      const archived = { ...existing, status: 'ARCHIVED', updatedAt: new Date().toISOString() };
      rows.set(req.params.requestId, archived);
      return res.status(200).json({ archived: true, event: archived });
    }
    rows.delete(req.params.requestId);
    return res.status(200).json({ deleted: true, requestId: req.params.requestId });
  });

  return {
    app,
    rotateVaultToken(nextToken) {
      validVaultToken = nextToken;
    }
  };
}

function listenServer(app) {
  return new Promise((resolve) => {
    const srv = http.createServer(app);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      resolve({ server: srv, baseUrl: `http://127.0.0.1:${addr.port}` });
    });
  });
}

function extractCookieValue(setCookieHeader, name) {
  if (!setCookieHeader) return '';
  const raw = Array.isArray(setCookieHeader) ? setCookieHeader.join(';') : String(setCookieHeader);
  const re = new RegExp(`${name}=([^;]+)`);
  const match = raw.match(re);
  return match ? decodeURIComponent(match[1]) : '';
}

test('Auth enforces scrypt password hashing and single-owner pavanreddy access', () => {
  const pw = 'StrongTestPass#2026!';
  const hash = createScryptHash(pw);
  assert.ok(hash.startsWith('scrypt$'));
  assert.equal(verifyScryptPassword(pw, hash), true);
  assert.equal(verifyScryptPassword('wrong-password', hash), false);

  const sessionMgr = createSessionManager({
    sessionSecret: crypto.randomBytes(32).toString('hex'),
    operatorPasswordHash: hash
  });

  assert.equal(sessionMgr.verifyOperatorCredentials('pavanreddy', pw), true);
  assert.equal(sessionMgr.verifyOperatorCredentials('admin', pw), false);
  assert.equal(sessionMgr.verifyOperatorCredentials('root', pw), false);
  assert.equal(sessionMgr.verifyOperatorCredentials('pavanreddy', 'badpass'), false);

  const issued = sessionMgr.issueSession();
  assert.equal(sessionMgr.verifySession({ bearerToken: issued.token, bindSecret: issued.bindSecret }).valid, true);
  assert.equal(sessionMgr.verifySession({ bearerToken: issued.token, bindSecret: 'wrong-cookie' }).valid, false);
  assert.equal(sessionMgr.verifySession({ bearerToken: '', bindSecret: issued.bindSecret }).valid, false);

  sessionMgr.revokeSession(issued.jti, issued.expiresAt);
  assert.equal(sessionMgr.verifySession({ bearerToken: issued.token, bindSecret: issued.bindSecret }).valid, false);
});

test('Insights analytics, filtering, and CSV formula sanitization behave deterministically', async () => {
  const insightsMod = await import('../src/utils/insights.js');
  const sampleEvents = [
    {
      requestId: 'req-1',
      deviceId: 'sgdev-1',
      deviceName: 'Vivo V2355',
      eventTime: '2026-11-15T12:47:40.333Z',
      decision: 'BLOCK',
      score: 100,
      status: 'OPEN',
      reasons: ['BRAND_DOMAIN_SPOOFED_IN_SUBDOMAIN'],
      indicators: ['NON_STANDARD_PORT'],
      zeroEgress: true,
      notes: '=CMD|calc'
    },
    {
      requestId: 'req-2',
      deviceId: 'sgdev-2',
      deviceName: 'Pixel 9 Pro',
      eventTime: '2026-11-15T13:10:00.000Z',
      decision: 'SAFE',
      score: 5,
      status: 'RESOLVED',
      reasons: ['KNOWN_SAFE'],
      indicators: [],
      zeroEgress: true
    }
  ];

  const stats = insightsMod.computeDashboardInsights(sampleEvents);
  assert.equal(stats.total, 2);
  assert.equal(stats.blocked, 1);
  assert.equal(stats.safe, 1);
  assert.equal(stats.openQueue, 1);
  assert.equal(stats.uniqueDevices, 2);
  assert.equal(stats.devices[0].deviceName, 'Vivo V2355');

  const filtered = insightsMod.filterEvents(sampleEvents, { search: 'vivo v2355' });
  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].requestId, 'req-1');

  const csv = insightsMod.exportEventsToCsv(sampleEvents);
  assert.ok(csv.includes("'=CMD|calc"));
});

test('Dual-layer BFF enforces login + binding cookie and proxies GET/PATCH/DELETE with Layer-1 Vault token', async (t) => {
  const vaultToken1 = 'kv-rotatable-token-alpha-1234567890';
  const vaultToken2 = 'kv-rotatable-token-beta-0987654321';
  let currentVaultToken = vaultToken1;

  const platformStub = createPlatformStub({ initialVaultToken: vaultToken1 });
  const platformSrv = await listenServer(platformStub.app);
  t.after(() => platformSrv.server.close());

  const operatorPassword = 'OperatorSecretPassword#99';
  const sessionManager = createSessionManager({
    sessionSecret: crypto.randomBytes(32).toString('hex'),
    operatorPasswordHash: createScryptHash(operatorPassword)
  });

  const vaultClientMock = {
    isReady: () => Boolean(currentVaultToken),
    getActiveToken: () => currentVaultToken,
    async refresh() {
      currentVaultToken = vaultToken2;
      return true;
    }
  };

  const bffApp = createDashboardApp({
    platformBaseUrl: platformSrv.baseUrl,
    vaultClient: vaultClientMock,
    sessionManager,
    distDir: path.join(__dirname, '..', 'nonexistent-dist'),
    cookieSecure: false
  });
  const bffSrv = await listenServer(bffApp);
  t.after(() => bffSrv.server.close());

  // Bootstrap must never expose vault tokens
  const bootRes = await fetch(`${bffSrv.baseUrl}/bff/bootstrap`);
  assert.equal(bootRes.status, 200);
  const bootBody = await bootRes.json();
  assert.equal(bootBody.layer1VaultReady, true);
  assert.equal(bootBody.operatorAccount, 'pavanreddy');
  assert.equal(JSON.stringify(bootBody).includes(vaultToken1), false);

  // Unauthenticated access blocked
  const unauthEvents = await fetch(`${bffSrv.baseUrl}/bff/api/v1/events`);
  assert.equal(unauthEvents.status, 401);

  // Non-pavanreddy username rejected
  const wrongUser = await fetch(`${bffSrv.baseUrl}/bff/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'otheruser', password: operatorPassword })
  });
  assert.equal(wrongUser.status, 401);

  // Real pavanreddy login succeeds & sets HttpOnly binding cookie + Bearer token
  const loginRes = await fetch(`${bffSrv.baseUrl}/bff/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'pavanreddy', password: operatorPassword })
  });
  assert.equal(loginRes.status, 200);
  const loginData = await loginRes.json();
  assert.equal(loginData.authenticated, true);
  assert.ok(loginData.token.startsWith('sgop1.'));
  const bindCookie = extractCookieValue(loginRes.headers.get('set-cookie'), BIND_COOKIE_NAME);
  assert.ok(bindCookie.length > 20);

  // Bearer WITHOUT cookie fails 401
  const noCookieRes = await fetch(`${bffSrv.baseUrl}/bff/api/v1/events`, {
    headers: { Authorization: `Bearer ${loginData.token}` }
  });
  assert.equal(noCookieRes.status, 401);

  // Cookie WITHOUT Bearer fails 401
  const noBearerRes = await fetch(`${bffSrv.baseUrl}/bff/api/v1/events`, {
    headers: { Cookie: `${BIND_COOKIE_NAME}=${bindCookie}` }
  });
  assert.equal(noBearerRes.status, 401);

  // BOTH present succeeds via Layer-1 Vault token
  const listRes = await fetch(`${bffSrv.baseUrl}/bff/api/v1/events`, {
    headers: {
      Authorization: `Bearer ${loginData.token}`,
      Cookie: `${BIND_COOKIE_NAME}=${bindCookie}`
    }
  });
  assert.equal(listRes.status, 200);
  const listData = await listRes.json();
  assert.equal(listData.count, 1);
  assert.equal(listData.events[0].deviceName, 'Vivo V2355');

  // Rotate token on platform -> BFF transparently refreshes Layer-1 token on 401
  platformStub.rotateVaultToken(vaultToken2);

  const patchRes = await fetch(`${bffSrv.baseUrl}/bff/api/v1/events/vivo-event-001`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${loginData.token}`,
      Cookie: `${BIND_COOKIE_NAME}=${bindCookie}`
    },
    body: JSON.stringify({
      decision: 'SAFE',
      status: 'RESOLVED',
      recommendedAction: 'ALLOW',
      notes: 'Family domain approved'
    })
  });
  assert.equal(patchRes.status, 200);
  const patchData = await patchRes.json();
  assert.equal(patchData.event.decision, 'SAFE');
  assert.equal(patchData.event.status, 'RESOLVED');
  assert.equal(patchData.event.notes, 'Family domain approved');

  // Archive delete (?archive=true)
  const archiveRes = await fetch(`${bffSrv.baseUrl}/bff/api/v1/events/vivo-event-001?archive=true`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${loginData.token}`,
      Cookie: `${BIND_COOKIE_NAME}=${bindCookie}`
    }
  });
  assert.equal(archiveRes.status, 200);
  const archiveData = await archiveRes.json();
  assert.equal(archiveData.archived, true);
  assert.equal(archiveData.event.status, 'ARCHIVED');

  // Permanent hard delete
  const purgeRes = await fetch(`${bffSrv.baseUrl}/bff/api/v1/events/vivo-event-001`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${loginData.token}`,
      Cookie: `${BIND_COOKIE_NAME}=${bindCookie}`
    }
  });
  assert.equal(purgeRes.status, 200);
  const purgeData = await purgeRes.json();
  assert.equal(purgeData.deleted, true);

  const afterPurge = await fetch(`${bffSrv.baseUrl}/bff/api/v1/events/vivo-event-001`, {
    headers: {
      Authorization: `Bearer ${loginData.token}`,
      Cookie: `${BIND_COOKIE_NAME}=${bindCookie}`
    }
  });
  assert.equal(afterPurge.status, 404);

  // Logout revokes token immediately
  const logoutRes = await fetch(`${bffSrv.baseUrl}/bff/auth/logout`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${loginData.token}`,
      Cookie: `${BIND_COOKIE_NAME}=${bindCookie}`
    }
  });
  assert.equal(logoutRes.status, 200);

  const afterLogout = await fetch(`${bffSrv.baseUrl}/bff/auth/session`, {
    headers: {
      Authorization: `Bearer ${loginData.token}`,
      Cookie: `${BIND_COOKIE_NAME}=${bindCookie}`
    }
  });
  assert.equal(afterLogout.status, 401);
});
