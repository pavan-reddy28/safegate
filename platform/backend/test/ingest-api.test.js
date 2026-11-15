'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');

const { createApp } = require('../src/app');
const { createApiTokenStore } = require('../src/api-token-store');
const {
  createProofVerifier,
  computeVerificationPayloadDigest
} = require('../src/proof-verifier');

// In-memory SQLite mock matching the exact better-sqlite3 methods & schema columns used by app.js
function createSqliteMock() {
  const devices = new Map();
  const events = new Map();
  const consumedProofs = new Map();
  const adminActions = [];
  const audits = [];

  return {
    devices,
    events,
    consumedProofs,
    adminActions,
    audits,
    pragma(name) {
      if (name === 'quick_check') {
        return [{ quick_check: 'ok' }];
      }
      return [];
    },
    transaction(fn) {
      return () => {
        const devSnap = new Map(devices);
        const evtSnap = new Map([...events.entries()].map(([k, v]) => [k, { ...v }]));
        const prfSnap = new Map(consumedProofs);
        const admLen = adminActions.length;
        try {
          return fn();
        } catch (err) {
          devices.clear();
          for (const [k, v] of devSnap) devices.set(k, v);
          events.clear();
          for (const [k, v] of evtSnap) events.set(k, v);
          consumedProofs.clear();
          for (const [k, v] of prfSnap) consumedProofs.set(k, v);
          adminActions.length = admLen;
          throw err;
        }
      };
    },
    prepare(sql) {
      return {
        run(...args) {
          if (sql.includes('INSERT INTO api_request_logs')) {
            audits.push(args);
            return { changes: 1 };
          }
          if (sql.includes('INSERT INTO devices')) {
            devices.set(args[0], { first: args[1], last: args[2] });
            return { changes: 1 };
          }
          if (sql.includes('INSERT INTO consumed_proof_tokens')) {
            const jti = args[0];
            if (consumedProofs.has(jti)) {
              const err = new Error('UNIQUE constraint failed: consumed_proof_tokens.jti');
              err.code = 'SQLITE_CONSTRAINT_PRIMARYKEY';
              throw err;
            }
            consumedProofs.set(jti, { requestId: args[1], expiresAt: args[4] });
            return { changes: 1 };
          }
          if (sql.includes('DELETE FROM consumed_proof_tokens')) {
            for (const [k, v] of consumedProofs) {
              if (v.expiresAt < args[0]) consumedProofs.delete(k);
            }
            return { changes: 0 };
          }
          if (sql.includes('INSERT INTO admin_actions')) {
            adminActions.push({
              request_id: args[0],
              device_id: args[1],
              actor_id: args[2],
              action: args[3],
              created_at: args[4]
            });
            return { changes: 1 };
          }
          if (sql.includes('INSERT INTO security_events')) {
            const rid = args[0];
            if (events.has(rid)) {
              const err = new Error('UNIQUE constraint failed: security_events.request_id');
              err.code = 'SQLITE_CONSTRAINT_PRIMARYKEY';
              throw err;
            }
            events.set(rid, {
              request_id: args[0],
              device_id: args[1],
              event_time: args[2],
              decision: args[3],
              score: args[4],
              reasons_json: args[5],
              status: 'OPEN',
              verification_status: args[6],
              local_decision: args[7],
              stage: args[8],
              recommended_action: args[9],
              destination_host: args[10],
              registrable_domain: args[11],
              protocol: args[12],
              indicators_json: args[13],
              security_checks_json: args[14],
              url_inspection_json: args[15],
              risk_level: args[16],
              layers_executed_count: args[17],
              zero_egress: args[18],
              proof_jti: args[19],
              payload_hash: args[20],
              app_version: args[21],
              operator_notes: null,
              created_at: args[22],
              updated_at: args[23]
            });
            return { changes: 1 };
          }
          if (sql.includes('UPDATE security_events')) {
            const requestId = args[args.length - 1];
            const row = events.get(requestId);
            if (!row) return { changes: 0 };

            if (sql.includes("status = 'ARCHIVED'")) {
              row.status = 'ARCHIVED';
              row.updated_at = args[0];
              return { changes: 1 };
            }

            const setMatch = sql.match(/SET\s+([\s\S]+?)\s+WHERE/i);
            if (setMatch) {
              const assignments = setMatch[1].split(',').map(part => part.trim());
              assignments.forEach((assignment, index) => {
                const col = assignment.split('=')[0].trim();
                row[col] = args[index];
              });
            }
            return { changes: 1 };
          }
          return { changes: 0 };
        },
        get(...args) {
          if (sql.includes('FROM security_events') && sql.includes('WHERE request_id = ?')) {
            return events.get(args[0]) || undefined;
          }
          return undefined;
        },
        all(...args) {
          if (sql.includes('FROM security_events')) {
            const limit = args[args.length - 2];
            const offset = args[args.length - 1];
            const filterParams = args.slice(0, args.length - 2);
            let paramIndex = 0;

            let rows = [...events.values()];
            if (sql.includes('device_id = ?')) {
              const val = filterParams[paramIndex++];
              rows = rows.filter(r => r.device_id === val);
            }
            if (sql.includes('status = ?')) {
              const val = filterParams[paramIndex++];
              rows = rows.filter(r => r.status === val);
            }
            if (sql.includes('decision = ?')) {
              const val = filterParams[paramIndex++];
              rows = rows.filter(r => r.decision === val);
            }
            if (sql.includes('registrable_domain = ?')) {
              const val = filterParams[paramIndex++];
              rows = rows.filter(r => r.registrable_domain === val);
            }

            rows.sort((a, b) => String(b.event_time).localeCompare(String(a.event_time)));
            return rows.slice(offset, offset + limit);
          }
          return [];
        }
      };
    }
  };
}

function createTestAppIngestAuth(expectedKey) {
  const expectedDigest = crypto.createHash('sha256').update(expectedKey, 'utf8').digest();
  return {
    matches(candidateKey) {
      if (typeof candidateKey !== 'string' || candidateKey.trim().length < 32) {
        return false;
      }
      const candidateDigest = crypto.createHash('sha256').update(candidateKey.trim(), 'utf8').digest();
      return (
        candidateDigest.length === expectedDigest.length &&
        crypto.timingSafeEqual(candidateDigest, expectedDigest)
      );
    }
  };
}

function makeSignedProof(claims, proofSecret) {
  const key = crypto.createHash('sha256').update(proofSecret, 'utf8').digest();
  const encoded = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', key).update(`sgp1.${encoded}`, 'utf8').digest('base64url');
  return `sgp1.${encoded}.${sig}`;
}

function sendHttpRequest(port, method, path, headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path,
        method,
        headers
      },
      res => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = JSON.parse(text);
          } catch {
            json = null;
          }
          resolve({ status: res.statusCode, headers: res.headers, json, text });
        });
      }
    );
    req.on('error', reject);
    if (body !== null) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

test('Two-Plane Auth enforces App-Only POST ingest with replay/privacy protection and Key Vault Bearer token for GET/PATCH/DELETE', async () => {
  const db = createSqliteMock();
  const apiTokenStore = createApiTokenStore();
  const vaultBearerToken = 'a1'.repeat(32);
  apiTokenStore.set('1h', vaultBearerToken, new Date(Date.now() + 600000));

  const appIngestKey = 'safegate-app-only-ingest-credential-99887766554433221100';
  const appIngestAuth = createTestAppIngestAuth(appIngestKey);

  const proofSecret = 'safegate-platform-test-proof-hmac-key-0123456789';
  const proofVerifier = createProofVerifier({
    hmacSecret: proofSecret,
    maxTtlSeconds: 300,
    requirePayloadDigest: true,
    allowedAppIds: ['com.safegate.app']
  });

  const silentLogger = {
    info() {},
    warn() {},
    error() {},
    fatal() {},
    idle() {}
  };

  const app = createApp({
    db,
    config: {
      eventProof: {
        requireAppHeader: true,
        allowedAppIds: ['com.safegate.app']
      }
    },
    logger: silentLogger,
    apiTokenStore,
    appIngestAuth,
    proofVerifier
  });

  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const { port } = server.address();

  try {
    // 1. Health & Readiness
    const health = await sendHttpRequest(port, 'GET', '/health');
    assert.equal(health.status, 200);
    const ready = await sendHttpRequest(port, 'GET', '/ready');
    assert.equal(ready.status, 200);

    // 2. Removed admin SQL endpoint returns 404
    const adminSql = await sendHttpRequest(
      port,
      'POST',
      '/api/v1/admin/db/query',
      {
        Authorization: `Bearer ${vaultBearerToken}`,
        'X-SafeGate-App': 'com.safegate.app',
        'Content-Type': 'application/json'
      },
      { query: 'SELECT 1' }
    );
    assert.equal(adminSql.status, 404);

    // Build realistic SafeGate localVerification payload
    const requestId = 'f70d31c1-6456-4361-8792-0ceec2f86e94';
    const deviceId = 'device-android-pixel9';
    const payload = {
      requestId,
      deviceId,
      verificationStatus: 'COMPLETED',
      localVerification: {
        decision: 'REPUTATION_CHECK_REQUIRED',
        stage: 'LOCAL',
        reasonCodes: ['LOCAL_STRUCTURAL_CHECK_PASSED'],
        indicators: [],
        destination: {
          hostname: 'api.pavanserver.me',
          registrableDomain: 'pavanserver.me',
          protocol: 'https:',
          nonStandardPort: false
        },
        redactedDestination: {
          originOnly: 'https://api.pavanserver.me',
          displayHost: 'api.pavanserver.me',
          privateComponentsStripped: true
        },
        riskScore: 0,
        urlInspection: {
          path: {
            segmentCount: 1,
            extension: null,
            originalPathLength: 8,
            sensitivePathSegmentCount: 0,
            indicators: []
          },
          query: {
            parameterCount: 0,
            redirectParameterCount: 0,
            nestedDestinationCount: 0,
            sensitiveParameterCount: 0,
            trackingParameterCount: 0,
            fragmentPresent: false,
            fragmentHasUrl: false,
            fragmentContainsSensitiveMaterial: false,
            indicators: []
          }
        },
        reputationCheckRequired: true,
        privacy: {
          sensitiveQueryValuesDetected: false,
          sensitivePathSegmentsDetected: false,
          outboundNetworkCalls: 0,
          zeroEgressOnDevice: true
        }
      },
      securityChecks: {
        zeroEgressGuaranteed: true,
        schemeAndEncodingCheck: 'PASSED',
        networkAndIpIsolationCheck: 'PASSED',
        homographAndBrandSpoofCheck: 'PASSED',
        malwareAndPathCheck: 'PASSED',
        redirectAndSmugglingCheck: 'PASSED',
        smsScamLureCheck: 'PASSED'
      },
      finalDecision: 'HOLD',
      recommendedAction: 'HOLD',
      finalReasonCodes: [
        'REPUTATION_CHECK_UNAVAILABLE_ZERO_EGRESS',
        'LOCAL_STRUCTURAL_CHECKS_PASSED'
      ],
      riskSummary: {
        level: 'MEDIUM',
        score: 0,
        reasons: [
          'REPUTATION_CHECK_UNAVAILABLE_ZERO_EGRESS',
          'LOCAL_STRUCTURAL_CHECKS_PASSED'
        ],
        indicatorsCount: 0
      },
      layersExecuted: [
        'ZERO_EGRESS_ON_DEVICE_ENFORCEMENT',
        'HTTP_BOUNDARY_AND_HEADER_HARDENING'
      ],
      appVersion: '2.0.0'
    };

    const now = Math.floor(Date.now() / 1000);
    const proofToken = makeSignedProof(
      {
        jti: crypto.randomUUID(),
        rid: requestId,
        did: deviceId,
        app: 'com.safegate.app',
        dec: 'HOLD',
        uh: crypto.createHash('sha256').update('https://api.pavanserver.me/healthy').digest('hex'),
        ph: computeVerificationPayloadDigest({
          requestId,
          deviceId,
          decision: 'HOLD',
          score: 0,
          reasons: payload.finalReasonCodes,
          destinationHost: 'api.pavanserver.me',
          layersExecutedCount: 2
        }),
        iat: now,
        exp: now + 120
      },
      proofSecret
    );
    payload.verificationToken = proofToken;

    // 3. STRICT PLANE ISOLATION ON POST: Key Vault Bearer token MUST NOT be accepted to insert events
    const vaultTriedPost = await sendHttpRequest(
      port,
      'POST',
      '/api/v1/events',
      {
        Authorization: `Bearer ${vaultBearerToken}`,
        'X-SafeGate-App': 'com.safegate.app',
        'Content-Type': 'application/json'
      },
      payload
    );
    assert.equal(vaultTriedPost.status, 401);
    assert.equal(vaultTriedPost.json.error.code, 'APP_INGEST_AUTH_REQUIRED');

    // 4. Missing X-SafeGate-App header -> 403 APP_CLIENT_NOT_AUTHORIZED
    const missingAppHeader = await sendHttpRequest(
      port,
      'POST',
      '/api/v1/events',
      {
        'X-SafeGate-App-Key': appIngestKey,
        'Content-Type': 'application/json'
      },
      payload
    );
    assert.equal(missingAppHeader.status, 403);
    assert.equal(missingAppHeader.json.error.code, 'APP_CLIENT_NOT_AUTHORIZED');

    // 5. Authentic App-Only POST insert -> 201 Created
    const created = await sendHttpRequest(
      port,
      'POST',
      '/api/v1/events',
      {
        'X-SafeGate-App': 'com.safegate.app',
        'X-SafeGate-App-Key': appIngestKey,
        'Content-Type': 'application/json'
      },
      payload
    );
    assert.equal(created.status, 201);
    assert.equal(created.json.requestId, requestId);
    assert.equal(db.events.size, 1);
    assert.equal(db.consumedProofs.size, 1);

    // 6. Second insert via Authorization: App <key> header format also succeeds
    const requestId2 = 'b52b4b29-a6d9-4448-8bd7-5d1812000002';
    const proofToken2 = makeSignedProof(
      {
        jti: crypto.randomUUID(),
        rid: requestId2,
        did: deviceId,
        app: 'com.safegate.app',
        dec: 'BLOCK',
        uh: crypto.createHash('sha256').update('https://evil-phish.example/login').digest('hex'),
        ph: computeVerificationPayloadDigest({
          requestId: requestId2,
          deviceId,
          decision: 'BLOCK',
          score: 100,
          reasons: ['PHISHING_CONFIRMED'],
          destinationHost: 'evil-phish.example',
          layersExecutedCount: 0
        }),
        iat: now,
        exp: now + 120
      },
      proofSecret
    );
    const createdViaAppScheme = await sendHttpRequest(
      port,
      'POST',
      '/api/v1/events',
      {
        'X-SafeGate-App': 'com.safegate.app',
        Authorization: `App ${appIngestKey}`,
        'Content-Type': 'application/json'
      },
      {
        requestId: requestId2,
        deviceId,
        decision: 'BLOCK',
        score: 100,
        reasons: ['PHISHING_CONFIRMED'],
        localVerification: {
          destination: {
            hostname: 'evil-phish.example',
            registrableDomain: 'evil-phish.example',
            protocol: 'https:'
          }
        },
        verificationToken: proofToken2
      }
    );
    assert.equal(createdViaAppScheme.status, 201);
    assert.equal(db.events.size, 2);

    // 7. Replaying same special proof token is rejected with 409 PROOF_TOKEN_REPLAYED
    const replay = await sendHttpRequest(
      port,
      'POST',
      '/api/v1/events',
      {
        'X-SafeGate-App': 'com.safegate.app',
        'X-SafeGate-App-Key': appIngestKey,
        'Content-Type': 'application/json'
      },
      payload
    );
    assert.equal(replay.status, 409);
    assert.equal(replay.json.error.code, 'PROOF_TOKEN_REPLAYED');

    // 8. Raw query / privacy leak attempt rejected with 400 PRIVACY_VIOLATION_REJECTED
    const leak = await sendHttpRequest(
      port,
      'POST',
      '/api/v1/events',
      {
        'X-SafeGate-App': 'com.safegate.app',
        'X-SafeGate-App-Key': appIngestKey,
        'Content-Type': 'application/json'
      },
      {
        requestId: 'req-privacy-leak-1',
        deviceId,
        decision: 'BLOCK',
        score: 100,
        localVerification: {
          destination: {
            hostname: 'evil.example?otp=9999'
          }
        },
        verificationToken: proofToken
      }
    );
    assert.equal(leak.status, 400);
    assert.equal(leak.json.error.code, 'PRIVACY_VIOLATION_REJECTED');

    // 9. STRICT PLANE ISOLATION ON READ/PATCH/DELETE: App ingest key MUST NOT access operator endpoints
    for (const [method, path, body] of [
      ['GET', '/api/v1/events', null],
      ['GET', `/api/v1/events/${requestId}`, null],
      ['PATCH', `/api/v1/events/${requestId}`, { status: 'REVIEWED' }],
      ['DELETE', `/api/v1/events/${requestId}`, null]
    ]) {
      const denied = await sendHttpRequest(
        port,
        method,
        path,
        {
          'X-SafeGate-App': 'com.safegate.app',
          'X-SafeGate-App-Key': appIngestKey,
          Authorization: `App ${appIngestKey}`,
          ...(body ? { 'Content-Type': 'application/json' } : {})
        },
        body
      );
      assert.equal(denied.status, 401);
      assert.equal(denied.json.error.code, 'UNAUTHORIZED');
    }

    // 10. Key Vault Bearer token -> GET /api/v1/events and GET /api/v1/events/:requestId
    const listRes = await sendHttpRequest(port, 'GET', '/api/v1/events?registrableDomain=pavanserver.me', {
      Authorization: `Bearer ${vaultBearerToken}`
    });
    assert.equal(listRes.status, 200);
    assert.equal(listRes.json.count, 1);
    assert.equal(listRes.json.events[0].requestId, requestId);
    assert.equal(listRes.json.events[0].destinationHost, 'api.pavanserver.me');
    assert.equal(listRes.json.events[0].layersExecutedCount, 2);

    const detailRes = await sendHttpRequest(port, 'GET', `/api/v1/events/${requestId}`, {
      Authorization: `Bearer ${vaultBearerToken}`
    });
    assert.equal(detailRes.status, 200);
    assert.equal(detailRes.json.event.decision, 'HOLD');

    // 11. Key Vault Bearer token -> PATCH /api/v1/events/:requestId can edit any mutable event data safely
    const patchRes = await sendHttpRequest(
      port,
      'PATCH',
      `/api/v1/events/${requestId}`,
      {
        Authorization: `Bearer ${vaultBearerToken}`,
        'Content-Type': 'application/json'
      },
      {
        status: 'RESOLVED',
        decision: 'SAFE',
        localDecision: 'SAFE',
        score: 5,
        reasons: ['OPERATOR_VERIFIED_HEALTHCHECK_ENDPOINT'],
        indicators: ['INTERNAL_API_HOST'],
        recommendedAction: 'ALLOW',
        riskLevel: 'SAFE',
        verificationStatus: 'COMPLETED',
        destinationHost: 'api.pavanserver.me',
        registrableDomain: 'pavanserver.me',
        protocol: 'https:',
        notes: 'Verified healthy API endpoint by operator'
      }
    );
    assert.equal(patchRes.status, 200);
    assert.equal(patchRes.json.event.status, 'RESOLVED');
    assert.equal(patchRes.json.event.decision, 'SAFE');
    assert.equal(patchRes.json.event.score, 5);
    assert.equal(patchRes.json.event.recommendedAction, 'ALLOW');
    assert.equal(patchRes.json.event.riskLevel, 'SAFE');
    assert.equal(patchRes.json.event.notes, 'Verified healthy API endpoint by operator');
    assert.deepEqual(patchRes.json.event.reasons, ['OPERATOR_VERIFIED_HEALTHCHECK_ENDPOINT']);
    assert.equal(db.adminActions.length, 1);
    assert.equal(db.adminActions[0].actor_id, 'keyvault-operator');

    // 12. PATCH still enforces privacy protection (rejects raw query or PII)
    const badPatch = await sendHttpRequest(
      port,
      'PATCH',
      `/api/v1/events/${requestId}`,
      {
        Authorization: `Bearer ${vaultBearerToken}`,
        'Content-Type': 'application/json'
      },
      {
        notes: 'user@example.com leaked'
      }
    );
    assert.equal(badPatch.status, 400);
    assert.equal(badPatch.json.error.code, 'PRIVACY_VIOLATION_REJECTED');

    // 13. Key Vault Bearer token -> DELETE /api/v1/events/:requestId archives event & audits action
    const deleteRes = await sendHttpRequest(port, 'DELETE', `/api/v1/events/${requestId}`, {
      Authorization: `Bearer ${vaultBearerToken}`
    });
    assert.equal(deleteRes.status, 200);
    assert.equal(deleteRes.json.status, 'ARCHIVED');
    assert.equal(db.adminActions.length, 2);

    const afterDelete = await sendHttpRequest(port, 'GET', `/api/v1/events/${requestId}`, {
      Authorization: `Bearer ${vaultBearerToken}`
    });
    assert.equal(afterDelete.status, 200);
    assert.equal(afterDelete.json.event.status, 'ARCHIVED');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
