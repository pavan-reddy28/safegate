'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  createProofVerifier,
  computeVerificationPayloadDigest
} = require('../src/proof-verifier');

function signHmacToken(claims, secret, prefix = 'sgp1') {
  const key = crypto.createHash('sha256').update(secret, 'utf8').digest();
  const encoded = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  const signedInput = prefix ? `${prefix}.${encoded}` : encoded;
  const sig = crypto.createHmac('sha256', key).update(signedInput, 'utf8').digest('base64url');
  return `${signedInput}.${sig}`;
}

function signEd25519Token(claims, privateKey, prefix = 'sgp1') {
  const encoded = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  const signedInput = prefix ? `${prefix}.${encoded}` : encoded;
  const sig = crypto.sign(null, Buffer.from(signedInput, 'utf8'), privateKey).toString('base64url');
  return `${signedInput}.${sig}`;
}

test('verifies valid HMAC-SHA256 verification proof bound to canonical local verification payload', () => {
  const secret = 'safegate-unit-test-hmac-secret-minimum-32-chars!!';
  const verifier = createProofVerifier({
    hmacSecret: secret,
    maxTtlSeconds: 300,
    requirePayloadDigest: true
  });

  const now = Math.floor(Date.now() / 1000);
  const context = {
    requestId: 'f70d31c1-6456-4361-8792-0ceec2f86e94',
    deviceId: 'device-android-01',
    decision: 'HOLD',
    score: 0,
    reasons: ['REPUTATION_CHECK_UNAVAILABLE_ZERO_EGRESS', 'LOCAL_STRUCTURAL_CHECKS_PASSED'],
    destinationHost: 'api.pavanserver.me',
    layersExecutedCount: 30
  };

  const token = signHmacToken({
    jti: crypto.randomUUID(),
    rid: context.requestId,
    did: context.deviceId,
    app: 'com.safegate.app',
    dec: 'HOLD',
    uh: crypto.createHash('sha256').update('https://api.pavanserver.me/healthy').digest('hex'),
    ph: computeVerificationPayloadDigest(context),
    iat: now,
    exp: now + 120
  }, secret);

  const result = verifier.verify(token, context);
  assert.equal(result.valid, true);
  assert.equal(result.algorithm, 'HMAC-SHA256');
  assert.equal(result.payloadHash, computeVerificationPayloadDigest(context));

  // Tampering with decision or score breaks payload binding even with valid token
  const tampered = verifier.verify(token, { ...context, decision: 'KNOWN_SAFE' });
  assert.equal(tampered.valid, false);
  assert.equal(tampered.code, 'PROOF_DECISION_MISMATCH');

  const tamperedHost = verifier.verify(token, { ...context, destinationHost: 'evil.example' });
  assert.equal(tamperedHost.valid, false);
  assert.equal(tamperedHost.code, 'PROOF_PAYLOAD_TAMPERED');
});

test('verifies valid Ed25519 asymmetric verification proof and rejects wrong key, expired, and excessive TTL', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const { privateKey: wrongPrivateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString('utf8');

  const verifier = createProofVerifier({
    publicKeyPem,
    maxTtlSeconds: 180,
    clockSkewSeconds: 5,
    requirePayloadDigest: true
  });

  const now = Math.floor(Date.now() / 1000);
  const context = {
    requestId: 'b52b4b29-a6d9-4448-8bd7-5d1812000001',
    deviceId: 'device-android-02',
    decision: 'BLOCK',
    score: 100,
    reasons: ['PHISHING_BRAND_IMPERSONATION_CONFIRMED'],
    destinationHost: null,
    layersExecutedCount: 30
  };

  const claims = {
    jti: crypto.randomUUID(),
    rid: context.requestId,
    did: context.deviceId,
    app: 'com.safegate.app',
    dec: 'BLOCK',
    uh: crypto.createHash('sha256').update('https://evil-phish.example/login').digest('hex'),
    ph: computeVerificationPayloadDigest(context),
    iat: now,
    exp: now + 90
  };

  const validToken = signEd25519Token(claims, privateKey);
  const verified = verifier.verify(validToken, context);
  assert.equal(verified.valid, true);
  assert.equal(verified.algorithm, 'Ed25519');

  // Wrong signing key rejected
  const forged = signEd25519Token(claims, wrongPrivateKey);
  assert.equal(verifier.verify(forged, context).code, 'PROOF_SIGNATURE_INVALID');

  // Excessive TTL rejected
  const longLived = signEd25519Token({ ...claims, exp: now + 9999 }, privateKey);
  assert.equal(verifier.verify(longLived, context).code, 'PROOF_TTL_EXCEEDED');

  // Expired rejected
  const expired = signEd25519Token({ ...claims, iat: now - 100, exp: now - 20 }, privateKey);
  assert.equal(verifier.verify(expired, context).code, 'PROOF_TOKEN_EXPIRED');

  // Wrong app rejected
  const wrongApp = signEd25519Token({ ...claims, app: 'com.attacker.script' }, privateKey);
  assert.equal(verifier.verify(wrongApp, context).code, 'PROOF_APP_NOT_AUTHORIZED');
});
