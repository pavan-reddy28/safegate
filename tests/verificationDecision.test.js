"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  calculateFinalDecision
} = require("../src/services/verification.service");

function local(decision, extra = {}) {
  return {
    decision,
    riskScore: 0,
    destination: { protocol: "https:" },
    ...extra
  };
}

test("Local BLOCK always produces BLOCK / DO_NOT_OPEN even for known domain", () => {
  const result = calculateFinalDecision(
    local("BLOCK", { reasonCodes: ["PHISHING_BRAND_IMPERSONATION_CONFIRMED"] }),
    "sbi.co.in"
  );

  assert.equal(result.finalDecision, "BLOCK");
  assert.equal(result.recommendedAction, "DO_NOT_OPEN");
});

test("Local SUSPICIOUS produces SUSPICIOUS / WARN_USER", () => {
  const result = calculateFinalDecision(local("SUSPICIOUS", { riskScore: 4 }), "bit.ly");

  assert.equal(result.finalDecision, "SUSPICIOUS");
  assert.equal(result.recommendedAction, "WARN_USER");
});

test("Clean known-safe HTTPS domain produces KNOWN_SAFE / ALLOW", () => {
  const result = calculateFinalDecision(
    local("REPUTATION_CHECK_REQUIRED", { riskScore: 0, destination: { protocol: "https:" } }),
    "sbi.co.in"
  );

  assert.equal(result.finalDecision, "KNOWN_SAFE");
  assert.equal(result.recommendedAction, "ALLOW");
});

test("Known-safe domain over unencrypted HTTP is NOT upgraded to KNOWN_SAFE", () => {
  const result = calculateFinalDecision(
    local("REPUTATION_CHECK_REQUIRED", { riskScore: 1, destination: { protocol: "http:" } }),
    "sbi.co.in"
  );

  assert.equal(result.finalDecision, "NO_KNOWN_THREAT");
  assert.equal(result.recommendedAction, "ALLOW_WITH_CAUTION");
});

test("Clean unknown HTTPS domain produces NO_KNOWN_THREAT / ALLOW_WITH_CAUTION", () => {
  const result = calculateFinalDecision(
    local("REPUTATION_CHECK_REQUIRED", { riskScore: 0, destination: { protocol: "https:" } }),
    "example.org"
  );

  assert.equal(result.finalDecision, "NO_KNOWN_THREAT");
  assert.equal(result.recommendedAction, "ALLOW_WITH_CAUTION");
});
