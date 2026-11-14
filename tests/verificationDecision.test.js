
const test = require("node:test");
const assert = require("node:assert/strict");

const {
    calculateFinalDecision
} = require("../src/services/verification.service");

function local(decision) {
    return { decision };
}

function google(status) {
    return { status };
}

test("Local BLOCK cannot be overridden by Google no-match", () => {
    const result = calculateFinalDecision(
        local("BLOCK"),
        google("NO_THREAT_FOUND")
    );

    assert.equal(result.finalDecision, "BLOCK");
    assert.equal(result.recommendedAction, "DO_NOT_OPEN");
});

test("Local BLOCK remains BLOCK when Google is unavailable", () => {
    const result = calculateFinalDecision(
        local("BLOCK"),
        google("UNAVAILABLE")
    );

    assert.equal(result.finalDecision, "BLOCK");
});

test("Google threat match blocks a structurally clean URL", () => {
    const result = calculateFinalDecision(
        local("REPUTATION_CHECK_REQUIRED"),
        google("THREAT_FOUND")
    );

    assert.equal(result.finalDecision, "BLOCK");
    assert.equal(result.recommendedAction, "DO_NOT_OPEN");
});

test("Local SUSPICIOUS remains suspicious when Google finds no threat", () => {
    const result = calculateFinalDecision(
        local("SUSPICIOUS"),
        google("NO_THREAT_FOUND")
    );

    assert.equal(result.finalDecision, "SUSPICIOUS");
    assert.equal(result.recommendedAction, "WARN_USER");
});

test("Local SUSPICIOUS becomes BLOCK when Google finds a threat", () => {
    const result = calculateFinalDecision(
        local("SUSPICIOUS"),
        google("THREAT_FOUND")
    );

    assert.equal(result.finalDecision, "BLOCK");
});

test("Clean local result and Google no-match produce NO_KNOWN_THREAT", () => {
    const result = calculateFinalDecision(
        local("REPUTATION_CHECK_REQUIRED"),
        google("NO_THREAT_FOUND")
    );

    assert.equal(result.finalDecision, "NO_KNOWN_THREAT");
    assert.equal(result.recommendedAction, "ALLOW_WITH_CAUTION");
});

test("Google unavailable produces HOLD for a structurally clean URL", () => {
    const result = calculateFinalDecision(
        local("REPUTATION_CHECK_REQUIRED"),
        google("UNAVAILABLE")
    );

    assert.equal(result.finalDecision, "HOLD");
    assert.equal(result.recommendedAction, "DO_NOT_OPEN");
});

test("Google not configured must not produce approval", () => {
    const result = calculateFinalDecision(
        local("REPUTATION_CHECK_REQUIRED"),
        google("NOT_CONFIGURED")
    );

    assert.equal(result.finalDecision, "HOLD");
});
