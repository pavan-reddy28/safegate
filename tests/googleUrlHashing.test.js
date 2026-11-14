
const test = require("node:test");
const assert = require("node:assert/strict");

const {
    canonicalizeUrl,
    buildHostCandidates,
    buildPathCandidates,
    createGoogleHashData
} = require("../src/security/googleUrlHashing");

test("Spaces are canonically escaped", () => {
    const result = canonicalizeUrl(
        "https://example.com/a b"
    );

    assert.equal(
        result.canonicalExpression,
        "example.com/a%20b"
    );
});

test("Repeated percent encoding is decoded", () => {
    const result = canonicalizeUrl(
        "https://example.com/%252F"
    );

    assert.equal(
        result.canonicalExpression,
        "example.com/"
    );
});

test("Consecutive path slashes are collapsed", () => {
    const result = canonicalizeUrl(
        "https://example.com/a//b"
    );

    assert.equal(
        result.canonicalExpression,
        "example.com/a/b"
    );
});

test("URL fragments are excluded", () => {
    const result = canonicalizeUrl(
        "https://example.com/login#section"
    );

    assert.equal(
        result.canonicalExpression,
        "example.com/login"
    );
});

test("Dot segments are normalized", () => {
    const result = canonicalizeUrl(
        "https://example.com/a/../login"
    );

    assert.equal(
        result.canonicalExpression,
        "example.com/login"
    );
});

test("Query slashes are not collapsed by path normalization", () => {
    const result = canonicalizeUrl(
        "https://example.com/login?next=%2Fa%2F%2Fb"
    );

    assert.equal(
        result.canonicalExpression,
        "example.com/login?next=/a//b"
    );
});

test("International domain names use ASCII representation", () => {
    const result = canonicalizeUrl(
        "https://bücher.de/"
    );

    assert.equal(
        result.hostname,
        "xn--bcher-kva.de"
    );
});

test("Only HTTP and HTTPS URLs are accepted", () => {
    assert.throws(() => {
        canonicalizeUrl("ftp://example.com/file");
    });
});

test("Invalid percent-encoded UTF-8 is rejected", () => {
    assert.throws(() => {
        canonicalizeUrl("https://example.com/%E0%A4%A");
    });
});

test("Host candidates follow Google's suffix rules", () => {
    const result = buildHostCandidates(
        "a.b.example.com"
    );

    assert.deepEqual(
        [...result].sort(),
        [
            "a.b.example.com",
            "b.example.com",
            "example.com"
        ].sort()
    );
});

test("Long hostnames use at most five candidates", () => {
    const result = buildHostCandidates(
        "a.b.c.d.e.f.com"
    );

    assert.deepEqual(result, [
        "f.com",
        "e.f.com",
        "d.e.f.com",
        "c.d.e.f.com",
        "a.b.c.d.e.f.com"
    ]);
});

test("IPv4 addresses use their exact hostname", () => {
    const result = buildHostCandidates("192.0.2.1");

    assert.deepEqual(result, ["192.0.2.1"]);
});

test("Path candidates follow the documented pattern", () => {
    const result = buildPathCandidates(
        "/1/2.html",
        "?param=1"
    );

    assert.deepEqual(result, [
        "/1/2.html?param=1",
        "/1/2.html",
        "/",
        "/1/"
    ]);
});

test("Hash prefixes are exactly four bytes", () => {
    const result = createGoogleHashData(
        "https://example.com/login"
    );

    assert.ok(result.hashPrefixes.length > 0);

    for (const prefix of result.hashPrefixes) {
        assert.equal(
            Buffer.from(prefix, "base64").length,
            4
        );
    }
});

test("Full SHA-256 hashes are retained locally", () => {
    const result = createGoogleHashData(
        "https://example.com/login"
    );

    assert.ok(result.fullHashes.length > 0);

    for (const hash of result.fullHashes) {
        assert.match(hash, /^[a-f0-9]{64}$/);
    }
});

test("Hash output does not contain the original URL", () => {
    const originalUrl = "https://example.com/private/path";

    const result = createGoogleHashData(originalUrl);

    assert.deepEqual(
        Object.keys(result).sort(),
        ["fullHashes", "hashPrefixes"].sort()
    );

    assert.equal(
        JSON.stringify(result).includes(originalUrl),
        false
    );
});

test("Google hashes use hostname root only in privacy mode", () => {
  const crypto = require("node:crypto");

  const result = createGoogleHashData(
    "https://example.com/a b?access_token=secret-value#fragment-secret"
  );

  const expectedRootHash = crypto
    .createHash("sha256")
    .update("example.com/", "utf8")
    .digest("hex");

  const pathHash = crypto
    .createHash("sha256")
    .update("example.com/a%20b", "utf8")
    .digest("hex");

  assert.ok(result.fullHashes.includes(expectedRootHash));
  assert.equal(result.fullHashes.includes(pathHash), false);

  assert.equal(
    JSON.stringify(result).includes("secret-value"),
    false
  );

  assert.equal(
    JSON.stringify(result).includes("fragment-secret"),
    false
  );
});

test("Google hash data is identical when only path/query/fragment changes", () => {
  const first = createGoogleHashData(
    "https://example.com/reset/alpha?token=alpha-secret#one"
  );

  const second = createGoogleHashData(
    "https://example.com/private/beta?password=beta-secret#two"
  );

  assert.deepEqual(first, second);
});



test("Privacy mode hashes hostname root, never the URL path", () => {
  const crypto = require("node:crypto");

  const result = createGoogleHashData(
    "https://example.com/a%20b?access_token=private-value#private-fragment"
  );

  const expectedRootHash = crypto
    .createHash("sha256")
    .update("example.com/", "utf8")
    .digest("hex");

  assert.ok(result.fullHashes.includes(expectedRootHash));

  const pathHash = crypto
    .createHash("sha256")
    .update("example.com/a%20b", "utf8")
    .digest("hex");

  assert.equal(result.fullHashes.includes(pathHash), false);

  assert.equal(
    JSON.stringify(result).includes("private-value"),
    false
  );

  assert.equal(
    JSON.stringify(result).includes("private-fragment"),
    false
  );
});
