
import {
    canonicalizeUrl,
    createGoogleHashData,
    matchGoogleFullHashes
} from "./googleHashing.js";

async function runTests() {
    console.log("SafeGate Browser Hashing Tests");

    const testUrl =
        "https://testsafebrowsing.appspot.com/s/phishing.html";

    const canonical = canonicalizeUrl(testUrl);

    console.log("Canonical hostname:", canonical.hostname);

    const result = await createGoogleHashData(testUrl);

    console.log("Full hashes generated:", result.fullHashes.length);

    console.log("Prefix count:", result.hashPrefixes.length);

    console.log(
        "All prefixes are 4 bytes:",
        result.hashPrefixes.every(
            prefix => atob(prefix).length === 4
        )
    );

    console.log(
        "Full hashes are 64-character hex:",
        result.fullHashes.every(
            hash => /^[a-f0-9]{64}$/.test(hash)
        )
    );

    console.log(
        "Original URL absent from hash data:",
        !JSON.stringify(result).includes(testUrl)
    );

    console.assert(result.fullHashes.length > 0);
    console.assert(result.hashPrefixes.length > 0);
    console.assert(result.hashPrefixes.length <= 30);
    console.assert(
        result.hashPrefixes.every(
            prefix => atob(prefix).length === 4
        )
    );

    const fakeCandidate = [{
        fullHash: btoa(
            String.fromCharCode(
                ...new Uint8Array(32)
            )
        ),
        fullHashDetails: [{
            threatType: "MALWARE",
            attributes: []
        }]
    }];

    const matches = matchGoogleFullHashes(
        result.fullHashes,
        fakeCandidate
    );

    console.assert(matches.length === 0);

    console.log("Non-matching candidate rejected:", matches.length === 0);

    console.log("Browser hashing smoke tests completed.");
}

runTests().catch(error => {
    console.error("Hashing test failed:", error.message);
});
