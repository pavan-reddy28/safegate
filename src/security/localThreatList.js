const {
    localBlockedDomains
} = require("../config/env");

const blockedDomains = new Set(
    localBlockedDomains.map(domain => domain.toLowerCase())
);

function isBlockedHost(hostname) {
    const host = hostname.toLowerCase();

    for (const blockedDomain of blockedDomains) {
        if (
            host === blockedDomain ||
            host.endsWith(`.${blockedDomain}`)
        ) {
            return true;
        }
    }

    return false;
}

module.exports = {
    isBlockedHost
};