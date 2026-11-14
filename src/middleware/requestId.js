const {
    randomUUID
} = require("node:crypto");

function requestIdMiddleware(req, res, next) {

    req.requestId = randomUUID();

    // Security-sensitive responses must not be cached.
    res.setHeader("Cache-Control", "no-store");

    next();
}

module.exports = {
    requestIdMiddleware
};