function notFoundHandler(req, res) {

    return res.status(404).json({
        requestId: req.requestId,

        error: {
            code: "ENDPOINT_NOT_FOUND",
            message: "The requested API endpoint does not exist."
        }
    });
}

function errorHandler(error, req, res, next) {

    if (res.headersSent) {
        return next(error);
    }

    let status = 500;

    let code = "INTERNAL_SERVER_ERROR";

    let message = "An internal server error occurred.";

    if (error.code === "CORS_ORIGIN_DENIED") {

        status = 403;
        code = "ORIGIN_NOT_ALLOWED";
        message = "This application origin is not allowed.";

    } else if (error.type === "entity.too.large") {

        status = 413;
        code = "REQUEST_TOO_LARGE";
        message = "The request exceeds the allowed size.";

    } else if (error.type === "entity.parse.failed") {

        status = 400;
        code = "INVALID_JSON";
        message = "The request contains invalid JSON.";

    }

    // Log only an error identifier, never submitted URL data.
    if (status === 500) {
        console.error(
            `[SafeGate] Internal error. Request ID: ${req.requestId}`
        );
    }

    return res.status(status).json({
        requestId: req.requestId,

        error: {
            code,
            message
        }
    });
}

module.exports = {
    notFoundHandler,
    errorHandler
};