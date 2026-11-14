const express = require("express");

const router = express.Router();

router.get("/", (req, res) => {

    return res.status(200).json({
        status: "OK",
        application: "SafeGate",
        service: "Local Verification API"
    });

});

module.exports = router;