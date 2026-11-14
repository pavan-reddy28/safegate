const express = require("express");

const {
    verifyUrlController
} = require("../controllers/verification.controller");

const router = express.Router();

router.post("/", verifyUrlController);

module.exports = router;