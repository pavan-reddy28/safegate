
const express = require("express");

const {
    googleHashRelayController
} = require("../controllers/googleHashRelay.controller");

const router = express.Router();

router.post("/", googleHashRelayController);

module.exports = router;
