"use strict";

const express = require("express");

const {
  verifyUrlController,
  authorizeRedirectController
} = require("../controllers/verification.controller");

const router = express.Router();

router.post("/", verifyUrlController);
router.post("/authorize-redirect", authorizeRedirectController);

module.exports = router;