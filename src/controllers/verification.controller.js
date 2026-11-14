"use strict";

const { z } = require("zod");

const {
  verifyUrl,
  authorizeRedirect
} = require("../services/verification.service");

const requestSchema = z.object({
  url: z.string().min(1).max(4096)
}).strict();

const authorizeSchema = z.object({
  url: z.string().min(1).max(4096),
  verificationToken: z.string().min(10).max(1024),
  userConfirmedWarning: z.boolean().optional().default(false)
}).strict();

async function verifyUrlController(req, res, next) {
  const validation = requestSchema.safeParse(req.body);

  if (!validation.success) {
    return res.status(400).json({
      requestId: req.requestId,
      error: {
        code: "INVALID_REQUEST",
        message: "Provide exactly one valid URL field."
      }
    });
  }

  try {
    const result = await verifyUrl(
      validation.data.url,
      req.requestId
    );

    return res.status(200).json({
      requestId: req.requestId,
      ...result
    });
  } catch (error) {
    // Never log the submitted URL or request body.
    next(error);
  }
}

function authorizeRedirectController(req, res, next) {
  const validation = authorizeSchema.safeParse(req.body);

  if (!validation.success) {
    return res.status(400).json({
      requestId: req.requestId,
      error: {
        code: "INVALID_REQUEST",
        message: "Provide valid url and verificationToken fields."
      }
    });
  }

  try {
    const decision = authorizeRedirect({
      url: validation.data.url,
      verificationToken: validation.data.verificationToken,
      userConfirmedWarning: validation.data.userConfirmedWarning
    });

    if (!decision.authorized) {
      return res.status(403).json({
        requestId: req.requestId,
        authorized: false,
        reasonCode: decision.reasonCode,
        ...(decision.finalDecision
          ? { finalDecision: decision.finalDecision }
          : {})
      });
    }

    return res.status(200).json({
      requestId: req.requestId,
      authorized: true,
      finalDecision: decision.finalDecision,
      recommendedAction: decision.recommendedAction,
      expiresInSeconds: decision.expiresInSeconds
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  verifyUrlController,
  authorizeRedirectController
};
