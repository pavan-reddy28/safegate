
const { z } = require("zod");

const {
  verifyUrl
} = require("../services/verification.service");

const requestSchema = z.object({
  url: z.string().min(1).max(4096)
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

    // Pass the request UUID into the service so it appears in the audit log.
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

module.exports = {
  verifyUrlController
};
