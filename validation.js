const Joi = require('joi');

const schemas = {
  authExchange: Joi.object({
    code: Joi.string().min(10).max(1000).required(),
    state: Joi.string().min(1).max(200).required(),
    codeVerifier: Joi.string().min(43).max(128).required(),
  }),

  authRefresh: Joi.object({
    refreshToken: Joi.string().min(10).max(1000).required(),
  }),

  subscriptionsList: Joi.object({}),

  subscriptionsDelete: Joi.object({
    // YouTube subscription IDs are base64url-safe alphanumeric strings.
    // Reject anything containing characters outside that alphabet to prevent
    // injection attempts from reaching the YouTube API.
    subscriptionId: Joi.string().min(10).max(200).pattern(/^[a-zA-Z0-9_-]+$/).required(),
  }),
};

const validate = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const errors = error.details.map(detail => detail.message);

      require('./logger').security('VALIDATION_FAILED', {
        ip: req.ip,
        endpoint: req.path,
        errors,
      });

      return res.status(400).json({ error: 'Invalid request data' });
    }

    req.validatedBody = value;
    next();
  };
};

module.exports = { schemas, validate };
