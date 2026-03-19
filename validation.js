const Joi = require('joi');

const schemas = {
  authExchange: Joi.object({
    code: Joi.string().min(10).max(1000).required(),
    state: Joi.string().uuid().required(),
    codeVerifier: Joi.string().min(43).max(128).required(),
  }),

  authRefresh: Joi.object({
    refreshToken: Joi.string().min(10).max(1000).required(),
  }),

  // accessToken is now passed via X-Google-Access-Token header, not body
  subscriptionsList: Joi.object({}),

  subscriptionsDelete: Joi.object({
    subscriptionId: Joi.string().min(10).max(200).required(),
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

      // Do not expose validation detail to clients
      return res.status(400).json({ error: 'Invalid request data' });
    }

    req.validatedBody = value;
    next();
  };
};

module.exports = { schemas, validate };
