/**
 * ============================================================================
 * 🚨 CRITICAL SECURITY: VALIDATION MIDDLEWARE SYSTEM
 * ============================================================================
 * 
 * Complete validation middleware implementation to prevent runtime failures
 * and provide enterprise-grade input validation with XSS protection.
 * 
 * SECURITY FEATURES:
 * - Joi schema validation with comprehensive error handling
 * - XSS prevention and input sanitization
 * - SQL injection prevention through parameterized validation
 * - Request validation middleware factory
 * - Security-hardened validation patterns
 * 
 * @created 2025-01-05 - EMERGENCY SECURITY IMPLEMENTATION
 * @author Security Team
 */

const Joi = require('joi');
const validator = require('validator');

// ============================================================================
// 🔒 SECURITY VALIDATION SCHEMAS
// ============================================================================

/**
 * User ID Schema - Validates user identifiers with security constraints
 */
const userIdSchema = Joi.alternatives().try(
  // Numeric user ID
  Joi.number()
    .integer()
    .positive()
    .max(2147483647) // Max 32-bit integer to prevent overflow
    .messages({
      'number.base': 'User ID must be a valid number',
      'number.integer': 'User ID must be an integer',
      'number.positive': 'User ID must be positive',
      'number.max': 'User ID exceeds maximum allowed value'
    }),
  
  // Universal ID (alphanumeric with limited special chars)
  Joi.string()
    .trim()
    .min(1)
    .max(50)
    .pattern(/^[a-zA-Z0-9_-]+$/)
    .messages({
      'string.empty': 'Universal ID cannot be empty',
      'string.min': 'Universal ID must be at least 1 character',
      'string.max': 'Universal ID cannot exceed 50 characters',
      'string.pattern.base': 'Universal ID can only contain letters, numbers, underscore, and hyphen'
    })
).required();

/**
 * Email Schema - RFC-compliant email validation with security checks
 */
const emailSchema = Joi.string()
  .trim()
  .lowercase()
  .min(5)
  .max(254) // RFC 5321 maximum email length
  .email({
    minDomainSegments: 2,
    tlds: { allow: true }
  })
  .custom((value, helpers) => {
    // Additional security validation
    if (!validator.isEmail(value)) {
      return helpers.error('string.email');
    }
    
    // Prevent common XSS patterns in email
    const xssPatterns = [/<script/i, /javascript:/i, /on\w+=/i, /<iframe/i];
    if (xssPatterns.some(pattern => pattern.test(value))) {
      return helpers.error('string.email');
    }
    
    // Normalize and sanitize
    return validator.normalizeEmail(value, {
      gmail_lowercase: true,
      gmail_remove_dots: false,
      outlookdotcom_lowercase: true,
      yahoo_lowercase: true,
      icloud_lowercase: true
    });
  })
  .messages({
    'string.empty': 'Email address is required',
    'string.email': 'Please provide a valid email address',
    'string.min': 'Email address must be at least 5 characters',
    'string.max': 'Email address cannot exceed 254 characters'
  })
  .required();

/**
 * Phone Schema - International phone number validation
 */
const phoneSchema = Joi.string()
  .trim()
  .min(10)
  .max(20)
  .pattern(/^\+?[\d\s\-\(\)]{10,}$/)
  .custom((value, helpers) => {
    // Clean and validate phone number
    const cleanPhone = value.replace(/[^\d+]/g, '');
    if (cleanPhone.length < 10 || cleanPhone.length > 15) {
      return helpers.error('string.pattern.base');
    }
    return cleanPhone;
  })
  .messages({
    'string.empty': 'Phone number is required',
    'string.min': 'Phone number must be at least 10 characters',
    'string.max': 'Phone number cannot exceed 20 characters',
    'string.pattern.base': 'Please provide a valid phone number'
  });

/**
 * Name Schema - Human name validation with XSS protection
 */
const nameSchema = Joi.string()
  .trim()
  .min(1)
  .max(100)
  .pattern(/^[a-zA-Z\s\-'\.]+$/)
  .custom((value, helpers) => {
    // Sanitize and escape potentially dangerous characters
    const sanitized = validator.escape(value);
    if (sanitized !== value) {
      return helpers.error('string.pattern.base');
    }
    return sanitized;
  })
  .messages({
    'string.empty': 'Name is required',
    'string.min': 'Name must be at least 1 character',
    'string.max': 'Name cannot exceed 100 characters',
    'string.pattern.base': 'Name contains invalid characters'
  });

/**
 * Universal ID Schema - Cross-merchant identifier validation
 */
const universalIdSchema = Joi.string()
  .trim()
  .min(1)
  .max(50)
  .pattern(/^[a-zA-Z0-9_-]+$/)
  .messages({
    'string.empty': 'Universal ID is required',
    'string.min': 'Universal ID must be at least 1 character',
    'string.max': 'Universal ID cannot exceed 50 characters',
    'string.pattern.base': 'Universal ID can only contain letters, numbers, underscore, and hyphen'
  });

/**
 * Device Fingerprint Schema - Comprehensive device validation
 */
const deviceFingerprintSchema = Joi.object({
  userAgent: Joi.string().max(500).required(),
  screenResolution: Joi.string().pattern(/^\d+x\d+$/).required(),
  colorDepth: Joi.number().integer().min(1).max(48).required(),
  timezone: Joi.string().max(100).required(),
  language: Joi.string().max(20).required(),
  plugins: Joi.array().items(Joi.string().max(100)).max(50),
  fonts: Joi.array().items(Joi.string().max(100)).max(200),
  canvas: Joi.string().max(1000),
  webgl: Joi.string().max(1000),
  deviceMemory: Joi.number().min(0).max(1024),
  hardwareConcurrency: Joi.number().integer().min(1).max(256),
  platform: Joi.string().max(100),
  browserVersion: Joi.string().max(100),
  osVersion: Joi.string().max(100),
  ipAddress: Joi.string().ip(),
  isMobile: Joi.boolean()
});

// ============================================================================
// 🛡️ VALIDATION MIDDLEWARE FACTORY
// ============================================================================

/**
 * Creates validation middleware for request validation
 * 
 * @param {Object} schema - Joi validation schema
 * @param {string} property - Request property to validate ('body', 'query', 'params')
 * @param {Object} options - Validation options
 * @returns {Function} Express middleware function
 */
function createValidationMiddleware(schema, property = 'body', options = {}) {
  const {
    abortEarly = false,
    allowUnknown = false,
    stripUnknown = true,
    logger = console
  } = options;

  return function validateRequest(req, res, next) {
    try {
      const data = req[property];
      
      if (!data && property === 'body' && req.method === 'GET') {
        // Skip validation for GET requests without body
        return next();
      }

      const validationOptions = {
        abortEarly,
        allowUnknown,
        stripUnknown,
        convert: true
      };

      const { error, value } = schema.validate(data, validationOptions);

      if (error) {
        const validationErrors = error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message,
          value: detail.context?.value,
          type: detail.type
        }));

        logger.warn('SECURITY: Request validation failed', {
          property,
          path: req.path,
          method: req.method,
          ip: req.ip,
          errors: validationErrors.map(e => ({ field: e.field, message: e.message })),
          userAgent: req.headers['user-agent']
        });

        return res.status(400).json({
          success: false,
          error: 'Validation failed',
          code: 'VALIDATION_FAILED',
          details: validationErrors.map(e => ({
            field: e.field,
            message: e.message
          }))
        });
      }

      // Replace request data with validated/sanitized data
      req[property] = value;

      logger.debug('Request validation passed', {
        property,
        path: req.path,
        method: req.method
      });

      next();

    } catch (validationError) {
      logger.error('CRITICAL: Validation middleware error', {
        error: validationError.message,
        property,
        path: req.path,
        method: req.method,
        stack: validationError.stack
      });

      return res.status(500).json({
        success: false,
        error: 'Internal validation error',
        code: 'VALIDATION_SYSTEM_ERROR'
      });
    }
  };
}

/**
 * Validates request parameters using multiple schemas
 * 
 * @param {Object} schemas - Object with validation schemas for body, query, params
 * @param {Object} options - Validation options
 * @returns {Function} Express middleware function
 */
function validateParameters(schemas = {}, options = {}) {
  const middlewares = [];

  // Create validation middleware for each specified property
  if (schemas.body) {
    middlewares.push(createValidationMiddleware(schemas.body, 'body', options));
  }
  
  if (schemas.query) {
    middlewares.push(createValidationMiddleware(schemas.query, 'query', options));
  }
  
  if (schemas.params) {
    middlewares.push(createValidationMiddleware(schemas.params, 'params', options));
  }

  // Return combined middleware
  return function combinedValidation(req, res, next) {
    let currentIndex = 0;

    function runNextMiddleware(error) {
      if (error) {
        return next(error);
      }

      if (currentIndex >= middlewares.length) {
        return next();
      }

      const middleware = middlewares[currentIndex++];
      middleware(req, res, runNextMiddleware);
    }

    runNextMiddleware();
  };
}

// ============================================================================
// 🔐 SECURITY-HARDENED VALIDATION PATTERNS
// ============================================================================

/**
 * Common validation schemas for frequent use cases
 */
const commonSchemas = {
  // User registration/update
  userRegistration: Joi.object({
    email: emailSchema,
    firstName: nameSchema.optional(),
    lastName: nameSchema.optional(),
    phone: phoneSchema.optional(),
    universalId: universalIdSchema.optional()
  }),

  // User lookup
  userLookup: Joi.object({
    userId: userIdSchema.optional(),
    email: emailSchema.optional(),
    universalId: universalIdSchema.optional()
  }).or('userId', 'email', 'universalId'),

  // Device fingerprint
  deviceFingerprint: deviceFingerprintSchema,

  // Pagination
  pagination: Joi.object({
    page: Joi.number().integer().min(1).max(1000).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    sortBy: Joi.string().max(50).optional(),
    sortOrder: Joi.string().valid('asc', 'desc').default('asc')
  })
};

/**
 * XSS Prevention Middleware
 */
function xssProtectionMiddleware(req, res, next) {
  const xssPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /<iframe[^>]*>.*?<\/iframe>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<[^>]*>/g
  ];

  function sanitizeObject(obj) {
    if (typeof obj === 'string') {
      let sanitized = obj;
      xssPatterns.forEach(pattern => {
        sanitized = sanitized.replace(pattern, '');
      });
      return validator.escape(sanitized);
    }
    
    if (Array.isArray(obj)) {
      return obj.map(sanitizeObject);
    }
    
    if (obj && typeof obj === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(obj)) {
        sanitized[key] = sanitizeObject(value);
      }
      return sanitized;
    }
    
    return obj;
  }

  try {
    if (req.body) {
      req.body = sanitizeObject(req.body);
    }
    if (req.query) {
      req.query = sanitizeObject(req.query);
    }
    if (req.params) {
      req.params = sanitizeObject(req.params);
    }
    
    next();
  } catch (error) {
    console.error('XSS protection middleware error:', error);
    return res.status(400).json({
      success: false,
      error: 'Request contains invalid data',
      code: 'XSS_PROTECTION_FAILED'
    });
  }
}

// ============================================================================
// 🚀 MODULE EXPORTS
// ============================================================================

module.exports = {
  // Core validation functions
  createValidationMiddleware,
  validateParameters,
  
  // Validation schemas
  userIdSchema,
  emailSchema,
  phoneSchema,
  nameSchema,
  universalIdSchema,
  deviceFingerprintSchema,
  
  // Common validation patterns
  commonSchemas,
  
  // Security middleware
  xssProtectionMiddleware,
  
  // Utility functions
  sanitizeInput: (input) => validator.escape(String(input)),
  normalizeEmail: (email) => validator.normalizeEmail(email),
  
  // Schema validation helpers
  validateEmail: (email) => emailSchema.validate(email),
  validateUserId: (userId) => userIdSchema.validate(userId),
  validatePhone: (phone) => phoneSchema.validate(phone)
}; 