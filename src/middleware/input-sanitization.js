/**
 * Input Sanitization Middleware - COMPREHENSIVE SECURITY
 * 
 * Sanitizes all incoming request data to prevent:
 * - XSS attacks
 * - SQL injection
 * - NoSQL injection
 * - Command injection
 * - Path traversal
 * - Script injection
 * 
 * SECURITY FEATURES:
 * - Deep object sanitization
 * - HTML entity encoding
 * - Script tag removal
 * - SQL keyword filtering
 * - Size limits enforcement
 * - Type validation
 * - Malicious pattern detection
 */

const validator = require('validator');
const { logger } = require('../utils/logger');

/**
 * Dangerous patterns that should be blocked
 */
const DANGEROUS_PATTERNS = [
  // SQL Injection patterns
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/gi,
  /(\b(OR|AND)\s+\d+\s*=\s*\d+)/gi,
  /('|(\\')|(;)|(--)|(\|)|(\*)|(%)|(\+))/g,
  
  // XSS patterns
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
  /javascript:/gi,
  /on\w+\s*=/gi,
  
  // Command injection patterns
  /(\||&|;|\$\(|\`)/g,
  
  // Path traversal patterns
  /\.\.\//g,
  /\.\.\\/g,
  
  // NoSQL injection patterns
  /\$where/gi,
  /\$ne/gi,
  /\$gt/gi,
  /\$lt/gi,
  /\$regex/gi
];

/**
 * Maximum sizes for different data types
 */
const SIZE_LIMITS = {
  string: 10000,      // 10KB for strings
  email: 254,         // RFC 5321 limit
  phone: 20,          // International phone numbers
  name: 100,          // Person names
  description: 2000,  // Descriptions
  url: 2048,          // URLs
  code: 20,           // Verification codes
  id: 100,            // IDs
  currency: 3,        // Currency codes
  amount: 20          // Amount strings
};

/**
 * Sanitize a single string value
 * @param {string} value - String to sanitize
 * @param {string} type - Type of string for specific validation
 * @returns {string} - Sanitized string
 */
function sanitizeString(value, type = 'string') {
  if (typeof value !== 'string') {
    return value;
  }
  
  // Apply size limits
  const maxLength = SIZE_LIMITS[type] || SIZE_LIMITS.string;
  if (value.length > maxLength) {
    logger.warn(`String truncated due to size limit`, {
      type,
      originalLength: value.length,
      maxLength
    });
    value = value.substring(0, maxLength);
  }
  
  // Check for dangerous patterns
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(value)) {
      logger.warn(`Dangerous pattern detected and blocked`, {
        pattern: pattern.toString(),
        value: value.substring(0, 100) + '...'
      });
      // Replace dangerous content with safe placeholder
      value = value.replace(pattern, '[BLOCKED]');
    }
  }
  
  // HTML encode to prevent XSS
  value = validator.escape(value);
  
  // Remove any remaining script tags or dangerous HTML
  value = value.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  value = value.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '');
  value = value.replace(/javascript:/gi, '');
  value = value.replace(/on\w+\s*=/gi, '');
  
  // Trim whitespace
  value = value.trim();
  
  return value;
}

/**
 * Sanitize a number value
 * @param {any} value - Value to sanitize
 * @returns {number|null} - Sanitized number or null if invalid
 */
function sanitizeNumber(value) {
  if (typeof value === 'number') {
    // Check for dangerous values
    if (!isFinite(value) || isNaN(value)) {
      return null;
    }
    return value;
  }
  
  if (typeof value === 'string') {
    const num = parseFloat(value);
    if (!isFinite(num) || isNaN(num)) {
      return null;
    }
    return num;
  }
  
  return null;
}

/**
 * Sanitize a boolean value
 * @param {any} value - Value to sanitize
 * @returns {boolean} - Sanitized boolean
 */
function sanitizeBoolean(value) {
  if (typeof value === 'boolean') {
    return value;
  }
  
  if (typeof value === 'string') {
    const lower = value.toLowerCase();
    return lower === 'true' || lower === '1' || lower === 'yes';
  }
  
  if (typeof value === 'number') {
    return value !== 0;
  }
  
  return false;
}

/**
 * Deep sanitize an object recursively
 * @param {any} obj - Object to sanitize
 * @param {number} depth - Current recursion depth
 * @returns {any} - Sanitized object
 */
function deepSanitize(obj, depth = 0) {
  // Prevent infinite recursion
  if (depth > 10) {
    logger.warn('Deep sanitization stopped due to depth limit');
    return null;
  }
  
  if (obj === null || obj === undefined) {
    return obj;
  }
  
  if (typeof obj === 'string') {
    return sanitizeString(obj);
  }
  
  if (typeof obj === 'number') {
    return sanitizeNumber(obj);
  }
  
  if (typeof obj === 'boolean') {
    return sanitizeBoolean(obj);
  }
  
  if (Array.isArray(obj)) {
    // Limit array size
    if (obj.length > 1000) {
      logger.warn(`Array truncated due to size limit`, {
        originalLength: obj.length,
        maxLength: 1000
      });
      obj = obj.slice(0, 1000);
    }
    
    return obj.map(item => deepSanitize(item, depth + 1));
  }
  
  if (typeof obj === 'object') {
    const sanitized = {};
    let keyCount = 0;
    
    for (const [key, value] of Object.entries(obj)) {
      // Limit object key count
      if (keyCount >= 100) {
        logger.warn('Object key limit reached, truncating');
        break;
      }
      
      // Sanitize key name
      const sanitizedKey = sanitizeString(key, 'id');
      
      // Skip dangerous keys
      if (sanitizedKey.includes('[BLOCKED]')) {
        logger.warn(`Dangerous key blocked: ${key}`);
        continue;
      }
      
      // Sanitize value
      sanitized[sanitizedKey] = deepSanitize(value, depth + 1);
      keyCount++;
    }
    
    return sanitized;
  }
  
  // For any other type, return null for safety
  return null;
}

/**
 * Sanitize specific field types with enhanced validation
 * @param {any} value - Value to sanitize
 * @param {string} fieldType - Type of field
 * @returns {any} - Sanitized value
 */
function sanitizeFieldType(value, fieldType) {
  switch (fieldType) {
    case 'email':
      if (typeof value === 'string') {
        const sanitized = sanitizeString(value, 'email');
        return validator.isEmail(sanitized) ? sanitized : null;
      }
      return null;
      
    case 'phone':
      if (typeof value === 'string') {
        const sanitized = sanitizeString(value, 'phone');
        // Remove all non-digit characters except + at the beginning
        const cleaned = sanitized.replace(/[^\d+]/g, '');
        return cleaned.match(/^\+?[1-9]\d{1,14}$/) ? cleaned : null;
      }
      return null;
      
    case 'url':
      if (typeof value === 'string') {
        const sanitized = sanitizeString(value, 'url');
        return validator.isURL(sanitized) ? sanitized : null;
      }
      return null;
      
    case 'currency':
      if (typeof value === 'string') {
        const sanitized = sanitizeString(value, 'currency');
        return sanitized.match(/^[A-Z]{3}$/) ? sanitized : 'USD';
      }
      return 'USD';
      
    case 'amount':
      const num = sanitizeNumber(value);
      if (num === null || num < 0 || num > 999999.99) {
        return null;
      }
      return Math.round(num * 100) / 100; // Round to 2 decimal places
      
    case 'code':
      if (typeof value === 'string') {
        const sanitized = sanitizeString(value, 'code');
        return sanitized.replace(/[^0-9]/g, ''); // Only digits for codes
      }
      return null;
      
    default:
      return deepSanitize(value);
  }
}

/**
 * Middleware to sanitize all request data
 */
function sanitizeInput(req, res, next) {
  try {
    const startTime = Date.now();
    
    // Sanitize request body
    if (req.body && typeof req.body === 'object') {
      req.body = deepSanitize(req.body);
    }
    
    // Sanitize query parameters
    if (req.query && typeof req.query === 'object') {
      req.query = deepSanitize(req.query);
    }
    
    // Sanitize URL parameters
    if (req.params && typeof req.params === 'object') {
      req.params = deepSanitize(req.params);
    }
    
    const processingTime = Date.now() - startTime;
    
    // Log sanitization activity
    logger.info('Input sanitization completed', {
      path: req.path,
      method: req.method,
      processingTime,
      bodyKeys: req.body ? Object.keys(req.body).length : 0,
      queryKeys: req.query ? Object.keys(req.query).length : 0,
      paramKeys: req.params ? Object.keys(req.params).length : 0,
      ip: req.ip
    });
    
    next();
    
  } catch (error) {
    logger.error('Input sanitization error', {
      error: error.message,
      stack: error.stack,
      path: req.path,
      method: req.method,
      ip: req.ip
    });
    
    // Continue with request even if sanitization fails
    // but log the error for investigation
    next();
  }
}

/**
 * Enhanced sanitization for payment endpoints
 */
function sanitizePaymentInput(req, res, next) {
  try {
    if (req.body) {
      // Sanitize specific payment fields
      if (req.body.amount) {
        req.body.amount = sanitizeFieldType(req.body.amount, 'amount');
      }
      
      if (req.body.currency) {
        req.body.currency = sanitizeFieldType(req.body.currency, 'currency');
      }
      
      if (req.body.customer) {
        if (req.body.customer.email) {
          req.body.customer.email = sanitizeFieldType(req.body.customer.email, 'email');
        }
        if (req.body.customer.phone) {
          req.body.customer.phone = sanitizeFieldType(req.body.customer.phone, 'phone');
        }
        if (req.body.customer.name) {
          req.body.customer.name = sanitizeString(req.body.customer.name, 'name');
        }
      }
      
      // Sanitize card data if present (but don't log it)
      if (req.body.paymentMethod?.card) {
        const card = req.body.paymentMethod.card;
        if (card.number) {
          card.number = sanitizeString(card.number.toString(), 'code').replace(/[^0-9]/g, '');
        }
        if (card.cvc) {
          card.cvc = sanitizeString(card.cvc.toString(), 'code').replace(/[^0-9]/g, '');
        }
      }
    }
    
    logger.info('Payment input sanitization completed', {
      path: req.path,
      method: req.method,
      hasAmount: !!req.body?.amount,
      hasCurrency: !!req.body?.currency,
      hasCustomer: !!req.body?.customer,
      hasPaymentMethod: !!req.body?.paymentMethod,
      ip: req.ip
    });
    
    next();
    
  } catch (error) {
    logger.error('Payment input sanitization error', {
      error: error.message,
      stack: error.stack,
      path: req.path,
      method: req.method,
      ip: req.ip
    });
    
    return res.status(400).json({
      success: false,
      error: 'SANITIZATION_ERROR',
      details: 'Invalid input data format'
    });
  }
}

/**
 * Enhanced sanitization for verification endpoints
 */
function sanitizeVerificationInput(req, res, next) {
  try {
    if (req.body) {
      if (req.body.code) {
        req.body.code = sanitizeFieldType(req.body.code, 'code');
      }
      
      if (req.body.phoneNumber) {
        req.body.phoneNumber = sanitizeFieldType(req.body.phoneNumber, 'phone');
      }
      
      if (req.body.userId) {
        req.body.userId = sanitizeString(req.body.userId, 'id');
      }
    }
    
    logger.info('Verification input sanitization completed', {
      path: req.path,
      method: req.method,
      hasCode: !!req.body?.code,
      hasPhone: !!req.body?.phoneNumber,
      hasUserId: !!req.body?.userId,
      ip: req.ip
    });
    
    next();
    
  } catch (error) {
    logger.error('Verification input sanitization error', {
      error: error.message,
      stack: error.stack,
      path: req.path,
      method: req.method,
      ip: req.ip
    });
    
    return res.status(400).json({
      success: false,
      error: 'SANITIZATION_ERROR',
      details: 'Invalid verification data format'
    });
  }
}

module.exports = {
  sanitizeInput,
  sanitizePaymentInput,
  sanitizeVerificationInput,
  sanitizeString,
  sanitizeNumber,
  sanitizeBoolean,
  sanitizeFieldType,
  deepSanitize
}; 