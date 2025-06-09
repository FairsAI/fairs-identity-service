/**
 * Checkout Request Sanitizer
 * 
 * Removes ALL sensitive data before sending optimization requests to AI service.
 * Ensures no payment card data, customer PII, or billing information reaches AI.
 * 
 * SECURITY FEATURES:
 * - Complete payment card data removal (PCI DSS compliance)
 * - Customer PII scrubbing (names, addresses, phone numbers)
 * - Sensitive billing information filtering
 * - Audit logging of sanitization process
 * - Optimization-relevant data preservation
 */

const crypto = require('crypto');
const { logger } = require('./logger');

// Sensitive field patterns to remove/mask
const SENSITIVE_PATTERNS = {
  // Payment card data (PCI DSS Level 1)
  CARD_NUMBER: /\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/g,
  CVV: /\b\d{3,4}\b/g,
  EXPIRY_DATE: /\b(0[1-9]|1[0-2])\/\d{2,4}\b/g,
  
  // Personal identifiers
  SSN: /\b\d{3}-\d{2}-\d{4}\b/g,
  PHONE: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
  EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  
  // Account numbers
  BANK_ACCOUNT: /\b\d{8,17}\b/g,
  ROUTING_NUMBER: /\b\d{9}\b/g
};

// Fields that should be completely removed
const REMOVE_FIELDS = [
  // Payment data
  'cardNumber', 'card_number', 'creditCardNumber', 'payment_method_nonce',
  'cvv', 'cvc', 'cvv2', 'securityCode', 'verification_value',
  'expiryDate', 'expiry_date', 'expiration_date', 'exp_month', 'exp_year',
  'cardholderName', 'cardholder_name', 'name_on_card',
  
  // Banking data
  'bankAccountNumber', 'bank_account_number', 'account_number',
  'routingNumber', 'routing_number', 'aba_number', 'swift_code',
  'iban', 'sort_code', 'bsb_number',
  
  // Personal identifiers
  'ssn', 'social_security_number', 'tax_id', 'national_id',
  'passport_number', 'drivers_license', 'government_id',
  
  // Contact information
  'email', 'phone', 'phoneNumber', 'phone_number', 'mobile',
  'firstName', 'first_name', 'lastName', 'last_name', 'fullName', 'full_name',
  
  // Address information
  'address', 'street_address', 'address_line_1', 'address_line_2',
  'city', 'state', 'province', 'zip_code', 'postal_code', 'country',
  'billing_address', 'shipping_address',
  
  // Authentication data
  'password', 'token', 'access_token', 'refresh_token', 'api_key',
  'session_id', 'csrf_token', 'auth_token'
];

// Fields that should be anonymized/hashed instead of removed
const ANONYMIZE_FIELDS = [
  'userId', 'user_id', 'customerId', 'customer_id', 'merchantId', 'merchant_id',
  'orderId', 'order_id', 'transactionId', 'transaction_id', 'paymentId', 'payment_id'
];

// Safe optimization fields to preserve
const SAFE_OPTIMIZATION_FIELDS = [
  'amount', 'currency', 'payment_method_type', 'transaction_type',
  'country_code', 'timezone', 'device_type', 'browser_type',
  'checkout_step', 'conversion_funnel_step', 'ab_test_variant',
  'session_duration', 'cart_abandonment_risk', 'fraud_score_range',
  'preferred_payment_methods', 'checkout_completion_time',
  'device_fingerprint_hash', 'ip_geolocation_country'
];

/**
 * Creates a deterministic hash for anonymization
 */
function createAnonymousHash(value, salt = 'ai-optimization') {
  return crypto
    .createHash('sha256')
    .update(`${salt}:${value}`)
    .digest('hex')
    .substring(0, 16); // Use first 16 chars for readability
}

/**
 * Recursively removes sensitive fields from an object
 */
function removeSensitiveFields(obj, path = '') {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }
  
  if (Array.isArray(obj)) {
    return obj.map((item, index) => 
      removeSensitiveFields(item, `${path}[${index}]`)
    );
  }
  
  const sanitized = {};
  
  for (const [key, value] of Object.entries(obj)) {
    const fieldPath = path ? `${path}.${key}` : key;
    const lowerKey = key.toLowerCase();
    
    // Remove completely sensitive fields
    if (REMOVE_FIELDS.some(field => lowerKey.includes(field.toLowerCase()))) {
      logger.info('Sensitive field removed during AI request sanitization', {
        field: fieldPath,
        type: 'REMOVED'
      });
      continue;
    }
    
    // Anonymize ID fields
    if (ANONYMIZE_FIELDS.some(field => lowerKey.includes(field.toLowerCase()))) {
      sanitized[key] = createAnonymousHash(String(value));
      logger.info('Field anonymized during AI request sanitization', {
        field: fieldPath,
        type: 'ANONYMIZED'
      });
      continue;
    }
    
    // Recursively sanitize nested objects
    if (typeof value === 'object') {
      sanitized[key] = removeSensitiveFields(value, fieldPath);
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}

/**
 * Sanitizes string values by removing sensitive patterns
 */
function sanitizeStringPatterns(str) {
  if (typeof str !== 'string') {
    return str;
  }
  
  let sanitized = str;
  
  // Remove sensitive patterns
  Object.entries(SENSITIVE_PATTERNS).forEach(([type, pattern]) => {
    const matches = sanitized.match(pattern);
    if (matches) {
      sanitized = sanitized.replace(pattern, '[REDACTED]');
      logger.info('Sensitive pattern detected and redacted', {
        patternType: type,
        matchCount: matches.length
      });
    }
  });
  
  return sanitized;
}

/**
 * Recursively sanitizes all string values in an object
 */
function sanitizeStringValues(obj) {
  if (typeof obj !== 'object' || obj === null) {
    return sanitizeStringPatterns(obj);
  }
  
  if (Array.isArray(obj)) {
    return obj.map(sanitizeStringValues);
  }
  
  const sanitized = {};
  
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      sanitized[key] = sanitizeStringPatterns(value);
    } else if (typeof value === 'object') {
      sanitized[key] = sanitizeStringValues(value);
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}

/**
 * Extracts only optimization-relevant data
 */
function extractOptimizationData(checkoutData) {
  const optimizationData = {};
  
  // Extract safe fields for optimization
  SAFE_OPTIMIZATION_FIELDS.forEach(field => {
    if (checkoutData[field] !== undefined) {
      optimizationData[field] = checkoutData[field];
    }
  });
  
  // Add derived optimization metrics
  if (checkoutData.items && Array.isArray(checkoutData.items)) {
    optimizationData.cart_item_count = checkoutData.items.length;
    optimizationData.cart_categories = [
      ...new Set(checkoutData.items.map(item => item.category).filter(Boolean))
    ];
  }
  
  // Add session context (anonymized)
  if (checkoutData.session) {
    optimizationData.session_context = {
      duration_range: categorizeSessionDuration(checkoutData.session.duration),
      page_views: Math.min(checkoutData.session.pageViews || 0, 100), // Cap for privacy
      checkout_attempts: Math.min(checkoutData.session.checkoutAttempts || 0, 10)
    };
  }
  
  // Add risk indicators (anonymized ranges)
  if (checkoutData.riskScore !== undefined) {
    optimizationData.fraud_risk_category = categorizeFraudRisk(checkoutData.riskScore);
  }
  
  return optimizationData;
}

/**
 * Categorizes session duration into ranges for privacy
 */
function categorizeSessionDuration(duration) {
  if (duration < 60) return 'short'; // < 1 minute
  if (duration < 300) return 'medium'; // 1-5 minutes
  if (duration < 1800) return 'long'; // 5-30 minutes
  return 'extended'; // > 30 minutes
}

/**
 * Categorizes fraud risk score into ranges
 */
function categorizeFraudRisk(score) {
  if (score < 0.2) return 'low';
  if (score < 0.5) return 'medium';
  if (score < 0.8) return 'high';
  return 'critical';
}

/**
 * Main sanitization function - prepares checkout data for AI service
 */
function sanitizeCheckoutRequest(checkoutData) {
  try {
    logger.info('Starting checkout request sanitization for AI service', {
      originalFields: Object.keys(checkoutData).length,
      hasPaymentData: !!(checkoutData.payment || checkoutData.card || checkoutData.billing)
    });
    
    // Step 1: Remove sensitive fields
    let sanitized = removeSensitiveFields(checkoutData);
    
    // Step 2: Sanitize string patterns
    sanitized = sanitizeStringValues(sanitized);
    
    // Step 3: Extract only optimization-relevant data
    const optimizationData = extractOptimizationData(sanitized);
    
    // Step 4: Add request metadata
    const sanitizedRequest = {
      optimization_request: {
        data: optimizationData,
        request_id: createAnonymousHash(`${Date.now()}-${Math.random()}`),
        timestamp: new Date().toISOString(),
        version: '1.0',
        sanitization_applied: true
      }
    };
    
    logger.info('Checkout request sanitization completed', {
      originalFields: Object.keys(checkoutData).length,
      sanitizedFields: Object.keys(optimizationData).length,
      requestId: sanitizedRequest.optimization_request.request_id
    });
    
    return sanitizedRequest;
    
  } catch (error) {
    logger.error('Checkout request sanitization failed', {
      error: error.message,
      stack: error.stack
    });
    
    throw new Error('Failed to sanitize checkout request for AI service');
  }
}

/**
 * Validates that sanitized request contains no sensitive data
 */
function validateSanitization(sanitizedRequest) {
  const violations = [];
  const requestString = JSON.stringify(sanitizedRequest);
  
  // Check for sensitive patterns
  Object.entries(SENSITIVE_PATTERNS).forEach(([type, pattern]) => {
    const matches = requestString.match(pattern);
    if (matches) {
      violations.push(`${type}: ${matches.length} matches found`);
    }
  });
  
  // Check for sensitive fields
  REMOVE_FIELDS.forEach(field => {
    if (requestString.toLowerCase().includes(field.toLowerCase())) {
      violations.push(`Sensitive field detected: ${field}`);
    }
  });
  
  if (violations.length > 0) {
    logger.error('Sanitization validation failed', { violations });
    throw new Error(`Sanitization validation failed: ${violations.join(', ')}`);
  }
  
  logger.info('Sanitization validation passed - no sensitive data detected');
  return true;
}

module.exports = {
  sanitizeCheckoutRequest,
  validateSanitization,
  createAnonymousHash,
  extractOptimizationData,
  SAFE_OPTIMIZATION_FIELDS,
  REMOVE_FIELDS,
  ANONYMIZE_FIELDS
}; 