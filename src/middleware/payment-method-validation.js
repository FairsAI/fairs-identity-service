/**
 * Payment Method Validation Middleware
 * 
 * TRANSACTION INTEGRITY REMEDIATION
 * Addresses issues identified in grow@grow.com transaction:
 * - Invalid expiry dates (44/2044)
 * - Missing form validation
 * - Inconsistent data formats
 */

const Joi = require('joi');
const { logger } = require('../utils/logger');

/**
 * Payment method validation schema
 */
const paymentMethodSchema = Joi.object({
  // User identification
  userId: Joi.number().integer().positive().optional(),
  email: Joi.string().email().max(254).optional(),
  firstName: Joi.string().pattern(/^[a-zA-Z\s'-]+$/).min(1).max(100).optional(),
  lastName: Joi.string().pattern(/^[a-zA-Z\s'-]+$/).min(1).max(100).optional(),
  
  // Payment method type
  type: Joi.string()
    .valid('credit_card', 'debit_card', 'card', 'bank_transfer', 'paypal')
    .default('credit_card'),
  
  paymentType: Joi.string()
    .valid('credit_card', 'debit_card', 'card', 'bank_transfer', 'paypal')
    .optional(),
  
  // Card details with enhanced validation
  cardNumber: Joi.string()
    .pattern(/^\d{13,19}$/)
    .messages({
      'string.pattern.base': 'Card number must be 13-19 digits'
    })
    .optional(),
  
  lastFourDigits: Joi.string()
    .pattern(/^\d{4}$/)
    .messages({
      'string.pattern.base': 'Last four digits must be exactly 4 digits'
    })
    .optional(),
  
  last_four_digits: Joi.string()
    .pattern(/^\d{4}$/)
    .optional(),
  
  // CRITICAL: Enhanced expiry validation to prevent 44/2044 errors
  expiryMonth: Joi.number()
    .integer()
    .min(1)
    .max(12)
    .messages({
      'number.min': 'Expiry month must be between 1 and 12',
      'number.max': 'Expiry month must be between 1 and 12',
      'number.base': 'Expiry month must be a valid number'
    })
    .optional(),
  
  expiry_month: Joi.number()
    .integer()
    .min(1)
    .max(12)
    .optional(),
  
  expiryYear: Joi.number()
    .integer()
    .min(new Date().getFullYear())
    .max(new Date().getFullYear() + 20)
    .messages({
      'number.min': `Expiry year must be between ${new Date().getFullYear()} and ${new Date().getFullYear() + 20}`,
      'number.max': `Expiry year must be between ${new Date().getFullYear()} and ${new Date().getFullYear() + 20}`,
      'number.base': 'Expiry year must be a valid 4-digit year'
    })
    .optional(),
  
  expiry_year: Joi.number()
    .integer()
    .min(new Date().getFullYear())
    .max(new Date().getFullYear() + 20)
    .optional(),
  
  // Composite expiry handling (MM/YY or MM/YYYY formats)
  expiry: Joi.string()
    .pattern(/^(0[1-9]|1[0-2])\/(20[2-9]\d|[2-9]\d)$/)
    .messages({
      'string.pattern.base': 'Expiry must be in MM/YY or MM/YYYY format (e.g., 12/25 or 12/2025)'
    })
    .optional(),
  
  expiryDate: Joi.string()
    .pattern(/^(0[1-9]|1[0-2])\/(20[2-9]\d|[2-9]\d)$/)
    .optional(),
  
  // Security
  cvv: Joi.string()
    .pattern(/^\d{3,4}$/)
    .messages({
      'string.pattern.base': 'CVV must be 3 or 4 digits'
    })
    .optional(),
  
  cvc: Joi.string()
    .pattern(/^\d{3,4}$/)
    .optional(),
  
  // Metadata
  label: Joi.string().max(100).default('Personal Card'),
  nickname: Joi.string().max(100).optional(),
  provider: Joi.string().max(50).optional(),
  paymentToken: Joi.string().max(255).optional(),
  payment_token: Joi.string().max(255).optional(),
  
  // Settings
  isDefault: Joi.boolean().default(false),
  is_default: Joi.boolean().optional(),
  
  // Billing address
  billingAddressId: Joi.number().integer().positive().optional(),
  billing_address_id: Joi.number().integer().positive().optional(),
  
  // Additional fields (phone, etc.)
  phone: Joi.string()
    .pattern(/^\+?[1-9]\d{1,14}$/)
    .max(20)
    .optional()
});

/**
 * Normalize and validate payment method data
 */
function normalizePaymentMethodData(data) {
  const normalized = { ...data };
  
  // Handle different expiry format inputs
  if (data.expiry || data.expiryDate) {
    const expiryString = data.expiry || data.expiryDate;
    const match = expiryString.match(/^(0?[1-9]|1[0-2])\/?(20)?([2-9]\d)$/);
    
    if (match) {
      normalized.expiryMonth = parseInt(match[1]);
      
      // Handle 2-digit vs 4-digit years
      const yearPart = match[3];
      normalized.expiryYear = match[2] ? parseInt(`20${yearPart}`) : parseInt(`20${yearPart}`);
      
      // Ensure year is 4 digits
      if (normalized.expiryYear < 100) {
        normalized.expiryYear += 2000;
      }
    }
  }
  
  // Normalize field name variations
  if (data.expiry_month && !data.expiryMonth) {
    normalized.expiryMonth = data.expiry_month;
  }
  if (data.expiry_year && !data.expiryYear) {
    normalized.expiryYear = data.expiry_year;
  }
  if (data.last_four_digits && !data.lastFourDigits) {
    normalized.lastFourDigits = data.last_four_digits;
  }
  if (data.payment_token && !data.paymentToken) {
    normalized.paymentToken = data.payment_token;
  }
  if (data.billing_address_id && !data.billingAddressId) {
    normalized.billingAddressId = data.billing_address_id;
  }
  if (data.is_default && data.isDefault === undefined) {
    normalized.isDefault = data.is_default;
  }
  
  // Ensure payment type consistency
  if (data.type && !data.paymentType) {
    normalized.paymentType = data.type;
  } else if (data.paymentType && !data.type) {
    normalized.type = data.paymentType;
  }
  
  return normalized;
}

/**
 * Validate card expiry date specifically
 */
function validateCardExpiry(month, year) {
  const now = new Date();
  const currentYear = now.getFullYear();
  const currentMonth = now.getMonth() + 1; // getMonth() returns 0-11
  
  // Basic range validation
  if (month < 1 || month > 12) {
    return {
      valid: false,
      error: `Invalid expiry month: ${month}. Must be between 1 and 12.`
    };
  }
  
  if (year < currentYear || year > currentYear + 20) {
    return {
      valid: false,
      error: `Invalid expiry year: ${year}. Must be between ${currentYear} and ${currentYear + 20}.`
    };
  }
  
  // Check if card is expired
  if (year === currentYear && month < currentMonth) {
    return {
      valid: false,
      error: `Card expired: ${month}/${year}. Expiry date must be in the future.`
    };
  }
  
  return {
    valid: true,
    month,
    year,
    formatted: `${String(month).padStart(2, '0')}/${year}`
  };
}

/**
 * Payment method validation middleware
 */
function validatePaymentMethod(req, res, next) {
  try {
    // Log incoming request for debugging
    if (process.env.LOG_PAYMENT_VALIDATION === 'true') {
      logger.info('Payment method validation request', {
        body: req.body,
        path: req.path,
        method: req.method
      });
    }
    
    // Normalize the data first
    const normalizedData = normalizePaymentMethodData(req.body);
    
    // Validate with Joi schema
    const { error, value } = paymentMethodSchema.validate(normalizedData, {
      abortEarly: false,
      stripUnknown: true,
      allowUnknown: true // Allow additional fields for flexibility
    });
    
    if (error) {
      const validationErrors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context.value,
        type: detail.type
      }));
      
      logger.warn('Payment method validation failed', {
        errors: validationErrors,
        originalData: req.body,
        normalizedData,
        path: req.path,
        ip: req.ip
      });
      
      return res.status(400).json({
        success: false,
        error: 'PAYMENT_METHOD_VALIDATION_ERROR',
        message: 'Invalid payment method data',
        validationErrors,
        remediation: {
          message: 'Please check the payment method details and try again',
          commonIssues: [
            'Expiry month must be 1-12',
            'Expiry year must be 4 digits (e.g., 2025)',
            'Card number must be 13-19 digits',
            'CVV must be 3-4 digits'
          ]
        }
      });
    }
    
    // Additional expiry validation if both month and year are present
    if (value.expiryMonth && value.expiryYear) {
      const expiryValidation = validateCardExpiry(value.expiryMonth, value.expiryYear);
      
      if (!expiryValidation.valid) {
        logger.warn('Card expiry validation failed', {
          month: value.expiryMonth,
          year: value.expiryYear,
          error: expiryValidation.error,
          path: req.path,
          ip: req.ip
        });
        
        return res.status(400).json({
          success: false,
          error: 'CARD_EXPIRY_VALIDATION_ERROR',
          message: expiryValidation.error,
          remediation: {
            message: 'Please enter a valid expiry date',
            format: 'MM/YYYY (e.g., 12/2025)',
            current: `${value.expiryMonth}/${value.expiryYear}`
          }
        });
      }
    }
    
    // Replace request body with validated and normalized data
    req.body = value;
    
    // Log successful validation
    logger.info('Payment method validation passed', {
      paymentType: value.paymentType || value.type,
      label: value.label,
      hasExpiry: !!(value.expiryMonth && value.expiryYear),
      expiryFormatted: value.expiryMonth && value.expiryYear ? 
        `${String(value.expiryMonth).padStart(2, '0')}/${value.expiryYear}` : null,
      path: req.path,
      ip: req.ip
    });
    
    next();
    
  } catch (error) {
    logger.error('Payment method validation middleware error', {
      error: error.message,
      stack: error.stack,
      body: req.body,
      path: req.path,
      ip: req.ip
    });
    
    return res.status(500).json({
      success: false,
      error: 'VALIDATION_SYSTEM_ERROR',
      message: 'Payment method validation system error'
    });
  }
}

module.exports = {
  validatePaymentMethod,
  validateCardExpiry,
  normalizePaymentMethodData,
  paymentMethodSchema
}; 