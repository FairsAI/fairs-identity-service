/**
 * ✅ OPTIMIZED: Using consolidated input sanitization from @fairs/shared-utils
 * 
 * BEFORE: 474 lines of duplicate code across 3 services
 * AFTER: Single shared module with enhanced features
 * 
 * BENEFITS:
 * - Consistent security across all services
 * - Reduced maintenance overhead
 * - Enhanced performance monitoring
 * - Unified error handling
 */

const { security } = require('@fairs/shared-utils');
const { logger } = require('../utils/logger');

// ✅ OPTIMIZATION: Removed 450+ lines of duplicate code
// All sanitization logic now handled by @fairs/shared-utils

// Create middleware instances with logger using organized structure
const sanitizeInput = security.createSanitizationMiddleware(logger);
const sanitizePaymentInput = security.createPaymentSanitizationMiddleware(logger);
const sanitizeVerificationInput = security.createVerificationSanitizationMiddleware(logger);

// ✅ OPTIMIZATION: Export shared utilities for backward compatibility
module.exports = {
  sanitizeInput,
  sanitizePaymentInput,
  sanitizeVerificationInput
}; 