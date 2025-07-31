/**
 * AI Service Authentication Middleware
 * 
 * Handles secure authentication for communication with AI optimization service.
 * Implements API key management, JWT tokens, and authentication failure handling.
 * 
 * SECURITY FEATURES:
 * - Environment-based API key management
 * - JWT token generation and validation
 * - Request signing for integrity verification
 * - Authentication failure tracking and rate limiting
 * - Secure credential rotation support
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { logger } = require('../utils/logger');

// Authentication configuration
const AI_SERVICE_CONFIG = {
  JWT_SECRET: process.env.AI_SERVICE_JWT_SECRET,
  JWT_SECRET: process.env.AI_SERVICE_JWT_SECRET,
  JWT_EXPIRY: process.env.AI_SERVICE_JWT_EXPIRY || '1h',
  SERVICE_ID: process.env.AI_SERVICE_ID || 'checkout-service',
  HMAC_SECRET: process.env.AI_SERVICE_HMAC_SECRET,
  MAX_AUTH_FAILURES: 5,
  AUTH_FAILURE_WINDOW: 15 * 60 * 1000 // 15 minutes
};

// Track authentication failures for rate limiting
const authFailures = new Map();

/**
 * Validates environment configuration for AI service authentication
 */
function validateAuthConfig() {
  const required = ['AI_SERVICE_JWT_SECRET', 'AI_SERVICE_JWT_SECRET', 'AI_SERVICE_HMAC_SECRET'];
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required AI service auth environment variables: ${missing.join(', ')}`);
  }
  
  return true;
}

/**
 * Generates JWT token for AI service authentication
 */
function generateAIServiceToken() {
  try {
    validateAuthConfig();
    
    const payload = {
      serviceId: AI_SERVICE_CONFIG.SERVICE_ID,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour
      purpose: 'ai-optimization-request'
    };
    
    const token = jwt.sign(payload, AI_SERVICE_CONFIG.JWT_SECRET, {
      algorithm: 'HS256',
      issuer: 'fairs-checkout',
      audience: 'fairs-ai-service'
    });
    
    logger.info('AI service JWT token generated', { 
      serviceId: payload.serviceId,
      expiresIn: '1h'
    });
    
    return token;
    
  } catch (error) {
    logger.error('Failed to generate AI service token', { error: error.message });
    throw new Error('AI service authentication token generation failed');
  }
}

/**
 * Creates HMAC signature for request integrity verification
 */
function createRequestSignature(requestBody, timestamp) {
  try {
    validateAuthConfig();
    
    const payload = `${timestamp}:${JSON.stringify(requestBody)}`;
    const signature = crypto
      .createHmac('sha256', AI_SERVICE_CONFIG.HMAC_SECRET)
      .update(payload)
      .digest('hex');
    
    return signature;
    
  } catch (error) {
    logger.error('Failed to create request signature', { error: error.message });
    throw new Error('Request signature generation failed');
  }
}

/**
 * Validates AI service response signature
 */
function validateResponseSignature(responseBody, signature, timestamp) {
  try {
    validateAuthConfig();
    
    const payload = `${timestamp}:${JSON.stringify(responseBody)}`;
    const expectedSignature = crypto
      .createHmac('sha256', AI_SERVICE_CONFIG.HMAC_SECRET)
      .update(payload)
      .digest('hex');
    
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
    
  } catch (error) {
    logger.error('Failed to validate response signature', { error: error.message });
    return false;
  }
}

/**
 * Tracks authentication failures for rate limiting
 */
function trackAuthFailure(serviceEndpoint) {
  const now = Date.now();
  const key = `auth_failure_${serviceEndpoint}`;
  
  if (!authFailures.has(key)) {
    authFailures.set(key, []);
  }
  
  const failures = authFailures.get(key);
  
  // Remove old failures outside the window
  const validFailures = failures.filter(
    timestamp => now - timestamp < AI_SERVICE_CONFIG.AUTH_FAILURE_WINDOW
  );
  
  validFailures.push(now);
  authFailures.set(key, validFailures);
  
  logger.warn('AI service authentication failure tracked', {
    endpoint: serviceEndpoint,
    failureCount: validFailures.length,
    maxFailures: AI_SERVICE_CONFIG.MAX_AUTH_FAILURES
  });
  
  return validFailures.length;
}

/**
 * Checks if authentication failures exceed rate limit
 */
function isAuthRateLimited(serviceEndpoint) {
  const key = `auth_failure_${serviceEndpoint}`;
  const failures = authFailures.get(key) || [];
  const now = Date.now();
  
  const recentFailures = failures.filter(
    timestamp => now - timestamp < AI_SERVICE_CONFIG.AUTH_FAILURE_WINDOW
  );
  
  return recentFailures.length >= AI_SERVICE_CONFIG.MAX_AUTH_FAILURES;
}

/**
 * Clears authentication failure tracking for successful auth
 */
function clearAuthFailures(serviceEndpoint) {
  const key = `auth_failure_${serviceEndpoint}`;
  authFailures.delete(key);
  
  logger.info('AI service authentication failures cleared', { 
    endpoint: serviceEndpoint 
  });
}

/**
 * Creates authentication headers for AI service requests
 */
function createAuthHeaders(requestBody = {}) {
  try {
    validateAuthConfig();
    
    const timestamp = Date.now();
    const token = generateAIServiceToken();
    const signature = createRequestSignature(requestBody, timestamp);
    
    return {
      'Authorization': `Bearer ${token}`,
      'Authorization': AI_SERVICE_CONFIG.JWT_SECRET,
      'X-Request-Signature': signature,
      'X-Request-Timestamp': timestamp.toString(),
      'X-Service-ID': AI_SERVICE_CONFIG.SERVICE_ID,
      'Content-Type': 'application/json'
    };
    
  } catch (error) {
    logger.error('Failed to create AI service auth headers', { error: error.message });
    throw new Error('AI service authentication header creation failed');
  }
}

/**
 * Middleware for handling AI service authentication errors
 */
function handleAuthError(error, serviceEndpoint) {
  const failureCount = trackAuthFailure(serviceEndpoint);
  
  if (failureCount >= AI_SERVICE_CONFIG.MAX_AUTH_FAILURES) {
    logger.error('AI service authentication rate limit exceeded', {
      endpoint: serviceEndpoint,
      failureCount
    });
    
    throw new Error(`AI service authentication rate limited. Too many failures (${failureCount})`);
  }
  
  logger.error('AI service authentication failed', {
    endpoint: serviceEndpoint,
    error: error.message,
    failureCount
  });
  
  throw new Error('AI service authentication failed');
}

/**
 * Validates AI service response authentication
 */
function validateResponseAuth(response, serviceEndpoint) {
  try {
    const signature = response.headers['x-response-signature'];
    const timestamp = response.headers['x-response-timestamp'];
    
    if (!signature || !timestamp) {
      throw new Error('Missing response authentication headers');
    }
    
    const isValid = validateResponseSignature(response.data, signature, timestamp);
    
    if (!isValid) {
      throw new Error('Invalid response signature');
    }
    
    // Clear failures on successful authentication
    clearAuthFailures(serviceEndpoint);
    
    logger.info('AI service response authentication validated', { 
      endpoint: serviceEndpoint 
    });
    
    return true;
    
  } catch (error) {
    logger.error('AI service response authentication failed', {
      endpoint: serviceEndpoint,
      error: error.message
    });
    
    throw new Error('AI service response authentication validation failed');
  }
}

module.exports = {
  validateAuthConfig,
  generateAIServiceToken,
  createRequestSignature,
  validateResponseSignature,
  createAuthHeaders,
  handleAuthError,
  validateResponseAuth,
  trackAuthFailure,
  isAuthRateLimited,
  clearAuthFailures
}; 