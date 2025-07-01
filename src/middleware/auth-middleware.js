/**
 * Authentication Middleware - ZERO HARDCODED CREDENTIALS
 * 
 * Enterprise-grade authentication middleware for payment processing systems
 * ALL credentials must come from secure environment configuration
 */

const { logger } = require('../utils/logger');
const { authService } = require('../auth/secure-authentication');
const config = require('../config');

/**
 * Validate API key from request header with enterprise security
 * @param {Object} options - Configuration options
 * @returns {Function} - Express middleware function
 */
function validateApiKey(options = {}) {
  const apiKeyHeader = options.header || 'x-api-key';
  
  // SECURITY: Get API keys from secure configuration
  // NO hardcoded credentials allowed
  const validApiKeys = config.api?.validApiKeys || [];
  
  if (validApiKeys.length === 0 && config.env !== 'test') {
    throw new Error('SECURITY ERROR: No valid API keys configured. Set VALID_API_KEYS environment variable.');
  }
  
  const apiKeys = new Set(validApiKeys);
  
  return (req, res, next) => {
    const apiKey = req.headers[apiKeyHeader.toLowerCase()];
    
    // Skip validation for excluded paths
    if (options.excludePaths && options.excludePaths.some(path => req.path.startsWith(path))) {
      return next();
    }
    
    if (!apiKey) {
      logger.warn(`API request missing API key: ${req.method} ${req.path}`);
      return res.status(401).json({
        success: false,
        error: 'API key is required'
      });
    }
    
    if (!apiKeys.has(apiKey)) {
      logger.warn(`Invalid API key used: ${req.method} ${req.path}`);
      return res.status(403).json({
        success: false,
        error: 'Invalid API key'
      });
    }
    
    // Store API key info in request for later use
    req.apiKeyInfo = {
      key: apiKey,
      isValid: true
    };
    
    next();
  };
}

/**
 * Validate merchant-specific access
 * @param {Object} options - Configuration options
 * @returns {Function} - Express middleware function
 */
function validateMerchantAccess(options = {}) {
  return async (req, res, next) => {
    try {
      // Skip validation for excluded paths
      if (options.excludePaths && options.excludePaths.some(path => req.path.startsWith(path))) {
        return next();
      }
      
      // Get merchant ID from request
      const merchantId = req.body.merchantId || req.query.merchantId || req.params.merchantId;
      
      if (!merchantId) {
        return res.status(400).json({
          success: false,
          error: 'Merchant ID is required'
        });
      }
      
      // Store in request for use by route handlers
      req.merchantId = merchantId;
      
      // SECURITY: Always require API key authentication - NEVER skip validation
      const apiKey = req.apiKeyInfo?.key;
      
      if (!apiKey) {
        logger.error(`SECURITY VIOLATION: Missing API key for merchant access attempt`, {
          merchantId,
          path: req.path,
          method: req.method,
          ip: req.ip,
          userAgent: req.headers['user-agent']
        });
        return res.status(401).json({
          success: false,
          error: 'API key authentication required for merchant access'
        });
      }
      
      // If we have a merchant-to-apikey mapping, validate it
      if (config.api?.merchantApiKeys && Object.keys(config.api.merchantApiKeys).length > 0) {
        // Check if this API key is authorized for this merchant
        const authorizedMerchants = config.api.merchantApiKeys[apiKey] || [];
        const hasAccess = authorizedMerchants.includes(merchantId) || 
                          authorizedMerchants.includes('*'); // Wildcard for all merchants
        
        if (!hasAccess) {
          logger.warn(`Unauthorized merchant access attempt: API key not authorized for merchant ${merchantId}`, {
            apiKeyPrefix: apiKey.substring(0, 8) + '...',
            merchantId,
            path: req.path,
            ip: req.ip
          });
          return res.status(403).json({
            success: false,
            error: 'API key not authorized for this merchant'
          });
        }
      } else {
        // No merchant mapping configured - require API key but allow access
        logger.debug(`API key validated for merchant access (no specific mapping)`, {
          merchantId,
          apiKeyPrefix: apiKey.substring(0, 8) + '...'
        });
      }
      
      next();
    } catch (error) {
      logger.error('Error validating merchant access:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to validate merchant access'
      });
    }
  };
}

/**
 * Validate JWT token from request header
 * @param {Object} options - Configuration options
 * @returns {Function} - Express middleware function
 */
function validateJwtToken(options = {}) {
  const tokenHeader = options.header || 'authorization';
  
  return (req, res, next) => {
    try {
      // Skip validation for excluded paths
      if (options.excludePaths && options.excludePaths.some(path => req.path.startsWith(path))) {
        return next();
      }
      
      // Get token from header
      const authHeader = req.headers[tokenHeader.toLowerCase()];
      
      if (!authHeader) {
        return res.status(401).json({
          success: false,
          error: 'Authorization token required'
        });
      }
      
      // Extract token (Bearer token format)
      const token = authHeader.startsWith('Bearer ') 
        ? authHeader.substring(7) 
        : authHeader;
      
      if (!token) {
        return res.status(401).json({
          success: false,
          error: 'Invalid authorization format'
        });
      }
      
      // Verify token using secure authentication service
      const decoded = authService.verifyToken(token);
      
      // Store decoded token info in request
      req.user = {
        userId: decoded.userId,
        username: decoded.username,
        merchantId: decoded.merchantId,
        permissions: decoded.permissions || [],
        tokenInfo: decoded
      };
      
      req.authToken = token;
      
      logger.debug(`JWT token validated for user: ${decoded.username}`);
      next();
      
    } catch (error) {
      logger.warn(`JWT token validation failed: ${error.message}`, {
        path: req.path,
        ip: req.ip
      });
      
      return res.status(401).json({
        success: false,
        error: 'Invalid or expired token'
      });
    }
  };
}

/**
 * Comprehensive authentication middleware that validates both API key and JWT
 * @param {Object} options - Configuration options
 * @returns {Function} - Express middleware function
 */
function requireAuthentication(options = {}) {
  const apiKeyValidator = validateApiKey(options);
  const jwtValidator = validateJwtToken(options);
  
  return (req, res, next) => {
    // First validate API key
    apiKeyValidator(req, res, (err) => {
      if (err) return next(err);
      
      // Then validate JWT token
      jwtValidator(req, res, next);
    });
  };
}

/**
 * Rate limiting middleware for authentication endpoints
 * @param {Object} options - Configuration options
 * @returns {Function} - Express middleware function
 */
function authenticationRateLimit(options = {}) {
  const windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes
  const maxAttempts = options.maxAttempts || 5;
  const requests = new Map();
  
  return (req, res, next) => {
    const clientId = req.ip + (req.headers['user-agent'] || '');
    const now = Date.now();
    
    // Clean up old entries
    for (const [key, data] of requests.entries()) {
      if (now - data.firstAttempt > windowMs) {
        requests.delete(key);
      }
    }
    
    // Check current client
    const clientData = requests.get(clientId) || { count: 0, firstAttempt: now };
    
    if (clientData.count >= maxAttempts && (now - clientData.firstAttempt) < windowMs) {
      logger.warn(`Rate limit exceeded for client: ${req.ip}`);
      return res.status(429).json({
        success: false,
        error: 'Too many authentication attempts. Please try again later.',
        retryAfter: Math.ceil((windowMs - (now - clientData.firstAttempt)) / 1000)
      });
    }
    
    // Increment counter
    clientData.count++;
    requests.set(clientId, clientData);
    
    next();
  };
}

module.exports = {
  validateApiKey,
  validateMerchantAccess,
  validateJwtToken,
  requireAuthentication,
  authenticationRateLimit
}; 