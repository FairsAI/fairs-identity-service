/**
 * Service Authentication Middleware
 * Handles service-to-service authentication using service tokens
 */

const { logger } = require('../utils/logger');
const jwt = require('jsonwebtoken');
const axios = require('axios');

// Cache for validated service tokens to reduce Auth Service calls
const tokenCache = new Map();
const TOKEN_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Clean expired tokens from cache
 */
function cleanTokenCache() {
  const now = Date.now();
  for (const [token, data] of tokenCache.entries()) {
    if (now - data.timestamp > TOKEN_CACHE_TTL) {
      tokenCache.delete(token);
    }
  }
}

/**
 * Validate service token with Auth Service
 * @param {string} token - Service token to validate
 * @returns {Promise<Object>} Token validation result
 */
async function validateServiceToken(token) {
  // Check cache first
  const cached = tokenCache.get(token);
  if (cached && Date.now() - cached.timestamp < TOKEN_CACHE_TTL) {
    return cached.data;
  }

  try {
    // Validate with Auth Service
    const authServiceUrl = process.env.AUTH_SERVICE_URL || 'http://fairs-auth-service:3005';
    const response = await axios.post(`${authServiceUrl}/api/v1/tokens/validate`, {
      token
    }, {
      timeout: 5000,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    if (response.data.valid) {
      // Cache the result
      tokenCache.set(token, {
        data: response.data,
        timestamp: Date.now()
      });
      
      // Clean cache periodically
      if (tokenCache.size > 100) {
        cleanTokenCache();
      }
    }

    return response.data;
  } catch (error) {
    logger.error('Service token validation failed', {
      error: error.message,
      token: token.substring(0, 20) + '...'
    });
    throw error;
  }
}

/**
 * Middleware to validate service tokens
 * Allows both user JWT tokens and service tokens
 */
function authenticateServiceOrUser(options = {}) {
  return async (req, res, next) => {
    try {
      // Skip validation for excluded paths
      if (options.excludePaths && options.excludePaths.some(path => req.path.startsWith(path))) {
        return next();
      }

      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          success: false,
          error: 'Authorization required'
        });
      }

      const token = authHeader.substring(7);
      
      // Quick decode to check token type
      const decoded = jwt.decode(token);
      
      if (!decoded) {
        return res.status(401).json({
          success: false,
          error: 'Invalid token format'
        });
      }

      // Check if it's a service token
      if (decoded.tokenType === 'service' && decoded.serviceId) {
        // Validate service token
        const validation = await validateServiceToken(token);
        
        if (!validation.valid) {
          return res.status(401).json({
            success: false,
            error: validation.error || 'Invalid service token'
          });
        }

        // Check if service has required permissions
        if (options.requiredPermissions) {
          const hasPermission = options.requiredPermissions.some(perm => 
            validation.user.permissions.includes(perm)
          );
          
          if (!hasPermission) {
            logger.warn('Service lacks required permissions', {
              serviceId: decoded.serviceId,
              required: options.requiredPermissions,
              actual: validation.user.permissions
            });
            return res.status(403).json({
              success: false,
              error: 'Insufficient permissions'
            });
          }
        }

        // Store service info in request
        req.service = {
          serviceId: decoded.serviceId,
          serviceName: decoded.serviceName,
          permissions: validation.user.permissions,
          isService: true
        };
        
        req.user = {
          userId: validation.user.userId,
          email: validation.user.email,
          merchantId: validation.user.merchantId,
          permissions: validation.user.permissions,
          isService: true
        };

        logger.debug('Service token validated', {
          serviceId: decoded.serviceId,
          serviceName: decoded.serviceName
        });
        
        return next();
      } 
      
      // For regular user tokens, use existing JWT validation
      // This would typically call your existing JWT validation logic
      try {
        const jwtSecret = process.env.JWT_SECRET || 'dev-jwt-secret-please-change-in-production-minimum-64-characters-required';
        const verified = jwt.verify(token, jwtSecret);
        
        req.user = {
          userId: verified.userId,
          email: verified.email,
          merchantId: verified.merchantId,
          permissions: verified.permissions || [],
          isService: false
        };
        
        return next();
      } catch (error) {
        return res.status(401).json({
          success: false,
          error: 'Invalid or expired token'
        });
      }
      
    } catch (error) {
      logger.error('Authentication error', error);
      return res.status(500).json({
        success: false,
        error: 'Authentication failed'
      });
    }
  };
}

/**
 * Require service authentication only
 * Rejects user tokens, only accepts service tokens
 */
function requireServiceAuth(options = {}) {
  return async (req, res, next) => {
    const auth = authenticateServiceOrUser(options);
    
    await auth(req, res, (err) => {
      if (err) return next(err);
      
      // Ensure it's a service token
      if (!req.service || !req.user.isService) {
        return res.status(403).json({
          success: false,
          error: 'Service authentication required'
        });
      }
      
      next();
    });
  };
}

module.exports = {
  authenticateServiceOrUser,
  requireServiceAuth,
  validateServiceToken
};