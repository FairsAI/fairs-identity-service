/**
 * Enhanced Service Authentication Middleware
 * 
 * Supports both JWT service tokens (preferred) and API keys (legacy)
 * for backward compatibility during migration
 */

const { logger } = require('../utils/logger');
const config = require('../config');
const { authenticateServiceToken } = require('@fairs/security-middleware');

/**
 * Enhanced service authentication that accepts both JWT tokens and API keys
 * @param {Object} options - Authentication options
 * @returns {Function} Express middleware
 */
function authenticateService(options = {}) {
  const {
    allowApiKeys = true, // Support API keys during transition
    requiredPermissions = [],
    apiKeyHeader = 'x-api-key'
  } = options;

  // Use the security middleware's authenticateServiceToken
  const jwtAuth = authenticateServiceToken({
    allowApiKeys,
    apiKeyHeader,
    requiredPermissions
  });

  return async (req, res, next) => {
    try {
      // Let the security middleware handle authentication
      await jwtAuth(req, res, (err) => {
        if (err) return next(err);
        
        // Log authentication method for monitoring
        if (req.service) {
          const authMethod = req.service.tokenType === 'jwt' ? 'JWT Token' : 'API Key';
          
          logger.info('Service authenticated', {
            serviceId: req.service.id,
            serviceName: req.service.name,
            authMethod,
            path: req.path,
            method: req.method
          });

          // Warn about API key usage to encourage migration
          if (req.service.tokenType === 'api-key') {
            logger.warn('API key authentication used - please migrate to JWT service tokens', {
              path: req.path,
              method: req.method
            });
          }

          // Add service info to response headers for debugging
          res.setHeader('X-Service-Auth', authMethod);
          res.setHeader('X-Service-ID', req.service.id);
        }
        
        next();
      });
    } catch (error) {
      logger.error('Service authentication error', {
        error: error.message,
        path: req.path
      });
      
      return res.status(500).json({
        success: false,
        error: 'Authentication error',
        code: 'AUTH_ERROR'
      });
    }
  };
}

/**
 * Require specific permissions for a route
 * Must be used after authenticateService middleware
 * @param {Array<string>} permissions - Required permissions
 * @returns {Function} Express middleware
 */
function requirePermissions(permissions = []) {
  return (req, res, next) => {
    if (!req.service) {
      return res.status(401).json({
        success: false,
        error: 'Service authentication required',
        code: 'NO_SERVICE_AUTH'
      });
    }

    // API keys have all permissions during transition
    if (req.service.tokenType === 'api-key') {
      return next();
    }

    // Check JWT token permissions
    const hasPermissions = permissions.every(perm => 
      req.service.permissions && req.service.permissions.includes(perm)
    );

    if (!hasPermissions) {
      logger.warn('Service lacks required permissions', {
        serviceId: req.service.id,
        required: permissions,
        available: req.service.permissions,
        path: req.path
      });

      return res.status(403).json({
        success: false,
        error: 'Insufficient permissions',
        code: 'FORBIDDEN',
        required: permissions
      });
    }

    next();
  };
}

/**
 * Legacy API key validation for backward compatibility
 * @deprecated Use authenticateService instead
 */
function validateApiKey(options = {}) {
  logger.warn('validateApiKey is deprecated - use authenticateService instead');
  
  return authenticateService({
    ...options,
    allowApiKeys: true,
    requiredPermissions: []
  });
}

/**
 * Check if request has valid service authentication
 * @param {Object} req - Express request
 * @returns {boolean} True if authenticated
 */
function isServiceAuthenticated(req) {
  return !!(req.service && req.service.id);
}

/**
 * Get service identity from request
 * @param {Object} req - Express request
 * @returns {Object|null} Service info or null
 */
function getServiceIdentity(req) {
  if (!req.service) return null;
  
  return {
    id: req.service.id,
    name: req.service.name,
    type: req.service.tokenType,
    permissions: req.service.permissions || []
  };
}

module.exports = {
  authenticateService,
  requirePermissions,
  validateApiKey, // Deprecated but kept for compatibility
  isServiceAuthenticated,
  getServiceIdentity
};