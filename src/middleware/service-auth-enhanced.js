/**
 * Service Authentication Middleware
 * 
 * PRE-LAUNCH VERSION: JWT-only authentication
 * - No API key support
 * - All services must have SERVICE_ID and SERVICE_SECRET
 * - Tokens expire and must be renewed
 */

const { logger } = require('../utils/logger');
const { authenticateServiceToken } = require('@fairs/security-middleware');

/**
 * JWT-only service authentication
 * @param {Object} options - Authentication options
 * @returns {Function} Express middleware
 */
function authenticateService(options = {}) {
  const {
    requiredPermissions = []
  } = options;

  // Use the JWT-only authenticateServiceToken from security middleware
  const jwtAuth = authenticateServiceToken({
    requiredPermissions
  });

  return async (req, res, next) => {
    try {
      // Let the security middleware handle authentication
      await jwtAuth(req, res, (err) => {
        if (err) return next(err);
        
        // Log successful authentication
        if (req.service) {
          logger.info('Service authenticated', {
            serviceId: req.service.id,
            serviceName: req.service.name,
            authMethod: 'JWT Token',
            path: req.path,
            method: req.method,
            permissions: req.service.permissions
          });

          // Add service info to response headers for debugging
          res.setHeader('X-Service-Auth', 'JWT');
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
 * @deprecated Use authenticateService instead
 */
function validateApiKey(options = {}) {
  throw new Error(
    'API key authentication is no longer supported. ' +
    'Use authenticateService() for JWT-based authentication. ' +
    'Ensure SERVICE_ID and SERVICE_SECRET are configured.'
  );
}

/**
 * Check if request has valid service authentication
 * @param {Object} req - Express request
 * @returns {boolean} True if authenticated
 */
function isServiceAuthenticated(req) {
  return !!(req.service && req.service.id && req.service.tokenType === 'jwt');
}

/**
 * Get service identity from request
 * @param {Object} req - Express request
 * @returns {Object|null} Service info or null
 */
function getServiceIdentity(req) {
  if (!req.service || req.service.tokenType !== 'jwt') return null;
  
  return {
    id: req.service.id,
    name: req.service.name,
    type: 'jwt',
    permissions: req.service.permissions || []
  };
}

module.exports = {
  authenticateService,
  requirePermissions,
  validateApiKey, // Deprecated but kept to throw error
  isServiceAuthenticated,
  getServiceIdentity
};