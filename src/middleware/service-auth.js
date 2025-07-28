/**
 * Service Authentication Middleware
 * 
 * Validates inter-service communication using API keys or service tokens.
 * This ensures only authorized services can access service-specific endpoints.
 */

const { logger } = require('../utils/logger');

/**
 * Validate that the request comes from an authorized service
 */
const validateServiceAuth = (req, res, next) => {
  try {
    // Get service auth token from headers
    const serviceToken = req.headers['x-service-auth'] || req.headers['authorization'];
    const serviceClient = req.headers['x-service-client'];

    // In development, allow requests without authentication
    if (process.env.NODE_ENV === 'development' && !serviceToken) {
      logger.debug('Service auth bypassed in development mode');
      req.serviceClient = serviceClient || 'unknown';
      return next();
    }

    // Check if service token is provided
    if (!serviceToken) {
      logger.warn('Service auth failed: No token provided', {
        path: req.path,
        method: req.method,
        serviceClient
      });
      return res.status(401).json({
        success: false,
        error: 'Service authentication required'
      });
    }

    // Validate service token
    // In production, this would validate against a service registry
    const expectedToken = process.env.SERVICE_AUTH_TOKEN || 'dev-service-token';
    const tokenValue = serviceToken.replace('Bearer ', '');

    if (tokenValue !== expectedToken) {
      logger.warn('Service auth failed: Invalid token', {
        path: req.path,
        method: req.method,
        serviceClient
      });
      return res.status(401).json({
        success: false,
        error: 'Invalid service credentials'
      });
    }

    // Set service client info on request
    req.serviceClient = serviceClient || 'authenticated-service';
    req.isServiceRequest = true;

    logger.debug('Service auth successful', {
      serviceClient: req.serviceClient,
      path: req.path
    });

    next();
  } catch (error) {
    logger.error('Service auth middleware error', {
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({
      success: false,
      error: 'Service authentication error'
    });
  }
};

/**
 * Middleware to require specific services
 * @param {Array<string>} allowedServices - List of allowed service names
 */
const requireServices = (allowedServices) => {
  return (req, res, next) => {
    // Skip in development if no service client specified
    if (process.env.NODE_ENV === 'development' && !req.serviceClient) {
      return next();
    }

    if (!req.serviceClient || !allowedServices.includes(req.serviceClient)) {
      logger.warn('Service not allowed', {
        serviceClient: req.serviceClient,
        allowedServices,
        path: req.path
      });
      return res.status(403).json({
        success: false,
        error: 'Service not authorized for this endpoint'
      });
    }

    next();
  };
};

module.exports = {
  validateServiceAuth,
  requireServices
};