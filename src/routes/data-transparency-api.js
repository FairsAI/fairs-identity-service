/**
 * Data Transparency API - Processing Transparency & Data Mapping
 * CCPA & PIPEDA Compliance Implementation - SECURITY FIXED
 */

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const validator = require('validator');
const dataTransparencyService = require('../services/dataTransparencyService');
const { logger } = require('../utils/logger');

// ============================================================================
// 🚨 CRITICAL SECURITY FIXES - DATA TRANSPARENCY PROTECTION
// ============================================================================

/**
 * JWT Authentication Middleware - CRITICAL SECURITY FIX
 */
const authenticateRequest = async (req, res, next) => {
  try {
    // Check for API key or JWT token
    const jwtToken = req.headers['Authorization'];
    const authHeader = req.headers.authorization;
    
    if (!jwtToken && !authHeader) {
      logger.warn('SECURITY: Unauthenticated transparency data request blocked', {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        endpoint: req.path
      });
      return res.status(401).json({
        success: false,
        error: 'Authentication required for transparency data access',
        code: 'TRANSPARENCY_AUTH_REQUIRED'
      });
    }
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      // JWT token validation
      const token = authHeader.substring(7);
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret-key');
      req.user = decoded;
      logger.debug('Transparency data JWT authentication successful', { userId: decoded.user_id });
    } else if (jwtToken) {
      // Basic API key validation
      if (jwtToken.length < 32) {
        return res.status(401).json({
          success: false,
          error: 'Invalid API key format for transparency data',
          code: 'INVALID_TRANSPARENCY_JWT_SECRET'
        });
      }
      req.jwtToken = jwtToken;
      logger.debug('Transparency data API key authentication successful');
    } else {
      return res.status(401).json({
        success: false,
        error: 'Invalid authentication method for transparency data',
        code: 'TRANSPARENCY_AUTH_INVALID'
      });
    }
    
    next();
  } catch (error) {
    logger.warn('SECURITY: Transparency data authentication failed', {
      error: error.message,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    return res.status(401).json({
      success: false,
      error: 'Transparency data authentication failed',
      code: 'TRANSPARENCY_AUTH_FAILED'
    });
  }
};

/**
 * Transparency Request Validation - CRITICAL SECURITY FIX
 */
const validateTransparencyRequest = (req, res, next) => {
  try {
    const requestedUserId = req.params.userId;
    const authenticatedUserId = req.user?.id || req.user?.user_id;
    const { email } = req.query;
    const authenticatedEmail = req.user?.email;
    
    // Verify user can only access their own data
    if (requestedUserId && String(requestedUserId) !== String(authenticatedUserId)) {
      return res.status(403).json({
        success: false,
        error: 'Can only access your own transparency data',
        code: 'TRANSPARENCY_ACCESS_DENIED'
      });
    }
    
    // Verify email matches authenticated user
    if (email && authenticatedEmail && email !== authenticatedEmail) {
      return res.status(403).json({
        success: false,
        error: 'Email must match authenticated account',
        code: 'EMAIL_MISMATCH'
      });
    }
    
    next();
  } catch (error) {
    logger.error('Transparency request validation failed', error);
    return res.status(500).json({
      success: false,
      error: 'Transparency request validation failed',
      code: 'TRANSPARENCY_VALIDATION_ERROR'
    });
  }
};

/**
 * Secure Error Handling - CRITICAL SECURITY FIX
 */
const sanitizeTransparencyErrorResponse = (error, context = '') => {
  // Log detailed error server-side
  logger.error(`Data Transparency API error ${context}`, {
    error: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString()
  });
  
  // Return generic error to client
  return {
    success: false,
    error: 'Transparency data processing failed',
    code: 'TRANSPARENCY_DATA_ERROR',
    timestamp: new Date().toISOString()
  };
};

// Apply authentication to ALL routes
router.use(authenticateRequest);

/**
 * Get comprehensive data processing transparency report - SECURITY FIXED
 * GET /api/data-transparency/processing-report/:userId
 */
router.get('/processing-report/:userId', validateTransparencyRequest, async (req, res) => {
    try {
        const { userId } = req.params;
        const { email } = req.query;

        if (!email) {
            return res.status(400).json({
                success: false,
                error: 'Email verification required for transparency report',
                code: 'EMAIL_VERIFICATION_REQUIRED'
            });
        }

        logger.info('Data processing transparency report request', { userId, email });

        const transparencyReport = await dataTransparencyService.getDataProcessingTransparency(userId);

        res.json({
            success: true,
            message: 'Data processing transparency report generated successfully',
            report: transparencyReport,
            legalBasis: 'CCPA Right to Know / PIPEDA Access Right',
            reportId: `transparency_${userId}_${Date.now()}`
        });

    } catch (error) {
        logger.error('Failed to generate transparency report', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to generate transparency report',
            code: 'TRANSPARENCY_REPORT_ERROR'
        });
    }
});

/**
 * Get data inventory for specific user - SECURITY FIXED
 * GET /api/data-transparency/data-inventory/:userId
 */
router.get('/data-inventory/:userId', validateTransparencyRequest, async (req, res) => {
    try {
        const { userId } = req.params;
        const { email } = req.query;

        if (!email) {
            return res.status(400).json({
                success: false,
                error: 'Email verification required for data inventory',
                code: 'EMAIL_VERIFICATION_REQUIRED'
            });
        }

        logger.info('Data inventory request', { userId, email });

        const dataInventory = await dataTransparencyService.getPersonalDataInventory(userId);

        res.json({
            success: true,
            message: 'Data inventory retrieved successfully',
            userId,
            dataInventory,
            categories: {
                PERSONAL_IDENTIFIERS: 'Information that identifies you personally',
                COMMERCIAL_INFO: 'Purchase history and commercial activity',
                INTERNET_ACTIVITY: 'Browsing behavior and device information',
                INFERENCES: 'Predictions about preferences and behavior'
            },
            generatedAt: new Date().toISOString()
        });

    } catch (error) {
        logger.error('Failed to get data inventory', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve data inventory',
            code: 'DATA_INVENTORY_ERROR'
        });
    }
});

/**
 * Get processing activities information
 * GET /api/data-transparency/processing-activities
 */
router.get('/processing-activities', async (req, res) => {
    try {
        logger.info('Processing activities information request');

        const processingActivities = await dataTransparencyService.getProcessingActivities(null);

        res.json({
            success: true,
            message: 'Processing activities information retrieved successfully',
            activities: processingActivities,
            legalFramework: {
                ccpa: 'California Consumer Privacy Act compliance',
                pipeda: 'Personal Information Protection and Electronic Documents Act compliance'
            },
            lastUpdated: new Date().toISOString()
        });

    } catch (error) {
        logger.error('Failed to get processing activities', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve processing activities',
            code: 'PROCESSING_ACTIVITIES_ERROR'
        });
    }
});

/**
 * Get data sharing and third-party information
 * GET /api/data-transparency/data-sharing
 */
router.get('/data-sharing', async (req, res) => {
    try {
        logger.info('Data sharing information request');

        const dataSharingInfo = await dataTransparencyService.getDataSharingInfo(null);

        res.json({
            success: true,
            message: 'Data sharing information retrieved successfully',
            dataSharing: dataSharingInfo,
            lastUpdated: new Date().toISOString()
        });

    } catch (error) {
        logger.error('Failed to get data sharing info', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve data sharing information',
            code: 'DATA_SHARING_ERROR'
        });
    }
});

/**
 * Get data retention policies
 * GET /api/data-transparency/retention-policies
 */
router.get('/retention-policies', async (req, res) => {
    try {
        logger.info('Data retention policies request');

        const retentionInfo = await dataTransparencyService.getDataRetentionInfo(null);

        res.json({
            success: true,
            message: 'Data retention policies retrieved successfully',
            retentionPolicies: retentionInfo,
            lastUpdated: new Date().toISOString()
        });

    } catch (error) {
        logger.error('Failed to get retention policies', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve retention policies',
            code: 'RETENTION_POLICIES_ERROR'
        });
    }
});

/**
 * Get legal basis information
 * GET /api/data-transparency/legal-basis
 */
router.get('/legal-basis', async (req, res) => {
    try {
        logger.info('Legal basis information request');

        const legalBasis = dataTransparencyService.getComprehensiveLegalBasis();

        res.json({
            success: true,
            message: 'Legal basis information retrieved successfully',
            legalBasis,
            lastUpdated: new Date().toISOString()
        });

    } catch (error) {
        logger.error('Failed to get legal basis info', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve legal basis information',
            code: 'LEGAL_BASIS_ERROR'
        });
    }
});

/**
 * Get user rights information
 * GET /api/data-transparency/user-rights
 */
router.get('/user-rights', async (req, res) => {
    try {
        logger.info('User rights information request');

        const userRights = dataTransparencyService.getUserRights();

        res.json({
            success: true,
            message: 'User rights information retrieved successfully',
            userRights,
            lastUpdated: new Date().toISOString()
        });

    } catch (error) {
        logger.error('Failed to get user rights info', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve user rights information',
            code: 'USER_RIGHTS_ERROR'
        });
    }
});

module.exports = router; 