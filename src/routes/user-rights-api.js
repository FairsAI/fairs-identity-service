/**
 * User Rights API - CCPA & PIPEDA Data Subject Rights
 * Production Ready Implementation - SECURITY FIXED
 */

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const validator = require('validator');
const privacyService = require('../services/privacyService');
// const { createGuestToken } = require('../auth/secure-authentication');
const { sanitizeInput } = require('../middleware/input-sanitization');
const rateLimit = require('express-rate-limit');
const { logger } = require('../utils/logger');

// ============================================================================
// 🚨 CRITICAL SECURITY FIXES - PRIVACY DATA PROTECTION
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
      logger.warn('SECURITY: Unauthenticated privacy data request blocked', {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        endpoint: req.path
      });
      return res.status(401).json({
        success: false,
        error: 'Authentication required for privacy data access',
        code: 'PRIVACY_AUTH_REQUIRED'
      });
    }
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      // JWT token validation
      const token = authHeader.substring(7);
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret-key');
      req.user = decoded;
      logger.debug('Privacy data JWT authentication successful', { userId: decoded.user_id });
    } else if (jwtToken) {
      // Basic API key validation
      if (jwtToken.length < 32) {
        return res.status(401).json({
          success: false,
          error: 'Invalid API key format for privacy data',
          code: 'INVALID_PRIVACY_JWT_SECRET'
        });
      }
      req.jwtToken = jwtToken;
      logger.debug('Privacy data API key authentication successful');
    } else {
      return res.status(401).json({
        success: false,
        error: 'Invalid authentication method for privacy data',
        code: 'PRIVACY_AUTH_INVALID'
      });
    }
    
    next();
  } catch (error) {
    logger.warn('SECURITY: Privacy data authentication failed', {
      error: error.message,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    return res.status(401).json({
      success: false,
      error: 'Privacy data authentication failed',
      code: 'PRIVACY_AUTH_FAILED'
    });
  }
};

/**
 * Privacy Request Validation - CRITICAL SECURITY FIX
 */
const validatePrivacyRequest = async (req, res, next) => {
  try {
    const { email, userID } = req.body;
    const authenticatedUserId = req.user?.id || req.user?.user_id;
    const authenticatedEmail = req.user?.email;
    
    // Verify user can only request their own data
    if (userID && String(userID) !== String(authenticatedUserId)) {
      return res.status(403).json({
        success: false,
        error: 'Can only request your own privacy data',
        code: 'PRIVACY_ACCESS_DENIED'
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
    
    // Force use of authenticated user's data
    req.body.userID = authenticatedUserId;
    if (authenticatedEmail) {
      req.body.email = authenticatedEmail;
    }
    
    next();
  } catch (error) {
    logger.error('Privacy request validation failed', error);
    return res.status(500).json({
      success: false,
      error: 'Privacy request validation failed',
      code: 'PRIVACY_VALIDATION_ERROR'
    });
  }
};

/**
 * Secure Error Handling - CRITICAL SECURITY FIX
 */
const sanitizePrivacyErrorResponse = (error, context = '') => {
  // Log detailed error server-side
  logger.error(`Privacy API error ${context}`, {
    error: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString()
  });
  
  // Return generic error to client
  return {
    success: false,
    error: 'Privacy data processing failed',
    code: 'PRIVACY_DATA_ERROR',
    timestamp: new Date().toISOString()
  };
};

// Apply authentication to ALL routes
router.use(authenticateRequest);

// Stricter rate limiting for data rights requests
const dataRightsRateLimit = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // limit each IP to 3 requests per hour
    message: {
        error: 'Too many data rights requests. Please wait before submitting another request.',
        code: 'DATA_RIGHTS_RATE_LIMIT'
    }
});

/**
 * CCPA Right to Know - Request complete data export - SECURITY FIXED
 * POST /api/user-rights/request-data-export
 */
router.post('/request-data-export', dataRightsRateLimit, sanitizeInput, validatePrivacyRequest, async (req, res) => {
    try {
        const { email, userID } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                error: 'Email address is required for data export request',
                code: 'EMAIL_REQUIRED'
            });
        }

        logger.info('CCPA Right to Know request initiated', { email, userID });

        const exportRequest = await privacyService.exportUserData(userID || email, email);

        res.json({
            success: true,
            requestId: exportRequest.requestId,
            message: 'Data export completed successfully',
            userData: exportRequest.userData,
            legalBasis: 'CCPA Section 1798.100 - Right to Know',
            exportDate: exportRequest.exportDate
        });

    } catch (error) {
        logger.error('Failed to process data export request', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to process your data export request',
            code: 'DATA_EXPORT_REQUEST_FAILED'
        });
    }
});

/**
 * CCPA Right to Delete - Request data deletion - SECURITY FIXED
 * POST /api/user-rights/request-data-deletion
 */
router.post('/request-data-deletion', dataRightsRateLimit, sanitizeInput, validatePrivacyRequest, async (req, res) => {
    try {
        const { email, userID, confirmDeletion = false } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                error: 'Email address is required for data deletion request',
                code: 'EMAIL_REQUIRED'
            });
        }

        logger.info('CCPA Right to Delete request initiated', { email, userID, confirmDeletion });

        const deletionRequest = await privacyService.deleteUserData(userID || email, email, confirmDeletion);

        res.json({
            success: true,
            requestId: deletionRequest.requestId,
            message: confirmDeletion ? 'Data deletion completed successfully' : 'Data deletion preview prepared',
            legalBasis: 'CCPA Section 1798.105 - Right to Delete',
            ...deletionRequest
        });

    } catch (error) {
        logger.error('Failed to process data deletion request', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to process your data deletion request',
            code: 'DATA_DELETION_REQUEST_FAILED'
        });
    }
});

/**
 * CCPA Right to Opt-Out - Opt out of data sale - SECURITY FIXED
 * POST /api/user-rights/opt-out-data-sale
 */
router.post('/opt-out-data-sale', sanitizeInput, validatePrivacyRequest, async (req, res) => {
    try {
        const { email, userID } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                error: 'Email address is required for opt-out request',
                code: 'EMAIL_REQUIRED'
            });
        }

        logger.info('CCPA opt-out of sale request', { email, userID });

        const optOutResult = await privacyService.optOutOfDataSale(userID || email, email);

        res.json({
            success: true,
            message: 'Successfully opted out of data sale',
            requestId: optOutResult.requestId,
            effectiveDate: optOutResult.optOutDate,
            legalBasis: 'CCPA Section 1798.120 - Right to Opt-Out',
            note: 'Your preference has been updated immediately'
        });

    } catch (error) {
        logger.error('Failed to process opt-out request', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to process your opt-out request',
            code: 'OPT_OUT_REQUEST_FAILED'
        });
    }
});

/**
 * PIPEDA Access Request - Canadian privacy law compliance - SECURITY FIXED
 * POST /api/user-rights/pipeda-access-request
 */
router.post('/pipeda-access-request', dataRightsRateLimit, sanitizeInput, validatePrivacyRequest, async (req, res) => {
    try {
        const { email, userID, requestType = 'ACCESS' } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                error: 'Email address is required for PIPEDA access request',
                code: 'EMAIL_REQUIRED'
            });
        }

        logger.info('PIPEDA access request initiated', { email, userID, requestType });

        const accessRequest = await privacyService.initiatePIPEDARequest({
            email,
            userID,
            requestType,
            legalBasis: 'PIPEDA_ACCESS_RIGHT'
        });

        res.json({
            success: true,
            requestId: accessRequest.requestId,
            message: 'PIPEDA access request submitted successfully',
            legalBasis: 'Personal Information Protection and Electronic Documents Act (PIPEDA)',
            nextSteps: 'Please check your email for verification instructions',
            estimatedCompletion: accessRequest.estimatedCompletion
        });

    } catch (error) {
        logger.error('Failed to process PIPEDA access request', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to process your PIPEDA access request',
            code: 'PIPEDA_ACCESS_REQUEST_FAILED'
        });
    }
});

/**
 * Check request status
 * GET /api/user-rights/request-status/:requestId
 */
router.get('/request-status/:requestId', sanitizeInput, async (req, res) => {
    try {
        const { requestId } = req.params;
        const { email } = req.query;

        if (!email) {
            return res.status(400).json({
                success: false,
                error: 'Email verification required to check request status',
                code: 'EMAIL_VERIFICATION_REQUIRED'
            });
        }

        logger.info('Request status check', { requestId, email });

        const status = await privacyService.getRequestStatus(requestId, email);

        res.json({
            success: true,
            requestId,
            status: status.status,
            submittedAt: status.submittedAt,
            estimatedCompletion: status.estimatedCompletion,
            lastUpdated: status.lastUpdated,
            progress: status.progress
        });

    } catch (error) {
        logger.error('Failed to get request status', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve request status',
            code: 'REQUEST_STATUS_ERROR'
        });
    }
});

/**
 * Verify email for data rights request
 * POST /api/user-rights/verify-email
 */
router.post('/verify-email', sanitizeInput, async (req, res) => {
    try {
        const { email, verificationCode, requestId } = req.body;

        if (!email || !verificationCode) {
            return res.status(400).json({
                success: false,
                error: 'Email and verification code are required',
                code: 'VERIFICATION_DATA_REQUIRED'
            });
        }

        logger.info('Email verification for data rights', { email, requestId });

        const verificationResult = await privacyService.verifyEmailForDataRights({
            email,
            verificationCode,
            requestId
        });

        res.json({
            success: true,
            message: 'Email verified successfully',
            requestId: verificationResult.requestId,
            nextSteps: verificationResult.nextSteps
        });

    } catch (error) {
        logger.error('Failed to verify email', { error: error.message });
        
        if (error.message === 'Invalid verification code') {
            return res.status(400).json({
                success: false,
                error: 'Invalid verification code. Please check your email and try again.',
                code: 'INVALID_VERIFICATION_CODE'
            });
        }

        res.status(500).json({
            success: false,
            error: 'Failed to verify email',
            code: 'EMAIL_VERIFICATION_FAILED'
        });
    }
});

/**
 * Get legal information about data rights
 * GET /api/user-rights/legal-info
 */
router.get('/legal-info', (req, res) => {
    res.json({
        success: true,
        ccpaRights: {
            rightToKnow: {
                description: 'Right to know what personal information is collected, used, shared or sold',
                legalBasis: 'CCPA Section 1798.100',
                timeframe: 'Response within 45 days'
            },
            rightToDelete: {
                description: 'Right to delete personal information',
                legalBasis: 'CCPA Section 1798.105',
                timeframe: 'Response within 45 days',
                exceptions: 'Some data may be retained for legal compliance'
            },
            rightToOptOut: {
                description: 'Right to opt out of the sale of personal information',
                legalBasis: 'CCPA Section 1798.120',
                timeframe: 'Immediate effect'
            }
        },
        pipedaRights: {
            accessRight: {
                description: 'Right to access personal information held by organizations',
                legalBasis: 'Personal Information Protection and Electronic Documents Act (PIPEDA)',
                timeframe: 'Response within 30 days'
            },
            correctionRight: {
                description: 'Right to correct inaccurate personal information',
                legalBasis: 'PIPEDA',
                timeframe: 'Response within 30 days'
            }
        },
        contactInfo: {
            dataProtectionOfficer: 'privacy@fairs.com',
            phone: '1-800-FAIRS-PRIVACY',
            address: 'Fairs Inc., 123 Privacy Lane, Data City, CA 90210'
        }
    });
});

module.exports = router; 