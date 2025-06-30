/**
 * User Rights API - CCPA & PIPEDA Data Subject Rights
 * Production Ready Implementation
 */

const express = require('express');
const router = express.Router();
const privacyService = require('../services/privacyService');
// const { createGuestToken } = require('../auth/secure-authentication');
const { sanitizeInput } = require('../middleware/input-sanitization');
const rateLimit = require('express-rate-limit');
const { logger } = require('../utils/logger');

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
 * CCPA Right to Know - Request complete data export
 * POST /api/user-rights/request-data-export
 */
router.post('/request-data-export', dataRightsRateLimit, sanitizeInput, async (req, res) => {
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
 * CCPA Right to Delete - Request data deletion
 * POST /api/user-rights/request-data-deletion
 */
router.post('/request-data-deletion', dataRightsRateLimit, sanitizeInput, async (req, res) => {
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
 * CCPA Right to Opt-Out - Opt out of data sale
 * POST /api/user-rights/opt-out-data-sale
 */
router.post('/opt-out-data-sale', sanitizeInput, async (req, res) => {
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
 * PIPEDA Access Request - Canadian privacy law compliance
 * POST /api/user-rights/pipeda-access-request
 */
router.post('/pipeda-access-request', dataRightsRateLimit, sanitizeInput, async (req, res) => {
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