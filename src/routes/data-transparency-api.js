/**
 * Data Transparency API - Processing Transparency & Data Mapping
 * CCPA & PIPEDA Compliance Implementation
 */

const express = require('express');
const router = express.Router();
const dataTransparencyService = require('../services/dataTransparencyService');
const { logger } = require('../utils/logger');

/**
 * Get comprehensive data processing transparency report
 * GET /api/data-transparency/processing-report/:userId
 */
router.get('/processing-report/:userId', async (req, res) => {
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
 * Get data inventory for specific user
 * GET /api/data-transparency/data-inventory/:userId
 */
router.get('/data-inventory/:userId', async (req, res) => {
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