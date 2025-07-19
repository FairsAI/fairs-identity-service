const express = require('express');
const { body, param, query } = require('express-validator');
const RecognitionController = require('../controllers/recognition-controller');

const router = express.Router();

// Initialize controller (will be injected with dependencies)
let recognitionController;

function initializeRoutes(database, redisClient) {
  recognitionController = new RecognitionController(database, redisClient);
  return router;
}

/**
 * POST /api/identity/recognize
 * Recognize user based on identifier and device data
 */
router.post('/recognize', [
  body('identifier')
    .notEmpty()
    .withMessage('Identifier (email) is required')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email address required'),
  
  body('deviceFingerprint')
    .optional()
    .isObject()
    .withMessage('Device fingerprint must be an object'),
  
  body('merchantId')
    .optional()
    .isString()
    .isLength({ min: 1, max: 255 })
    .withMessage('Merchant ID must be a string'),
  
  body('behavioralData')
    .optional()
    .isObject()
    .withMessage('Behavioral data must be an object')
], (req, res) => {
  recognitionController.recognizeUser(req, res);
});

/**
 * POST /api/identity/verify/send
 * Send verification code
 */
router.post('/verify/send', [
  body('userId')
    .notEmpty()
    .isUUID()
    .withMessage('Valid user ID is required'),
  
  body('channel')
    .notEmpty()
    .isIn(['email', 'sms'])
    .withMessage('Channel must be email or sms'),
  
  body('recipient')
    .notEmpty()
    .withMessage('Recipient is required')
    .custom((value, { req }) => {
      if (req.body.channel === 'email') {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(value)) {
          throw new Error('Valid email address required for email channel');
        }
      } else if (req.body.channel === 'sms') {
        const phoneRegex = /^\+?[1-9]\d{1,14}$/;
        if (!phoneRegex.test(value)) {
          throw new Error('Valid phone number required for SMS channel');
        }
      }
      return true;
    }),
  
  body('reason')
    .optional()
    .isString()
    .isLength({ max: 100 })
    .withMessage('Reason must be a string with max 100 characters')
], (req, res) => {
  recognitionController.sendVerificationCode(req, res);
});

/**
 * POST /api/identity/verify/check
 * Verify submitted code
 */
router.post('/verify/check', [
  body('verificationId')
    .notEmpty()
    .isLength({ min: 32, max: 32 })
    .withMessage('Valid verification ID is required'),
  
  body('code')
    .notEmpty()
    .isNumeric()
    .isLength({ min: 6, max: 6 })
    .withMessage('6-digit numeric code is required'),
  
  body('deviceFingerprint')
    .optional()
    .isObject()
    .withMessage('Device fingerprint must be an object')
], (req, res) => {
  recognitionController.verifyCode(req, res);
});

/**
 * GET /api/identity/confidence/:userId
 * Get confidence score for a user
 */
router.get('/confidence/:userId', [
  param('userId')
    .isUUID()
    .withMessage('Valid user ID is required'),
  
  query('deviceFingerprint')
    .optional()
    .isString()
    .withMessage('Device fingerprint must be a JSON string')
], (req, res) => {
  recognitionController.getConfidenceScore(req, res);
});

/**
 * POST /api/identity/device/link
 * Link a device to a user
 */
router.post('/device/link', [
  body('userId')
    .notEmpty()
    .isUUID()
    .withMessage('Valid user ID is required'),
  
  body('deviceFingerprint')
    .notEmpty()
    .isString()
    .isLength({ min: 32 })
    .withMessage('Valid device fingerprint is required'),
  
  body('trusted')
    .optional()
    .isBoolean()
    .withMessage('Trusted must be a boolean')
], (req, res) => {
  recognitionController.linkDevice(req, res);
});

/**
 * GET /api/identity/device-graph/:userId
 * Get user's device graph
 */
router.get('/device-graph/:userId', [
  param('userId')
    .isUUID()
    .withMessage('Valid user ID is required')
], (req, res) => {
  recognitionController.getDeviceGraph(req, res);
});

/**
 * POST /api/identity/behavioral/update
 * Update user behavioral profile
 */
router.post('/behavioral/update', [
  body('userId')
    .notEmpty()
    .isUUID()
    .withMessage('Valid user ID is required'),
  
  body('behavioralData')
    .notEmpty()
    .isObject()
    .withMessage('Behavioral data object is required')
    .custom((value) => {
      // Validate behavioral data structure
      const allowedKeys = [
        'typingPatterns', 'mousePatterns', 'navigationPatterns', 
        'timePatterns', 'interactionPatterns'
      ];
      
      const providedKeys = Object.keys(value);
      const validKeys = providedKeys.every(key => allowedKeys.includes(key));
      
      if (!validKeys) {
        throw new Error('Invalid behavioral data keys provided');
      }
      
      return true;
    })
], (req, res) => {
  recognitionController.updateBehavioralProfile(req, res);
});

/**
 * GET /api/identity/stats
 * Get recognition statistics
 */
router.get('/stats', [
  query('timeframe')
    .optional()
    .isIn(['last_hour', 'last_24h', 'last_week', 'last_month'])
    .withMessage('Invalid timeframe specified')
], (req, res) => {
  recognitionController.getStats(req, res);
});

// Health check endpoint
router.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    service: 'identity-recognition',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

module.exports = { router, initializeRoutes };