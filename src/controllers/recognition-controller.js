const { validationResult } = require('express-validator');
const UserRecognitionService = require('../services/user-recognition-service');
const featureFlags = require('../services/feature-flag-service');
const winston = require('winston');

class RecognitionController {
  constructor(database, redisClient) {
    this.recognitionService = new UserRecognitionService(database, redisClient);
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console()
      ]
    });
  }

  /**
   * POST /api/identity/recognize
   * Recognize user based on identifier and device data
   */
  async recognizeUser(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }

      const {
        identifier,
        deviceFingerprint,
        merchantId,
        behavioralData
      } = req.body;

      const context = {
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        behavioralData,
        timestamp: new Date().toISOString()
      };

      const result = await this.recognitionService.recognizeUser(
        identifier,
        deviceFingerprint,
        merchantId,
        context
      );

      // Log recognition attempt
      this.logger.info('User recognition attempt', {
        identifier: this.maskEmail(identifier),
        merchantId,
        recognized: result.recognized,
        method: result.method,
        confidence: result.confidence,
        ipAddress: req.ip
      });

      res.status(200).json({
        success: true,
        data: result
      });

    } catch (error) {
      this.logger.error('Recognition endpoint error', {
        error: error.message,
        stack: error.stack
      });

      res.status(500).json({
        success: false,
        error: 'Recognition service error',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
      });
    }
  }

  /**
   * POST /api/identity/verify/send
   * Send verification code
   */
  async sendVerificationCode(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }

      const {
        userId,
        channel,
        recipient,
        reason
      } = req.body;

      const metadata = {
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        reason: reason || 'manual_verification'
      };

      const result = await this.recognitionService.verificationService.sendVerificationCode(
        userId,
        channel,
        recipient,
        metadata
      );

      this.logger.info('Verification code sent', {
        userId,
        channel,
        recipient: this.maskRecipient(channel, recipient),
        verificationId: result.verificationId
      });

      res.status(200).json({
        success: true,
        data: result
      });

    } catch (error) {
      this.logger.error('Send verification error', {
        error: error.message,
        userId: req.body.userId,
        channel: req.body.channel
      });

      res.status(400).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * POST /api/identity/verify/check
   * Verify submitted code
   */
  async verifyCode(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }

      const {
        verificationId,
        code,
        deviceFingerprint
      } = req.body;

      const context = {
        ipAddress: req.ip,
        userAgent: req.get('user-agent')
      };

      const result = await this.recognitionService.verifyCode(
        verificationId,
        code,
        deviceFingerprint,
        context
      );

      if (result.success) {
        this.logger.info('Verification code verified successfully', {
          verificationId,
          userId: result.userId,
          channel: result.channel
        });

        res.status(200).json({
          success: true,
          data: result
        });
      } else {
        this.logger.warn('Verification code verification failed', {
          verificationId,
          error: result.error,
          errorCode: result.errorCode
        });

        res.status(400).json({
          success: false,
          error: result.error,
          errorCode: result.errorCode,
          attemptsRemaining: result.attemptsRemaining
        });
      }

    } catch (error) {
      this.logger.error('Verify code error', {
        error: error.message,
        verificationId: req.body.verificationId
      });

      res.status(500).json({
        success: false,
        error: 'Verification service error'
      });
    }
  }

  /**
   * GET /api/identity/confidence/:userId
   * Get confidence score for a user
   */
  async getConfidenceScore(req, res) {
    try {
      const { userId } = req.params;
      const { deviceFingerprint } = req.query;

      if (!userId) {
        return res.status(400).json({
          success: false,
          error: 'User ID is required'
        });
      }

      // Get user from database
      const user = await this.recognitionService.findUserByIdentifier(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      const context = {
        ipAddress: req.ip,
        userAgent: req.get('user-agent')
      };

      const confidenceResult = await this.recognitionService.confidenceService.calculateConfidenceScore(
        user,
        deviceFingerprint ? JSON.parse(deviceFingerprint) : null,
        context
      );

      res.status(200).json({
        success: true,
        data: {
          userId,
          confidence: confidenceResult.confidence,
          breakdown: confidenceResult.breakdown,
          factors: confidenceResult.factors,
          authMethod: this.recognitionService.confidenceService.getAuthenticationMethod(confidenceResult.confidence)
        }
      });

    } catch (error) {
      this.logger.error('Get confidence score error', {
        error: error.message,
        userId: req.params.userId
      });

      res.status(500).json({
        success: false,
        error: 'Confidence scoring service error'
      });
    }
  }

  /**
   * POST /api/identity/device/link
   * Link a device to a user
   */
  async linkDevice(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }

      const {
        userId,
        deviceFingerprint,
        trusted = false
      } = req.body;

      const context = {
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        trusted
      };

      await this.recognitionService.updateDeviceGraph(
        userId,
        deviceFingerprint,
        context
      );

      this.logger.info('Device linked to user', {
        userId,
        deviceFingerprint: deviceFingerprint.substring(0, 10) + '...',
        trusted
      });

      res.status(200).json({
        success: true,
        message: 'Device linked successfully'
      });

    } catch (error) {
      this.logger.error('Link device error', {
        error: error.message,
        userId: req.body.userId
      });

      res.status(500).json({
        success: false,
        error: 'Device linking service error'
      });
    }
  }

  /**
   * GET /api/identity/device-graph/:userId
   * Get user's device graph
   */
  async getDeviceGraph(req, res) {
    try {
      const { userId } = req.params;

      if (!userId) {
        return res.status(400).json({
          success: false,
          error: 'User ID is required'
        });
      }

      const deviceGraph = await this.recognitionService.getDeviceGraph(userId);

      res.status(200).json({
        success: true,
        data: deviceGraph
      });

    } catch (error) {
      this.logger.error('Get device graph error', {
        error: error.message,
        userId: req.params.userId
      });

      res.status(500).json({
        success: false,
        error: 'Device graph service error'
      });
    }
  }

  /**
   * POST /api/identity/behavioral/update
   * Update user behavioral profile
   */
  async updateBehavioralProfile(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }

      const {
        userId,
        behavioralData
      } = req.body;

      await this.recognitionService.updateBehavioralProfile(userId, behavioralData);

      this.logger.info('Behavioral profile updated', {
        userId,
        dataKeys: Object.keys(behavioralData)
      });

      res.status(200).json({
        success: true,
        message: 'Behavioral profile updated successfully'
      });

    } catch (error) {
      this.logger.error('Update behavioral profile error', {
        error: error.message,
        userId: req.body.userId
      });

      res.status(500).json({
        success: false,
        error: 'Behavioral profile service error'
      });
    }
  }

  /**
   * GET /api/identity/stats
   * Get recognition statistics
   */
  async getStats(req, res) {
    try {
      const { timeframe } = req.query;

      const [recognitionStats, verificationStats] = await Promise.all([
        this.recognitionService.getRecognitionStats(timeframe),
        this.recognitionService.verificationService.getVerificationStats(timeframe)
      ]);

      res.status(200).json({
        success: true,
        data: {
          recognition: recognitionStats,
          verification: verificationStats,
          featureFlags: featureFlags.getConfiguration()
        }
      });

    } catch (error) {
      this.logger.error('Get stats error', {
        error: error.message
      });

      res.status(500).json({
        success: false,
        error: 'Statistics service error'
      });
    }
  }

  /**
   * Utility methods
   */
  maskEmail(email) {
    if (!email || !email.includes('@')) return email;
    const [local, domain] = email.split('@');
    return local.substring(0, 2) + '***@' + domain;
  }

  maskRecipient(channel, recipient) {
    if (channel === 'email') {
      return this.maskEmail(recipient);
    } else if (channel === 'sms') {
      return recipient.substring(0, 4) + '****' + recipient.slice(-2);
    }
    return '***';
  }
}

module.exports = RecognitionController;