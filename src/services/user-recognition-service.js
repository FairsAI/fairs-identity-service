const winston = require('winston');
const DeviceFingerprintService = require('./device-fingerprint-service');
const ConfidenceScoringService = require('./confidence-scoring-service');
const VerificationService = require('./verification-service');
const featureFlags = require('./feature-flag-service');

class UserRecognitionService {
  constructor(database, redisClient) {
    this.db = database;
    this.redis = redisClient;
    this.deviceFingerprintService = new DeviceFingerprintService();
    this.confidenceService = new ConfidenceScoringService();
    this.verificationService = new VerificationService(redisClient);
    
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console()
      ]
    });
  }

  /**
   * Main recognition method - determine if user can be recognized
   * @param {string} identifier - Email or user identifier
   * @param {Object} deviceData - Device fingerprint data
   * @param {string} merchantId - Current merchant
   * @param {Object} context - Additional context (IP, behavioral data, etc.)
   * @returns {Object} Recognition result with confidence and next steps
   */
  async recognizeUser(identifier, deviceData, merchantId, context = {}) {
    try {
      this.logger.info('Starting user recognition', {
        identifier: this.maskEmail(identifier),
        merchantId,
        deviceFingerprint: deviceData?.userAgent?.substring(0, 20) + '...'
      });

      // Check if auto-recognition is enabled
      if (!featureFlags.isAutoRecognitionEnabled()) {
        return await this.handleRecognitionDisabled(identifier, merchantId);
      }

      // Generate device fingerprint
      const deviceFingerprint = deviceData ? 
        this.deviceFingerprintService.generateFingerprint(deviceData) : null;

      // Find user by identifier
      const user = await this.findUserByIdentifier(identifier);
      if (!user) {
        return {
          recognized: false,
          method: 'registration_required',
          confidence: 0,
          reason: 'user_not_found',
          identifier
        };
      }

      // Calculate confidence score
      const confidenceResult = await this.confidenceService.calculateConfidenceScore(
        user,
        deviceFingerprint,
        {
          ...context,
          merchantId,
          ipAddress: context.ipAddress,
          userAgent: deviceData?.userAgent
        }
      );

      const confidence = confidenceResult.confidence;
      const authMethod = this.confidenceService.getAuthenticationMethod(confidence);

      // Build recognition response based on confidence
      const response = {
        recognized: true,
        userId: user.id,
        confidence,
        method: authMethod,
        confidenceBreakdown: confidenceResult.breakdown,
        factors: confidenceResult.factors,
        deviceFingerprint: deviceFingerprint?.hash,
        merchantId
      };

      // Handle based on auth method
      switch (authMethod) {
        case 'auto_login':
          return await this.handleAutoLogin(user, response, context);
          
        case 'verification_required':
          return await this.handleVerificationRequired(user, response, context);
          
        case 'full_verification_required':
          return await this.handleFullVerification(user, response, context);
          
        case 'password_required':
        default:
          return await this.handlePasswordRequired(user, response, context);
      }

    } catch (error) {
      this.logger.error('Recognition service error', {
        error: error.message,
        identifier: this.maskEmail(identifier),
        merchantId
      });

      return {
        recognized: false,
        method: 'error',
        confidence: 0,
        reason: 'service_error',
        error: error.message
      };
    }
  }

  /**
   * Handle case when auto-recognition is disabled
   */
  async handleRecognitionDisabled(identifier, merchantId) {
    // Default to email lookup verification
    const user = await this.findUserByIdentifier(identifier);
    
    if (!user) {
      return {
        recognized: false,
        method: 'registration_required',
        confidence: 0,
        reason: 'auto_recognition_disabled',
        identifier
      };
    }

    return {
      recognized: true,
      userId: user.id,
      method: 'email_verification_required',
      confidence: 0,
      reason: 'auto_recognition_disabled',
      verificationChannel: 'email',
      recipient: this.maskEmail(user.email)
    };
  }

  /**
   * Handle high confidence auto-login
   */
  async handleAutoLogin(user, response, context) {
    // Log device for future recognition
    if (response.deviceFingerprint) {
      await this.updateDeviceGraph(user.id, response.deviceFingerprint, context);
    }

    // Update behavioral profile in background
    if (context.behavioralData && featureFlags.isBehavioralTrackingEnabled()) {
      process.nextTick(() => {
        this.updateBehavioralProfile(user.id, context.behavioralData);
      });
    }

    return {
      ...response,
      message: 'High confidence recognition - auto login approved',
      deviceGraph: await this.getDeviceGraph(user.id)
    };
  }

  /**
   * Handle medium confidence verification requirement
   */
  async handleVerificationRequired(user, response, context) {
    const preferredChannel = this.verificationService.getPreferredChannel(user);
    
    if (!preferredChannel) {
      return {
        ...response,
        method: 'password_required',
        reason: 'no_verification_channel'
      };
    }

    try {
      // Send verification code
      const recipient = preferredChannel === 'sms' ? user.phone : user.email;
      const verificationResult = await this.verificationService.sendVerificationCode(
        user.id,
        preferredChannel,
        recipient,
        {
          ...context,
          reason: 'medium_confidence_verification'
        }
      );

      return {
        ...response,
        method: 'verification_sent',
        verificationId: verificationResult.verificationId,
        verificationChannel: preferredChannel,
        recipient: verificationResult.recipient,
        expiresIn: verificationResult.expiresIn
      };

    } catch (error) {
      this.logger.error('Failed to send verification for medium confidence', {
        error: error.message,
        userId: user.id
      });

      return {
        ...response,
        method: 'password_required',
        reason: 'verification_send_failed'
      };
    }
  }

  /**
   * Handle low confidence full verification
   */
  async handleFullVerification(user, response, context) {
    const preferredChannel = this.verificationService.getPreferredChannel(user);
    
    if (!preferredChannel) {
      return {
        ...response,
        method: 'password_required',
        reason: 'no_verification_channel'
      };
    }

    try {
      // Send verification code for full verification
      const recipient = preferredChannel === 'sms' ? user.phone : user.email;
      const verificationResult = await this.verificationService.sendVerificationCode(
        user.id,
        preferredChannel,
        recipient,
        {
          ...context,
          reason: 'low_confidence_verification'
        }
      );

      return {
        ...response,
        method: 'full_verification_required',
        verificationId: verificationResult.verificationId,
        verificationChannel: preferredChannel,
        recipient: verificationResult.recipient,
        expiresIn: verificationResult.expiresIn,
        message: 'Low confidence - full verification required'
      };

    } catch (error) {
      this.logger.error('Failed to send verification for low confidence', {
        error: error.message,
        userId: user.id
      });

      return {
        ...response,
        method: 'password_required',
        reason: 'verification_send_failed'
      };
    }
  }

  /**
   * Handle password requirement
   */
  async handlePasswordRequired(user, response, context) {
    return {
      ...response,
      method: 'password_required',
      message: 'Confidence too low - password authentication required'
    };
  }

  /**
   * Verify a submitted verification code
   */
  async verifyCode(verificationId, code, deviceData, context = {}) {
    try {
      const result = await this.verificationService.verifyCode(verificationId, code, context);
      
      if (result.success) {
        // Update user trust after successful verification
        this.confidenceService.updateUserTrustScore(result.userId, true, 'verification');
        
        // Update device graph
        if (deviceData) {
          const deviceFingerprint = this.deviceFingerprintService.generateFingerprint(deviceData);
          await this.updateDeviceGraph(result.userId, deviceFingerprint.hash, context);
        }
      }

      return result;
    } catch (error) {
      this.logger.error('Code verification error', {
        error: error.message,
        verificationId
      });
      throw error;
    }
  }

  /**
   * Database operations
   */
  async findUserByIdentifier(identifier) {
    try {
      // Try email first
      const userQuery = 'SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL LIMIT 1';
      const result = await this.db.query(userQuery, [identifier]);
      
      if (result.rows.length > 0) {
        return result.rows[0];
      }

      // Could also try phone number or other identifiers
      return null;
    } catch (error) {
      this.logger.error('Database error finding user', {
        error: error.message,
        identifier: this.maskEmail(identifier)
      });
      return null;
    }
  }

  async updateDeviceGraph(userId, deviceFingerprint, context) {
    try {
      const deviceData = {
        userId,
        fingerprint: deviceFingerprint,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        lastSeen: new Date(),
        trustScore: 70 // Default trust score
      };

      // Check if device already exists
      const existingQuery = 'SELECT * FROM user_devices WHERE user_id = $1 AND fingerprint = $2';
      const existing = await this.db.query(existingQuery, [userId, deviceFingerprint]);

      if (existing.rows.length > 0) {
        // Update existing device
        const updateQuery = `
          UPDATE user_devices 
          SET last_seen = $3, ip_address = $4, user_agent = $5, trust_score = trust_score + 1
          WHERE user_id = $1 AND fingerprint = $2
        `;
        await this.db.query(updateQuery, [
          userId, deviceFingerprint, deviceData.lastSeen, 
          deviceData.ipAddress, deviceData.userAgent
        ]);
      } else {
        // Insert new device
        const insertQuery = `
          INSERT INTO user_devices (user_id, fingerprint, ip_address, user_agent, last_seen, trust_score)
          VALUES ($1, $2, $3, $4, $5, $6)
        `;
        await this.db.query(insertQuery, [
          userId, deviceFingerprint, deviceData.ipAddress,
          deviceData.userAgent, deviceData.lastSeen, deviceData.trustScore
        ]);
      }
    } catch (error) {
      this.logger.error('Error updating device graph', {
        error: error.message,
        userId,
        deviceFingerprint
      });
    }
  }

  async getDeviceGraph(userId) {
    try {
      const query = 'SELECT * FROM user_devices WHERE user_id = $1 ORDER BY last_seen DESC';
      const result = await this.db.query(query, [userId]);
      
      return {
        devices: result.rows.map(device => ({
          fingerprint: device.fingerprint,
          lastSeen: device.last_seen,
          trustScore: device.trust_score,
          deviceType: 'unknown' // Would be determined from user agent
        })),
        deviceCount: result.rows.length
      };
    } catch (error) {
      this.logger.error('Error getting device graph', {
        error: error.message,
        userId
      });
      return { devices: [], deviceCount: 0 };
    }
  }

  async updateBehavioralProfile(userId, behavioralData) {
    try {
      // This would update behavioral patterns in the database
      // For now, just log the update
      this.logger.info('Behavioral profile update', {
        userId,
        dataKeys: Object.keys(behavioralData)
      });
    } catch (error) {
      this.logger.error('Error updating behavioral profile', {
        error: error.message,
        userId
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

  /**
   * Get recognition statistics
   */
  async getRecognitionStats(timeframe = 'last_24h') {
    try {
      // This would query analytics database
      return {
        totalAttempts: 0,
        autoLogins: 0,
        verificationsRequired: 0,
        passwordFallbacks: 0,
        averageConfidence: 0,
        timeframe
      };
    } catch (error) {
      this.logger.error('Error getting recognition stats', {
        error: error.message
      });
      return null;
    }
  }
}

module.exports = UserRecognitionService;