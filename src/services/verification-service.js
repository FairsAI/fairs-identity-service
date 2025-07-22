const crypto = require('crypto');
const axios = require('axios');
const winston = require('winston');
const AWSEmailService = require('./aws-ses-service');
const featureFlags = require('./feature-flag-service');

class VerificationService {
  constructor(redisClient) {
    this.redis = redisClient;
    this.emailService = new AWSEmailService();
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console()
      ]
    });

    // Configuration
    this.codeLength = 6;
    this.codeExpiry = 10 * 60; // 10 minutes in seconds
    this.maxAttempts = 3;
    this.cooldownPeriod = 60; // 1 minute between sends
    this.apiOrchestratorUrl = process.env.API_ORCHESTRATOR_URL || 'http://fairs-api-orchestrator:4000';
  }

  /**
   * Send verification code via preferred channel
   */
  async sendVerificationCode(userId, channel, recipient, metadata = {}) {
    try {
      // Check if verification is enabled
      if (channel === 'email' && !featureFlags.isEmailVerificationEnabled()) {
        throw new Error('Email verification is disabled');
      }
      
      if (channel === 'sms' && !featureFlags.isTwilioEnabled()) {
        throw new Error('SMS verification is disabled');
      }

      // Check cooldown period
      const cooldownKey = `verification_cooldown:${userId}:${channel}`;
      const inCooldown = await this.redis.get(cooldownKey);
      if (inCooldown) {
        throw new Error(`Please wait ${this.cooldownPeriod} seconds before requesting another code`);
      }

      // Generate verification code
      const code = this.generateVerificationCode();
      const verificationId = crypto.randomBytes(16).toString('hex');

      // Store verification data
      const verificationData = {
        userId,
        channel,
        recipient,
        code,
        attempts: 0,
        maxAttempts: this.maxAttempts,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + this.codeExpiry * 1000).toISOString(),
        metadata: {
          ipAddress: metadata.ipAddress,
          userAgent: metadata.userAgent,
          deviceFingerprint: metadata.deviceFingerprint,
          reason: metadata.reason || 'login_verification'
        }
      };

      // Store in Redis with expiry
      const verificationKey = `verification:${verificationId}`;
      await this.redis.setex(
        verificationKey,
        this.codeExpiry,
        JSON.stringify(verificationData)
      );

      // Send verification code
      let sendResult;
      if (channel === 'email') {
        sendResult = await this.sendEmailCode(recipient, code, metadata);
      } else if (channel === 'sms') {
        sendResult = await this.sendSMSCode(recipient, code, metadata);
      } else {
        throw new Error(`Unsupported verification channel: ${channel}`);
      }

      // Set cooldown
      await this.redis.setex(cooldownKey, this.cooldownPeriod, '1');

      // Log verification attempt
      this.logger.info('Verification code sent', {
        verificationId,
        userId,
        channel,
        recipient: this.maskRecipient(channel, recipient),
        reason: metadata.reason
      });

      return {
        success: true,
        verificationId,
        channel,
        recipient: this.maskRecipient(channel, recipient),
        expiresIn: this.codeExpiry,
        cooldownPeriod: this.cooldownPeriod
      };

    } catch (error) {
      this.logger.error('Failed to send verification code', {
        error: error.message,
        userId,
        channel,
        recipient: this.maskRecipient(channel, recipient)
      });
      throw error;
    }
  }

  /**
   * Verify submitted code
   */
  async verifyCode(verificationId, submittedCode, metadata = {}) {
    try {
      const verificationKey = `verification:${verificationId}`;
      const verificationDataStr = await this.redis.get(verificationKey);

      if (!verificationDataStr) {
        return {
          success: false,
          error: 'Verification code expired or invalid',
          errorCode: 'EXPIRED_OR_INVALID'
        };
      }

      const verificationData = JSON.parse(verificationDataStr);

      // Check if too many attempts
      if (verificationData.attempts >= verificationData.maxAttempts) {
        await this.redis.del(verificationKey);
        return {
          success: false,
          error: 'Too many failed attempts',
          errorCode: 'TOO_MANY_ATTEMPTS'
        };
      }

      // Increment attempt counter
      verificationData.attempts += 1;
      await this.redis.setex(
        verificationKey,
        this.codeExpiry,
        JSON.stringify(verificationData)
      );

      // Check code
      if (verificationData.code !== submittedCode) {
        this.logger.warn('Incorrect verification code', {
          verificationId,
          userId: verificationData.userId,
          attempts: verificationData.attempts,
          maxAttempts: verificationData.maxAttempts
        });

        return {
          success: false,
          error: 'Incorrect verification code',
          errorCode: 'INCORRECT_CODE',
          attemptsRemaining: verificationData.maxAttempts - verificationData.attempts
        };
      }

      // Code is correct - clean up
      await this.redis.del(verificationKey);

      // Log successful verification
      this.logger.info('Verification code verified successfully', {
        verificationId,
        userId: verificationData.userId,
        channel: verificationData.channel
      });

      return {
        success: true,
        userId: verificationData.userId,
        channel: verificationData.channel,
        recipient: verificationData.recipient,
        verifiedAt: new Date().toISOString()
      };

    } catch (error) {
      this.logger.error('Failed to verify code', {
        error: error.message,
        verificationId
      });
      throw error;
    }
  }

  /**
   * Send email verification code via AWS SES
   */
  async sendEmailCode(email, code, metadata = {}) {
    try {
      const result = await this.emailService.sendVerificationCode(email, code);
      
      this.logger.info('Email verification sent via AWS SES', {
        email: this.maskRecipient('email', email),
        messageId: result.messageId
      });

      return {
        success: true,
        provider: 'aws-ses',
        messageId: result.messageId
      };
    } catch (error) {
      this.logger.error('AWS SES email send failed', {
        error: error.message,
        email: this.maskRecipient('email', email)
      });
      throw new Error(`Failed to send email verification: ${error.message}`);
    }
  }

  /**
   * Send SMS verification code via API Orchestrator to commerce-platform Twilio
   */
  async sendSMSCode(phone, code, metadata = {}) {
    try {
      const twilioPayload = {
        to: phone,
        message: `Your Fairs verification code is: ${code}. This code expires in 10 minutes.`,
        metadata: {
          type: 'verification',
          userId: metadata.userId,
          reason: metadata.reason || 'login_verification'
        }
      };

      const response = await axios.post(
        `${this.apiOrchestratorUrl}/api/v1/commerce/sms/send`,
        twilioPayload,
        {
          timeout: 10000,
          headers: {
            'Content-Type': 'application/json',
            'X-Service-Auth': process.env.INTERNAL_SERVICE_KEY || 'dev-key'
          }
        }
      );

      this.logger.info('SMS verification sent via Twilio', {
        phone: this.maskRecipient('sms', phone),
        twilioSid: response.data.sid
      });

      return {
        success: true,
        provider: 'twilio',
        messageSid: response.data.sid
      };

    } catch (error) {
      this.logger.error('Twilio SMS send failed', {
        error: error.message,
        phone: this.maskRecipient('sms', phone)
      });

      // Handle specific Twilio errors
      if (error.response?.status === 400) {
        throw new Error('Invalid phone number format');
      } else if (error.response?.status === 429) {
        throw new Error('SMS rate limit exceeded');
      } else {
        throw new Error(`Failed to send SMS verification: ${error.message}`);
      }
    }
  }

  /**
   * Generate random verification code
   */
  generateVerificationCode() {
    const min = Math.pow(10, this.codeLength - 1);
    const max = Math.pow(10, this.codeLength) - 1;
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  /**
   * Mask recipient for logging
   */
  maskRecipient(channel, recipient) {
    if (channel === 'email') {
      const [local, domain] = recipient.split('@');
      return local.substring(0, 2) + '***@' + domain;
    } else if (channel === 'sms') {
      return recipient.substring(0, 4) + '****' + recipient.slice(-2);
    }
    return '***';
  }

  /**
   * Get preferred verification channel based on user data
   */
  getPreferredChannel(user) {
    return featureFlags.getPreferredVerificationChannel(
      !!user.phone,
      !!user.email
    );
  }

  /**
   * Clean up expired verifications (for maintenance)
   */
  async cleanupExpiredVerifications() {
    try {
      const pattern = 'verification:*';
      const keys = await this.redis.keys(pattern);
      
      let cleanedCount = 0;
      for (const key of keys) {
        const ttl = await this.redis.ttl(key);
        if (ttl === -1) { // No expiry set
          await this.redis.del(key);
          cleanedCount++;
        }
      }

      if (cleanedCount > 0) {
        this.logger.info(`Cleaned up ${cleanedCount} expired verifications`);
      }

      return cleanedCount;
    } catch (error) {
      this.logger.error('Failed to cleanup expired verifications', {
        error: error.message
      });
      return 0;
    }
  }

  /**
   * Get verification statistics
   */
  async getVerificationStats(timeframe = 'last_hour') {
    try {
      // This would typically query a metrics database
      // For now, return basic stats from Redis
      const pattern = 'verification:*';
      const keys = await this.redis.keys(pattern);
      
      let activeVerifications = 0;
      let channelStats = { email: 0, sms: 0 };
      
      for (const key of keys) {
        const data = await this.redis.get(key);
        if (data) {
          activeVerifications++;
          const verification = JSON.parse(data);
          channelStats[verification.channel] = (channelStats[verification.channel] || 0) + 1;
        }
      }

      return {
        activeVerifications,
        channelStats,
        timeframe
      };
    } catch (error) {
      this.logger.error('Failed to get verification stats', {
        error: error.message
      });
      return {
        activeVerifications: 0,
        channelStats: { email: 0, sms: 0 },
        timeframe,
        error: error.message
      };
    }
  }
}

module.exports = VerificationService;