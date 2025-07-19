const winston = require('winston');

class FeatureFlagService {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console()
      ]
    });

    // Simple ON/OFF flags from environment variables
    this.flags = {
      autoRecognition: this.parseFlag(process.env.ENABLE_AUTO_RECOGNITION, false),
      crossMerchantRecognition: this.parseFlag(process.env.ENABLE_CROSS_MERCHANT_RECOGNITION, false),
      twilioVerification: this.parseFlag(process.env.TWILIO_ENABLED, true),
      emailVerification: this.parseFlag(process.env.EMAIL_VERIFICATION_ENABLED, true),
      behavioralTracking: this.parseFlag(process.env.ENABLE_BEHAVIORAL_TRACKING, true),
      deviceFingerprinting: this.parseFlag(process.env.ENABLE_DEVICE_FINGERPRINTING, true)
    };

    // Thresholds for confidence scoring
    this.thresholds = {
      highConfidence: parseInt(process.env.HIGH_CONFIDENCE_THRESHOLD || '80'),
      mediumConfidence: parseInt(process.env.MEDIUM_CONFIDENCE_THRESHOLD || '50'),
      deviceTrust: parseInt(process.env.DEVICE_TRUST_THRESHOLD || '70')
    };

    this.logger.info('Feature flags initialized', {
      flags: this.flags,
      thresholds: this.thresholds
    });
  }

  parseFlag(value, defaultValue) {
    if (value === undefined || value === null) {
      return defaultValue;
    }
    return value.toLowerCase() === 'true';
  }

  isEnabled(feature) {
    const enabled = this.flags[feature] || false;
    this.logger.debug(`Feature flag check: ${feature} = ${enabled}`);
    return enabled;
  }

  getThreshold(threshold) {
    return this.thresholds[threshold] || 0;
  }

  // Check if auto-recognition is enabled
  isAutoRecognitionEnabled() {
    return this.isEnabled('autoRecognition');
  }

  // Check if cross-merchant recognition is enabled
  isCrossMerchantEnabled() {
    return this.isEnabled('crossMerchantRecognition');
  }

  // Check if Twilio verification is enabled
  isTwilioEnabled() {
    return this.isEnabled('twilioVerification');
  }

  // Check if email verification is enabled
  isEmailVerificationEnabled() {
    return this.isEnabled('emailVerification');
  }

  // Check if behavioral tracking is enabled
  isBehavioralTrackingEnabled() {
    return this.isEnabled('behavioralTracking');
  }

  // Check if device fingerprinting is enabled
  isDeviceFingerprintingEnabled() {
    return this.isEnabled('deviceFingerprinting');
  }

  // Get confidence thresholds
  getHighConfidenceThreshold() {
    return this.getThreshold('highConfidence');
  }

  getMediumConfidenceThreshold() {
    return this.getThreshold('mediumConfidence');
  }

  getDeviceTrustThreshold() {
    return this.getThreshold('deviceTrust');
  }

  // Determine authentication method based on confidence score
  getAuthMethod(confidenceScore) {
    if (!this.isAutoRecognitionEnabled()) {
      return 'password_required';
    }

    if (confidenceScore >= this.getHighConfidenceThreshold()) {
      return 'auto_login';
    } else if (confidenceScore >= this.getMediumConfidenceThreshold()) {
      return 'verification_required';
    } else {
      return 'full_verification_required';
    }
  }

  // Override flags for testing (should only be used in development)
  setFlag(feature, value) {
    if (process.env.NODE_ENV !== 'production') {
      this.flags[feature] = value;
      this.logger.warn(`Feature flag overridden: ${feature} = ${value}`);
    } else {
      this.logger.error('Attempted to override feature flag in production');
      throw new Error('Cannot override feature flags in production');
    }
  }

  // Get current configuration
  getConfiguration() {
    return {
      flags: { ...this.flags },
      thresholds: { ...this.thresholds },
      environment: process.env.NODE_ENV
    };
  }

  // Check if we should use email or SMS for verification
  getPreferredVerificationChannel(hasPhone, hasEmail) {
    if (this.isTwilioEnabled() && hasPhone) {
      return 'sms';
    } else if (this.isEmailVerificationEnabled() && hasEmail) {
      return 'email';
    } else if (hasEmail) {
      // Fallback to email even if disabled
      return 'email';
    }
    return null;
  }

  // Determine if we should collect behavioral data
  shouldCollectBehavioralData() {
    return this.isAutoRecognitionEnabled() && this.isBehavioralTrackingEnabled();
  }

  // Determine if we should verify device
  shouldVerifyDevice() {
    return this.isAutoRecognitionEnabled() && this.isDeviceFingerprintingEnabled();
  }
}

// Export singleton instance
const instance = new FeatureFlagService();

// For testing - allow reinitialization
if (process.env.NODE_ENV === 'test') {
  instance._reinitialize = () => {
    const newInstance = new FeatureFlagService();
    Object.assign(instance, newInstance);
    return instance;
  };
}

module.exports = instance;