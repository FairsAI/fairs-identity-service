const featureFlags = require('../../../src/services/feature-flag-service');

describe('FeatureFlagService', () => {
  let featureFlags;

  beforeEach(() => {
    // Reset environment variables before each test
    delete require.cache[require.resolve('../../../src/services/feature-flag-service')];
    featureFlags = require('../../../src/services/feature-flag-service');
  });

  describe('Flag Parsing', () => {
    test('should parse boolean flags correctly', () => {
      process.env.ENABLE_AUTO_RECOGNITION = 'true';
      featureFlags._reinitialize();
      expect(featureFlags.isAutoRecognitionEnabled()).toBe(true);

      process.env.ENABLE_AUTO_RECOGNITION = 'false';
      featureFlags._reinitialize();
      expect(featureFlags.isAutoRecognitionEnabled()).toBe(false);
    });

    test('should use default values when env vars are missing', () => {
      delete process.env.ENABLE_AUTO_RECOGNITION;
      featureFlags._reinitialize();
      expect(featureFlags.isAutoRecognitionEnabled()).toBe(false); // Default
    });

    test('should parse threshold values correctly', () => {
      process.env.HIGH_CONFIDENCE_THRESHOLD = '85';
      process.env.MEDIUM_CONFIDENCE_THRESHOLD = '55';
      featureFlags._reinitialize();
      
      expect(featureFlags.getHighConfidenceThreshold()).toBe(85);
      expect(featureFlags.getMediumConfidenceThreshold()).toBe(55);
    });
  });

  describe('Authentication Method Determination', () => {
    test('should return password_required when auto-recognition is disabled', () => {
      process.env.ENABLE_AUTO_RECOGNITION = 'false';
      featureFlags._reinitialize();
      
      expect(featureFlags.getAuthMethod(95)).toBe('password_required');
      expect(featureFlags.getAuthMethod(50)).toBe('password_required');
    });

    test('should return correct auth method based on confidence when enabled', () => {
      process.env.ENABLE_AUTO_RECOGNITION = 'true';
      process.env.HIGH_CONFIDENCE_THRESHOLD = '80';
      process.env.MEDIUM_CONFIDENCE_THRESHOLD = '50';
      featureFlags._reinitialize();

      expect(featureFlags.getAuthMethod(85)).toBe('auto_login');
      expect(featureFlags.getAuthMethod(65)).toBe('verification_required');
      expect(featureFlags.getAuthMethod(30)).toBe('full_verification_required');
    });
  });

  describe('Verification Channel Selection', () => {
    test('should prefer SMS when Twilio enabled and phone available', () => {
      process.env.TWILIO_ENABLED = 'true';
      featureFlags._reinitialize();

      expect(featureFlags.getPreferredVerificationChannel(true, true)).toBe('sms');
    });

    test('should fallback to email when no phone', () => {
      process.env.TWILIO_ENABLED = 'true';
      process.env.EMAIL_VERIFICATION_ENABLED = 'true';
      featureFlags._reinitialize();

      expect(featureFlags.getPreferredVerificationChannel(false, true)).toBe('email');
    });

    test('should return null when no channels available', () => {
      process.env.TWILIO_ENABLED = 'false';
      process.env.EMAIL_VERIFICATION_ENABLED = 'false';
      featureFlags._reinitialize();

      expect(featureFlags.getPreferredVerificationChannel(false, false)).toBe(null);
    });
  });

  describe('Configuration', () => {
    test('should return current configuration', () => {
      const config = featureFlags.getConfiguration();
      
      expect(config).toHaveProperty('flags');
      expect(config).toHaveProperty('thresholds');
      expect(config).toHaveProperty('environment');
      expect(config.environment).toBe('test');
    });
  });

  describe('Development Overrides', () => {
    test('should allow flag overrides in non-production', () => {
      process.env.NODE_ENV = 'development';
      
      expect(() => {
        featureFlags.setFlag('autoRecognition', true);
      }).not.toThrow();
      
      expect(featureFlags.isAutoRecognitionEnabled()).toBe(true);
    });

    test('should prevent flag overrides in production', () => {
      process.env.NODE_ENV = 'production';
      
      expect(() => {
        featureFlags.setFlag('autoRecognition', true);
      }).toThrow('Cannot override feature flags in production');
    });
  });
});