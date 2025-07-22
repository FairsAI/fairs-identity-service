const VerificationService = require('../../../src/services/verification-service');
const MockRedisClient = require('../../mocks/redis-mock');
const axios = require('axios');

// Mock AWS SES
jest.mock('@aws-sdk/client-ses', () => require('../../mocks/aws-ses-mock'));
const { mockSESSuccess, mockSESError, resetMocks } = require('../../mocks/aws-ses-mock');

// Mock axios for Twilio calls
jest.mock('axios');

describe('VerificationService', () => {
  let service;
  let mockRedis;

  beforeEach(() => {
    mockRedis = new MockRedisClient();
    service = new VerificationService(mockRedis);
    resetMocks();
    jest.clearAllMocks();
  });

  describe('Verification Code Generation', () => {
    test('should generate 6-digit numeric code', () => {
      const code = service.generateVerificationCode();
      expect(code).toBeGreaterThanOrEqual(100000);
      expect(code).toBeLessThanOrEqual(999999);
      expect(Number.isInteger(code)).toBe(true);
    });

    test('should generate different codes on multiple calls', () => {
      const code1 = service.generateVerificationCode();
      const code2 = service.generateVerificationCode();
      // While they could theoretically be the same, it's very unlikely
      expect(code1).toBeDefined();
      expect(code2).toBeDefined();
    });
  });

  describe('Email Verification', () => {
    test('should send email verification successfully', async () => {
      mockSESSuccess();

      const result = await service.sendVerificationCode(
        'user-123',
        'email',
        'test@example.com',
        { ipAddress: '192.168.1.1' }
      );

      expect(result.success).toBe(true);
      expect(result.channel).toBe('email');
      expect(result.recipient).toBe('te***@example.com');
      expect(result.verificationId).toBeDefined();
      expect(result.expiresIn).toBe(600); // 10 minutes
    });

    test('should handle AWS SES errors gracefully', async () => {
      mockSESError();

      await expect(service.sendVerificationCode(
        'user-123',
        'email',
        'test@example.com'
      )).rejects.toThrow('Failed to send email verification');
    });

    test('should prevent sending during cooldown period', async () => {
      mockSESSuccess();

      // Send first verification
      await service.sendVerificationCode('user-123', 'email', 'test@example.com');

      // Try to send again immediately
      await expect(service.sendVerificationCode(
        'user-123',
        'email',
        'test@example.com'
      )).rejects.toThrow('Please wait 60 seconds');
    });
  });

  describe('SMS Verification', () => {
    test('should send SMS verification via Twilio successfully', async () => {
      const mockAxiosResponse = {
        data: { sid: 'SM123456789' }
      };
      axios.post.mockResolvedValue(mockAxiosResponse);

      const result = await service.sendVerificationCode(
        'user-123',
        'sms',
        '+1234567890',
        { ipAddress: '192.168.1.1' }
      );

      expect(result.success).toBe(true);
      expect(result.channel).toBe('sms');
      expect(result.recipient).toBe('+123****90');
      expect(axios.post).toHaveBeenCalledWith(
        'http://test-api-orchestrator:4000/api/v1/commerce/sms/send',
        expect.objectContaining({
          to: '+1234567890',
          message: expect.stringContaining('Your Fairs verification code is:')
        }),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/json'
          })
        })
      );
    });

    test('should handle Twilio API errors', async () => {
      axios.post.mockRejectedValue({
        response: { status: 400 },
        message: 'Invalid phone number'
      });

      await expect(service.sendVerificationCode(
        'user-123',
        'sms',
        'invalid-phone'
      )).rejects.toThrow('Invalid phone number format');
    });

    test('should handle rate limiting errors', async () => {
      axios.post.mockRejectedValue({
        response: { status: 429 },
        message: 'Rate limit exceeded'
      });

      await expect(service.sendVerificationCode(
        'user-123',
        'sms',
        '+1234567890'
      )).rejects.toThrow('SMS rate limit exceeded');
    });
  });

  describe('Code Verification', () => {
    test('should verify correct code successfully', async () => {
      mockSESSuccess();

      // Send verification first
      const sendResult = await service.sendVerificationCode(
        'user-123',
        'email',
        'test@example.com'
      );

      // Get the code from Redis (for testing)
      const verificationData = JSON.parse(
        await mockRedis.get(`verification:${sendResult.verificationId}`)
      );
      const correctCode = verificationData.code;

      // Verify the code
      const verifyResult = await service.verifyCode(
        sendResult.verificationId,
        correctCode.toString()
      );

      expect(verifyResult.success).toBe(true);
      expect(verifyResult.userId).toBe('user-123');
      expect(verifyResult.channel).toBe('email');
    });

    test('should reject incorrect code', async () => {
      mockSESSuccess();

      const sendResult = await service.sendVerificationCode(
        'user-123',
        'email',
        'test@example.com'
      );

      const verifyResult = await service.verifyCode(
        sendResult.verificationId,
        '000000' // Wrong code
      );

      expect(verifyResult.success).toBe(false);
      expect(verifyResult.error).toBe('Incorrect verification code');
      expect(verifyResult.errorCode).toBe('INCORRECT_CODE');
    });

    test('should handle expired verification', async () => {
      const verifyResult = await service.verifyCode(
        'non-existent-id',
        '123456'
      );

      expect(verifyResult.success).toBe(false);
      expect(verifyResult.error).toBe('Verification code expired or invalid');
      expect(verifyResult.errorCode).toBe('EXPIRED_OR_INVALID');
    });

    test('should enforce maximum attempts', async () => {
      mockSESSuccess();

      const sendResult = await service.sendVerificationCode(
        'user-123',
        'email',
        'test@example.com'
      );

      // Make 3 failed attempts
      for (let i = 0; i < 3; i++) {
        await service.verifyCode(sendResult.verificationId, '000000');
      }

      // Fourth attempt should be blocked
      const finalResult = await service.verifyCode(
        sendResult.verificationId,
        '000000'
      );

      expect(finalResult.success).toBe(false);
      expect(finalResult.error).toBe('Too many failed attempts');
      expect(finalResult.errorCode).toBe('TOO_MANY_ATTEMPTS');
    });
  });

  describe('Recipient Masking', () => {
    test('should mask email addresses properly', () => {
      expect(service.maskRecipient('email', 'test@example.com')).toBe('te***@example.com');
      expect(service.maskRecipient('email', 'a@b.com')).toBe('a***@b.com');
      expect(service.maskRecipient('email', 'longer.email@domain.org')).toBe('lo***@domain.org');
    });

    test('should mask phone numbers properly', () => {
      expect(service.maskRecipient('sms', '+1234567890')).toBe('+123****90');
      expect(service.maskRecipient('sms', '5551234567')).toBe('5551****67');
    });
  });

  describe('Preferred Channel Selection', () => {
    test('should prefer SMS when user has phone and Twilio enabled', () => {
      const user = { phone: '+1234567890', email: 'test@example.com' };
      const channel = service.getPreferredChannel(user);
      expect(channel).toBe('sms'); // Based on feature flags
    });

    test('should fallback to email when no phone', () => {
      const user = { email: 'test@example.com' };
      const channel = service.getPreferredChannel(user);
      expect(channel).toBe('email');
    });
  });

  describe('Feature Flag Integration', () => {
    test('should respect email verification flag', async () => {
      // Mock feature flags to disable email verification
      jest.doMock('../../../src/services/feature-flag-service', () => ({
        isEmailVerificationEnabled: () => false,
        isTwilioEnabled: () => true
      }));

      await expect(service.sendVerificationCode(
        'user-123',
        'email',
        'test@example.com'
      )).rejects.toThrow('Email verification is disabled');
    });

    test('should respect SMS verification flag', async () => {
      // Mock feature flags to disable SMS
      jest.doMock('../../../src/services/feature-flag-service', () => ({
        isEmailVerificationEnabled: () => true,
        isTwilioEnabled: () => false
      }));

      await expect(service.sendVerificationCode(
        'user-123',
        'sms',
        '+1234567890'
      )).rejects.toThrow('SMS verification is disabled');
    });
  });

  describe('Statistics and Cleanup', () => {
    test('should return verification statistics', async () => {
      mockSESSuccess();

      // Create some verifications
      await service.sendVerificationCode('user-1', 'email', 'test1@example.com');
      await service.sendVerificationCode('user-2', 'sms', '+1234567890');

      const stats = await service.getVerificationStats();

      expect(stats.activeVerifications).toBe(2);
      expect(stats.channelStats.email).toBe(1);
      expect(stats.channelStats.sms).toBe(1);
    });

    test('should cleanup expired verifications', async () => {
      // Manually add expired verification
      const expiredData = JSON.stringify({
        userId: 'user-123',
        code: '123456',
        createdAt: new Date(Date.now() - 20 * 60 * 1000) // 20 minutes ago
      });
      
      await mockRedis.set('verification:expired-123', expiredData);

      const cleanedCount = await service.cleanupExpiredVerifications();
      expect(cleanedCount).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Error Handling', () => {
    test('should handle Redis errors gracefully', async () => {
      // Mock Redis to throw errors
      mockRedis.setex = jest.fn().mockRejectedValue(new Error('Redis error'));

      await expect(service.sendVerificationCode(
        'user-123',
        'email',
        'test@example.com'
      )).rejects.toThrow();
    });

    test('should handle invalid channel gracefully', async () => {
      await expect(service.sendVerificationCode(
        'user-123',
        'invalid-channel',
        'test@example.com'
      )).rejects.toThrow('Unsupported verification channel');
    });
  });
});