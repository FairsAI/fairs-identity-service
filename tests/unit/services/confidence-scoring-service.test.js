const ConfidenceScoringService = require('../../../src/services/confidence-scoring-service');

describe('ConfidenceScoringService', () => {
  let service;

  beforeEach(() => {
    service = new ConfidenceScoringService();
  });

  describe('Overall Confidence Calculation', () => {
    test('should calculate confidence score with all factors', async () => {
      const user = {
        id: 'test-user-id',
        deviceHistory: [
          {
            fingerprint: { hash: 'abc123' },
            lastSeen: new Date(Date.now() - 24 * 60 * 60 * 1000) // 1 day ago
          }
        ],
        behavioralProfile: {
          typingPatterns: { avgSpeed: 200 },
          timePatterns: { commonHours: [9, 10, 11, 14, 15, 16] }
        },
        verificationHistory: [
          { timestamp: new Date(Date.now() - 60 * 60 * 1000), success: true }
        ],
        crossMerchantProfile: {
          verifiedMerchants: ['merchant1', 'merchant2'],
          behavioralConsistency: 0.8
        },
        lastLoginAt: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
        createdAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000) // 60 days ago
      };

      const deviceFingerprint = { hash: 'abc123' };
      const context = {
        typingData: { avgSpeed: 195 },
        ipAddress: '192.168.1.1'
      };

      const result = await service.calculateConfidenceScore(user, deviceFingerprint, context);

      expect(result).toHaveProperty('confidence');
      expect(result).toHaveProperty('breakdown');
      expect(result).toHaveProperty('factors');
      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(100);
      expect(Array.isArray(result.factors)).toBe(true);
    });

    test('should handle minimal user data', async () => {
      const user = {
        id: 'test-user-id',
        deviceHistory: [],
        createdAt: new Date()
      };

      const result = await service.calculateConfidenceScore(user, null, {});

      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(100);
    });

    test('should apply feature flag constraints when auto-recognition disabled', async () => {
      // Mock feature flags to disable auto-recognition
      const originalFeatureFlags = require('../../../src/services/feature-flag-service');
      jest.doMock('../../../src/services/feature-flag-service', () => ({
        ...originalFeatureFlags,
        isAutoRecognitionEnabled: () => false,
        getMediumConfidenceThreshold: () => 50
      }));

      const user = {
        id: 'test-user-id',
        deviceHistory: [{ fingerprint: { hash: 'abc123' }, lastSeen: new Date() }]
      };

      const result = await service.calculateConfidenceScore(user, { hash: 'abc123' }, {});

      expect(result.confidence).toBeLessThan(50);
      expect(result.featureFlagApplied).toBe(true);
      expect(result.reason).toBe('auto_recognition_disabled');
    });
  });

  describe('Device Recognition Scoring', () => {
    test('should score perfect device match highly', async () => {
      const user = {
        deviceHistory: [
          {
            fingerprint: { hash: 'abc123' },
            lastSeen: new Date(Date.now() - 60 * 60 * 1000) // 1 hour ago
          }
        ]
      };

      const currentFingerprint = { hash: 'abc123' };

      const score = await service.scoreDeviceRecognition(user, currentFingerprint);
      expect(score).toBeGreaterThan(80);
    });

    test('should apply time decay to device scores', async () => {
      const user = {
        deviceHistory: [
          {
            fingerprint: { hash: 'abc123' },
            lastSeen: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 days ago
          }
        ]
      };

      const currentFingerprint = { hash: 'abc123' };

      const score = await service.scoreDeviceRecognition(user, currentFingerprint);
      expect(score).toBeLessThan(100); // Should be decayed
    });

    test('should return 0 for no device history', async () => {
      const user = { deviceHistory: [] };
      const score = await service.scoreDeviceRecognition(user, { hash: 'abc123' });
      expect(score).toBe(0);
    });
  });

  describe('Behavioral Consistency Scoring', () => {
    test('should score consistent typing patterns highly', async () => {
      const user = {
        behavioralProfile: {
          typingPatterns: { avgSpeed: 200 }
        }
      };

      const context = {
        typingData: { avgSpeed: 195 } // Very similar
      };

      const score = await service.scoreBehavioralConsistency(user, context);
      expect(score).toBeGreaterThan(80);
    });

    test('should score time patterns correctly', async () => {
      const user = {
        behavioralProfile: {
          timePatterns: { commonHours: [9, 10, 11, 14, 15] }
        }
      };

      // Mock current time to be 10 AM
      const mockDate = new Date();
      mockDate.setHours(10);
      jest.spyOn(global, 'Date').mockImplementation(() => mockDate);

      const score = await service.scoreBehavioralConsistency(user, {});
      expect(score).toBeGreaterThan(0);

      global.Date.mockRestore();
    });
  });

  describe('Verification History Scoring', () => {
    test('should score recent successful verifications highly', async () => {
      const user = {
        verificationHistory: [
          { timestamp: new Date(Date.now() - 60 * 60 * 1000), success: true },
          { timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000), success: true },
          { timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000), success: true }
        ]
      };

      const score = await service.scoreVerificationHistory(user);
      expect(score).toBeGreaterThan(50);
    });

    test('should penalize failed verifications', async () => {
      const user = {
        verificationHistory: [
          { timestamp: new Date(Date.now() - 60 * 60 * 1000), success: false },
          { timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000), success: false },
          { timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000), success: true }
        ]
      };

      const score = await service.scoreVerificationHistory(user);
      expect(score).toBeLessThan(70);
    });

    test('should return 0 for no verification history', async () => {
      const user = { verificationHistory: [] };
      const score = await service.scoreVerificationHistory(user);
      expect(score).toBe(0);
    });
  });

  describe('Cross-Merchant Data Scoring', () => {
    test('should score multiple verified merchants highly', async () => {
      const user = {
        crossMerchantProfile: {
          verifiedMerchants: ['merchant1', 'merchant2', 'merchant3'],
          behavioralConsistency: 0.9,
          trustSignals: [0.8, 0.9, 0.85]
        }
      };

      const score = await service.scoreCrossMerchantData(user, {});
      expect(score).toBeGreaterThan(70);
    });

    test('should return 0 when cross-merchant is disabled', async () => {
      // Mock feature flags
      const originalFeatureFlags = require('../../../src/services/feature-flag-service');
      jest.doMock('../../../src/services/feature-flag-service', () => ({
        ...originalFeatureFlags,
        isCrossMerchantEnabled: () => false
      }));

      const user = {
        crossMerchantProfile: {
          verifiedMerchants: ['merchant1', 'merchant2']
        }
      };

      const score = await service.scoreCrossMerchantData(user, {});
      expect(score).toBe(0);
    });
  });

  describe('Time-based Factors Scoring', () => {
    test('should score recent login highly', async () => {
      const user = {
        lastLoginAt: new Date(Date.now() - 30 * 60 * 1000), // 30 minutes ago
        createdAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000) // 60 days ago
      };

      const score = await service.scoreTimeFactors(user, {});
      expect(score).toBeGreaterThan(60);
    });

    test('should score established accounts higher', async () => {
      const newUser = {
        createdAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000) // 5 days ago
      };

      const establishedUser = {
        createdAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000) // 1 year ago
      };

      const newScore = await service.scoreTimeFactors(newUser, {});
      const establishedScore = await service.scoreTimeFactors(establishedUser, {});

      expect(establishedScore).toBeGreaterThan(newScore);
    });
  });

  describe('Authentication Method Determination', () => {
    test('should determine correct auth method for high confidence', () => {
      const method = service.getAuthenticationMethod(85);
      expect(['auto_login', 'verification_required']).toContain(method);
    });

    test('should determine correct auth method for low confidence', () => {
      const method = service.getAuthenticationMethod(25);
      expect(['full_verification_required', 'password_required']).toContain(method);
    });
  });

  describe('Utility Methods', () => {
    test('should calculate days since timestamp correctly', () => {
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const days = service.getDaysSince(oneDayAgo);
      expect(days).toBe(1);
    });

    test('should compare typing patterns with similarity', () => {
      const stored = { avgSpeed: 200 };
      const current = { avgSpeed: 195 };
      
      const similarity = service.compareTypingPatterns(stored, current);
      expect(similarity).toBeGreaterThan(90);
    });

    test('should handle missing data gracefully', () => {
      expect(service.compareTypingPatterns(null, null)).toBe(0);
      expect(service.compareMousePatterns(undefined, {})).toBe(0);
    });
  });

  describe('Error Handling', () => {
    test('should handle errors gracefully and return safe defaults', async () => {
      // Simulate error by passing invalid user data
      const result = await service.calculateConfidenceScore(null, null, {});

      expect(result.confidence).toBe(0);
      expect(result.breakdown).toEqual({});
      expect(result.factors).toHaveProperty('error');
    });
  });
});