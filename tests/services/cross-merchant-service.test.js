/**
 * Tests for Cross-Merchant Service
 * 
 * Tests the business logic layer for cross-merchant identity operations
 */

// Mock logger module first, before any imports
jest.mock('../../src/utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn()
  }
}));

// Mock db-connection to prevent database initialization
jest.mock('../../src/database/db-connection', () => ({
  dbConnection: {
    query: jest.fn(),
    transaction: jest.fn()
  }
}));

const { CrossMerchantService } = require('../../src/services/cross-merchant-service');

// Mock dependencies
const mockCrossMerchantRepo = {
  findUserByDevice: jest.fn(),
  getUserByUniversalId: jest.fn(),
  getUserByUserId: jest.fn(),
  createUniversalId: jest.fn(),
  associateMerchant: jest.fn(),
  getMerchantData: jest.fn(),
  associateDeviceWithUser: jest.fn(),
  getUserDevices: jest.fn(),
  mergeIdentities: jest.fn(),
  findUniversalIdByMerchantUser: jest.fn(),
  getMerchantAssociations: jest.fn()
};

const mockDeviceRepo = {
  findByFingerprint: jest.fn(),
  create: jest.fn()
};

const mockLogger = {
  debug: jest.fn(),
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn()
};

describe('CrossMerchantService', () => {
  let service;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new CrossMerchantService(mockCrossMerchantRepo, mockDeviceRepo);
  });

  describe('recognizeUser', () => {
    it('should recognize existing user with high confidence', async () => {
      const deviceFingerprint = 'fingerprint_123';
      const merchantId = 'merchant_456';
      
      // Mock device exists
      mockDeviceRepo.findByFingerprint.mockResolvedValue({
        id: 1,
        fingerprint: deviceFingerprint
      });

      // Mock user association found
      mockCrossMerchantRepo.findUserByDevice.mockResolvedValue({
        universal_id: 'univ_123',
        confidence_score: 0.9,
        last_used: new Date()
      });

      // Mock user profile
      mockCrossMerchantRepo.getUserByUniversalId.mockResolvedValue({
        universalId: 'univ_123',
        email: 'test@example.com',
        phone: '+1234567890',
        verificationLevel: 'high',
        isVerified: true,
        updatedAt: new Date()
      });

      // Mock merchant data
      mockCrossMerchantRepo.getMerchantData.mockResolvedValue({
        customData: {
          hasAddresses: true,
          hasPaymentMethods: true
        },
        lastActive: new Date()
      });

      const result = await service.recognizeUser(deviceFingerprint, merchantId);

      expect(result.recognized).toBe(true);
      expect(result.universalId).toBe('univ_123');
      expect(result.confidence).toBeGreaterThanOrEqual(70); // Based on confidence calculation
      expect(result.highConfidence).toBe(result.confidence >= 96);
      expect(result.profile.email).toBe('test@example.com');
    });

    it('should handle new device (unrecognized user)', async () => {
      const deviceFingerprint = 'new_fingerprint';
      const merchantId = 'merchant_456';

      // Mock device doesn't exist
      mockDeviceRepo.findByFingerprint.mockResolvedValue(null);
      mockDeviceRepo.create.mockResolvedValue({
        id: 2,
        fingerprint: deviceFingerprint
      });

      // Mock no user association
      mockCrossMerchantRepo.findUserByDevice.mockResolvedValue(null);

      const result = await service.recognizeUser(deviceFingerprint, merchantId);

      expect(result.recognized).toBe(false);
      expect(result.confidence).toBe(0);
      expect(result.requiresRegistration).toBe(true);
      expect(result.deviceId).toBe(2);
    });

    it('should handle missing parameters', async () => {
      const result = await service.recognizeUser(null, 'merchant_123');
      
      expect(result.recognized).toBe(false);
      expect(result.error).toBe('Device fingerprint and merchant ID are required');
    });
  });

  describe('registerNewUser', () => {
    it('should register new user with device', async () => {
      const userData = {
        email: 'newuser@example.com',
        phone: '+1234567890',
        firstName: 'John',
        lastName: 'Doe'
      };
      const deviceFingerprint = 'device_123';
      const merchantId = 'merchant_456';

      // Mock successful universal ID creation
      mockCrossMerchantRepo.createUniversalId.mockResolvedValue('univ_new_123');
      
      // Mock successful merchant association
      mockCrossMerchantRepo.associateMerchant.mockResolvedValue({
        universalId: 'univ_new_123',
        merchantId: 'merchant_456',
        isNew: true
      });

      // Mock device creation
      mockDeviceRepo.findByFingerprint.mockResolvedValue(null);
      mockDeviceRepo.create.mockResolvedValue({
        id: 3,
        fingerprint: deviceFingerprint
      });

      // Mock device association
      mockCrossMerchantRepo.associateDeviceWithUser.mockResolvedValue({
        id: 1
      });

      const result = await service.registerNewUser(userData, deviceFingerprint, merchantId);

      expect(result.success).toBe(true);
      expect(result.universalId).toBe('univ_new_123');
      expect(mockCrossMerchantRepo.createUniversalId).toHaveBeenCalledWith(
        expect.objectContaining({
          email: userData.email,
          phone: userData.phone,
          verificationLevel: 'low'
        })
      );
    });

    it('should handle registration without device', async () => {
      const userData = {
        email: 'newuser@example.com'
      };
      const merchantId = 'merchant_456';

      mockCrossMerchantRepo.createUniversalId.mockResolvedValue('univ_new_456');
      mockCrossMerchantRepo.associateMerchant.mockResolvedValue({
        universalId: 'univ_new_456',
        isNew: true
      });

      const result = await service.registerNewUser(userData, null, merchantId);

      expect(result.success).toBe(true);
      expect(result.universalId).toBe('univ_new_456');
      expect(mockDeviceRepo.findByFingerprint).not.toHaveBeenCalled();
    });

    it('should reject registration without email or phone', async () => {
      const userData = {
        firstName: 'John'
      };

      await expect(
        service.registerNewUser(userData, null, 'merchant_123')
      ).rejects.toThrow('Either email or phone is required for registration');
    });
  });

  describe('linkMerchantUser', () => {
    it('should link existing merchant user to universal identity', async () => {
      const merchantUserId = 'user_123';
      const universalId = 'univ_456';
      const merchantId = 'merchant_789';

      // Mock universal ID exists
      mockCrossMerchantRepo.getUserByUniversalId.mockResolvedValue({
        universalId: universalId,
        email: 'test@example.com'
      });

      // Mock no existing conflicting link
      mockCrossMerchantRepo.getUserByUserId.mockResolvedValue(null);

      // Mock successful association
      mockCrossMerchantRepo.associateMerchant.mockResolvedValue({
        universalId: universalId,
        merchantId: merchantId,
        merchantUserId: merchantUserId,
        isNew: true
      });

      const result = await service.linkMerchantUser(merchantUserId, universalId, merchantId);

      expect(result.success).toBe(true);
      expect(result.universalId).toBe(universalId);
    });

    it('should reject linking to non-existent universal ID', async () => {
      mockCrossMerchantRepo.getUserByUniversalId.mockResolvedValue(null);

      await expect(
        service.linkMerchantUser('user_123', 'invalid_univ', 'merchant_123')
      ).rejects.toThrow('Universal ID not found');
    });

    it('should reject linking already linked user to different universal ID', async () => {
      mockCrossMerchantRepo.getUserByUniversalId.mockResolvedValue({
        universalId: 'univ_456'
      });

      mockCrossMerchantRepo.getUserByUserId.mockResolvedValue({
        universalId: 'univ_different'
      });

      await expect(
        service.linkMerchantUser('user_123', 'univ_456', 'merchant_123')
      ).rejects.toThrow('Merchant user already linked to different universal ID');
    });
  });

  describe('mergeIdentities', () => {
    it('should merge two identities successfully', async () => {
      const primaryId = 'univ_primary';
      const secondaryId = 'univ_secondary';

      // Mock both identities exist
      mockCrossMerchantRepo.getUserByUniversalId
        .mockResolvedValueOnce({
          universalId: primaryId,
          email: 'primary@example.com',
          phone: '+1111111111'
        })
        .mockResolvedValueOnce({
          universalId: secondaryId,
          email: 'secondary@example.com',
          phone: '+2222222222'
        });

      mockCrossMerchantRepo.mergeIdentities.mockResolvedValue({
        success: true
      });

      const result = await service.mergeIdentities(primaryId, secondaryId, 'duplicate_detected');

      expect(result.success).toBe(true);
      expect(result.primaryId).toBe(primaryId);
      expect(result.mergedSecondaryId).toBe(secondaryId);
    });

    it('should handle non-existent primary identity', async () => {
      mockCrossMerchantRepo.getUserByUniversalId
        .mockResolvedValueOnce(null);

      await expect(
        service.mergeIdentities('invalid_primary', 'univ_secondary', 'test')
      ).rejects.toThrow('Primary universal ID not found');
    });
  });

  describe('getUserProfile', () => {
    it('should return full user profile with merchant context', async () => {
      const universalId = 'univ_123';
      const merchantId = 'merchant_456';

      mockCrossMerchantRepo.getUserByUniversalId.mockResolvedValue({
        universalId: universalId,
        email: 'test@example.com',
        phone: '+1234567890',
        verificationLevel: 'high',
        isVerified: true,
        merchantCount: 3,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      mockCrossMerchantRepo.getMerchantData.mockResolvedValue({
        merchantId: merchantId,
        customData: { preferences: {} }
      });

      mockCrossMerchantRepo.getUserDevices.mockResolvedValue([
        {
          id: 1,
          is_primary: true,
          last_association_use: new Date(),
          association_confidence: 0.95
        }
      ]);

      const result = await service.getUserProfile(universalId, merchantId);

      expect(result.universalId).toBe(universalId);
      expect(result.email).toBe('test@example.com');
      expect(result.merchantData).toBeTruthy();
      expect(result.devices).toHaveLength(1);
      expect(result.deviceCount).toBe(1);
    });

    it('should return null for non-existent user', async () => {
      mockCrossMerchantRepo.getUserByUniversalId.mockResolvedValue(null);

      const result = await service.getUserProfile('invalid_id', 'merchant_123');

      expect(result).toBeNull();
    });
  });

  describe('Confidence calculation', () => {
    it('should calculate high confidence for verified user with recent activity', async () => {
      const deviceFingerprint = 'fingerprint_123';
      const merchantId = 'merchant_456';

      mockDeviceRepo.findByFingerprint.mockResolvedValue({
        id: 1,
        fingerprint: deviceFingerprint
      });

      // High confidence association
      mockCrossMerchantRepo.findUserByDevice.mockResolvedValue({
        universal_id: 'univ_123',
        confidence_score: 0.95,
        last_used: new Date() // Recent activity
      });

      // Verified user profile
      mockCrossMerchantRepo.getUserByUniversalId.mockResolvedValue({
        universalId: 'univ_123',
        email: 'verified@example.com',
        phone: '+1234567890',
        verificationLevel: 'high',
        isVerified: true,
        updatedAt: new Date() // Recent update
      });

      mockCrossMerchantRepo.getMerchantData.mockResolvedValue({});

      const result = await service.recognizeUser(deviceFingerprint, merchantId);

      // Should have high confidence (device match + email verified + phone verified + recent activity)
      expect(result.confidence).toBeGreaterThanOrEqual(90);
      expect(result.highConfidence).toBe(true);
    });

    it('should calculate low confidence for unverified user with old activity', async () => {
      const deviceFingerprint = 'fingerprint_123';
      const merchantId = 'merchant_456';

      mockDeviceRepo.findByFingerprint.mockResolvedValue({
        id: 1,
        fingerprint: deviceFingerprint
      });

      // Low confidence association
      mockCrossMerchantRepo.findUserByDevice.mockResolvedValue({
        universal_id: 'univ_123',
        confidence_score: 0.5,
        last_used: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000) // 90 days ago
      });

      // Unverified user profile
      mockCrossMerchantRepo.getUserByUniversalId.mockResolvedValue({
        universalId: 'univ_123',
        email: 'unverified@example.com',
        phone: null,
        verificationLevel: 'low',
        isVerified: false,
        updatedAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000)
      });

      mockCrossMerchantRepo.getMerchantData.mockResolvedValue({});

      const result = await service.recognizeUser(deviceFingerprint, merchantId);

      // Should have low confidence (no verification, old activity)
      expect(result.confidence).toBeLessThan(50);
      expect(result.highConfidence).toBe(false);
    });
  });
});