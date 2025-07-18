/**
 * Tests for Cross-Merchant Identity Repository
 * 
 * Tests the 5 new methods added to support cross-merchant identity operations
 */

const { crossMerchantIdentityRepository } = require('../../src/database/cross-merchant-identity-repository');
const { dbConnection } = require('../../src/database/db-connection');

// Mock the database connection
jest.mock('../../src/database/db-connection', () => ({
  dbConnection: {
    query: jest.fn(),
    beginTransaction: jest.fn(),
    commit: jest.fn(),
    rollback: jest.fn(),
    transaction: jest.fn(async (callback) => {
      const mockClient = {
        query: jest.fn(),
        release: jest.fn()
      };
      return callback(mockClient);
    })
  }
}));

// Mock the logger
jest.mock('../../src/utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn()
  }
}));

describe('CrossMerchantIdentityRepository', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getUserByUniversalId', () => {
    it('should return user data when universal ID exists', async () => {
      const mockUserData = [{
        universal_id: 'univ_123',
        primary_email: 'test@example.com',
        primary_phone: '+1234567890',
        verification_level: 'high',
        is_verified: true,
        metadata: { source: 'test' },
        associated_devices: ['device1', 'device2'],
        merchant_count: '3',
        device_count: '2',
        created_at: new Date(),
        updated_at: new Date()
      }];

      dbConnection.query.mockResolvedValue(mockUserData);

      const result = await crossMerchantIdentityRepository.getUserByUniversalId('univ_123');

      expect(dbConnection.query).toHaveBeenCalledWith(
        expect.stringContaining('SELECT'),
        ['univ_123']
      );
      expect(result).toEqual({
        universalId: 'univ_123',
        email: 'test@example.com',
        phone: '+1234567890',
        verificationLevel: 'high',
        isVerified: true,
        metadata: { source: 'test' },
        associatedDevices: ['device1', 'device2'],
        merchantCount: 3,
        deviceCount: 2,
        createdAt: mockUserData[0].created_at,
        updatedAt: mockUserData[0].updated_at
      });
    });

    it('should return null when universal ID does not exist', async () => {
      dbConnection.query.mockResolvedValue([]);

      const result = await crossMerchantIdentityRepository.getUserByUniversalId('nonexistent');

      expect(result).toBeNull();
    });

    it('should throw error on database failure', async () => {
      dbConnection.query.mockRejectedValue(new Error('Database error'));

      await expect(
        crossMerchantIdentityRepository.getUserByUniversalId('univ_123')
      ).rejects.toThrow('Database error');
    });
  });

  describe('getUserByUserId', () => {
    it('should return universal ID for existing user', async () => {
      const mockData = [{
        universal_id: 'univ_123',
        merchant_user_id: 'user_456',
        merchant_id: 'merchant_123',
        primary_email: 'test@example.com',
        primary_phone: '+1234567890',
        verification_level: 'high',
        is_verified: true,
        metadata: {},
        custom_data: {},
        last_active: new Date()
      }];

      dbConnection.query.mockResolvedValue(mockData);

      const result = await crossMerchantIdentityRepository.getUserByUserId('user_456', 'merchant_123');

      expect(dbConnection.query).toHaveBeenCalledWith(
        expect.stringContaining('SELECT'),
        ['user_456', 'merchant_123']
      );
      expect(result.universalId).toBe('univ_123');
      expect(result.merchantUserId).toBe('user_456');
      expect(result.email).toBe('test@example.com');
    });

    it('should return null when user not found', async () => {
      dbConnection.query.mockResolvedValue([]);

      const result = await crossMerchantIdentityRepository.getUserByUserId('nonexistent', 'merchant_123');

      expect(result).toBeNull();
    });
  });

  describe('createUniversalId', () => {
    it('should create new universal ID successfully', async () => {
      // Mock the transaction callback
      dbConnection.transaction.mockImplementation(async (callback) => {
        const mockClient = {
          query: jest.fn()
            .mockResolvedValueOnce({ rows: [] }) // Check for existing identity
            .mockResolvedValueOnce({ rows: [{ identity_key: 'univ_new_123' }] }), // Insert new identity
          release: jest.fn()
        };
        return callback(mockClient);
      });

      const userData = {
        email: 'new@example.com',
        phone: '+1234567890',
        metadata: { source: 'test' },
        verificationLevel: 'low'
      };

      const result = await crossMerchantIdentityRepository.createUniversalId(userData);

      expect(result).toMatch(/^[a-f0-9-]+$/);
      expect(dbConnection.transaction).toHaveBeenCalled();
    });

    it('should handle existing email conflict', async () => {
      const existingData = [{
        identity_key: 'univ_existing',
        primary_email: 'existing@example.com'
      }];

      dbConnection.transaction.mockImplementation(async (callback) => {
        const mockClient = {
          query: jest.fn().mockResolvedValueOnce({ rows: existingData }),
          release: jest.fn()
        };
        return callback(mockClient);
      });

      const result = await crossMerchantIdentityRepository.createUniversalId({
        email: 'existing@example.com'
      });

      expect(result).toBe('univ_existing');
      expect(dbConnection.transaction).toHaveBeenCalled();
    });
  });

  describe('associateMerchant', () => {
    it('should create new merchant association', async () => {
      dbConnection.transaction.mockImplementation(async (callback) => {
        const mockClient = {
          query: jest.fn()
            .mockResolvedValueOnce({ rows: [{ identity_key: 'univ_123' }] }) // Verify universal ID exists
            .mockResolvedValueOnce({ rows: [{ 
              identity_key: 'univ_123',
              merchant_id: 'merchant_456',
              merchant_user_id: 'user_789',
              custom_data: { preferences: {} },
              is_active: true,
              created_at: new Date(),
              last_active: new Date()
            }] }), // Insert new association (upsert query)
          release: jest.fn()
        };
        return callback(mockClient);
      });

      const result = await crossMerchantIdentityRepository.associateMerchant(
        'univ_123',
        'merchant_456',
        'user_789',
        {
          customData: { preferences: {} },
          isActive: true
        }
      );

      expect(result.universalId).toBe('univ_123');
      expect(result.merchantId).toBe('merchant_456');
      expect(result.merchantUserId).toBe('user_789');
      expect(result.isActive).toBe(true);
    });

    it('should update existing merchant association', async () => {
      const existingAssoc = [{
        identity_key: 'univ_123',
        merchant_id: 'merchant_456'
      }];

      dbConnection.transaction.mockImplementation(async (callback) => {
        const mockClient = {
          query: jest.fn()
            .mockResolvedValueOnce({ rows: [{ identity_key: 'univ_123' }] }) // Verify universal ID exists
            .mockResolvedValueOnce({ rows: [{
              identity_key: 'univ_123',
              merchant_id: 'merchant_456',
              merchant_user_id: 'user_789',
              custom_data: {},
              is_active: true,
              created_at: new Date(),
              last_active: new Date()
            }] }), // Update returns the updated row (upsert query)
          release: jest.fn()
        };
        return callback(mockClient);
      });

      const result = await crossMerchantIdentityRepository.associateMerchant(
        'univ_123',
        'merchant_456',
        'user_789',
        { isActive: true }
      );

      expect(result.universalId).toBe('univ_123');
      expect(result.merchantId).toBe('merchant_456');
      expect(result.merchantUserId).toBe('user_789');
    });
  });

  describe('getMerchantData', () => {
    it('should return merchant-specific data', async () => {
      const mockData = [{
        identity_key: 'univ_123',
        merchant_id: 'merchant_123',
        merchant_user_id: 'user_456',
        primary_email: 'test@example.com',
        primary_phone: '+1234567890',
        verification_level: 'high',
        is_verified: true,
        custom_data: { preferences: { theme: 'dark' } },
        global_metadata: {},
        is_active: true,
        device_count: '2',
        created_at: new Date(),
        last_active: new Date()
      }];

      dbConnection.query.mockResolvedValue(mockData);

      const result = await crossMerchantIdentityRepository.getMerchantData('univ_123', 'merchant_123');

      expect(result.merchantId).toBe('merchant_123');
      expect(result.merchantUserId).toBe('user_456');
      expect(result.customData).toEqual({ preferences: { theme: 'dark' } });
      expect(result.isActive).toBe(true);
    });

    it('should return null when no merchant data found', async () => {
      dbConnection.query.mockResolvedValue([]);

      const result = await crossMerchantIdentityRepository.getMerchantData('univ_123', 'merchant_999');

      expect(result).toBeNull();
    });
  });

  describe('Race condition handling', () => {
    it('should handle concurrent universal ID creation', async () => {
      let callCount = 0;
      dbConnection.transaction.mockImplementation(async (callback) => {
        callCount++;
        const mockClient = {
          query: jest.fn(),
          release: jest.fn()
        };
        
        if (callCount === 1) {
          // First attempt - check returns empty, insert fails with unique constraint violation
          const duplicateError = new Error('duplicate key value violates unique constraint');
          duplicateError.code = '23505'; // PostgreSQL unique_violation error code
          
          mockClient.query
            .mockResolvedValueOnce({ rows: [] }) // Check for existing
            .mockRejectedValueOnce(duplicateError); // Insert fails
          return callback(mockClient).catch(err => {
            if (err.code === '23505') {
              throw err; // Let _withRetry handle it
            }
            throw err;
          });
        } else {
          // Second attempt (retry) - find existing
          mockClient.query.mockResolvedValueOnce({ rows: [{ 
            identity_key: 'univ_existing',
            primary_email: 'test@example.com'
          }] });
          return callback(mockClient);
        }
      });

      const result = await crossMerchantIdentityRepository.createUniversalId({
        email: 'test@example.com'
      });

      expect(result).toBe('univ_existing');
      expect(dbConnection.transaction).toHaveBeenCalledTimes(2);
    });
  });
});