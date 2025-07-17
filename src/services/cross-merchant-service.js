/**
 * Cross-Merchant Service
 * 
 * Business logic layer for cross-merchant identity operations.
 * Handles user recognition, registration, identity merging, and merchant associations.
 * 
 * @module CrossMerchantService
 */

const { crossMerchantIdentityRepository } = require('../database/cross-merchant-identity-repository');
const { deviceFingerprintRepository } = require('../database/device-fingerprint-repository');
const { logger } = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');

// Confidence scoring weights
const CONFIDENCE_WEIGHTS = {
  DEVICE_MATCH: 40,
  EMAIL_VERIFIED: 30,
  PHONE_VERIFIED: 20,
  RECENT_ACTIVITY: 10
};

// Confidence threshold for high confidence recognition
const HIGH_CONFIDENCE_THRESHOLD = 96;

class CrossMerchantService {
  constructor(repository = crossMerchantIdentityRepository, deviceRepo = deviceFingerprintRepository) {
    this.repository = repository;
    this.deviceRepo = deviceRepo;
    this.logger = logger;
  }

  /**
   * Recognize a user based on device fingerprint and merchant context
   * @param {string} deviceFingerprint - Device fingerprint hash
   * @param {string} merchantId - Merchant ID
   * @param {Object} sessionData - Additional session data
   * @returns {Promise<Object>} Recognition result with confidence score
   */
  async recognizeUser(deviceFingerprint, merchantId, sessionData = {}) {
    try {
      this.logger.info('Attempting user recognition', {
        merchantId,
        hasDeviceFingerprint: !!deviceFingerprint,
        sessionId: sessionData.sessionId
      });

      if (!deviceFingerprint || !merchantId) {
        throw new Error('Device fingerprint and merchant ID are required');
      }

      // Step 1: Find or create device fingerprint record
      let device = await this.deviceRepo.findByFingerprint(deviceFingerprint);
      
      if (!device) {
        // Create new device record
        device = await this.deviceRepo.create({
          fingerprint: deviceFingerprint,
          metadata: sessionData.deviceMetadata || {}
        });
        
        this.logger.info('Created new device fingerprint', {
          deviceId: device.id,
          merchantId
        });
      }

      // Step 2: Check device associations
      const userAssociation = await this.repository.findUserByDevice(device.id, {
        merchantId,
        activeOnly: true
      });

      if (!userAssociation) {
        // No user found for this device
        return {
          recognized: false,
          confidence: 0,
          deviceId: device.id,
          requiresRegistration: true
        };
      }

      // Step 3: Get full user profile
      const userProfile = await this.repository.getUserByUniversalId(userAssociation.universal_id);
      
      if (!userProfile) {
        throw new Error('User profile not found for universal ID');
      }

      // Step 4: Calculate confidence score
      const confidence = this._calculateConfidence(userAssociation, userProfile, sessionData);

      // Step 5: Update last activity
      await this._trackActivity(userAssociation.universal_id, merchantId, 'recognition');

      // Step 6: Get merchant-specific data
      const merchantData = await this.repository.getMerchantData(
        userAssociation.universal_id,
        merchantId
      );

      return {
        recognized: true,
        universalId: userAssociation.universal_id,
        confidence,
        highConfidence: confidence >= HIGH_CONFIDENCE_THRESHOLD,
        profile: {
          email: userProfile.email,
          phone: userProfile.phone,
          hasAddresses: merchantData?.customData?.hasAddresses || false,
          hasPaymentMethods: merchantData?.customData?.hasPaymentMethods || false,
          lastSeen: merchantData?.lastActive || userProfile.updatedAt,
          verificationLevel: userProfile.verificationLevel,
          isVerified: userProfile.isVerified
        },
        deviceId: device.id,
        merchantData
      };

    } catch (error) {
      this.logger.error('User recognition failed', {
        error: error.message,
        merchantId,
        stack: error.stack
      });
      
      return {
        recognized: false,
        confidence: 0,
        error: error.message
      };
    }
  }

  /**
   * Register a new user with cross-merchant identity
   * @param {Object} userData - User registration data
   * @param {string} deviceFingerprint - Device fingerprint
   * @param {string} merchantId - Merchant ID
   * @returns {Promise<Object>} Registration result
   */
  async registerNewUser(userData, deviceFingerprint, merchantId) {
    try {
      this.logger.info('Registering new cross-merchant user', {
        email: userData.email ? '***' : undefined,
        phone: userData.phone ? '***' : undefined,
        merchantId
      });

      // Validate required data
      if (!merchantId) {
        throw new Error('Merchant ID is required');
      }

      if (!userData.email && !userData.phone) {
        throw new Error('Either email or phone is required for registration');
      }

      // Step 1: Create universal identity
      const universalId = await this.repository.createUniversalId({
        email: userData.email,
        phone: userData.phone,
        metadata: {
          source: 'cross_merchant_registration',
          merchantId,
          registeredAt: new Date().toISOString()
        },
        verificationLevel: 'low' // Start with low, increase with verification
      });

      // Step 2: Create merchant association
      const merchantUserId = userData.merchantUserId || uuidv4();
      await this.repository.associateMerchant(universalId, merchantId, merchantUserId, {
        customData: {
          firstName: userData.firstName,
          lastName: userData.lastName,
          preferences: userData.preferences || {}
        },
        isActive: true
      });

      // Step 3: Associate device if provided
      if (deviceFingerprint) {
        let device = await this.deviceRepo.findByFingerprint(deviceFingerprint);
        
        if (!device) {
          device = await this.deviceRepo.create({
            fingerprint: deviceFingerprint,
            metadata: userData.deviceMetadata || {}
          });
        }

        await this.repository.associateDeviceWithUser(universalId, device.id, {
          merchantId,
          confidenceScore: 0.8, // Initial confidence for new registration
          isPrimary: true,
          status: 'active'
        });
      }

      // Step 4: Track registration event
      await this._trackActivity(universalId, merchantId, 'registration');

      this.logger.info('Successfully registered new cross-merchant user', {
        universalId,
        merchantId,
        merchantUserId
      });

      return {
        success: true,
        universalId,
        merchantUserId,
        message: 'User registered successfully'
      };

    } catch (error) {
      this.logger.error('User registration failed', {
        error: error.message,
        merchantId
      });
      
      throw error;
    }
  }

  /**
   * Link an existing merchant user to a universal identity
   * @param {string} merchantUserId - Merchant-specific user ID
   * @param {string} universalId - Universal ID to link to
   * @param {string} merchantId - Merchant ID
   * @returns {Promise<Object>} Link result
   */
  async linkMerchantUser(merchantUserId, universalId, merchantId) {
    try {
      this.logger.info('Linking merchant user to universal identity', {
        merchantUserId,
        universalId,
        merchantId
      });

      // Validate inputs
      if (!merchantUserId || !universalId || !merchantId) {
        throw new Error('All parameters are required');
      }

      // Check if universal ID exists
      const universalUser = await this.repository.getUserByUniversalId(universalId);
      if (!universalUser) {
        throw new Error('Universal ID not found');
      }

      // Check if merchant user already linked
      const existingLink = await this.repository.getUserByUserId(merchantUserId, merchantId);
      if (existingLink && existingLink.universalId !== universalId) {
        throw new Error('Merchant user already linked to different universal ID');
      }

      // Create or update association
      const result = await this.repository.associateMerchant(
        universalId,
        merchantId,
        merchantUserId,
        {
          customData: {
            linkedAt: new Date().toISOString(),
            linkSource: 'manual_link'
          },
          isActive: true
        }
      );

      this.logger.info('Successfully linked merchant user', {
        merchantUserId,
        universalId,
        merchantId
      });

      return {
        success: true,
        ...result
      };

    } catch (error) {
      this.logger.error('Failed to link merchant user', {
        error: error.message,
        merchantUserId,
        universalId,
        merchantId
      });
      
      throw error;
    }
  }

  /**
   * Merge two universal identities
   * @param {string} primaryId - Primary universal ID to keep
   * @param {string} secondaryId - Secondary universal ID to merge
   * @param {string} reason - Reason for merge
   * @returns {Promise<Object>} Merge result
   */
  async mergeIdentities(primaryId, secondaryId, reason) {
    try {
      this.logger.info('Merging universal identities', {
        primaryId,
        secondaryId,
        reason
      });

      // Validate both identities exist
      const [primaryUser, secondaryUser] = await Promise.all([
        this.repository.getUserByUniversalId(primaryId),
        this.repository.getUserByUniversalId(secondaryId)
      ]);

      if (!primaryUser) {
        throw new Error('Primary universal ID not found');
      }

      if (!secondaryUser) {
        throw new Error('Secondary universal ID not found');
      }

      // Check for conflicts
      if (primaryUser.email && secondaryUser.email && 
          primaryUser.email !== secondaryUser.email) {
        this.logger.warn('Email conflict during merge', {
          primaryEmail: primaryUser.email,
          secondaryEmail: secondaryUser.email
        });
      }

      // Perform the merge
      await this.repository.mergeIdentities(primaryId, secondaryId, {
        reason,
        mergedAt: new Date().toISOString(),
        conflicts: {
          email: primaryUser.email !== secondaryUser.email,
          phone: primaryUser.phone !== secondaryUser.phone
        }
      });

      // Track merge event
      await this._trackActivity(primaryId, null, 'identity_merge', {
        secondaryId,
        reason
      });

      this.logger.info('Successfully merged identities', {
        primaryId,
        secondaryId,
        reason
      });

      return {
        success: true,
        primaryId,
        mergedSecondaryId: secondaryId,
        message: 'Identities merged successfully'
      };

    } catch (error) {
      this.logger.error('Failed to merge identities', {
        error: error.message,
        primaryId,
        secondaryId
      });
      
      throw error;
    }
  }

  /**
   * Get user profile with merchant context
   * @param {string} universalId - Universal ID
   * @param {string} requestingMerchantId - Merchant requesting the profile
   * @returns {Promise<Object>} User profile
   */
  async getUserProfile(universalId, requestingMerchantId) {
    try {
      this.logger.debug('Getting user profile', {
        universalId,
        requestingMerchantId
      });

      // Get base profile
      const profile = await this.repository.getUserByUniversalId(universalId);
      
      if (!profile) {
        return null;
      }

      // Get merchant-specific data if merchant ID provided
      let merchantData = null;
      if (requestingMerchantId) {
        merchantData = await this.repository.getMerchantData(
          universalId,
          requestingMerchantId
        );
      }

      // Get associated devices
      const devices = await this.repository.getUserDevices(universalId, {
        merchantId: requestingMerchantId,
        activeOnly: true
      });

      return {
        universalId: profile.universalId,
        email: profile.email,
        phone: profile.phone,
        verificationLevel: profile.verificationLevel,
        isVerified: profile.isVerified,
        merchantCount: profile.merchantCount,
        deviceCount: devices.length,
        merchantData,
        devices: devices.map(d => ({
          id: d.id,
          isPrimary: d.is_primary,
          lastUsed: d.last_association_use,
          confidence: d.association_confidence
        })),
        createdAt: profile.createdAt,
        updatedAt: profile.updatedAt
      };

    } catch (error) {
      this.logger.error('Failed to get user profile', {
        error: error.message,
        universalId,
        requestingMerchantId
      });
      
      throw error;
    }
  }

  /**
   * Track user activity for analytics and fraud detection
   * @param {string} universalId - Universal ID
   * @param {string} merchantId - Merchant ID
   * @param {string} activityType - Type of activity
   * @param {Object} metadata - Additional metadata
   * @returns {Promise<void>}
   */
  async trackUserActivity(universalId, merchantId, activityType, metadata = {}) {
    try {
      await this._trackActivity(universalId, merchantId, activityType, metadata);
    } catch (error) {
      // Don't throw on activity tracking errors
      this.logger.error('Failed to track user activity', {
        error: error.message,
        universalId,
        merchantId,
        activityType
      });
    }
  }

  /**
   * Calculate confidence score for user recognition
   * @private
   */
  _calculateConfidence(association, profile, sessionData) {
    let confidence = 0;

    // Device match weight
    if (association.confidence_score > 0.8) {
      confidence += CONFIDENCE_WEIGHTS.DEVICE_MATCH;
    }

    // Email verified weight
    if (profile.email && profile.verificationLevel !== 'low') {
      confidence += CONFIDENCE_WEIGHTS.EMAIL_VERIFIED;
    }

    // Phone verified weight
    if (profile.phone && profile.isVerified) {
      confidence += CONFIDENCE_WEIGHTS.PHONE_VERIFIED;
    }

    // Recent activity weight
    const lastActive = new Date(association.last_used || profile.updatedAt);
    const daysSinceActive = (Date.now() - lastActive) / (1000 * 60 * 60 * 24);
    if (daysSinceActive < 30) {
      confidence += CONFIDENCE_WEIGHTS.RECENT_ACTIVITY;
    }

    // Cap at 100
    return Math.min(confidence, 100);
  }

  /**
   * Track user activity
   * @private
   */
  async _trackActivity(universalId, merchantId, activityType, metadata = {}) {
    // In a real implementation, this would write to an activity log table
    // For now, just log it
    this.logger.info('User activity tracked', {
      universalId,
      merchantId,
      activityType,
      timestamp: new Date().toISOString(),
      metadata
    });
  }
}

// Create and export singleton instance
const crossMerchantService = new CrossMerchantService();

module.exports = {
  CrossMerchantService,
  crossMerchantService
};