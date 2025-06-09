/**
 * Identity Service
 * 
 * Handles identity operations including:
 * - Device fingerprinting
 * - Verification
 * - Cross-merchant identity resolution
 */

const { logger } = require('../utils/logger');

class IdentityService {
  constructor() {
    this.deviceFingerprints = new Map();
    this.verifications = new Map();
    this.identities = new Map();
  }
  
  /**
   * Register a device fingerprint
   * @param {Object} components - Device fingerprint components
   * @returns {Object} - Device fingerprint information
   */
  async registerFingerprint(components) {
    try {
      // Create a unique device ID
      const deviceId = `device_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
      
      // Store fingerprint data
      this.deviceFingerprints.set(deviceId, {
        id: deviceId,
        components,
        createdAt: new Date(),
        updatedAt: new Date()
      });
      
      logger.info({
        message: 'Device fingerprint registered',
        deviceId
      });
      
      return {
        deviceId,
        created: Date.now(),
        confidence: 0.95
      };
    } catch (error) {
      logger.error({
        message: 'Error registering device fingerprint',
        error: error.message,
        stack: error.stack
      });
      
      throw error;
    }
  }
  
  /**
   * Process a verification request
   * @param {Object} data - Verification data
   * @returns {Object} - Verification result
   */
  async processVerification(data) {
    try {
      const { universalId, method, phoneNumber, email, code } = data;
      
      // Create a verification record
      const verificationId = `vrf_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      
      // Store verification data
      this.verifications.set(verificationId, {
        id: verificationId,
        universalId,
        method,
        phoneNumber,
        email,
        code,
        status: 'success',
        createdAt: new Date()
      });
      
      logger.info({
        message: 'Verification processed',
        verificationId,
        method
      });
      
      return {
        verificationId,
        status: 'success',
        created: Date.now()
      };
    } catch (error) {
      logger.error({
        message: 'Error processing verification',
        error: error.message,
        stack: error.stack
      });
      
      throw error;
    }
  }
  
  /**
   * Resolve identity
   * @param {Object} data - Identity data
   * @returns {Object} - Identity resolution result
   */
  async resolveIdentity(data) {
    try {
      const { email, phone, deviceId, merchantId } = data;
      
      // Check if this user already exists
      let existingUniversalId = null;
      let isExistingUser = false;
      
      if (email) {
        // Check for existing identity by email
        for (const [id, identity] of this.identities.entries()) {
          if (identity.email === email) {
            existingUniversalId = id;
            isExistingUser = true;
            break;
          }
        }
      }
      
      // Create a new identity if none exists
      const universalId = existingUniversalId || `uid_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      
      if (!isExistingUser) {
        // Store new identity
        this.identities.set(universalId, {
          universalId,
          email,
          phone,
          deviceIds: deviceId ? [deviceId] : [],
          merchantMappings: merchantId ? { [merchantId]: `${merchantId}_user_${Date.now()}` } : {},
          createdAt: new Date(),
          updatedAt: new Date()
        });
      } else {
        // Update existing identity
        const identity = this.identities.get(universalId);
        
        if (deviceId && !identity.deviceIds.includes(deviceId)) {
          identity.deviceIds.push(deviceId);
        }
        
        if (merchantId && !identity.merchantMappings[merchantId]) {
          identity.merchantMappings[merchantId] = `${merchantId}_user_${Date.now()}`;
        }
        
        identity.updatedAt = new Date();
        this.identities.set(universalId, identity);
      }
      
      logger.info({
        message: isExistingUser ? 'Identity resolved to existing user' : 'New identity created',
        universalId,
        isExistingUser
      });
      
      return {
        universalId,
        isExistingUser,
        created: !isExistingUser ? Date.now() : undefined,
        updated: isExistingUser ? Date.now() : undefined,
        confidence: 0.95
      };
    } catch (error) {
      logger.error({
        message: 'Error resolving identity',
        error: error.message,
        stack: error.stack
      });
      
      throw error;
    }
  }
}

const identityService = new IdentityService();

module.exports = { identityService }; 