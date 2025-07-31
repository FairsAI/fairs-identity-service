/**
 * Enhanced Identity Service Client with JWT Support
 * 
 * This client uses JWT service tokens for authentication
 * while maintaining backward compatibility with API keys
 */

const { ServiceClient } = require('@fairs/security-middleware');
const { logger } = require('../utils/logger');

class IdentityServiceClient {
  constructor() {
    // Use orchestrator URL as per CLAUDE.md requirements
    const orchestratorUrl = process.env.API_ORCHESTRATOR_URL || 'http://fairs-api-orchestrator:4000';
    this.baseURL = `${orchestratorUrl}/api/v1/identity`;
    
    // Initialize service client for JWT tokens
    this.serviceClient = new ServiceClient({
      serviceId: process.env.SERVICE_ID,
      serviceSecret: process.env.SERVICE_SECRET,
      authServiceUrl: process.env.AUTH_SERVICE_URL || 'http://fairs-auth-service:3005'
    });
    
    logger.info('Identity service client initialized', {
      baseURL: this.baseURL,
      serviceId: process.env.SERVICE_ID,
      hasSecret: !!process.env.SERVICE_SECRET
    });
  }

  /**
   * Lookup user by email, phone, or universal ID
   * @param {Object} lookupData - Lookup criteria
   * @returns {Promise<Object>} User data if found
   */
  async lookupUser(lookupData) {
    try {
      const { email, phone, universalId, lookupType } = lookupData;
      
      const response = await this.serviceClient.requestJSON(
        `${this.baseURL}/lookup`,
        {
          method: 'POST',
          body: JSON.stringify({ 
            email, 
            phone,
            universalId,
            lookupType: lookupType || (email ? 'email' : phone ? 'phone' : 'universalId')
          })
        }
      );
      
      logger.info('User lookup successful', {
        lookupType,
        found: response.success,
        hasUser: !!response.user
      });
      
      return response;
    } catch (error) {
      logger.error('User lookup failed', {
        error: error.message,
        lookupData
      });
      throw error;
    }
  }

  /**
   * Create a new identity
   * @param {Object} userData - User data for identity creation
   * @returns {Promise<Object>} Created identity
   */
  async createIdentity(userData) {
    try {
      const response = await this.serviceClient.requestJSON(
        `${this.baseURL}/users`,
        {
          method: 'POST',
          body: JSON.stringify(userData)
        }
      );
      
      logger.info('Identity created successfully', {
        userId: response.user?.id,
        universalId: response.user?.universalId
      });
      
      return response;
    } catch (error) {
      logger.error('Identity creation failed', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Resolve identity across merchants
   * @param {Object} identityData - Identity resolution data
   * @returns {Promise<Object>} Resolved identity
   */
  async resolveIdentity(identityData) {
    try {
      const response = await this.serviceClient.requestJSON(
        `${this.baseURL}/resolve`,
        {
          method: 'POST',
          body: JSON.stringify(identityData)
        }
      );
      
      logger.info('Identity resolved successfully', {
        universalId: response.universalId,
        merchantMappings: Object.keys(response.merchantMappings || {}).length
      });
      
      return response;
    } catch (error) {
      logger.error('Identity resolution failed', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Get user by ID
   * @param {string} userId - User ID
   * @returns {Promise<Object>} User data
   */
  async getUser(userId) {
    try {
      const response = await this.serviceClient.requestJSON(
        `${this.baseURL}/users/${userId}`,
        {
          method: 'GET'
        }
      );
      
      return response;
    } catch (error) {
      logger.error('Get user failed', {
        error: error.message,
        userId
      });
      throw error;
    }
  }

  /**
   * Update user data
   * @param {string} userId - User ID
   * @param {Object} updates - Updates to apply
   * @returns {Promise<Object>} Updated user
   */
  async updateUser(userId, updates) {
    try {
      const response = await this.serviceClient.requestJSON(
        `${this.baseURL}/users/${userId}`,
        {
          method: 'PUT',
          body: JSON.stringify(updates)
        }
      );
      
      logger.info('User updated successfully', {
        userId,
        updatedFields: Object.keys(updates)
      });
      
      return response;
    } catch (error) {
      logger.error('User update failed', {
        error: error.message,
        userId
      });
      throw error;
    }
  }

  /**
   * Create device fingerprint
   * @param {Object} fingerprintData - Device fingerprint data
   * @returns {Promise<Object>} Created fingerprint
   */
  async createDeviceFingerprint(fingerprintData) {
    try {
      const response = await this.serviceClient.requestJSON(
        `${this.baseURL}/device-fingerprint`,
        {
          method: 'POST',
          body: JSON.stringify(fingerprintData)
        }
      );
      
      logger.info('Device fingerprint created', {
        fingerprintId: response.fingerprintId,
        userId: fingerprintData.userId
      });
      
      return response;
    } catch (error) {
      logger.error('Device fingerprint creation failed', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Send verification code
   * @param {Object} verificationData - Verification request data
   * @returns {Promise<Object>} Verification response
   */
  async sendVerification(verificationData) {
    try {
      const response = await this.serviceClient.requestJSON(
        `${this.baseURL}/verification/send`,
        {
          method: 'POST',
          body: JSON.stringify(verificationData)
        }
      );
      
      logger.info('Verification sent', {
        verificationType: verificationData.type,
        target: verificationData.target
      });
      
      return response;
    } catch (error) {
      logger.error('Verification send failed', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Verify code
   * @param {Object} verificationData - Verification data with code
   * @returns {Promise<Object>} Verification result
   */
  async verifyCode(verificationData) {
    try {
      const response = await this.serviceClient.requestJSON(
        `${this.baseURL}/verification/verify`,
        {
          method: 'POST',
          body: JSON.stringify(verificationData)
        }
      );
      
      logger.info('Verification completed', {
        success: response.success,
        verificationType: verificationData.type
      });
      
      return response;
    } catch (error) {
      logger.error('Verification failed', {
        error: error.message
      });
      throw error;
    }
  }
}

// Export singleton instance
module.exports = new IdentityServiceClient();