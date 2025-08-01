/**
 * Profile Service Client for Identity Service
 * 
 * SECURITY: All communication goes through API Orchestrator
 * This client enables Identity Service to fetch profile data from Profile Service
 * to maintain backward compatibility during migration
 */

const { logger } = require('../utils/logger');

class ProfileServiceClient {
  constructor() {
    // SECURITY: All service communication MUST go through API Orchestrator
    const orchestratorUrl = process.env.API_ORCHESTRATOR_URL || 'http://fairs-api-orchestrator:4000';
    this.baseUrl = `${orchestratorUrl}/api/v1/profiles`;
    this.timeout = 5000;
    this.retries = 3;
    
    logger.info('Profile Service Client initialized', {
      baseUrl: this.baseUrl,
      orchestratorUrl
    });
  }

  /**
   * Set service token for authenticated requests
   * @param {string} token - JWT service token
   */
  setServiceToken(token) {
    this.serviceToken = token;
  }

  /**
   * Make HTTP request with retry logic
   * @private
   */
  async makeRequest(url, options = {}) {
    const requestOptions = {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'x-service-client': 'identity-service',
        'x-request-id': `identity_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        ...(this.serviceToken && { 'Authorization': `Bearer ${this.serviceToken}` }),
        ...options.headers
      },
      ...options
    };

    let lastError;
    
    for (let attempt = 1; attempt <= this.retries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        
        const response = await fetch(url, {
          ...requestOptions,
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`Profile Service responded with ${response.status}`);
        }

        const data = await response.json();
        
        logger.debug('Profile Service request successful', {
          url,
          attempt,
          status: response.status
        });
        
        return data;
        
      } catch (error) {
        lastError = error;
        
        logger.warn('Profile Service request failed', {
          url,
          attempt,
          maxRetries: this.retries,
          error: error.message
        });
        
        // Don't retry on 4xx errors (except 429)
        if (error.message.includes('responded with 4') && !error.message.includes('429')) {
          break;
        }
        
        // Wait before retry with exponential backoff
        if (attempt < this.retries) {
          const waitTime = Math.pow(2, attempt) * 1000;
          await new Promise(resolve => setTimeout(resolve, waitTime));
        }
      }
    }
    
    logger.error('Profile Service request failed after all retries', {
      url,
      error: lastError.message,
      retries: this.retries
    });
    
    // Return null instead of throwing to allow graceful degradation
    return null;
  }

  /**
   * Get user profile by ID
   * @param {string} userId - User UUID
   * @returns {Promise<Object|null>} Profile data or null if not found
   */
  async getProfile(userId) {
    try {
      if (!userId) {
        logger.warn('getProfile called without userId');
        return null;
      }

      const url = `${this.baseUrl}/${userId}`;
      const response = await this.makeRequest(url);
      
      if (response && response.success && response.profile) {
        logger.info('Retrieved profile from Profile Service', {
          userId,
          hasProfile: true
        });
        return response.profile;
      }
      
      logger.info('No profile found in Profile Service', { userId });
      return null;
      
    } catch (error) {
      logger.error('Failed to get profile from Profile Service', {
        userId,
        error: error.message
      });
      return null;
    }
  }

  /**
   * Get profile by email
   * @param {string} email - User email
   * @returns {Promise<Object|null>} Profile data or null if not found
   */
  async getProfileByEmail(email) {
    try {
      if (!email) {
        logger.warn('getProfileByEmail called without email');
        return null;
      }

      // Profile Service expects lookup by ID, so we return null
      // Identity Service will need to look up ID first
      logger.debug('Profile lookup by email not directly supported', { email });
      return null;
      
    } catch (error) {
      logger.error('Failed to get profile by email', {
        email,
        error: error.message
      });
      return null;
    }
  }

  /**
   * Create profile for new user
   * @param {Object} profileData - Profile data
   * @returns {Promise<Object|null>} Created profile or null if failed
   */
  async createProfile(profileData) {
    try {
      const url = this.baseUrl;
      const response = await this.makeRequest(url, {
        method: 'POST',
        body: JSON.stringify(profileData)
      });
      
      if (response && response.success && response.profile) {
        logger.info('Created profile in Profile Service', {
          userId: profileData.id,
          email: profileData.email
        });
        return response.profile;
      }
      
      logger.error('Failed to create profile in Profile Service', {
        userId: profileData.id,
        response
      });
      return null;
      
    } catch (error) {
      logger.error('Error creating profile in Profile Service', {
        userId: profileData.id,
        error: error.message
      });
      return null;
    }
  }

  /**
   * Update profile data
   * @param {string} userId - User UUID
   * @param {Object} updates - Profile updates
   * @returns {Promise<Object|null>} Updated profile or null if failed
   */
  async updateProfile(userId, updates) {
    try {
      const url = `${this.baseUrl}/${userId}`;
      const response = await this.makeRequest(url, {
        method: 'PATCH',
        body: JSON.stringify(updates)
      });
      
      if (response && response.success && response.profile) {
        logger.info('Updated profile in Profile Service', {
          userId,
          updatedFields: Object.keys(updates)
        });
        return response.profile;
      }
      
      logger.error('Failed to update profile in Profile Service', {
        userId,
        response
      });
      return null;
      
    } catch (error) {
      logger.error('Error updating profile in Profile Service', {
        userId,
        error: error.message
      });
      return null;
    }
  }

  /**
   * Health check
   * @returns {Promise<boolean>} True if healthy
   */
  async healthCheck() {
    try {
      const url = `${this.baseUrl}/health`;
      const response = await this.makeRequest(url);
      
      return response && response.status === 'healthy';
      
    } catch (error) {
      logger.error('Profile Service health check failed', {
        error: error.message
      });
      return false;
    }
  }
}

// Export singleton instance
const profileServiceClient = new ProfileServiceClient();

module.exports = {
  ProfileServiceClient,
  profileServiceClient
};