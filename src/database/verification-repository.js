/**
 * Verification Repository
 * 
 * Manages verification events and verification status checks.
 * Enables tracking and validating user verification events.
 */

const { dbConnection } = require('./db-connection');
const { logger } = require('../utils/logger');

// Constants
const VERIFICATION_EXPIRY_HOURS = 24; // Verification status expires after 24 hours
const VERIFICATION_TYPES = ['email', 'phone', 'document', 'biometric', 'social', '2fa'];
const VERIFICATION_METHODS = ['code', 'link', 'otp', 'document_upload', 'facial_recognition', 'oauth'];

class VerificationRepository {
  /**
   * Record a verification event
   * @param {Object} verificationEvent - The verification event details
   * @param {string} verificationEvent.userId - Universal user ID
   * @param {string} verificationEvent.merchantId - Merchant ID
   * @param {string} verificationEvent.verificationType - Type of verification (email, phone, etc.)
   * @param {string} verificationEvent.verificationMethod - Method used (code, link, etc.)
   * @param {boolean} verificationEvent.successful - Whether verification succeeded
   * @param {number} verificationEvent.deviceId - Optional device ID
   * @param {number} verificationEvent.confidenceScore - Optional confidence score (0.0-1.0)
   * @param {string} verificationEvent.ipAddress - Optional IP address
   * @param {string} verificationEvent.userAgent - Optional user agent
   * @param {string} verificationEvent.sessionId - Optional session ID
   * @param {string} verificationEvent.errorMessage - Optional error message if failed
   * @param {Object} verificationEvent.metadata - Optional additional data
   * @returns {Promise<Object>} The recorded verification event
   */
  async recordVerification(verificationEvent) {
    try {
      const {
        userId,
        merchantId,
        verificationType,
        verificationMethod,
        successful,
        deviceId = null,
        confidenceScore = null,
        ipAddress = null,
        userAgent = null,
        sessionId = null,
        errorMessage = null,
        metadata = null
      } = verificationEvent;
      
      // Validate required fields
      if (!userId || !merchantId || !verificationType || !verificationMethod) {
        throw new Error('Missing required verification event fields');
      }
      
      // Validate verification type and method
      if (!VERIFICATION_TYPES.includes(verificationType)) {
        logger.warn('Unrecognized verification type', { verificationType });
      }
      
      if (!VERIFICATION_METHODS.includes(verificationMethod)) {
        logger.warn('Unrecognized verification method', { verificationMethod });
      }
      
      logger.debug('Recording verification event', {
        userId,
        merchantId,
        verificationType,
        successful
      });
      
      const query = `
        INSERT INTO verification_events (
          user_id,
          merchant_id,
          verification_type,
          verification_method,
          successful,
          device_id,
          confidence_score,
          ip_address,
          user_agent,
          session_id,
          error_message,
          metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING *
      `;
      
      const values = [
        userId,
        merchantId,
        verificationType,
        verificationMethod,
        successful,
        deviceId,
        confidenceScore,
        ipAddress,
        userAgent,
        sessionId,
        errorMessage,
        metadata ? JSON.stringify(metadata) : null
      ];
      
      const result = await dbConnection.query(query, values);
      
      if (successful) {
        // If verification was successful, update the cross-merchant identity
        await this._updateIdentityVerificationStatus(userId, verificationType, confidenceScore);
      }
      
      logger.info('Recorded verification event', {
        id: result[0].id,
        userId,
        verificationType,
        successful
      });
      
      return result[0];
    } catch (error) {
      logger.error('Error recording verification event:', error);
      throw error;
    }
  }
  
  /**
   * Get verification status for a user/device
   * @param {string} userId - Universal user ID
   * @param {Object} options - Options for verification check
   * @param {number} options.deviceId - Optional device ID to check
   * @param {string} options.verificationType - Optional verification type to check
   * @param {number} options.hoursValid - Hours verification remains valid (default: 24)
   * @param {string} options.merchantId - Optional merchant ID to check against
   * @returns {Promise<Object>} Verification status details
   */
  async getVerificationStatus(userId, options = {}) {
    try {
      const {
        deviceId,
        verificationType,
        hoursValid = VERIFICATION_EXPIRY_HOURS,
        merchantId
      } = options;
      
      logger.debug('Checking verification status', {
        userId,
        deviceId: deviceId || 'any',
        verificationType: verificationType || 'any'
      });
      
      // Start building the query and values array
      let query = `
        SELECT 
          ve.id,
          ve.user_id,
          ve.device_id,
          ve.verification_type,
          ve.verification_method,
          ve.confidence_score,
          ve.timestamp,
          cmi.is_verified,
          cmi.verification_level
        FROM verification_events ve
        JOIN cross_merchant_identities cmi ON ve.user_id = cmi.identity_key
        WHERE ve.user_id = $1
          AND ve.successful = true
      `;
      
      let values = [userId];
      let paramIndex = 2;
      
      // Add device ID filter if specified
      if (deviceId) {
        query += ` AND ve.device_id = $${paramIndex}`;
        values.push(deviceId);
        paramIndex++;
      }
      
      // Add verification type filter if specified
      if (verificationType) {
        query += ` AND ve.verification_type = $${paramIndex}`;
        values.push(verificationType);
        paramIndex++;
      }
      
      // Add merchant ID filter if specified
      if (merchantId) {
        query += ` AND ve.merchant_id = $${paramIndex}`;
        values.push(merchantId);
        paramIndex++;
      }
      
      // Add time validity filter
      query += ` AND ve.timestamp > NOW() - INTERVAL '${hoursValid} hours'`;
      
      // Order by most recent first
      query += ` ORDER BY ve.timestamp DESC LIMIT 1`;
      
      const results = await dbConnection.query(query, values);
      
      if (results.length === 0) {
        logger.debug('No valid verification found', {
          userId,
          deviceId: deviceId || 'any',
          verificationType: verificationType || 'any'
        });
        
        // If no verification events were found, still return basic identity info
        const identityQuery = `
          SELECT 
            identity_key AS user_id,
            is_verified,
            verification_level
          FROM cross_merchant_identities
          WHERE identity_key = $1
        `;
        
        const identityResults = await dbConnection.query(identityQuery, [userId]);
        
        if (identityResults.length === 0) {
          return {
            verified: false,
            userId,
            verificationLevel: 'none',
            daysSinceVerification: null,
            lastVerification: null
          };
        }
        
        return {
          verified: identityResults[0].is_verified,
          userId,
          verificationLevel: identityResults[0].verification_level,
          daysSinceVerification: null,
          lastVerification: null
        };
      }
      
      const verificationEvent = results[0];
      const now = new Date();
      const verificationTime = new Date(verificationEvent.timestamp);
      const daysSinceVerification = (now - verificationTime) / (1000 * 60 * 60 * 24);
      
      logger.debug('Found verification status', {
        userId,
        verified: verificationEvent.is_verified,
        level: verificationEvent.verification_level,
        daysSince: daysSinceVerification.toFixed(1)
      });
      
      return {
        verified: verificationEvent.is_verified,
        userId,
        deviceId: verificationEvent.device_id,
        verificationType: verificationEvent.verification_type,
        verificationMethod: verificationEvent.verification_method,
        verificationLevel: verificationEvent.verification_level,
        confidenceScore: verificationEvent.confidence_score,
        daysSinceVerification,
        lastVerification: verificationEvent.timestamp,
        verificationId: verificationEvent.id
      };
    } catch (error) {
      logger.error('Error getting verification status:', error);
      throw error;
    }
  }
  
  /**
   * Get recent verification events for a user
   * @param {string} userId - Universal user ID 
   * @param {Object} options - Query options
   * @param {number} options.limit - Max number of events to return (default: 10)
   * @param {string} options.merchantId - Optional merchant filter
   * @returns {Promise<Array>} Recent verification events
   */
  async getRecentVerifications(userId, options = {}) {
    try {
      const {
        limit = 10,
        merchantId
      } = options;
      
      logger.debug('Getting recent verifications', { userId, limit });
      
      let query = `
        SELECT *
        FROM verification_events
        WHERE user_id = $1
      `;
      
      let values = [userId];
      let paramIndex = 2;
      
      if (merchantId) {
        query += ` AND merchant_id = $${paramIndex}`;
        values.push(merchantId);
        paramIndex++;
      }
      
      query += ` ORDER BY timestamp DESC LIMIT $${paramIndex}`;
      values.push(limit);
      
      const results = await dbConnection.query(query, values);
      
      logger.debug('Found recent verifications', {
        userId,
        count: results.length
      });
      
      return results;
    } catch (error) {
      logger.error('Error getting recent verifications:', error);
      throw error;
    }
  }
  
  /**
   * Update verification status in cross-merchant identity
   * @private
   * @param {string} userId - Universal user ID
   * @param {string} verificationType - Verification type
   * @param {number} confidenceScore - Verification confidence score
   * @returns {Promise<void>}
   */
  async _updateIdentityVerificationStatus(userId, verificationType, confidenceScore) {
    try {
      // Determine verification level based on verification type
      let verificationLevel = 'low';
      
      if (['document', 'biometric'].includes(verificationType)) {
        verificationLevel = 'high';
      } else if (['phone', '2fa'].includes(verificationType)) {
        verificationLevel = 'medium';
      }
      
      // Update the cross-merchant identity
      const query = `
        UPDATE cross_merchant_identities
        SET 
          is_verified = true,
          verification_level = CASE
            WHEN verification_level = 'high' THEN 'high'
            WHEN verification_level = 'medium' AND $1 = 'low' THEN 'medium'
            ELSE $1
          END,
          last_updated = CURRENT_TIMESTAMP
        WHERE identity_key = $2
      `;
      
      await dbConnection.query(query, [verificationLevel, userId]);
      
      logger.debug('Updated identity verification status', {
        userId,
        verificationLevel
      });
    } catch (error) {
      logger.error('Error updating identity verification status:', error);
      throw error;
    }
  }
}

// Create and export a singleton instance
const verificationRepository = new VerificationRepository();
module.exports = { verificationRepository, VerificationRepository }; 