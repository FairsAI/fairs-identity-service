/**
 * Cross-Merchant Identity Repository
 * 
 * Manages universal user identities and associations across merchants.
 * Enables cross-merchant identity resolution and device-user associations.
 */

const { dbConnection } = require('./db-connection');
const { logger } = require('../utils/logger');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

class CrossMerchantIdentityRepository {
  /**
   * Associate a device with a universal user identity
   * @param {string} universalId - The universal user ID
   * @param {number} deviceId - Device fingerprint ID
   * @param {Object} options - Association options
   * @param {string} options.merchantId - Merchant ID
   * @param {number} options.confidenceScore - Association confidence (0.0-1.0)
   * @param {boolean} options.isPrimary - Whether this is the user's primary device
   * @param {string} options.status - Association status (active, archived, etc.)
   * @returns {Promise<Object>} The association record
   */
  async associateDeviceWithUser(universalId, deviceId, options = {}) {
    try {
      const {
        merchantId,
        confidenceScore = 1.0,
        isPrimary = false,
        status = 'active',
        verificationLevel = 'low'
      } = options;
      
      if (!merchantId) {
        throw new Error('Merchant ID is required for device-user association');
      }
      
      logger.debug('Associating device with user', {
        universalId,
        deviceId,
        merchantId
      });
      
      // Check if the association already exists
      const existingAssoc = await this._findDeviceUserAssociation(deviceId, universalId, merchantId);
      
      if (existingAssoc) {
        // Update the existing association
        const query = `
          UPDATE device_user_associations
          SET 
            last_used = CURRENT_TIMESTAMP,
            confidence_score = $1,
            is_primary = $2,
            status = $3,
            verification_level = $4
          WHERE id = $5
          RETURNING *
        `;
        
        const values = [
          confidenceScore,
          isPrimary,
          status,
          verificationLevel,
          existingAssoc.id
        ];
        
        const result = await dbConnection.query(query, values);
        
        logger.info('Updated device-user association', {
          associationId: existingAssoc.id,
          universalId,
          deviceId
        });
        
        return result[0];
      } else {
        // Create a new association
        const query = `
          INSERT INTO device_user_associations (
            device_id,
            user_id,
            merchant_id,
            confidence_score,
            is_primary,
            status,
            verification_level
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7)
          RETURNING *
        `;
        
        const values = [
          deviceId,
          universalId,
          merchantId,
          confidenceScore,
          isPrimary,
          status,
          verificationLevel
        ];
        
        const result = await dbConnection.query(query, values);
        
        // Update the cross-merchant identity to include this device
        await this._updateCrossMerchantIdentityDevices(universalId, deviceId);
        
        logger.info('Created new device-user association', {
          associationId: result[0].id,
          universalId,
          deviceId
        });
        
        return result[0];
      }
    } catch (error) {
      logger.error('Error associating device with user:', error);
      throw error;
    }
  }
  
  /**
   * Find universal user ID by device ID
   * @param {number} deviceId - Device fingerprint ID
   * @param {Object} options - Find options
   * @param {string} options.merchantId - Optional merchant ID to filter by
   * @param {boolean} options.activeOnly - Only return active associations (default: true)
   * @returns {Promise<Object>} User identity info
   */
  async findUserByDevice(deviceId, options = {}) {
    try {
      const {
        merchantId,
        activeOnly = true
      } = options;
      
      logger.debug('Finding user by device', { deviceId, merchantId });
      
      let query;
      let values;
      
      if (merchantId) {
        // If a merchant ID is provided, find the specific association
        query = `
          SELECT 
            dua.user_id AS universal_id,
            dua.merchant_id,
            dua.confidence_score,
            dua.is_primary,
            dua.status,
            dua.verification_level,
            cmi.is_verified,
            cmi.metadata
          FROM device_user_associations dua
          JOIN cross_merchant_identities cmi ON dua.user_id = cmi.identity_key
          WHERE dua.device_id = $1
            AND dua.merchant_id = $2
            ${activeOnly ? "AND dua.status = 'active'" : ""}
          ORDER BY dua.confidence_score DESC, dua.last_used DESC
          LIMIT 1
        `;
        
        values = [deviceId, merchantId];
      } else {
        // If no merchant ID, find the most recently used/highest confidence association
        query = `
          SELECT 
            dua.user_id AS universal_id,
            dua.merchant_id,
            dua.confidence_score,
            dua.is_primary,
            dua.status,
            dua.verification_level,
            cmi.is_verified,
            cmi.metadata
          FROM device_user_associations dua
          JOIN cross_merchant_identities cmi ON dua.user_id = cmi.identity_key
          WHERE dua.device_id = $1
            ${activeOnly ? "AND dua.status = 'active'" : ""}
          ORDER BY dua.confidence_score DESC, dua.last_used DESC
          LIMIT 1
        `;
        
        values = [deviceId];
      }
      
      const results = await dbConnection.query(query, values);
      
      if (results.length === 0) {
        return null;
      }
      
      logger.debug('Found user by device', {
        deviceId,
        universalId: results[0].universal_id
      });
      
      return results[0];
    } catch (error) {
      logger.error('Error finding user by device:', error);
      throw error;
    }
  }
  
  /**
   * Get all devices associated with a user
   * @param {string} universalId - Universal user ID
   * @param {Object} options - Options
   * @param {string} options.merchantId - Optional merchant ID to filter by
   * @param {boolean} options.activeOnly - Only return active associations (default: true)
   * @returns {Promise<Array>} Associated devices
   */
  async getUserDevices(universalId, options = {}) {
    try {
      const {
        merchantId,
        activeOnly = true
      } = options;
      
      logger.debug('Getting user devices', { universalId, merchantId });
      
      let query;
      let values;
      
      if (merchantId) {
        // If a merchant ID is provided, find devices specific to that merchant
        query = `
          SELECT 
            df.*,
            dua.confidence_score AS association_confidence,
            dua.is_primary,
            dua.status,
            dua.verification_level,
            dua.last_used AS last_association_use
          FROM device_user_associations dua
          JOIN device_fingerprints df ON dua.device_id = df.id
          WHERE dua.user_id = $1
            AND dua.merchant_id = $2
            ${activeOnly ? "AND dua.status = 'active'" : ""}
          ORDER BY dua.is_primary DESC, dua.last_used DESC
        `;
        
        values = [universalId, merchantId];
      } else {
        // If no merchant ID, find all devices across merchants
        query = `
          SELECT 
            df.*,
            dua.confidence_score AS association_confidence,
            dua.is_primary,
            dua.status,
            dua.verification_level,
            dua.merchant_id,
            dua.last_used AS last_association_use
          FROM device_user_associations dua
          JOIN device_fingerprints df ON dua.device_id = df.id
          WHERE dua.user_id = $1
            ${activeOnly ? "AND dua.status = 'active'" : ""}
          ORDER BY dua.is_primary DESC, dua.last_used DESC
        `;
        
        values = [universalId];
      }
      
      const results = await dbConnection.query(query, values);
      
      logger.debug('Found user devices', {
        universalId,
        deviceCount: results.length
      });
      
      return results;
    } catch (error) {
      logger.error('Error getting user devices:', error);
      throw error;
    }
  }
  
  /**
   * Register a merchant-specific user ID with a universal ID
   * @param {string} universalId - Universal user ID (created if null)
   * @param {string} merchantId - Merchant ID
   * @param {string} merchantUserId - Merchant's user ID
   * @param {Object} options - Registration options
   * @returns {Promise<Object>} The cross-merchant identity
   */
  async registerMerchantUser(universalId, merchantId, merchantUserId, options = {}) {
    try {
      logger.debug('Registering merchant user', {
        universalId: universalId || 'new',
        merchantId,
        merchantUserId
      });
      
      // If no universal ID, create a new one
      const identity = universalId || this._generateUniversalId();
      
      // Begin transaction
      return await dbConnection.transaction(async (client) => {
        // First, ensure cross-merchant identity exists
        await this._ensureCrossMerchantIdentity(identity, client);
        
        // Check if this merchant user is already registered with a different universal ID
        const existingQuery = `
          SELECT identity_key
          FROM cross_merchant_users
          WHERE merchant_id = $1 AND merchant_user_id = $2
        `;
        
        const existingResults = await client.query(existingQuery, [merchantId, merchantUserId]);
        
        if (existingResults.rows.length > 0 && existingResults.rows[0].identity_key !== identity) {
          // If this merchant user is already associated with a different identity, 
          // we need to merge the identities
          await this._mergeIdentities(existingResults.rows[0].identity_key, identity, client);
        }
        
        // Register/update the merchant user
        const upsertQuery = `
          INSERT INTO cross_merchant_users (
            identity_key, 
            merchant_id, 
            merchant_user_id
          )
          VALUES ($1, $2, $3)
          ON CONFLICT (merchant_id, merchant_user_id) 
          DO UPDATE SET 
            identity_key = $1,
            last_updated = CURRENT_TIMESTAMP
          RETURNING *
        `;
        
        await client.query(upsertQuery, [identity, merchantId, merchantUserId]);
        
        // Fetch the updated cross-merchant identity
        const identityQuery = `
          SELECT * FROM cross_merchant_identities
          WHERE identity_key = $1
        `;
        
        const identityResult = await client.query(identityQuery, [identity]);
        
        logger.info('Registered merchant user', {
          universalId: identity,
          merchantId,
          merchantUserId
        });
        
        return identityResult.rows[0];
      });
    } catch (error) {
      logger.error('Error registering merchant user:', error);
      throw error;
    }
  }
  
  /**
   * Find universal ID by merchant user
   * @param {string} merchantId - Merchant ID
   * @param {string} merchantUserId - Merchant's user ID
   * @returns {Promise<string>} Universal ID or null if not found
   */
  async findUniversalIdByMerchantUser(merchantId, merchantUserId) {
    try {
      logger.debug('Finding universal ID by merchant user', {
        merchantId,
        merchantUserId
      });
      
      const query = `
        SELECT identity_key
        FROM cross_merchant_users
        WHERE merchant_id = $1 AND merchant_user_id = $2
      `;
      
      const results = await dbConnection.query(query, [merchantId, merchantUserId]);
      
      if (results.length === 0) {
        return null;
      }
      
      logger.debug('Found universal ID by merchant user', {
        merchantId,
        merchantUserId,
        universalId: results[0].identity_key
      });
      
      return results[0].identity_key;
    } catch (error) {
      logger.error('Error finding universal ID by merchant user:', error);
      throw error;
    }
  }
  
  /**
   * Get all merchant associations for a user
   * @param {string} universalId - Universal user ID
   * @returns {Promise<Array>} Merchant associations
   */
  async getMerchantAssociations(universalId) {
    try {
      logger.debug('Getting merchant associations', { universalId });
      
      const query = `
        SELECT 
          cmu.merchant_id,
          cmu.merchant_user_id,
          cmu.last_updated
        FROM cross_merchant_users cmu
        WHERE cmu.identity_key = $1
        ORDER BY cmu.last_updated DESC
      `;
      
      const results = await dbConnection.query(query, [universalId]);
      
      logger.debug('Found merchant associations', {
        universalId,
        count: results.length
      });
      
      return results;
    } catch (error) {
      logger.error('Error getting merchant associations:', error);
      throw error;
    }
  }
  
  /**
   * Generate a new universal ID
   * @private
   * @returns {string} New universal ID
   */
  _generateUniversalId() {
    return uuidv4();
  }
  
  /**
   * Find a device-user association
   * @private
   * @param {number} deviceId - Device ID
   * @param {string} universalId - Universal ID
   * @param {string} merchantId - Merchant ID
   * @returns {Promise<Object>} Association record or null
   */
  async _findDeviceUserAssociation(deviceId, universalId, merchantId) {
    const query = `
      SELECT *
      FROM device_user_associations
      WHERE device_id = $1
        AND user_id = $2
        AND merchant_id = $3
    `;
    
    const results = await dbConnection.query(query, [deviceId, universalId, merchantId]);
    
    return results.length > 0 ? results[0] : null;
  }
  
  /**
   * Ensure a cross-merchant identity exists
   * @private
   * @param {string} identityKey - Universal ID
   * @param {Object} client - Optional database client (for transactions)
   * @returns {Promise<Object>} Identity record
   */
  async _ensureCrossMerchantIdentity(identityKey, client) {
    const query = `
      INSERT INTO cross_merchant_identities (
        identity_key,
        confidence_score,
        is_verified,
        verification_level
      )
      VALUES ($1, 1.0, false, 'low')
      ON CONFLICT (identity_key) DO NOTHING
      RETURNING *
    `;
    
    if (client) {
      await client.query(query, [identityKey]);
    } else {
      await dbConnection.query(query, [identityKey]);
    }
  }
  
  /**
   * Update cross-merchant identity's associated devices array
   * @private
   * @param {string} identityKey - Universal ID
   * @param {number} deviceId - Device ID to add
   * @returns {Promise<void>}
   */
  async _updateCrossMerchantIdentityDevices(identityKey, deviceId) {
    const query = `
      UPDATE cross_merchant_identities
      SET associated_devices = array_append(COALESCE(associated_devices, ARRAY[]::integer[]), $1)
      WHERE identity_key = $2
        AND NOT ($1 = ANY(COALESCE(associated_devices, ARRAY[]::integer[])))
    `;
    
    await dbConnection.query(query, [deviceId, identityKey]);
  }
  
  /**
   * Merge two identities
   * @private
   * @param {string} sourceId - Source identity key
   * @param {string} targetId - Target identity key 
   * @param {Object} client - Database client for transaction
   * @returns {Promise<void>}
   */
  async _mergeIdentities(sourceId, targetId, client) {
    // Update all device associations
    const updateAssociationsQuery = `
      UPDATE device_user_associations
      SET user_id = $1
      WHERE user_id = $2
    `;
    
    await client.query(updateAssociationsQuery, [targetId, sourceId]);
    
    // Update all merchant users
    const updateMerchantUsersQuery = `
      UPDATE cross_merchant_users
      SET identity_key = $1
      WHERE identity_key = $2
    `;
    
    await client.query(updateMerchantUsersQuery, [targetId, sourceId]);
    
    // Merge the device arrays
    const mergeDevicesQuery = `
      UPDATE cross_merchant_identities 
      SET associated_devices = (
        SELECT array_agg(DISTINCT d) 
        FROM (
          SELECT unnest(COALESCE(a.associated_devices, ARRAY[]::integer[]) || 
                         COALESCE(b.associated_devices, ARRAY[]::integer[])) d
          FROM cross_merchant_identities a, cross_merchant_identities b
          WHERE a.identity_key = $1 AND b.identity_key = $2
        ) subquery
      )
      WHERE identity_key = $1
    `;
    
    await client.query(mergeDevicesQuery, [targetId, sourceId]);
    
    // Delete the source identity
    const deleteSourceQuery = `
      DELETE FROM cross_merchant_identities
      WHERE identity_key = $1
    `;
    
    await client.query(deleteSourceQuery, [sourceId]);
  }
}

// Create and export a singleton instance
const crossMerchantIdentityRepository = new CrossMerchantIdentityRepository();
module.exports = { crossMerchantIdentityRepository, CrossMerchantIdentityRepository }; 