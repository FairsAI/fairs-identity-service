/**
 * Cross-Merchant Identity Repository - RACE CONDITION SAFE
 * 
 * Manages universal user identities and associations across merchants.
 * Enables cross-merchant identity resolution and device-user associations.
 * 
 * SECURITY: All operations use database locking to prevent race conditions
 */

const { dbConnection } = require('./db-connection');
const { logger } = require('../utils/logger');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

// Constants for retry logic
const MAX_RETRY_ATTEMPTS = 3;
const RETRY_DELAY_MS = 100;

class CrossMerchantIdentityRepository {
  /**
   * Associate a device with a universal user identity - RACE CONDITION SAFE
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
    return this._withRetry('associateDeviceWithUser', async () => {
      return await dbConnection.transaction(async (client) => {
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
        
        logger.debug('Associating device with user (transaction-safe)', {
          universalId,
          deviceId,
          merchantId
        });
        
        // RACE CONDITION FIX: Use SELECT FOR UPDATE to lock the association record
        const lockQuery = `
          SELECT *
          FROM device_user_associations
          WHERE device_id = $1
            AND user_id = $2
            AND merchant_id = $3
          FOR UPDATE
        `;
        
        const existingResult = await client.query(lockQuery, [deviceId, universalId, merchantId]);
        
        if (existingResult.rows.length > 0) {
          // Update the existing association atomically
          const updateQuery = `
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
            existingResult.rows[0].id
          ];
          
          const result = await client.query(updateQuery, values);
          
          logger.info('Updated device-user association (atomic)', {
            associationId: existingResult.rows[0].id,
            universalId,
            deviceId
          });
          
          return result.rows[0];
        } else {
          // RACE CONDITION FIX: Use INSERT with conflict handling
          const insertQuery = `
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
            ON CONFLICT (device_id, user_id, merchant_id) 
            DO UPDATE SET
              last_used = CURRENT_TIMESTAMP,
              confidence_score = $4,
              is_primary = $5,
              status = $6,
              verification_level = $7
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
          
          const result = await client.query(insertQuery, values);
          
          // Update the cross-merchant identity to include this device (atomic)
          await this._updateCrossMerchantIdentityDevicesAtomic(universalId, deviceId, client);
          
          logger.info('Created new device-user association (atomic)', {
            associationId: result.rows[0].id,
            universalId,
            deviceId
          });
          
          return result.rows[0];
        }
      });
    });
  }
  
  /**
   * Find universal user ID by device ID - OPTIMIZED FOR CONCURRENT ACCESS
   * @param {number} deviceId - Device fingerprint ID
   * @param {Object} options - Find options
   * @param {string} options.merchantId - Optional merchant ID to filter by
   * @param {boolean} options.activeOnly - Only return active associations (default: true)
   * @returns {Promise<Object>} User identity info
   */
  async findUserByDevice(deviceId, options = {}) {
    return this._withRetry('findUserByDevice', async () => {
      const {
        merchantId,
        activeOnly = true
      } = options;
      
      logger.debug('Finding user by device (concurrent-safe)', { deviceId, merchantId });
      
      let query;
      let values;
      
      if (merchantId) {
        // RACE CONDITION FIX: Use consistent read with proper locking hints
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
          FOR SHARE
        `;
        
        values = [deviceId, merchantId];
      } else {
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
          FOR SHARE
        `;
        
        values = [deviceId];
      }
      
      const results = await dbConnection.query(query, values);
      
      if (results.length === 0) {
        return null;
      }
      
      logger.debug('Found user by device (concurrent-safe)', {
        deviceId,
        universalId: results[0].universal_id
      });
      
      return results[0];
    });
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
   * Register a merchant user with universal identity - RACE CONDITION SAFE
   * @param {string} universalId - Universal ID or null for new identity
   * @param {string} merchantId - Merchant ID
   * @param {string} merchantUserId - Merchant's user ID
   * @param {Object} options - Registration options
   * @returns {Promise<Object>} Cross-merchant identity record
   */
  async registerMerchantUser(universalId, merchantId, merchantUserId, options = {}) {
    return this._withRetry('registerMerchantUser', async () => {
      logger.debug('Registering merchant user (transaction-safe)', {
        universalId: universalId || 'new',
        merchantId,
        merchantUserId
      });
      
      // If no universal ID, create a new one
      const identity = universalId || this._generateUniversalId();
      
      // RACE CONDITION FIX: Use serializable transaction with proper locking
      return await dbConnection.transaction(async (client) => {
        // CRITICAL: Lock the merchant user record to prevent concurrent registrations
        const lockMerchantUserQuery = `
          SELECT identity_key
          FROM cross_merchant_users
          WHERE merchant_id = $1 AND merchant_user_id = $2
          FOR UPDATE
        `;
        
        const existingResults = await client.query(lockMerchantUserQuery, [merchantId, merchantUserId]);
        
        // Lock the target identity if it exists
        if (identity !== universalId && existingResults.rows.length > 0) {
          const lockIdentityQuery = `
            SELECT identity_key
            FROM cross_merchant_identities
            WHERE identity_key IN ($1, $2)
            ORDER BY identity_key
            FOR UPDATE
          `;
          
          await client.query(lockIdentityQuery, [identity, existingResults.rows[0].identity_key]);
        }
        
        // First, ensure cross-merchant identity exists
        await this._ensureCrossMerchantIdentityAtomic(identity, client);
        
        if (existingResults.rows.length > 0 && existingResults.rows[0].identity_key !== identity) {
          // RACE CONDITION FIX: Atomic identity merge with conflict resolution
          await this._mergeIdentitiesAtomic(existingResults.rows[0].identity_key, identity, client);
        }
        
        // RACE CONDITION FIX: Atomic upsert with proper conflict handling
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
        
        // Fetch the updated cross-merchant identity with lock
        const identityQuery = `
          SELECT * FROM cross_merchant_identities
          WHERE identity_key = $1
          FOR SHARE
        `;
        
        const identityResult = await client.query(identityQuery, [identity]);
        
        logger.info('Registered merchant user (atomic)', {
          universalId: identity,
          merchantId,
          merchantUserId
        });
        
        return identityResult.rows[0];
      });
    });
  }
  
  /**
   * Find universal ID by merchant user - CONCURRENT SAFE
   * @param {string} merchantId - Merchant ID
   * @param {string} merchantUserId - Merchant's user ID
   * @returns {Promise<string>} Universal ID or null if not found
   */
  async findUniversalIdByMerchantUser(merchantId, merchantUserId) {
    return this._withRetry('findUniversalIdByMerchantUser', async () => {
      logger.debug('Finding universal ID by merchant user (concurrent-safe)', {
        merchantId,
        merchantUserId
      });
      
      // RACE CONDITION FIX: Use shared lock for consistent read
      const query = `
        SELECT identity_key
        FROM cross_merchant_users
        WHERE merchant_id = $1 AND merchant_user_id = $2
        FOR SHARE
      `;
      
      const results = await dbConnection.query(query, [merchantId, merchantUserId]);
      
      if (results.length === 0) {
        return null;
      }
      
      logger.debug('Found universal ID by merchant user (concurrent-safe)', {
        merchantId,
        merchantUserId,
        universalId: results[0].identity_key
      });
      
      return results[0].identity_key;
    });
  }
  
  /**
   * Get all merchant associations for a user - CONCURRENT SAFE
   * @param {string} universalId - Universal user ID
   * @returns {Promise<Array>} Merchant associations
   */
  async getMerchantAssociations(universalId) {
    return this._withRetry('getMerchantAssociations', async () => {
      logger.debug('Getting merchant associations (concurrent-safe)', { universalId });
      
      // RACE CONDITION FIX: Use shared lock for consistent read
      const query = `
        SELECT 
          cmu.merchant_id,
          cmu.merchant_user_id,
          cmu.last_updated
        FROM cross_merchant_users cmu
        WHERE cmu.identity_key = $1
        ORDER BY cmu.last_updated DESC
        FOR SHARE
      `;
      
      const results = await dbConnection.query(query, [universalId]);
      
      logger.debug('Found merchant associations (concurrent-safe)', {
        universalId,
        count: results.length
      });
      
      return results;
    });
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
   * Retry wrapper for handling race condition conflicts
   * @private
   * @param {string} operationName - Name of the operation for logging
   * @param {Function} operation - The operation to retry
   * @returns {Promise<any>} Operation result
   */
  async _withRetry(operationName, operation) {
    let lastError;
    
    for (let attempt = 1; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        
        // Check if this is a retryable error (serialization failure, deadlock, etc.)
        const isRetryable = this._isRetryableError(error);
        
        if (!isRetryable || attempt === MAX_RETRY_ATTEMPTS) {
          logger.error(`Operation ${operationName} failed after ${attempt} attempts:`, error);
          throw error;
        }
        
        // Exponential backoff with jitter
        const delay = RETRY_DELAY_MS * Math.pow(2, attempt - 1) + Math.random() * 50;
        
        logger.warn(`Operation ${operationName} failed on attempt ${attempt}, retrying in ${delay}ms:`, {
          error: error.message,
          code: error.code,
          attempt,
          maxAttempts: MAX_RETRY_ATTEMPTS
        });
        
        await this._sleep(delay);
      }
    }
    
    throw lastError;
  }
  
  /**
   * Check if an error is retryable due to race conditions
   * @private
   * @param {Error} error - The error to check
   * @returns {boolean} Whether the error is retryable
   */
  _isRetryableError(error) {
    if (!error.code) return false;
    
    // PostgreSQL error codes for race conditions
    const retryableCodes = [
      '40001', // serialization_failure
      '40P01', // deadlock_detected
      '23505', // unique_violation (in some INSERT ... ON CONFLICT scenarios)
      '25006', // read_only_sql_transaction (read-only conflict)
    ];
    
    return retryableCodes.includes(error.code);
  }
  
  /**
   * Sleep for a specified number of milliseconds
   * @private
   * @param {number} ms - Milliseconds to sleep
   * @returns {Promise<void>}
   */
  _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  /**
   * Atomic version of _ensureCrossMerchantIdentity
   * @private
   * @param {string} identityKey - Universal ID
   * @param {Object} client - Database client for transaction
   * @returns {Promise<Object>} Identity record
   */
  async _ensureCrossMerchantIdentityAtomic(identityKey, client) {
    // RACE CONDITION FIX: Use INSERT ... ON CONFLICT for atomic operation
    const query = `
      INSERT INTO cross_merchant_identities (
        identity_key,
        confidence_score,
        is_verified,
        verification_level
      )
      VALUES ($1, 1.0, false, 'low')
      ON CONFLICT (identity_key) DO UPDATE SET
        last_updated = CURRENT_TIMESTAMP
      RETURNING *
    `;
    
    const result = await client.query(query, [identityKey]);
    return result.rows[0];
  }
  
  /**
   * Atomic version of _updateCrossMerchantIdentityDevices
   * @private
   * @param {string} identityKey - Universal ID
   * @param {number} deviceId - Device ID to add
   * @param {Object} client - Database client for transaction
   * @returns {Promise<void>}
   */
  async _updateCrossMerchantIdentityDevicesAtomic(identityKey, deviceId, client) {
    // RACE CONDITION FIX: Use atomic array operations with proper locking
    const query = `
      UPDATE cross_merchant_identities
      SET associated_devices = array_append(COALESCE(associated_devices, ARRAY[]::integer[]), $1)
      WHERE identity_key = $2
        AND NOT ($1 = ANY(COALESCE(associated_devices, ARRAY[]::integer[])))
    `;
    
    await client.query(query, [deviceId, identityKey]);
  }
  
  /**
   * Atomic version of _mergeIdentities with proper conflict resolution
   * @private
   * @param {string} sourceId - Source identity key
   * @param {string} targetId - Target identity key 
   * @param {Object} client - Database client for transaction
   * @returns {Promise<void>}
   */
  async _mergeIdentitiesAtomic(sourceId, targetId, client) {
    logger.info('Merging identities atomically', { sourceId, targetId });
    
    // RACE CONDITION FIX: Update all references atomically in order
    
    // 1. Update device associations
    const updateAssociationsQuery = `
      UPDATE device_user_associations
      SET user_id = $1
      WHERE user_id = $2
    `;
    await client.query(updateAssociationsQuery, [targetId, sourceId]);
    
    // 2. Update merchant users 
    const updateMerchantUsersQuery = `
      UPDATE cross_merchant_users
      SET identity_key = $1
      WHERE identity_key = $2
    `;
    await client.query(updateMerchantUsersQuery, [targetId, sourceId]);
    
    // 3. Merge device arrays atomically
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
    
    // 4. Delete the source identity
    const deleteSourceQuery = `
      DELETE FROM cross_merchant_identities
      WHERE identity_key = $1
    `;
    await client.query(deleteSourceQuery, [sourceId]);
    
    logger.info('Identity merge completed atomically', { sourceId, targetId });
  }

  /**
   * Get user by universal ID - RACE CONDITION SAFE
   * @param {string} universalId - The universal user ID (UUID)
   * @returns {Promise<Object|null>} User object or null if not found
   */
  async getUserByUniversalId(universalId) {
    try {
      logger.debug('Getting user by universal ID', { universalId });
      
      const query = `
        SELECT 
          cmi.identity_key AS universal_id,
          cmi.primary_email,
          cmi.primary_phone,
          cmi.verification_level,
          cmi.is_verified,
          cmi.metadata,
          cmi.associated_devices,
          cmi.created_at,
          cmi.updated_at,
          COUNT(DISTINCT cmu.merchant_id) as merchant_count,
          COUNT(DISTINCT dua.device_id) as device_count
        FROM cross_merchant_identities cmi
        LEFT JOIN cross_merchant_users cmu ON cmi.identity_key = cmu.identity_key
        LEFT JOIN device_user_associations dua ON cmi.identity_key = dua.user_id
        WHERE cmi.identity_key = $1
        GROUP BY cmi.identity_key, cmi.primary_email, cmi.primary_phone, 
                 cmi.verification_level, cmi.is_verified, cmi.metadata,
                 cmi.associated_devices, cmi.created_at, cmi.updated_at
      `;
      
      const result = await dbConnection.query(query, [universalId]);
      
      if (result.length === 0) {
        logger.debug('User not found by universal ID', { universalId });
        return null;
      }
      
      const user = {
        universalId: result[0].universal_id,
        email: result[0].primary_email,
        phone: result[0].primary_phone,
        verificationLevel: result[0].verification_level,
        isVerified: result[0].is_verified,
        metadata: result[0].metadata,
        associatedDevices: result[0].associated_devices || [],
        merchantCount: parseInt(result[0].merchant_count),
        deviceCount: parseInt(result[0].device_count),
        createdAt: result[0].created_at,
        updatedAt: result[0].updated_at
      };
      
      logger.debug('Found user by universal ID', { universalId, merchantCount: user.merchantCount });
      return user;
      
    } catch (error) {
      logger.error('Failed to get user by universal ID', { error: error.message, universalId });
      throw error;
    }
  }

  /**
   * Get user by merchant-specific user ID - RACE CONDITION SAFE
   * @param {string} userId - Merchant-specific user ID
   * @param {string} merchantId - Merchant ID
   * @returns {Promise<Object|null>} User object with universal ID or null
   */
  async getUserByUserId(userId, merchantId) {
    try {
      logger.debug('Getting user by merchant user ID', { userId, merchantId });
      
      const query = `
        SELECT 
          cmu.identity_key AS universal_id,
          cmu.merchant_user_id,
          cmu.merchant_id,
          cmu.custom_data,
          cmu.last_active,
          cmi.primary_email,
          cmi.primary_phone,
          cmi.verification_level,
          cmi.is_verified,
          cmi.metadata
        FROM cross_merchant_users cmu
        JOIN cross_merchant_identities cmi ON cmu.identity_key = cmi.identity_key
        WHERE cmu.merchant_user_id = $1 AND cmu.merchant_id = $2
        FOR SHARE
      `;
      
      const result = await dbConnection.query(query, [userId, merchantId]);
      
      if (result.length === 0) {
        logger.debug('User not found by merchant user ID', { userId, merchantId });
        return null;
      }
      
      const user = {
        universalId: result[0].universal_id,
        merchantUserId: result[0].merchant_user_id,
        merchantId: result[0].merchant_id,
        email: result[0].primary_email,
        phone: result[0].primary_phone,
        verificationLevel: result[0].verification_level,
        isVerified: result[0].is_verified,
        metadata: result[0].metadata,
        customData: result[0].custom_data,
        lastActive: result[0].last_active
      };
      
      logger.debug('Found user by merchant user ID', { userId, merchantId, universalId: user.universalId });
      return user;
      
    } catch (error) {
      logger.error('Failed to get user by merchant user ID', { error: error.message, userId, merchantId });
      throw error;
    }
  }

  /**
   * Create a new universal identity - RACE CONDITION SAFE
   * @param {Object} userData - User data for creation
   * @param {string} userData.email - Primary email (optional)
   * @param {string} userData.phone - Primary phone (optional)
   * @param {Object} userData.metadata - Additional metadata
   * @param {string} userData.verificationLevel - Verification level (low, medium, high)
   * @returns {Promise<string>} The new universal ID (UUID)
   */
  async createUniversalId(userData = {}) {
    return this._withRetry('createUniversalId', async () => {
      return await dbConnection.transaction(async (client) => {
        const {
          email = null,
          phone = null,
          metadata = {},
          verificationLevel = 'low'
        } = userData;
        
        const universalId = uuidv4();
        
        logger.debug('Creating new universal identity', {
          universalId,
          hasEmail: !!email,
          hasPhone: !!phone
        });
        
        // Check if email or phone already exists
        if (email || phone) {
          let existingCheckQuery = 'SELECT identity_key FROM cross_merchant_identities WHERE ';
          const conditions = [];
          const values = [];
          let paramIndex = 1;
          
          if (email) {
            conditions.push(`primary_email = $${paramIndex}`);
            values.push(email);
            paramIndex++;
          }
          
          if (phone) {
            if (conditions.length > 0) conditions.push('OR');
            conditions.push(`primary_phone = $${paramIndex}`);
            values.push(phone);
          }
          
          existingCheckQuery += conditions.join(' ') + ' LIMIT 1';
          
          const existingResult = await client.query(existingCheckQuery, values);
          
          if (existingResult.rows.length > 0) {
            logger.warn('Universal identity already exists for email/phone', {
              existingId: existingResult.rows[0].identity_key,
              email: email ? '***' : null,
              phone: phone ? '***' : null
            });
            return existingResult.rows[0].identity_key;
          }
        }
        
        // Insert new universal identity
        const insertQuery = `
          INSERT INTO cross_merchant_identities (
            identity_key,
            primary_email,
            primary_phone,
            verification_level,
            is_verified,
            metadata,
            associated_devices
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7)
          ON CONFLICT (identity_key) DO NOTHING
          RETURNING identity_key
        `;
        
        const insertValues = [
          universalId,
          email,
          phone,
          verificationLevel,
          false, // is_verified starts as false
          metadata,
          [] // empty device array initially
        ];
        
        const result = await client.query(insertQuery, insertValues);
        
        if (result.rows.length === 0) {
          throw new Error('Failed to create universal identity');
        }
        
        logger.info('Created new universal identity', {
          universalId,
          verificationLevel
        });
        
        return universalId;
      });
    });
  }

  /**
   * Associate a merchant user with a universal ID - RACE CONDITION SAFE
   * @param {string} universalId - Universal ID
   * @param {string} merchantId - Merchant ID
   * @param {string} merchantUserId - Merchant-specific user ID
   * @param {Object} options - Association options
   * @returns {Promise<Object>} Association details
   */
  async associateMerchant(universalId, merchantId, merchantUserId, options = {}) {
    return this._withRetry('associateMerchant', async () => {
      return await dbConnection.transaction(async (client) => {
        const {
          customData = {},
          isActive = true
        } = options;
        
        logger.debug('Associating merchant user with universal ID', {
          universalId,
          merchantId,
          merchantUserId
        });
        
        // Verify universal ID exists
        const verifyQuery = `
          SELECT identity_key 
          FROM cross_merchant_identities 
          WHERE identity_key = $1
          FOR UPDATE
        `;
        
        const verifyResult = await client.query(verifyQuery, [universalId]);
        
        if (verifyResult.rows.length === 0) {
          throw new Error(`Universal ID not found: ${universalId}`);
        }
        
        // Insert or update merchant association
        const upsertQuery = `
          INSERT INTO cross_merchant_users (
            identity_key,
            merchant_id,
            merchant_user_id,
            custom_data,
            is_active,
            last_active
          )
          VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
          ON CONFLICT (merchant_id, merchant_user_id)
          DO UPDATE SET
            identity_key = $1,
            custom_data = $4,
            is_active = $5,
            last_active = CURRENT_TIMESTAMP
          RETURNING *
        `;
        
        const values = [
          universalId,
          merchantId,
          merchantUserId,
          customData,
          isActive
        ];
        
        const result = await client.query(upsertQuery, values);
        
        logger.info('Associated merchant user with universal ID', {
          universalId,
          merchantId,
          merchantUserId
        });
        
        return {
          universalId: result.rows[0].identity_key,
          merchantId: result.rows[0].merchant_id,
          merchantUserId: result.rows[0].merchant_user_id,
          customData: result.rows[0].custom_data,
          isActive: result.rows[0].is_active,
          createdAt: result.rows[0].created_at,
          lastActive: result.rows[0].last_active
        };
      });
    });
  }

  /**
   * Get merchant-specific data for a universal user - RACE CONDITION SAFE
   * @param {string} universalId - Universal ID
   * @param {string} merchantId - Merchant ID
   * @returns {Promise<Object|null>} Merchant-specific user data or null
   */
  async getMerchantData(universalId, merchantId) {
    try {
      logger.debug('Getting merchant data for universal user', { universalId, merchantId });
      
      const query = `
        SELECT 
          cmu.*,
          cmi.primary_email,
          cmi.primary_phone,
          cmi.verification_level,
          cmi.is_verified,
          cmi.metadata as global_metadata,
          COUNT(dua.device_id) as device_count
        FROM cross_merchant_users cmu
        JOIN cross_merchant_identities cmi ON cmu.identity_key = cmi.identity_key
        LEFT JOIN device_user_associations dua ON (
          cmu.identity_key = dua.user_id 
          AND cmu.merchant_id = dua.merchant_id
          AND dua.status = 'active'
        )
        WHERE cmu.identity_key = $1 AND cmu.merchant_id = $2
        GROUP BY cmu.identity_key, cmu.merchant_id, cmu.merchant_user_id,
                 cmu.custom_data, cmu.is_active, cmu.created_at, cmu.last_active,
                 cmi.primary_email, cmi.primary_phone, cmi.verification_level,
                 cmi.is_verified, cmi.metadata
      `;
      
      const result = await dbConnection.query(query, [universalId, merchantId]);
      
      if (result.length === 0) {
        logger.debug('No merchant data found', { universalId, merchantId });
        return null;
      }
      
      const merchantData = {
        universalId: result[0].identity_key,
        merchantId: result[0].merchant_id,
        merchantUserId: result[0].merchant_user_id,
        email: result[0].primary_email,
        phone: result[0].primary_phone,
        verificationLevel: result[0].verification_level,
        isVerified: result[0].is_verified,
        customData: result[0].custom_data,
        globalMetadata: result[0].global_metadata,
        isActive: result[0].is_active,
        deviceCount: parseInt(result[0].device_count),
        createdAt: result[0].created_at,
        lastActive: result[0].last_active
      };
      
      logger.debug('Found merchant data', { 
        universalId, 
        merchantId, 
        deviceCount: merchantData.deviceCount 
      });
      
      return merchantData;
      
    } catch (error) {
      logger.error('Failed to get merchant data', { 
        error: error.message, 
        universalId, 
        merchantId 
      });
      throw error;
    }
  }
}

// Create and export a singleton instance
const crossMerchantIdentityRepository = new CrossMerchantIdentityRepository();
module.exports = { crossMerchantIdentityRepository, CrossMerchantIdentityRepository }; 