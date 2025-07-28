/**
 * User Recognition Model
 * 
 * Manages user recognition tracking and device fingerprint associations.
 * This model acts as a bridge between the identity API routes and the 
 * device fingerprint repository, providing user-specific recognition capabilities.
 */

const { dbConnection } = require('../database/db-connection');
const { deviceFingerprintRepository } = require('../database/device-fingerprint-repository');
const { logger } = require('../utils/logger');

class UserRecognition {
  /**
   * Record a successful user recognition event
   * @param {string} userId - The recognized user's ID
   * @param {Object} data - Recognition data including device fingerprint
   * @returns {Promise<Object>} The created recognition record
   */
  static async recordRecognition(userId, data) {
    try {
      const {
        deviceFingerprint,
        browserFingerprint,
        confidence = 100,
        method = 'email',
        ipAddress,
        userAgent,
        merchantId
      } = data;

      logger.info('Recording user recognition', {
        userId,
        method,
        confidence,
        hasDeviceFingerprint: !!deviceFingerprint
      });

      // If device fingerprint provided, store or update it
      let deviceId = null;
      if (deviceFingerprint) {
        // Parse device fingerprint if it's a string
        const fingerprintData = typeof deviceFingerprint === 'string' 
          ? { fingerprintHash: deviceFingerprint }
          : deviceFingerprint;

        // Add additional context
        const components = {
          ...fingerprintData,
          ipAddress,
          userAgent,
          isMobile: userAgent && /mobile|android|iphone|ipad/i.test(userAgent)
        };

        // Store fingerprint using the repository
        const device = await deviceFingerprintRepository.storeFingerprint(components);
        deviceId = device.id;

        // Associate device with user
        await this._associateDeviceWithUser(deviceId, userId, merchantId);
      }

      // Record the recognition event
      const query = `
        INSERT INTO identity_service.user_recognitions (
          user_id,
          device_id,
          method,
          confidence,
          ip_address,
          merchant_id,
          metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
      `;

      const metadata = {
        browserFingerprint,
        userAgent,
        timestamp: new Date().toISOString()
      };

      const values = [
        userId,
        deviceId,
        method,
        confidence,
        ipAddress,
        merchantId,
        JSON.stringify(metadata)
      ];

      const result = await dbConnection.query(query, values);
      
      logger.info('User recognition recorded successfully', {
        recognitionId: result[0]?.id,
        userId,
        deviceId
      });

      return result[0];
    } catch (error) {
      logger.error('Failed to record user recognition', {
        error: error.message,
        userId,
        stack: error.stack
      });
      
      // Don't throw - recognition tracking shouldn't break the flow
      return null;
    }
  }

  /**
   * Record a recognition attempt (successful or failed)
   * @param {Object} data - Attempt data
   * @returns {Promise<Object>} The created attempt record
   */
  static async recordAttempt(data) {
    try {
      const {
        identifier,
        identifierType = 'email',
        matchedUserId = null,
        confidence = 0,
        success = false,
        deviceFingerprint,
        ipAddress,
        merchantId
      } = data;

      logger.info('Recording recognition attempt', {
        identifierType,
        success,
        hasMatch: !!matchedUserId
      });

      // Store device fingerprint if provided
      let deviceId = null;
      if (deviceFingerprint) {
        const components = typeof deviceFingerprint === 'string'
          ? { fingerprintHash: deviceFingerprint }
          : deviceFingerprint;

        const device = await deviceFingerprintRepository.storeFingerprint({
          ...components,
          ipAddress
        });
        deviceId = device.id;
      }

      const query = `
        INSERT INTO identity_service.recognition_attempts (
          identifier,
          identifier_type,
          matched_user_id,
          device_id,
          confidence,
          success,
          ip_address,
          merchant_id,
          metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
      `;

      const metadata = {
        timestamp: new Date().toISOString(),
        method: identifierType
      };

      const values = [
        identifier,
        identifierType,
        matchedUserId,
        deviceId,
        confidence,
        success,
        ipAddress,
        merchantId,
        JSON.stringify(metadata)
      ];

      const result = await dbConnection.query(query, values);
      
      logger.info('Recognition attempt recorded', {
        attemptId: result[0]?.id,
        success,
        identifier: identifier?.substring(0, 3) + '***' // Partial log for privacy
      });

      return result[0];
    } catch (error) {
      logger.error('Failed to record recognition attempt', {
        error: error.message,
        identifierType: data.identifierType
      });
      
      // Don't throw - attempt tracking shouldn't break the flow
      return null;
    }
  }

  /**
   * Find a user by their device fingerprint
   * @param {string} deviceFingerprint - The device fingerprint to search for
   * @param {Object} options - Search options
   * @returns {Promise<Object|null>} The user and recognition data or null
   */
  static async findByDeviceFingerprint(deviceFingerprint, options = {}) {
    try {
      const { merchantId, minConfidence = 70 } = options;

      logger.debug('Finding user by device fingerprint', {
        fingerprintLength: deviceFingerprint?.length,
        merchantId,
        minConfidence
      });

      // First, find the device using the fingerprint repository
      const device = await deviceFingerprintRepository.findDeviceByComponents(
        { fingerprintHash: deviceFingerprint },
        { similarityThreshold: 0.8 }
      );

      if (!device) {
        logger.debug('No device found for fingerprint');
        return null;
      }

      // Find user associations for this device
      let query = `
        SELECT 
          dua.user_id,
          dua.confidence,
          dua.last_seen,
          u.email,
          u.phone,
          u.first_name,
          u.last_name,
          u.is_active
        FROM identity_service.device_user_associations dua
        INNER JOIN identity_service.users u ON dua.user_id = u.id
        WHERE dua.device_id = $1
          AND dua.confidence >= $2
          AND u.is_active = true
      `;

      const values = [device.id, minConfidence];

      // Filter by merchant if specified
      if (merchantId) {
        query += ` AND dua.merchant_id = $3`;
        values.push(merchantId);
      }

      query += ` ORDER BY dua.confidence DESC, dua.last_seen DESC LIMIT 1`;

      const result = await dbConnection.query(query, values);

      if (result.length === 0) {
        logger.debug('No user associations found for device', {
          deviceId: device.id
        });
        return null;
      }

      const userAssociation = result[0];

      logger.info('User found by device fingerprint', {
        userId: userAssociation.user_id,
        confidence: userAssociation.confidence,
        deviceId: device.id
      });

      return {
        user_id: userAssociation.user_id,
        confidence: userAssociation.confidence,
        device_id: device.id,
        user: {
          id: userAssociation.user_id,
          email: userAssociation.email,
          phone: userAssociation.phone,
          firstName: userAssociation.first_name,
          lastName: userAssociation.last_name
        }
      };
    } catch (error) {
      logger.error('Failed to find user by device fingerprint', {
        error: error.message,
        stack: error.stack
      });
      
      // Don't throw - recognition lookup shouldn't break the flow
      return null;
    }
  }

  /**
   * Associate a device with a user
   * @private
   */
  static async _associateDeviceWithUser(deviceId, userId, merchantId = null) {
    try {
      // Check if association already exists
      const existingQuery = `
        SELECT id, confidence FROM identity_service.device_user_associations
        WHERE device_id = $1 AND user_id = $2 AND merchant_id = $3
      `;

      const existing = await dbConnection.query(existingQuery, [deviceId, userId, merchantId]);

      if (existing.length > 0) {
        // Update existing association
        const updateQuery = `
          UPDATE identity_service.device_user_associations
          SET confidence = LEAST(100, confidence + 5),
              last_seen = CURRENT_TIMESTAMP,
              association_count = association_count + 1
          WHERE id = $1
          RETURNING *
        `;
        
        return await dbConnection.query(updateQuery, [existing[0].id]);
      } else {
        // Create new association
        const insertQuery = `
          INSERT INTO identity_service.device_user_associations (
            device_id,
            user_id,
            merchant_id,
            confidence,
            association_count
          )
          VALUES ($1, $2, $3, $4, $5)
          RETURNING *
        `;
        
        return await dbConnection.query(insertQuery, [
          deviceId,
          userId,
          merchantId,
          80, // Initial confidence
          1   // First association
        ]);
      }
    } catch (error) {
      logger.error('Failed to associate device with user', {
        error: error.message,
        deviceId,
        userId
      });
      throw error;
    }
  }

  /**
   * Create required database tables if they don't exist
   * This is a temporary solution - should be moved to proper migrations
   */
  static async ensureTables() {
    try {
      // First ensure the device_fingerprints table exists
      await dbConnection.query(`
        CREATE TABLE IF NOT EXISTS device_fingerprints (
          id SERIAL PRIMARY KEY,
          fingerprint_hash VARCHAR(255) NOT NULL,
          user_agent TEXT,
          screen_resolution VARCHAR(50),
          color_depth INTEGER,
          timezone VARCHAR(100),
          language_preferences VARCHAR(100),
          browser_plugins TEXT,
          installed_fonts TEXT,
          canvas_fingerprint TEXT,
          webgl_fingerprint TEXT,
          battery_info TEXT,
          device_memory INTEGER,
          hardware_concurrency INTEGER,
          platform VARCHAR(100),
          ip_address INET,
          connection_type VARCHAR(50),
          browser_version VARCHAR(50),
          os_version VARCHAR(50),
          is_mobile BOOLEAN DEFAULT false,
          network_info TEXT,
          metadata JSONB,
          confidence_score FLOAT DEFAULT 1.0,
          validation_failures JSONB,
          spoofing_flags JSONB,
          behavioral_anomalies JSONB,
          suspicion_level VARCHAR(20) DEFAULT 'none',
          risk_score FLOAT DEFAULT 0,
          is_suspicious BOOLEAN DEFAULT false,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `).catch(() => {
        // Table might already exist
        logger.debug('device_fingerprints table might already exist');
      });

      // Create user_recognitions table
      await dbConnection.query(`
        CREATE TABLE IF NOT EXISTS identity_service.user_recognitions (
          id SERIAL PRIMARY KEY,
          user_id UUID NOT NULL,
          device_id INTEGER,
          method VARCHAR(50) NOT NULL,
          confidence INTEGER DEFAULT 100,
          ip_address INET,
          merchant_id VARCHAR(255),
          metadata JSONB,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `).catch(err => {
        logger.debug('user_recognitions table might already exist', err.message);
      });

      // Create recognition_attempts table
      await dbConnection.query(`
        CREATE TABLE IF NOT EXISTS identity_service.recognition_attempts (
          id SERIAL PRIMARY KEY,
          identifier VARCHAR(255) NOT NULL,
          identifier_type VARCHAR(50) NOT NULL,
          matched_user_id UUID,
          device_id INTEGER,
          confidence INTEGER DEFAULT 0,
          success BOOLEAN DEFAULT false,
          ip_address INET,
          merchant_id VARCHAR(255),
          metadata JSONB,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Create device_user_associations table
      await dbConnection.query(`
        CREATE TABLE IF NOT EXISTS identity_service.device_user_associations (
          id SERIAL PRIMARY KEY,
          device_id INTEGER NOT NULL,
          user_id UUID NOT NULL,
          merchant_id VARCHAR(255),
          confidence INTEGER DEFAULT 50,
          association_count INTEGER DEFAULT 1,
          last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(device_id, user_id, merchant_id)
        )
      `);

      // Create indexes separately
      await dbConnection.query(`
        CREATE INDEX IF NOT EXISTS idx_user_recognitions_user_id 
        ON identity_service.user_recognitions(user_id)
      `).catch(() => {});

      await dbConnection.query(`
        CREATE INDEX IF NOT EXISTS idx_user_recognitions_device_id 
        ON identity_service.user_recognitions(device_id)
      `).catch(() => {});

      await dbConnection.query(`
        CREATE INDEX IF NOT EXISTS idx_recognition_attempts_identifier 
        ON identity_service.recognition_attempts(identifier)
      `).catch(() => {});

      await dbConnection.query(`
        CREATE INDEX IF NOT EXISTS idx_device_user_associations_device 
        ON identity_service.device_user_associations(device_id)
      `).catch(() => {});

      await dbConnection.query(`
        CREATE INDEX IF NOT EXISTS idx_device_user_associations_user 
        ON identity_service.device_user_associations(user_id)
      `).catch(() => {});

      logger.info('User recognition tables ensured');
    } catch (error) {
      logger.error('Failed to ensure recognition tables', {
        error: error.message
      });
      // Don't throw - let the service start even if tables can't be created
    }
  }
}

// Ensure tables exist on module load
UserRecognition.ensureTables().catch(err => {
  logger.error('Failed to ensure tables on startup', { error: err.message });
});

module.exports = UserRecognition;