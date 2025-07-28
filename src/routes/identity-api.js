/**
 * Identity API Routes - Identity Service owns user data
 * 
 * Architecture:
 * - Identity Service is the source of truth for user profile data
 * - Auth Service only handles authentication (password verification, tokens)
 * - All user data queries come directly to Identity Service
 */

const express = require('express');
const router = express.Router();
const { dbConnection } = require('../database/db-connection');
const { logger } = require('../utils/logger');
const UserRecognition = require('../models/user-recognition');

/**
 * User Lookup (SDK endpoint)
 * POST /api/identity/lookup
 */
router.post('/identity/lookup', async (req, res) => {
  logger.info({
    message: 'User lookup request (SDK)',
    lookupType: req.body.lookupType,
    hasEmail: !!req.body.email,
    hasPhone: !!req.body.phone
  });
  
  try {
    const { email, phone, lookupType, deviceFingerprint, ipAddress, userAgent } = req.body;
    
    if (!lookupType || (lookupType === 'email' && !email) || (lookupType === 'phone' && !phone)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid lookup parameters'
      });
    }
    
    // Look up user in identity service database
    let user = null;
    let query, params;
    
    if (lookupType === 'email' && email) {
      query = 'SELECT * FROM identity_service.users WHERE email = $1 AND is_active = true LIMIT 1';
      params = [email.trim().toLowerCase()];
    } else if (lookupType === 'phone' && phone) {
      query = 'SELECT * FROM identity_service.users WHERE phone = $1 AND is_active = true LIMIT 1';
      params = [phone];
    }
    
    const result = await dbConnection.query(query, params);
    user = result[0];
    
    if (!user) {
      return res.json({
        success: false,
        user: null
      });
    }
    
    // Record successful recognition
    await UserRecognition.recordRecognition(user.id, {
      deviceFingerprint,
      confidence: 100,
      method: lookupType,
      ipAddress,
      userAgent
    });
    
    logger.info('User lookup successful', {
      userId: user.id
    });
    
    // Return user data from identity service
    return res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        phone: user.phone,
        firstName: user.first_name,
        lastName: user.last_name,
        name: `${user.first_name || ''} ${user.last_name || ''}`.trim() || null,
        authUserId: user.auth_user_id
      }
    });
    
  } catch (error) {
    logger.error('User lookup error', {
      error: error.message,
      stack: error.stack
    });
    
    return res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

/**
 * Service-to-Service User Lookup
 * POST /api/identity/service-lookup
 */
router.post('/identity/service-lookup',
  require('../middleware/service-auth').validateServiceAuth,
  require('../middleware/service-auth').requireServices(['checkout-service', 'payment-service', 'auth-service', 'orchestrator']),
  async (req, res) => {
    logger.info({
      message: 'Service lookup request',
      serviceClient: req.serviceClient,
      lookupType: req.body.lookupType,
      hasEmail: !!req.body.email,
      hasPhone: !!req.body.phone
    });
    
    try {
      const { email, phone, lookupType, deviceFingerprint, ipAddress, userAgent } = req.body;
      
      if (!lookupType || (lookupType === 'email' && !email) || (lookupType === 'phone' && !phone)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid lookup parameters'
        });
      }
      
      // Look up user in identity service database
      let user = null;
      let query, params;
      
      if (lookupType === 'email' && email) {
        query = 'SELECT * FROM identity_service.users WHERE email = $1 AND is_active = true LIMIT 1';
        params = [email.trim().toLowerCase()];
      } else if (lookupType === 'phone' && phone) {
        query = 'SELECT * FROM identity_service.users WHERE phone = $1 AND is_active = true LIMIT 1';
        params = [phone];
      }
      
      const result = await dbConnection.query(query, params);
      user = result[0];
      
      if (!user) {
        // Record failed recognition attempt
        await UserRecognition.recordAttempt({
          identifier: email || phone,
          identifierType: lookupType,
          success: false,
          deviceFingerprint
        });
        
        return res.json({
          success: false,
          user: null
        });
      }
      
      // Record successful recognition
      await UserRecognition.recordRecognition(user.id, {
        deviceFingerprint,
        confidence: 100,
        method: lookupType,
        ipAddress,
        userAgent
      });
      
      // Record successful attempt
      await UserRecognition.recordAttempt({
        identifier: email || phone,
        identifierType: lookupType,
        matchedUserId: user.id,
        confidence: 100,
        success: true,
        deviceFingerprint
      });
      
      logger.info('Service lookup successful', {
        serviceClient: req.serviceClient,
        userId: user.id
      });
      
      // Return user data from identity service
      return res.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          phone: user.phone,
          firstName: user.first_name,
          lastName: user.last_name,
          name: `${user.first_name || ''} ${user.last_name || ''}`.trim() || null,
          authUserId: user.auth_user_id // Link to auth service if user has set password
        }
      });
      
    } catch (error) {
      logger.error('Service lookup error', {
        error: error.message,
        stack: error.stack,
        serviceClient: req.serviceClient
      });
      
      return res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }
);

/**
 * Create User
 * POST /api/identity/users
 */
router.post('/users', async (req, res) => {
  try {
    const { email, phone, firstName, lastName } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email is required'
      });
    }
    
    // Check if user already exists
    const existing = await dbConnection.query(
      'SELECT id FROM identity_service.users WHERE email = $1',
      [email.trim().toLowerCase()]
    );
    
    if (existing.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'User already exists'
      });
    }
    
    // Create new user
    const query = `
      INSERT INTO identity_service.users 
      (email, phone, first_name, last_name)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `;
    
    const values = [
      email.trim().toLowerCase(),
      phone || null,
      firstName || null,
      lastName || null
    ];
    
    const result = await dbConnection.query(query, values);
    const user = result[0];
    
    logger.info('User created in identity service', {
      userId: user.id,
      email: user.email
    });
    
    return res.status(201).json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        phone: user.phone,
        firstName: user.first_name,
        lastName: user.last_name
      }
    });
    
  } catch (error) {
    logger.error('Create user error', {
      error: error.message
    });
    
    return res.status(500).json({
      success: false,
      error: 'Failed to create user'
    });
  }
});

/**
 * Get User by ID
 * GET /api/identity/users/:userId
 */
router.get('/users/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    
    const result = await dbConnection.query(
      'SELECT * FROM identity_service.users WHERE id = $1 AND is_active = true',
      [userId]
    );
    
    const user = result[0];
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }
    
    return res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        phone: user.phone,
        firstName: user.first_name,
        lastName: user.last_name,
        name: `${user.first_name || ''} ${user.last_name || ''}`.trim() || null,
        createdAt: user.created_at,
        authUserId: user.auth_user_id
      }
    });
    
  } catch (error) {
    logger.error('Get user error', {
      error: error.message,
      userId: req.params.userId
    });
    
    return res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

/**
 * Link User to Auth Service
 * POST /api/identity/users/:userId/link-auth
 * Called when user sets a password for the first time
 */
router.post('/users/:userId/link-auth', async (req, res) => {
  try {
    const { userId } = req.params;
    const { authUserId } = req.body;
    
    await dbConnection.query(
      'UPDATE identity_service.users SET auth_user_id = $1 WHERE id = $2',
      [authUserId, userId]
    );
    
    logger.info('User linked to auth service', {
      userId,
      authUserId
    });
    
    return res.json({
      success: true,
      message: 'User linked to auth service'
    });
    
  } catch (error) {
    logger.error('Link auth error', {
      error: error.message
    });
    
    return res.status(500).json({
      success: false,
      error: 'Failed to link user to auth service'
    });
  }
});

/**
 * Device Recognition Endpoint
 * POST /api/identity/recognize-device
 * 
 * Attempts to recognize a user by their device fingerprint
 */
router.post('/identity/recognize-device', async (req, res) => {
  try {
    const { deviceFingerprint, browserFingerprint } = req.body;
    
    if (!deviceFingerprint) {
      return res.status(400).json({
        success: false,
        error: 'Device fingerprint required'
      });
    }
    
    // Look up user by device fingerprint
    const recognition = await UserRecognition.findByDeviceFingerprint(deviceFingerprint);
    
    if (!recognition) {
      return res.json({
        success: false,
        recognized: false
      });
    }
    
    // Fetch user data from identity service database
    const result = await dbConnection.query(
      'SELECT * FROM identity_service.users WHERE id = $1 AND is_active = true',
      [recognition.user_id]
    );
    
    const user = result[0];
    
    if (!user) {
      logger.warn('User found in recognition but not in users table', {
        userId: recognition.user_id
      });
      return res.json({
        success: false,
        recognized: false
      });
    }
    
    // Update recognition timestamp
    await UserRecognition.recordRecognition(user.id, {
      deviceFingerprint,
      browserFingerprint,
      confidence: recognition.confidence,
      method: 'device',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    return res.json({
      success: true,
      recognized: true,
      confidence: recognition.confidence,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        name: `${user.first_name || ''} ${user.last_name || ''}`.trim() || null
      }
    });
    
  } catch (error) {
    logger.error('Device recognition error', {
      error: error.message
    });
    
    return res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

/**
 * Get User Recognition Data
 * POST /api/identity/users/:userId/recognition
 * 
 * This endpoint calculates confidence scores based on device context
 * and historical recognition data
 */
router.post('/identity/users/:userId/recognition', 
  require('../middleware/service-auth').validateServiceAuth,
  require('../middleware/service-auth').requireServices(['checkout-service', 'orchestrator']),
  async (req, res) => {
    logger.info({
      message: 'User recognition request',
      userId: req.params.userId,
      serviceClient: req.serviceClient,
      hasDeviceContext: !!req.body.deviceContext
    });

    try {
      const { userId } = req.params;
      const { deviceContext, merchantId = 'default' } = req.body;

      // Validate user exists
      const userQuery = 'SELECT * FROM identity_service.users WHERE id = $1 AND is_active = true';
      const userResult = await dbConnection.query(userQuery, [userId]);
      
      if (userResult.length === 0) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      const user = userResult[0];

      // Calculate confidence score based on various factors
      let confidenceScore = 0;
      const confidenceFactors = {
        tokenValidity: 0,
        deviceConsistency: 0,
        behavioralConsistency: 0,
        sessionFreshness: 0,
        securityRisk: 0
      };

      // Factor 1: Token validity (if user has valid session) - 40% weight
      // This would come from auth service in a full implementation
      confidenceFactors.tokenValidity = 0.8; // Default high score for existing users
      confidenceScore += confidenceFactors.tokenValidity * 0.4;

      // Factor 2: Device consistency - 25% weight
      if (deviceContext && deviceContext.deviceId) {
        // Check if we've seen this device before for this user
        const deviceQuery = `
          SELECT confidence FROM identity_service.device_user_associations
          WHERE user_id = $1 AND merchant_id = $2
          ORDER BY last_seen DESC
          LIMIT 1
        `;
        const deviceResult = await dbConnection.query(deviceQuery, [userId, merchantId]);
        
        if (deviceResult.length > 0) {
          confidenceFactors.deviceConsistency = deviceResult[0].confidence / 100;
        } else {
          // New device
          confidenceFactors.deviceConsistency = 0.3;
        }
      } else {
        confidenceFactors.deviceConsistency = 0.2; // No device context
      }
      confidenceScore += confidenceFactors.deviceConsistency * 0.25;

      // Factor 3: Behavioral consistency - 15% weight
      if (deviceContext && deviceContext.mouseMovements && deviceContext.keystrokes) {
        // Simple behavioral scoring based on activity
        const hasNormalActivity = deviceContext.mouseMovements > 10 && deviceContext.keystrokes > 5;
        confidenceFactors.behavioralConsistency = hasNormalActivity ? 0.9 : 0.5;
      } else {
        confidenceFactors.behavioralConsistency = 0.5;
      }
      confidenceScore += confidenceFactors.behavioralConsistency * 0.15;

      // Factor 4: Session freshness - 10% weight
      // In a real implementation, check last login time
      confidenceFactors.sessionFreshness = 0.8;
      confidenceScore += confidenceFactors.sessionFreshness * 0.1;

      // Factor 5: Security risk assessment - 10% weight
      // Check for suspicious patterns
      confidenceFactors.securityRisk = 0.9; // Low risk by default
      confidenceScore += confidenceFactors.securityRisk * 0.1;

      // Convert to percentage
      const confidencePercentage = Math.round(confidenceScore * 100);

      // Determine recommended flow based on confidence
      let recommendedFlow = 'standard_checkout';
      let shouldSkipSteps = false;
      let skippableSteps = [];

      if (confidencePercentage >= 80) {
        recommendedFlow = 'express_checkout';
        shouldSkipSteps = true;
        skippableSteps = ['phone_verification', 'email_verification'];
      } else if (confidencePercentage >= 50) {
        recommendedFlow = 'simplified_checkout';
        shouldSkipSteps = true;
        skippableSteps = ['phone_verification'];
      }

      // Log recognition event
      const eventQuery = `
        INSERT INTO identity_service.recognition_events (
          user_id,
          merchant_id,
          confidence_score,
          recommended_flow,
          recognition_successful,
          ip_address,
          user_agent,
          processing_time_ms,
          created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      `;

      const startTime = Date.now();
      await dbConnection.query(eventQuery, [
        userId,
        merchantId,
        confidencePercentage / 100,
        recommendedFlow,
        true,
        req.ip,
        req.headers['user-agent'],
        Date.now() - startTime
      ]).catch(err => {
        logger.warn('Failed to log recognition event', { error: err.message });
      });

      // Log confidence history for ML training
      const historyQuery = `
        INSERT INTO identity_service.confidence_history (
          user_id,
          merchant_id,
          confidence_score,
          factors,
          device_context,
          created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
      `;

      await dbConnection.query(historyQuery, [
        userId,
        merchantId,
        confidencePercentage / 100,
        JSON.stringify(confidenceFactors),
        JSON.stringify(deviceContext || {})
      ]).catch(err => {
        logger.warn('Failed to log confidence history', { error: err.message });
      });

      logger.info('User recognition calculated', {
        userId,
        confidenceScore: confidencePercentage,
        recommendedFlow
      });

      return res.json({
        success: true,
        data: {
          userId,
          confidenceScore: confidencePercentage,
          recommendedFlow,
          shouldSkipSteps,
          skippableSteps,
          factors: confidenceFactors
        }
      });

    } catch (error) {
      logger.error('User recognition error', {
        error: error.message,
        stack: error.stack
      });

      return res.status(500).json({
        success: false,
        error: 'Failed to calculate recognition confidence'
      });
    }
  }
);

module.exports = router;