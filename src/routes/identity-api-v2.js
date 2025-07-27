/**
 * Identity API v2 - Identity Service owns user data
 * Auth Service only handles authentication
 */

const express = require('express');
const router = express.Router();
const { dbConnection } = require('../database/db-connection');
const { logger } = require('../utils/logger');
const UserRecognition = require('../models/user-recognition');

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

module.exports = router;