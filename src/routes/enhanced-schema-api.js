const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const validator = require('validator');
const rateLimit = require('express-rate-limit');
const userAddressRepository = require('../repositories/user-address-repository');
const userPaymentMethodRepository = require('../repositories/user-payment-method-repository');
const { userRepository } = require('../repositories/user-repository');
const { validatePaymentMethod } = require('../middleware/payment-method-validation');
const { logger } = require('../utils/logger');

// ============================================================================
// 🚨 CRITICAL SECURITY FIXES - FINANCIAL DATA PROTECTION
// ============================================================================

/**
 * JWT Authentication Middleware - CRITICAL SECURITY FIX
 */
const authenticateRequest = async (req, res, next) => {
  try {
    // Check for API key or JWT token
    const apiKey = req.headers['x-api-key'];
    const authHeader = req.headers.authorization;
    
    if (!apiKey && !authHeader) {
      logger.warn('SECURITY: Unauthenticated financial data request blocked', {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        endpoint: req.path
      });
      return res.status(401).json({
        success: false,
        error: 'Authentication required for financial data access',
        code: 'FINANCIAL_AUTH_REQUIRED'
      });
    }
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      // JWT token validation
      const token = authHeader.substring(7);
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret-key');
      req.user = decoded;
      req.merchantId = decoded.merchantId; // Use camelCase to match authService
      logger.debug('Financial data JWT authentication successful', { userId: decoded.userId });
    } else if (apiKey) {
      // Basic API key validation
      if (apiKey.length < 32) {
        return res.status(401).json({
          success: false,
          error: 'Invalid API key format for financial data',
          code: 'INVALID_FINANCIAL_API_KEY'
        });
      }
      req.apiKey = apiKey;
      logger.debug('Financial data API key authentication successful');
    } else {
      return res.status(401).json({
        success: false,
        error: 'Invalid authentication method for financial data',
        code: 'FINANCIAL_AUTH_INVALID'
      });
    }
    
    next();
  } catch (error) {
    logger.warn('SECURITY: Financial data authentication failed', {
      error: error.message,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    return res.status(401).json({
      success: false,
      error: 'Financial data authentication failed',
      code: 'FINANCIAL_AUTH_FAILED'
    });
  }
};

/**
 * User Ownership Validation - CRITICAL SECURITY FIX
 */
const validateUserOwnership = (req, res, next) => {
  try {
    const requestedUserId = req.params.userId || req.body.userId;
    const authenticatedUserId = req.user?.userId; // Use camelCase to match authService
    
    if (!requestedUserId) {
      return res.status(400).json({
        success: false,
        error: 'User ID is required for financial data access',
        code: 'USER_ID_REQUIRED'
      });
    }
    
    if (!authenticatedUserId) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required for financial data',
        code: 'FINANCIAL_AUTH_REQUIRED'
      });
    }
    
    // Only allow users to access their own financial data (unless admin)
    if (String(requestedUserId) !== String(authenticatedUserId) && !req.user?.isAdmin) {
      logger.warn('SECURITY: Unauthorized financial data access attempt', {
        requestedUserId,
        authenticatedUserId,
        ip: req.ip,
        userAgent: req.headers['user-agent']
      });
      
      return res.status(403).json({
        success: false,
        error: 'Access denied: Cannot access other users financial data',
        code: 'FINANCIAL_DATA_ACCESS_DENIED'
      });
    }
    
    next();
  } catch (error) {
    logger.error('Financial data ownership validation failed', error);
    return res.status(500).json({
      success: false,
      error: 'Authorization validation failed',
      code: 'FINANCIAL_AUTH_VALIDATION_ERROR'
    });
  }
};

/**
 * Financial Data Input Validation - CRITICAL SECURITY FIX
 */
const validateFinancialInput = (req, res, next) => {
  try {
    // Email validation
    if (req.body.email) {
      if (!validator.isEmail(req.body.email)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid email format',
          code: 'INVALID_EMAIL'
        });
      }
      req.body.email = validator.normalizeEmail(req.body.email);
    }
    
    // Address validation
    if (req.body.addressLine1 && req.body.addressLine1.length > 200) {
      return res.status(400).json({
        success: false,
        error: 'Address line too long',
        code: 'INVALID_ADDRESS_LENGTH'
      });
    }
    
    // Postal code validation
    if (req.body.postalCode && !/^[A-Za-z0-9\s-]{3,10}$/.test(req.body.postalCode)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid postal code format',
        code: 'INVALID_POSTAL_CODE'
      });
    }
    
    // Sanitize string inputs
    ['firstName', 'lastName', 'addressLine1', 'addressLine2', 'city', 'label', 'nickname'].forEach(field => {
      if (req.body[field]) {
        req.body[field] = validator.escape(String(req.body[field]).trim().slice(0, 200));
      }
    });
    
    next();
  } catch (error) {
    logger.error('Financial input validation failed', error);
    return res.status(400).json({
      success: false,
      error: 'Input validation failed',
      code: 'FINANCIAL_VALIDATION_ERROR'
    });
  }
};

/**
 * Financial Data Rate Limiting - CRITICAL SECURITY FIX
 */
const financialDataRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each user to 20 financial operations per window
  message: {
    success: false,
    error: 'Too many financial data requests',
    code: 'FINANCIAL_RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('SECURITY: Financial data rate limit exceeded', {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      endpoint: req.path
    });
    res.status(429).json({
      success: false,
      error: 'Too many financial data requests, please try again later',
      code: 'FINANCIAL_RATE_LIMIT_EXCEEDED'
    });
  }
});

/**
 * Secure Error Handling - CRITICAL SECURITY FIX
 */
const sanitizeErrorResponse = (error, context = '') => {
  // Log detailed error server-side
  logger.error(`Enhanced Schema API error ${context}`, {
    error: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString()
  });
  
  // Return generic error to client
  return {
    success: false,
    error: 'Financial data processing failed',
    code: 'FINANCIAL_DATA_ERROR',
    timestamp: new Date().toISOString()
  };
};

// Apply rate limiting to all routes
router.use(financialDataRateLimit);

// Apply authentication to ALL routes
router.use(authenticateRequest);

// ============================================================================
// ENHANCED SCHEMA: MULTIPLE ADDRESS MANAGEMENT
// ============================================================================

/**
 * Save user address with label and nickname - SECURITY FIXED
 * POST /api/addresses
 */
router.post('/addresses', validateFinancialInput, async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Save user address request',
    userId: req.body.userId,
    email: req.body.email,
    label: req.body.label || req.body.nickname,
    type: req.body.type || req.body.addressType
  });

  try {
    let { userId, email, firstName, lastName, type, nickname, ...addressData } = req.body;
    
    // 🚨 CRITICAL SECURITY FIX: Use authenticated user's ID
    const authenticatedUserId = req.user?.id || req.user?.user_id;
    
    // If userId provided in body, verify it matches authenticated user
    if (userId && String(userId) !== String(authenticatedUserId)) {
      return res.status(403).json({
        success: false,
        error: 'Cannot create addresses for other users',
        code: 'ADDRESS_CREATION_DENIED'
      });
    }
    
    // Force use of authenticated user's ID
    userId = authenticatedUserId;
    
    // If no userId from auth, create user first
    if (!userId && email) {
      logger.info('Enhanced Schema: Creating new user for address', { email, firstName, lastName });
      
      try {
        // Check if user already exists by email
        const existingUser = await userRepository.getUserByEmail(email);
        
        if (existingUser) {
          userId = existingUser.id;
          logger.info('Enhanced Schema: Found existing user', { userId, email });
        } else {
          // Create new user
          const newUser = await userRepository.createUser({
            email,
            firstName: firstName || 'User',
            lastName: lastName || '',
            phone: addressData.phone || null
          });
          userId = newUser.id;
          logger.info('Enhanced Schema: Created new user', { userId, email });
        }
      } catch (userError) {
        logger.error('Enhanced Schema: Failed to create user', userError);
        return res.status(500).json({ 
          success: false, 
          error: 'Failed to create user: ' + userError.message 
        });
      }
    }
    
    // Get firstName/lastName from request body (prioritize form input over user account)
    let userFirstName = req.body.firstName || firstName || addressData.firstName;
    let userLastName = req.body.lastName || lastName || addressData.lastName;
    
    // If names still not provided, get from user record as fallback
    if (!userFirstName || !userLastName) {
      try {
        const userDetails = await userRepository.getUserById(userId);
        userFirstName = userFirstName || userDetails?.first_name || 'User';
        userLastName = userLastName || userDetails?.last_name || 'User';
      } catch (error) {
        userFirstName = userFirstName || 'User';
        userLastName = userLastName || 'User';
      }
    }

    // Map API fields to repository expected fields - REAL DATABASE PERSISTENCE
    const mappedAddressData = {
      ...addressData,
      firstName: userFirstName,
      lastName: userLastName,
      addressType: type || addressData.addressType || 'shipping',
      label: nickname || addressData.label || 'Address'
    };
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID or email is required for address creation' 
      });
    }

    if (!mappedAddressData.city || !mappedAddressData.addressLine1) {
      return res.status(400).json({ 
        success: false, 
        error: 'Address line 1 and city are required' 
      });
    }

    logger.info('Enhanced Schema: About to save address', { 
      userId, 
      userIdType: typeof userId, 
      formFirstName: req.body.firstName,
      formLastName: req.body.lastName,
      finalFirstName: userFirstName,
      finalLastName: userLastName,
      requestBody: req.body,
      addressData: mappedAddressData 
    });
    
    console.log('🔍 FINAL DEBUG - About to save:', { userId, mappedAddressData });
    
    const address = await userAddressRepository.saveAddress(userId, mappedAddressData);
    
    res.json({ 
      success: true, 
      address,
      userId, // ✅ Return real integer ID for frontend to store
      message: `${mappedAddressData.label || 'Address'} saved successfully`
    });
  } catch (error) {
    const sanitizedError = sanitizeErrorResponse(error, 'address creation');
    res.status(500).json(sanitizedError);
  }
});

/**
 * Get all addresses for user - SECURITY FIXED
 * GET /api/addresses/:userId
 */
router.get('/addresses/:userId', validateUserOwnership, async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Get user addresses request',
    userId: req.params.userId
  });

  try {
    const addresses = await userAddressRepository.getUserAddresses(req.params.userId);
    
    res.json({ 
      success: true, 
      addresses,
      count: addresses.length
    });
  } catch (error) {
    logger.error('Failed to get user addresses:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Get shipping addresses for user (independent selection) - SECURITY FIXED
 * GET /api/addresses/:userId/shipping
 */
router.get('/addresses/:userId/shipping', validateUserOwnership, async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Get user shipping addresses request',
    userId: req.params.userId
  });

  try {
    const addresses = await userAddressRepository.getUserAddressesByType(req.params.userId, 'shipping');
    const defaults = await userAddressRepository.getDefaultAddresses(req.params.userId);
    
    res.json({ 
      success: true, 
      addresses,
      defaultAddress: defaults.shipping,
      count: addresses.length,
      type: 'shipping'
    });
  } catch (error) {
    logger.error('Failed to get user shipping addresses:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Get billing addresses for user (independent selection) - SECURITY FIXED
 * GET /api/addresses/:userId/billing
 */
router.get('/addresses/:userId/billing', validateUserOwnership, async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Get user billing addresses request',
    userId: req.params.userId
  });

  try {
    const addresses = await userAddressRepository.getUserAddressesByType(req.params.userId, 'billing');
    const defaults = await userAddressRepository.getDefaultAddresses(req.params.userId);
    
    res.json({ 
      success: true, 
      addresses,
      defaultAddress: defaults.billing,
      count: addresses.length,
      type: 'billing'
    });
  } catch (error) {
    logger.error('Failed to get user billing addresses:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Update address
 * PUT /api/addresses/:addressId
 */
router.put('/addresses/:addressId', async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Update address request',
    addressId: req.params.addressId,
    userId: req.body.userId,
    requestBody: req.body
  });

  try {
    const { userId, ...updateData } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID is required' 
      });
    }

    // Map camelCase frontend fields to snake_case database fields
    const mappedUpdateData = {
      ...updateData,
      // Map camelCase to snake_case
      first_name: updateData.firstName || updateData.first_name,
      last_name: updateData.lastName || updateData.last_name,
      address_line_1: updateData.addressLine1 || updateData.address_line_1,
      address_line_2: updateData.addressLine2 || updateData.address_line_2,
      state_province: updateData.stateProvince || updateData.state_province || updateData.state,
      postal_code: updateData.postalCode || updateData.postal_code,
      country_code: updateData.countryCode || updateData.country_code || updateData.country,
      delivery_instructions: updateData.deliveryInstructions || updateData.delivery_instructions,
      address_type: updateData.addressType || updateData.address_type,
      is_default_shipping: updateData.isDefaultShipping || updateData.is_default_shipping,
      is_default_billing: updateData.isDefaultBilling || updateData.is_default_billing
    };

    // Remove undefined camelCase fields to avoid conflicts
    delete mappedUpdateData.firstName;
    delete mappedUpdateData.lastName;
    delete mappedUpdateData.addressLine1;
    delete mappedUpdateData.addressLine2;
    delete mappedUpdateData.stateProvince;
    delete mappedUpdateData.postalCode;
    delete mappedUpdateData.countryCode;
    delete mappedUpdateData.deliveryInstructions;
    delete mappedUpdateData.addressType;
    delete mappedUpdateData.isDefaultShipping;
    delete mappedUpdateData.isDefaultBilling;

    logger.info('Enhanced Schema: Mapped update data:', { 
      originalData: updateData,
      mappedData: mappedUpdateData 
    });

    const address = await userAddressRepository.updateAddress(req.params.addressId, userId, mappedUpdateData);
    
    res.json({ 
      success: true, 
      address,
      message: 'Address updated successfully'
    });
  } catch (error) {
    logger.error('Failed to update address:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Delete address
 * DELETE /api/addresses/:addressId
 */
router.delete('/addresses/:addressId', async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Delete address request',
    addressId: req.params.addressId,
    userId: req.body.userId
  });

  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID is required' 
      });
    }

    const deletedAddress = await userAddressRepository.deleteAddress(req.params.addressId, userId);
    
    res.json({ 
      success: true, 
      deletedAddress,
      message: 'Address deleted successfully'
    });
  } catch (error) {
    logger.error('Failed to delete address:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Set address as default (independent shipping/billing)
 * POST /api/addresses/:addressId/default
 */
router.post('/addresses/:addressId/default', async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Set address as default request',
    addressId: req.params.addressId,
    userId: req.body.userId,
    defaultType: req.body.defaultType
  });

  try {
    const { userId, defaultType = 'both' } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID is required' 
      });
    }

    if (!['shipping', 'billing', 'both'].includes(defaultType)) {
      return res.status(400).json({ 
        success: false, 
        error: 'defaultType must be shipping, billing, or both' 
      });
    }

    const address = await userAddressRepository.setAsDefault(req.params.addressId, userId, defaultType);
    
    res.json({ 
      success: true, 
      address,
      message: `Address set as default ${defaultType} successfully`
    });
  } catch (error) {
    logger.error('Failed to set address as default:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Track address usage
 * POST /api/addresses/:addressId/used
 */
router.post('/addresses/:addressId/used', async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Track address usage',
    addressId: req.params.addressId,
    userId: req.body.userId
  });

  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID is required' 
      });
    }

    const usage = await userAddressRepository.trackUsage(req.params.addressId, userId);
    
    res.json({ 
      success: true, 
      usage,
      message: 'Address usage tracked successfully'
    });
  } catch (error) {
    logger.error('Failed to track address usage:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// ============================================================================
// ENHANCED SCHEMA: MULTIPLE PAYMENT METHOD MANAGEMENT
// ============================================================================

/**
 * Save user payment method with label and nickname - SECURITY FIXED
 * POST /api/payment-methods
 */
router.post('/payment-methods', validateFinancialInput, validatePaymentMethod, async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Save user payment method request',
    userId: req.body.userId,
    email: req.body.email,
    label: req.body.label || req.body.nickname,
    type: req.body.type || req.body.paymentType
  });

  try {
    let { userId, email, firstName, lastName, type, nickname, ...paymentData } = req.body;
    
    // 🚨 CRITICAL SECURITY FIX: Use authenticated user's ID
    const authenticatedUserId = req.user?.id || req.user?.user_id;
    
    // If userId provided in body, verify it matches authenticated user
    if (userId && String(userId) !== String(authenticatedUserId)) {
      return res.status(403).json({
        success: false,
        error: 'Cannot create payment methods for other users',
        code: 'PAYMENT_METHOD_CREATION_DENIED'
      });
    }
    
    // Force use of authenticated user's ID
    userId = authenticatedUserId;
    
    // If no userId from auth, create user first
    if (!userId && email) {
      logger.info('Enhanced Schema: Creating new user for payment method', { email, firstName, lastName });
      
      try {
        // Check if user already exists by email
        const existingUser = await userRepository.getUserByEmail(email);
        
        if (existingUser) {
          userId = existingUser.id;
          logger.info('Enhanced Schema: Found existing user', { userId, email });
        } else {
          // Create new user
          const newUser = await userRepository.createUser({
            email,
            firstName: firstName || 'User',
            lastName: lastName || '',
            phone: paymentData.phone || null
          });
          userId = newUser.id;
          logger.info('Enhanced Schema: Created new user', { userId, email });
        }
      } catch (userError) {
        logger.error('Enhanced Schema: Failed to create user', userError);
        return res.status(500).json({ 
          success: false, 
          error: 'Failed to create user: ' + userError.message 
        });
      }
    }
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID or email is required for payment method creation' 
      });
    }

    // Map API fields to repository expected fields
    // Note: paymentData has already been validated and normalized by validatePaymentMethod middleware
    const mappedPaymentData = {
      ...paymentData,
      paymentType: type || paymentData.paymentType || 'credit_card',
      label: nickname || paymentData.label || 'Personal Card'
    };

    const paymentMethod = await userPaymentMethodRepository.savePaymentMethod(userId, mappedPaymentData);
    
    // Log successful creation with validation details
    logger.info('Enhanced Schema: Payment method created successfully', {
      userId,
      paymentMethodId: paymentMethod.id,
      type: mappedPaymentData.paymentType,
      label: mappedPaymentData.label,
      hasValidExpiry: !!(paymentMethod.expiry_month && paymentMethod.expiry_year),
      expiryFormatted: paymentMethod.expiry_month && paymentMethod.expiry_year ? 
        `${String(paymentMethod.expiry_month).padStart(2, '0')}/${paymentMethod.expiry_year}` : null
    });
    
    res.json({ 
      success: true, 
      paymentMethod,
      userId, // ✅ Return real integer ID for frontend to store
      message: `${mappedPaymentData.label || 'Payment method'} saved successfully`,
      validation: {
        expiry: paymentMethod.expiry_month && paymentMethod.expiry_year ? 
          `${String(paymentMethod.expiry_month).padStart(2, '0')}/${paymentMethod.expiry_year}` : null,
        validated: true
      }
    });
  } catch (error) {
    logger.error('Failed to save Enhanced Schema payment method:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Get all payment methods for user - SECURITY FIXED
 * GET /api/payment-methods/:userId
 */
router.get('/payment-methods/:userId', validateUserOwnership, async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Get user payment methods request',
    userId: req.params.userId
  });

  try {
    const paymentMethods = await userPaymentMethodRepository.getUserPaymentMethods(req.params.userId);
    
    res.json({ 
      success: true, 
      paymentMethods,
      count: paymentMethods.length
    });
  } catch (error) {
    logger.error('Failed to get user payment methods:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Update payment method
 * PUT /api/payment-methods/:paymentMethodId
 */
router.put('/payment-methods/:paymentMethodId', validatePaymentMethod, async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Update payment method request',
    paymentMethodId: req.params.paymentMethodId,
    userId: req.body.userId
  });

  try {
    const { userId, ...updateData } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID is required' 
      });
    }

    const paymentMethod = await userPaymentMethodRepository.updatePaymentMethod(req.params.paymentMethodId, userId, updateData);
    
    res.json({ 
      success: true, 
      paymentMethod,
      message: 'Payment method updated successfully'
    });
  } catch (error) {
    logger.error('Failed to update payment method:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Delete payment method
 * DELETE /api/payment-methods/:paymentMethodId
 */
router.delete('/payment-methods/:paymentMethodId', async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Delete payment method request',
    paymentMethodId: req.params.paymentMethodId,
    userId: req.body.userId
  });

  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID is required' 
      });
    }

    const deletedPaymentMethod = await userPaymentMethodRepository.deletePaymentMethod(req.params.paymentMethodId, userId);
    
    res.json({ 
      success: true, 
      deletedPaymentMethod,
      message: 'Payment method deleted successfully'
    });
  } catch (error) {
    logger.error('Failed to delete payment method:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Set payment method as default
 * POST /api/payment-methods/:paymentMethodId/default
 */
router.post('/payment-methods/:paymentMethodId/default', async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Set payment method as default request',
    paymentMethodId: req.params.paymentMethodId,
    userId: req.body.userId
  });

  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID is required' 
      });
    }

    const paymentMethod = await userPaymentMethodRepository.setAsDefault(req.params.paymentMethodId, userId);
    
    res.json({ 
      success: true, 
      paymentMethod,
      message: 'Payment method set as default successfully'
    });
  } catch (error) {
    logger.error('Failed to set payment method as default:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Track payment method usage
 * POST /api/payment-methods/:paymentMethodId/used
 */
router.post('/payment-methods/:paymentMethodId/used', async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Track payment method usage',
    paymentMethodId: req.params.paymentMethodId,
    userId: req.body.userId
  });

  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID is required' 
      });
    }

    const usage = await userPaymentMethodRepository.trackUsage(req.params.paymentMethodId, userId);
    
    res.json({ 
      success: true, 
      usage,
      message: 'Payment method usage tracked successfully'
    });
  } catch (error) {
    logger.error('Failed to track payment method usage:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Update billing address for payment method
 * PUT /api/payment-methods/:paymentMethodId/billing-address
 */
router.put('/payment-methods/:paymentMethodId/billing-address', async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Update payment method billing address',
    paymentMethodId: req.params.paymentMethodId,
    userId: req.body.userId,
    billingAddressId: req.body.billingAddressId
  });

  try {
    const { userId, billingAddressId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID is required' 
      });
    }

    if (!billingAddressId) {
      return res.status(400).json({ 
        success: false, 
        error: 'Billing address ID is required' 
      });
    }

    const paymentMethod = await userPaymentMethodRepository.updateBillingAddress(
      req.params.paymentMethodId, 
      billingAddressId, 
      userId
    );
    
    res.json({ 
      success: true, 
      paymentMethod,
      message: 'Payment method billing address updated successfully'
    });
  } catch (error) {
    logger.error('Failed to update payment method billing address:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// ============================================================================
// ENHANCED SCHEMA: COMPLETE USER PROFILE
// ============================================================================

/**
 * Get complete user profile (user + addresses + payment methods + preferences) - SECURITY FIXED
 * GET /api/users/:userId/profile
 */
router.get('/users/:userId/profile', validateUserOwnership, async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Get complete user profile request',
    userId: req.params.userId
  });

  try {
    const userId = req.params.userId;

    // Get all user data in parallel
    const [addresses, paymentMethods, defaultAddresses, defaultPaymentMethod] = await Promise.all([
      userAddressRepository.getUserAddresses(userId),
      userPaymentMethodRepository.getUserPaymentMethods(userId),
      userAddressRepository.getDefaultAddresses(userId),
      userPaymentMethodRepository.getDefaultPaymentMethod(userId)
    ]);

    // Organize addresses by type
    const addressesByType = {
      shipping: addresses.filter(addr => addr.address_type === 'shipping' || addr.address_type === 'both'),
      billing: addresses.filter(addr => addr.address_type === 'billing' || addr.address_type === 'both'),
      all: addresses
    };

    const profile = {
      userId,
      addresses: addressesByType,
      paymentMethods,
      defaults: {
        shippingAddress: defaultAddresses.shipping,
        billingAddress: defaultAddresses.billing,
        paymentMethod: defaultPaymentMethod
      },
      stats: {
        totalAddresses: addresses.length,
        totalPaymentMethods: paymentMethods.length,
        shippingAddresses: addressesByType.shipping.length,
        billingAddresses: addressesByType.billing.length
      }
    };

    res.json({ 
      success: true, 
      profile,
      message: 'Complete user profile retrieved successfully'
    });
  } catch (error) {
    logger.error('Failed to get complete user profile:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Get user's default addresses and payment method - SECURITY FIXED
 * GET /api/users/:userId/defaults
 */
router.get('/users/:userId/defaults', validateUserOwnership, async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Get user defaults request',
    userId: req.params.userId
  });

  try {
    const userId = req.params.userId;

    const [defaultAddresses, defaultPaymentMethod] = await Promise.all([
      userAddressRepository.getDefaultAddresses(userId),
      userPaymentMethodRepository.getDefaultPaymentMethod(userId)
    ]);

    const defaults = {
      shippingAddress: defaultAddresses.shipping,
      billingAddress: defaultAddresses.billing,
      paymentMethod: defaultPaymentMethod
    };

    res.json({ 
      success: true, 
      defaults,
      message: 'User defaults retrieved successfully'
    });
  } catch (error) {
    logger.error('Failed to get user defaults:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

module.exports = router; 