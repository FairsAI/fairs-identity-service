const express = require('express');
const router = express.Router();
const userAddressRepository = require('../repositories/user-address-repository');
const userPaymentMethodRepository = require('../repositories/user-payment-method-repository');
const { userRepository } = require('../repositories/user-repository');
const { logger } = require('../utils/logger');

// ============================================================================
// ENHANCED SCHEMA: MULTIPLE ADDRESS MANAGEMENT
// ============================================================================

/**
 * Save user address with label and nickname
 * POST /api/addresses
 */
router.post('/addresses', async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Save user address request',
    userId: req.body.userId,
    email: req.body.email,
    label: req.body.label || req.body.nickname,
    type: req.body.type || req.body.addressType
  });

  try {
    let { userId, email, firstName, lastName, type, nickname, ...addressData } = req.body;
    
    // If no userId provided, create user first
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
    
    // Map API fields to repository expected fields
    const mappedAddressData = {
      ...addressData,
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

    const address = await userAddressRepository.saveAddress(userId, mappedAddressData);
    
    res.json({ 
      success: true, 
      address,
      userId, // ✅ Return real integer ID for frontend to store
      message: `${mappedAddressData.label || 'Address'} saved successfully`
    });
  } catch (error) {
    logger.error('Failed to save Enhanced Schema address:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Get all addresses for user
 * GET /api/addresses/:userId
 */
router.get('/addresses/:userId', async (req, res) => {
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
 * Get shipping addresses for user (independent selection)
 * GET /api/addresses/:userId/shipping
 */
router.get('/addresses/:userId/shipping', async (req, res) => {
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
 * Get billing addresses for user (independent selection)
 * GET /api/addresses/:userId/billing
 */
router.get('/addresses/:userId/billing', async (req, res) => {
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

    const address = await userAddressRepository.updateAddress(req.params.addressId, userId, updateData);
    
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
 * Save user payment method with label and nickname
 * POST /api/payment-methods
 */
router.post('/payment-methods', async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Save user payment method request',
    userId: req.body.userId,
    email: req.body.email,
    label: req.body.label || req.body.nickname,
    type: req.body.type || req.body.paymentType
  });

  try {
    let { userId, email, firstName, lastName, type, nickname, ...paymentData } = req.body;
    
    // If no userId provided, create user first
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
    const mappedPaymentData = {
      ...paymentData,
      paymentType: type || paymentData.paymentType || 'card',
      label: nickname || paymentData.label || 'Payment Method'
    };

    const paymentMethod = await userPaymentMethodRepository.savePaymentMethod(userId, mappedPaymentData);
    
    res.json({ 
      success: true, 
      paymentMethod,
      userId, // ✅ Return real integer ID for frontend to store
      message: `${paymentData.label || 'Payment method'} saved successfully`
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
 * Get all payment methods for user
 * GET /api/payment-methods/:userId
 */
router.get('/payment-methods/:userId', async (req, res) => {
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
router.put('/payment-methods/:paymentMethodId', async (req, res) => {
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
 * Get complete user profile (user + addresses + payment methods + preferences)
 * GET /api/users/:userId/profile
 */
router.get('/users/:userId/profile', async (req, res) => {
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
 * Get user's default addresses and payment method
 * GET /api/users/:userId/defaults
 */
router.get('/users/:userId/defaults', async (req, res) => {
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

// ============================================================================
// USER MANAGEMENT (Source of Truth)
// ============================================================================

/**
 * Create user (Identity Service is Source of Truth)
 * POST /api/users
 */
router.post('/users', async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: User creation request (handled internally)',
    userId: req.body.id,
    email: req.body.email
  });

  try {
    const { id, email, firstName, lastName, phone, temporary, consented } = req.body;
    
    if (!id || !email) {
      return res.status(400).json({ 
        success: false, 
        error: 'User ID and email are required' 
      });
    }

    // Identity service handles user data internally when addresses/payments are created
    // This endpoint exists for API compatibility but user data is managed automatically
    logger.info('Enhanced Schema: User data will be managed automatically when addresses/payments are created', { 
      userId: id, 
      email 
    });
    
    res.json({ 
      success: true, 
      user: {
        id,
        email,
        firstName,
        lastName,
        phone,
        temporary: temporary || false,
        consented: consented || false
      },
      message: 'User data accepted - will be managed automatically by identity service'
    });
  } catch (error) {
    logger.error('User creation request failed:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

/**
 * Get user by ID
 * GET /api/users/:userId
 */
router.get('/users/:userId', async (req, res) => {
  logger.info({
    message: 'Enhanced Schema: Get user request',
    userId: req.params.userId
  });

  try {
    const userId = req.params.userId;
    
    // Return a basic user profile based on address/payment data if available
    // This is a placeholder implementation since users are managed internally
    res.json({ 
      success: true, 
      user: {
        id: userId,
        email: `${userId}@temp.fairs.com`,
        temporary: true,
        message: 'User data managed internally by identity service'
      }
    });
  } catch (error) {
    logger.error('Get user request failed:', error);
    res.status(404).json({ 
      success: false, 
      error: 'User not found - user data managed internally' 
    });
  }
});

module.exports = router; 