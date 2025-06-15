const { dbConnection } = require('../database/db-connection');
const { logger } = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');

class UserPaymentMethodRepository {
  constructor() {
    this.db = dbConnection;
  }

  /**
   * Save user payment method with billing address validation
   */
  async savePaymentMethod(userId, paymentData) {
    const paymentMethodId = uuidv4();
    
    // Validate billing address if provided
    if (paymentData.billingAddressId || paymentData.billing_address_id) {
      const billingAddressId = paymentData.billingAddressId || paymentData.billing_address_id;
      const isValidBilling = await this.validateBillingAddress(billingAddressId, userId);
      if (!isValidBilling) {
        throw new Error('Invalid billing address for user');
      }
    }
    
    const query = `
      INSERT INTO identity_service.user_payment_methods 
      (id, user_id, payment_type, provider, label, last_four_digits, 
       expiry_month, expiry_year, payment_token, billing_address_id, is_default, 
       created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
      RETURNING *;
    `;

    const values = [
      paymentMethodId,
      userId,
      paymentData.paymentType || 'credit_card',
      paymentData.provider || null,
      paymentData.label || 'Payment Method',
      paymentData.lastFourDigits || paymentData.last_four_digits || null,
      paymentData.expiryMonth || paymentData.expiry_month || null,
      paymentData.expiryYear || paymentData.expiry_year || null,
      paymentData.paymentToken || paymentData.payment_token || null,
      paymentData.billingAddressId || paymentData.billing_address_id || null,
      paymentData.isDefault || false
    ];

    try {
      // If this is set as default, unset other defaults for this user
      if (paymentData.isDefault) {
        await this.unsetDefaultPaymentMethods(userId);
      }

      const result = await this.db.query(query, values);
      
      logger.info({
        message: 'Enhanced Schema payment method saved successfully',
        userId,
        paymentMethodId,
        label: paymentData.label,
        type: paymentData.paymentType,
        billingAddressId: paymentData.billingAddressId || paymentData.billing_address_id
      });
      
      return result[0];
    } catch (error) {
      logger.error('Failed to save Enhanced Schema payment method:', error);
      throw error;
    }
  }

  /**
   * Get all payment methods for user with full billing address details
   */
  async getUserPaymentMethods(userId) {
    const query = `
      SELECT 
        pm.*,
        ba.id as billing_address_id,
        ba.label as billing_address_label,
        ba.first_name as billing_first_name,
        ba.last_name as billing_last_name,
        ba.company as billing_company,
        ba.address_line_1 as billing_address_line_1,
        ba.address_line_2 as billing_address_line_2,
        ba.city as billing_city,
        ba.state_province as billing_state,
        ba.postal_code as billing_postal_code,
        ba.country_code as billing_country_code,
        ba.phone as billing_phone
      FROM identity_service.user_payment_methods pm
      LEFT JOIN identity_service.user_addresses ba ON pm.billing_address_id = ba.id
      WHERE pm.user_id = $1 
      ORDER BY pm.is_default DESC, pm.created_at DESC;
    `;

    try {
      const result = await this.db.query(query, [userId]);
      
              // Transform result to include nested billing address object
        return result.map(row => {
          const paymentMethod = {
            id: row.id,
            user_id: row.user_id,
            payment_type: row.payment_type,
            provider: row.provider,
            label: row.label,
            last_four_digits: row.last_four_digits,
            expiry_month: row.expiry_month,
            expiry_year: row.expiry_year,
            payment_token: row.payment_token,
            is_default: row.is_default,
            created_at: row.created_at,
            updated_at: row.updated_at
          };

        // Add billing address if exists
        if (row.billing_address_id) {
          paymentMethod.billingAddress = {
            id: row.billing_address_id,
            label: row.billing_address_label,
            firstName: row.billing_first_name,
            lastName: row.billing_last_name,
            company: row.billing_company,
            addressLine1: row.billing_address_line_1,
            addressLine2: row.billing_address_line_2,
            city: row.billing_city,
            stateProvince: row.billing_state,
            postalCode: row.billing_postal_code,
            countryCode: row.billing_country_code,
            phone: row.billing_phone,
            fullAddress: this.formatFullAddress({
              addressLine1: row.billing_address_line_1,
              addressLine2: row.billing_address_line_2,
              city: row.billing_city,
              stateProvince: row.billing_state,
              postalCode: row.billing_postal_code,
              countryCode: row.billing_country_code
            })
          };
        }

        return paymentMethod;
      });
    } catch (error) {
      logger.error('Failed to get user payment methods:', error);
      throw error;
    }
  }

  /**
   * Get payment method by ID
   */
  async getPaymentMethodById(paymentMethodId, userId = null) {
    let query = `
      SELECT pm.*, ua.label as billing_address_label, ua.city as billing_city, ua.state_province as billing_state
      FROM identity_service.user_payment_methods pm
      LEFT JOIN identity_service.user_addresses ua ON pm.billing_address_id = ua.id
      WHERE pm.id = $1
    `;
    let values = [paymentMethodId];
    
    if (userId) {
      query += ` AND pm.user_id = $2`;
      values.push(userId);
    }

    try {
      const result = await this.db.query(query, values);
      return result[0] || null;
    } catch (error) {
      logger.error('Failed to get payment method by ID:', error);
      throw error;
    }
  }

  /**
   * Update payment method
   */
  async updatePaymentMethod(paymentMethodId, userId, updateData) {
    const setClause = [];
    const values = [];
    let paramIndex = 1;

    // Build dynamic update query
    const updateableFields = [
      'payment_type', 'provider', 'label', 'last_four_digits',
      'expiry_month', 'expiry_year', 'payment_token', 'billing_address_id',
      'is_default'
    ];

    updateableFields.forEach(field => {
      if (updateData[field] !== undefined) {
        setClause.push(`${field} = $${paramIndex}`);
        values.push(updateData[field]);
        paramIndex++;
      }
    });

    if (setClause.length === 0) {
      throw new Error('No fields to update');
    }

    setClause.push(`updated_at = NOW()`);
    values.push(paymentMethodId, userId);

    const query = `
      UPDATE identity_service.user_payment_methods 
      SET ${setClause.join(', ')}
      WHERE id = $${paramIndex} AND user_id = $${paramIndex + 1}
      RETURNING *;
    `;

    try {
      // If setting as default, unset other defaults
      if (updateData.is_default) {
        await this.unsetDefaultPaymentMethods(userId);
      }

      const result = await this.db.query(query, values);
      
      if (result.length === 0) {
        throw new Error('Payment method not found or access denied');
      }

      logger.info({
        message: 'Payment method updated successfully',
        paymentMethodId,
        userId
      });

      return result[0];
    } catch (error) {
      logger.error('Failed to update payment method:', error);
      throw error;
    }
  }

  /**
   * Delete payment method
   */
  async deletePaymentMethod(paymentMethodId, userId) {
    const query = `
      DELETE FROM identity_service.user_payment_methods 
      WHERE id = $1 AND user_id = $2
      RETURNING *;
    `;

    try {
      const result = await this.db.query(query, [paymentMethodId, userId]);
      
      if (result.length === 0) {
        throw new Error('Payment method not found or access denied');
      }

      logger.info({
        message: 'Payment method deleted successfully',
        paymentMethodId,
        userId
      });

      return result[0];
    } catch (error) {
      logger.error('Failed to delete payment method:', error);
      throw error;
    }
  }

  /**
   * Set payment method as default
   */
  async setAsDefault(paymentMethodId, userId) {
    try {
      // Unset other defaults for this user
      await this.unsetDefaultPaymentMethods(userId);

      // Set this payment method as default
      const query = `
        UPDATE identity_service.user_payment_methods 
        SET is_default = true, updated_at = NOW()
        WHERE id = $1 AND user_id = $2
        RETURNING *;
      `;

      const result = await this.db.query(query, [paymentMethodId, userId]);
      
      if (result.length === 0) {
        throw new Error('Payment method not found or access denied');
      }

      logger.info({
        message: 'Payment method set as default',
        paymentMethodId,
        userId
      });

      return result[0];
    } catch (error) {
      logger.error('Failed to set payment method as default:', error);
      throw error;
    }
  }

  /**
   * Track payment method usage for smart defaults
   */
  async trackUsage(paymentMethodId, userId) {
    const query = `
      UPDATE identity_service.user_payment_methods 
      SET usage_frequency = usage_frequency + 1, 
          last_used = NOW(),
          updated_at = NOW()
      WHERE id = $1 AND user_id = $2
      RETURNING usage_frequency, last_used;
    `;

    try {
      const result = await this.db.query(query, [paymentMethodId, userId]);
      
      logger.info({
        message: 'Payment method usage tracked',
        paymentMethodId,
        userId,
        newFrequency: result[0]?.usage_frequency
      });

      return result[0];
    } catch (error) {
      logger.error('Failed to track payment method usage:', error);
      throw error;
    }
  }

  /**
   * Unset default payment methods for user
   */
  async unsetDefaultPaymentMethods(userId) {
    const query = `
      UPDATE identity_service.user_payment_methods 
      SET is_default = false, updated_at = NOW()
      WHERE user_id = $1 AND is_default = true;
    `;

    try {
      await this.db.query(query, [userId]);
    } catch (error) {
      logger.error('Failed to unset default payment methods:', error);
      throw error;
    }
  }

  /**
   * Get user's default payment method
   */
  async getDefaultPaymentMethod(userId) {
    const query = `
      SELECT pm.*, ua.label as billing_address_label, ua.city as billing_city, ua.state_province as billing_state
      FROM identity_service.user_payment_methods pm
      LEFT JOIN identity_service.user_addresses ua ON pm.billing_address_id = ua.id
      WHERE pm.user_id = $1 AND pm.is_default = true
      LIMIT 1;
    `;

    try {
      const result = await this.db.query(query, [userId]);
      return result[0] || null;
    } catch (error) {
      logger.error('Failed to get default payment method:', error);
      throw error;
    }
  }

  /**
   * Get payment methods by verification status
   */
  async getPaymentMethodsByStatus(userId, verificationStatus) {
    const query = `
      SELECT pm.*, ua.label as billing_address_label, ua.city as billing_city, ua.state_province as billing_state
      FROM identity_service.user_payment_methods pm
      LEFT JOIN identity_service.user_addresses ua ON pm.billing_address_id = ua.id
      WHERE pm.user_id = $1 AND pm.verification_status = $2
      ORDER BY pm.is_default DESC, pm.created_at DESC;
    `;

    try {
      const result = await this.db.query(query, [userId, verificationStatus]);
      return result;
    } catch (error) {
      logger.error('Failed to get payment methods by status:', error);
      throw error;
    }
  }

  /**
   * Update billing address for payment method
   */
  async updateBillingAddress(paymentMethodId, billingAddressId, userId) {
    // Validate billing address belongs to user
    const isValidBilling = await this.validateBillingAddress(billingAddressId, userId);
    
    if (!isValidBilling) {
      throw new Error('Invalid billing address for user');
    }
    
    const query = `
      UPDATE identity_service.user_payment_methods 
      SET billing_address_id = $1, updated_at = NOW()
      WHERE id = $2 AND user_id = $3
      RETURNING *;
    `;

    try {
      const result = await this.db.query(query, [billingAddressId, paymentMethodId, userId]);
      
      if (result.length === 0) {
        throw new Error('Payment method not found or access denied');
      }

      logger.info({
        message: 'Payment method billing address updated',
        paymentMethodId,
        billingAddressId,
        userId
      });

      return result[0];
    } catch (error) {
      logger.error('Failed to update payment method billing address:', error);
      throw error;
    }
  }

  /**
   * Validate billing address belongs to user and supports billing
   */
  async validateBillingAddress(billingAddressId, userId) {
    const query = `
      SELECT id, user_id, address_type 
      FROM identity_service.user_addresses 
      WHERE id = $1 AND user_id = $2 AND (address_type = 'billing' OR address_type = 'both')
    `;

    try {
      const result = await this.db.query(query, [billingAddressId, userId]);
      return result.length > 0;
    } catch (error) {
      logger.error('Failed to validate billing address:', error);
      return false;
    }
  }

  /**
   * Format full address string
   */
  formatFullAddress(address) {
    const parts = [];
    
    if (address.addressLine1) parts.push(address.addressLine1);
    if (address.addressLine2) parts.push(address.addressLine2);
    
    const cityStateZip = [];
    if (address.city) cityStateZip.push(address.city);
    if (address.stateProvince) cityStateZip.push(address.stateProvince);
    if (address.postalCode) cityStateZip.push(address.postalCode);
    
    if (cityStateZip.length > 0) {
      parts.push(cityStateZip.join(' '));
    }
    
    if (address.countryCode && address.countryCode !== 'US') {
      parts.push(address.countryCode);
    }
    
    return parts.join(', ');
  }
}

module.exports = new UserPaymentMethodRepository(); 