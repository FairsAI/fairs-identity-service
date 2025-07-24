const { dbConnection } = require('../database/db-connection');
const { logger } = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');

class UserAddressRepository {
  constructor() {
    this.db = dbConnection;
  }

  /**
   * Save user address with label and nickname support
   * HYBRID APPROACH: UUID Primary Key (secure) + INTEGER user_id FK (efficient)
   */
  async saveAddress(userId, addressData) {
    // Let database auto-generate UUID primary key (secure, distributed)
    // Use INTEGER user_id foreign key (efficient lookups)
    const query = `
      INSERT INTO identity_service.user_addresses 
      (user_id, address_type, label, first_name, last_name, company, 
       address_line_1, address_line_2, city, state_province, postal_code, country_code, 
       phone, delivery_instructions, is_default_shipping, is_default_billing, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW())
      RETURNING *;
    `;

    const addressType = addressData.addressType || 'both';
    const isDefaultShipping = addressData.isDefaultShipping || addressData.isDefault || false;
    const isDefaultBilling = addressData.isDefaultBilling || addressData.isDefault || false;

    // Debug: Log what we're receiving
    logger.info('Repository Debug - Address Data:', { 
      addressData,
      firstName: addressData.firstName,
      lastName: addressData.lastName,
      first_name: addressData.first_name,
      last_name: addressData.last_name 
    });

    const values = [
      userId,
      addressType,
      addressData.label || 'Address',
      addressData.firstName || addressData.first_name || addressData.email?.split('@')[0] || 'User',
      addressData.lastName || addressData.last_name || 'User',
      addressData.company || null,
      addressData.addressLine1 || addressData.address_line_1,
      addressData.addressLine2 || addressData.address_line_2 || null,
      addressData.city,
      addressData.stateProvince || addressData.state_province || addressData.state,
      addressData.postalCode || addressData.postal_code,
      addressData.countryCode || addressData.country_code || addressData.country || 'US',
      addressData.phone || null,
      addressData.deliveryInstructions || addressData.delivery_instructions || null,
      isDefaultShipping,
      isDefaultBilling
    ];

    try {
      // If this is set as default shipping, unset other default shipping addresses
      if (isDefaultShipping && (addressType === 'shipping' || addressType === 'both')) {
        await this.unsetDefaultShippingAddresses(userId);
      }
      
      // If this is set as default billing, unset other default billing addresses
      if (isDefaultBilling && (addressType === 'billing' || addressType === 'both')) {
        await this.unsetDefaultBillingAddresses(userId);
      }

      const result = await this.db.query(query, values);
      
      logger.info({
        message: 'Enhanced Schema address saved successfully',
        userId,
        addressId: result[0].id,
        label: addressData.label,
        type: addressData.addressType
      });
      
      return result[0];
    } catch (error) {
      logger.error('Failed to save Enhanced Schema address:', error);
      throw error;
    }
  }

  /**
   * Get all addresses for user
   */
  async getUserAddresses(userId) {
    const query = `
      SELECT * FROM identity_service.user_addresses 
      WHERE user_id = $1 
      ORDER BY is_default_shipping DESC, is_default_billing DESC, created_at DESC;
    `;

    try {
      const result = await this.db.query(query, [userId]);
      return result;
    } catch (error) {
      logger.error('Failed to get user addresses:', error);
      throw error;
    }
  }

  /**
   * Get addresses by type (shipping, billing, both)
   */
  async getUserAddressesByType(userId, addressType) {
    const defaultColumn = addressType === 'shipping' ? 'is_default_shipping' : 'is_default_billing';
    const query = `
      SELECT * FROM identity_service.user_addresses 
      WHERE user_id = $1 AND (address_type = $2 OR address_type = 'both')
      ORDER BY ${defaultColumn} DESC, created_at DESC;
    `;

    try {
      const result = await this.db.query(query, [userId, addressType]);
      return result;
    } catch (error) {
      logger.error(`Failed to get user ${addressType} addresses:`, error);
      throw error;
    }
  }

  /**
   * Get address by ID
   */
  async getAddressById(addressId, userId = null) {
    let query = `SELECT * FROM identity_service.user_addresses WHERE id = $1`;
    let values = [addressId];
    
    if (userId) {
      query += ` AND user_id = $2`;
      values.push(userId);
    }

    try {
      const result = await this.db.query(query, values);
      return result[0] || null;
    } catch (error) {
      logger.error('Failed to get address by ID:', error);
      throw error;
    }
  }

  /**
   * Update address
   */
  async updateAddress(addressId, userId, updateData) {
    const setClause = [];
    const values = [];
    let paramIndex = 1;

    // Build dynamic update query
    const updateableFields = [
      'label', 'first_name', 'last_name', 'company',
      'address_line_1', 'address_line_2', 'city', 'state_province',
      'postal_code', 'country_code', 'phone', 'delivery_instructions',
      'address_type', 'is_default_shipping', 'is_default_billing'
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
    values.push(addressId, userId);

    const query = `
      UPDATE identity_service.user_addresses 
      SET ${setClause.join(', ')}
      WHERE id = $${paramIndex} AND user_id = $${paramIndex + 1}
      RETURNING *;
    `;

    try {
      // If setting as default shipping, unset other default shipping addresses
      if (updateData.is_default_shipping) {
        await this.unsetDefaultShippingAddresses(userId);
      }
      
      // If setting as default billing, unset other default billing addresses
      if (updateData.is_default_billing) {
        await this.unsetDefaultBillingAddresses(userId);
      }

      const result = await this.db.query(query, values);
      
      if (result.length === 0) {
        throw new Error('Address not found or access denied');
      }

      logger.info({
        message: 'Address updated successfully',
        addressId,
        userId
      });

      return result[0];
    } catch (error) {
      logger.error('Failed to update address:', error);
      throw error;
    }
  }

  /**
   * Delete address
   */
  async deleteAddress(addressId, userId) {
    const query = `
      DELETE FROM identity_service.user_addresses 
      WHERE id = $1 AND user_id = $2
      RETURNING *;
    `;

    try {
      const result = await this.db.query(query, [addressId, userId]);
      
      if (result.length === 0) {
        throw new Error('Address not found or access denied');
      }

      logger.info({
        message: 'Address deleted successfully',
        addressId,
        userId
      });

      return result[0];
    } catch (error) {
      logger.error('Failed to delete address:', error);
      throw error;
    }
  }

  /**
   * Set address as default for shipping, billing, or both
   */
  async setAsDefault(addressId, userId, defaultType = 'both') {
    // First get the address
    const address = await this.getAddressById(addressId, userId);
    if (!address) {
      throw new Error('Address not found');
    }

    try {
      let updateFields = [];
      
      // Allow any address to be set as default - no type restrictions
      if (defaultType === 'shipping' || defaultType === 'both') {
        await this.unsetDefaultShippingAddresses(userId);
        updateFields.push('is_default_shipping = true');
      }
      
      if (defaultType === 'billing' || defaultType === 'both') {
        await this.unsetDefaultBillingAddresses(userId);
        updateFields.push('is_default_billing = true');
      }

      if (updateFields.length === 0) {
        throw new Error(`Invalid defaultType: ${defaultType}`);
      }

      // Set this address as default
      const query = `
        UPDATE identity_service.user_addresses 
        SET ${updateFields.join(', ')}, updated_at = NOW()
        WHERE id = $1 AND user_id = $2
        RETURNING *;
      `;

      const result = await this.db.query(query, [addressId, userId]);
      
      logger.info({
        message: 'Address set as default',
        addressId,
        userId,
        defaultType,
        addressType: address.address_type
      });

      return result[0];
    } catch (error) {
      logger.error('Failed to set address as default:', error);
      throw error;
    }
  }

  /**
   * Track address usage for smart defaults
   */
  async trackUsage(addressId, userId) {
    const query = `
      UPDATE identity_service.user_addresses 
      SET usage_frequency = usage_frequency + 1, 
          last_used = NOW(),
          updated_at = NOW()
      WHERE id = $1 AND user_id = $2
      RETURNING usage_frequency, last_used;
    `;

    try {
      const result = await this.db.query(query, [addressId, userId]);
      
      logger.info({
        message: 'Address usage tracked',
        addressId,
        userId,
        newFrequency: result[0]?.usage_frequency
      });

      return result[0];
    } catch (error) {
      logger.error('Failed to track address usage:', error);
      throw error;
    }
  }

  /**
   * Unset default shipping addresses for user
   */
  async unsetDefaultShippingAddresses(userId) {
    const query = `
      UPDATE identity_service.user_addresses 
      SET is_default_shipping = false, updated_at = NOW()
      WHERE user_id = $1 AND (address_type = 'shipping' OR address_type = 'both') AND is_default_shipping = true;
    `;

    try {
      await this.db.query(query, [userId]);
      
      logger.info({
        message: 'Default shipping addresses unset',
        userId
      });
    } catch (error) {
      logger.error('Failed to unset default shipping addresses:', error);
      throw error;
    }
  }

  /**
   * Unset default billing addresses for user
   */
  async unsetDefaultBillingAddresses(userId) {
    const query = `
      UPDATE identity_service.user_addresses 
      SET is_default_billing = false, updated_at = NOW()
      WHERE user_id = $1 AND (address_type = 'billing' OR address_type = 'both') AND is_default_billing = true;
    `;

    try {
      await this.db.query(query, [userId]);
      
      logger.info({
        message: 'Default billing addresses unset',
        userId
      });
    } catch (error) {
      logger.error('Failed to unset default billing addresses:', error);
      throw error;
    }
  }

  /**
   * Get user's default addresses (independent shipping and billing)
   */
  async getDefaultAddresses(userId) {
    const shippingQuery = `
      SELECT * FROM identity_service.user_addresses 
      WHERE user_id = $1 AND is_default_shipping = true 
      AND (address_type = 'shipping' OR address_type = 'both')
      LIMIT 1;
    `;
    
    const billingQuery = `
      SELECT * FROM identity_service.user_addresses 
      WHERE user_id = $1 AND is_default_billing = true 
      AND (address_type = 'billing' OR address_type = 'both')
      LIMIT 1;
    `;

    try {
      const [shippingResult, billingResult] = await Promise.all([
        this.db.query(shippingQuery, [userId]),
        this.db.query(billingQuery, [userId])
      ]);
      
      const defaults = {
        shipping: shippingResult[0] || null,
        billing: billingResult[0] || null
      };

      return defaults;
    } catch (error) {
      logger.error('Failed to get default addresses:', error);
      throw error;
    }
  }
  /**
   * Update address owner from session to user
   * Used when converting guest checkout to registered user
   */
  async updateAddressOwner(addressId, fromUserId, toUserId) {
    const query = `
      UPDATE identity_service.user_addresses 
      SET user_id = $1, updated_at = NOW()
      WHERE id = $2 AND user_id = $3
      RETURNING *;
    `;

    try {
      const result = await this.db.query(query, [toUserId, addressId, fromUserId]);
      
      if (result.length === 0) {
        throw new Error('Address not found or not owned by fromUserId');
      }

      logger.info({
        message: 'Address owner updated successfully',
        addressId,
        fromUserId,
        toUserId
      });
      
      return result[0];
    } catch (error) {
      logger.error('Failed to update address owner:', error);
      throw error;
    }
  }
}

module.exports = new UserAddressRepository(); 