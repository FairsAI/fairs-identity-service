/**
 * User Repository
 * 
 * Manages user data storage and retrieval operations
 */

const { dbConnection } = require('../database/db-connection');
const { logger } = require('../utils/logger');
const bcrypt = require('bcrypt');

class UserRepository {
  /**
   * Get user by ID
   * @param {number} userId - User ID
   * @returns {Promise<Object|null>} User object or null if not found
   */
  async getUserById(userId) {
    try {
      logger.debug('Getting user by ID', { userId });
      
      const query = `
        SELECT id, email, first_name, last_name, phone,
               is_guest, member_converted_at,
               created_at, updated_at, is_active
        FROM identity_service.users 
        WHERE id = $1 AND is_active = true
      `;
      
      const result = await dbConnection.query(query, [userId]);
      
      if (result.length === 0) {
        logger.debug('User not found', { userId });
        return null;
      }
      
      logger.debug('User found', { userId, email: result[0].email });
      return result[0];
    } catch (error) {
      logger.error('Error getting user by ID', { error: error.message, userId });
      throw error;
    }
  }

  /**
   * Get user by email
   * @param {string} email - User email
   * @returns {Promise<Object|null>} User object or null if not found
   */
  async getUserByEmail(email) {
    try {
      logger.debug('Getting user by email', { email });
      
      const query = `
        SELECT id, email, first_name, last_name, phone, 
               is_guest, member_converted_at,
               created_at, updated_at, is_active
        FROM identity_service.users 
        WHERE email = $1 AND is_active = true
      `;
      
      const result = await dbConnection.query(query, [email.toLowerCase()]);
      
      if (result.length === 0) {
        logger.debug('User not found by email', { email });
        return null;
      }
      
      logger.debug('User found by email', { userId: result[0].id, email });
      return result[0];
    } catch (error) {
      logger.error('Error getting user by email', { error: error.message, email });
      throw error;
    }
  }

  /**
   * Create a new user
   * @param {Object} userData - User data
   * @param {string} userData.email - User email
   * @param {string} userData.firstName - User first name
   * @param {string} userData.lastName - User last name
   * @param {string} userData.phone - User phone number
   * @param {string} userData.password - User password (optional)
   * @returns {Promise<Object>} Created user object
   */
  async createUser(userData) {
    try {
      const { 
        email, 
        firstName, 
        first_name,
        lastName, 
        last_name,
        phone, 
        password,
        is_guest,
        member_converted_at,
      } = userData;
      
      // Handle both camelCase and snake_case field names
      const finalFirstName = firstName || first_name;
      const finalLastName = lastName || last_name;
      
      logger.debug('Creating new user', { 
        email, 
        firstName: finalFirstName, 
        lastName: finalLastName,
        isGuest: is_guest 
      });
      
      // Check if user already exists
      const existingUser = await this.getUserByEmail(email);
      if (existingUser) {
        throw new Error('User with this email already exists');
      }
      
      // Hash password if provided
      let hashedPassword = null;
      if (password) {
        hashedPassword = await bcrypt.hash(password, 12);
      }
      
      // Generate UUID if not provided (for guest-to-member conversion, use the guest ID)
      const { v4: uuidv4 } = require('uuid');
      const userId = userData.id || uuidv4();
      
      logger.info('🔍 DEBUG: User ID generation', {
        providedId: userData.id,
        finalUserId: userId,
        userDataKeys: Object.keys(userData)
      });
      
      const query = `
        INSERT INTO identity_service.users (
          id, email, first_name, last_name, phone, 
          is_guest, member_converted_at,
          created_at, updated_at, is_active
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW(), true)
        RETURNING id, email, first_name, last_name, phone, 
                  is_guest, member_converted_at,
                  created_at, updated_at, is_active
      `;
      
      const values = [
        userId,
        email.toLowerCase(),
        finalFirstName,
        finalLastName,
        phone || null,
        is_guest || false,
        member_converted_at || null
      ];
      
      logger.info('🔍 DEBUG: Before INSERT query', {
        userId: userId,
        values: values,
        valueCount: values.length,
        firstValue: values[0]
      });
      
      const result = await dbConnection.query(query, values);
      
      logger.info('User created successfully', { 
        userId: result[0].id, 
        email: result[0].email,
        isGuest: result[0].is_guest
      });
      
      return result[0];
    } catch (error) {
      logger.error('Error creating user', { 
        error: error.message, 
        email: userData.email 
      });
      throw error;
    }
  }

  /**
   * Update user information
   * @param {number} userId - User ID
   * @param {Object} updateData - Data to update
   * @returns {Promise<Object>} Updated user object
   */
  async updateUser(userId, updateData) {
    try {
      logger.debug('Updating user', { userId, fields: Object.keys(updateData) });
      
      // Include new member conversion fields in allowed updates
      const allowedFields = [
        'first_name', 
        'last_name', 
        'phone', 
        'is_guest', 
        'member_converted_at',
        'is_active'
      ];
      const updates = [];
      const values = [];
      let paramIndex = 1;
      
      for (const [key, value] of Object.entries(updateData)) {
        if (allowedFields.includes(key)) {
          updates.push(`${key} = $${paramIndex}`);
          values.push(value);
          paramIndex++;
        }
      }
      
      if (updates.length === 0) {
        throw new Error('No valid fields to update');
      }
      
      updates.push(`updated_at = NOW()`);
      values.push(userId);
      
      const query = `
        UPDATE identity_service.users 
        SET ${updates.join(', ')}
        WHERE id = $${paramIndex} AND is_active = true
        RETURNING id, email, first_name, last_name, phone, 
                  is_guest, member_converted_at,
                  created_at, updated_at, is_active
      `;
      
      const result = await dbConnection.query(query, values);
      
      if (result.length === 0) {
        throw new Error('User not found or inactive');
      }
      
      logger.info('User updated successfully', { 
        userId,
        isGuest: result[0].is_guest,
        memberConverted: !!result[0].member_converted_at
      });
      return result[0];
    } catch (error) {
      logger.error('Error updating user', { error: error.message, userId });
      throw error;
    }
  }

  /**
   * Deactivate user (soft delete)
   * @param {number} userId - User ID
   * @returns {Promise<boolean>} Success status
   */
  async deactivateUser(userId) {
    try {
      logger.debug('Deactivating user', { userId });
      
      const query = `
        UPDATE identity_service.users 
        SET is_active = false, updated_at = NOW()
        WHERE id = $1 AND is_active = true
      `;
      
      const result = await dbConnection.query(query, [userId]);
      
      if (result.rowCount === 0) {
        throw new Error('User not found or already inactive');
      }
      
      logger.info('User deactivated successfully', { userId });
      return true;
    } catch (error) {
      logger.error('Error deactivating user', { error: error.message, userId });
      throw error;
    }
  }

  /**
   * Verify user password
   * @param {string} email - User email
   * @param {string} password - Password to verify
   * @returns {Promise<Object|null>} User object if password is correct, null otherwise
   */
  async verifyPassword(email, password) {
    try {
      logger.debug('Verifying user password', { email });
      
      const query = `
        SELECT id, email, first_name, last_name, phone, created_at, updated_at, is_active
        FROM identity_service.users 
        WHERE email = $1 AND is_active = true
      `;
      
      const result = await dbConnection.query(query, [email.toLowerCase()]);
      
      if (result.length === 0) {
        logger.debug('User not found for password verification', { email });
        return null;
      }
      
      const user = result[0];
      
      // Since we don't have password_hash in identity service,
      // password verification should be done via auth service
      logger.debug('Password verification not supported in identity service', { email });
      return null;
      
      logger.debug('Password verified successfully', { userId: user.id, email });
      return user;
    } catch (error) {
      logger.error('Error verifying password', { error: error.message, email });
      throw error;
    }
  }
}

// Create singleton instance
const userRepository = new UserRepository();

module.exports = { userRepository }; 