/**
 * Cross Merchant Identity
 * 
 * Manages cross-merchant identity and user recognition
 */

export class CrossMerchantIdentity {
  constructor() {
    this.identities = new Map();
    this.eventHandlers = new Map();
  }

  /**
   * Register a user identity
   * @param {string} userId - User ID
   * @param {Object} userData - User data
   * @returns {boolean} Success
   */
  registerIdentity(userId, userData) {
    if (!userId) {
      return false;
    }
    
    this.identities.set(userId, {
      userId,
      ...userData,
      registeredAt: Date.now()
    });
    
    this._emit('identity:registered', { userId });
    
    return true;
  }

  /**
   * Check if a user identity exists
   * @param {string} userId - User ID
   * @returns {boolean} Whether user exists
   */
  hasIdentity(userId) {
    return this.identities.has(userId);
  }

  /**
   * Get a user identity
   * @param {string} userId - User ID
   * @returns {Object|null} User identity
   */
  getIdentity(userId) {
    return this.identities.get(userId) || null;
  }

  /**
   * Find a user by phone number
   * @param {string} phoneNumber - Phone number
   * @returns {Object|null} User identity
   */
  findByPhone(phoneNumber) {
    if (!phoneNumber) {
      return null;
    }
    
    for (const [_, identity] of this.identities) {
      if (identity.phoneNumber === phoneNumber) {
        return identity;
      }
    }
    
    return null;
  }

  /**
   * Find a user by email
   * @param {string} email - Email address
   * @returns {Object|null} User identity
   */
  findByEmail(email) {
    if (!email) {
      return null;
    }
    
    for (const [_, identity] of this.identities) {
      if (identity.email === email) {
        return identity;
      }
    }
    
    return null;
  }

  /**
   * Add event handler
   * @param {string} event - Event name
   * @param {Function} handler - Event handler
   */
  on(event, handler) {
    if (!this.eventHandlers.has(event)) {
      this.eventHandlers.set(event, []);
    }
    
    this.eventHandlers.get(event).push(handler);
  }

  /**
   * Remove event handler
   * @param {string} event - Event name
   * @param {Function} handler - Event handler
   */
  off(event, handler) {
    if (!this.eventHandlers.has(event)) {
      return;
    }
    
    const handlers = this.eventHandlers.get(event);
    const index = handlers.indexOf(handler);
    
    if (index !== -1) {
      handlers.splice(index, 1);
    }
  }

  /**
   * Emit an event
   * @param {string} event - Event name
   * @param {Object} data - Event data
   * @private
   */
  _emit(event, data) {
    if (!this.eventHandlers.has(event)) {
      return;
    }
    
    const handlers = this.eventHandlers.get(event);
    
    for (const handler of handlers) {
      handler(data);
    }
  }
}

// Export instance
export default CrossMerchantIdentity; 