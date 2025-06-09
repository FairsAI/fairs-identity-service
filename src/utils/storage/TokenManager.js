/**
 * Token Manager
 * 
 * Manages secure tokens for user recognition with device binding, 
 * expiration, and tamper protection.
 */

const { DeviceFingerprint } = require('./DeviceFingerprint');

class TokenManager {
  /**
   * Creates a new TokenManager instance
   * 
   * @param {Object} options - Configuration options
   * @param {Object} options.keyManager - KeyManager instance for signing operations
   * @param {Object} options.storage - SecureStorageManager instance for token storage
   * @param {string} [options.namespace='fairs_tokens'] - Namespace for token storage
   * @param {number} [options.tokenExpiration=86400] - Token expiration in seconds (default: 24 hours)
   * @param {number} [options.refreshThreshold=3600] - Seconds before expiration to trigger refresh (default: 1 hour)
   * @param {number} [options.maxValidationAttempts=10] - Maximum validation attempts before rate limiting
   * @param {number} [options.rateLimitDuration=300] - Rate limit duration in seconds (default: 5 minutes)
   * @param {boolean} [options.strictDeviceBinding=true] - Whether to strictly enforce device binding
   */
  constructor(options = {}) {
    if (!options.keyManager) {
      throw new Error('KeyManager is required for TokenManager');
    }
    
    if (!options.storage) {
      throw new Error('SecureStorageManager is required for TokenManager');
    }
    
    this.keyManager = options.keyManager;
    this.storage = options.storage;
    this.namespace = options.namespace || 'fairs_tokens';
    this.tokenExpiration = options.tokenExpiration || 86400; // 24 hours
    this.refreshThreshold = options.refreshThreshold || 3600; // 1 hour
    this.maxValidationAttempts = options.maxValidationAttempts || 10;
    this.rateLimitDuration = options.rateLimitDuration || 300; // 5 minutes
    this.strictDeviceBinding = options.strictDeviceBinding !== false;
    
    // Initialize device fingerprinting for device binding
    this.deviceFingerprint = new DeviceFingerprint();
    
    // Keep track of validation attempts for rate limiting
    this.validationAttempts = new Map();
    
    // Revoked token storage
    this.revokedTokens = new Set();
    
    // Load revoked tokens from storage
    this._loadRevokedTokens();
  }

  /**
   * Generates a new token for a user
   * 
   * @async
   * @param {string} userId - User identifier
   * @param {Object} [payload={}] - Additional payload data
   * @param {Object} [options={}] - Token generation options
   * @param {number} [options.expiresIn] - Custom expiration in seconds
   * @param {boolean} [options.storeToken=true] - Whether to store the token
   * @returns {Promise<{token: string, decoded: Object}>} The generated token and decoded data
   */
  async generateToken(userId, payload = {}, options = {}) {
    if (!userId) {
      throw new Error('User ID is required for token generation');
    }
    
    const expiresIn = options.expiresIn || this.tokenExpiration;
    const storeToken = options.storeToken !== false;
    
    try {
      // Generate device fingerprint for binding
      const deviceFingerprint = await this.deviceFingerprint.generateFingerprint();
      
      // Create token payload
      const now = Math.floor(Date.now() / 1000);
      const tokenData = {
        uid: userId,                        // User identifier
        dev: deviceFingerprint,             // Device binding
        iat: now,                           // Issued at timestamp
        exp: now + expiresIn,               // Expiration timestamp
        jti: this._generateTokenId(),       // Unique token ID (prevents replay)
        ...payload                          // Additional custom data
      };
      
      // Sign the token
      const signature = await this._signToken(tokenData);
      tokenData.sig = signature;
      
      // Convert to string representation
      const tokenString = this._encodeToken(tokenData);
      
      // Store the token if requested
      if (storeToken) {
        await this._storeToken(userId, tokenData);
      }
      
      return {
        token: tokenString,
        decoded: tokenData
      };
    } catch (error) {
      console.error('Error generating token:', error);
      throw new Error(`Failed to generate token: ${error.message}`);
    }
  }

  /**
   * Validates a token
   * 
   * @async
   * @param {string} token - The token to validate
   * @param {Object} [options={}] - Validation options
   * @param {boolean} [options.checkExpiration=true] - Whether to check token expiration
   * @param {boolean} [options.checkDeviceBinding=true] - Whether to check device binding
   * @param {boolean} [options.refreshIfNeeded=true] - Whether to refresh token if near expiry
   * @returns {Promise<{valid: boolean, decoded: Object, refreshed: Object|null, reason: string|null}>} Validation result
   */
  async validateToken(token, options = {}) {
    const checkExpiration = options.checkExpiration !== false;
    const checkDeviceBinding = options.checkDeviceBinding !== false && this.strictDeviceBinding;
    const refreshIfNeeded = options.refreshIfNeeded !== false;
    
    // Check for rate limiting
    if (this._isRateLimited(token)) {
      return {
        valid: false,
        decoded: null,
        refreshed: null,
        reason: 'Rate limit exceeded'
      };
    }
    
    try {
      // Track validation attempt for rate limiting
      this._trackValidationAttempt(token);
      
      // Decode token
      const decoded = this._decodeToken(token);
      if (!decoded) {
        return {
          valid: false,
          decoded: null,
          refreshed: null,
          reason: 'Invalid token format'
        };
      }
      
      // Check if token is revoked
      if (this.revokedTokens.has(decoded.jti)) {
        return {
          valid: false,
          decoded,
          refreshed: null,
          reason: 'Token revoked'
        };
      }
      
      // Verify signature
      const validSignature = await this._verifySignature(decoded);
      if (!validSignature) {
        return {
          valid: false,
          decoded,
          refreshed: null,
          reason: 'Invalid signature'
        };
      }
      
      // Check expiration if requested
      if (checkExpiration) {
        const now = Math.floor(Date.now() / 1000);
        if (decoded.exp && decoded.exp < now) {
          return {
            valid: false,
            decoded,
            refreshed: null,
            reason: 'Token expired'
          };
        }
      }
      
      // Check device binding if requested
      if (checkDeviceBinding) {
        const currentFingerprint = await this.deviceFingerprint.generateFingerprint();
        if (decoded.dev !== currentFingerprint) {
          return {
            valid: false,
            decoded,
            refreshed: null,
            reason: 'Device binding mismatch'
          };
        }
      }
      
      let refreshed = null;
      
      // Refresh token if it's nearing expiration and refresh is requested
      if (refreshIfNeeded && decoded.exp) {
        const now = Math.floor(Date.now() / 1000);
        const timeToExpiry = decoded.exp - now;
        
        if (timeToExpiry > 0 && timeToExpiry < this.refreshThreshold) {
          // Generate a new token with the same payload but updated timestamps
          const { token: newToken, decoded: newDecoded } = await this.generateToken(
            decoded.uid,
            { ...decoded, iat: undefined, exp: undefined, jti: undefined, sig: undefined }
          );
          
          refreshed = {
            token: newToken,
            decoded: newDecoded
          };
        }
      }
      
      return {
        valid: true,
        decoded,
        refreshed,
        reason: null
      };
    } catch (error) {
      console.error('Error validating token:', error);
      return {
        valid: false,
        decoded: null,
        refreshed: null,
        reason: `Validation error: ${error.message}`
      };
    }
  }

  /**
   * Refreshes a token with updated expiration
   * 
   * @async
   * @param {string} token - The token to refresh
   * @param {Object} [options={}] - Refresh options
   * @param {boolean} [options.extendExpiry=true] - Whether to extend expiration from now
   * @returns {Promise<{token: string, decoded: Object}|null>} The refreshed token or null if invalid
   */
  async refreshToken(token, options = {}) {
    const extendExpiry = options.extendExpiry !== false;
    
    try {
      // First validate the token (without auto-refresh to avoid recursion)
      const validation = await this.validateToken(token, {
        refreshIfNeeded: false
      });
      
      if (!validation.valid) {
        return null;
      }
      
      // Revoke the old token
      this.revokeToken(token);
      
      // Generate a new token with the same user ID and payload
      const oldPayload = { ...validation.decoded };
      
      // Remove fields that will be regenerated
      delete oldPayload.iat;
      delete oldPayload.exp;
      delete oldPayload.jti;
      delete oldPayload.sig;
      
      // Extract user ID
      const userId = oldPayload.uid;
      delete oldPayload.uid;
      
      // Generate a new token
      const expiresIn = extendExpiry ? this.tokenExpiration : (validation.decoded.exp - Math.floor(Date.now() / 1000));
      return await this.generateToken(userId, oldPayload, { expiresIn });
    } catch (error) {
      console.error('Error refreshing token:', error);
      return null;
    }
  }

  /**
   * Revokes a token to prevent future use
   * 
   * @async
   * @param {string} token - The token to revoke
   * @returns {Promise<boolean>} Whether revocation was successful
   */
  async revokeToken(token) {
    try {
      const decoded = this._decodeToken(token);
      if (!decoded || !decoded.jti) {
        return false;
      }
      
      // Add to revoked tokens
      this.revokedTokens.add(decoded.jti);
      
      // Store the updated revoked tokens list
      await this._storeRevokedTokens();
      
      // Try to remove from storage
      try {
        const storageKey = `${this.namespace}.token.${decoded.uid}`;
        await this.storage.removeItem(storageKey);
      } catch (e) {
        // Ignore storage errors - the token is still in the revoked list
      }
      
      return true;
    } catch (error) {
      console.error('Error revoking token:', error);
      return false;
    }
  }

  /**
   * Gets a stored token for a user
   * 
   * @async
   * @param {string} userId - User identifier
   * @returns {Promise<{token: string, decoded: Object}|null>} The stored token or null
   */
  async getStoredToken(userId) {
    if (!userId) {
      return null;
    }
    
    try {
      const storageKey = `${this.namespace}.token.${userId}`;
      const storedToken = await this.storage.getItem(storageKey);
      
      if (!storedToken) {
        return null;
      }
      
      // Parse the stored token
      const tokenData = JSON.parse(storedToken);
      const tokenString = this._encodeToken(tokenData);
      
      return {
        token: tokenString,
        decoded: tokenData
      };
    } catch (error) {
      console.error('Error getting stored token:', error);
      return null;
    }
  }

  /**
   * Clears all tokens for the current user/device
   * 
   * @async
   * @returns {Promise<boolean>} Whether clearing was successful
   */
  async clearTokens() {
    try {
      // Get all keys in the token namespace
      const keys = await this.storage.getKeys();
      const tokenKeys = keys.filter(key => key.startsWith(`${this.namespace}.token.`));
      
      // Remove all token keys
      for (const key of tokenKeys) {
        await this.storage.removeItem(key);
      }
      
      return true;
    } catch (error) {
      console.error('Error clearing tokens:', error);
      return false;
    }
  }

  /**
   * Signs token data using KeyManager
   * 
   * @private
   * @async
   * @param {Object} tokenData - Token data to sign
   * @returns {Promise<string>} The signature
   */
  async _signToken(tokenData) {
    // Create a copy without the signature field
    const dataToSign = { ...tokenData };
    delete dataToSign.sig;
    
    // Convert to string for signing
    const tokenString = JSON.stringify(dataToSign);
    
    try {
      // Use KeyManager to encrypt the token string as a signature
      // This leverages the existing key infrastructure
      const encrypted = await this.keyManager.encrypt(tokenString);
      
      // Return the signature (just the hash part, not the full encrypted data)
      return encrypted.data;
    } catch (error) {
      console.error('Error signing token:', error);
      
      // Fallback to a simpler signature if encryption fails
      const encoder = new TextEncoder();
      const data = encoder.encode(tokenString);
      
      if (window.crypto && window.crypto.subtle) {
        const hash = await window.crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hash))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      } else {
        // Very simple fallback hash
        let hash = 0;
        for (let i = 0; i < tokenString.length; i++) {
          hash = ((hash << 5) - hash) + tokenString.charCodeAt(i);
          hash |= 0; // Convert to 32bit integer
        }
        return (hash >>> 0).toString(16);
      }
    }
  }

  /**
   * Verifies token signature
   * 
   * @private
   * @async
   * @param {Object} tokenData - Token data with signature
   * @returns {Promise<boolean>} Whether signature is valid
   */
  async _verifySignature(tokenData) {
    const signature = tokenData.sig;
    if (!signature) {
      return false;
    }
    
    // Create a copy without the signature field
    const dataToVerify = { ...tokenData };
    delete dataToVerify.sig;
    
    // Convert to string for verification
    const tokenString = JSON.stringify(dataToVerify);
    
    try {
      // Generate a new signature and compare
      const computedSignature = await this._signToken(dataToVerify);
      return signature === computedSignature;
    } catch (error) {
      console.error('Error verifying signature:', error);
      return false;
    }
  }

  /**
   * Generates a unique token ID
   * 
   * @private
   * @returns {string} Unique token ID
   */
  _generateTokenId() {
    const timestamp = Date.now().toString(36);
    const randomPart = Math.random().toString(36).substring(2, 10);
    return `${timestamp}-${randomPart}`;
  }

  /**
   * Encodes token data to string representation
   * 
   * @private
   * @param {Object} tokenData - Token data
   * @returns {string} Encoded token
   */
  _encodeToken(tokenData) {
    const jsonStr = JSON.stringify(tokenData);
    
    // Use base64 encoding if available
    if (typeof btoa === 'function') {
      return btoa(jsonStr);
    }
    
    // Simple encoding fallback
    return encodeURIComponent(jsonStr);
  }

  /**
   * Decodes token string to data
   * 
   * @private
   * @param {string} token - Token string
   * @returns {Object|null} Decoded token data or null if invalid
   */
  _decodeToken(token) {
    try {
      let jsonStr;
      
      // Try base64 decoding
      try {
        if (typeof atob === 'function') {
          jsonStr = atob(token);
        } else {
          jsonStr = decodeURIComponent(token);
        }
      } catch (e) {
        // If not base64, try URI decoding
        jsonStr = decodeURIComponent(token);
      }
      
      // Parse JSON
      return JSON.parse(jsonStr);
    } catch (error) {
      console.error('Error decoding token:', error);
      return null;
    }
  }

  /**
   * Stores a token in secure storage
   * 
   * @private
   * @async
   * @param {string} userId - User identifier
   * @param {Object} tokenData - Token data
   * @returns {Promise<boolean>} Whether storage was successful
   */
  async _storeToken(userId, tokenData) {
    try {
      const storageKey = `${this.namespace}.token.${userId}`;
      await this.storage.setItem(storageKey, JSON.stringify(tokenData));
      return true;
    } catch (error) {
      console.error('Error storing token:', error);
      return false;
    }
  }

  /**
   * Tracks token validation attempts for rate limiting
   * 
   * @private
   * @param {string} token - Token string
   */
  _trackValidationAttempt(token) {
    const now = Date.now();
    
    // Use token prefix as identifier to prevent storage exploding with invalid tokens
    const tokenId = token.substring(0, 32);
    
    // Get current attempts
    let attempts = this.validationAttempts.get(tokenId) || {
      count: 0,
      firstAttempt: now,
      lastAttempt: now
    };
    
    // Check if we should reset based on time
    if (now - attempts.firstAttempt > this.rateLimitDuration * 1000) {
      // Reset if rate limit duration has passed
      attempts = {
        count: 0,
        firstAttempt: now,
        lastAttempt: now
      };
    }
    
    // Increment counter and update time
    attempts.count += 1;
    attempts.lastAttempt = now;
    
    // Store updated attempts
    this.validationAttempts.set(tokenId, attempts);
    
    // Clean up old entries periodically
    if (Math.random() < 0.1) { // 10% chance to clean up
      this._cleanupValidationAttempts();
    }
  }

  /**
   * Checks if a token is rate limited
   * 
   * @private
   * @param {string} token - Token string
   * @returns {boolean} Whether token is rate limited
   */
  _isRateLimited(token) {
    const now = Date.now();
    const tokenId = token.substring(0, 32);
    const attempts = this.validationAttempts.get(tokenId);
    
    if (!attempts) {
      return false;
    }
    
    // Check if within rate limit duration
    if (now - attempts.firstAttempt <= this.rateLimitDuration * 1000) {
      // Check if exceeded max attempts
      return attempts.count > this.maxValidationAttempts;
    }
    
    return false;
  }

  /**
   * Cleans up old validation attempt records
   * 
   * @private
   */
  _cleanupValidationAttempts() {
    const now = Date.now();
    const expiryTime = now - this.rateLimitDuration * 1000 * 2; // Double duration for safety
    
    for (const [tokenId, attempts] of this.validationAttempts.entries()) {
      if (attempts.lastAttempt < expiryTime) {
        this.validationAttempts.delete(tokenId);
      }
    }
  }

  /**
   * Loads revoked tokens from storage
   * 
   * @private
   * @async
   */
  async _loadRevokedTokens() {
    try {
      const storageKey = `${this.namespace}.revoked`;
      const storedRevoked = await this.storage.getItem(storageKey);
      
      if (storedRevoked) {
        const revokedList = JSON.parse(storedRevoked);
        this.revokedTokens = new Set(revokedList);
        
        // Clean up expired revoked tokens
        this._cleanupRevokedTokens();
      }
    } catch (error) {
      console.error('Error loading revoked tokens:', error);
      this.revokedTokens = new Set();
    }
  }

  /**
   * Stores revoked tokens in storage
   * 
   * @private
   * @async
   * @returns {Promise<boolean>} Whether storage was successful
   */
  async _storeRevokedTokens() {
    try {
      const storageKey = `${this.namespace}.revoked`;
      const revokedList = Array.from(this.revokedTokens);
      await this.storage.setItem(storageKey, JSON.stringify(revokedList));
      return true;
    } catch (error) {
      console.error('Error storing revoked tokens:', error);
      return false;
    }
  }

  /**
   * Cleans up expired revoked tokens
   * 
   * @private
   * @async
   */
  async _cleanupRevokedTokens() {
    // Only keep revoked tokens up to a certain limit
    const MAX_REVOKED_TOKENS = 1000;
    
    if (this.revokedTokens.size > MAX_REVOKED_TOKENS) {
      // Convert to array, sort by timestamp in token ID, and keep only the newest
      const revokedArray = Array.from(this.revokedTokens);
      
      // Sort by timestamp part of the token ID (first part before the dash)
      revokedArray.sort((a, b) => {
        const timestampA = parseInt(a.split('-')[0], 36);
        const timestampB = parseInt(b.split('-')[0], 36);
        return timestampB - timestampA; // Descending order (newest first)
      });
      
      // Keep only the latest tokens
      const newRevokedList = revokedArray.slice(0, MAX_REVOKED_TOKENS);
      this.revokedTokens = new Set(newRevokedList);
      
      // Store the updated list
      await this._storeRevokedTokens();
    }
  }
}

// Export for both browser and Node.js environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { TokenManager };
} else if (typeof window !== 'undefined') {
  window.TokenManager = TokenManager;
} 