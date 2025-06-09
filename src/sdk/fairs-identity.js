/**
 * Fairs Identity Management
 * 
 * Provides identity management with server-side persistence
 * to complement client-side storage for improved user recognition
 * across sessions and devices.
 */

const { EnhancedDeviceFingerprint } = require('./enhanced-device-fingerprint');

/**
 * Main SDK integration for hybrid client-server identity
 */
class FairsIdentity {
  /**
   * Create a new identity manager
   * @param {Object} options - Configuration options
   * @param {string} options.apiEndpoint - API endpoint for server communication
   * @param {string} options.merchantId - Merchant ID
   * @param {number} options.confidenceThreshold - Minimum confidence score for matching
   * @param {boolean} options.debug - Enable debug logging
   * @param {boolean} options.autoRefresh - Automatically refresh user data
   * @param {number} options.refreshInterval - Interval for auto-refresh in milliseconds
   */
  constructor(options = {}) {
    this.apiEndpoint = options.apiEndpoint || '/api';
    this.merchantId = options.merchantId;
    this.debug = options.debug || false;
    this.autoRefresh = options.autoRefresh !== false;
    this.refreshInterval = options.refreshInterval || 30 * 60 * 1000; // 30 minutes
    
    // Initialize device fingerprinting
    this.deviceFingerprint = new EnhancedDeviceFingerprint({
      apiEndpoint: `${this.apiEndpoint}/device-fingerprint`,
      confidenceThreshold: options.confidenceThreshold || 0.95,
      debug: this.debug
    });
    
    // Initialize identity state
    this.deviceId = null;
    this.universalId = null;
    this.verified = false;
    this.verificationDetails = null;
    this.userDevices = [];
    this.merchantAssociations = [];
    this._refreshTimer = null;
    
    // For tracking refresh failures
    this._lastRefresh = 0;
    this._refreshFailures = 0;
    
    if (this.debug) {
      console.log('[FairsIdentity] Initialized with options:', {
        apiEndpoint: this.apiEndpoint,
        merchantId: this.merchantId,
        autoRefresh: this.autoRefresh
      });
    }
  }
  
  /**
   * Initialize identity system
   * @returns {Promise<Object>} - Identity data
   */
  async initialize() {
    try {
      if (this.debug) {
        console.log('[FairsIdentity] Initializing identity system');
      }
      
      // Get device fingerprint
      const device = await this.deviceFingerprint.getFingerprint();
      this.deviceId = device.deviceId;
      
      if (this.debug) {
        console.log('[FairsIdentity] Device fingerprint retrieved:', {
          deviceId: this.deviceId,
          source: device.source
        });
      }
      
      // Check if device is associated with a user
      await this._checkDeviceIdentity();
      
      // Set up automatic refresh if enabled
      if (this.autoRefresh && this.universalId) {
        this._setupAutoRefresh();
      }
      
      return {
        deviceId: this.deviceId,
        universalId: this.universalId,
        verified: this.verified,
        verificationDetails: this.verificationDetails,
        deviceSource: device.source,
        confidenceScore: device.confidenceScore
      };
    } catch (error) {
      if (this.debug) {
        console.error('[FairsIdentity] Error initializing identity:', error);
      }
      
      // Return device ID even if identity check fails
      return {
        deviceId: this.deviceId,
        error: error.message
      };
    }
  }
  
  /**
   * Create a new user
   * @param {Object} userData - User data
   * @param {string} userData.merchantUserId - Merchant-specific user ID
   * @param {Object} userData.profile - User profile data
   * @returns {Promise<Object>} - New user data
   */
  async createUser(userData) {
    try {
      if (!this.merchantId) {
        throw new Error('Merchant ID is required');
      }
      
      if (!userData || !userData.merchantUserId) {
        throw new Error('merchantUserId is required');
      }
      
      if (this.debug) {
        console.log('[FairsIdentity] Creating new user:', {
          merchantId: this.merchantId,
          merchantUserId: userData.merchantUserId
        });
      }
      
      // Generate universal ID if not provided
      const universalId = userData.universalId || this._generateUniversalId();
      
      // Register merchant user
      const response = await fetch(`${this.apiEndpoint}/identity/merchant`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          universalId,
          merchantId: this.merchantId,
          merchantUserId: userData.merchantUserId,
          profile: userData.profile || {}
        }),
        credentials: 'include'
      });
      
      if (!response.ok) {
        throw new Error(`Failed to create user: ${response.status}`);
      }
      
      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error || 'Failed to create user');
      }
      
      // Associate device with new user
      if (this.deviceId) {
        await this._associateDevice(universalId);
      }
      
      // Update local state
      this.universalId = universalId;
      
      // Load user data
      await this._loadUserDevices();
      await this._loadMerchantAssociations();
      
      if (this.autoRefresh) {
        this._setupAutoRefresh();
      }
      
      return {
        universalId: this.universalId,
        deviceId: this.deviceId,
        success: true
      };
    } catch (error) {
      if (this.debug) {
        console.error('[FairsIdentity] Error creating user:', error);
      }
      
      return {
        error: error.message,
        success: false
      };
    }
  }
  
  /**
   * Record successful verification
   * @param {Object} verificationData - Verification data
   * @param {string} verificationData.method - Verification method
   * @param {string} verificationData.status - Verification status
   * @param {Object} verificationData.additionalData - Additional data
   * @returns {Promise<boolean>} - Success status
   */
  async recordVerification(verificationData) {
    try {
      if (!this.universalId) {
        throw new Error('Universal ID not available');
      }
      
      if (!verificationData || !verificationData.method) {
        throw new Error('Verification method is required');
      }
      
      if (this.debug) {
        console.log('[FairsIdentity] Recording verification:', {
          universalId: this.universalId,
          method: verificationData.method
        });
      }
      
      const response = await fetch(`${this.apiEndpoint}/verification`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          universalId: this.universalId,
          deviceId: this.deviceId,
          merchantId: this.merchantId,
          method: verificationData.method,
          status: verificationData.status || 'success',
          additionalData: verificationData.additionalData || {}
        }),
        credentials: 'include'
      });
      
      if (!response.ok) {
        throw new Error(`Failed to record verification: ${response.status}`);
      }
      
      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error || 'Failed to record verification');
      }
      
      // Update local state
      if (verificationData.status !== 'failure') {
        this.verified = true;
        this.verificationDetails = {
          method: verificationData.method,
          timestamp: new Date().toISOString()
        };
      }
      
      return true;
    } catch (error) {
      if (this.debug) {
        console.error('[FairsIdentity] Error recording verification:', error);
      }
      
      return false;
    }
  }
  
  /**
   * Check if user has been recently verified
   * @returns {Promise<Object>} - Verification status
   */
  async checkVerificationStatus() {
    try {
      if (!this.universalId) {
        return { isVerified: false, reason: 'No universal ID available' };
      }
      
      if (this.debug) {
        console.log('[FairsIdentity] Checking verification status:', {
          universalId: this.universalId
        });
      }
      
      const response = await fetch(`${this.apiEndpoint}/verification/${this.universalId}?deviceId=${this.deviceId || ''}`, {
        method: 'GET',
        credentials: 'include'
      });
      
      if (!response.ok) {
        throw new Error(`Failed to check verification: ${response.status}`);
      }
      
      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error || 'Failed to check verification');
      }
      
      // Update local state
      this.verified = result.verification.isVerified;
      this.verificationDetails = result.verification;
      
      return result.verification;
    } catch (error) {
      if (this.debug) {
        console.error('[FairsIdentity] Error checking verification status:', error);
      }
      
      return {
        isVerified: false,
        error: error.message
      };
    }
  }
  
  /**
   * Refresh user identity and associated data
   * @returns {Promise<boolean>} - Success status
   */
  async refresh() {
    try {
      if (this.debug) {
        console.log('[FairsIdentity] Refreshing user identity');
      }
      
      // Check device identity
      await this._checkDeviceIdentity();
      
      if (this.universalId) {
        // Load user data
        await this._loadUserDevices();
        await this._loadMerchantAssociations();
        
        // Check verification status
        await this.checkVerificationStatus();
      }
      
      this._lastRefresh = Date.now();
      this._refreshFailures = 0;
      
      return true;
    } catch (error) {
      if (this.debug) {
        console.error('[FairsIdentity] Error refreshing identity:', error);
      }
      
      this._refreshFailures++;
      
      return false;
    }
  }
  
  /**
   * Generate a unique universal ID
   * @returns {string} - Universal ID
   * @private
   */
  _generateUniversalId() {
    // Use UUID v4 generation if crypto API is available
    if (window.crypto && window.crypto.getRandomValues) {
      const buffer = new Uint8Array(16);
      window.crypto.getRandomValues(buffer);
      
      // Set version bits (v4)
      buffer[6] = (buffer[6] & 0x0f) | 0x40;
      buffer[8] = (buffer[8] & 0x3f) | 0x80;
      
      // Convert to canonical string format
      const hexCodes = [];
      for (let i = 0; i < buffer.length; i++) {
        hexCodes.push(buffer[i].toString(16).padStart(2, '0'));
      }
      
      // Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      return [
        hexCodes.slice(0, 4).join(''),
        hexCodes.slice(4, 6).join(''),
        hexCodes.slice(6, 8).join(''),
        hexCodes.slice(8, 10).join(''),
        hexCodes.slice(10, 16).join('')
      ].join('-');
    }
    
    // Fallback to timestamp + random
    const timestamp = new Date().getTime();
    const random = [];
    for (let i = 0; i < 8; i++) {
      random.push(Math.floor(Math.random() * 16).toString(16));
    }
    
    return `${timestamp.toString(16)}-${random.join('')}`;
  }
  
  /**
   * Check if device is associated with a user
   * @returns {Promise<void>}
   * @private
   */
  async _checkDeviceIdentity() {
    if (!this.deviceId) {
      throw new Error('Device ID not available');
    }
    
    const response = await fetch(`${this.apiEndpoint}/identity/device/${this.deviceId}${this.merchantId ? `?merchantId=${this.merchantId}` : ''}`, {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error(`Failed to check identity: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (data.success && data.identity) {
      this.universalId = data.identity.universalId;
      this.verified = data.identity.isVerified;
      
      if (this.debug) {
        console.log('[FairsIdentity] Device associated with user:', {
          universalId: this.universalId,
          verified: this.verified
        });
      }
    } else {
      this.universalId = null;
      this.verified = false;
      
      if (this.debug) {
        console.log('[FairsIdentity] Device not associated with any user');
      }
    }
  }
  
  /**
   * Associate current device with a user
   * @param {string} universalId - Universal ID
   * @returns {Promise<boolean>} - Success status
   * @private
   */
  async _associateDevice(universalId) {
    if (!this.deviceId) {
      throw new Error('Device ID not available');
    }
    
    if (!universalId) {
      throw new Error('Universal ID is required');
    }
    
    if (!this.merchantId) {
      throw new Error('Merchant ID is required');
    }
    
    if (this.debug) {
      console.log('[FairsIdentity] Associating device with user:', {
        deviceId: this.deviceId,
        universalId
      });
    }
    
    const response = await fetch(`${this.apiEndpoint}/identity/associate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        universalId,
        deviceId: this.deviceId,
        merchantId: this.merchantId,
        isPrimary: true
      }),
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error(`Failed to associate device: ${response.status}`);
    }
    
    const result = await response.json();
    
    return result.success === true;
  }
  
  /**
   * Load user devices from server
   * @returns {Promise<Array>} - User devices
   * @private
   */
  async _loadUserDevices() {
    if (!this.universalId) {
      this.userDevices = [];
      return this.userDevices;
    }
    
    if (this.debug) {
      console.log('[FairsIdentity] Loading user devices');
    }
    
    try {
      const response = await fetch(`${this.apiEndpoint}/identity/${this.universalId}/devices`, {
        method: 'GET',
        credentials: 'include'
      });
      
      if (!response.ok) {
        throw new Error(`Failed to load user devices: ${response.status}`);
      }
      
      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error || 'Failed to load user devices');
      }
      
      this.userDevices = result.devices || [];
      
      if (this.debug) {
        console.log(`[FairsIdentity] Loaded ${this.userDevices.length} user devices`);
      }
      
      return this.userDevices;
    } catch (error) {
      if (this.debug) {
        console.error('[FairsIdentity] Error loading user devices:', error);
      }
      
      // Keep existing devices on error
      return this.userDevices;
    }
  }
  
  /**
   * Load merchant associations from server
   * @returns {Promise<Array>} - Merchant associations
   * @private
   */
  async _loadMerchantAssociations() {
    if (!this.universalId) {
      this.merchantAssociations = [];
      return this.merchantAssociations;
    }
    
    if (this.debug) {
      console.log('[FairsIdentity] Loading merchant associations');
    }
    
    try {
      const response = await fetch(`${this.apiEndpoint}/identity/${this.universalId}/merchants`, {
        method: 'GET',
        credentials: 'include'
      });
      
      if (!response.ok) {
        throw new Error(`Failed to load merchant associations: ${response.status}`);
      }
      
      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error || 'Failed to load merchant associations');
      }
      
      this.merchantAssociations = result.merchants || [];
      
      if (this.debug) {
        console.log(`[FairsIdentity] Loaded ${this.merchantAssociations.length} merchant associations`);
      }
      
      return this.merchantAssociations;
    } catch (error) {
      if (this.debug) {
        console.error('[FairsIdentity] Error loading merchant associations:', error);
      }
      
      // Keep existing associations on error
      return this.merchantAssociations;
    }
  }
  
  /**
   * Set up automatic refresh timer
   * @private
   */
  _setupAutoRefresh() {
    // Clear existing timer if any
    if (this._refreshTimer) {
      clearInterval(this._refreshTimer);
    }
    
    // Set up new timer
    this._refreshTimer = setInterval(() => {
      // Skip refresh if too many recent failures
      if (this._refreshFailures > 3) {
        const timeSinceLastRefresh = Date.now() - this._lastRefresh;
        // Only retry if more than 5 minutes since last failure
        if (timeSinceLastRefresh < 5 * 60 * 1000) {
          return;
        }
      }
      
      this.refresh().catch(error => {
        if (this.debug) {
          console.error('[FairsIdentity] Auto-refresh failed:', error);
        }
      });
    }, this.refreshInterval);
    
    // Ensure clean up on page unload
    window.addEventListener('beforeunload', () => {
      if (this._refreshTimer) {
        clearInterval(this._refreshTimer);
      }
    });
  }
  
  /**
   * Clean up resources
   */
  destroy() {
    if (this._refreshTimer) {
      clearInterval(this._refreshTimer);
      this._refreshTimer = null;
    }
    
    if (this.debug) {
      console.log('[FairsIdentity] Resources cleaned up');
    }
  }
}

// Support both CommonJS and ES modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { FairsIdentity };
} else if (typeof define === 'function' && define.amd) {
  define(['./enhanced-device-fingerprint'], function(EnhancedDeviceFingerprint) {
    return { FairsIdentity };
  });
} else {
  window.FairsIdentity = FairsIdentity;
} 