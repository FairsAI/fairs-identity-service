/**
 * Cross-Merchant Manager
 * 
 * Manages user recognition across different merchant domains
 * while respecting modern browser privacy restrictions.
 */

class CrossMerchantManager {
  /**
   * Creates a new CrossMerchantManager instance
   * 
   * @param {Object} options - Configuration options
   * @param {Object} options.storageManager - SecureStorageManager instance
   * @param {Object} options.tokenManager - TokenManager instance (optional)
   * @param {Object} options.apiClient - API client for server-side fallbacks
   * @param {string} [options.namespace='cross_merchant'] - Namespace for storage
   * @param {boolean} [options.useTopLevelDomain=true] - Whether to use top-level domain for cookies
   * @param {number} [options.idExpirationDays=365] - Expiration days for IDs
   * @param {boolean} [options.debug=false] - Enable debug logging
   */
  constructor(options = {}) {
    if (!options.storageManager) {
      throw new Error('SecureStorageManager is required for CrossMerchantManager');
    }
    
    if (!options.apiClient) {
      throw new Error('API client is required for server-side fallbacks');
    }
    
    this.storageManager = options.storageManager;
    this.tokenManager = options.tokenManager;
    this.apiClient = options.apiClient;
    this.namespace = options.namespace || 'cross_merchant';
    this.useTopLevelDomain = options.useTopLevelDomain !== false;
    this.idExpirationDays = options.idExpirationDays || 365;
    this.debug = options.debug || false;
    
    // Strategies for recognition ordered by preference
    this.strategies = [
      'first_party_cookies',
      'local_storage',
      'server_side'
    ];
    
    // Storage keys
    this.universalIdKey = `${this.namespace}.universal_id`;
    this.merchantMapKey = `${this.namespace}.merchant_map`;
    
    // Cache for universal ID
    this.cachedUniversalId = null;
    this.merchantMap = null;
  }
  
  /**
   * Initializes the cross-merchant manager
   * 
   * @async
   * @returns {Promise<boolean>} Initialization success
   */
  async initialize() {
    try {
      // Detect browser capabilities
      await this._detectCapabilities();
      
      // Load merchant map if available
      await this._loadMerchantMap();
      
      this._log('Initialized with capabilities:', this.capabilities);
      return true;
    } catch (error) {
      this._logError('Initialization failed', error);
      return false;
    }
  }
  
  /**
   * Gets or creates a universal ID for user recognition
   * 
   * @async
   * @param {Object} [options={}] - Options
   * @param {boolean} [options.forceRefresh=false] - Whether to force a refresh of the ID
   * @returns {Promise<string>} Universal ID
   */
  async getUniversalId(options = {}) {
    const forceRefresh = options.forceRefresh || false;
    
    // Return cached ID if available and not forcing refresh
    if (this.cachedUniversalId && !forceRefresh) {
      return this.cachedUniversalId;
    }
    
    // Try to get existing ID
    const existingId = await this._retrieveUniversalId();
    
    if (existingId && !forceRefresh) {
      this.cachedUniversalId = existingId;
      return existingId;
    }
    
    // Create new universal ID
    const newId = await this._createUniversalId();
    this.cachedUniversalId = newId;
    
    return newId;
  }
  
  /**
   * Associates current merchant with universal ID
   * 
   * @async
   * @param {string} universalId - Universal ID
   * @param {string} merchantId - Merchant ID to associate
   * @param {Object} [merchantData={}] - Optional merchant-specific data
   * @returns {Promise<boolean>} Success status
   */
  async associateMerchant(universalId, merchantId, merchantData = {}) {
    if (!universalId || !merchantId) {
      throw new Error('Both universal ID and merchant ID are required');
    }
    
    try {
      // Load merchant map if not already loaded
      if (!this.merchantMap) {
        await this._loadMerchantMap();
      }
      
      // Associate merchant with universal ID
      this.merchantMap[merchantId] = {
        universalId,
        lastSeen: new Date().toISOString(),
        data: merchantData
      };
      
      // Save merchant map across available storage
      await this._saveMerchantMap();
      
      // Sync with server if possible
      await this._syncWithServer({
        universalId,
        merchantId,
        action: 'associate',
        data: merchantData
      });
      
      return true;
    } catch (error) {
      this._logError('Error associating merchant', error);
      return false;
    }
  }
  
  /**
   * Recognizes user across merchants
   * 
   * @async
   * @param {string} identifier - User identifier (email, user ID, etc.)
   * @param {Object} [options={}] - Recognition options
   * @returns {Promise<Object>} Recognition data
   */
  async recognizeUser(identifier, options = {}) {
    try {
      // Get universal ID
      const universalId = await this.getUniversalId();
      
      // Get current merchant ID
      const currentMerchant = options.merchantId || await this._getCurrentMerchant();
      
      // Try to recognize locally first
      const localRecognition = await this._recognizeLocally(universalId, identifier);
      
      // If local recognition successful and comprehensive, return it
      if (localRecognition && localRecognition.comprehensive) {
        return localRecognition.data;
      }
      
      // Otherwise, try server recognition
      const serverRecognition = await this._recognizeServerSide(universalId, identifier, currentMerchant);
      
      // Merge local and server data, prioritizing server data
      const recognitionData = {
        ...(localRecognition?.data || {}),
        ...(serverRecognition || {}),
        universalId,
        currentMerchant
      };
      
      return recognitionData;
    } catch (error) {
      this._logError('Error recognizing user', error);
      
      // Return minimal data on error
      return {
        universalId: this.cachedUniversalId,
        recognized: false,
        error: error.message
      };
    }
  }
  
  /**
   * Syncs recognition data with server
   * 
   * @async
   * @param {Object} [options={}] - Sync options
   * @param {boolean} [options.forceSync=false] - Force full sync
   * @returns {Promise<boolean>} Sync success
   */
  async syncRecognitionData(options = {}) {
    try {
      const forceSync = options.forceSync || false;
      
      // Get universal ID
      const universalId = await this.getUniversalId();
      
      // Load merchant map
      await this._loadMerchantMap();
      
      // Sync with server
      const result = await this._syncWithServer({
        universalId,
        merchantMap: this.merchantMap,
        action: 'sync',
        forceSync
      });
      
      // Update local merchant map with server data if received
      if (result && result.merchantMap) {
        this.merchantMap = {
          ...this.merchantMap,
          ...result.merchantMap
        };
        
        // Save updated map
        await this._saveMerchantMap();
      }
      
      return true;
    } catch (error) {
      this._logError('Error syncing recognition data', error);
      return false;
    }
  }
  
  /**
   * Clears all recognition data
   * 
   * @async
   * @param {Object} [options={}] - Clear options
   * @param {boolean} [options.serverSide=true] - Whether to clear server-side data
   * @returns {Promise<boolean>} Clear success
   */
  async clearRecognitionData(options = {}) {
    const clearServerSide = options.serverSide !== false;
    
    try {
      // Clear universal ID from all storage methods
      await this._clearUniversalId();
      
      // Clear cached values
      this.cachedUniversalId = null;
      this.merchantMap = {};
      
      // Clear merchant map
      await this.storageManager.remove(this.merchantMapKey);
      
      // Clear first-party cookies
      this._clearCookies();
      
      // Notify server to clear data
      if (clearServerSide) {
        await this._syncWithServer({
          action: 'clear'
        });
      }
      
      return true;
    } catch (error) {
      this._logError('Error clearing recognition data', error);
      return false;
    }
  }
  
  /**
   * Detects browser capabilities for cross-merchant recognition
   * 
   * @private
   * @async
   */
  async _detectCapabilities() {
    this.capabilities = {
      localStorage: this._isLocalStorageAvailable(),
      cookies: this._areCookiesAvailable(),
      storagePartitioned: this._isStoragePartitioned(),
      topLevelDomainCookies: await this._testTopLevelDomainCookies(),
      privateMode: await this._isPrivateMode()
    };
    
    // Determine best strategy based on capabilities
    this._determineBestStrategy();
  }
  
  /**
   * Determines the best recognition strategy based on capabilities
   * 
   * @private
   */
  _determineBestStrategy() {
    // Reorder strategies based on browser capabilities
    if (this.capabilities.storagePartitioned) {
      // If storage is partitioned, prioritize first-party cookies and server-side
      this.strategies = [
        'first_party_cookies',
        'server_side',
        'local_storage'
      ];
    } else if (this.capabilities.privateMode) {
      // If in private mode, local storage may be restricted
      this.strategies = [
        'first_party_cookies',
        'server_side',
        'local_storage'
      ];
    }
    
    // If cookies are not available, remove cookie strategy
    if (!this.capabilities.cookies) {
      this.strategies = this.strategies.filter(s => s !== 'first_party_cookies');
    }
    
    // If localStorage is not available, remove local storage strategy
    if (!this.capabilities.localStorage) {
      this.strategies = this.strategies.filter(s => s !== 'local_storage');
    }
    
    this._log('Using recognition strategies (in order):', this.strategies);
  }
  
  /**
   * Checks if local storage is available
   * 
   * @private
   * @returns {boolean} Whether local storage is available
   */
  _isLocalStorageAvailable() {
    try {
      const testKey = `${this.namespace}_test`;
      localStorage.setItem(testKey, 'test');
      const result = localStorage.getItem(testKey) === 'test';
      localStorage.removeItem(testKey);
      return result;
    } catch (e) {
      return false;
    }
  }
  
  /**
   * Checks if cookies are available
   * 
   * @private
   * @returns {boolean} Whether cookies are available
   */
  _areCookiesAvailable() {
    try {
      const testKey = `${this.namespace}_test`;
      document.cookie = `${testKey}=test; path=/; max-age=60`;
      const result = document.cookie.indexOf(`${testKey}=test`) !== -1;
      document.cookie = `${testKey}=; path=/; max-age=0`;
      return result;
    } catch (e) {
      return false;
    }
  }
  
  /**
   * Tests if storage partitioning is active
   * 
   * @private
   * @returns {boolean} Whether storage is likely partitioned
   */
  _isStoragePartitioned() {
    // Check for Safari 14+ ITP
    const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
    
    // Check for Firefox containers or ETP
    const isFirefox = navigator.userAgent.indexOf('Firefox') !== -1;
    
    // Check for Chrome partitioning (as of Chrome 89+)
    const isChrome = navigator.userAgent.indexOf('Chrome') !== -1;
    
    // For Safari, storage partitioning is active by default in recent versions
    if (isSafari) {
      return true;
    }
    
    // For Firefox, check for Total Cookie Protection signals
    if (isFirefox) {
      // This is a simplification - actual detection is more complex
      return true;
    }
    
    // For Chrome, check for potential partitioning
    if (isChrome) {
      // Chrome's partitioning is becoming default (early 2023)
      return true;
    }
    
    // Default to assuming partitioning for safety
    return true;
  }
  
  /**
   * Tests top-level domain cookie functionality
   * 
   * @private
   * @async
   * @returns {Promise<boolean>} Whether top-level domain cookies work
   */
  async _testTopLevelDomainCookies() {
    try {
      const domain = this._extractTopLevelDomain();
      if (!domain) return false;
      
      const testKey = `${this.namespace}_tld_test`;
      document.cookie = `${testKey}=test; domain=.${domain}; path=/; max-age=60`;
      
      const result = document.cookie.indexOf(`${testKey}=test`) !== -1;
      document.cookie = `${testKey}=; domain=.${domain}; path=/; max-age=0`;
      
      return result;
    } catch (e) {
      return false;
    }
  }
  
  /**
   * Checks if browser is likely in private/incognito mode
   * 
   * @private
   * @async
   * @returns {Promise<boolean>} Whether private mode is detected
   */
  async _isPrivateMode() {
    try {
      // Try to write to local storage
      const testKey = `${this.namespace}_private_test`;
      localStorage.setItem(testKey, 'test');
      localStorage.removeItem(testKey);
      
      // Try to write to indexed DB
      const db = await new Promise((resolve, reject) => {
        const request = window.indexedDB.open('test_private_db');
        request.onerror = () => resolve(null);
        request.onsuccess = () => resolve(request.result);
      });
      
      if (db) db.close();
      
      return !db;
    } catch (e) {
      return true;
    }
  }
  
  /**
   * Extracts the top-level domain from the current URL
   * 
   * @private
   * @returns {string|null} Top-level domain or null
   */
  _extractTopLevelDomain() {
    try {
      const hostname = window.location.hostname;
      const parts = hostname.split('.');
      
      // Handle simple cases (e.g., example.com)
      if (parts.length <= 2) return hostname;
      
      // Extract TLD and SLD (second-level domain)
      return parts.slice(-2).join('.');
    } catch (e) {
      return null;
    }
  }
  
  /**
   * Creates and stores a new universal ID
   * 
   * @private
   * @async
   * @returns {Promise<string>} The new universal ID
   */
  async _createUniversalId() {
    // Generate a UUID v4
    const uuid = this._generateUUID();
    
    // Store in available storage methods
    await this._storeUniversalId(uuid);
    
    return uuid;
  }
  
  /**
   * Retrieves universal ID from available storage methods
   * 
   * @private
   * @async
   * @returns {Promise<string|null>} Universal ID or null
   */
  async _retrieveUniversalId() {
    let universalId = null;
    
    // Try all strategies in order until we find an ID
    for (const strategy of this.strategies) {
      switch (strategy) {
        case 'first_party_cookies':
          universalId = this._getIdFromCookie();
          break;
        case 'local_storage':
          universalId = await this._getIdFromLocalStorage();
          break;
        case 'server_side':
          universalId = await this._getIdFromServer();
          break;
      }
      
      if (universalId) {
        // If found in one strategy, ensure it's saved to all available strategies
        await this._storeUniversalId(universalId);
        break;
      }
    }
    
    return universalId;
  }
  
  /**
   * Stores universal ID across all available storage methods
   * 
   * @private
   * @async
   * @param {string} universalId - Universal ID to store
   */
  async _storeUniversalId(universalId) {
    // Store in all available strategies
    if (this.capabilities.cookies) {
      this._storeIdInCookie(universalId);
    }
    
    if (this.capabilities.localStorage) {
      await this._storeIdInLocalStorage(universalId);
    }
    
    // Always attempt to store server-side
    await this._storeIdOnServer(universalId);
    
    // Store in secure storage manager
    await this.storageManager.store(this.universalIdKey, universalId, {
      important: true
    });
  }
  
  /**
   * Clears universal ID from all storage methods
   * 
   * @private
   * @async
   */
  async _clearUniversalId() {
    // Clear from cookies
    this._clearIdFromCookie();
    
    // Clear from local storage
    if (this.capabilities.localStorage) {
      try {
        localStorage.removeItem(this.universalIdKey);
      } catch (e) {
        // Ignore errors
      }
    }
    
    // Clear from secure storage manager
    await this.storageManager.remove(this.universalIdKey);
  }
  
  /**
   * Stores universal ID in a cookie
   * 
   * @private
   * @param {string} universalId - Universal ID
   */
  _storeIdInCookie(universalId) {
    try {
      const domain = this.useTopLevelDomain ? this._extractTopLevelDomain() : undefined;
      const domainPart = domain ? `domain=.${domain}; ` : '';
      
      document.cookie = `${this.universalIdKey}=${universalId}; ${domainPart}path=/; max-age=${this.idExpirationDays * 24 * 60 * 60}; SameSite=Lax`;
    } catch (e) {
      this._logError('Error storing cookie', e);
    }
  }
  
  /**
   * Gets universal ID from cookie
   * 
   * @private
   * @returns {string|null} Universal ID or null
   */
  _getIdFromCookie() {
    try {
      const cookies = document.cookie.split(';');
      for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.startsWith(`${this.universalIdKey}=`)) {
          return cookie.substring(this.universalIdKey.length + 1);
        }
      }
    } catch (e) {
      this._logError('Error getting ID from cookie', e);
    }
    return null;
  }
  
  /**
   * Clears universal ID cookie
   * 
   * @private
   */
  _clearIdFromCookie() {
    try {
      const domain = this.useTopLevelDomain ? this._extractTopLevelDomain() : undefined;
      const domainPart = domain ? `domain=.${domain}; ` : '';
      
      document.cookie = `${this.universalIdKey}=; ${domainPart}path=/; max-age=0`;
    } catch (e) {
      // Ignore errors
    }
  }
  
  /**
   * Clears all cookies in the namespace
   * 
   * @private
   */
  _clearCookies() {
    try {
      const cookies = document.cookie.split(';');
      const domain = this.useTopLevelDomain ? this._extractTopLevelDomain() : undefined;
      const domainPart = domain ? `domain=.${domain}; ` : '';
      
      for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        const name = cookie.split('=')[0];
        
        if (name.startsWith(this.namespace)) {
          document.cookie = `${name}=; ${domainPart}path=/; max-age=0`;
        }
      }
    } catch (e) {
      // Ignore errors
    }
  }
  
  /**
   * Stores universal ID in local storage
   * 
   * @private
   * @async
   * @param {string} universalId - Universal ID
   */
  async _storeIdInLocalStorage(universalId) {
    try {
      localStorage.setItem(this.universalIdKey, universalId);
    } catch (e) {
      this._logError('Error storing ID in localStorage', e);
    }
  }
  
  /**
   * Gets universal ID from local storage
   * 
   * @private
   * @async
   * @returns {Promise<string|null>} Universal ID or null
   */
  async _getIdFromLocalStorage() {
    try {
      // Try direct localStorage first
      const id = localStorage.getItem(this.universalIdKey);
      if (id) return id;
      
      // Try secure storage manager
      return await this.storageManager.retrieve(this.universalIdKey);
    } catch (e) {
      this._logError('Error getting ID from localStorage', e);
      return null;
    }
  }
  
  /**
   * Stores universal ID on server
   * 
   * @private
   * @async
   * @param {string} universalId - Universal ID
   */
  async _storeIdOnServer(universalId) {
    try {
      await this._syncWithServer({
        universalId,
        action: 'store'
      });
    } catch (e) {
      this._logError('Error storing ID on server', e);
    }
  }
  
  /**
   * Gets universal ID from server
   * 
   * @private
   * @async
   * @returns {Promise<string|null>} Universal ID or null
   */
  async _getIdFromServer() {
    try {
      const response = await this._syncWithServer({
        action: 'retrieve'
      });
      
      return response?.universalId || null;
    } catch (e) {
      this._logError('Error getting ID from server', e);
      return null;
    }
  }
  
  /**
   * Loads the merchant map from storage
   * 
   * @private
   * @async
   */
  async _loadMerchantMap() {
    try {
      // Try to load merchant map from storage
      const storedMap = await this.storageManager.retrieve(this.merchantMapKey);
      
      this.merchantMap = storedMap || {};
    } catch (e) {
      this._logError('Error loading merchant map', e);
      this.merchantMap = {};
    }
  }
  
  /**
   * Saves the merchant map to storage
   * 
   * @private
   * @async
   */
  async _saveMerchantMap() {
    try {
      await this.storageManager.store(this.merchantMapKey, this.merchantMap, {
        important: true
      });
    } catch (e) {
      this._logError('Error saving merchant map', e);
    }
  }
  
  /**
   * Recognizes user locally using stored merchant map
   * 
   * @private
   * @async
   * @param {string} universalId - Universal ID
   * @param {string} identifier - User identifier
   * @returns {Promise<Object|null>} Recognition data or null
   */
  async _recognizeLocally(universalId, identifier) {
    try {
      // Ensure we have merchant map loaded
      if (!this.merchantMap) {
        await this._loadMerchantMap();
      }
      
      // Find all merchants associated with this universal ID
      const associatedMerchants = Object.entries(this.merchantMap)
        .filter(([_, data]) => data.universalId === universalId)
        .map(([merchantId, data]) => ({
          merchantId,
          lastSeen: data.lastSeen,
          data: data.data || {}
        }));
      
      // Check if we have comprehensive data
      const comprehensive = associatedMerchants.length > 0;
      
      return {
        comprehensive,
        data: {
          universalId,
          identifier,
          merchants: associatedMerchants,
          recognized: associatedMerchants.length > 0
        }
      };
    } catch (e) {
      this._logError('Error recognizing locally', e);
      return null;
    }
  }
  
  /**
   * Recognizes user server-side
   * 
   * @private
   * @async
   * @param {string} universalId - Universal ID
   * @param {string} identifier - User identifier
   * @param {string} currentMerchant - Current merchant ID
   * @returns {Promise<Object|null>} Recognition data or null
   */
  async _recognizeServerSide(universalId, identifier, currentMerchant) {
    try {
      const response = await this._syncWithServer({
        universalId,
        identifier,
        merchantId: currentMerchant,
        action: 'recognize'
      });
      
      // Update local merchant map with data from server
      if (response && response.merchants) {
        // Process server merchants into local map format
        response.merchants.forEach(merchant => {
          if (merchant.merchantId) {
            this.merchantMap[merchant.merchantId] = {
              universalId,
              lastSeen: merchant.lastSeen || new Date().toISOString(),
              data: merchant.data || {}
            };
          }
        });
        
        // Save updated merchant map
        await this._saveMerchantMap();
      }
      
      return response;
    } catch (e) {
      this._logError('Error recognizing server-side', e);
      return null;
    }
  }
  
  /**
   * Gets current merchant ID
   * 
   * @private
   * @async
   * @returns {Promise<string>} Current merchant ID
   */
  async _getCurrentMerchant() {
    // Get from document location
    const hostname = window.location.hostname;
    
    return hostname;
  }
  
  /**
   * Syncs with server for various recognition operations
   * 
   * @private
   * @async
   * @param {Object} data - Data to sync
   * @returns {Promise<Object|null>} Server response or null
   */
  async _syncWithServer(data) {
    try {
      // Add device info to help with fingerprinting
      const deviceInfo = await this._getDeviceInfo();
      
      // Add token from TokenManager if available
      let token = null;
      if (this.tokenManager) {
        const storedToken = await this.tokenManager.getStoredToken('universal');
        token = storedToken?.token || null;
      }
      
      // Prepare request
      const request = {
        ...data,
        deviceInfo,
        token
      };
      
      // Send to server
      const response = await this.apiClient.post('/recognition/sync', request);
      
      // If response includes a token and we have TokenManager, store it
      if (response?.token && this.tokenManager) {
        await this.tokenManager._storeToken('universal', this.tokenManager._decodeToken(response.token));
      }
      
      return response;
    } catch (e) {
      this._logError('Error syncing with server', e);
      return null;
    }
  }
  
  /**
   * Gets basic device info for server-side recognition
   * 
   * @private
   * @async
   * @returns {Promise<Object>} Device info
   */
  async _getDeviceInfo() {
    try {
      return {
        userAgent: navigator.userAgent,
        language: navigator.language,
        screenSize: `${window.screen.width}x${window.screen.height}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        timestamp: new Date().toISOString()
      };
    } catch (e) {
      return {};
    }
  }
  
  /**
   * Generates a UUID v4
   * 
   * @private
   * @returns {string} UUID v4
   */
  _generateUUID() {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
      return crypto.randomUUID();
    }
    
    // Fallback implementation
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
  
  /**
   * Logs a message if debug is enabled
   * 
   * @private
   * @param {...any} args - Log arguments
   */
  _log(...args) {
    if (this.debug) {
      console.log('[CrossMerchantManager]', ...args);
    }
  }
  
  /**
   * Logs an error if debug is enabled
   * 
   * @private
   * @param {string} message - Error message
   * @param {Error} error - Error object
   */
  _logError(message, error) {
    if (this.debug) {
      console.error('[CrossMerchantManager] ERROR:', message, error);
    }
  }
}

// Export for both browser and Node.js environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { CrossMerchantManager };
} else if (typeof window !== 'undefined') {
  window.CrossMerchantManager = CrossMerchantManager;
} 