/**
 * Compatibility Layer
 * 
 * Provides backward compatibility with localStorage while using the secure storage system.
 * Acts as a drop-in replacement with both synchronous and asynchronous APIs.
 */

class CompatibilityLayer {
  /**
   * Creates a new CompatibilityLayer instance
   * 
   * @param {Object} options - Configuration options
   * @param {Object} options.secureStorage - SecureStorageManager instance
   * @param {Array<string|RegExp>} [options.secureKeys=[]] - Keys to route through secure storage
   * @param {Array<string|RegExp>} [options.excludedKeys=[]] - Keys to exclude from secure storage
   * @param {boolean} [options.warnOnSyncUsage=true] - Whether to warn about synchronous usage
   * @param {boolean} [options.preferSecureStorage=false] - Whether to route all keys through secure storage by default
   * @param {boolean} [options.debug=false] - Enable debug logging
   */
  constructor(options = {}) {
    if (!options.secureStorage) {
      throw new Error('SecureStorageManager is required for CompatibilityLayer');
    }
    
    this.secureStorage = options.secureStorage;
    this.secureKeys = options.secureKeys || [];
    this.excludedKeys = options.excludedKeys || [];
    this.warnOnSyncUsage = options.warnOnSyncUsage !== false;
    this.preferSecureStorage = options.preferSecureStorage || false;
    this.debug = options.debug || false;
    
    // Cache for synchronous access
    this.cache = new Map();
    
    // Flag to track if localStorage has been patched
    this.isLocalStoragePatched = false;
    
    // Reference to original localStorage methods
    this.originalMethods = {
      getItem: null,
      setItem: null,
      removeItem: null,
      clear: null,
      key: null
    };
  }
  
  /**
   * Initializes the compatibility layer and populates cache
   * 
   * @async
   * @returns {Promise<boolean>} Initialization success
   */
  async initialize() {
    try {
      // Cache all secure keys for synchronous access
      await this._populateCache();
      
      this._log('CompatibilityLayer initialized');
      return true;
    } catch (error) {
      this._logError('Failed to initialize CompatibilityLayer', error);
      return false;
    }
  }
  
  /**
   * Populates cache with all secure keys
   * 
   * @private
   * @async
   */
  async _populateCache() {
    try {
      // Clear existing cache
      this.cache.clear();
      
      // If we have specific secure keys defined, populate cache for those
      for (const keyPattern of this.secureKeys) {
        if (typeof keyPattern === 'string') {
          // For string patterns, simply try to fetch the key
          try {
            const value = await this.secureStorage.retrieve(keyPattern);
            if (value !== null && value !== undefined) {
              this.cache.set(keyPattern, value);
            }
          } catch (e) {
            // Ignore errors for keys that don't exist
          }
        }
        // Handling RegExp patterns would require enumerating all keys,
        // which is typically not feasible for secure storage
      }
      
      this._log(`Cache populated with ${this.cache.size} keys`);
    } catch (error) {
      this._logError('Failed to populate cache', error);
    }
  }
  
  /**
   * Checks if a key should be routed through secure storage
   * 
   * @private
   * @param {string} key - Key to check
   * @returns {boolean} Whether the key should use secure storage
   */
  _shouldUseSecureStorage(key) {
    // Check if key is in excluded list
    for (const pattern of this.excludedKeys) {
      if (typeof pattern === 'string' && pattern === key) {
        return false;
      } else if (pattern instanceof RegExp && pattern.test(key)) {
        return false;
      }
    }
    
    // Check if key is in secure list
    for (const pattern of this.secureKeys) {
      if (typeof pattern === 'string' && pattern === key) {
        return true;
      } else if (pattern instanceof RegExp && pattern.test(key)) {
        return true;
      }
    }
    
    // Default behavior based on preference
    return this.preferSecureStorage;
  }
  
  /**
   * Gets an item synchronously (from cache if secure, or localStorage)
   * 
   * @param {string} key - Key to retrieve
   * @returns {string|null} Retrieved value or null
   */
  getItem(key) {
    if (this._shouldUseSecureStorage(key)) {
      // Use cache for secure keys
      if (this.warnOnSyncUsage) {
        console.warn(`[CompatibilityLayer] Synchronous access to secure key '${key}'. Consider using getItemAsync instead.`);
      }
      
      if (this.cache.has(key)) {
        const value = this.cache.get(key);
        return typeof value === 'string' ? value : JSON.stringify(value);
      }
      
      return null;
    } else {
      // Use localStorage for non-secure keys
      return localStorage.getItem(key);
    }
  }
  
  /**
   * Gets an item asynchronously
   * 
   * @async
   * @param {string} key - Key to retrieve
   * @returns {Promise<string|null>} Retrieved value or null
   */
  async getItemAsync(key) {
    if (this._shouldUseSecureStorage(key)) {
      try {
        const value = await this.secureStorage.retrieve(key);
        
        // Update cache
        this.cache.set(key, value);
        
        return typeof value === 'string' ? value : JSON.stringify(value);
      } catch (error) {
        this._logError(`Failed to retrieve key async: ${key}`, error);
        return null;
      }
    } else {
      // Use localStorage for non-secure keys
      return localStorage.getItem(key);
    }
  }
  
  /**
   * Sets an item synchronously (updates cache and localStorage)
   * 
   * @param {string} key - Key to set
   * @param {string} value - Value to store
   */
  setItem(key, value) {
    if (this._shouldUseSecureStorage(key)) {
      if (this.warnOnSyncUsage) {
        console.warn(`[CompatibilityLayer] Synchronous write to secure key '${key}'. Consider using setItemAsync instead.`);
      }
      
      // Parse value if it's JSON
      let parsedValue;
      try {
        parsedValue = JSON.parse(value);
      } catch (e) {
        parsedValue = value;
      }
      
      // Update cache
      this.cache.set(key, parsedValue);
      
      // Queue async update to secure storage
      setTimeout(() => {
        this.secureStorage.store(key, parsedValue)
          .catch(error => this._logError(`Failed to store key async: ${key}`, error));
      }, 0);
    } else {
      // Use localStorage for non-secure keys
      localStorage.setItem(key, value);
    }
  }
  
  /**
   * Sets an item asynchronously
   * 
   * @async
   * @param {string} key - Key to set
   * @param {string|Object} value - Value to store
   * @returns {Promise<boolean>} Success status
   */
  async setItemAsync(key, value) {
    if (this._shouldUseSecureStorage(key)) {
      try {
        // Parse value if it's a string (might be JSON)
        let parsedValue = value;
        if (typeof value === 'string') {
          try {
            parsedValue = JSON.parse(value);
          } catch (e) {
            // Keep as string if not valid JSON
          }
        }
        
        // Update cache
        this.cache.set(key, parsedValue);
        
        // Store in secure storage
        await this.secureStorage.store(key, parsedValue);
        return true;
      } catch (error) {
        this._logError(`Failed to store key async: ${key}`, error);
        return false;
      }
    } else {
      // Use localStorage for non-secure keys
      localStorage.setItem(key, value);
      return true;
    }
  }
  
  /**
   * Removes an item synchronously (from cache and localStorage)
   * 
   * @param {string} key - Key to remove
   */
  removeItem(key) {
    if (this._shouldUseSecureStorage(key)) {
      if (this.warnOnSyncUsage) {
        console.warn(`[CompatibilityLayer] Synchronous removal of secure key '${key}'. Consider using removeItemAsync instead.`);
      }
      
      // Remove from cache
      this.cache.delete(key);
      
      // Queue async removal from secure storage
      setTimeout(() => {
        this.secureStorage.remove(key)
          .catch(error => this._logError(`Failed to remove key async: ${key}`, error));
      }, 0);
    } else {
      // Use localStorage for non-secure keys
      localStorage.removeItem(key);
    }
  }
  
  /**
   * Removes an item asynchronously
   * 
   * @async
   * @param {string} key - Key to remove
   * @returns {Promise<boolean>} Success status
   */
  async removeItemAsync(key) {
    if (this._shouldUseSecureStorage(key)) {
      try {
        // Remove from cache
        this.cache.delete(key);
        
        // Remove from secure storage
        await this.secureStorage.remove(key);
        return true;
      } catch (error) {
        this._logError(`Failed to remove key async: ${key}`, error);
        return false;
      }
    } else {
      // Use localStorage for non-secure keys
      localStorage.removeItem(key);
      return true;
    }
  }
  
  /**
   * Clears storage synchronously (cache and non-secure localStorage)
   */
  clear() {
    // Clear cache
    this.cache.clear();
    
    if (this.warnOnSyncUsage) {
      console.warn('[CompatibilityLayer] Synchronous clear called. This only clears non-secure keys. Use clearAsync for full clearing.');
    }
    
    // Queue async clear for secure storage
    setTimeout(() => {
      this.secureStorage.clear()
        .catch(error => this._logError('Failed to clear secure storage async', error));
    }, 0);
    
    // Clear non-secure localStorage
    if (!this.preferSecureStorage) {
      localStorage.clear();
    } else {
      // Only clear excluded keys if we're routing everything through secure storage
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (!this._shouldUseSecureStorage(key)) {
          localStorage.removeItem(key);
        }
      }
    }
  }
  
  /**
   * Clears storage asynchronously
   * 
   * @async
   * @returns {Promise<boolean>} Success status
   */
  async clearAsync() {
    try {
      // Clear cache
      this.cache.clear();
      
      // Clear secure storage
      await this.secureStorage.clear();
      
      // Clear non-secure localStorage
      if (!this.preferSecureStorage) {
        localStorage.clear();
      } else {
        // Only clear excluded keys if we're routing everything through secure storage
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (!this._shouldUseSecureStorage(key)) {
            localStorage.removeItem(key);
          }
        }
      }
      
      return true;
    } catch (error) {
      this._logError('Failed to clear storage async', error);
      return false;
    }
  }
  
  /**
   * Returns the name of the nth key in the storage
   * 
   * @param {number} index - Index of the key to get
   * @returns {string|null} Key name or null
   */
  key(index) {
    return localStorage.key(index);
  }
  
  /**
   * Patches global localStorage to route secure keys through secure storage
   * 
   * @returns {boolean} Whether patching was successful
   */
  patchGlobalStorage() {
    if (typeof localStorage === 'undefined') {
      this._logError('localStorage is not available in this environment');
      return false;
    }
    
    if (this.isLocalStoragePatched) {
      this._log('localStorage is already patched');
      return true;
    }
    
    try {
      // Save references to original methods
      this.originalMethods = {
        getItem: localStorage.getItem,
        setItem: localStorage.setItem,
        removeItem: localStorage.removeItem,
        clear: localStorage.clear,
        key: localStorage.key
      };
      
      // Patch getItem
      localStorage.getItem = (key) => this.getItem(key);
      
      // Patch setItem
      localStorage.setItem = (key, value) => this.setItem(key, value);
      
      // Patch removeItem
      localStorage.removeItem = (key) => this.removeItem(key);
      
      // Patch clear
      localStorage.clear = () => this.clear();
      
      // Add async methods to localStorage
      localStorage.getItemAsync = (key) => this.getItemAsync(key);
      localStorage.setItemAsync = (key, value) => this.setItemAsync(key, value);
      localStorage.removeItemAsync = (key) => this.removeItemAsync(key);
      localStorage.clearAsync = () => this.clearAsync();
      
      this.isLocalStoragePatched = true;
      this._log('localStorage successfully patched');
      return true;
    } catch (error) {
      this._logError('Failed to patch localStorage', error);
      
      // Try to restore original methods if patching failed
      this._restoreGlobalStorage();
      return false;
    }
  }
  
  /**
   * Restores original localStorage methods
   * 
   * @returns {boolean} Whether restoration was successful
   */
  restoreGlobalStorage() {
    if (!this.isLocalStoragePatched) {
      this._log('localStorage is not patched');
      return true;
    }
    
    return this._restoreGlobalStorage();
  }
  
  /**
   * Internal method to restore original localStorage methods
   * 
   * @private
   * @returns {boolean} Whether restoration was successful
   */
  _restoreGlobalStorage() {
    try {
      if (this.originalMethods.getItem) {
        localStorage.getItem = this.originalMethods.getItem;
      }
      
      if (this.originalMethods.setItem) {
        localStorage.setItem = this.originalMethods.setItem;
      }
      
      if (this.originalMethods.removeItem) {
        localStorage.removeItem = this.originalMethods.removeItem;
      }
      
      if (this.originalMethods.clear) {
        localStorage.clear = this.originalMethods.clear;
      }
      
      if (this.originalMethods.key) {
        localStorage.key = this.originalMethods.key;
      }
      
      // Remove async methods
      delete localStorage.getItemAsync;
      delete localStorage.setItemAsync;
      delete localStorage.removeItemAsync;
      delete localStorage.clearAsync;
      
      this.isLocalStoragePatched = false;
      this._log('localStorage successfully restored');
      return true;
    } catch (error) {
      this._logError('Failed to restore localStorage', error);
      return false;
    }
  }
  
  /**
   * Logs a message if debug is enabled
   * 
   * @private
   * @param {...any} args - Log arguments
   */
  _log(...args) {
    if (this.debug) {
      console.log('[CompatibilityLayer]', ...args);
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
      console.error('[CompatibilityLayer] ERROR:', message, error);
    }
  }
}

// Export for both browser and Node.js environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { CompatibilityLayer };
} else if (typeof window !== 'undefined') {
  window.CompatibilityLayer = CompatibilityLayer;
} 