/**
 * Secure Storage Manager
 * 
 * A multi-layered storage system with automatic fallbacks and in-memory caching.
 * This class provides a unified interface for storing and retrieving data using
 * various browser storage mechanisms based on availability and security considerations.
 */

const { BrowserCapabilityDetector } = require('./BrowserCapabilityDetector');

class SecureStorageManager {
  /**
   * Creates a new SecureStorageManager instance
   * 
   * @param {Object} options - Configuration options
   * @param {string} [options.namespace='fairs'] - Namespace prefix for all stored keys
   * @param {Object} [options.storage] - Storage configuration
   * @param {boolean} [options.storage.preferIndexedDB=true] - Whether to prefer IndexedDB when available
   * @param {boolean} [options.storage.useLocalStorage=true] - Whether to use localStorage
   * @param {boolean} [options.storage.useSessionStorage=true] - Whether to use sessionStorage
   * @param {boolean} [options.storage.useCookies=true] - Whether to use cookies
   * @param {Object} [options.cache] - Cache configuration
   * @param {boolean} [options.cache.enabled=true] - Whether to use in-memory caching
   * @param {number} [options.cache.defaultTTL=300000] - Default cache TTL in milliseconds (5 minutes)
   * @param {number} [options.cache.maxSize=100] - Maximum number of items to cache
   */
  constructor(options = {}) {
    this.namespace = options.namespace || 'fairs';
    this.detector = new BrowserCapabilityDetector();
    this.capabilities = null;
    this.storageAdapters = {};
    this.adaptersInitialized = false;
    
    // Storage options
    this.storageOptions = {
      preferIndexedDB: options.storage?.preferIndexedDB !== false,
      useLocalStorage: options.storage?.useLocalStorage !== false,
      useSessionStorage: options.storage?.useSessionStorage !== false,
      useCookies: options.storage?.useCookies !== false,
    };
    
    // Cache configuration
    this.cacheConfig = {
      enabled: options.cache?.enabled !== false,
      defaultTTL: options.cache?.defaultTTL || 300000, // 5 minutes
      maxSize: options.cache?.maxSize || 100,
    };
    
    // Initialize cache
    this.cache = {
      items: new Map(),
      accessOrder: [], // For LRU implementation
    };
    
    // Initialize with memory adapter as a fallback
    this.storageAdapters.memory = new MemoryStorageAdapter();
    
    // Primary, secondary, tertiary storage types
    this.primaryStorage = 'memory';
    this.secondaryStorage = null;
    this.tertiaryStorage = null;
    
    // Initialize logger function
    this.log = options.log || console.log;
  }

  /**
   * Initializes the storage manager, detecting capabilities and setting up adapters
   * 
   * @async
   * @returns {Promise<Object>} Object containing detected capabilities
   */
  async initialize() {
    if (this.adaptersInitialized) {
      return this.capabilities;
    }
    
    try {
      // Detect browser capabilities
      this.capabilities = await this.detector.detect();
      
      // Set up storage adapters based on capabilities
      await this._initializeAdapters();
      
      this.adaptersInitialized = true;
      return this.capabilities;
    } catch (error) {
      this.log('Failed to initialize SecureStorageManager:', error);
      // Use memory adapter as fallback
      this.primaryStorage = 'memory';
      this.adaptersInitialized = true;
      return this.capabilities || { recommended: { primaryStorage: 'memory' } };
    }
  }

  /**
   * Initializes storage adapters based on detected capabilities
   * 
   * @private
   * @async
   */
  async _initializeAdapters() {
    const { recommended, storage } = this.capabilities;
    
    // Set primary storage based on capabilities and preferences
    if (this.storageOptions.preferIndexedDB && storage.indexedDB) {
      this.storageAdapters.indexedDB = new IndexedDBStorageAdapter(this.namespace);
      await this.storageAdapters.indexedDB.initialize();
      this.primaryStorage = 'indexedDB';
    } else if (storage.localStorage && this.storageOptions.useLocalStorage) {
      this.storageAdapters.localStorage = new LocalStorageAdapter(this.namespace);
      this.primaryStorage = 'localStorage';
    } else if (storage.cookies && this.storageOptions.useCookies) {
      this.storageAdapters.cookies = new CookieStorageAdapter(this.namespace);
      this.primaryStorage = 'cookies';
    } else if (storage.sessionStorage && this.storageOptions.useSessionStorage) {
      this.storageAdapters.sessionStorage = new SessionStorageAdapter(this.namespace);
      this.primaryStorage = 'sessionStorage';
    } else {
      this.primaryStorage = 'memory';
    }
    
    // Set up secondary storage
    if (recommended.secondaryStorage && 
        recommended.secondaryStorage !== this.primaryStorage && 
        storage[recommended.secondaryStorage]) {
      
      if (recommended.secondaryStorage === 'localStorage' && this.storageOptions.useLocalStorage) {
        this.storageAdapters.localStorage = new LocalStorageAdapter(this.namespace);
        this.secondaryStorage = 'localStorage';
      } else if (recommended.secondaryStorage === 'cookies' && this.storageOptions.useCookies) {
        this.storageAdapters.cookies = new CookieStorageAdapter(this.namespace);
        this.secondaryStorage = 'cookies';
      } else if (recommended.secondaryStorage === 'sessionStorage' && this.storageOptions.useSessionStorage) {
        this.storageAdapters.sessionStorage = new SessionStorageAdapter(this.namespace);
        this.secondaryStorage = 'sessionStorage';
      } else if (recommended.secondaryStorage === 'indexedDB' && this.storageOptions.preferIndexedDB) {
        this.storageAdapters.indexedDB = new IndexedDBStorageAdapter(this.namespace);
        await this.storageAdapters.indexedDB.initialize();
        this.secondaryStorage = 'indexedDB';
      }
    }
    
    // Set up tertiary storage using similar logic
    if (recommended.tertiaryStorage && 
        recommended.tertiaryStorage !== this.primaryStorage && 
        recommended.tertiaryStorage !== this.secondaryStorage && 
        storage[recommended.tertiaryStorage]) {
      
      if (recommended.tertiaryStorage === 'localStorage' && this.storageOptions.useLocalStorage) {
        this.storageAdapters.localStorage = new LocalStorageAdapter(this.namespace);
        this.tertiaryStorage = 'localStorage';
      } else if (recommended.tertiaryStorage === 'cookies' && this.storageOptions.useCookies) {
        this.storageAdapters.cookies = new CookieStorageAdapter(this.namespace);
        this.tertiaryStorage = 'cookies';
      } else if (recommended.tertiaryStorage === 'sessionStorage' && this.storageOptions.useSessionStorage) {
        this.storageAdapters.sessionStorage = new SessionStorageAdapter(this.namespace);
        this.tertiaryStorage = 'sessionStorage';
      }
    }
  }

  /**
   * Stores data using the configured storage adapters
   * 
   * @async
   * @param {string} key - The key to store the data under
   * @param {any} value - The data to store
   * @param {Object} [options={}] - Storage options
   * @param {number} [options.ttl] - Time-to-live in milliseconds for the cache entry
   * @param {boolean} [options.skipCache=false] - Whether to skip caching this item
   * @param {boolean} [options.important=false] - Whether the data is important (try all storage methods)
   * @returns {Promise<boolean>} Whether the storage operation was successful
   */
  async store(key, value, options = {}) {
    // Ensure manager is initialized
    if (!this.adaptersInitialized) {
      await this.initialize();
    }
    
    // Normalize key
    const normalizedKey = this._normalizeKey(key);
    
    // Validate data
    if (value === undefined) {
      throw new Error('Cannot store undefined value');
    }
    
    // Update cache if enabled and not explicitly skipped
    if (this.cacheConfig.enabled && !options.skipCache) {
      this._updateCache(normalizedKey, value, options.ttl);
    }
    
    // Try primary storage first
    let success = false;
    const serializedValue = JSON.stringify(value);
    
    try {
      success = await this.storageAdapters[this.primaryStorage].setItem(normalizedKey, serializedValue);
      
      // If primary storage failed or data is important, try secondary
      if ((!success || options.important) && this.secondaryStorage) {
        const secondarySuccess = await this.storageAdapters[this.secondaryStorage].setItem(
          normalizedKey, 
          serializedValue
        );
        success = success || secondarySuccess;
        
        // If still not successful or data is important, try tertiary
        if ((!success || options.important) && this.tertiaryStorage) {
          const tertiarySuccess = await this.storageAdapters[this.tertiaryStorage].setItem(
            normalizedKey, 
            serializedValue
          );
          success = success || tertiarySuccess;
        }
      }
    } catch (error) {
      this.log(`Error storing data for key ${normalizedKey}:`, error);
      // Use memory as last resort
      if (options.important) {
        this.storageAdapters.memory.setItem(normalizedKey, serializedValue);
        success = true;
      }
    }
    
    return success;
  }

  /**
   * Retrieves data using the configured storage adapters
   * 
   * @async
   * @param {string} key - The key to retrieve data for
   * @param {Object} [options={}] - Retrieval options
   * @param {boolean} [options.bypassCache=false] - Whether to bypass the cache
   * @param {any} [options.defaultValue=null] - Default value if item is not found
   * @returns {Promise<any>} The retrieved data or default value if not found
   */
  async retrieve(key, options = {}) {
    // Ensure manager is initialized
    if (!this.adaptersInitialized) {
      await this.initialize();
    }
    
    // Normalize key
    const normalizedKey = this._normalizeKey(key);
    
    // Check cache first unless bypassed
    if (this.cacheConfig.enabled && !options.bypassCache) {
      const cachedItem = this._getFromCache(normalizedKey);
      if (cachedItem !== undefined) {
        return cachedItem;
      }
    }
    
    // Try to get from storage, starting with primary
    let storedValue = null;
    let retrievalSuccess = false;
    
    try {
      // Try primary storage
      storedValue = await this.storageAdapters[this.primaryStorage].getItem(normalizedKey);
      retrievalSuccess = storedValue !== null;
      
      // If not found in primary, try secondary
      if (!retrievalSuccess && this.secondaryStorage) {
        storedValue = await this.storageAdapters[this.secondaryStorage].getItem(normalizedKey);
        retrievalSuccess = storedValue !== null;
        
        // If found in secondary, also store in primary for next time
        if (retrievalSuccess) {
          this.storageAdapters[this.primaryStorage].setItem(normalizedKey, storedValue).catch(() => {});
        }
        
        // If still not found, try tertiary
        if (!retrievalSuccess && this.tertiaryStorage) {
          storedValue = await this.storageAdapters[this.tertiaryStorage].getItem(normalizedKey);
          retrievalSuccess = storedValue !== null;
          
          // If found in tertiary, also store in primary for next time
          if (retrievalSuccess) {
            this.storageAdapters[this.primaryStorage].setItem(normalizedKey, storedValue).catch(() => {});
          }
        }
      }
      
      // Parse the value if successfully retrieved
      if (retrievalSuccess && typeof storedValue === 'string') {
        try {
          const parsedValue = JSON.parse(storedValue);
          
          // Update cache with the retrieved value
          if (this.cacheConfig.enabled && !options.bypassCache) {
            this._updateCache(normalizedKey, parsedValue);
          }
          
          return parsedValue;
        } catch (parseError) {
          this.log(`Error parsing stored value for key ${normalizedKey}:`, parseError);
          // Return the raw string if parsing fails
          return storedValue;
        }
      }
    } catch (error) {
      this.log(`Error retrieving data for key ${normalizedKey}:`, error);
    }
    
    // Return default value if item wasn't found
    return options.defaultValue !== undefined ? options.defaultValue : null;
  }

  /**
   * Removes data from all storage adapters
   * 
   * @async
   * @param {string} key - The key to remove
   * @returns {Promise<boolean>} Whether the removal was successful
   */
  async remove(key) {
    // Ensure manager is initialized
    if (!this.adaptersInitialized) {
      await this.initialize();
    }
    
    // Normalize key
    const normalizedKey = this._normalizeKey(key);
    
    // Remove from cache
    this._removeFromCache(normalizedKey);
    
    // Remove from all storage adapters
    let success = true;
    const adapters = Object.keys(this.storageAdapters);
    
    for (const adapterName of adapters) {
      try {
        const adapterSuccess = await this.storageAdapters[adapterName].removeItem(normalizedKey);
        success = success && adapterSuccess;
      } catch (error) {
        this.log(`Error removing data for key ${normalizedKey} from ${adapterName}:`, error);
        success = false;
      }
    }
    
    return success;
  }

  /**
   * Clears all data in the managed namespace from all storage adapters
   * 
   * @async
   * @returns {Promise<boolean>} Whether the clear operation was successful
   */
  async clear() {
    // Ensure manager is initialized
    if (!this.adaptersInitialized) {
      await this.initialize();
    }
    
    // Clear cache
    this.cache.items.clear();
    this.cache.accessOrder = [];
    
    // Clear all storage adapters
    let success = true;
    const adapters = Object.keys(this.storageAdapters);
    
    for (const adapterName of adapters) {
      try {
        const adapterSuccess = await this.storageAdapters[adapterName].clear();
        success = success && adapterSuccess;
      } catch (error) {
        this.log(`Error clearing data from ${adapterName}:`, error);
        success = false;
      }
    }
    
    return success;
  }

  /**
   * Gets all keys stored in the primary storage
   * 
   * @async
   * @returns {Promise<string[]>} Array of keys
   */
  async getAllKeys() {
    // Ensure manager is initialized
    if (!this.adaptersInitialized) {
      await this.initialize();
    }
    
    try {
      // Get keys from primary storage
      const keys = await this.storageAdapters[this.primaryStorage].getKeys();
      
      // Filter out keys that don't belong to our namespace
      return keys.filter(key => key.startsWith(`${this.namespace}.`))
                .map(key => key.substring(this.namespace.length + 1));
    } catch (error) {
      this.log('Error getting all keys:', error);
      return [];
    }
  }

  /**
   * Normalizes a key by adding namespace prefix
   * 
   * @private
   * @param {string} key - The key to normalize
   * @returns {string} Normalized key
   */
  _normalizeKey(key) {
    // Remove the namespace prefix if already present
    if (key.startsWith(`${this.namespace}.`)) {
      key = key.substring(this.namespace.length + 1);
    }
    return key;
  }

  /**
   * Updates the cache with a new value and updates LRU tracking
   * 
   * @private
   * @param {string} key - The cache key
   * @param {any} value - The value to cache
   * @param {number} [ttl] - Time-to-live in milliseconds
   */
  _updateCache(key, value, ttl) {
    // Remove item from accessOrder if it exists
    const index = this.cache.accessOrder.indexOf(key);
    if (index !== -1) {
      this.cache.accessOrder.splice(index, 1);
    }
    
    // Add to the end of accessOrder (most recently used)
    this.cache.accessOrder.push(key);
    
    // Calculate expiry time
    const expiresAt = ttl ? Date.now() + ttl : Date.now() + this.cacheConfig.defaultTTL;
    
    // Store in cache
    this.cache.items.set(key, {
      value,
      expiresAt
    });
    
    // Enforce cache size limit (LRU eviction)
    if (this.cache.items.size > this.cacheConfig.maxSize) {
      // Remove least recently used item
      const oldestKey = this.cache.accessOrder.shift();
      if (oldestKey) {
        this.cache.items.delete(oldestKey);
      }
    }
  }

  /**
   * Gets a value from the cache if it exists and is not expired
   * 
   * @private
   * @param {string} key - The cache key
   * @returns {any} The cached value or undefined if not found/expired
   */
  _getFromCache(key) {
    const cachedItem = this.cache.items.get(key);
    
    if (!cachedItem) {
      return undefined;
    }
    
    // Check if the cached item has expired
    if (cachedItem.expiresAt < Date.now()) {
      // Remove expired item
      this._removeFromCache(key);
      return undefined;
    }
    
    // Update access order for LRU
    const index = this.cache.accessOrder.indexOf(key);
    if (index !== -1) {
      this.cache.accessOrder.splice(index, 1);
    }
    this.cache.accessOrder.push(key);
    
    return cachedItem.value;
  }

  /**
   * Removes an item from the cache
   * 
   * @private
   * @param {string} key - The cache key
   */
  _removeFromCache(key) {
    this.cache.items.delete(key);
    
    const index = this.cache.accessOrder.indexOf(key);
    if (index !== -1) {
      this.cache.accessOrder.splice(index, 1);
    }
  }
}

/**
 * LocalStorage Adapter
 * Provides interface for localStorage operations
 */
class LocalStorageAdapter {
  /**
   * Creates a LocalStorage adapter
   * 
   * @param {string} namespace - Namespace for keys
   */
  constructor(namespace) {
    this.namespace = namespace;
  }

  /**
   * Sets an item in localStorage
   * 
   * @param {string} key - The key to store under
   * @param {string} value - The value to store
   * @returns {Promise<boolean>} Whether the operation was successful
   */
  async setItem(key, value) {
    try {
      localStorage.setItem(`${this.namespace}.${key}`, value);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Gets an item from localStorage
   * 
   * @param {string} key - The key to retrieve
   * @returns {Promise<string|null>} The stored value or null if not found
   */
  async getItem(key) {
    try {
      return localStorage.getItem(`${this.namespace}.${key}`);
    } catch (error) {
      return null;
    }
  }

  /**
   * Removes an item from localStorage
   * 
   * @param {string} key - The key to remove
   * @returns {Promise<boolean>} Whether the operation was successful
   */
  async removeItem(key) {
    try {
      localStorage.removeItem(`${this.namespace}.${key}`);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Clears all items in the namespace from localStorage
   * 
   * @returns {Promise<boolean>} Whether the operation was successful
   */
  async clear() {
    try {
      const keys = this.getKeys();
      keys.forEach(key => localStorage.removeItem(key));
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Gets all keys in localStorage that belong to the namespace
   * 
   * @returns {string[]} Array of keys
   */
  getKeys() {
    const keys = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(`${this.namespace}.`)) {
        keys.push(key);
      }
    }
    return keys;
  }
}

/**
 * SessionStorage Adapter
 * Provides interface for sessionStorage operations
 */
class SessionStorageAdapter {
  /**
   * Creates a SessionStorage adapter
   * 
   * @param {string} namespace - Namespace for keys
   */
  constructor(namespace) {
    this.namespace = namespace;
  }

  /**
   * Sets an item in sessionStorage
   * 
   * @param {string} key - The key to store under
   * @param {string} value - The value to store
   * @returns {Promise<boolean>} Whether the operation was successful
   */
  async setItem(key, value) {
    try {
      sessionStorage.setItem(`${this.namespace}.${key}`, value);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Gets an item from sessionStorage
   * 
   * @param {string} key - The key to retrieve
   * @returns {Promise<string|null>} The stored value or null if not found
   */
  async getItem(key) {
    try {
      return sessionStorage.getItem(`${this.namespace}.${key}`);
    } catch (error) {
      return null;
    }
  }

  /**
   * Removes an item from sessionStorage
   * 
   * @param {string} key - The key to remove
   * @returns {Promise<boolean>} Whether the operation was successful
   */
  async removeItem(key) {
    try {
      sessionStorage.removeItem(`${this.namespace}.${key}`);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Clears all items in the namespace from sessionStorage
   * 
   * @returns {Promise<boolean>} Whether the operation was successful
   */
  async clear() {
    try {
      const keys = this.getKeys();
      keys.forEach(key => sessionStorage.removeItem(key));
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Gets all keys in sessionStorage that belong to the namespace
   * 
   * @returns {string[]} Array of keys
   */
  getKeys() {
    const keys = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && key.startsWith(`${this.namespace}.`)) {
        keys.push(key);
      }
    }
    return keys;
  }
}

/**
 * Cookie Storage Adapter
 * Provides interface for cookie operations
 */
class CookieStorageAdapter {
  /**
   * Creates a Cookie adapter
   * 
   * @param {string} namespace - Namespace for keys
   */
  constructor(namespace) {
    this.namespace = namespace;
    // Default cookie expiration (30 days)
    this.maxAge = 30 * 24 * 60 * 60; 
    this.path = '/';
  }

  /**
   * Sets a cookie
   * 
   * @param {string} key - The key to store under
   * @param {string} value - The value to store
   * @returns {Promise<boolean>} Whether the operation was successful
   */
  async setItem(key, value) {
    try {
      const encodedValue = encodeURIComponent(value);
      const name = `${this.namespace}.${key}`;
      
      // Check if we're in a secure context
      const secureFlag = window.location.protocol === 'https:' ? '; Secure' : '';
      
      // Set SameSite to Lax for better compatibility
      const sameSite = '; SameSite=Lax';
      
      // Set the cookie
      document.cookie = `${name}=${encodedValue}; path=${this.path}; max-age=${this.maxAge}${secureFlag}${sameSite}`;
      
      // Verify the cookie was set
      return document.cookie.indexOf(`${name}=`) !== -1;
    } catch (error) {
      return false;
    }
  }

  /**
   * Gets a cookie
   * 
   * @param {string} key - The key to retrieve
   * @returns {Promise<string|null>} The stored value or null if not found
   */
  async getItem(key) {
    try {
      const name = `${this.namespace}.${key}`;
      
      // Use a regex to extract the cookie value
      const match = document.cookie.match(new RegExp(
        '(^|;\\s*)' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)'
      ));
      
      return match ? decodeURIComponent(match[2]) : null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Removes a cookie
   * 
   * @param {string} key - The key to remove
   * @returns {Promise<boolean>} Whether the operation was successful
   */
  async removeItem(key) {
    try {
      const name = `${this.namespace}.${key}`;
      
      // Set expiration to past date to remove the cookie
      document.cookie = `${name}=; path=${this.path}; max-age=0`;
      
      // Verify the cookie was removed
      return document.cookie.indexOf(`${name}=`) === -1;
    } catch (error) {
      return false;
    }
  }

  /**
   * Clears all cookies in the namespace
   * 
   * @returns {Promise<boolean>} Whether the operation was successful
   */
  async clear() {
    try {
      const cookies = document.cookie.split(';');
      let success = true;
      
      for (const cookie of cookies) {
        const [name] = cookie.trim().split('=');
        if (name && name.startsWith(this.namespace)) {
          const removed = await this.removeItem(name.substring(this.namespace.length + 1));
          success = success && removed;
        }
      }
      
      return success;
    } catch (error) {
      return false;
    }
  }

  /**
   * Gets all cookie keys in the namespace
   * 
   * @returns {string[]} Array of keys
   */
  getKeys() {
    const cookies = document.cookie.split(';');
    const prefix = this.namespace + '.';
    const keys = [];
    
    for (const cookie of cookies) {
      const [name] = cookie.trim().split('=');
      if (name && name.startsWith(prefix)) {
        keys.push(name);
      }
    }
    
    return keys;
  }
}

/**
 * IndexedDB Storage Adapter
 * Provides interface for IndexedDB operations
 */
class IndexedDBStorageAdapter {
  /**
   * Creates an IndexedDB adapter
   * 
   * @param {string} namespace - Namespace for the database
   */
  constructor(namespace) {
    this.namespace = namespace;
    this.dbName = `${namespace}_storage`;
    this.storeName = 'keyValueStore';
    this.db = null;
  }

  /**
   * Initializes the IndexedDB database
   * 
   * @async
   * @returns {Promise<boolean>} Whether initialization was successful
   */
  async initialize() {
    return new Promise((resolve) => {
      try {
        const request = indexedDB.open(this.dbName, 1);
        
        request.onupgradeneeded = (event) => {
          const db = event.target.result;
          // Create object store if it doesn't exist
          if (!db.objectStoreNames.contains(this.storeName)) {
            db.createObjectStore(this.storeName, { keyPath: 'key' });
          }
        };
        
        request.onsuccess = (event) => {
          this.db = event.target.result;
          resolve(true);
        };
        
        request.onerror = () => {
          console.error('IndexedDB initialization error');
          resolve(false);
        };
      } catch (error) {
        console.error('IndexedDB initialization error:', error);
        resolve(false);
      }
    });
  }

  /**
   * Sets an item in IndexedDB
   * 
   * @param {string} key - The key to store under
   * @param {string} value - The value to store
   * @returns {Promise<boolean>} Whether the operation was successful
   */
  async setItem(key, value) {
    if (!this.db) {
      await this.initialize();
    }
    
    if (!this.db) {
      return false;
    }
    
    return new Promise((resolve) => {
      try {
        const transaction = this.db.transaction([this.storeName], 'readwrite');
        const store = transaction.objectStore(this.storeName);
        
        const request = store.put({
          key: `${this.namespace}.${key}`,
          value: value,
          timestamp: Date.now()
        });
        
        request.onsuccess = () => resolve(true);
        request.onerror = () => resolve(false);
      } catch (error) {
        console.error('IndexedDB setItem error:', error);
        resolve(false);
      }
    });
  }

  /**
   * Gets an item from IndexedDB
   * 
   * @param {string} key - The key to retrieve
   * @returns {Promise<string|null>} The stored value or null if not found
   */
  async getItem(key) {
    if (!this.db) {
      await this.initialize();
    }
    
    if (!this.db) {
      return null;
    }
    
    return new Promise((resolve) => {
      try {
        const transaction = this.db.transaction([this.storeName], 'readonly');
        const store = transaction.objectStore(this.storeName);
        
        const request = store.get(`${this.namespace}.${key}`);
        
        request.onsuccess = () => {
          const data = request.result;
          resolve(data ? data.value : null);
        };
        
        request.onerror = () => resolve(null);
      } catch (error) {
        console.error('IndexedDB getItem error:', error);
        resolve(null);
      }
    });
  }

  /**
   * Removes an item from IndexedDB
   * 
   * @param {string} key - The key to remove
   * @returns {Promise<boolean>} Whether the operation was successful
   */
  async removeItem(key) {
    if (!this.db) {
      await this.initialize();
    }
    
    if (!this.db) {
      return false;
    }
    
    return new Promise((resolve) => {
      try {
        const transaction = this.db.transaction([this.storeName], 'readwrite');
        const store = transaction.objectStore(this.storeName);
        
        const request = store.delete(`${this.namespace}.${key}`);
        
        request.onsuccess = () => resolve(true);
        request.onerror = () => resolve(false);
      } catch (error) {
        console.error('IndexedDB removeItem error:', error);
        resolve(false);
      }
    });
  }

  /**
   * Clears all items in IndexedDB
   * 
   * @returns {Promise<boolean>} Whether the operation was successful
   */
  async clear() {
    if (!this.db) {
      await this.initialize();
    }
    
    if (!this.db) {
      return false;
    }
    
    return new Promise((resolve) => {
      try {
        const transaction = this.db.transaction([this.storeName], 'readwrite');
        const store = transaction.objectStore(this.storeName);
        
        // Only clear items with our namespace
        const prefixRange = IDBKeyRange.bound(
          `${this.namespace}.`, 
          `${this.namespace}.\uffff`,
          false,
          false
        );
        
        const request = store.delete(prefixRange);
        
        request.onsuccess = () => resolve(true);
        request.onerror = () => resolve(false);
      } catch (error) {
        console.error('IndexedDB clear error:', error);
        resolve(false);
      }
    });
  }

  /**
   * Gets all keys in IndexedDB
   * 
   * @returns {Promise<string[]>} Array of keys
   */
  async getKeys() {
    if (!this.db) {
      await this.initialize();
    }
    
    if (!this.db) {
      return [];
    }
    
    return new Promise((resolve) => {
      try {
        const transaction = this.db.transaction([this.storeName], 'readonly');
        const store = transaction.objectStore(this.storeName);
        const keys = [];
        
        const request = store.openCursor();
        
        request.onsuccess = (event) => {
          const cursor = event.target.result;
          if (cursor) {
            if (cursor.key.startsWith(`${this.namespace}.`)) {
              keys.push(cursor.key);
            }
            cursor.continue();
          } else {
            resolve(keys);
          }
        };
        
        request.onerror = () => resolve([]);
      } catch (error) {
        console.error('IndexedDB getKeys error:', error);
        resolve([]);
      }
    });
  }
}

/**
 * Memory Storage Adapter
 * Provides in-memory storage for when other methods fail
 */
class MemoryStorageAdapter {
  /**
   * Creates a Memory storage adapter
   */
  constructor() {
    this.data = new Map();
  }

  /**
   * Sets an item in memory
   * 
   * @param {string} key - The key to store under
   * @param {string} value - The value to store
   * @returns {Promise<boolean>} Always resolves to true
   */
  async setItem(key, value) {
    this.data.set(key, value);
    return true;
  }

  /**
   * Gets an item from memory
   * 
   * @param {string} key - The key to retrieve
   * @returns {Promise<string|null>} The stored value or null if not found
   */
  async getItem(key) {
    return this.data.has(key) ? this.data.get(key) : null;
  }

  /**
   * Removes an item from memory
   * 
   * @param {string} key - The key to remove
   * @returns {Promise<boolean>} Always resolves to true
   */
  async removeItem(key) {
    this.data.delete(key);
    return true;
  }

  /**
   * Clears all items from memory
   * 
   * @returns {Promise<boolean>} Always resolves to true
   */
  async clear() {
    this.data.clear();
    return true;
  }

  /**
   * Gets all keys in memory
   * 
   * @returns {Promise<string[]>} Array of keys
   */
  async getKeys() {
    return Array.from(this.data.keys());
  }
}

// Export for both browser and Node.js environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SecureStorageManager };
} else if (typeof window !== 'undefined') {
  window.SecureStorageManager = SecureStorageManager;
} 