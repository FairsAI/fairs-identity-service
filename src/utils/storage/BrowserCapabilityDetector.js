/**
 * Browser Capability Detector
 * 
 * Detects available browser features and storage mechanisms for robust client-side storage.
 * This class is crucial for the secure storage implementation to determine available options
 * and fallback strategies based on the browser environment.
 */

class BrowserCapabilityDetector {
  /**
   * Detects all browser capabilities and returns a comprehensive capabilities object
   * 
   * @async
   * @returns {Promise<Object>} Object containing all detected capabilities
   */
  async detect() {
    const capabilities = {
      storage: {
        localStorage: this.checkLocalStorage(),
        sessionStorage: this.checkSessionStorage(),
        cookies: this.checkCookies(),
        indexedDB: await this.checkIndexedDB(),
      },
      environment: {
        isPrivateMode: await this.detectPrivateMode(),
        hasStoragePartitioning: this.detectStoragePartitioning(),
        supportsThirdPartyCookies: await this.checkThirdPartyCookies(),
        supportsWebCrypto: this.checkWebCrypto(),
      },
      securityFeatures: {
        secureCookiesSupported: this.checkSecureCookies(),
        sameSiteSupported: this.checkSameSiteCookies(),
      },
      recommended: {
        primaryStorage: null,
        secondaryStorage: null,
        tertiaryStorage: null,
      }
    };

    // Determine recommended storage methods based on detected capabilities
    capabilities.recommended = this._determineRecommendedStorage(capabilities);

    return capabilities;
  }

  /**
   * Checks if localStorage is available and can be used
   * 
   * @returns {boolean} Whether localStorage is available
   */
  checkLocalStorage() {
    try {
      const testKey = '_browser_capability_test_';
      localStorage.setItem(testKey, 'test');
      const result = localStorage.getItem(testKey) === 'test';
      localStorage.removeItem(testKey);
      return result;
    } catch (error) {
      return false;
    }
  }

  /**
   * Checks if sessionStorage is available and can be used
   * 
   * @returns {boolean} Whether sessionStorage is available
   */
  checkSessionStorage() {
    try {
      const testKey = '_browser_capability_test_';
      sessionStorage.setItem(testKey, 'test');
      const result = sessionStorage.getItem(testKey) === 'test';
      sessionStorage.removeItem(testKey);
      return result;
    } catch (error) {
      return false;
    }
  }

  /**
   * Checks if cookies are available and can be set
   * 
   * @returns {boolean} Whether cookies are available
   */
  checkCookies() {
    try {
      const testKey = '_browser_capability_test_';
      const testValue = 'test';
      
      // Set test cookie with a short expiry
      document.cookie = `${testKey}=${testValue}; path=/; max-age=10`;
      
      // Check if cookie was set successfully
      const success = document.cookie.indexOf(`${testKey}=${testValue}`) !== -1;
      
      // Clean up
      document.cookie = `${testKey}=; path=/; max-age=0`;
      
      return success;
    } catch (error) {
      return false;
    }
  }

  /**
   * Checks if IndexedDB is available and can be used
   * 
   * @async
   * @returns {Promise<boolean>} Whether IndexedDB is available
   */
  async checkIndexedDB() {
    if (!window.indexedDB) {
      return false;
    }

    return new Promise(resolve => {
      try {
        const dbName = '_browser_capability_test_';
        const request = indexedDB.open(dbName, 1);
        
        // Set a timeout in case the indexedDB request hangs
        const timeoutId = setTimeout(() => {
          resolve(false);
        }, 1000);
        
        request.onerror = () => {
          clearTimeout(timeoutId);
          resolve(false);
        };
        
        request.onsuccess = event => {
          clearTimeout(timeoutId);
          const db = event.target.result;
          db.close();
          
          // Clean up the test database
          indexedDB.deleteDatabase(dbName);
          resolve(true);
        };
      } catch (error) {
        resolve(false);
      }
    });
  }

  /**
   * Detects if the browser is in private browsing mode
   * This is a best-effort detection and may not be 100% accurate for all browsers
   * 
   * @async
   * @returns {Promise<boolean>} Whether the browser is likely in private mode
   */
  async detectPrivateMode() {
    // Safari private mode detection (most reliable)
    if (window.safari && window.safari.pushNotification) {
      return true;
    }

    // Firefox detection through error handling for localStorage quota
    try {
      const testKey = 'storage_test';
      // Try to fill storage in Firefox (will throw in private mode)
      const data = '0'.repeat(5 * 1024 * 1024); // 5MB
      localStorage.setItem(testKey, data);
      localStorage.removeItem(testKey);
      return false;
    } catch (e) {
      // Error indicates possible private mode
      // But we need to differentiate from other localStorage errors
      if (e instanceof DOMException && 
          (e.code === 22 || e.code === 1014 || 
           e.name === 'QuotaExceededError' || 
           e.name === 'NS_ERROR_DOM_QUOTA_REACHED')) {
        // Looks like private mode
        return true;
      }
    }

    // Chrome detection through indexedDB access
    if (window.indexedDB) {
      try {
        const db = await this._testIndexedDBForPrivateMode();
        return !db; // If db is null, likely in private mode
      } catch (e) {
        return true; // Error likely indicates private mode
      }
    }

    // Edge cases - other heuristic checks
    const isIE = navigator.userAgent.includes('MSIE') || 
                 navigator.userAgent.includes('Trident/');
    
    if (isIE) {
      try {
        window.localStorage;
        return false;
      } catch (e) {
        return true;
      }
    }

    // Default - if we can't determine, assume not in private mode
    return false;
  }

  /**
   * Helper method for private mode detection using IndexedDB
   * 
   * @private
   * @async
   * @returns {Promise<boolean>} Whether IndexedDB test succeeded
   */
  _testIndexedDBForPrivateMode() {
    return new Promise((resolve, reject) => {
      try {
        const dbName = '_private_mode_test_';
        const request = indexedDB.open(dbName);
        
        request.onerror = () => {
          resolve(null);
        };
        
        request.onsuccess = (event) => {
          const db = event.target.result;
          db.close();
          indexedDB.deleteDatabase(dbName);
          resolve(db);
        };

        // Set a timeout in case the request hangs
        setTimeout(() => resolve(null), 1000);
      } catch (e) {
        reject(e);
      }
    });
  }

  /**
   * Detects if the browser implements storage partitioning
   * Modern browsers increasingly partition storage by origin to prevent tracking
   * 
   * @returns {boolean} Whether storage partitioning is likely enabled
   */
  detectStoragePartitioning() {
    const ua = navigator.userAgent.toLowerCase();
    
    // Safari implements strict storage partitioning
    if (ua.includes('safari') && !ua.includes('chrome')) {
      return true;
    }
    
    // Firefox with enhanced tracking protection
    if (ua.includes('firefox') && !ua.includes('seamonkey')) {
      return true; // Firefox has Tracking Protection
    }
    
    // Chrome 89+ implements partitioned third-party storage
    if (ua.includes('chrome')) {
      const chromeMatch = ua.match(/chrome\/(\d+)/);
      if (chromeMatch && chromeMatch[1]) {
        const version = parseInt(chromeMatch[1], 10);
        return version >= 89;
      }
    }
    
    // Default to true for newer browsers as this is becoming standard
    return true;
  }

  /**
   * Tests if third-party cookies are supported
   * This is a best-effort detection that may not be 100% accurate
   * 
   * @async
   * @returns {Promise<boolean>} Whether third-party cookies likely work
   */
  async checkThirdPartyCookies() {
    // The most reliable way would be to check with an actual third-party domain
    // Since we can't do that synchronously, we use heuristics

    // Check for known user agents that block third-party cookies by default
    const ua = navigator.userAgent.toLowerCase();
    
    if (ua.includes('safari') && !ua.includes('chrome')) {
      // Safari blocks third-party cookies by default
      return false;
    }
    
    if (ua.includes('firefox')) {
      // Firefox with Enhanced Tracking Protection blocks third-party cookies
      return false;
    }

    // For Chrome 89+, Storage Access API indicates partitioning
    if (typeof document.hasStorageAccess === 'function') {
      try {
        const hasAccess = await document.hasStorageAccess();
        // If we need to request access, third-party cookies are likely restricted
        return hasAccess;
      } catch (e) {
        // If this fails, assume restriction
        return false;
      }
    }

    // Default to false as browsers are increasingly restricting third-party cookies
    return false;
  }

  /**
   * Checks if the Web Crypto API is available
   * 
   * @returns {boolean} Whether Web Crypto API is available
   */
  checkWebCrypto() {
    return typeof window.crypto !== 'undefined' && 
           typeof window.crypto.subtle !== 'undefined' &&
           typeof window.crypto.subtle.encrypt === 'function';
  }

  /**
   * Checks if secure cookies are supported
   * 
   * @returns {boolean} Whether secure cookies are supported
   */
  checkSecureCookies() {
    // Secure cookies require HTTPS
    return window.location.protocol === 'https:';
  }

  /**
   * Checks if SameSite cookie attribute is supported
   * 
   * @returns {boolean} Whether SameSite attribute is supported
   */
  checkSameSiteCookies() {
    // Most modern browsers support SameSite
    const ua = navigator.userAgent.toLowerCase();
    
    // Check for very old browsers that don't support SameSite
    if (ua.includes('chrome')) {
      const chromeMatch = ua.match(/chrome\/(\d+)/);
      if (chromeMatch && chromeMatch[1]) {
        const version = parseInt(chromeMatch[1], 10);
        return version >= 51; // Chrome 51+ supports SameSite
      }
    }
    
    // Safari 12+, Firefox 60+, Edge 16+ all support SameSite
    return true; // Default to true for modern browsers
  }

  /**
   * Determines the recommended storage methods based on detected capabilities
   * 
   * @private
   * @param {Object} capabilities - The detected capabilities object
   * @returns {Object} Recommended storage methods in order of preference
   */
  _determineRecommendedStorage(capabilities) {
    const recommended = {
      primaryStorage: null,
      secondaryStorage: null,
      tertiaryStorage: null,
    };

    // Priority order based on security, persistence, and size capabilities
    if (capabilities.storage.indexedDB) {
      recommended.primaryStorage = 'indexedDB';
    } else if (capabilities.storage.localStorage) {
      recommended.primaryStorage = 'localStorage';
    } else if (capabilities.storage.cookies) {
      recommended.primaryStorage = 'cookies';
    } else {
      recommended.primaryStorage = 'memory';
    }

    // Secondary storage (different from primary)
    if (recommended.primaryStorage !== 'localStorage' && capabilities.storage.localStorage) {
      recommended.secondaryStorage = 'localStorage';
    } else if (recommended.primaryStorage !== 'cookies' && capabilities.storage.cookies) {
      recommended.secondaryStorage = 'cookies';
    } else if (recommended.primaryStorage !== 'sessionStorage' && capabilities.storage.sessionStorage) {
      recommended.secondaryStorage = 'sessionStorage';
    } else if (recommended.primaryStorage !== 'indexedDB' && capabilities.storage.indexedDB) {
      recommended.secondaryStorage = 'indexedDB';
    } else {
      recommended.secondaryStorage = 'memory';
    }

    // Tertiary storage (different from primary and secondary)
    if (recommended.primaryStorage !== 'sessionStorage' && 
        recommended.secondaryStorage !== 'sessionStorage' && 
        capabilities.storage.sessionStorage) {
      recommended.tertiaryStorage = 'sessionStorage';
    } else if (recommended.primaryStorage !== 'cookies' && 
              recommended.secondaryStorage !== 'cookies' && 
              capabilities.storage.cookies) {
      recommended.tertiaryStorage = 'cookies';
    } else {
      recommended.tertiaryStorage = 'memory';
    }

    return recommended;
  }
}

// Export for both browser and Node.js environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { BrowserCapabilityDetector };
} else if (typeof window !== 'undefined') {
  window.BrowserCapabilityDetector = BrowserCapabilityDetector;
} 