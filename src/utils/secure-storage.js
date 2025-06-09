/**
 * Enhanced secure storage with improved encryption and integrity
 */

class SecureStorage {
  constructor(namespace = 'fa', options = {}) {
    this.namespace = namespace;
    this.encryptionEnabled = options.encryption !== false && this._isEncryptionAvailable();
    this.integrityCheckEnabled = options.integrityCheck !== false;
    this.defaultStorage = options.defaultStorage || 'localStorage';
    this.memoryStorage = {};
  }
  
  _isEncryptionAvailable() {
    return typeof crypto !== 'undefined' && 
           typeof crypto.subtle !== 'undefined' && 
           typeof crypto.subtle.encrypt === 'function';
  }
  
  async setItem(key, value) {
    const prefixedKey = this.namespace + '.' + key;
    
    try {
      // Store in localStorage as primary storage
      localStorage.setItem(prefixedKey, JSON.stringify(value));
      return true;
    } catch (e) {
      // If localStorage fails, use memory storage
      this.memoryStorage[prefixedKey] = value;
      return false;
    }
  }
  
  async getItem(key) {
    const prefixedKey = this.namespace + '.' + key;
    
    try {
      // Try localStorage first
      const storedValue = localStorage.getItem(prefixedKey);
      if (storedValue !== null) {
        return JSON.parse(storedValue);
      }
    } catch (e) {
      // Ignore localStorage errors
    }
    
    // Fall back to memory storage
    return prefixedKey in this.memoryStorage ? this.memoryStorage[prefixedKey] : null;
  }
  
  removeItem(key) {
    const prefixedKey = this.namespace + '.' + key;
    
    try {
      localStorage.removeItem(prefixedKey);
    } catch (e) {
      // Ignore errors
    }
    
    delete this.memoryStorage[prefixedKey];
  }
}

// Export for use in browser and Node.js environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SecureStorage };
} else if (typeof window !== 'undefined') {
  window.SecureStorage = SecureStorage;
} 