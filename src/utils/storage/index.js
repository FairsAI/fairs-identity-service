/**
 * Storage System Index
 * 
 * Exports the core storage components and provides a simple unified API.
 */

const { BrowserCapabilityDetector } = require('./BrowserCapabilityDetector');
const { SecureStorageManager } = require('./SecureStorageManager');

// Create a singleton instance with default options
let storageInstance = null;

/**
 * Get a singleton instance of the SecureStorageManager
 * 
 * @param {Object} options - Configuration options
 * @returns {SecureStorageManager} A SecureStorageManager instance
 */
function getStorageManager(options = {}) {
  if (!storageInstance) {
    storageInstance = new SecureStorageManager({
      namespace: 'fairs',
      ...options
    });
    
    // Initialize immediately
    storageInstance.initialize().catch(err => {
      console.error('Failed to initialize storage manager:', err);
    });
  }
  
  return storageInstance;
}

/**
 * Detect browser capabilities
 * 
 * @returns {Promise<Object>} Browser capabilities
 */
async function detectBrowserCapabilities() {
  const detector = new BrowserCapabilityDetector();
  return detector.detect();
}

// Export everything
module.exports = {
  BrowserCapabilityDetector,
  SecureStorageManager,
  getStorageManager,
  detectBrowserCapabilities
}; 