/**
 * Usage Example for Secure Storage System
 * 
 * This file demonstrates how to use the new secure storage system
 * to replace the current localStorage implementation.
 */

// Import the storage manager
const { getStorageManager, detectBrowserCapabilities } = require('./index');

/**
 * Example: Storing User Data
 * 
 * Before:
 * ```javascript
 * localStorage.setItem('fairs_user_data', JSON.stringify(userData));
 * ```
 * 
 * After:
 */
async function storeUserData(userData) {
  const storage = getStorageManager();
  
  // Store the user data with high importance (will try multiple storage mechanisms)
  const success = await storage.store('user_data', userData, {
    important: true,  // Try all available storage methods
    ttl: 24 * 60 * 60 * 1000  // Cache for 24 hours
  });
  
  if (!success) {
    console.warn('Failed to persist user data');
  }
  
  return success;
}

/**
 * Example: Retrieving User Data
 * 
 * Before:
 * ```javascript
 * const userData = JSON.parse(localStorage.getItem('fairs_user_data') || '{}');
 * ```
 * 
 * After:
 */
async function getUserData() {
  const storage = getStorageManager();
  
  // Retrieve the user data with a default empty object
  return await storage.retrieve('user_data', {
    defaultValue: {}
  });
}

/**
 * Example: Storing Cross-Merchant ID
 * 
 * Before:
 * ```javascript
 * localStorage.setItem('fairs_xmid', universalId);
 * ```
 * 
 * After:
 */
async function storeUniversalId(universalId) {
  const storage = getStorageManager();
  
  // Store the universal ID with high importance
  const success = await storage.store('xmid', universalId, {
    important: true
  });
  
  if (!success) {
    console.warn('Failed to persist universal ID');
  }
  
  return success;
}

/**
 * Example: Retrieving Cross-Merchant ID
 * 
 * Before:
 * ```javascript
 * const universalId = localStorage.getItem('fairs_xmid');
 * ```
 * 
 * After:
 */
async function getUniversalId() {
  const storage = getStorageManager();
  
  // Retrieve the universal ID
  return await storage.retrieve('xmid', {
    defaultValue: null
  });
}

/**
 * Example: Storing Merchant Mappings
 * 
 * Before:
 * ```javascript
 * localStorage.setItem('fairs_xm_mappings', JSON.stringify(mappings));
 * ```
 * 
 * After:
 */
async function storeMerchantMappings(mappings) {
  const storage = getStorageManager();
  
  // Store the mappings
  const success = await storage.store('xm_mappings', mappings, {
    important: true
  });
  
  if (!success) {
    console.warn('Failed to persist merchant mappings');
  }
  
  return success;
}

/**
 * Example: Retrieving Merchant Mappings
 * 
 * Before:
 * ```javascript
 * const mappings = JSON.parse(localStorage.getItem('fairs_xm_mappings') || '{}');
 * ```
 * 
 * After:
 */
async function getMerchantMappings() {
  const storage = getStorageManager();
  
  // Retrieve the mappings with a default empty object
  return await storage.retrieve('xm_mappings', {
    defaultValue: {}
  });
}

/**
 * Example: Checking if a user has a mapping for a specific merchant
 * 
 * Before:
 * ```javascript
 * const universalId = localStorage.getItem('fairs_xmid');
 * if (universalId) {
 *   const mappings = JSON.parse(localStorage.getItem('fairs_xm_mappings') || '{}');
 *   if (mappings['nike-demo']) {
 *     // Process for returning user
 *   }
 * }
 * ```
 * 
 * After:
 */
async function hasMerchantMapping(merchantId) {
  const storage = getStorageManager();
  
  // Get the universal ID first
  const universalId = await storage.retrieve('xmid');
  
  if (!universalId) {
    return false;
  }
  
  // Get the mappings
  const mappings = await storage.retrieve('xm_mappings', {
    defaultValue: {}
  });
  
  // Check if we have a mapping for the specific merchant
  return !!mappings[merchantId];
}

/**
 * Example: Detecting browser capabilities before using storage
 * 
 * This can be used to make decisions about which features to enable
 * based on the browser's capabilities.
 */
async function checkAndAdaptToBrowserCapabilities() {
  try {
    // Detect capabilities
    const capabilities = await detectBrowserCapabilities();
    
    console.log('Browser storage capabilities:', capabilities.storage);
    console.log('Browser environment:', capabilities.environment);
    console.log('Security features:', capabilities.securityFeatures);
    console.log('Recommended storage methods:', capabilities.recommended);
    
    // Example of adapting UI based on capabilities
    if (capabilities.environment.isPrivateMode) {
      showPrivateBrowsingNotice();
    }
    
    if (!capabilities.environment.supportsThirdPartyCookies) {
      showCookieRestrictionNotice();
    }
    
    return capabilities;
  } catch (error) {
    console.error('Failed to detect browser capabilities:', error);
    return null;
  }
}

/**
 * Example UI notification functions (to be implemented)
 */
function showPrivateBrowsingNotice() {
  // Implement UI notification about private browsing limitations
  console.log('Notice: You are browsing in private/incognito mode. Some features may be limited.');
}

function showCookieRestrictionNotice() {
  // Implement UI notification about cookie restrictions
  console.log('Notice: Your browser has cookie restrictions that may limit cross-site functionality.');
}

// Export the example functions
module.exports = {
  storeUserData,
  getUserData,
  storeUniversalId,
  getUniversalId,
  storeMerchantMappings,
  getMerchantMappings,
  hasMerchantMapping,
  checkAndAdaptToBrowserCapabilities
}; 