/**
 * Storage Migration Utilities
 * 
 * Provides tools for migrating from localStorage to secure storage
 * and maintaining backward compatibility.
 */

const { DataMigrator } = require('./DataMigrator');
const { CompatibilityLayer } = require('./CompatibilityLayer');

/**
 * Integrates secure storage with the application
 * 
 * @param {Object} options - Integration options
 * @param {Object} options.secureStorage - SecureStorageManager instance
 * @param {Array<string|RegExp>} [options.secureKeys=[]] - Keys to route through secure storage
 * @param {Array<string|RegExp>} [options.excludedKeys=[]] - Keys to exclude from secure storage
 * @param {boolean} [options.migrateImmediately=true] - Whether to migrate data immediately
 * @param {boolean} [options.patchGlobalStorage=true] - Whether to patch global localStorage
 * @param {boolean} [options.warnOnSyncUsage=true] - Whether to warn about synchronous usage
 * @param {boolean} [options.preferSecureStorage=false] - Whether to route all keys through secure storage by default
 * @param {Object} [options.migrationOptions={}] - Additional options for DataMigrator
 * @param {Object} [options.compatibilityOptions={}] - Additional options for CompatibilityLayer
 * @param {boolean} [options.debug=false] - Enable debug logging
 * @returns {Promise<Object>} Integration result
 */
async function integrateSecureStorage(options = {}) {
  if (!options.secureStorage) {
    throw new Error('SecureStorageManager is required for secure storage integration');
  }
  
  const secureStorage = options.secureStorage;
  const secureKeys = options.secureKeys || [];
  const excludedKeys = options.excludedKeys || [];
  const migrateImmediately = options.migrateImmediately !== false;
  const patchGlobalStorage = options.patchGlobalStorage !== false;
  const warnOnSyncUsage = options.warnOnSyncUsage !== false;
  const preferSecureStorage = options.preferSecureStorage || false;
  const migrationOptions = options.migrationOptions || {};
  const compatibilityOptions = options.compatibilityOptions || {};
  const debug = options.debug || false;
  
  // Create compatibility layer
  const compatibility = new CompatibilityLayer({
    secureStorage,
    secureKeys,
    excludedKeys,
    warnOnSyncUsage,
    preferSecureStorage,
    debug,
    ...compatibilityOptions
  });
  
  // Initialize compatibility layer
  await compatibility.initialize();
  
  // Patch global localStorage if requested
  let patchResult = false;
  if (patchGlobalStorage) {
    patchResult = compatibility.patchGlobalStorage();
    
    if (debug && !patchResult) {
      console.error('[SecureStorageIntegration] Failed to patch global localStorage');
    }
  }
  
  // Create data migrator
  const migrator = new DataMigrator({
    secureStorage,
    namespace: migrationOptions.namespace || 'fairs',
    keysToMigrate: migrationOptions.keysToMigrate || secureKeys.filter(k => typeof k === 'string'),
    transformers: migrationOptions.transformers || {},
    keepOriginal: migrationOptions.keepOriginal !== false,
    validateData: migrationOptions.validateData !== false,
    debug,
    ...migrationOptions
  });
  
  // Initialize migrator
  await migrator.initialize();
  
  // Migrate data if requested
  let migrationResult = null;
  if (migrateImmediately) {
    migrationResult = await migrator.migrate();
    
    if (debug) {
      if (migrationResult.success) {
        console.log(`[SecureStorageIntegration] Successfully migrated ${migrationResult.migratedCount} keys to secure storage`);
      } else {
        console.error(`[SecureStorageIntegration] Migration completed with errors - ${migrationResult.failedCount} keys failed`);
      }
    }
  }
  
  return {
    success: true,
    compatibility,
    migrator,
    patchResult,
    migrationResult
  };
}

/**
 * Creates a simple global integration using default sensible settings
 * 
 * @param {Object} secureStorage - SecureStorageManager instance
 * @param {Array<string>} secureKeys - Keys to secure (e.g., ['fairs_user_data', 'fairs_token'])
 * @param {boolean} [debug=false] - Enable debug logging
 * @returns {Promise<Object>} Integration result
 */
async function quickIntegration(secureStorage, secureKeys, debug = false) {
  if (!secureStorage) {
    throw new Error('SecureStorageManager is required for quick integration');
  }
  
  if (!Array.isArray(secureKeys) || secureKeys.length === 0) {
    throw new Error('At least one secure key must be provided for quick integration');
  }
  
  return integrateSecureStorage({
    secureStorage,
    secureKeys,
    migrateImmediately: true,
    patchGlobalStorage: true,
    warnOnSyncUsage: true,
    preferSecureStorage: false,
    debug
  });
}

/**
 * Applies the integration as a self-executing function
 * 
 * This function is meant to be used in a script tag to patch localStorage
 * immediately without explicit initialization.
 * 
 * @param {Object} globalConfig - Configuration object attached to window
 * @returns {Promise<void>} Resolves when integration is complete
 */
async function applyGlobalIntegration(globalConfig = {}) {
  // Use configuration from global object or defaults
  const config = typeof window !== 'undefined' && window.secureStorageConfig 
    ? window.secureStorageConfig 
    : globalConfig;
  
  if (!config || !config.secureStorage) {
    console.error('[SecureStorageIntegration] Cannot apply global integration - secureStorage not provided');
    return;
  }
  
  try {
    const secureKeys = config.secureKeys || ['fairs_user_data', 'fairs_xmid', 'fairs_verification'];
    const debug = config.debug || false;
    
    await quickIntegration(config.secureStorage, secureKeys, debug);
    
    if (debug) {
      console.log('[SecureStorageIntegration] Global integration applied successfully');
    }
  } catch (error) {
    console.error('[SecureStorageIntegration] Failed to apply global integration', error);
  }
}

// Global integration script
if (typeof window !== 'undefined') {
  // Add global integration function to window
  window.integrateSecureStorage = integrateSecureStorage;
  window.quickIntegrateSecureStorage = quickIntegration;
  
  // Auto-apply if configured
  if (window.secureStorageConfig && window.secureStorageConfig.autoApply) {
    applyGlobalIntegration(window.secureStorageConfig).catch(console.error);
  }
}

// Export modules and utilities
module.exports = {
  DataMigrator,
  CompatibilityLayer,
  integrateSecureStorage,
  quickIntegration,
  applyGlobalIntegration
}; 