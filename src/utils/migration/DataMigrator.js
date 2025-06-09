/**
 * Data Migrator
 * 
 * Migrates data from legacy storage (localStorage) to the new secure storage system.
 * Provides validation, versioning, and rollback capabilities.
 */

class DataMigrator {
  /**
   * Creates a new DataMigrator instance
   * 
   * @param {Object} options - Configuration options
   * @param {Object} options.secureStorage - SecureStorageManager instance
   * @param {Object} [options.sourceStorage=localStorage] - Source storage (defaults to localStorage)
   * @param {string} [options.namespace='fairs'] - Namespace for legacy data
   * @param {Array<string>} [options.keysToMigrate] - Specific keys to migrate (migrates all namespace keys if not specified)
   * @param {Object} [options.transformers={}] - Data transformers by key pattern
   * @param {boolean} [options.keepOriginal=true] - Whether to keep original data after migration
   * @param {boolean} [options.validateData=true] - Whether to validate data after migration
   * @param {boolean} [options.debug=false] - Enable debug logging
   */
  constructor(options = {}) {
    if (!options.secureStorage) {
      throw new Error('SecureStorageManager is required for DataMigrator');
    }
    
    this.secureStorage = options.secureStorage;
    this.sourceStorage = options.sourceStorage || (typeof localStorage !== 'undefined' ? localStorage : null);
    this.namespace = options.namespace || 'fairs';
    this.keysToMigrate = options.keysToMigrate || null;
    this.transformers = options.transformers || {};
    this.keepOriginal = options.keepOriginal !== false;
    this.validateData = options.validateData !== false;
    this.debug = options.debug || false;
    
    // Migration metadata key
    this.migrationMetaKey = `${this.namespace}_migration_metadata`;
    
    // Migration status
    this.migrationStatus = {
      inProgress: false,
      version: 0,
      startTime: null,
      completedKeys: [],
      failedKeys: [],
      lastError: null
    };
    
    // Backup of migrated data for rollback
    this.backupData = new Map();
  }
  
  /**
   * Initializes the migrator and loads migration status
   * 
   * @async
   * @returns {Promise<Object>} Current migration status
   */
  async initialize() {
    try {
      // Load existing migration status
      await this._loadMigrationStatus();
      
      this._log('DataMigrator initialized with status:', this.migrationStatus);
      return this.migrationStatus;
    } catch (error) {
      this._logError('Failed to initialize DataMigrator', error);
      return this.migrationStatus;
    }
  }
  
  /**
   * Loads existing migration status from secure storage
   * 
   * @private
   * @async
   */
  async _loadMigrationStatus() {
    try {
      const storedStatus = await this.secureStorage.retrieve(this.migrationMetaKey);
      
      if (storedStatus) {
        this.migrationStatus = {
          ...this.migrationStatus,
          ...storedStatus
        };
      }
    } catch (error) {
      this._logError('Failed to load migration status', error);
    }
  }
  
  /**
   * Saves current migration status to secure storage
   * 
   * @private
   * @async
   * @returns {Promise<boolean>} Success status
   */
  async _saveMigrationStatus() {
    try {
      await this.secureStorage.store(this.migrationMetaKey, {
        ...this.migrationStatus,
        lastUpdated: new Date().toISOString()
      });
      return true;
    } catch (error) {
      this._logError('Failed to save migration status', error);
      return false;
    }
  }
  
  /**
   * Gets keys to migrate based on namespace and configuration
   * 
   * @private
   * @returns {Array<string>} Keys to migrate
   */
  _getKeysToMigrate() {
    // If specific keys are provided, use those
    if (Array.isArray(this.keysToMigrate) && this.keysToMigrate.length > 0) {
      return [...this.keysToMigrate];
    }
    
    // Otherwise, find all keys in localStorage that start with namespace
    if (this.sourceStorage) {
      const keys = [];
      for (let i = 0; i < this.sourceStorage.length; i++) {
        const key = this.sourceStorage.key(i);
        if (key && key.startsWith(`${this.namespace}.`)) {
          keys.push(key);
        }
      }
      return keys;
    }
    
    return [];
  }
  
  /**
   * Starts the migration process
   * 
   * @async
   * @param {Object} [options={}] - Migration options
   * @param {number} [options.version] - Migration version (defaults to current version + 1)
   * @param {boolean} [options.force=false] - Whether to force migration even if already completed
   * @returns {Promise<Object>} Migration result
   */
  async migrate(options = {}) {
    const forceRun = options.force || false;
    const newVersion = options.version || (this.migrationStatus.version + 1);
    
    // Check if migration is already in progress
    if (this.migrationStatus.inProgress && !forceRun) {
      this._log('Migration already in progress, skipping');
      return {
        success: false,
        status: this.migrationStatus,
        error: 'Migration already in progress'
      };
    }
    
    // Update migration status
    this.migrationStatus = {
      ...this.migrationStatus,
      inProgress: true,
      version: newVersion,
      startTime: new Date().toISOString(),
      completedKeys: [],
      failedKeys: [],
      lastError: null
    };
    
    await this._saveMigrationStatus();
    
    try {
      // Get keys to migrate
      const keysToMigrate = this._getKeysToMigrate();
      
      if (keysToMigrate.length === 0) {
        this._log('No keys found to migrate');
        this.migrationStatus.inProgress = false;
        await this._saveMigrationStatus();
        return {
          success: true,
          status: this.migrationStatus,
          message: 'No keys found to migrate'
        };
      }
      
      this._log(`Starting migration of ${keysToMigrate.length} keys to secure storage`);
      
      // Clear backup data
      this.backupData.clear();
      
      // Process each key
      for (const key of keysToMigrate) {
        try {
          await this._migrateKey(key);
          this.migrationStatus.completedKeys.push(key);
        } catch (error) {
          this._logError(`Failed to migrate key: ${key}`, error);
          this.migrationStatus.failedKeys.push(key);
          this.migrationStatus.lastError = error.message;
        }
        
        // Periodically save migration status
        if ((this.migrationStatus.completedKeys.length + this.migrationStatus.failedKeys.length) % 5 === 0) {
          await this._saveMigrationStatus();
        }
      }
      
      // Update final status
      this.migrationStatus.inProgress = false;
      this.migrationStatus.endTime = new Date().toISOString();
      await this._saveMigrationStatus();
      
      // Validate migration if needed
      let validationResult = { success: true };
      if (this.validateData) {
        validationResult = await this.validateMigration();
      }
      
      return {
        success: this.migrationStatus.failedKeys.length === 0 && validationResult.success,
        status: this.migrationStatus,
        migratedCount: this.migrationStatus.completedKeys.length,
        failedCount: this.migrationStatus.failedKeys.length,
        validationResult
      };
    } catch (error) {
      this._logError('Migration failed with error', error);
      
      // Update status on error
      this.migrationStatus.inProgress = false;
      this.migrationStatus.endTime = new Date().toISOString();
      this.migrationStatus.lastError = error.message;
      await this._saveMigrationStatus();
      
      return {
        success: false,
        status: this.migrationStatus,
        error: error.message
      };
    }
  }
  
  /**
   * Migrates a single key from source to secure storage
   * 
   * @private
   * @async
   * @param {string} key - Key to migrate
   * @returns {Promise<boolean>} Success status
   */
  async _migrateKey(key) {
    try {
      // Read from source storage
      const rawValue = this.sourceStorage.getItem(key);
      
      if (rawValue === null) {
        this._log(`Key ${key} not found in source storage`);
        return false;
      }
      
      // Parse value if it's JSON
      let value;
      try {
        value = JSON.parse(rawValue);
      } catch (e) {
        // Use raw value if not JSON
        value = rawValue;
      }
      
      // Apply transformer if available
      const transformedValue = this._transformValue(key, value);
      
      // Backup original data for potential rollback
      this.backupData.set(key, { sourceValue: value, transformedValue });
      
      // Store in secure storage
      await this.secureStorage.store(key, transformedValue);
      
      // Remove from source if not keeping original
      if (!this.keepOriginal) {
        this.sourceStorage.removeItem(key);
      }
      
      this._log(`Successfully migrated key: ${key}`);
      return true;
    } catch (error) {
      throw new Error(`Failed to migrate key ${key}: ${error.message}`);
    }
  }
  
  /**
   * Transforms data based on configured transformers
   * 
   * @private
   * @param {string} key - Data key
   * @param {any} value - Data value
   * @returns {any} Transformed value
   */
  _transformValue(key, value) {
    // Find matching transformer
    for (const pattern in this.transformers) {
      if (key.match(new RegExp(pattern))) {
        try {
          const transformer = this.transformers[pattern];
          return transformer(value, key);
        } catch (error) {
          this._logError(`Transformation failed for key ${key}`, error);
          // Return original if transformation fails
          return value;
        }
      }
    }
    
    // Return original if no transformer found
    return value;
  }
  
  /**
   * Validates the migration by comparing source and migrated data
   * 
   * @async
   * @returns {Promise<Object>} Validation result
   */
  async validateMigration() {
    const result = {
      success: true,
      validatedKeys: 0,
      mismatchedKeys: [],
      errors: []
    };
    
    try {
      // Get migrated keys
      const migratedKeys = this.migrationStatus.completedKeys;
      
      for (const key of migratedKeys) {
        try {
          // Get original value
          let originalValue = this.sourceStorage.getItem(key);
          
          if (originalValue === null) {
            continue; // Skip if original no longer exists
          }
          
          // Parse if JSON
          try {
            originalValue = JSON.parse(originalValue);
          } catch (e) {
            // Keep as is if not JSON
          }
          
          // Apply transformer to get expected value
          const expectedValue = this._transformValue(key, originalValue);
          
          // Get stored secure value
          const secureValue = await this.secureStorage.retrieve(key);
          
          // Compare values
          const isEqual = this._deepEquals(secureValue, expectedValue);
          
          result.validatedKeys++;
          
          if (!isEqual) {
            result.success = false;
            result.mismatchedKeys.push(key);
          }
        } catch (error) {
          result.success = false;
          result.errors.push({ key, error: error.message });
        }
      }
      
      this._log(`Validation completed: ${result.validatedKeys} keys checked, ${result.mismatchedKeys.length} mismatches`);
      return result;
    } catch (error) {
      this._logError('Validation failed', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  /**
   * Performs a deep equality check between two values
   * 
   * @private
   * @param {any} a - First value
   * @param {any} b - Second value
   * @returns {boolean} Whether values are deeply equal
   */
  _deepEquals(a, b) {
    if (a === b) return true;
    
    if (a === null || b === null) return false;
    if (a === undefined || b === undefined) return false;
    
    if (typeof a !== typeof b) return false;
    
    if (typeof a === 'object') {
      if (Array.isArray(a) && Array.isArray(b)) {
        if (a.length !== b.length) return false;
        
        for (let i = 0; i < a.length; i++) {
          if (!this._deepEquals(a[i], b[i])) return false;
        }
        
        return true;
      }
      
      const keysA = Object.keys(a);
      const keysB = Object.keys(b);
      
      if (keysA.length !== keysB.length) return false;
      
      for (const key of keysA) {
        if (!keysB.includes(key)) return false;
        if (!this._deepEquals(a[key], b[key])) return false;
      }
      
      return true;
    }
    
    return false;
  }
  
  /**
   * Rolls back migration for all keys or specified keys
   * 
   * @async
   * @param {Object} [options={}] - Rollback options
   * @param {Array<string>} [options.keys] - Specific keys to roll back (defaults to all migrated keys)
   * @returns {Promise<Object>} Rollback result
   */
  async rollback(options = {}) {
    try {
      if (!this.backupData.size) {
        return {
          success: false,
          message: 'No backup data available for rollback'
        };
      }
      
      const keysToRollback = options.keys || Array.from(this.backupData.keys());
      const result = {
        success: true,
        rolledBackKeys: [],
        failedKeys: []
      };
      
      for (const key of keysToRollback) {
        try {
          // Only rollback keys that we have backup data for
          if (!this.backupData.has(key)) {
            continue;
          }
          
          const { sourceValue } = this.backupData.get(key);
          
          // Remove from secure storage
          await this.secureStorage.remove(key);
          
          // Restore to source storage if it was removed
          if (!this.keepOriginal) {
            const valueToStore = typeof sourceValue === 'string' 
              ? sourceValue 
              : JSON.stringify(sourceValue);
            
            this.sourceStorage.setItem(key, valueToStore);
          }
          
          result.rolledBackKeys.push(key);
        } catch (error) {
          this._logError(`Failed to rollback key: ${key}`, error);
          result.success = false;
          result.failedKeys.push(key);
        }
      }
      
      // Update migration status
      const rolledBackSet = new Set(result.rolledBackKeys);
      this.migrationStatus.completedKeys = this.migrationStatus.completedKeys
        .filter(key => !rolledBackSet.has(key));
      
      await this._saveMigrationStatus();
      
      this._log(`Rollback completed: ${result.rolledBackKeys.length} keys rolled back, ${result.failedKeys.length} failed`);
      return result;
    } catch (error) {
      this._logError('Rollback failed with error', error);
      return {
        success: false,
        error: error.message
      };
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
      console.log('[DataMigrator]', ...args);
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
      console.error('[DataMigrator] ERROR:', message, error);
    }
  }
}

// Export for both browser and Node.js environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { DataMigrator };
} else if (typeof window !== 'undefined') {
  window.DataMigrator = DataMigrator;
} 