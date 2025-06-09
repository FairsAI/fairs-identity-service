/**
 * Privacy Respecting Fingerprinter
 * 
 * Creates device fingerprints for recognition while respecting
 * privacy regulations (GDPR, CCPA) and user consent.
 */

class PrivacyRespectingFingerprinter {
  /**
   * Creates a new fingerprinter with privacy controls
   * 
   * @param {Object} options - Configuration options
   * @param {string} [options.level='minimal'] - Default fingerprinting level (minimal, moderate, enhanced)
   * @param {boolean} [options.userConsent=false] - Default user consent status
   * @param {string} [options.storageKey='fingerprint_consent'] - Storage key for saving consent
   * @param {Object} [options.storage] - Custom storage adapter (defaults to localStorage)
   * @param {string} [options.consentExpiryDays=180] - Days until consent expires
   * @param {boolean} [options.debug=false] - Enable debug logging
   */
  constructor(options = {}) {
    this.level = options.level || 'minimal';
    this.userConsent = options.userConsent || false;
    this.storageKey = options.storageKey || 'fingerprint_consent';
    this.storage = options.storage || (typeof localStorage !== 'undefined' ? localStorage : null);
    this.consentExpiryDays = options.consentExpiryDays || 180;
    this.debug = options.debug || false;
    
    // Define data collected at each level
    this.levelDefinitions = {
      minimal: {
        description: 'Basic device information (screen size, language, timezone)',
        dataPoints: ['screenSize', 'language', 'timezone']
      },
      moderate: {
        description: 'Moderate device information (adds platform, color depth, plugins count)',
        dataPoints: ['screenSize', 'language', 'timezone', 'platform', 'colorDepth', 'pluginsCount']
      },
      enhanced: {
        description: 'Enhanced device information (adds limited canvas fingerprinting)',
        dataPoints: ['screenSize', 'language', 'timezone', 'platform', 'colorDepth', 'pluginsCount', 'limitedCanvas']
      }
    };
    
    // Initialize - try to load saved consent
    this._loadSavedConsent();
    
    this._log('Initialized with level:', this.level, 'and consent:', this.userConsent);
  }
  
  /**
   * Gets current user consent status
   * 
   * @async
   * @returns {Promise<boolean>} Current consent status
   */
  async getUserConsent() {
    return this.userConsent;
  }
  
  /**
   * Sets and saves user consent status
   * 
   * @async
   * @param {boolean} consentGiven - Whether user has given consent
   * @param {string} [level] - Optional fingerprinting level to set
   * @returns {Promise<boolean>} Updated consent status
   */
  async setUserConsent(consentGiven, level) {
    this.userConsent = Boolean(consentGiven);
    
    // If level is provided and valid, update it
    if (level && this.levelDefinitions[level]) {
      this.level = level;
    }
    
    // Save consent to storage
    this._saveConsent();
    
    this._log('User consent updated:', this.userConsent, 'with level:', this.level);
    
    return this.userConsent;
  }
  
  /**
   * Provides information about data collection practices
   * 
   * @returns {Object} Information about collected data
   */
  getCollectionInformation() {
    const currentLevel = this.levelDefinitions[this.level] || this.levelDefinitions.minimal;
    
    return {
      currentLevel: this.level,
      description: currentLevel.description,
      dataPoints: currentLevel.dataPoints,
      consentGiven: this.userConsent,
      allLevels: Object.keys(this.levelDefinitions).reduce((info, level) => {
        info[level] = {
          description: this.levelDefinitions[level].description,
          dataPoints: this.levelDefinitions[level].dataPoints
        };
        return info;
      }, {})
    };
  }
  
  /**
   * Generates a user-readable privacy report
   * 
   * @returns {string} User-friendly privacy report
   */
  generatePrivacyReport() {
    const info = this.getCollectionInformation();
    
    let report = `Privacy Report - Device Recognition\n`;
    report += `----------------------------------------\n\n`;
    report += `Current Collection Level: ${info.currentLevel}\n`;
    report += `User Consent: ${info.consentGiven ? 'Granted' : 'Not granted'}\n\n`;
    report += `Data being collected:\n`;
    
    info.dataPoints.forEach(point => {
      report += `- ${point}\n`;
    });
    
    report += `\nOur commitment to privacy:\n`;
    report += `- We minimize data collection to what's necessary\n`;
    report += `- Your data is never shared with third parties\n`;
    report += `- You can opt out or change your settings at any time\n`;
    report += `- We do not track you across websites\n`;
    
    return report;
  }
  
  /**
   * Generates a fingerprint based on current level and consent
   * 
   * @async
   * @returns {Promise<{hash: string, components: Object, level: string}>} Fingerprint data
   */
  async generateFingerprint() {
    try {
      // If no consent, use minimal fingerprinting or fallback
      const effectiveLevel = this.userConsent ? this.level : 'minimal';
      
      this._log('Generating fingerprint with level:', effectiveLevel);
      
      // Collect components based on level
      const components = await this._collectComponents(effectiveLevel);
      
      // Generate stable hash
      const hash = await this._generateHash(components);
      
      return {
        hash,
        components,
        level: effectiveLevel
      };
    } catch (error) {
      this._logError('Error generating fingerprint:', error);
      
      // Return a fallback with minimal information
      return this._generateFallbackFingerprint();
    }
  }
  
  /**
   * Collects fingerprint components based on the level
   * 
   * @private
   * @async
   * @param {string} level - Fingerprinting level
   * @returns {Promise<Object>} Collected components
   */
  async _collectComponents(level) {
    const components = {};
    
    // Level 1 (Minimal) - Basic device info
    // Screen size
    if (typeof window !== 'undefined' && window.screen) {
      components.screenSize = `${window.screen.width}x${window.screen.height}`;
      components.screenAvailable = `${window.screen.availWidth}x${window.screen.availHeight}`;
    } else {
      components.screenSize = 'unavailable';
      components.screenAvailable = 'unavailable';
    }
    
    // Language
    if (typeof navigator !== 'undefined') {
      components.language = navigator.language || navigator.userLanguage || 'unavailable';
    } else {
      components.language = 'unavailable';
    }
    
    // Timezone
    try {
      components.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'unavailable';
      components.timezoneOffset = new Date().getTimezoneOffset();
    } catch (e) {
      components.timezone = 'unavailable';
      components.timezoneOffset = 0;
    }
    
    // Stop here if only minimal fingerprinting is requested
    if (level === 'minimal') {
      return components;
    }
    
    // Level 2 (Moderate) - Add platform, color depth, plugins count
    if (typeof navigator !== 'undefined') {
      // Platform (simplified to OS family)
      components.platform = this._getOSFamily();
      
      // Count plugins (just the number, not the plugins themselves)
      if (navigator.plugins) {
        components.pluginsCount = navigator.plugins.length;
      } else {
        components.pluginsCount = 0;
      }
    }
    
    // Color depth
    if (typeof window !== 'undefined' && window.screen) {
      components.colorDepth = window.screen.colorDepth || 'unavailable';
    } else {
      components.colorDepth = 'unavailable';
    }
    
    // Stop here if only moderate fingerprinting is requested
    if (level === 'moderate') {
      return components;
    }
    
    // Level 3 (Enhanced) - Add limited canvas fingerprinting
    if (level === 'enhanced' && typeof document !== 'undefined') {
      try {
        // Get limited canvas fingerprint (no text, simple shapes only)
        components.limitedCanvas = await this._getLimitedCanvasFingerprint();
      } catch (e) {
        components.limitedCanvas = 'unavailable';
      }
    }
    
    return components;
  }
  
  /**
   * Gets a simplified OS family name
   * 
   * @private
   * @returns {string} OS family
   */
  _getOSFamily() {
    const userAgent = navigator.userAgent || '';
    
    // Use only broad categories to avoid identification
    if (userAgent.indexOf('Windows') !== -1) return 'Windows';
    if (userAgent.indexOf('Mac') !== -1) return 'Mac';
    if (userAgent.indexOf('Linux') !== -1) return 'Linux';
    if (userAgent.indexOf('Android') !== -1) return 'Android';
    if (userAgent.indexOf('iOS') !== -1 || 
        userAgent.indexOf('iPhone') !== -1 || 
        userAgent.indexOf('iPad') !== -1) return 'iOS';
    
    return 'Other';
  }
  
  /**
   * Creates a limited canvas fingerprint
   * Only uses basic shapes, no text, to reduce uniqueness
   * 
   * @private
   * @async
   * @returns {Promise<string>} Limited canvas fingerprint
   */
  async _getLimitedCanvasFingerprint() {
    // Only proceed if document and canvas are available
    if (!document) {
      return 'unavailable';
    }
    
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 100;
      canvas.height = 50;
      
      const ctx = canvas.getContext('2d');
      if (!ctx) return 'unavailable';
      
      // Draw only simple shapes and limited colors (no text!)
      // This reduces uniqueness while still providing value
      ctx.fillStyle = '#f60';
      ctx.fillRect(10, 10, 30, 30);
      
      ctx.fillStyle = '#069';
      ctx.beginPath();
      ctx.arc(70, 25, 15, 0, 2 * Math.PI);
      ctx.fill();
      
      // Get hash of limited canvas data
      // Only use a portion of the data to reduce uniqueness
      const limitedDataUrl = canvas.toDataURL().substring(0, 64);
      return this._simpleHash(limitedDataUrl);
      
    } catch (e) {
      return 'unavailable';
    }
  }
  
  /**
   * Generates a hash from fingerprint components
   * 
   * @private
   * @async
   * @param {Object} components - Fingerprint components
   * @returns {Promise<string>} Generated hash
   */
  async _generateHash(components) {
    // Create string from components
    const componentStr = JSON.stringify(components);
    
    // Use WebCrypto if available
    if (typeof crypto !== 'undefined' && crypto.subtle && typeof TextEncoder !== 'undefined') {
      try {
        const encoder = new TextEncoder();
        const data = encoder.encode(componentStr);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        
        // Convert to hex string but only return a portion (first 32 chars)
        // This helps with privacy by reducing uniqueness while maintaining utility
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 32);
      } catch (e) {
        // Fallback to simple hash
        return this._simpleHash(componentStr);
      }
    }
    
    // Fallback hash function
    return this._simpleHash(componentStr);
  }
  
  /**
   * Simple non-cryptographic hash function
   * 
   * @private
   * @param {string} str - String to hash
   * @returns {string} Simple hash
   */
  _simpleHash(str) {
    let hash = 0;
    
    if (!str.length) return hash.toString(16);
    
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash &= hash; // Convert to 32bit integer
    }
    
    return (hash >>> 0).toString(16);
  }
  
  /**
   * Generates a fallback fingerprint with minimal information
   * 
   * @private
   * @returns {Object} Fallback fingerprint
   */
  _generateFallbackFingerprint() {
    // Generate a random identifier and store it in a session
    let sessionId = '';
    
    // Try to get from sessionStorage
    try {
      sessionId = sessionStorage.getItem('temp_session_id');
      if (!sessionId) {
        sessionId = Math.random().toString(36).substring(2, 15);
        sessionStorage.setItem('temp_session_id', sessionId);
      }
    } catch (e) {
      // Fallback to a temporary random ID
      sessionId = Math.random().toString(36).substring(2, 15);
    }
    
    return {
      hash: sessionId,
      components: {
        fallback: true,
        timestamp: new Date().getTime()
      },
      level: 'fallback'
    };
  }
  
  /**
   * Saves consent status to storage
   * 
   * @private
   */
  _saveConsent() {
    if (!this.storage) return;
    
    try {
      const consentData = {
        consent: this.userConsent,
        level: this.level,
        timestamp: new Date().getTime(),
        expiresAt: new Date().getTime() + (this.consentExpiryDays * 24 * 60 * 60 * 1000)
      };
      
      this.storage.setItem(this.storageKey, JSON.stringify(consentData));
    } catch (e) {
      this._logError('Failed to save consent', e);
    }
  }
  
  /**
   * Loads saved consent from storage
   * 
   * @private
   */
  _loadSavedConsent() {
    if (!this.storage) return;
    
    try {
      const savedConsent = this.storage.getItem(this.storageKey);
      if (!savedConsent) return;
      
      const consentData = JSON.parse(savedConsent);
      
      // Check if consent has expired
      if (consentData.expiresAt && consentData.expiresAt > new Date().getTime()) {
        this.userConsent = Boolean(consentData.consent);
        
        // Only use the level if it's valid
        if (consentData.level && this.levelDefinitions[consentData.level]) {
          this.level = consentData.level;
        }
        
        this._log('Loaded saved consent:', this.userConsent, 'with level:', this.level);
      } else {
        // Consent expired, remove it
        this.storage.removeItem(this.storageKey);
        this._log('Saved consent expired, removed');
      }
    } catch (e) {
      this._logError('Failed to load saved consent', e);
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
      console.log('[PrivacyRespectingFingerprinter]', ...args);
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
      console.error('[PrivacyRespectingFingerprinter] ERROR:', message, error);
    }
  }
}

// Export for both browser and Node.js environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PrivacyRespectingFingerprinter };
} else if (typeof window !== 'undefined') {
  window.PrivacyRespectingFingerprinter = PrivacyRespectingFingerprinter;
} 