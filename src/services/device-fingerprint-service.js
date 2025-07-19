const crypto = require('crypto');
const winston = require('winston');

class DeviceFingerprintService {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console()
      ]
    });
  }

  /**
   * Generate a device fingerprint from various browser/device characteristics
   * @param {Object} deviceData - Device information from client
   * @returns {Object} Fingerprint data and hash
   */
  generateFingerprint(deviceData) {
    try {
      // Extract relevant features for fingerprinting
      const features = {
        // Browser features
        userAgent: deviceData.userAgent || '',
        language: deviceData.language || '',
        languages: deviceData.languages || [],
        platform: deviceData.platform || '',
        vendor: deviceData.vendor || '',
        
        // Screen properties
        screenResolution: deviceData.screenResolution || '',
        screenColorDepth: deviceData.screenColorDepth || '',
        screenPixelRatio: deviceData.screenPixelRatio || 1,
        
        // Hardware features
        hardwareConcurrency: deviceData.hardwareConcurrency || 0,
        deviceMemory: deviceData.deviceMemory || 0,
        
        // Time zone
        timezone: deviceData.timezone || '',
        timezoneOffset: deviceData.timezoneOffset || 0,
        
        // Canvas fingerprint (if provided)
        canvasFingerprint: deviceData.canvasFingerprint || '',
        
        // WebGL data (if provided)
        webglVendor: deviceData.webglVendor || '',
        webglRenderer: deviceData.webglRenderer || '',
        
        // Audio fingerprint (if provided)
        audioFingerprint: deviceData.audioFingerprint || '',
        
        // Font list (if provided, limited to common fonts)
        fonts: this.normalizefonts(deviceData.fonts || []),
        
        // Plugin information (becoming less relevant)
        plugins: this.normalizePlugins(deviceData.plugins || []),
        
        // Touch support
        touchSupport: deviceData.touchSupport || false,
        
        // Do Not Track
        doNotTrack: deviceData.doNotTrack || false
      };

      // Generate stable hash from features
      const fingerprintString = this.createFingerprintString(features);
      const fingerprintHash = this.hashFingerprint(fingerprintString);

      // Calculate entropy (uniqueness score)
      const entropy = this.calculateEntropy(features);

      return {
        hash: fingerprintHash,
        features: features,
        entropy: entropy,
        version: '1.0',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      this.logger.error('Error generating fingerprint', { error: error.message });
      throw error;
    }
  }

  /**
   * Create a stable string representation of fingerprint features
   */
  createFingerprintString(features) {
    // Order matters for consistent hashing
    const orderedKeys = Object.keys(features).sort();
    const values = orderedKeys.map(key => {
      const value = features[key];
      if (Array.isArray(value)) {
        return value.join(',');
      }
      return String(value);
    });
    
    return values.join('|');
  }

  /**
   * Hash the fingerprint string using SHA-256
   */
  hashFingerprint(fingerprintString) {
    return crypto
      .createHash('sha256')
      .update(fingerprintString)
      .digest('hex');
  }

  /**
   * Calculate entropy score (0-100) based on feature uniqueness
   */
  calculateEntropy(features) {
    let score = 0;
    
    // High entropy features
    if (features.canvasFingerprint) score += 20;
    if (features.audioFingerprint) score += 15;
    if (features.webglVendor && features.webglRenderer) score += 15;
    
    // Medium entropy features
    if (features.fonts && features.fonts.length > 10) score += 10;
    if (features.plugins && features.plugins.length > 0) score += 10;
    if (features.screenResolution) score += 10;
    if (features.timezone) score += 5;
    
    // Low entropy features
    if (features.platform) score += 5;
    if (features.language) score += 5;
    if (features.hardwareConcurrency > 0) score += 5;
    
    return Math.min(score, 100);
  }

  /**
   * Normalize font list to common fonts only
   */
  normalizefonts(fonts) {
    const commonFonts = [
      'Arial', 'Helvetica', 'Times New Roman', 'Times',
      'Courier New', 'Courier', 'Verdana', 'Georgia',
      'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS',
      'Trebuchet MS', 'Arial Black', 'Impact'
    ];
    
    // Handle non-array inputs gracefully
    if (!Array.isArray(fonts)) {
      return [];
    }
    
    return fonts.filter(font => commonFonts.includes(font)).sort();
  }

  /**
   * Normalize plugin list
   */
  normalizePlugins(plugins) {
    return plugins.map(plugin => ({
      name: plugin.name || '',
      filename: plugin.filename || ''
    })).sort((a, b) => a.name.localeCompare(b.name));
  }

  /**
   * Compare two fingerprints and return similarity score (0-100)
   */
  compareFingerprints(fingerprint1, fingerprint2) {
    if (fingerprint1.hash === fingerprint2.hash) {
      return 100;
    }

    const features1 = fingerprint1.features;
    const features2 = fingerprint2.features;
    
    let matchScore = 0;
    let totalWeight = 0;

    // Define weights for different features
    const weights = {
      userAgent: 10,
      platform: 5,
      screenResolution: 15,
      timezone: 10,
      canvasFingerprint: 20,
      webglVendor: 10,
      webglRenderer: 10,
      audioFingerprint: 15,
      fonts: 5
    };

    // Compare each feature - only count weights for features that exist in both
    for (const [feature, weight] of Object.entries(weights)) {
      // Only compare if both fingerprints have this feature
      if (features1[feature] !== undefined && features2[feature] !== undefined) {
        totalWeight += weight;
        
        if (features1[feature] === features2[feature]) {
          matchScore += weight;
        } else if (Array.isArray(features1[feature]) && Array.isArray(features2[feature])) {
          // For arrays, calculate percentage of matching elements
          const arr1 = features1[feature];
          const arr2 = features2[feature];
          const matches = arr1.filter(item => arr2.includes(item)).length;
          const maxLength = Math.max(arr1.length, arr2.length);
          if (maxLength > 0) {
            const similarity = matches / maxLength;
            matchScore += weight * similarity;
          }
        }
      }
    }

    // Handle case where no comparable features exist
    if (totalWeight === 0) {
      return 0;
    }

    return Math.round((matchScore / totalWeight) * 100);
  }

  /**
   * Determine if a device is trusted based on fingerprint
   */
  isDeviceTrusted(currentFingerprint, trustedFingerprints, threshold = 85) {
    for (const trusted of trustedFingerprints) {
      const similarity = this.compareFingerprints(currentFingerprint, trusted);
      if (similarity >= threshold) {
        return {
          trusted: true,
          matchedFingerprint: trusted,
          similarity: similarity
        };
      }
    }
    
    return {
      trusted: false,
      matchedFingerprint: null,
      similarity: 0
    };
  }

  /**
   * Extract device metadata for logging/analytics
   */
  extractDeviceMetadata(deviceData) {
    return {
      browserName: this.extractBrowserName(deviceData.userAgent),
      browserVersion: this.extractBrowserVersion(deviceData.userAgent),
      osName: this.extractOSName(deviceData.userAgent),
      osVersion: this.extractOSVersion(deviceData.userAgent),
      deviceType: this.detectDeviceType(deviceData),
      isMobile: this.isMobileDevice(deviceData.userAgent),
      isTablet: this.isTabletDevice(deviceData.userAgent)
    };
  }

  /**
   * Helper methods for user agent parsing
   */
  extractBrowserName(userAgent) {
    if (!userAgent) return 'Unknown';
    
    if (userAgent.includes('Chrome')) return 'Chrome';
    if (userAgent.includes('Firefox')) return 'Firefox';
    if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) return 'Safari';
    if (userAgent.includes('Edge')) return 'Edge';
    if (userAgent.includes('Opera')) return 'Opera';
    
    return 'Other';
  }

  extractBrowserVersion(userAgent) {
    if (!userAgent) return 'Unknown';
    
    const match = userAgent.match(/(Chrome|Firefox|Safari|Edge|Opera)\/(\d+)/);
    return match ? match[2] : 'Unknown';
  }

  extractOSName(userAgent) {
    if (!userAgent) return 'Unknown';
    
    if (userAgent.includes('Windows')) return 'Windows';
    if (userAgent.includes('Mac OS')) return 'macOS';
    if (userAgent.includes('Linux')) return 'Linux';
    if (userAgent.includes('Android')) return 'Android';
    if (userAgent.includes('iOS') || userAgent.includes('iPhone') || userAgent.includes('iPad')) return 'iOS';
    
    return 'Other';
  }

  extractOSVersion(userAgent) {
    if (!userAgent) return 'Unknown';
    
    // Simple version extraction - can be enhanced
    const windowsMatch = userAgent.match(/Windows NT (\d+\.\d+)/);
    if (windowsMatch) return windowsMatch[1];
    
    const macMatch = userAgent.match(/Mac OS X (\d+[._]\d+)/);
    if (macMatch) return macMatch[1].replace('_', '.');
    
    return 'Unknown';
  }

  detectDeviceType(deviceData) {
    const ua = deviceData.userAgent || '';
    
    if (this.isMobileDevice(ua)) return 'mobile';
    if (this.isTabletDevice(ua)) return 'tablet';
    if (deviceData.touchSupport) return 'touch-device';
    
    return 'desktop';
  }

  isMobileDevice(userAgent) {
    return /Mobile|Android|iPhone/i.test(userAgent);
  }

  isTabletDevice(userAgent) {
    return /iPad|Android.*Tablet|Tablet.*Android/i.test(userAgent);
  }
}

module.exports = DeviceFingerprintService;