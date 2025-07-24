/**
 * Device Fingerprint Repository
 * 
 * Manages the storage and retrieval of device fingerprints, providing
 * similarity matching algorithms for device recognition with comprehensive
 * anti-spoofing security measures.
 * 
 * SECURITY ENHANCEMENTS:
 * - Device fingerprint validation and authenticity checking
 * - Anti-spoofing detection algorithms
 * - Behavioral pattern analysis
 * - Entropy validation
 * - Real-time fraud detection
 */

const { dbConnection } = require('./db-connection');
const { logger } = require('../utils/logger');
const crypto = require('crypto');

// SECURITY: Known user agent patterns for validation
const KNOWN_USER_AGENT_PATTERNS = {
  Chrome: /Chrome\/[\d.]+/,
  Firefox: /Firefox\/[\d.]+/,
  Safari: /Safari\/[\d.]+/,
  Edge: /Edge\/[\d.]+/,
  Opera: /Opera\/[\d.]+/
};

// SECURITY: Valid screen resolution ranges
const VALID_SCREEN_RESOLUTIONS = {
  minWidth: 320,
  maxWidth: 7680,
  minHeight: 240,
  maxHeight: 4320,
  commonRatios: [
    { width: 1920, height: 1080 },
    { width: 1366, height: 768 },
    { width: 1280, height: 720 },
    { width: 1440, height: 900 },
    { width: 1600, height: 900 },
    { width: 2560, height: 1440 },
    { width: 3840, height: 2160 }
  ]
};

// SECURITY: Minimum entropy threshold for fingerprint components
const MIN_ENTROPY_THRESHOLD = 2.5; // bits per component

// SECURITY: Behavioral pattern detection thresholds
const BEHAVIORAL_THRESHOLDS = {
  maxFingerprintChangesPerHour: 5,
  maxDevicesPerIP: 10,
  suspiciousTimingWindow: 1000, // milliseconds
  minInteractionTime: 500 // milliseconds minimum interaction time
};

class DeviceFingerprintRepository {
  /**
   * Store a new device fingerprint with comprehensive anti-spoofing validation
   * @param {Object} components - The fingerprint components
   * @param {Object} options - Additional context for validation
   * @returns {Promise<Object>} The stored fingerprint record
   */
  async storeFingerprint(components, options = {}) {
    try {
      logger.debug('🔒 SECURITY: Starting device fingerprint validation', {
        fingerprintComponentCount: Object.keys(components).length,
        ipAddress: components.ipAddress,
        userAgent: components.userAgent?.substring(0, 50) + '...'
      });
      
      // PHASE 1: COMPREHENSIVE FINGERPRINT VALIDATION
      const validationResult = await this._validateFingerprintComponents(components, options);
      
      if (!validationResult.isValid) {
        logger.warn('🚨 SECURITY ALERT: Invalid fingerprint detected', {
          reason: validationResult.reason,
          violations: validationResult.violations,
          suspiciousComponents: validationResult.suspiciousComponents,
          ipAddress: components.ipAddress,
          confidence: validationResult.confidence
        });
        
        // For invalid fingerprints, still store but mark with low confidence
        components._validationFailures = validationResult.violations;
        components._confidenceScore = Math.max(0.1, validationResult.confidence);
      } else {
        components._confidenceScore = validationResult.confidence;
      }
      
      // PHASE 2: ANTI-SPOOFING DETECTION
      const spoofingResult = await this._detectSpoofingAttempts(components, options);
      
      if (spoofingResult.isSuspicious) {
        logger.warn('🚨 SECURITY ALERT: Potential spoofing attempt detected', {
          suspicionLevel: spoofingResult.suspicionLevel,
          indicators: spoofingResult.indicators,
          confidence: spoofingResult.confidence,
          ipAddress: components.ipAddress,
          behavioralFlags: spoofingResult.behavioralFlags
        });
        
        // Apply security penalties for suspicious fingerprints
        components._spoofingFlags = spoofingResult.indicators;
        components._suspicionLevel = spoofingResult.suspicionLevel;
        components._confidenceScore = Math.min(components._confidenceScore || 1.0, spoofingResult.confidence);
      }
      
      // PHASE 3: BEHAVIORAL PATTERN ANALYSIS
      const behavioralResult = await this._analyzeBehavioralPatterns(components, options);
      
      if (behavioralResult.isAnomalous) {
        logger.warn('🚨 SECURITY ALERT: Anomalous behavioral patterns detected', {
          anomalies: behavioralResult.anomalies,
          riskScore: behavioralResult.riskScore,
          ipAddress: components.ipAddress
        });
        
        components._behavioralAnomalies = behavioralResult.anomalies;
        components._riskScore = behavioralResult.riskScore;
      }
      
      // PHASE 4: ENTROPY VALIDATION
      const entropyResult = this._validateFingerprints(components);
      
      if (entropyResult.entropy < MIN_ENTROPY_THRESHOLD) {
        logger.warn('🚨 SECURITY ALERT: Low entropy fingerprint detected', {
          entropy: entropyResult.entropy,
          threshold: MIN_ENTROPY_THRESHOLD,
          lowEntropyComponents: entropyResult.lowEntropyComponents,
          ipAddress: components.ipAddress
        });
        
        components._lowEntropy = true;
        components._entropyScore = entropyResult.entropy;
        components._confidenceScore = Math.min(components._confidenceScore || 1.0, 0.3);
      }
      
      // Generate secure fingerprint hash with anti-tampering measures
      const fingerprintHash = this._generateSecureFingerprintHash(components);
      
      // Check if fingerprint already exists
      const existingFingerprint = await this._findFingerprintByHash(fingerprintHash);
      if (existingFingerprint) {
        // Update the last_seen time and analyze timing patterns
        await this._analyzeTimingPatterns(existingFingerprint, components);
        await this.updateDeviceLastSeen(existingFingerprint.id);
        return existingFingerprint;
      }
      
      // Extract and sanitize fields from components
      const {
        userAgent,
        screenResolution,
        colorDepth,
        timezone,
        language,
        plugins,
        fonts,
        canvas,
        webgl,
        battery,
        deviceMemory,
        hardwareConcurrency,
        platform,
        ipAddress,
        connectionType,
        browserVersion,
        osVersion,
        isMobile,
        networkInfo,
        ...metadata
      } = components;
      
      // SECURITY: Store fingerprint with security metadata
      const query = `
        INSERT INTO device_fingerprints (
          fingerprint_hash,
          user_agent,
          screen_resolution,
          color_depth,
          timezone,
          language_preferences,
          browser_plugins,
          installed_fonts,
          canvas_fingerprint,
          webgl_fingerprint,
          battery_info,
          device_memory,
          hardware_concurrency,
          platform,
          ip_address,
          connection_type,
          browser_version,
          os_version,
          is_mobile,
          network_info,
          metadata,
          confidence_score
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
        RETURNING *
      `;
      
      // Convert arrays and objects to strings with validation
      const pluginsStr = this._sanitizePluginString(plugins);
      const fontsStr = this._sanitizeFontString(fonts);
      const batteryStr = this._sanitizeBatteryInfo(battery);
      const networkInfoStr = this._sanitizeNetworkInfo(networkInfo);
      
      // Compile security metadata
      const securityMetadata = {
        ...metadata,
        validationFailures: components._validationFailures || [],
        spoofingFlags: components._spoofingFlags || [],
        behavioralAnomalies: components._behavioralAnomalies || [],
        suspicionLevel: components._suspicionLevel || 'none',
        riskScore: components._riskScore || 0,
        entropyScore: components._entropyScore || entropyResult.entropy,
        securityTimestamp: new Date().toISOString(),
        validationVersion: '2.0.0' // Track validation version for future upgrades
      };
      
      const values = [
        fingerprintHash,
        this._sanitizeUserAgent(userAgent),
        this._sanitizeScreenResolution(screenResolution),
        colorDepth || null,
        timezone || null,
        language || null,
        pluginsStr,
        fontsStr,
        canvas || null,
        webgl || null,
        batteryStr,
        deviceMemory || null,
        hardwareConcurrency || null,
        platform || null,
        ipAddress || null,
        connectionType || null,
        browserVersion || null,
        osVersion || null,
        isMobile || false,
        networkInfoStr,
        JSON.stringify(securityMetadata),
        components._confidenceScore || 1.0
      ];
      
      const result = await dbConnection.query(query, values);
      
      // SECURITY: Log successful storage with security analysis
      logger.info('✅ SECURITY: Device fingerprint stored with security validation', { 
        id: result[0]?.id,
        hash: fingerprintHash.substring(0, 8) + '...',
        confidenceScore: components._confidenceScore,
        securityFlags: {
          hasValidationFailures: (components._validationFailures || []).length > 0,
          hasSpoofingFlags: (components._spoofingFlags || []).length > 0,
          hasBehavioralAnomalies: (components._behavioralAnomalies || []).length > 0,
          isLowEntropy: components._lowEntropy || false
        },
        ipAddress: components.ipAddress
      });
      
      return result[0];
    } catch (error) {
      logger.error('🚨 SECURITY ERROR: Failed to store device fingerprint:', {
        error: error.message,
        stack: error.stack,
        ipAddress: components?.ipAddress
      });
      throw error;
    }
  }
  
  /**
   * SECURITY: Comprehensive fingerprint component validation
   * @param {Object} components - Fingerprint components to validate
   * @param {Object} options - Additional context for validation
   * @returns {Promise<Object>} Validation result with confidence score
   * @private
   */
  async _validateFingerprintComponents(components, options = {}) {
    const violations = [];
    const suspiciousComponents = [];
    let confidence = 1.0;
    
    try {
      // SECURITY: Validate User Agent authenticity
      if (components.userAgent) {
        const uaValidation = this._validateUserAgent(components.userAgent);
        if (!uaValidation.isValid) {
          violations.push('invalid_user_agent');
          suspiciousComponents.push('userAgent');
          confidence -= 0.3;
        }
        
        // Check for bot patterns
        if (this._detectBotUserAgent(components.userAgent)) {
          violations.push('bot_user_agent');
          suspiciousComponents.push('userAgent');
          confidence -= 0.4;
        }
      }
      
      // SECURITY: Validate Screen Resolution authenticity
      if (components.screenResolution) {
        const resValidation = this._validateScreenResolution(components.screenResolution);
        if (!resValidation.isValid) {
          violations.push('invalid_screen_resolution');
          suspiciousComponents.push('screenResolution');
          confidence -= 0.2;
        }
      }
      
      // SECURITY: Validate Browser-Platform consistency
      const consistencyCheck = this._validateBrowserPlatformConsistency(components);
      if (!consistencyCheck.isConsistent) {
        violations.push('browser_platform_inconsistency');
        suspiciousComponents.push(...consistencyCheck.inconsistentFields);
        confidence -= 0.25;
      }
      
      // SECURITY: Validate Hardware specifications consistency
      const hardwareCheck = this._validateHardwareConsistency(components);
      if (!hardwareCheck.isConsistent) {
        violations.push('hardware_inconsistency');
        suspiciousComponents.push(...hardwareCheck.inconsistentFields);
        confidence -= 0.2;
      }
      
      // SECURITY: Check for impossible combinations
      const impossibleCheck = this._detectImpossibleCombinations(components);
      if (impossibleCheck.hasImpossible) {
        violations.push('impossible_combination');
        suspiciousComponents.push(...impossibleCheck.impossibleFields);
        confidence -= 0.5;
      }
      
      // SECURITY: Validate Canvas and WebGL fingerprints
      if (components.canvas && components.webgl) {
        const canvasWebglCheck = this._validateCanvasWebglConsistency(components.canvas, components.webgl);
        if (!canvasWebglCheck.isConsistent) {
          violations.push('canvas_webgl_inconsistency');
          suspiciousComponents.push('canvas', 'webgl');
          confidence -= 0.15;
        }
      }
      
      // Ensure confidence doesn't go below minimum threshold
      confidence = Math.max(0.1, confidence);
      
      return {
        isValid: violations.length === 0,
        confidence,
        violations,
        suspiciousComponents,
        reason: violations.length > 0 ? violations.join(', ') : 'validation_passed'
      };
      
    } catch (error) {
      logger.error('🚨 SECURITY ERROR: Fingerprint validation failed:', {
        error: error.message,
        components: Object.keys(components)
      });
      
      return {
        isValid: false,
        confidence: 0.1,
        violations: ['validation_error'],
        suspiciousComponents: [],
        reason: 'validation_system_error'
      };
    }
  }
  
  /**
   * SECURITY: Detect potential spoofing attempts using behavioral analysis
   * @param {Object} components - Fingerprint components
   * @param {Object} options - Additional context
   * @returns {Promise<Object>} Spoofing detection result
   * @private
   */
  async _detectSpoofingAttempts(components, options = {}) {
    const indicators = [];
    const behavioralFlags = [];
    let suspicionLevel = 'none';
    let confidence = 1.0;
    
    try {
      // SECURITY: Check for rapid fingerprint changes from same IP
      if (components.ipAddress) {
        const recentFingerprints = await this._getRecentFingerprintsByIP(components.ipAddress, 1); // Last hour
        
        if (recentFingerprints.length > BEHAVIORAL_THRESHOLDS.maxFingerprintChangesPerHour) {
          indicators.push('rapid_fingerprint_changes');
          behavioralFlags.push('multiple_devices_per_ip');
          suspicionLevel = 'high';
          confidence -= 0.4;
        }
        
        // Check for identical fingerprints from different IPs (device cloning)
        const identicalCount = await this._countIdenticalFingerprints(components);
        if (identicalCount > 1) {
          indicators.push('fingerprint_cloning');
          behavioralFlags.push('duplicate_fingerprints');
          suspicionLevel = 'high';
          confidence -= 0.6;
        }
      }
      
      // SECURITY: Detect automation patterns
      if (options.timingData) {
        const automationCheck = this._detectAutomationPatterns(options.timingData);
        if (automationCheck.isAutomated) {
          indicators.push('automation_detected');
          behavioralFlags.push(...automationCheck.patterns);
          suspicionLevel = suspicionLevel === 'high' ? 'high' : 'medium';
          confidence -= 0.3;
        }
      }
      
      // SECURITY: Check for headless browser indicators
      const headlessCheck = this._detectHeadlessBrowser(components);
      if (headlessCheck.isHeadless) {
        indicators.push('headless_browser');
        behavioralFlags.push(...headlessCheck.indicators);
        suspicionLevel = suspicionLevel === 'high' ? 'high' : 'medium';
        confidence -= 0.4;
      }
      
      // SECURITY: Analyze Canvas fingerprint for generation patterns
      if (components.canvas) {
        const canvasAnalysis = this._analyzeCanvasFingerprint(components.canvas);
        if (canvasAnalysis.isSuspicious) {
          indicators.push('suspicious_canvas');
          behavioralFlags.push(...canvasAnalysis.suspiciousPatterns);
          suspicionLevel = suspicionLevel === 'high' ? 'high' : 'medium';
          confidence -= 0.2;
        }
      }
      
      // SECURITY: Check for perfect fingerprints (too consistent)
      const perfectnessCheck = this._detectPerfectFingerprint(components);
      if (perfectnessCheck.isPerfect) {
        indicators.push('perfect_fingerprint');
        behavioralFlags.push('artificially_consistent');
        suspicionLevel = 'medium';
        confidence -= 0.25;
      }
      
      // Ensure confidence doesn't go below minimum threshold
      confidence = Math.max(0.1, confidence);
      
      return {
        isSuspicious: indicators.length > 0,
        suspicionLevel,
        confidence,
        indicators,
        behavioralFlags
      };
      
    } catch (error) {
      logger.error('🚨 SECURITY ERROR: Spoofing detection failed:', {
        error: error.message,
        ipAddress: components.ipAddress
      });
      
      return {
        isSuspicious: true,
        suspicionLevel: 'high',
        confidence: 0.1,
        indicators: ['detection_error'],
        behavioralFlags: ['system_error']
      };
    }
  }
  
  /**
   * SECURITY: Analyze behavioral patterns for anomaly detection
   * @param {Object} components - Fingerprint components
   * @param {Object} options - Additional context
   * @returns {Promise<Object>} Behavioral analysis result
   * @private
   */
  async _analyzeBehavioralPatterns(components, options = {}) {
    const anomalies = [];
    let riskScore = 0;
    
    try {
      // SECURITY: Analyze timing patterns
      if (options.timingData) {
        const timingAnalysis = await this._analyzeTimingPatterns(null, components, options.timingData);
        if (timingAnalysis.isAnomalous) {
          anomalies.push('timing_anomaly');
          riskScore += 0.3;
        }
      }
      
      // SECURITY: Check for interaction patterns
      if (options.interactionData) {
        const interactionAnalysis = this._analyzeInteractionPatterns(options.interactionData);
        if (interactionAnalysis.isAnomalous) {
          anomalies.push('interaction_anomaly');
          riskScore += 0.2;
        }
      }
      
      // SECURITY: Geographic anomaly detection
      if (components.ipAddress && options.previousLocations) {
        const geoAnalysis = this._analyzeGeographicPatterns(components.ipAddress, options.previousLocations);
        if (geoAnalysis.isAnomalous) {
          anomalies.push('geographic_anomaly');
          riskScore += geoAnalysis.riskLevel;
        }
      }
      
      // SECURITY: Device switching pattern analysis
      if (components.ipAddress) {
        const deviceSwitchingAnalysis = await this._analyzeDeviceSwitchingPatterns(components.ipAddress);
        if (deviceSwitchingAnalysis.isAnomalous) {
          anomalies.push('device_switching_anomaly');
          riskScore += 0.25;
        }
      }
      
      return {
        isAnomalous: anomalies.length > 0,
        anomalies,
        riskScore: Math.min(1.0, riskScore) // Cap at 1.0
      };
      
    } catch (error) {
      logger.error('🚨 SECURITY ERROR: Behavioral analysis failed:', {
        error: error.message,
        ipAddress: components.ipAddress
      });
      
      return {
        isAnomalous: true,
        anomalies: ['analysis_error'],
        riskScore: 0.8
      };
    }
  }
  
  /**
   * SECURITY: Validate fingerprint entropy to detect low-entropy attacks
   * @param {Object} components - Fingerprint components
   * @returns {Object} Entropy validation result
   * @private
   */
  _validateFingerprints(components) {
    const lowEntropyComponents = [];
    let totalEntropy = 0;
    let componentCount = 0;
    
    try {
      // Calculate entropy for each component
      const entropyResults = {
        userAgent: this._calculateEntropy(components.userAgent || ''),
        screenResolution: this._calculateEntropy(components.screenResolution || ''),
        plugins: this._calculateEntropy((components.plugins || []).join(',')),
        fonts: this._calculateEntropy((components.fonts || []).join(',')),
        canvas: this._calculateEntropy(components.canvas || ''),
        webgl: this._calculateEntropy(components.webgl || ''),
        timezone: this._calculateEntropy(components.timezone || ''),
        language: this._calculateEntropy(components.language || '')
      };
      
      // Analyze each component
      Object.entries(entropyResults).forEach(([component, entropy]) => {
        if (entropy > 0) {
          totalEntropy += entropy;
          componentCount++;
          
          // Flag low entropy components
          if (entropy < 1.5) {
            lowEntropyComponents.push(component);
          }
        }
      });
      
      const averageEntropy = componentCount > 0 ? totalEntropy / componentCount : 0;
      
      return {
        entropy: averageEntropy,
        lowEntropyComponents,
        componentEntropies: entropyResults
      };
      
    } catch (error) {
      logger.error('🚨 SECURITY ERROR: Entropy calculation failed:', error);
      return {
        entropy: 0,
        lowEntropyComponents: Object.keys(components),
        componentEntropies: {}
      };
    }
  }
  
  /**
   * SECURITY: Calculate Shannon entropy for a string
   * @param {string} str - String to calculate entropy for
   * @returns {number} Entropy value in bits
   * @private
   */
  _calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    
    const frequency = {};
    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      frequency[char] = (frequency[char] || 0) + 1;
    }
    
    let entropy = 0;
    const length = str.length;
    
    Object.values(frequency).forEach(count => {
      const probability = count / length;
      entropy -= probability * Math.log2(probability);
    });
    
    return entropy;
  }
  
  /**
   * SECURITY: Generate secure fingerprint hash with anti-tampering measures
   * @param {Object} components - Fingerprint components
   * @returns {string} Secure hash with salt and pepper
   * @private
   */
  _generateSecureFingerprintHash(components) {
    const {
      userAgent,
      screenResolution,
      colorDepth,
      timezone,
      language,
      plugins,
      fonts,
      canvas,
      webgl,
      deviceMemory,
      hardwareConcurrency,
      platform,
      browserVersion,
      osVersion
    } = components;
    
    // Create a string representation of the core components
    const keyComponents = [
      String(userAgent || ''),
      String(screenResolution || ''),
      String(colorDepth || ''),
      String(timezone || ''),
      String(language || ''),
      Array.isArray(plugins) ? plugins.join(',') : String(plugins || ''),
      Array.isArray(fonts) ? fonts.join(',') : String(fonts || ''),
      String(canvas || ''),
      String(webgl || ''),
      String(deviceMemory || ''),
      String(hardwareConcurrency || ''),
      String(platform || ''),
      String(browserVersion || ''),
      String(osVersion || '')
    ].join('|');
    
    // SECURITY: Add salt and pepper for additional security
    const salt = crypto.randomBytes(16).toString('hex');
    const pepper = process.env.FINGERPRINT_PEPPER || 'default_pepper_should_be_changed';
    const saltedComponents = salt + keyComponents + pepper;
    
    // Generate SHA-256 hash with additional security
    const hash = crypto.createHash('sha256');
    hash.update(saltedComponents);
    const baseHash = hash.digest('hex');
    
    // SECURITY: Include salt in the final hash for verification
    return baseHash + ':' + salt;
  }
  
  /**
   * Find a device by its fingerprint components
   * @param {Object} components - The fingerprint components to match against
   * @param {Object} options - Options for the matching algorithm
   * @param {number} options.similarityThreshold - Minimum similarity score (0.0 to 1.0)
   * @param {boolean} options.requireExactIp - Whether to require exact IP match
   * @param {string} options.merchantId - Optional merchant ID to limit scope
   * @returns {Promise<Object|null>} The matched device or null
   */
  async findDeviceByComponents(components, options = {}) {
    try {
      const { 
        similarityThreshold = 0.7,
        requireExactIp = false,
        merchantId = null,
        maxResults = 1
      } = options;
      
      logger.debug('Finding device by fingerprint components', {
        threshold: similarityThreshold,
        requireExactIp,
        merchantId: merchantId || 'any'
      });
      
      // Generate a hash of the fingerprint components
      const fingerprintHash = this._generateFingerprintHash(components);
      
      // First try: exact match by hash (fastest path)
      const exactMatch = await this._findFingerprintByHash(fingerprintHash);
      if (exactMatch) {
        logger.debug('Found exact fingerprint match by hash');
        await this.updateDeviceLastSeen(exactMatch.id, components.ipAddress);
        return exactMatch;
      }
      
      // Second try: find by IP address if required
      if (requireExactIp && components.ipAddress) {
        const ipMatch = await this._findFingerprintsByIp(components.ipAddress, merchantId);
        
        if (ipMatch.length > 0) {
          // For IP matches, we still want to check similarity to find the most similar device
          const matchesWithScores = await Promise.all(
            ipMatch.map(async (device) => {
              const score = await this._calculateSimilarity(components, device);
              return { device, score };
            })
          );
          
          // Sort by similarity score (highest first)
          matchesWithScores.sort((a, b) => b.score - a.score);
          
          // Return the most similar device if it meets the threshold
          if (matchesWithScores[0] && matchesWithScores[0].score >= similarityThreshold) {
            const bestMatch = matchesWithScores[0].device;
            logger.debug('Found best match by IP address with similarity', {
              score: matchesWithScores[0].score,
              id: bestMatch.id
            });
            
            await this.updateDeviceLastSeen(bestMatch.id, components.ipAddress);
            return bestMatch;
          }
        }
      }
      
      // Third try: full similarity comparison with all active devices
      // This is the most resource-intensive approach but also the most thorough
      const limit = 50; // Limit to recent devices for performance
      const recentDevices = await this._getRecentDevices(limit, merchantId);
      
      const matchesWithScores = await Promise.all(
        recentDevices.map(async (device) => {
          const score = await this._calculateSimilarity(components, device);
          return { device, score };
        })
      );
      
      // Sort by similarity score (highest first)
      matchesWithScores.sort((a, b) => b.score - a.score);
      
      // Filter to matches that meet the threshold
      const qualifyingMatches = matchesWithScores.filter(
        match => match.score >= similarityThreshold
      );
      
      if (qualifyingMatches.length > 0) {
        const bestMatch = qualifyingMatches[0].device;
        logger.debug('Found best match by similarity algorithm', {
          score: qualifyingMatches[0].score,
          id: bestMatch.id
        });
        
        await this.updateDeviceLastSeen(bestMatch.id, components.ipAddress);
        
        if (maxResults === 1) {
          return bestMatch;
        } else {
          // Return multiple results if requested
          return qualifyingMatches
            .slice(0, maxResults)
            .map(match => ({
              ...match.device,
              similarity_score: match.score
            }));
        }
      }
      
      // No match found
      logger.debug('No matching device found with required similarity');
      return null;
    } catch (error) {
      logger.error('Error finding device by components:', error);
      throw error;
    }
  }
  
  /**
   * Update the last_seen timestamp for a device
   * @param {number} deviceId - The device ID to update
   * @param {string} ipAddress - Optional IP address to update
   * @returns {Promise<boolean>} Success indicator
   */
  async updateDeviceLastSeen(deviceId, ipAddress = null) {
    try {
      let query = `
        UPDATE device_fingerprints
        SET last_seen = CURRENT_TIMESTAMP
      `;
      
      const values = [deviceId];
      
      if (ipAddress) {
        query += `, ip_address = $2 WHERE id = $1`;
        values.push(ipAddress);
      } else {
        query += ` WHERE id = $1`;
      }
      
      await dbConnection.query(query, values);
      
      logger.debug('Updated device last_seen timestamp', { deviceId });
      return true;
    } catch (error) {
      logger.error('Error updating device last_seen:', error);
      return false;
    }
  }
  
  /**
   * Calculate similarity between two fingerprints
   * @param {Object} componentsA - First set of fingerprint components
   * @param {Object} componentsB - Second set of fingerprint components
   * @returns {Promise<number>} Similarity score (0.0 to 1.0)
   * @private
   */
  async _calculateSimilarity(componentsA, componentsB) {
    // Define weights for different components based on their uniqueness and stability
    const weights = {
      userAgent: 0.10,
      screenResolution: 0.08,
      colorDepth: 0.02,
      timezone: 0.05,
      language_preferences: 0.05,
      browser_plugins: 0.07,
      installed_fonts: 0.10,
      canvas_fingerprint: 0.15,
      webgl_fingerprint: 0.15,
      device_memory: 0.03,
      hardware_concurrency: 0.03,
      platform: 0.07,
      browser_version: 0.05,
      os_version: 0.05
    };
    
    // Total weight should add up to 1.0
    const totalWeight = Object.values(weights).reduce((sum, weight) => sum + weight, 0);
    
    // Normalize weights if they don't add up to 1.0
    if (Math.abs(totalWeight - 1.0) > 0.001) {
      for (const key in weights) {
        weights[key] /= totalWeight;
      }
    }
    
    // Calculate similarity for each property
    let totalSimilarity = 0;
    let totalApplicableWeight = 0;
    
    // Helper function to add a property's similarity to the total
    const addPropertySimilarity = (propA, propB, propertyName) => {
      if (propA === undefined || propB === undefined) {
        return; // Skip properties that don't exist in both objects
      }
      
      const weight = weights[propertyName] || 0.01; // Default to small weight for unknown properties
      const similarity = this._compareValues(propA, propB, propertyName);
      
      totalSimilarity += similarity * weight;
      totalApplicableWeight += weight;
    };
    
    // Map component names from request to database field names
    const fieldMap = {
      userAgent: 'user_agent',
      screenResolution: 'screen_resolution',
      colorDepth: 'color_depth',
      timezone: 'timezone',
      language: 'language_preferences',
      plugins: 'browser_plugins',
      fonts: 'installed_fonts',
      canvas: 'canvas_fingerprint',
      webgl: 'webgl_fingerprint',
      deviceMemory: 'device_memory',
      hardwareConcurrency: 'hardware_concurrency',
      platform: 'platform',
      browserVersion: 'browser_version',
      osVersion: 'os_version'
    };
    
    // Compare all relevant properties
    for (const [componentKey, dbField] of Object.entries(fieldMap)) {
      const valueA = componentsA[componentKey] || componentsA[dbField];
      const valueB = componentsB[componentKey] || componentsB[dbField];
      
      addPropertySimilarity(valueA, valueB, dbField);
    }
    
    // If no applicable properties were found, return 0
    if (totalApplicableWeight === 0) {
      return 0;
    }
    
    // Normalize the result to account for missing properties
    const normalizedSimilarity = totalSimilarity / totalApplicableWeight;
    
    return normalizedSimilarity;
  }
  
  /**
   * Compare two values and return a similarity score (0.0 to 1.0)
   * @param {any} valueA - First value
   * @param {any} valueB - Second value
   * @param {string} propertyType - Type of property being compared
   * @returns {number} Similarity score
   * @private
   */
  _compareValues(valueA, valueB, propertyType) {
    // Handle null or undefined values
    if (valueA === null || valueA === undefined || valueB === null || valueB === undefined) {
      return 0;
    }
    
    // Convert to strings for comparison if they're not already
    const strA = typeof valueA === 'string' ? valueA : String(valueA);
    const strB = typeof valueB === 'string' ? valueB : String(valueB);
    
    // If the values are identical, return 1
    if (strA === strB) {
      return 1;
    }
    
    // Handle different property types differently
    switch (propertyType) {
      case 'user_agent':
        // User agent similarity based on key components
        return this._calculateUserAgentSimilarity(strA, strB);
        
      case 'screen_resolution':
        // Compare screen resolutions
        return this._calculateResolutionSimilarity(strA, strB);
        
      case 'browser_plugins':
      case 'installed_fonts':
        // Compare lists as sets (order doesn't matter)
        return this._calculateSetSimilarity(strA, strB);
        
      case 'canvas_fingerprint':
      case 'webgl_fingerprint':
        // These should be exact matches
        return strA === strB ? 1 : 0;
        
      case 'platform':
      case 'browser_version':
      case 'os_version':
        // Platform similarity should be exact
        return strA === strB ? 1 : 0.3; // Give some credit even if different
        
      default:
        // Default string similarity
        return this._calculateStringSimilarity(strA, strB);
    }
  }
  
  /**
   * Calculate similarity between user agent strings
   * @param {string} agentA - First user agent
   * @param {string} agentB - Second user agent
   * @returns {number} Similarity score
   * @private
   */
  _calculateUserAgentSimilarity(agentA, agentB) {
    // Extract browser, version and OS information
    const extractInfo = (ua) => {
      const browserMatch = ua.match(/(Chrome|Firefox|Safari|Edge|MSIE|Trident)\/?\s*([\d.]+)?/i);
      const osMatch = ua.match(/(Windows|Mac|Linux|Android|iOS|iPhone|iPad)[\s/]*([\d._]+)?/i);
      
      return {
        browser: browserMatch ? browserMatch[1] : '',
        browserVersion: browserMatch ? (browserMatch[2] || '') : '',
        os: osMatch ? osMatch[1] : '',
        osVersion: osMatch ? (osMatch[2] || '') : '',
        mobile: /Mobile|Android|iPhone|iPad/i.test(ua),
        full: ua
      };
    };
    
    const infoA = extractInfo(agentA);
    const infoB = extractInfo(agentB);
    
    // Compare components with different weights
    let score = 0;
    
    // Browser type match (most important)
    if (infoA.browser.toLowerCase() === infoB.browser.toLowerCase()) {
      score += 0.5;
      
      // Browser version match (less important than browser type)
      if (infoA.browserVersion === infoB.browserVersion) {
        score += 0.2;
      } else if (infoA.browserVersion && infoB.browserVersion) {
        // Check major version
        const majorA = infoA.browserVersion.split('.')[0];
        const majorB = infoB.browserVersion.split('.')[0];
        if (majorA === majorB) {
          score += 0.1;
        }
      }
    }
    
    // OS match
    if (infoA.os.toLowerCase() === infoB.os.toLowerCase()) {
      score += 0.2;
      
      // OS version match
      if (infoA.osVersion === infoB.osVersion) {
        score += 0.1;
      }
    }
    
    // Mobile/Desktop consistency
    if (infoA.mobile === infoB.mobile) {
      score += 0.1;
    }
    
    // String similarity for the rest
    const stringSimilarity = this._calculateStringSimilarity(agentA, agentB);
    score += stringSimilarity * 0.1; // Small weight for general string similarity
    
    // Normalize to 0-1 range (but max score should be 1.1 based on weights above)
    return Math.min(score, 1.0);
  }
  
  /**
   * Calculate similarity between screen resolutions
   * @param {string} resA - First resolution string (e.g. "1920x1080")
   * @param {string} resB - Second resolution string
   * @returns {number} Similarity score
   * @private
   */
  _calculateResolutionSimilarity(resA, resB) {
    // Parse resolution strings
    const parseResolution = (res) => {
      const match = String(res).match(/(\d+)\s*[x×]\s*(\d+)/i);
      return match ? { width: parseInt(match[1], 10), height: parseInt(match[2], 10) } : null;
    };
    
    const dimA = parseResolution(resA);
    const dimB = parseResolution(resB);
    
    if (!dimA || !dimB) {
      return 0;
    }
    
    // If exact match
    if (dimA.width === dimB.width && dimA.height === dimB.height) {
      return 1;
    }
    
    // Calculate similarity based on dimensions and aspect ratio
    const areaA = dimA.width * dimA.height;
    const areaB = dimB.width * dimB.height;
    const ratioA = dimA.width / dimA.height;
    const ratioB = dimB.width / dimB.height;
    
    // Area similarity (0 to 1)
    const areaSimilarity = Math.min(areaA, areaB) / Math.max(areaA, areaB);
    
    // Aspect ratio similarity (0 to 1)
    const ratioSimilarity = Math.min(ratioA, ratioB) / Math.max(ratioA, ratioB);
    
    // Combined similarity (aspect ratio is more important than raw area)
    return 0.4 * areaSimilarity + 0.6 * ratioSimilarity;
  }
  
  /**
   * Calculate similarity between two sets (comma-separated strings)
   * @param {string} setA - First set as string
   * @param {string} setB - Second set as string
   * @returns {number} Similarity score
   * @private
   */
  _calculateSetSimilarity(setA, setB) {
    // Parse sets
    const parseSet = (str) => {
      if (!str) return new Set();
      return new Set(str.split(',').map(item => item.trim()).filter(Boolean));
    };
    
    const setAItems = parseSet(setA);
    const setBItems = parseSet(setB);
    
    // If both sets are empty
    if (setAItems.size === 0 && setBItems.size === 0) {
      return 1;
    }
    
    // If one set is empty
    if (setAItems.size === 0 || setBItems.size === 0) {
      return 0;
    }
    
    // Calculate Jaccard similarity (intersection over union)
    const intersection = new Set([...setAItems].filter(item => setBItems.has(item)));
    const union = new Set([...setAItems, ...setBItems]);
    
    return intersection.size / union.size;
  }
  
  /**
   * Calculate string similarity using Levenshtein distance
   * @param {string} strA - First string
   * @param {string} strB - Second string
   * @returns {number} Similarity score
   * @private
   */
  _calculateStringSimilarity(strA, strB) {
    // For very long strings, use a simpler approach
    if (strA.length > 100 || strB.length > 100) {
      return this._calculateLongStringSimilarity(strA, strB);
    }
    
    const lenA = strA.length;
    const lenB = strB.length;
    
    // If either string is empty
    if (lenA === 0) return lenB === 0 ? 1 : 0;
    if (lenB === 0) return 0;
    
    // Initialize the matrix
    const matrix = Array(lenB + 1).fill().map(() => Array(lenA + 1).fill(0));
    
    // Fill first row and column
    for (let i = 0; i <= lenA; i++) matrix[0][i] = i;
    for (let i = 0; i <= lenB; i++) matrix[i][0] = i;
    
    // Fill the matrix
    for (let i = 1; i <= lenB; i++) {
      for (let j = 1; j <= lenA; j++) {
        const cost = strA[j - 1] === strB[i - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,        // Deletion
          matrix[i][j - 1] + 1,        // Insertion
          matrix[i - 1][j - 1] + cost  // Substitution
        );
      }
    }
    
    // Levenshtein distance
    const distance = matrix[lenB][lenA];
    
    // Convert to similarity (0 to 1)
    const maxLen = Math.max(lenA, lenB);
    return 1 - (distance / maxLen);
  }
  
  /**
   * Calculate similarity for very long strings
   * @param {string} strA - First string
   * @param {string} strB - Second string
   * @returns {number} Similarity score
   * @private
   */
  _calculateLongStringSimilarity(strA, strB) {
    // For very long strings, use character frequency comparison
    const getCharFrequency = (str) => {
      const freq = {};
      for (let i = 0; i < str.length; i++) {
        const char = str[i];
        freq[char] = (freq[char] || 0) + 1;
      }
      return freq;
    };
    
    const freqA = getCharFrequency(strA);
    const freqB = getCharFrequency(strB);
    
    // Count matches
    let matches = 0;
    let total = 0;
    
    // Union of all characters
    const allChars = new Set([...Object.keys(freqA), ...Object.keys(freqB)]);
    
    allChars.forEach(char => {
      const countA = freqA[char] || 0;
      const countB = freqB[char] || 0;
      
      matches += Math.min(countA, countB);
      total += Math.max(countA, countB);
    });
    
    return total === 0 ? 0 : matches / total;
  }
  
  /**
   * Generate a consistent hash from fingerprint components (legacy method)
   * @param {Object} components - Fingerprint components
   * @returns {string} Hash of the components
   * @private
   */
  _generateFingerprintHash(components) {
    const {
      userAgent,
      screenResolution,
      colorDepth,
      timezone,
      language,
      plugins,
      fonts,
      canvas,
      webgl,
      deviceMemory,
      hardwareConcurrency,
      platform,
      browserVersion,
      osVersion
    } = components;
    
    // Create a string representation of the core components
    const keyComponents = [
      String(userAgent || ''),
      String(screenResolution || ''),
      String(colorDepth || ''),
      String(timezone || ''),
      String(language || ''),
      Array.isArray(plugins) ? plugins.join(',') : String(plugins || ''),
      Array.isArray(fonts) ? fonts.join(',') : String(fonts || ''),
      String(canvas || ''),
      String(webgl || ''),
      String(deviceMemory || ''),
      String(hardwareConcurrency || ''),
      String(platform || ''),
      String(browserVersion || ''),
      String(osVersion || '')
    ].join('|');
    
    // Generate SHA-256 hash
    const hash = crypto.createHash('sha256');
    hash.update(keyComponents);
    return hash.digest('hex');
  }

  // ================================
  // SECURITY VALIDATION HELPER METHODS
  // ================================

  /**
   * SECURITY: Validate User Agent string authenticity
   * @param {string} userAgent - User agent to validate
   * @returns {Object} Validation result
   * @private
   */
  _validateUserAgent(userAgent) {
    if (!userAgent || typeof userAgent !== 'string') {
      return { isValid: false, reason: 'missing_or_invalid_type' };
    }
    
    // Check for known browser patterns
    const hasKnownPattern = Object.values(KNOWN_USER_AGENT_PATTERNS).some(pattern => pattern.test(userAgent));
    if (!hasKnownPattern) {
      return { isValid: false, reason: 'unknown_browser_pattern' };
    }
    
    // Check for common spoof indicators
    const spoofIndicators = [
      /HeadlessChrome/i,
      /PhantomJS/i,
      /Selenium/i,
      /webdriver/i,
      /bot/i,
      /crawler/i,
      /spider/i
    ];
    
    const hasSpoofIndicators = spoofIndicators.some(pattern => pattern.test(userAgent));
    if (hasSpoofIndicators) {
      return { isValid: false, reason: 'spoof_indicators_detected' };
    }
    
    // Check for reasonable length
    if (userAgent.length < 20 || userAgent.length > 500) {
      return { isValid: false, reason: 'unreasonable_length' };
    }
    
    return { isValid: true };
  }

  /**
   * SECURITY: Detect bot patterns in User Agent
   * @param {string} userAgent - User agent to check
   * @returns {boolean} True if bot patterns detected
   * @private
   */
  _detectBotUserAgent(userAgent) {
    const botPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /HeadlessChrome/i, /PhantomJS/i, /Selenium/i,
      /webdriver/i, /automation/i, /test/i
    ];
    
    return botPatterns.some(pattern => pattern.test(userAgent));
  }

  /**
   * SECURITY: Validate screen resolution authenticity
   * @param {string} screenResolution - Screen resolution to validate
   * @returns {Object} Validation result
   * @private
   */
  _validateScreenResolution(screenResolution) {
    if (!screenResolution || typeof screenResolution !== 'string') {
      return { isValid: false, reason: 'missing_or_invalid_type' };
    }
    
    const match = screenResolution.match(/^(\d+)x(\d+)$/);
    if (!match) {
      return { isValid: false, reason: 'invalid_format' };
    }
    
    const width = parseInt(match[1], 10);
    const height = parseInt(match[2], 10);
    
    // Check for reasonable ranges
    if (width < VALID_SCREEN_RESOLUTIONS.minWidth || width > VALID_SCREEN_RESOLUTIONS.maxWidth ||
        height < VALID_SCREEN_RESOLUTIONS.minHeight || height > VALID_SCREEN_RESOLUTIONS.maxHeight) {
      return { isValid: false, reason: 'unreasonable_dimensions' };
    }
    
    // Check for impossible combinations (e.g., height > width for desktop)
    if (width < height && width > 1000) { // Likely desktop with impossible orientation
      return { isValid: false, reason: 'impossible_orientation' };
    }
    
    return { isValid: true };
  }

  /**
   * SECURITY: Validate browser-platform consistency
   * @param {Object} components - Fingerprint components
   * @returns {Object} Consistency check result
   * @private
   */
  _validateBrowserPlatformConsistency(components) {
    const inconsistentFields = [];
    
    // Check Safari on non-Apple platforms
    if (components.userAgent && components.userAgent.includes('Safari') && 
        components.platform && !components.platform.includes('Mac') && !components.platform.includes('iPhone')) {
      inconsistentFields.push('safari_non_apple');
    }
    
    // Check Edge on non-Windows platforms
    if (components.userAgent && components.userAgent.includes('Edge') && 
        components.platform && !components.platform.includes('Win')) {
      inconsistentFields.push('edge_non_windows');
    }
    
    // Check mobile indicators consistency
    if (components.isMobile && components.screenResolution) {
      const [width] = components.screenResolution.split('x').map(Number);
      if (width > 1200) { // Desktop resolution on mobile
        inconsistentFields.push('mobile_desktop_resolution');
      }
    }
    
    return {
      isConsistent: inconsistentFields.length === 0,
      inconsistentFields
    };
  }

  /**
   * SECURITY: Validate hardware specifications consistency
   * @param {Object} components - Fingerprint components
   * @returns {Object} Hardware consistency check result
   * @private
   */
  _validateHardwareConsistency(components) {
    const inconsistentFields = [];
    
    // Check memory consistency
    if (components.deviceMemory && components.hardwareConcurrency) {
      if (components.deviceMemory > 32 && components.hardwareConcurrency < 4) {
        inconsistentFields.push('high_memory_low_cores');
      }
      if (components.deviceMemory < 2 && components.hardwareConcurrency > 16) {
        inconsistentFields.push('low_memory_high_cores');
      }
    }
    
    // Check mobile hardware consistency
    if (components.isMobile) {
      if (components.hardwareConcurrency && components.hardwareConcurrency > 12) {
        inconsistentFields.push('mobile_excessive_cores');
      }
      if (components.deviceMemory && components.deviceMemory > 16) {
        inconsistentFields.push('mobile_excessive_memory');
      }
    }
    
    return {
      isConsistent: inconsistentFields.length === 0,
      inconsistentFields
    };
  }

  /**
   * SECURITY: Detect impossible device combinations
   * @param {Object} components - Fingerprint components
   * @returns {Object} Impossible combination check result
   * @private
   */
  _detectImpossibleCombinations(components) {
    const impossibleFields = [];
    
    // Check for impossible browser versions
    if (components.browserVersion && components.userAgent) {
      const currentYear = new Date().getFullYear();
      const versionMatch = components.browserVersion.match(/(\d+)/);
      if (versionMatch) {
        const majorVersion = parseInt(versionMatch[1], 10);
        
        // Chrome versions that are impossible (too future or too old)
        if (components.userAgent.includes('Chrome') && (majorVersion > 200 || majorVersion < 50)) {
          impossibleFields.push('impossible_chrome_version');
        }
      }
    }
    
    // Check for impossible timezone-language combinations
    if (components.timezone && components.language) {
      // Very basic check - can be expanded
      if (components.timezone.includes('America') && components.language.includes('zh')) {
        // Chinese language with American timezone (possible but suspicious)
        impossibleFields.push('suspicious_timezone_language');
      }
    }
    
    return {
      hasImpossible: impossibleFields.length > 0,
      impossibleFields
    };
  }

  /**
   * SECURITY: Validate Canvas and WebGL fingerprint consistency
   * @param {string} canvas - Canvas fingerprint
   * @param {string} webgl - WebGL fingerprint
   * @returns {Object} Consistency check result
   * @private
   */
  _validateCanvasWebglConsistency(canvas, webgl) {
    // Basic validation - both should be present if one is present
    if (!canvas && webgl) {
      return { isConsistent: false, reason: 'webgl_without_canvas' };
    }
    
    if (canvas && !webgl) {
      return { isConsistent: false, reason: 'canvas_without_webgl' };
    }
    
    // Check for reasonable hash lengths
    if (canvas && (canvas.length < 10 || canvas.length > 100)) {
      return { isConsistent: false, reason: 'invalid_canvas_length' };
    }
    
    if (webgl && (webgl.length < 10 || webgl.length > 100)) {
      return { isConsistent: false, reason: 'invalid_webgl_length' };
    }
    
    return { isConsistent: true };
  }

  // ================================
  // BEHAVIORAL ANALYSIS METHODS
  // ================================

  /**
   * SECURITY: Get recent fingerprints by IP address
   * @param {string} ipAddress - IP address to check
   * @param {number} hours - Hours to look back
   * @returns {Promise<Array>} Recent fingerprints
   * @private
   */
  async _getRecentFingerprintsByIP(ipAddress, hours = 1) {
    try {
      const query = `
        SELECT * FROM device_fingerprints
        WHERE ip_address = $1 AND created_at > NOW() - INTERVAL '${hours} hours'
        ORDER BY created_at DESC
      `;
      
      return await dbConnection.query(query, [ipAddress]);
    } catch (error) {
      logger.error('🚨 SECURITY ERROR: Failed to get recent fingerprints by IP:', error);
      return [];
    }
  }

  /**
   * SECURITY: Count identical fingerprints across different IPs
   * @param {Object} components - Fingerprint components
   * @returns {Promise<number>} Count of identical fingerprints
   * @private
   */
  async _countIdenticalFingerprints(components) {
    try {
      const hash = this._generateSecureFingerprintHash(components);
      const query = `
        SELECT COUNT(*) as count FROM device_fingerprints
        WHERE fingerprint_hash = $1 AND ip_address != $2
      `;
      
      const result = await dbConnection.query(query, [hash, components.ipAddress]);
      return parseInt(result[0]?.count || 0, 10);
    } catch (error) {
      logger.error('🚨 SECURITY ERROR: Failed to count identical fingerprints:', error);
      return 0;
    }
  }

  /**
   * SECURITY: Detect automation patterns in timing data
   * @param {Object} timingData - Timing information
   * @returns {Object} Automation detection result
   * @private
   */
  _detectAutomationPatterns(timingData) {
    const patterns = [];
    
    if (timingData.pageLoadTime && timingData.pageLoadTime < 100) {
      patterns.push('extremely_fast_load');
    }
    
    if (timingData.interactionTimes && Array.isArray(timingData.interactionTimes)) {
      const intervals = timingData.interactionTimes.slice(1).map((time, i) => 
        time - timingData.interactionTimes[i]
      );
      
      // Check for perfectly consistent timing (automated)
      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((sum, interval) => 
        sum + Math.pow(interval - avgInterval, 2), 0) / intervals.length;
      
      if (variance < 10 && intervals.length > 3) { // Very low variance
        patterns.push('consistent_timing');
      }
    }
    
    return {
      isAutomated: patterns.length > 0,
      patterns
    };
  }

  /**
   * SECURITY: Detect headless browser indicators
   * @param {Object} components - Fingerprint components
   * @returns {Object} Headless detection result
   * @private
   */
  _detectHeadlessBrowser(components) {
    const indicators = [];
    
    // Check for common headless indicators in user agent
    if (components.userAgent) {
      if (components.userAgent.includes('HeadlessChrome')) {
        indicators.push('headless_chrome_ua');
      }
    }
    
    // Check for impossible plugin combinations (headless often has no plugins)
    if (components.plugins && Array.isArray(components.plugins) && components.plugins.length === 0) {
      indicators.push('no_plugins');
    }
    
    // Check for missing expected features
    if (!components.canvas && !components.webgl) {
      indicators.push('missing_rendering_features');
    }
    
    return {
      isHeadless: indicators.length > 1, // Require multiple indicators
      indicators
    };
  }

  /**
   * SECURITY: Analyze Canvas fingerprint for suspicious patterns
   * @param {string} canvas - Canvas fingerprint
   * @returns {Object} Canvas analysis result
   * @private
   */
  _analyzeCanvasFingerprint(canvas) {
    const suspiciousPatterns = [];
    
    // Check for common generated patterns
    if (canvas.length === 32 && /^[a-f0-9]+$/.test(canvas)) {
      suspiciousPatterns.push('md5_pattern');
    }
    
    if (canvas.length === 64 && /^[a-f0-9]+$/.test(canvas)) {
      suspiciousPatterns.push('sha256_pattern');
    }
    
    // Check for repeated patterns
    const uniqueChars = new Set(canvas.split(''));
    if (uniqueChars.size < canvas.length * 0.3) {
      suspiciousPatterns.push('low_character_diversity');
    }
    
    return {
      isSuspicious: suspiciousPatterns.length > 0,
      suspiciousPatterns
    };
  }

  /**
   * SECURITY: Detect artificially perfect fingerprints
   * @param {Object} components - Fingerprint components
   * @returns {Object} Perfectness detection result
   * @private
   */
  _detectPerfectFingerprint(components) {
    let perfectnessScore = 0;
    
    // Check if all optional components are present (suspicious)
    const optionalComponents = ['canvas', 'webgl', 'battery', 'deviceMemory', 'hardwareConcurrency'];
    const presentOptional = optionalComponents.filter(comp => components[comp]);
    
    if (presentOptional.length === optionalComponents.length) {
      perfectnessScore += 0.3;
    }
    
    // Check for perfect plugin lists (suspicious)
    if (components.plugins && Array.isArray(components.plugins) && components.plugins.length > 10) {
      perfectnessScore += 0.2;
    }
    
    // Check for perfect font lists (suspicious)
    if (components.fonts && Array.isArray(components.fonts) && components.fonts.length > 50) {
      perfectnessScore += 0.2;
    }
    
    return {
      isPerfect: perfectnessScore > 0.5,
      perfectnessScore
    };
  }

  // ================================
  // DATA SANITIZATION METHODS  
  // ================================

  /**
   * SECURITY: Sanitize user agent string
   * @param {string} userAgent - User agent to sanitize
   * @returns {string} Sanitized user agent
   * @private
   */
  _sanitizeUserAgent(userAgent) {
    if (!userAgent) return null;
    
    // Remove potentially dangerous characters and limit length
    return userAgent.replace(/[<>'"]/g, '').substring(0, 500);
  }

  /**
   * SECURITY: Sanitize screen resolution string
   * @param {string} resolution - Resolution to sanitize
   * @returns {string} Sanitized resolution
   * @private
   */
  _sanitizeScreenResolution(resolution) {
    if (!resolution) return null;
    
    // Only allow digits and 'x'
    const sanitized = resolution.replace(/[^0-9x]/g, '');
    return sanitized.match(/^\d+x\d+$/) ? sanitized : null;
  }

  /**
   * SECURITY: Sanitize plugin string
   * @param {Array|string} plugins - Plugins to sanitize
   * @returns {string} Sanitized plugin string
   * @private
   */
  _sanitizePluginString(plugins) {
    if (!plugins) return '';
    
    if (Array.isArray(plugins)) {
      return plugins.map(p => String(p).replace(/[<>'"]/g, '')).join(',').substring(0, 2000);
    }
    
    return String(plugins).replace(/[<>'"]/g, '').substring(0, 2000);
  }

  /**
   * SECURITY: Sanitize font string
   * @param {Array|string} fonts - Fonts to sanitize
   * @returns {string} Sanitized font string
   * @private
   */
  _sanitizeFontString(fonts) {
    if (!fonts) return '';
    
    if (Array.isArray(fonts)) {
      return fonts.map(f => String(f).replace(/[<>'"]/g, '')).join(',').substring(0, 5000);
    }
    
    return String(fonts).replace(/[<>'"]/g, '').substring(0, 5000);
  }

  /**
   * SECURITY: Sanitize battery info
   * @param {Object|string} battery - Battery info to sanitize
   * @returns {string} Sanitized battery string
   * @private
   */
  _sanitizeBatteryInfo(battery) {
    if (!battery) return null;
    
    if (typeof battery === 'object') {
      try {
        return JSON.stringify(battery).substring(0, 500);
      } catch (e) {
        return null;
      }
    }
    
    return String(battery).substring(0, 500);
  }

  /**
   * SECURITY: Sanitize network info
   * @param {Object|string} networkInfo - Network info to sanitize
   * @returns {string} Sanitized network string
   * @private
   */
  _sanitizeNetworkInfo(networkInfo) {
    if (!networkInfo) return null;
    
    if (typeof networkInfo === 'object') {
      try {
        return JSON.stringify(networkInfo).substring(0, 1000);
      } catch (e) {
        return null;
      }
    }
    
    return String(networkInfo).substring(0, 1000);
  }

  // ================================
  // TIMING AND BEHAVIORAL ANALYSIS
  // ================================

  /**
   * SECURITY: Analyze timing patterns for anomaly detection
   * @param {Object} existingFingerprint - Existing fingerprint record
   * @param {Object} components - New fingerprint components
   * @param {Object} timingData - Optional timing data
   * @returns {Object} Timing analysis result
   * @private
   */
  async _analyzeTimingPatterns(existingFingerprint, components, timingData = null) {
    try {
      if (!existingFingerprint) {
        return { isAnomalous: false };
      }
      
      const timeSinceLastSeen = Date.now() - new Date(existingFingerprint.last_seen).getTime();
      
      // Flag if seen again too quickly (potential automation)
      if (timeSinceLastSeen < BEHAVIORAL_THRESHOLDS.suspiciousTimingWindow) {
        logger.warn('🚨 SECURITY ALERT: Suspicious timing pattern', {
          deviceId: existingFingerprint.id,
          timeSinceLastSeen,
          threshold: BEHAVIORAL_THRESHOLDS.suspiciousTimingWindow
        });
        
        return { isAnomalous: true, reason: 'too_frequent_access' };
      }
      
      return { isAnomalous: false };
      
    } catch (error) {
      logger.error('🚨 SECURITY ERROR: Timing analysis failed:', error);
      return { isAnomalous: true, reason: 'analysis_error' };
    }
  }

  /**
   * SECURITY: Analyze interaction patterns
   * @param {Object} interactionData - Interaction timing and patterns
   * @returns {Object} Interaction analysis result
   * @private
   */
  _analyzeInteractionPatterns(interactionData) {
    const anomalies = [];
    
    if (interactionData.totalInteractionTime < BEHAVIORAL_THRESHOLDS.minInteractionTime) {
      anomalies.push('insufficient_interaction_time');
    }
    
    if (interactionData.clickPattern && interactionData.clickPattern.variance < 0.1) {
      anomalies.push('robotic_click_pattern');
    }
    
    return {
      isAnomalous: anomalies.length > 0,
      anomalies
    };
  }

  /**
   * SECURITY: Analyze geographic patterns for IP anomalies
   * @param {string} ipAddress - Current IP address
   * @param {Array} previousLocations - Previous geographic locations
   * @returns {Object} Geographic analysis result
   * @private
   */
  _analyzeGeographicPatterns(ipAddress, previousLocations) {
    // This is a simplified implementation
    // In production, you would use a proper geolocation service
    
    if (!previousLocations || previousLocations.length === 0) {
      return { isAnomalous: false };
    }
    
    // Basic check for impossible travel speeds
    // This would need proper geolocation integration
    return { isAnomalous: false, riskLevel: 0 };
  }

  /**
   * SECURITY: Analyze device switching patterns for anomalies
   * @param {string} ipAddress - IP address to analyze
   * @returns {Promise<Object>} Device switching analysis result
   * @private
   */
  async _analyzeDeviceSwitchingPatterns(ipAddress) {
    try {
      const recentDevices = await this._getRecentFingerprintsByIP(ipAddress, 24); // Last 24 hours
      
      if (recentDevices.length > BEHAVIORAL_THRESHOLDS.maxDevicesPerIP) {
        return {
          isAnomalous: true,
          reason: 'excessive_device_switching',
          deviceCount: recentDevices.length,
          threshold: BEHAVIORAL_THRESHOLDS.maxDevicesPerIP
        };
      }
      
      return { isAnomalous: false };
      
    } catch (error) {
      logger.error('🚨 SECURITY ERROR: Device switching analysis failed:', error);
      return { isAnomalous: true, reason: 'analysis_error' };
    }
  }
  
  /**
   * Find a fingerprint by its hash
   * @param {string} hash - Fingerprint hash to find
   * @returns {Promise<Object|null>} Matching fingerprint or null
   * @private
   */
  async _findFingerprintByHash(hash) {
    try {
      // SECURITY: Handle both new secure hash format (with salt) and legacy format
      let searchHash = hash;
      
      // If hash contains salt separator, extract base hash
      if (hash.includes(':')) {
        searchHash = hash.split(':')[0];
      }
      
      const query = `
        SELECT * FROM device_fingerprints
        WHERE fingerprint_hash = $1 OR fingerprint_hash LIKE $2
        LIMIT 1
      `;
      
      // Search for exact match or hash that starts with the base hash
      const result = await dbConnection.query(query, [hash, searchHash + ':%']);
      
      if (result.length > 0) {
        // SECURITY: Log hash access for audit trail
        logger.debug('🔍 SECURITY: Fingerprint hash lookup', {
          hashFound: true,
          deviceId: result[0].id,
          hasSecureFormat: hash.includes(':'),
          lastSeen: result[0].last_seen
        });
        
        return result[0];
      }
      
      return null;
    } catch (error) {
      logger.error('🚨 SECURITY ERROR: Failed to find fingerprint by hash:', {
        error: error.message,
        hashFormat: hash.includes(':') ? 'secure' : 'legacy'
      });
      throw error;
    }
  }
  
  /**
   * Find fingerprints by IP address
   * @param {string} ipAddress - IP address to match
   * @param {string} merchantId - Optional merchant ID to limit scope
   * @returns {Promise<Array>} Matching fingerprints
   * @private
   */
  async _findFingerprintsByIp(ipAddress, merchantId = null) {
    try {
      let query = `
        SELECT df.* FROM device_fingerprints df
      `;
      
      const values = [ipAddress];
      
      // If merchantId is provided, join with device_user_associations
      if (merchantId) {
        query += `
          INNER JOIN device_user_associations dua ON df.id = dua.device_id
          WHERE df.ip_address = $1 AND dua.merchant_id = $2
        `;
        values.push(merchantId);
      } else {
        query += `
          WHERE df.ip_address = $1
        `;
      }
      
      query += ` ORDER BY df.last_seen DESC LIMIT 10`;
      
      const result = await dbConnection.query(query, values);
      
      return result;
    } catch (error) {
      logger.error('Error finding fingerprints by IP:', error);
      throw error;
    }
  }
  
  /**
   * Get the most recently used devices
   * @param {number} limit - Maximum number of devices to return
   * @param {string} merchantId - Optional merchant ID to limit scope
   * @returns {Promise<Array>} List of recent devices
   * @private
   */
  async _getRecentDevices(limit = 50, merchantId = null) {
    try {
      let query = `
        SELECT df.* FROM device_fingerprints df
      `;
      
      const values = [limit];
      
      // If merchantId is provided, join with device_user_associations
      if (merchantId) {
        query += `
          INNER JOIN device_user_associations dua ON df.id = dua.device_id
          WHERE dua.merchant_id = $2
          ORDER BY df.last_seen DESC
          LIMIT $1
        `;
        values.unshift(merchantId);
      } else {
        query += `
          ORDER BY df.last_seen DESC
          LIMIT $1
        `;
      }
      
      const result = await dbConnection.query(query, values);
      
      return result;
    } catch (error) {
      logger.error('Error getting recent devices:', error);
      throw error;
    }
  }
}

// Export singleton instance
const deviceFingerprintRepository = new DeviceFingerprintRepository();
module.exports = { deviceFingerprintRepository }; 