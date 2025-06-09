/**
 * Device Fingerprint Repository
 * 
 * Manages the storage and retrieval of device fingerprints, providing
 * similarity matching algorithms for device recognition.
 */

const { dbConnection } = require('./db-connection');
const { logger } = require('../utils/logger');
const crypto = require('crypto');

class DeviceFingerprintRepository {
  /**
   * Store a new device fingerprint
   * @param {Object} components - The fingerprint components
   * @returns {Promise<Object>} The stored fingerprint record
   */
  async storeFingerprint(components) {
    try {
      logger.debug('Storing new device fingerprint');
      
      // Generate a hash of the fingerprint components for uniqueness
      const fingerprintHash = this._generateFingerprintHash(components);
      
      // Check if fingerprint already exists
      const existingFingerprint = await this._findFingerprintByHash(fingerprintHash);
      if (existingFingerprint) {
        // If it exists, update the last_seen time
        await this.updateDeviceLastSeen(existingFingerprint.id);
        return existingFingerprint;
      }
      
      // Extract relevant fields from components
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
      
      // Insert new fingerprint
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
      
      // Convert arrays and objects to strings
      const pluginsStr = Array.isArray(plugins) ? plugins.join(',') : String(plugins || '');
      const fontsStr = Array.isArray(fonts) ? fonts.join(',') : String(fonts || '');
      const batteryStr = typeof battery === 'object' ? JSON.stringify(battery) : String(battery || '');
      const networkInfoStr = typeof networkInfo === 'object' ? JSON.stringify(networkInfo) : String(networkInfo || '');
      
      const values = [
        fingerprintHash,
        userAgent || null,
        screenResolution || null,
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
        Object.keys(metadata).length > 0 ? JSON.stringify(metadata) : null,
        1.0 // Initial confidence score
      ];
      
      const result = await dbConnection.query(query, values);
      
      logger.info('Successfully stored new device fingerprint', { 
        id: result[0]?.id,
        hash: fingerprintHash
      });
      
      return result[0];
    } catch (error) {
      logger.error('Error storing device fingerprint:', error);
      throw error;
    }
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
   * Generate a consistent hash from fingerprint components
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
  
  /**
   * Find a fingerprint by its hash
   * @param {string} hash - Fingerprint hash to find
   * @returns {Promise<Object|null>} Matching fingerprint or null
   * @private
   */
  async _findFingerprintByHash(hash) {
    try {
      const query = `
        SELECT * FROM device_fingerprints
        WHERE fingerprint_hash = $1
        LIMIT 1
      `;
      
      const result = await dbConnection.query(query, [hash]);
      
      return result.length > 0 ? result[0] : null;
    } catch (error) {
      logger.error('Error finding fingerprint by hash:', error);
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