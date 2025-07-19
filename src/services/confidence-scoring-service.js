const winston = require('winston');
const featureFlags = require('./feature-flag-service');

class ConfidenceScoringService {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console()
      ]
    });

    // Scoring weights for different factors
    this.weights = {
      deviceRecognition: 30,      // Device fingerprint match
      behavioralConsistency: 25,  // Behavioral patterns
      verificationHistory: 20,    // Recent verification success
      crossMerchantData: 15,      // Data from other merchants
      timeBasedFactors: 10        // Time since last seen, etc.
    };

    // Decay factors
    this.decayFactors = {
      daily: 0.95,    // 5% decay per day
      weekly: 0.85,   // 15% decay per week
      monthly: 0.70   // 30% decay per month
    };
  }

  /**
   * Calculate overall confidence score for user recognition
   * @param {Object} user - User data
   * @param {Object} deviceFingerprint - Current device fingerprint
   * @param {Object} context - Additional context (IP, time, etc.)
   * @returns {Object} Confidence score and breakdown
   */
  async calculateConfidenceScore(user, deviceFingerprint, context = {}) {
    try {
      const scores = {
        deviceRecognition: await this.scoreDeviceRecognition(user, deviceFingerprint),
        behavioralConsistency: await this.scoreBehavioralConsistency(user, context),
        verificationHistory: await this.scoreVerificationHistory(user),
        crossMerchantData: await this.scoreCrossMerchantData(user, context),
        timeBasedFactors: await this.scoreTimeFactors(user, context)
      };

      // Calculate weighted average
      let totalScore = 0;
      let totalWeight = 0;

      for (const [factor, score] of Object.entries(scores)) {
        const weight = this.weights[factor];
        totalScore += score * weight;
        totalWeight += weight;
      }

      const confidence = Math.round((totalScore / totalWeight) * 100) / 100;
      const adjustedConfidence = Math.max(0, Math.min(100, confidence));

      // Apply feature flag constraints
      if (!featureFlags.isAutoRecognitionEnabled()) {
        // If auto-recognition is disabled, cap confidence at medium threshold
        const maxConfidence = featureFlags.getMediumConfidenceThreshold() - 1;
        return {
          confidence: Math.min(adjustedConfidence, maxConfidence),
          breakdown: scores,
          factors: this.getConfidenceFactors(adjustedConfidence, scores),
          featureFlagApplied: true,
          reason: 'auto_recognition_disabled'
        };
      }

      return {
        confidence: adjustedConfidence,
        breakdown: scores,
        factors: this.getConfidenceFactors(adjustedConfidence, scores),
        featureFlagApplied: false
      };

    } catch (error) {
      this.logger.error('Error calculating confidence score', {
        error: error.message,
        userId: user?.id
      });

      return {
        confidence: 0,
        breakdown: {},
        factors: { error: error.message },
        featureFlagApplied: false
      };
    }
  }

  /**
   * Score device recognition based on fingerprint matching
   */
  async scoreDeviceRecognition(user, currentFingerprint) {
    if (!featureFlags.isDeviceFingerprintingEnabled() || !currentFingerprint) {
      return 0;
    }

    try {
      // This would query the device graph from database
      // For now, simulate device matching logic
      const userDevices = user.deviceHistory || [];
      
      if (userDevices.length === 0) {
        return 0; // No previous devices
      }

      let bestMatch = 0;
      for (const device of userDevices) {
        // Simulate fingerprint comparison
        const similarity = this.compareFingerprints(currentFingerprint, device.fingerprint);
        
        // Apply time decay
        const daysSinceLastSeen = this.getDaysSince(device.lastSeen);
        const decayedSimilarity = similarity * Math.pow(this.decayFactors.daily, daysSinceLastSeen);
        
        bestMatch = Math.max(bestMatch, decayedSimilarity);
      }

      return bestMatch;
    } catch (error) {
      this.logger.error('Device recognition scoring error', { error: error.message });
      return 0;
    }
  }

  /**
   * Score behavioral consistency
   */
  async scoreBehavioralConsistency(user, context) {
    if (!featureFlags.isBehavioralTrackingEnabled()) {
      return 0;
    }

    try {
      const behavioralProfile = user.behavioralProfile || {};
      let consistencyScore = 0;
      let factorCount = 0;

      // Typing patterns
      if (behavioralProfile.typingPatterns && context.typingData) {
        const typingConsistency = this.compareTypingPatterns(
          behavioralProfile.typingPatterns,
          context.typingData
        );
        consistencyScore += typingConsistency;
        factorCount++;
      }

      // Mouse movement patterns
      if (behavioralProfile.mousePatterns && context.mouseData) {
        const mouseConsistency = this.compareMousePatterns(
          behavioralProfile.mousePatterns,
          context.mouseData
        );
        consistencyScore += mouseConsistency;
        factorCount++;
      }

      // Navigation patterns
      if (behavioralProfile.navigationPatterns && context.navigationData) {
        const navConsistency = this.compareNavigationPatterns(
          behavioralProfile.navigationPatterns,
          context.navigationData
        );
        consistencyScore += navConsistency;
        factorCount++;
      }

      // Time-based patterns
      if (behavioralProfile.timePatterns) {
        const timeConsistency = this.compareTimePatterns(
          behavioralProfile.timePatterns,
          new Date()
        );
        consistencyScore += timeConsistency;
        factorCount++;
      }

      return factorCount > 0 ? consistencyScore / factorCount : 0;
    } catch (error) {
      this.logger.error('Behavioral consistency scoring error', { error: error.message });
      return 0;
    }
  }

  /**
   * Score verification history
   */
  async scoreVerificationHistory(user) {
    try {
      const verificationHistory = user.verificationHistory || [];
      
      if (verificationHistory.length === 0) {
        return 0;
      }

      // Recent successful verifications boost confidence
      const recentVerifications = verificationHistory.filter(v => {
        const daysSince = this.getDaysSince(v.timestamp);
        return daysSince <= 30 && v.success;
      });

      let score = 0;

      // Base score from successful verifications
      const successRate = recentVerifications.length / Math.max(verificationHistory.length, 1);
      score += successRate * 70;

      // Bonus for recent activity
      const mostRecentVerification = verificationHistory[0];
      if (mostRecentVerification) {
        const daysSince = this.getDaysSince(mostRecentVerification.timestamp);
        const recencyBonus = Math.max(0, 30 - daysSince) / 30 * 30;
        score += recencyBonus;
      }

      return Math.min(score, 100);
    } catch (error) {
      this.logger.error('Verification history scoring error', { error: error.message });
      return 0;
    }
  }

  /**
   * Score cross-merchant data
   */
  async scoreCrossMerchantData(user, context) {
    if (!featureFlags.isCrossMerchantEnabled()) {
      return 0;
    }

    try {
      const crossMerchantData = user.crossMerchantProfile || {};
      let score = 0;

      // Number of merchants user is verified with
      const merchantCount = crossMerchantData.verifiedMerchants?.length || 0;
      if (merchantCount > 0) {
        score += Math.min(merchantCount * 10, 50); // Max 50 points for multiple merchants
      }

      // Cross-merchant behavioral consistency
      if (crossMerchantData.behavioralConsistency) {
        score += crossMerchantData.behavioralConsistency * 30;
      }

      // Trust signals from other merchants
      if (crossMerchantData.trustSignals) {
        const avgTrustScore = crossMerchantData.trustSignals.reduce((a, b) => a + b, 0) / crossMerchantData.trustSignals.length;
        score += avgTrustScore * 20;
      }

      return Math.min(score, 100);
    } catch (error) {
      this.logger.error('Cross-merchant scoring error', { error: error.message });
      return 0;
    }
  }

  /**
   * Score time-based factors
   */
  async scoreTimeFactors(user, context) {
    try {
      let score = 0;

      // Time since last login
      if (user.lastLoginAt) {
        const daysSinceLogin = this.getDaysSince(user.lastLoginAt);
        
        if (daysSinceLogin <= 1) {
          score += 40; // Very recent
        } else if (daysSinceLogin <= 7) {
          score += 30; // Recent
        } else if (daysSinceLogin <= 30) {
          score += 20; // Somewhat recent
        } else {
          score += 10; // Old
        }
      }

      // Typical activity time patterns
      if (user.activityPatterns) {
        const currentHour = new Date().getHours();
        const isTypicalTime = user.activityPatterns.commonHours?.includes(currentHour);
        if (isTypicalTime) {
          score += 30;
        }
      }

      // Account age factor
      if (user.createdAt) {
        const accountAgeDays = this.getDaysSince(user.createdAt);
        if (accountAgeDays > 30) {
          score += 30; // Established account
        } else if (accountAgeDays > 7) {
          score += 20; // Week-old account
        } else {
          score += 10; // New account
        }
      }

      return Math.min(score, 100);
    } catch (error) {
      this.logger.error('Time factors scoring error', { error: error.message });
      return 0;
    }
  }

  /**
   * Get human-readable confidence factors
   */
  getConfidenceFactors(confidence, breakdown) {
    const factors = [];

    if (breakdown.deviceRecognition > 70) {
      factors.push('Recognized device');
    }
    
    if (breakdown.behavioralConsistency > 70) {
      factors.push('Consistent behavior patterns');
    }
    
    if (breakdown.verificationHistory > 70) {
      factors.push('Strong verification history');
    }
    
    if (breakdown.crossMerchantData > 50) {
      factors.push('Verified across multiple merchants');
    }
    
    if (breakdown.timeBasedFactors > 70) {
      factors.push('Typical usage time and patterns');
    }

    return factors;
  }

  /**
   * Helper methods for pattern comparison
   */
  compareFingerprints(fp1, fp2) {
    // Simplified fingerprint comparison
    if (!fp1 || !fp2) return 0;
    
    // This would use the DeviceFingerprintService comparison
    const similarity = fp1.hash === fp2.hash ? 100 : 0;
    return similarity;
  }

  compareTypingPatterns(stored, current) {
    // Simplified typing pattern comparison
    if (!stored || !current) return 0;
    
    const avgSpeedDiff = Math.abs(stored.avgSpeed - current.avgSpeed);
    const speedSimilarity = Math.max(0, 100 - (avgSpeedDiff / stored.avgSpeed * 100));
    
    return speedSimilarity;
  }

  compareMousePatterns(stored, current) {
    // Simplified mouse pattern comparison
    if (!stored || !current) return 0;
    
    return 50; // Placeholder
  }

  compareNavigationPatterns(stored, current) {
    // Simplified navigation pattern comparison
    if (!stored || !current) return 0;
    
    return 50; // Placeholder
  }

  compareTimePatterns(stored, currentTime) {
    if (!stored || !stored.commonHours) return 0;
    
    const currentHour = currentTime.getHours();
    return stored.commonHours.includes(currentHour) ? 80 : 20;
  }

  getDaysSince(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  }

  /**
   * Determine authentication method based on confidence score
   */
  getAuthenticationMethod(confidence) {
    return featureFlags.getAuthMethod(confidence);
  }

  /**
   * Update user confidence over time based on successful authentications
   */
  updateUserTrustScore(userId, successful, method) {
    // This would update long-term user trust metrics
    this.logger.info('User trust score update', {
      userId,
      successful,
      method,
      timestamp: new Date().toISOString()
    });
  }
}

module.exports = ConfidenceScoringService;