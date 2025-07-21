/**
 * Enhanced Identity Service API Client - Phase 5
 * Provides comprehensive user preference management and cross-service integration
 * Uses cross_merchant_id as universal foreign key across all services
 */

const { logger } = require('../monitoring/integration-logger');
const { dbConnection } = require('../database/db-connection');

class EnhancedIdentityAPIClient {
  constructor(options = {}) {
    // SECURITY: All service communication MUST go through API Orchestrator
    const orchestratorUrl = process.env.API_ORCHESTRATOR_URL || 'http://fairs-api-orchestrator:4000';
    this.baseURL = options.baseURL || `${orchestratorUrl}/api/v1/identity`;
    this.apiKey = this.validateApiKey(options.apiKey || process.env.IDENTITY_SERVICE_API_KEY);
    this.timeout = options.timeout || 30000;
    this.logger = logger.child({ service: 'enhanced-identity-api-client' });
  }

  /**
   * Get comprehensive user preferences with cross-service references
   * @param {string} userId - User ID (cross_merchant_id)
   * @returns {Promise<Object>} Complete user preferences
   */
  async getUserPreferences(userId) {
    try {
      this.logger.info(`Getting user preferences for user: ${userId}`);

      const query = `
        SELECT 
          u.id,
          u.email,
          u.first_name,
          u.last_name,
          u.preferred_payment_method_id,
          u.preferred_shipping_address_id,
          u.preferred_billing_address_id,
          u.user_preferences,
          u.behavior_profile,
          u.ml_features,
          u.shopping_patterns,
          u.risk_score,
          u.loyalty_tier,
          u.lifetime_value,
          
          -- User addresses for shipping preferences
          COALESCE(
            (SELECT json_agg(
              json_build_object(
                'id', ua.id,
                'address_line_1', ua.address_line_1,
                'city', ua.city,
                'state_province', ua.state_province,
                'postal_code', ua.postal_code,
                'country_code', ua.country_code,
                'is_default_shipping', ua.is_default_shipping,
                'is_default_billing', ua.is_default_billing,
                'address_type', ua.address_type,
                'label', ua.label
              )
            ) FROM identity_service.user_addresses ua WHERE ua.user_id = u.id),
            '[]'::json
          ) as user_addresses,
          
          -- User payment methods managed by payments service
          '[]'::json as user_payment_methods,
          
          -- Recent behavior analytics
          (SELECT json_build_object(
            'session_count', COUNT(*),
            'avg_session_duration', AVG(uba.session_duration_minutes),
            'total_page_views', SUM(uba.page_views),
            'conversion_events', SUM(uba.conversion_events)
          ) FROM identity_service.user_behavior_analytics uba 
          WHERE uba.user_id = u.id 
          AND uba.created_at >= NOW() - INTERVAL '30 days') as recent_behavior
          
        FROM identity_service.users u
        WHERE u.id = $1 AND u.is_active = true
      `;

      const result = await dbConnection.query(query, [userId]);
      
      if (!result || result.length === 0) {
        throw new Error(`User not found: ${userId}`);
      }

      const user = result[0];
      
      // Calculate trust score based on behavior and risk
      const trustScore = this.calculateTrustScore(user);
      
      return {
        user_id: user.id,
        email: user.email,
        full_name: `${user.first_name || ''} ${user.last_name || ''}`.trim(),
        preferred_payment_method_id: user.preferred_payment_method_id,
        preferred_shipping_address_id: user.preferred_shipping_address_id,
        preferred_billing_address_id: user.preferred_billing_address_id,
        user_preferences: user.user_preferences || {},
        behavior_profile: user.behavior_profile || {},
        ml_features: user.ml_features || {},
        shopping_patterns: user.shopping_patterns || {},
        risk_score: user.risk_score || 0.0,
        loyalty_tier: user.loyalty_tier || 'bronze',
        lifetime_value: user.lifetime_value || 0.0,
        trust_score: trustScore,
        user_addresses: user.user_addresses || [],
        user_payment_methods: [], // Managed by payments service
        recent_behavior: user.recent_behavior || {}
      };

    } catch (error) {
      this.logger.error(`Failed to get user preferences for ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Update user preferences with cross-service validation
   * @param {string} userId - User ID
   * @param {Object} preferences - Preference updates
   * @returns {Promise<Object>} Updated preferences
   */
  async updateUserPreferences(userId, preferences) {
    try {
      this.logger.info(`Updating user preferences for user: ${userId}`);

      const updates = [];
      const values = [userId];
      let paramIndex = 2;

      // Build dynamic update query
      if (preferences.preferred_payment_method_id !== undefined) {
        updates.push(`preferred_payment_method_id = $${paramIndex}`);
        values.push(preferences.preferred_payment_method_id);
        paramIndex++;
      }

      if (preferences.preferred_shipping_address_id !== undefined) {
        updates.push(`preferred_shipping_address_id = $${paramIndex}`);
        values.push(preferences.preferred_shipping_address_id);
        paramIndex++;
      }

      if (preferences.preferred_billing_address_id !== undefined) {
        updates.push(`preferred_billing_address_id = $${paramIndex}`);
        values.push(preferences.preferred_billing_address_id);
        paramIndex++;
      }

      if (preferences.user_preferences) {
        updates.push(`user_preferences = $${paramIndex}`);
        values.push(JSON.stringify(preferences.user_preferences));
        paramIndex++;
      }

      if (preferences.behavior_profile) {
        updates.push(`behavior_profile = $${paramIndex}`);
        values.push(JSON.stringify(preferences.behavior_profile));
        paramIndex++;
      }

      if (updates.length === 0) {
        throw new Error('No valid preferences provided for update');
      }

      updates.push(`updated_at = CURRENT_TIMESTAMP`);

      const query = `
        UPDATE identity_service.users 
        SET ${updates.join(', ')}
        WHERE id = $1 
        RETURNING id, email, preferred_payment_method_id, preferred_shipping_address_id, preferred_billing_address_id
      `;

      const result = await dbConnection.query(query, values);
      
      if (!result || result.length === 0) {
        throw new Error(`Failed to update user preferences for ${userId}`);
      }

      this.logger.info(`Successfully updated preferences for user: ${userId}`);
      return result[0];

    } catch (error) {
      this.logger.error(`Failed to update user preferences for ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Record user behavior analytics for ML learning
   * @param {string} userId - User ID
   * @param {Object} behaviorData - Behavior analytics data
   * @returns {Promise<Object>} Recorded behavior entry
   */
  async recordUserBehavior(userId, behaviorData) {
    try {
      this.logger.info(`Recording behavior for user: ${userId}`);

      const query = `
        INSERT INTO identity_service.user_behavior_analytics (
          user_id, session_id, merchant_id, event_type, event_data,
          page_views, session_duration_minutes, conversion_events,
          device_type, user_agent, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP)
        RETURNING id, event_type, created_at
      `;

      const values = [
        userId,
        behaviorData.session_id || null,
        behaviorData.merchant_id || 'default',
        behaviorData.event_type || 'interaction',
        JSON.stringify(behaviorData.event_data || {}),
        behaviorData.page_views || 1,
        behaviorData.session_duration_minutes || 0,
        behaviorData.conversion_events || 0,
        behaviorData.device_type || 'unknown',
        behaviorData.user_agent || null
      ];

      const result = await dbConnection.query(query, values);
      
      this.logger.info(`Successfully recorded behavior for user: ${userId}`);
      return result[0];

    } catch (error) {
      this.logger.error(`Failed to record behavior for ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Get user ML features for personalization
   * @param {string} userId - User ID
   * @returns {Promise<Object>} ML features and recommendations
   */
  async getUserMLFeatures(userId) {
    try {
      const query = `
        SELECT 
          u.ml_features,
          u.behavior_profile,
          u.shopping_patterns,
          u.risk_score,
          u.loyalty_tier,
          u.lifetime_value,
          
          -- Aggregated behavior metrics
          (SELECT json_build_object(
            'total_sessions', COUNT(*),
            'avg_session_duration', COALESCE(AVG(session_duration_minutes), 0),
            'total_conversions', SUM(conversion_events),
            'engagement_score', COALESCE(AVG(page_views), 0) * 0.1,
            'last_activity', MAX(created_at)
          ) FROM identity_service.user_behavior_analytics 
          WHERE user_id = u.id) as behavior_metrics
          
        FROM identity_service.users u
        WHERE u.id = $1
      `;

      const result = await dbConnection.query(query, [userId]);
      
      if (!result || result.length === 0) {
        return this.getDefaultMLFeatures();
      }

      const user = result[0];
      const behaviorMetrics = user.behavior_metrics || {};

      return {
        user_id: userId,
        ml_features: user.ml_features || {},
        behavior_profile: user.behavior_profile || {},
        shopping_patterns: user.shopping_patterns || {},
        risk_score: user.risk_score || 0.0,
        loyalty_tier: user.loyalty_tier || 'bronze',
        lifetime_value: user.lifetime_value || 0.0,
        behavior_metrics,
        personalization_score: this.calculatePersonalizationScore(user, behaviorMetrics),
        recommendations: this.generateRecommendations(user, behaviorMetrics)
      };

    } catch (error) {
      this.logger.error(`Failed to get ML features for ${userId}:`, error);
      return this.getDefaultMLFeatures();
    }
  }

  /**
   * Calculate trust score based on user data
   * @param {Object} user - User data
   * @returns {number} Trust score (0.0 to 1.0)
   */
  calculateTrustScore(user) {
    let score = 0.5; // Base trust score

    // Risk score impact (inverted - lower risk = higher trust)
    if (user.risk_score !== null) {
      score += (1.0 - parseFloat(user.risk_score)) * 0.3;
    }

    // Loyalty tier impact
    const loyaltyBonus = {
      'bronze': 0.0,
      'silver': 0.1,
      'gold': 0.2,
      'platinum': 0.3
    };
    score += loyaltyBonus[user.loyalty_tier] || 0.0;

    // Behavior consistency (if recent behavior exists)
    if (user.recent_behavior && user.recent_behavior.session_count > 0) {
      const consistencyBonus = Math.min(user.recent_behavior.session_count / 10, 0.2);
      score += consistencyBonus;
    }

    // Ensure score is within bounds
    return Math.max(0.0, Math.min(1.0, score));
  }

  /**
   * Calculate personalization score
   * @param {Object} user - User data
   * @param {Object} behaviorMetrics - Behavior metrics
   * @returns {number} Personalization score (0.0 to 1.0)
   */
  calculatePersonalizationScore(user, behaviorMetrics) {
    let score = 0.3; // Base personalization

    // ML features completeness
    const mlFeatures = user.ml_features || {};
    const featureCount = Object.keys(mlFeatures).length;
    score += Math.min(featureCount / 10, 0.3);

    // Behavior data richness
    if (behaviorMetrics.total_sessions > 0) {
      score += Math.min(behaviorMetrics.total_sessions / 20, 0.2);
    }

    // Shopping patterns depth
    const shoppingPatterns = user.shopping_patterns || {};
    const patternCount = Object.keys(shoppingPatterns).length;
    score += Math.min(patternCount / 5, 0.2);

    return Math.max(0.0, Math.min(1.0, score));
  }

  /**
   * Generate personalized recommendations
   * @param {Object} user - User data
   * @param {Object} behaviorMetrics - Behavior metrics
   * @returns {Array} Recommendation list
   */
  generateRecommendations(user, behaviorMetrics) {
    const recommendations = [];

    // Loyalty tier recommendations
    if (user.loyalty_tier === 'bronze' && behaviorMetrics.total_sessions > 5) {
      recommendations.push({
        type: 'loyalty_upgrade',
        message: 'You\'re close to Silver tier! Complete 2 more purchases.',
        confidence: 0.8
      });
    }

    // Behavior-based recommendations
    if (behaviorMetrics.engagement_score > 5) {
      recommendations.push({
        type: 'premium_features',
        message: 'Enable saved payment methods for faster checkout',
        confidence: 0.9
      });
    }

    return recommendations;
  }

  /**
   * Get default ML features for new users
   * @returns {Object} Default ML features
   */
  getDefaultMLFeatures() {
    return {
      ml_features: {},
      behavior_profile: {},
      shopping_patterns: {},
      risk_score: 0.5,
      loyalty_tier: 'bronze',
      lifetime_value: 0.0,
      behavior_metrics: {},
      personalization_score: 0.3,
      recommendations: [
        {
          type: 'welcome',
          message: 'Complete your profile for personalized recommendations',
          confidence: 1.0
        }
      ]
    };
  }

  /**
   * Health check for the identity service
   * @returns {Promise<Object>} Service health status
   */
  async getServiceHealth() {
    try {
      const result = await dbConnection.query('SELECT 1 as health_check');
      return {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        database: result ? 'connected' : 'disconnected'
      };
    } catch (error) {
      this.logger.error('Health check failed:', error);
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: error.message
      };
    }
  }
}

module.exports = { EnhancedIdentityAPIClient }; 