/**
 * Authentication Metrics Middleware
 * 
 * Tracks authentication methods used to monitor JWT migration progress
 */

const { logger } = require('../utils/logger');

// In-memory metrics (could be moved to Redis for persistence)
const authMetrics = {
  jwt: 0,
  apiKey: 0,
  userJwt: 0,
  startTime: new Date(),
  lastReset: new Date()
};

// Track authentication by service
const serviceMetrics = new Map();

/**
 * Middleware to track authentication methods
 */
function trackAuthentication(req, res, next) {
  // Track service authentication
  if (req.service) {
    const authType = req.service.tokenType === 'jwt' ? 'jwt' : 'apiKey';
    authMetrics[authType]++;
    
    // Track by service
    const serviceId = req.service.id || 'unknown';
    if (!serviceMetrics.has(serviceId)) {
      serviceMetrics.set(serviceId, {
        jwt: 0,
        apiKey: 0,
        firstSeen: new Date(),
        lastSeen: new Date()
      });
    }
    
    const metrics = serviceMetrics.get(serviceId);
    metrics[authType]++;
    metrics.lastSeen = new Date();
    
    // Log if still using API key
    if (authType === 'apiKey' && metrics.apiKey % 100 === 0) {
      logger.warn('Service still using API key authentication', {
        serviceId,
        apiKeyRequests: metrics.apiKey,
        message: 'Please migrate to JWT service tokens'
      });
    }
  }
  
  // Track user JWT authentication
  if (req.user && !req.service) {
    authMetrics.userJwt++;
  }
  
  next();
}

/**
 * Get authentication metrics
 */
function getAuthMetrics() {
  const total = authMetrics.jwt + authMetrics.apiKey;
  const uptime = Date.now() - authMetrics.startTime.getTime();
  
  // Calculate percentages
  const jwtPercentage = total > 0 ? (authMetrics.jwt / total * 100).toFixed(2) : 0;
  const apiKeyPercentage = total > 0 ? (authMetrics.apiKey / total * 100).toFixed(2) : 0;
  
  // Get service breakdown
  const serviceBreakdown = Array.from(serviceMetrics.entries()).map(([serviceId, metrics]) => {
    const serviceTotal = metrics.jwt + metrics.apiKey;
    return {
      serviceId,
      totalRequests: serviceTotal,
      jwtRequests: metrics.jwt,
      apiKeyRequests: metrics.apiKey,
      jwtPercentage: serviceTotal > 0 ? (metrics.jwt / serviceTotal * 100).toFixed(2) : 0,
      firstSeen: metrics.firstSeen,
      lastSeen: metrics.lastSeen,
      migrationStatus: metrics.apiKey === 0 ? 'fully-migrated' : 
                      metrics.jwt > 0 ? 'partially-migrated' : 'not-migrated'
    };
  }).sort((a, b) => b.totalRequests - a.totalRequests);
  
  return {
    summary: {
      totalServiceRequests: total,
      jwtRequests: authMetrics.jwt,
      apiKeyRequests: authMetrics.apiKey,
      userJwtRequests: authMetrics.userJwt,
      jwtPercentage: `${jwtPercentage}%`,
      apiKeyPercentage: `${apiKeyPercentage}%`,
      uptimeMs: uptime,
      startTime: authMetrics.startTime,
      lastReset: authMetrics.lastReset
    },
    serviceBreakdown,
    migrationProgress: {
      fullyMigrated: serviceBreakdown.filter(s => s.migrationStatus === 'fully-migrated').length,
      partiallyMigrated: serviceBreakdown.filter(s => s.migrationStatus === 'partially-migrated').length,
      notMigrated: serviceBreakdown.filter(s => s.migrationStatus === 'not-migrated').length,
      totalServices: serviceBreakdown.length
    },
    recommendations: generateRecommendations(serviceBreakdown)
  };
}

/**
 * Generate migration recommendations based on metrics
 */
function generateRecommendations(serviceBreakdown) {
  const recommendations = [];
  
  // Services still using only API keys
  const apiKeyOnlyServices = serviceBreakdown.filter(s => s.migrationStatus === 'not-migrated');
  if (apiKeyOnlyServices.length > 0) {
    recommendations.push({
      priority: 'high',
      message: `${apiKeyOnlyServices.length} service(s) still using only API keys`,
      services: apiKeyOnlyServices.map(s => s.serviceId),
      action: 'Update these services to use JWT service tokens'
    });
  }
  
  // Services with high API key usage
  const highApiKeyUsage = serviceBreakdown.filter(s => 
    s.apiKeyRequests > 1000 && parseFloat(s.jwtPercentage) < 50
  );
  if (highApiKeyUsage.length > 0) {
    recommendations.push({
      priority: 'medium',
      message: 'Services with high API key usage detected',
      services: highApiKeyUsage.map(s => ({
        serviceId: s.serviceId,
        apiKeyRequests: s.apiKeyRequests,
        jwtPercentage: s.jwtPercentage
      })),
      action: 'Prioritize migration for high-traffic services'
    });
  }
  
  // Services successfully migrated
  const fullyMigrated = serviceBreakdown.filter(s => s.migrationStatus === 'fully-migrated');
  if (fullyMigrated.length > 0) {
    recommendations.push({
      priority: 'info',
      message: `${fullyMigrated.length} service(s) fully migrated to JWT`,
      services: fullyMigrated.map(s => s.serviceId),
      action: 'Consider removing API key support for these services'
    });
  }
  
  return recommendations;
}

/**
 * Reset metrics (for testing or scheduled resets)
 */
function resetMetrics() {
  authMetrics.jwt = 0;
  authMetrics.apiKey = 0;
  authMetrics.userJwt = 0;
  authMetrics.lastReset = new Date();
  serviceMetrics.clear();
  
  logger.info('Authentication metrics reset');
}

module.exports = {
  trackAuthentication,
  getAuthMetrics,
  resetMetrics
};