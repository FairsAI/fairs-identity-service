/**
 * Authentication Metrics Middleware
 * 
 * PRE-LAUNCH VERSION: JWT-only metrics
 * Tracks JWT token usage for both services and users
 */

const { logger } = require('../utils/logger');

// In-memory metrics (could be moved to Redis for persistence)
const authMetrics = {
  serviceJwt: 0,
  userJwt: 0,
  totalRequests: 0,
  startTime: new Date(),
  lastReset: new Date()
};

// Track authentication by service
const serviceMetrics = new Map();

/**
 * Middleware to track JWT authentication
 */
function trackAuthentication(req, res, next) {
  authMetrics.totalRequests++;
  
  // Track service JWT authentication
  if (req.service) {
    authMetrics.serviceJwt++;
    
    // Track by service
    const serviceId = req.service.id || 'unknown';
    if (!serviceMetrics.has(serviceId)) {
      serviceMetrics.set(serviceId, {
        requests: 0,
        firstSeen: new Date(),
        lastSeen: new Date(),
        permissions: req.service.permissions || []
      });
    }
    
    const metrics = serviceMetrics.get(serviceId);
    metrics.requests++;
    metrics.lastSeen = new Date();
    metrics.permissions = req.service.permissions || [];
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
  const uptime = Date.now() - authMetrics.startTime.getTime();
  
  // Get service breakdown
  const serviceBreakdown = Array.from(serviceMetrics.entries()).map(([serviceId, metrics]) => {
    return {
      serviceId,
      serviceName: serviceId.replace('-service', ' Service').replace(/-/g, ' ')
        .split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '),
      totalRequests: metrics.requests,
      permissions: metrics.permissions,
      firstSeen: metrics.firstSeen,
      lastSeen: metrics.lastSeen,
      avgRequestsPerHour: (metrics.requests / (uptime / 3600000)).toFixed(2)
    };
  }).sort((a, b) => b.totalRequests - a.totalRequests);
  
  return {
    summary: {
      totalRequests: authMetrics.totalRequests,
      serviceJwtRequests: authMetrics.serviceJwt,
      userJwtRequests: authMetrics.userJwt,
      servicePercentage: authMetrics.totalRequests > 0 
        ? `${(authMetrics.serviceJwt / authMetrics.totalRequests * 100).toFixed(2)}%` 
        : '0%',
      userPercentage: authMetrics.totalRequests > 0 
        ? `${(authMetrics.userJwt / authMetrics.totalRequests * 100).toFixed(2)}%` 
        : '0%',
      uptimeMs: uptime,
      uptimeHours: (uptime / 3600000).toFixed(2),
      startTime: authMetrics.startTime,
      lastReset: authMetrics.lastReset
    },
    serviceBreakdown,
    authenticationStatus: {
      message: 'JWT-only authentication active',
      totalServices: serviceBreakdown.length,
      averageRequestsPerService: serviceBreakdown.length > 0 
        ? (authMetrics.serviceJwt / serviceBreakdown.length).toFixed(2)
        : 0
    }
  };
}


/**
 * Reset metrics (for testing or scheduled resets)
 */
function resetMetrics() {
  authMetrics.serviceJwt = 0;
  authMetrics.userJwt = 0;
  authMetrics.totalRequests = 0;
  authMetrics.lastReset = new Date();
  serviceMetrics.clear();
  
  logger.info('Authentication metrics reset');
}

module.exports = {
  trackAuthentication,
  getAuthMetrics,
  resetMetrics
};