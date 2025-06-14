/**
 * Performance Monitoring Middleware
 * Enterprise-grade request tracking and system monitoring for Phase 4
 */

const { dbConnection } = require('../database/db-connection');

class PerformanceMonitor {
  constructor() {
    this.metrics = new Map();
    this.startTime = Date.now();
    this.requestCounts = {
      total: 0,
      successful: 0,
      errors: 0,
      slow: 0
    };
    this.slowThreshold = 1000; // 1 second
    this.recentRequests = []; // Keep last 100 requests
    this.maxRecentRequests = 100;
  }

  middleware() {
    return (req, res, next) => {
      const startTime = Date.now();
      const requestId = this.generateRequestId();
      
      // Track request start
      req.requestId = requestId;
      req.startTime = startTime;
      
      // Track request metrics
      this.requestCounts.total++;
      
      // Override res.json to capture response metrics
      const originalJson = res.json;
      const originalSend = res.send;
      const originalEnd = res.end;
      
      const captureResponse = (data) => {
        const responseTime = Date.now() - startTime;
        const statusCode = res.statusCode;
        
        // Update counters
        if (statusCode >= 200 && statusCode < 400) {
          this.requestCounts.successful++;
        } else {
          this.requestCounts.errors++;
        }
        
        if (responseTime > this.slowThreshold) {
          this.requestCounts.slow++;
        }
        
        // Log performance metrics
        const performanceLevel = this.getPerformanceLevel(responseTime);
        const logLevel = statusCode >= 400 ? 'error' : 
                        responseTime > this.slowThreshold ? 'warn' : 'info';
        
        console.log(`[${logLevel.toUpperCase()}] ${requestId}: ${req.method} ${req.path} - ${responseTime}ms [${performanceLevel}] (${statusCode})`);
        
        // Add performance headers
        res.set({
          'X-Response-Time': `${responseTime}ms`,
          'X-Request-ID': requestId,
          'X-Performance-Level': performanceLevel,
          'X-Enhanced-Schema': 'active',
          'X-Database': 'fairs_commerce'
        });
        
        // Store request data for analytics
        this.storeRequestMetrics({
          requestId,
          method: req.method,
          path: req.path,
          statusCode,
          responseTime,
          performanceLevel,
          timestamp: new Date().toISOString(),
          userAgent: req.get('User-Agent'),
          ip: req.ip || req.connection?.remoteAddress
        });
      };

      // Override response methods
      res.json = function(body) {
        captureResponse(body);
        return originalJson.call(this, body);
      };

      res.send = function(body) {
        captureResponse(body);
        return originalSend.call(this, body);
      };

      res.end = function(data) {
        captureResponse(data);
        return originalEnd.call(this, data);
      };

      next();
    };
  }

  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getPerformanceLevel(responseTime) {
    if (responseTime < 50) return 'excellent';
    if (responseTime < 200) return 'good';
    if (responseTime < 500) return 'acceptable';
    if (responseTime < 1000) return 'slow';
    return 'critical';
  }

  storeRequestMetrics(requestData) {
    // Add to recent requests (keep only last 100)
    this.recentRequests.unshift(requestData);
    if (this.recentRequests.length > this.maxRecentRequests) {
      this.recentRequests = this.recentRequests.slice(0, this.maxRecentRequests);
    }

    // Store in metrics map for quick access
    this.metrics.set(requestData.requestId, requestData);
    
    // Clean up old metrics (keep only last hour)
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    for (const [id, data] of this.metrics.entries()) {
      if (new Date(data.timestamp).getTime() < oneHourAgo) {
        this.metrics.delete(id);
      }
    }
  }

  async getDatabaseMetrics() {
    try {
      // Use single Enhanced Schema database connection
      const healthCheck = await dbConnection.query('SELECT NOW() as timestamp, current_database() as database, current_schema() as schema');
      
      return {
        health: {
          status: dbConnection.isHealthy() ? 'healthy' : 'unhealthy',
          database: healthCheck[0]?.database || 'unknown',
          schema: healthCheck[0]?.schema || 'unknown',
          timestamp: healthCheck[0]?.timestamp || new Date().toISOString()
        },
        connections: {
          enhancedSchema: {
            database: 'fairs_commerce',
            schema: 'identity_service',
            status: dbConnection.isHealthy() ? 'connected' : 'disconnected'
          }
        },
        uptime: Date.now() - this.startTime,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return { 
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  getRequestMetrics() {
    const now = Date.now();
    const oneMinuteAgo = now - (60 * 1000);
    const fiveMinutesAgo = now - (5 * 60 * 1000);
    const oneHourAgo = now - (60 * 60 * 1000);

    // Filter requests by time periods
    const lastMinute = this.recentRequests.filter(req => 
      new Date(req.timestamp).getTime() > oneMinuteAgo);
    const lastFiveMinutes = this.recentRequests.filter(req => 
      new Date(req.timestamp).getTime() > fiveMinutesAgo);
    const lastHour = this.recentRequests.filter(req => 
      new Date(req.timestamp).getTime() > oneHourAgo);

    // Calculate metrics
    const calculateStats = (requests) => {
      if (requests.length === 0) return { count: 0, avgResponseTime: 0, errorRate: 0 };
      
      const totalResponseTime = requests.reduce((sum, req) => sum + req.responseTime, 0);
      const errors = requests.filter(req => req.statusCode >= 400).length;
      
      return {
        count: requests.length,
        avgResponseTime: Math.round(totalResponseTime / requests.length),
        errorRate: Math.round((errors / requests.length) * 100),
        slowRequests: requests.filter(req => req.responseTime > this.slowThreshold).length
      };
    };

    return {
      timestamp: new Date().toISOString(),
      overall: {
        ...this.requestCounts,
        uptime: now - this.startTime,
        requestsPerSecond: this.requestCounts.total / ((now - this.startTime) / 1000)
      },
      periods: {
        lastMinute: calculateStats(lastMinute),
        lastFiveMinutes: calculateStats(lastFiveMinutes),
        lastHour: calculateStats(lastHour)
      },
      performance: {
        excellent: this.recentRequests.filter(req => req.performanceLevel === 'excellent').length,
        good: this.recentRequests.filter(req => req.performanceLevel === 'good').length,
        acceptable: this.recentRequests.filter(req => req.performanceLevel === 'acceptable').length,
        slow: this.recentRequests.filter(req => req.performanceLevel === 'slow').length,
        critical: this.recentRequests.filter(req => req.performanceLevel === 'critical').length
      }
    };
  }

  getEndpointAnalytics() {
    const endpointStats = new Map();
    
    this.recentRequests.forEach(req => {
      const endpoint = `${req.method} ${req.path}`;
      
      if (!endpointStats.has(endpoint)) {
        endpointStats.set(endpoint, {
          endpoint,
          count: 0,
          totalResponseTime: 0,
          errors: 0,
          statusCodes: new Map()
        });
      }
      
      const stats = endpointStats.get(endpoint);
      stats.count++;
      stats.totalResponseTime += req.responseTime;
      
      if (req.statusCode >= 400) {
        stats.errors++;
      }
      
      const statusCount = stats.statusCodes.get(req.statusCode) || 0;
      stats.statusCodes.set(req.statusCode, statusCount + 1);
    });

    // Convert to array and calculate averages
    const analyticsArray = Array.from(endpointStats.values()).map(stats => ({
      endpoint: stats.endpoint,
      count: stats.count,
      avgResponseTime: Math.round(stats.totalResponseTime / stats.count),
      errorRate: Math.round((stats.errors / stats.count) * 100),
      statusCodes: Object.fromEntries(stats.statusCodes),
      performance: stats.totalResponseTime / stats.count < 100 ? 'excellent' : 
                  stats.totalResponseTime / stats.count < 500 ? 'good' : 'needs_optimization'
    }));

    // Sort by request count
    return analyticsArray.sort((a, b) => b.count - a.count);
  }

  getSystemDiagnostics() {
    const memoryUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    return {
      timestamp: new Date().toISOString(),
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
      },
      memory: {
        heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB',
        heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB',
        external: Math.round(memoryUsage.external / 1024 / 1024) + 'MB',
        rss: Math.round(memoryUsage.rss / 1024 / 1024) + 'MB',
        utilization: Math.round((memoryUsage.heapUsed / memoryUsage.heapTotal) * 100) + '%'
      },
      cpu: {
        user: Math.round(cpuUsage.user / 1000) + 'ms',
        system: Math.round(cpuUsage.system / 1000) + 'ms'
      },
      phase4: {
        databaseSeparation: 'active',
        monitoring: 'enabled',
        performanceTracking: 'real_time',
        enterpriseFeatures: 'enabled'
      }
    };
  }

  // Health check for the monitoring system itself
  async getMonitoringHealth() {
    try {
      const systemDiagnostics = this.getSystemDiagnostics();
      const requestMetrics = this.getRequestMetrics();
      const databaseMetrics = await this.getDatabaseMetrics();

      const overallHealth = 
        systemDiagnostics.memory.utilization.replace('%', '') < 80 &&
        requestMetrics.periods.lastMinute.errorRate < 5 &&
        Object.values(databaseMetrics.health || {}).every(db => db.status === 'healthy');

      return {
        status: overallHealth ? 'healthy' : 'degraded',
        monitoring: {
          activeRequests: this.recentRequests.length,
          metricsCollected: this.metrics.size,
          uptime: Date.now() - this.startTime
        },
        system: systemDiagnostics,
        requests: requestMetrics,
        databases: databaseMetrics,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'error',
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  // Reset metrics (useful for testing or maintenance)
  resetMetrics() {
    this.metrics.clear();
    this.recentRequests = [];
    this.requestCounts = {
      total: 0,
      successful: 0,
      errors: 0,
      slow: 0
    };
    this.startTime = Date.now();
    
    console.log('Performance monitoring metrics reset at', new Date().toISOString());
  }
}

// Export singleton instance
module.exports = new PerformanceMonitor(); 