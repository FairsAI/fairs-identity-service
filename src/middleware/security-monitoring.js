/**
 * Security Monitoring and Alerting System
 * 
 * Complements their security plan with real-time threat detection
 * and automated response capabilities for payment systems
 */

const { logger } = require('../utils/logger');

class SecurityMonitor {
  constructor() {
    this.threats = new Map(); // IP -> threat data
    this.alertThresholds = {
      failedAuth: { count: 5, window: 300000 }, // 5 failures in 5 minutes
      invalidApiKey: { count: 3, window: 300000 }, // 3 invalid keys in 5 minutes  
      sqlInjection: { count: 1, window: 0 }, // Immediate alert
      rateLimitHit: { count: 10, window: 300000 }, // 10 rate limit hits in 5 minutes
      suspiciousInput: { count: 5, window: 300000 } // 5 suspicious inputs in 5 minutes
    };
    
    this.securityEvents = [];
    this.maxEventHistory = 10000;
    
    // Cleanup old events every 5 minutes
    setInterval(() => this.cleanupEvents(), 300000);
  }

  /**
   * Log security event and check for threats
   */
  logSecurityEvent(eventType, details) {
    const timestamp = Date.now();
    const clientIP = details.ip || 'unknown';
    
    const event = {
      timestamp,
      eventType,
      clientIP,
      userAgent: details.userAgent || 'unknown',
      endpoint: details.endpoint || 'unknown',
      severity: this.getSeverity(eventType),
      details
    };

    // Add to event history
    this.securityEvents.unshift(event);
    if (this.securityEvents.length > this.maxEventHistory) {
      this.securityEvents.pop();
    }

    // Track threat level for this IP
    this.trackThreatLevel(clientIP, eventType, timestamp);

    // Log to security logger
    logger.warn('Security Event Detected', event);

    // Check if immediate action is required
    if (this.shouldAlert(eventType, clientIP)) {
      this.triggerSecurityAlert(eventType, clientIP, event);
    }

    return event;
  }

  getSeverity(eventType) {
    const severityMap = {
      sql_injection_attempt: 'CRITICAL',
      authentication_failure: 'HIGH',
      invalid_api_key_format: 'HIGH', 
      api_key_not_found: 'HIGH',
      rate_limit_exceeded: 'MEDIUM',
      suspicious_input: 'MEDIUM',
      invalid_token_format: 'MEDIUM',
      schema_validation_failed: 'LOW'
    };
    
    return severityMap[eventType] || 'LOW';
  }

  trackThreatLevel(clientIP, eventType, timestamp) {
    if (!this.threats.has(clientIP)) {
      this.threats.set(clientIP, {
        events: [],
        threatScore: 0,
        blocked: false,
        firstSeen: timestamp
      });
    }

    const threat = this.threats.get(clientIP);
    threat.events.push({ eventType, timestamp });

    // Calculate threat score
    threat.threatScore = this.calculateThreatScore(threat.events);

    // Auto-block if threat score is too high
    if (threat.threatScore >= 100 && !threat.blocked) {
      threat.blocked = true;
      this.triggerAutoBlock(clientIP, threat);
    }
  }

  calculateThreatScore(events) {
    const now = Date.now();
    const recent = events.filter(e => now - e.timestamp < 300000); // Last 5 minutes
    
    let score = 0;
    
    for (const event of recent) {
      switch (event.eventType) {
        case 'sql_injection_attempt':
          score += 50; // Immediate high threat
          break;
        case 'authentication_failure':
          score += 10;
          break;
        case 'invalid_api_key_format':
        case 'api_key_not_found':
          score += 15;
          break;
        case 'rate_limit_exceeded':
          score += 5;
          break;
        case 'suspicious_input':
          score += 8;
          break;
        default:
          score += 2;
      }
    }

    return Math.min(score, 100); // Cap at 100
  }

  shouldAlert(eventType, clientIP) {
    const threshold = this.alertThresholds[eventType];
    if (!threshold) return false;

    if (threshold.count === 1) return true; // Immediate alert events

    const threat = this.threats.get(clientIP);
    if (!threat) return false;

    const now = Date.now();
    const recentEvents = threat.events.filter(e => 
      e.eventType === eventType && 
      now - e.timestamp < threshold.window
    );

    return recentEvents.length >= threshold.count;
  }

  triggerSecurityAlert(eventType, clientIP, event) {
    const alert = {
      alertId: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      severity: this.getSeverity(eventType),
      eventType,
      clientIP,
      event,
      threatLevel: this.threats.get(clientIP)?.threatScore || 0
    };

    // Log critical alert
    logger.error('🚨 SECURITY ALERT TRIGGERED', alert);

    // Send to monitoring dashboard
    this.sendToMonitoringDashboard(alert);

    // For critical events, consider immediate action
    if (alert.severity === 'CRITICAL') {
      this.handleCriticalThreat(clientIP, alert);
    }
  }

  triggerAutoBlock(clientIP, threat) {
    logger.error('🛡️ AUTO-BLOCK TRIGGERED', {
      clientIP,
      threatScore: threat.threatScore,
      events: threat.events.length,
      duration: Date.now() - threat.firstSeen
    });

    // Add IP to blocked list (implement with Redis/database)
    this.addToBlockList(clientIP, threat);
  }

  handleCriticalThreat(clientIP, alert) {
    // For SQL injection attempts or other critical threats
    // Implement immediate response actions
    
    logger.error('🔥 CRITICAL THREAT DETECTED - IMMEDIATE ACTION REQUIRED', {
      clientIP,
      eventType: alert.eventType,
      alertId: alert.alertId
    });

    // Could implement automatic temporary blocking
    // or escalation to security team
  }

  /**
   * Express middleware for security monitoring
   */
  createMiddleware() {
    return (req, res, next) => {
      const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
      
      // Check if IP is blocked
      const threat = this.threats.get(clientIP);
      if (threat && threat.blocked) {
        this.logSecurityEvent('blocked_ip_access_attempt', {
          ip: clientIP,
          endpoint: req.path,
          userAgent: req.get('User-Agent')
        });
        
        return res.status(403).json({
          success: false,
          error: 'Access denied due to security policy'
        });
      }

      // Add security context to request
      req.securityContext = {
        clientIP,
        threatScore: threat?.threatScore || 0,
        isMonitored: true
      };

      next();
    };
  }

  /**
   * Get security dashboard data
   */
  getDashboardData() {
    const now = Date.now();
    const last24Hours = this.securityEvents.filter(e => now - e.timestamp < 86400000);
    
    return {
      totalEvents: this.securityEvents.length,
      last24Hours: last24Hours.length,
      criticalEvents: last24Hours.filter(e => e.severity === 'CRITICAL').length,
      blockedIPs: Array.from(this.threats.values()).filter(t => t.blocked).length,
      topThreats: this.getTopThreats(),
      recentEvents: this.securityEvents.slice(0, 50),
      threatsByType: this.getThreatsByType(last24Hours)
    };
  }

  getTopThreats() {
    return Array.from(this.threats.entries())
      .map(([ip, threat]) => ({ ip, ...threat }))
      .sort((a, b) => b.threatScore - a.threatScore)
      .slice(0, 10);
  }

  getThreatsByType(events) {
    const types = {};
    for (const event of events) {
      types[event.eventType] = (types[event.eventType] || 0) + 1;
    }
    return types;
  }

  cleanupEvents() {
    const cutoff = Date.now() - 86400000; // 24 hours
    this.securityEvents = this.securityEvents.filter(e => e.timestamp > cutoff);
    
    // Cleanup old threat data
    for (const [ip, threat] of this.threats.entries()) {
      threat.events = threat.events.filter(e => e.timestamp > cutoff);
      if (threat.events.length === 0 && !threat.blocked) {
        this.threats.delete(ip);
      }
    }
  }

  sendToMonitoringDashboard(alert) {
    // Implementation would send to your monitoring system
    // (Slack, PagerDuty, etc.)
    console.log('📊 Alert sent to monitoring dashboard:', alert.alertId);
  }

  addToBlockList(clientIP, threat) {
    // Implementation would add to Redis/database block list
    console.log('🚫 IP added to block list:', clientIP);
  }
}

module.exports = new SecurityMonitor(); 