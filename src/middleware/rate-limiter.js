/**
 * Rate Limiter Middleware
 * 
 * Provides middleware for rate limiting API requests to prevent abuse.
 */

const { logger } = require('../utils/logger');

// Simple in-memory store for rate limiting
// In production, this should be replaced with Redis or similar
class RateLimitStore {
  constructor() {
    this.store = new Map();
    this.cleanupInterval = setInterval(() => this.cleanup(), 15 * 60 * 1000); // Cleanup every 15 minutes
  }
  
  /**
   * Increment the request count for a key
   * @param {string} key - The rate limiting key (IP, API key, etc)
   * @param {number} windowMs - The time window in milliseconds
   * @returns {Object} - Current rate limit info
   */
  increment(key, windowMs) {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Get or initialize record
    if (!this.store.has(key)) {
      this.store.set(key, { 
        hits: [],
        blockedUntil: null
      });
    }
    
    const record = this.store.get(key);
    
    // If currently blocked, check if block has expired
    if (record.blockedUntil && record.blockedUntil > now) {
      return {
        isBlocked: true,
        blockedUntil: record.blockedUntil,
        remainingMs: record.blockedUntil - now,
        current: record.hits.length,
        remaining: 0
      };
    } else if (record.blockedUntil) {
      // Block expired, clear it
      record.blockedUntil = null;
    }
    
    // Remove old hits outside current window
    record.hits = record.hits.filter(hit => hit > windowStart);
    
    // Add current hit
    record.hits.push(now);
    
    return {
      isBlocked: false,
      current: record.hits.length,
      remaining: null // Will be calculated by the middleware
    };
  }
  
  /**
   * Block a key for a specific time
   * @param {string} key - The rate limiting key
   * @param {number} durationMs - Block duration in milliseconds
   */
  block(key, durationMs) {
    if (!this.store.has(key)) {
      this.store.set(key, { hits: [] });
    }
    
    const record = this.store.get(key);
    record.blockedUntil = Date.now() + durationMs;
  }
  
  /**
   * Clean up old entries
   */
  cleanup() {
    const now = Date.now();
    
    // Remove entries older than one hour with no recent hits
    for (const [key, record] of this.store.entries()) {
      // If has a block that's still active, keep it
      if (record.blockedUntil && record.blockedUntil > now) {
        continue;
      }
      
      // If no hits or all hits are older than 1 hour, remove the record
      if (record.hits.length === 0 || 
          record.hits.every(hit => hit < now - 60 * 60 * 1000)) {
        this.store.delete(key);
      }
    }
  }
  
  /**
   * Reset all rate limits
   */
  reset() {
    this.store.clear();
  }
}

// Global rate limit store
const globalLimitStore = new RateLimitStore();

/**
 * Create rate limiting middleware
 * @param {Object} options - Rate limiting options
 * @returns {Function} - Express middleware
 */
function rateLimiter(options = {}) {
  const {
    windowMs = 60 * 1000, // 1 minute by default
    maxRequests = 60, // 60 requests per minute by default
    keyGenerator = (req) => req.ip, // Default to IP-based limiting
    skipSuccessfulRequests = false,
    handler = defaultHandler,
    skip = () => false,
    blockDuration = 15 * 60 * 1000, // 15 minutes block by default
    enableAutomaticBlocking = true, // Block after max is exceeded
    limiterStore = globalLimitStore
  } = options;
  
  return async (req, res, next) => {
    // Skip middleware if specified
    if (skip(req, res)) {
      return next();
    }
    
    const key = keyGenerator(req);
    
    // Track response success for skipSuccessfulRequests option
    if (skipSuccessfulRequests) {
      const originalSend = res.send;
      
      res.send = function(...args) {
        res.__rateLimit.skipIncrement = res.statusCode < 400;
        return originalSend.apply(res, args);
      };
    }
    
    try {
      // Increment rate counter
      const rateInfo = limiterStore.increment(key, windowMs);
      
      // Calculate remaining
      rateInfo.remaining = Math.max(0, maxRequests - rateInfo.current);
      
      // Set rate limit headers
      res.setHeader('X-RateLimit-Limit', maxRequests);
      res.setHeader('X-RateLimit-Remaining', rateInfo.remaining);
      
      // Store rate limit info
      req.rateLimit = rateInfo;
      res.__rateLimit = { skipIncrement: false };
      
      // Check if rate limited
      if (rateInfo.isBlocked) {
        // Set Retry-After header (in seconds)
        const retryAfterSeconds = Math.ceil(rateInfo.remainingMs / 1000);
        res.setHeader('Retry-After', retryAfterSeconds);
        
        return handler(req, res, next, {
          message: `Too many requests, please try again in ${retryAfterSeconds} seconds`,
          retryAfter: retryAfterSeconds,
          isBlocked: true
        });
      }
      
      // Check if we need to block due to rate exceeded
      if (enableAutomaticBlocking && rateInfo.remaining <= 0) {
        limiterStore.block(key, blockDuration);
        
        // Set Retry-After header
        const retryAfterSeconds = Math.ceil(blockDuration / 1000);
        res.setHeader('Retry-After', retryAfterSeconds);
        
        return handler(req, res, next, {
          message: `Rate limit exceeded, please try again in ${retryAfterSeconds} seconds`,
          retryAfter: retryAfterSeconds
        });
      }
      
      // Continue to next middleware/route handler
      next();
    } catch (error) {
      logger.error('Rate limiter error:', error);
      next(error);
    }
  };
}

/**
 * Default rate limit exceeded handler
 */
function defaultHandler(req, res, next, options) {
  logger.warn(`Rate limit exceeded: ${req.method} ${req.originalUrl}`);
  
  return res.status(429).json({
    success: false,
    error: 'Too Many Requests',
    message: options.message,
    retryAfter: options.retryAfter
  });
}

/**
 * Create API key based rate limiter middleware
 * @param {Object} options - Options (same as rateLimiter)
 * @returns {Function} - Express middleware
 */
function apiKeyRateLimiter(options = {}) {
  return rateLimiter({
    ...options,
    keyGenerator: (req) => {
      // Use API key from header if available, otherwise fall back to IP
      const apiKey = req.headers['x-api-key'] || 
                     req.headers['authorization'] || 
                     req.query.apiKey;
      
      if (apiKey) {
        return `apikey:${apiKey}`;
      }
      
      return req.ip;
    }
  });
}

module.exports = {
  rateLimiter,
  apiKeyRateLimiter,
  RateLimitStore,
  globalLimitStore
}; 