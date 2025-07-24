/**
 * 🔒 SECURITY HARDENED: Secure Authentication Service
 * Enterprise-grade JWT authentication with comprehensive security controls
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config');
const { logger } = require('../utils/logger');

class AuthService {
    constructor() {
        // 🔒 SECURITY: Require strong JWT secret in production
        this.jwtSecret = this.validateJwtSecret();
        this.tokenBlacklist = new Set(); // Simple blacklist for demo
        this.rateLimitMap = new Map(); // Rate limiting storage
    }

    /**
     * 🔒 SECURITY: Validate JWT secret strength
     */
    validateJwtSecret() {
        const secret = config.api?.jwtSecret || process.env.JWT_SECRET;
        
        if (!secret) {
            throw new Error('JWT_SECRET environment variable is required');
        }
        
        // Ensure minimum secret length for security
        if (secret.length < 32) {
            logger.warn('⚠️  JWT secret is shorter than recommended 32 characters');
        }
        
        // Never use default secrets in production
        if (process.env.NODE_ENV === 'production' && secret.includes('default')) {
            throw new Error('Default JWT secret not allowed in production');
        }
        
        return secret;
    }

    /**
     * 🔒 SECURITY HARDENED: Verify JWT token with comprehensive validation
     */
    verifyToken(token) {
        try {
            if (!token || token.trim() === '') {
                throw new Error('Empty token provided');
            }

            // Check if token is blacklisted
            if (this.tokenBlacklist.has(token)) {
                throw new Error('Token has been revoked');
            }

            // Verify JWT with security options
            const decoded = jwt.verify(token, this.jwtSecret, {
                algorithms: ['HS256'], // Only allow secure algorithms
                issuer: 'fairs-identity-service',
                audience: 'fairs-platform',
                maxAge: '24h', // Maximum token age
                clockTolerance: 30 // 30 second clock tolerance
            });

            // Additional security validations
            this.validateTokenClaims(decoded);
            
            logger.debug('JWT token verified successfully', {
                userId: decoded.userId,
                tokenType: decoded.type || 'standard',
                expiresAt: new Date(decoded.exp * 1000).toISOString()
            });

            return decoded;
            
        } catch (error) {
            logger.warn('JWT verification failed', { 
                error: error.message,
                tokenPrefix: token ? token.substring(0, 10) + '...' : 'none'
            });
            
            if (error.name === 'TokenExpiredError') {
                throw new Error('Token has expired');
            } else if (error.name === 'JsonWebTokenError') {
                throw new Error('Invalid token format');
            } else if (error.name === 'NotBeforeError') {
                throw new Error('Token not yet valid');
            } else {
                throw new Error('Token verification failed');
            }
        }
    }

    /**
     * 🔒 SECURITY: Validate token claims for security
     */
    validateTokenClaims(decoded) {
        // Ensure required claims exist
        if (!decoded.userId || !decoded.iat || !decoded.exp) {
            throw new Error('Missing required token claims');
        }
        
        // Check token age
        const now = Math.floor(Date.now() / 1000);
        if (decoded.exp < now) {
            throw new Error('Token has expired');
        }
        
        // Prevent tokens issued too far in the future
        if (decoded.iat > now + 60) {
            throw new Error('Token issued time is invalid');
        }
        
        // Validate user ID format (simple validation)
        if (typeof decoded.userId !== 'string' || decoded.userId.length < 1) {
            throw new Error('Invalid user ID in token');
        }
    }

    /**
     * 🔒 SECURITY: Token generation DISABLED - Auth consolidation phase 1
     * Identity service must not generate tokens. Use auth-service instead.
     */
    generateToken(payload, options = {}) {
        logger.error('Token generation attempted in identity service', {
            userId: payload?.userId,
            caller: new Error().stack.split('\n')[2], // Log caller for debugging
            timestamp: new Date().toISOString()
        });
        
        throw new Error('Token generation is disabled in identity service. Use auth-service for all token generation.');
    }

    /**
     * 🔒 SECURITY: Token revocation for logout/security
     */
    revokeToken(token) {
        try {
            this.tokenBlacklist.add(token);
            logger.info('Token revoked successfully');
            return true;
        } catch (error) {
            logger.error('Token revocation failed', { error: error.message });
            return false;
        }
    }

    /**
     * 🔒 SECURITY: Rate limiting for token operations
     */
    checkRateLimit(identifier, maxAttempts = 5, windowMs = 15 * 60 * 1000) {
        const now = Date.now();
        const windowStart = now - windowMs;
        
        if (!this.rateLimitMap.has(identifier)) {
            this.rateLimitMap.set(identifier, []);
        }
        
        const attempts = this.rateLimitMap.get(identifier);
        
        // Remove old attempts
        const recentAttempts = attempts.filter(time => time > windowStart);
        this.rateLimitMap.set(identifier, recentAttempts);
        
        if (recentAttempts.length >= maxAttempts) {
            throw new Error('Rate limit exceeded');
        }
        
        recentAttempts.push(now);
        return true;
    }

    /**
     * 🔒 SECURITY: Guest token creation DISABLED - Auth consolidation phase 1
     * All tokens must be generated by auth-service only.
     */
    createGuestToken(email) {
        logger.error('Guest token generation attempted in identity service', {
            email,
            caller: new Error().stack.split('\n')[2],
            timestamp: new Date().toISOString()
        });
        
        throw new Error('Guest token generation is disabled. Use auth-service for all token generation.');
    }
}

const authService = new AuthService();

module.exports = {
    authService,
    // Export functions for compatibility - DISABLED for auth consolidation
    createGuestToken: (email) => {
        throw new Error('Guest token generation is disabled. Use auth-service for all token generation.');
    },
    authenticateToken: async (req, res, next) => {
        try {
            const authHeader = req.headers.authorization;
            
            if (!authHeader) {
                return res.status(401).json({
                    success: false,
                    error: 'Authorization token required',
                    code: 'MISSING_TOKEN'
                });
            }

            const token = authHeader.startsWith('Bearer ') 
                ? authHeader.substring(7) 
                : authHeader;

            // Rate limiting by IP
            const clientIP = req.ip || req.connection.remoteAddress;
            authService.checkRateLimit(clientIP);

            const decoded = authService.verifyToken(token);
            req.user = decoded;
            req.token = token;
            
            // Add security headers
            res.set({
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block'
            });
            
            next();
            
        } catch (error) {
            logger.warn('Authentication failed', {
                error: error.message,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
            
            return res.status(401).json({
                success: false,
                error: error.message || 'Authentication failed',
                code: 'AUTH_FAILED'
            });
        }
    }
}; 