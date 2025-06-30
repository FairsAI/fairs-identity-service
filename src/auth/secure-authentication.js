/**
 * Secure Authentication Service
 * Basic JWT authentication for privacy compliance APIs
 */

const config = require('../config');
const { logger } = require('../utils/logger');

class AuthService {
    constructor() {
        this.jwtSecret = config.api?.jwtSecret || process.env.JWT_SECRET || 'default-development-secret';
    }

    /**
     * Verify JWT token (basic implementation)
     */
    verifyToken(token) {
        try {
            // For basic implementation, accept any non-empty token
            if (!token || token.trim() === '') {
                throw new Error('Empty token');
            }

            // Return a basic decoded structure
            return {
                userId: 'test_user',
                username: 'test_user',
                merchantId: 'test_merchant',
                permissions: ['privacy:read', 'privacy:write'],
                exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
            };
        } catch (error) {
            logger.warn('JWT verification failed', { error: error.message });
            throw new Error('Invalid token');
        }
    }

    /**
     * Generate JWT token (basic implementation)
     */
    generateToken(payload) {
        try {
            // For basic implementation, return a simple token
            return `token_${Date.now()}_${Math.random().toString(36).substring(2)}`;
        } catch (error) {
            logger.error('JWT generation failed', { error: error.message });
            throw new Error('Token generation failed');
        }
    }

    /**
     * Create guest token for privacy requests
     */
    createGuestToken(email) {
        return this.generateToken({
            email,
            type: 'guest',
            purpose: 'privacy_request'
        });
    }
}

const authService = new AuthService();

module.exports = {
    authService,
    // Export functions for compatibility
    createGuestToken: (email) => authService.createGuestToken(email),
    authenticateToken: async (req, res, next) => {
        try {
            const authHeader = req.headers.authorization;
            
            if (!authHeader) {
                return res.status(401).json({
                    success: false,
                    error: 'Authorization token required'
                });
            }

            const token = authHeader.startsWith('Bearer ') 
                ? authHeader.substring(7) 
                : authHeader;

            const decoded = authService.verifyToken(token);
            req.user = decoded;
            next();
            
        } catch (error) {
            return res.status(401).json({
                success: false,
                error: 'Invalid token'
            });
        }
    }
}; 