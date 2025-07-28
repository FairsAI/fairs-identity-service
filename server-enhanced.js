/**
 * Fairs Identity Service Server - Enhanced Security Version
 * 
 * Main entry point for the identity service with enhanced security features
 */

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { logger } = require('./src/utils/logger');
const config = require('./src/config');

// Import security middleware
const { 
    csrfProtection, 
    securityHeaders, 
    createRateLimiter, 
    secureCORS,
    authenticate,
    validateInput
} = require('../shared/security-middleware');

// Import routes
const identityRoutes = require('./src/routes/identity-api');
const enhancedSchemaRoutes = require('./src/routes/enhanced-schema-api');
const userRightsRoutes = require('./src/routes/user-rights-api');
const dataTransparencyRoutes = require('./src/routes/data-transparency-api');

// Create Express application
const app = express();

// Cookie parser for CSRF
app.use(cookieParser());

// Enhanced security headers
app.use(securityHeaders({
    customCSP: {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "data:", "https:"],
        'connect-src': ["'self'"],
        'font-src': ["'self'"],
        'object-src': ["'none'"],
        'media-src': ["'self'"],
        'frame-src': ["'none'"]
    }
}));

// Enhanced CORS configuration
app.use(secureCORS({
    allowedOrigins: config.security?.corsOrigins || ['http://localhost:3000'],
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowCredentials: true
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// General rate limiting
app.use(createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false
}));

// Request logging middleware
app.use((req, res, next) => {
    logger.info({
        message: 'Incoming request',
        method: req.method,
        url: req.url,
        userAgent: req.get('User-Agent'),
        ip: req.ip || req.connection.remoteAddress
    });
    next();
});

// CSRF protection for state-changing operations
const csrfExclusions = [
    '/health',
    '/api/identity/device/fingerprint',
    '/api/identity/recognize',
    '/api/identity/verify',
    '/api/v1/users/check'
];

app.use((req, res, next) => {
    const shouldExclude = csrfExclusions.some(path => req.path.startsWith(path));
    if (req.method === 'GET' || shouldExclude) {
        return next();
    }
    csrfProtection()(req, res, next);
});

// API routes
app.use('/api/identity', identityRoutes);
app.use('/api/enhanced-schema', enhancedSchemaRoutes);
app.use('/api/user-rights', userRightsRoutes);
app.use('/api/data-transparency', dataTransparencyRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'identity-service',
        version: process.env.SERVICE_VERSION || '1.0.0',
        timestamp: new Date().toISOString()
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error({
        message: 'Unhandled error',
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method
    });

    // Don't expose internal errors to clients
    const message = process.env.NODE_ENV === 'production' 
        ? 'An error occurred processing your request' 
        : err.message;

    res.status(err.status || 500).json({
        error: message,
        code: err.code || 'INTERNAL_ERROR'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Route not found',
        code: 'NOT_FOUND'
    });
});

// Start server
const PORT = config.server.port || 3000;
const server = app.listen(PORT, () => {
    logger.info({
        message: 'Identity service (enhanced) started successfully',
        port: PORT,
        environment: process.env.NODE_ENV || 'development',
        securityMode: 'enhanced'
    });
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        logger.info('HTTP server closed');
        process.exit(0);
    });
});

module.exports = app;