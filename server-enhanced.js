/**
 * Fairs Identity Service Server - Enhanced Security Version
 * Migrated to use @fairs/security-middleware for consistency
 */

require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const { logger } = require('./src/utils/logger');
const config = require('./src/config');

// Import security middleware from shared package
const { 
  csrfProtection,
  injectCSRFToken,
  securityHeaders,
  secureCORS,
  progressiveRateLimiter,
  endpointRateLimiter,
  apiRequestSigning,
  SecurityMiddleware
} = require('@fairs/security-middleware');

// Import routes
const identityRoutes = require('./src/routes/identity-api');
const enhancedSchemaRoutes = require('./src/routes/enhanced-schema-api');
const userRightsRoutes = require('./src/routes/user-rights-api');
const dataTransparencyRoutes = require('./src/routes/data-transparency-api');

// Create Express application
const app = express();

// Trust proxy
app.set('trust proxy', true);

// Cookie parser for CSRF
app.use(cookieParser());

// Health check endpoint (before security)
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'identity-service',
        version: process.env.SERVICE_VERSION || '1.0.0',
        security: 'enhanced-v2',
        timestamp: new Date().toISOString()
    });
});

// Compression middleware
app.use(compression());

// Security headers with CSP
app.use(securityHeaders({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            frameAncestors: ["'none'"]
        }
    },
    // Additional security headers
    frameOptions: 'DENY',
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// CORS configuration
app.use(secureCORS({
    allowedOrigins: config.security?.corsOrigins || [
        'http://localhost:3000',
        'http://localhost:3007',
        'http://localhost:4000',
        'http://localhost:3002'
    ],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'Authorization', 'x-csrf-token', 'x-signature', 'x-timestamp'],
    exposedHeaders: ['x-csrf-token']
}));

// Body parsing middleware (before CSRF)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Progressive rate limiting
app.use(progressiveRateLimiter({
    anonymous: { 
        windowMs: 60 * 1000, // 1 minute
        max: 50,
        message: 'Too many requests from anonymous user'
    },
    authenticated: { 
        windowMs: 60 * 1000, // 1 minute
        max: 200,
        message: 'Too many requests, please try again later'
    }
}));

// CSRF protection
app.use(csrfProtection({
    excludePaths: [
        '/health',
        '/metrics',
        '/api/identity/identity/lookup', // Public lookup endpoint for service calls
        '/api/identity/lookup', // Legacy path
        '/api/identity/resolve', // Public resolution endpoint
        '/api/identity/batch-lookup', // Batch operations
        '/api/identity/device-fingerprint', // Device fingerprinting
        '/api/identity/device-fingerprint/match' // Device matching
    ],
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    httpOnly: true
}));

// Inject CSRF token into responses
app.use(injectCSRFToken);

// CSRF token endpoint
app.get('/api/csrf-token', (req, res) => {
    res.json({ 
        csrfToken: req.csrfToken ? req.csrfToken() : 'development-token',
        expiresIn: 3600 // 1 hour
    });
});

// Input sanitization
app.use(SecurityMiddleware.sanitizeInput());

// Request ID middleware
app.use((req, res, next) => {
    req.id = require('uuid').v4();
    res.setHeader('X-Request-ID', req.id);
    next();
});

// Request logging middleware
app.use((req, res, next) => {
    logger.info({
        message: 'Incoming request',
        requestId: req.id,
        method: req.method,
        url: req.url,
        userAgent: req.get('User-Agent'),
        ip: req.ip || req.connection.remoteAddress,
        timestamp: new Date().toISOString()
    });
    next();
});

// Endpoint-specific rate limiting
app.use(endpointRateLimiter({
    '/api/identity/lookup': {
        windowMs: 60 * 1000, // 1 minute
        max: 30,
        message: 'Too many lookup requests'
    },
    '/api/identity/create': {
        windowMs: 60 * 1000, // 1 minute
        max: 10,
        message: 'Too many identity creation requests'
    },
    '/api/identity/batch-lookup': {
        windowMs: 60 * 1000, // 1 minute
        max: 10,
        message: 'Too many batch lookup requests'
    },
    '/api/enhanced-schema/*': {
        windowMs: 60 * 1000, // 1 minute
        max: 50,
        message: 'Too many schema operations'
    },
    '/api/user-rights/*': {
        windowMs: 60 * 1000, // 1 minute
        max: 50,
        message: 'Too many user rights operations'
    }
}));

// API request signing for service-to-service
if (process.env.API_SIGNING_SECRET) {
    app.use(apiRequestSigning({
        secret: process.env.API_SIGNING_SECRET,
        serviceName: 'identity-service',
        verifyIncoming: true,
        signOutgoing: true,
        excludePaths: ['/health', '/api/csrf-token']
    }));
    logger.info('API request signing initialized');
} else {
    logger.warn('API_SIGNING_SECRET not configured - service-to-service signing disabled');
}

// Service authentication support for JWT tokens
if (process.env.SERVICE_ID && process.env.SERVICE_SECRET) {
    const { serviceClientMiddleware } = require('@fairs/security-middleware');
    
    // Attach service client to all requests for outgoing service calls
    app.use(serviceClientMiddleware({
        serviceId: process.env.SERVICE_ID,
        serviceSecret: process.env.SERVICE_SECRET,
        authServiceUrl: process.env.AUTH_SERVICE_URL || 'http://fairs-auth-service:3005'
    }));
    
    logger.info('Service authentication enabled', {
        serviceId: process.env.SERVICE_ID,
        authServiceUrl: process.env.AUTH_SERVICE_URL || 'http://fairs-auth-service:3005'
    });
} else {
    logger.warn('Service authentication not configured - SERVICE_ID and SERVICE_SECRET not set');
}

// Authentication metrics tracking
const { trackAuthentication } = require('./src/middleware/auth-metrics');
app.use(trackAuthentication);

// API routes
app.use('/api/identity', identityRoutes);
app.use('/api/enhanced-schema', enhancedSchemaRoutes);
app.use('/api/user-rights', userRightsRoutes);
app.use('/api/data-transparency', dataTransparencyRoutes);

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Route not found',
        code: 'NOT_FOUND',
        path: req.path,
        requestId: req.id
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error({
        message: 'Unhandled error',
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        requestId: req.id
    });

    // CSRF error handling
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({
            error: 'Invalid CSRF token',
            code: 'CSRF_VALIDATION_FAILED',
            requestId: req.id
        });
    }

    // JWT error handling
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            error: 'Invalid token',
            code: 'INVALID_TOKEN',
            requestId: req.id
        });
    }

    // Validation error handling
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            error: 'Validation failed',
            code: 'VALIDATION_ERROR',
            details: process.env.NODE_ENV !== 'production' ? err.details : undefined,
            requestId: req.id
        });
    }

    // Don't expose internal errors to clients
    const message = process.env.NODE_ENV === 'production' 
        ? 'An error occurred processing your request' 
        : err.message;

    res.status(err.status || 500).json({
        error: message,
        code: err.code || 'INTERNAL_ERROR',
        requestId: req.id
    });
});

// Start server
const PORT = process.env.PORT || 3002;
const server = app.listen(PORT, () => {
    logger.info({
        message: 'Identity service (enhanced) started successfully',
        port: PORT,
        environment: process.env.NODE_ENV || 'development',
        securityMode: 'enhanced-v2',
        features: {
            csrf: true,
            rateLimit: true,
            securityHeaders: true,
            apiSigning: !!process.env.API_SIGNING_SECRET,
            inputSanitization: true
        }
    });
    
    console.log(`🚀 Identity Service (Enhanced Security v2) running on port ${PORT}`);
    console.log(`🔒 Security Features: CSRF, Progressive Rate Limiting, Security Headers, API Signing`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🔑 CSRF token endpoint: http://localhost:${PORT}/api/csrf-token`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        logger.info('HTTP server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    logger.info('SIGINT signal received: closing HTTP server');
    server.close(() => {
        logger.info('HTTP server closed');
        process.exit(0);
    });
});

module.exports = app;