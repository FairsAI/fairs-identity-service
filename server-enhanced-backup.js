/**
 * Fairs Identity Service Server - Enhanced Security Version
 * 
 * Main entry point for the identity service with enhanced security features
 */

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { logger } = require('./src/utils/logger');
const config = require('./src/config');

// Import routes
const identityRoutes = require('./src/routes/identity-api');
const enhancedSchemaRoutes = require('./src/routes/enhanced-schema-api');
const userRightsRoutes = require('./src/routes/user-rights-api');
const dataTransparencyRoutes = require('./src/routes/data-transparency-api');

// Create Express application
const app = express();

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"]
        }
    }
}));

// CORS configuration
app.use(cors({
    origin: config.security?.corsOrigins || ['http://localhost:3000', 'http://localhost:3007'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'x-csrf-token']
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// General rate limiting
app.use(rateLimit({
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

// Skip CSRF protection for now - using rate limiting and other security measures

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