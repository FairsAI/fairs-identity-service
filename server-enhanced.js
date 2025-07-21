/**
 * Fairs Identity Service Server - Enhanced Security Version
 * 
 * Main entry point with Phase 0.4 security enhancements
 * Including CSRF protection, advanced security headers, and rate limiting
 */

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { logger } = require('./src/utils/logger');
const config = require('./src/config');

// Import enhanced security middleware
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
const { initializeRoutes: initializeRecognitionRoutes } = require('./src/routes/recognition-routes');

// Create Express application
const app = express();

// Cookie parser for CSRF
app.use(cookieParser());

// Health check endpoint (before security middleware)
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'fairs-identity-service',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    uptime: process.uptime(),
    security: 'enhanced'
  });
});

// Apply enhanced security middleware components
// Security headers with CSP
app.use(securityHeaders({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline for some legacy features
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      'frame-ancestors': ["'none'"]
    }
  }
}));

// CSRF protection
app.use(csrfProtection({
  excludePaths: [
    '/health', 
    '/metrics',
    '/api/identity/lookup', // Public lookup endpoint
    '/api/identity/recognize', // Public recognition endpoint
    '/api/identity/device-fingerprint', // Public fingerprint endpoint
    '/api/addresses', // Allow address creation for checkout
    '/api/payment-methods' // Allow payment method creation for checkout
  ],
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict'
}));
app.use(injectCSRFToken);

// Advanced CORS
app.use(secureCORS({
  allowedOrigins: config.security?.corsOrigins || [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:3002', 
    'http://localhost:3003',
    'http://localhost:4000'
  ],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'x-csrf-token', 'x-signature', 'x-timestamp']
}));

// Progressive rate limiting
app.use(progressiveRateLimiter({
  anonymous: { windowMs: 60000, max: 60 }, // 60 requests per minute for anonymous
  authenticated: { windowMs: 60000, max: 300 } // 300 requests per minute for authenticated
}));

// Input sanitization
app.use(SecurityMiddleware.sanitizeInput());

// Body parsing middleware with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
  logger.info({
    message: 'Incoming request',
    method: req.method,
    url: req.url,
    userAgent: req.get('User-Agent'),
    ip: req.ip || req.connection.remoteAddress,
    requestId: req.id
  });
  next();
});

// Add request ID for tracing
app.use((req, res, next) => {
  req.id = Math.random().toString(36).substring(2, 15);
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Endpoint-specific rate limiting
app.use(endpointRateLimiter({
  '/api/identity/lookup': {
    windowMs: 60000,
    max: 30 // 30 lookups per minute
  },
  '/api/identity/recognize': {
    windowMs: 60000,
    max: 20 // 20 recognition attempts per minute
  },
  '/api/identity/verify': {
    windowMs: 300000,
    max: 10 // 10 verification attempts per 5 minutes
  },
  '/api/users': {
    windowMs: 3600000,
    max: 50 // 50 user operations per hour
  }
}));

// API routes
app.use('/api', identityRoutes);

// Enhanced Schema routes for multiple addresses and payment methods
app.use('/api', enhancedSchemaRoutes);

// User Rights API for data subject rights
app.use('/api/user-rights', userRightsRoutes);

// Data Transparency API for processing transparency
app.use('/api/data-transparency', dataTransparencyRoutes);

// Recognition and verification routes (initialized with dependencies)
let recognitionRoutes = null;

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    path: req.originalUrl,
    requestId: req.id
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  logger.error({
    message: 'Unhandled error',
    error: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    requestId: req.id
  });

  res.status(error.status || 500).json({
    success: false,
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message,
    requestId: req.id
  });
});

/**
 * Database Connection Verification and Service Initialization
 */
async function initializeServices() {
  try {
    // Initialize database connection
    const { dbConnection } = require('./src/database/db-connection');
    
    // Simple connection test
    const result = await dbConnection.query('SELECT 1 as connection_test');
    console.log('✅ Database connection verified - Simple test passed');
    
    // Optional: Try to list Enhanced Schema tables (non-blocking)
    try {
      const tableCheck = await dbConnection.query(`
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'identity_service' 
        AND table_name IN ('user_payment_methods', 'user_addresses')
        ORDER BY table_name
      `);
      
      console.log('🎯 Enhanced Schema tables found:', tableCheck.map(r => r.table_name));
    } catch (tableError) {
      console.log('⚠️ Could not check Enhanced Schema tables:', tableError.message);
    }

    // Initialize Redis connection
    const redisConnection = require('./src/database/redis-connection');
    await redisConnection.initialize();
    console.log('✅ Redis connection established');

    // Initialize recognition routes with database and Redis dependencies
    recognitionRoutes = initializeRecognitionRoutes(dbConnection, redisConnection);
    app.use('/api/identity', recognitionRoutes);
    console.log('✅ Recognition routes initialized');
    
    // Initialize API request signing for service-to-service communication
    if (process.env.API_SIGNING_SECRET) {
      app.use(apiRequestSigning({
        secret: process.env.API_SIGNING_SECRET,
        serviceName: 'identity-service',
        verifyIncoming: true,
        signOutgoing: true
      }));
      console.log('✅ API request signing initialized');
    }
    
  } catch (error) {
    console.error('❌ Service initialization failed:', error.message);
    console.log('⚠️ Continuing startup - some features may be unavailable');
  }
}

// Start server
const PORT = process.env.IDENTITY_SERVICE_PORT || process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

const server = app.listen(PORT, HOST, async () => {
  logger.info({
    message: 'Server started successfully',
    port: PORT,
    host: HOST,
    environment: process.env.NODE_ENV || 'development',
    security: 'Phase 0.4 Enhanced'
  });
  
  console.log(`🚀 Fairs Identity Service (Enhanced Security) running on http://${HOST}:${PORT}`);
  console.log(`📊 Health check available at http://${HOST}:${PORT}/health`);
  console.log(`🔒 Security Features: CSRF Protection, Rate Limiting, Security Headers`);
  
  // Initialize all services after server starts
  await initializeServices();
});

// ===========================================
// GRACEFUL SHUTDOWN HANDLING
// ===========================================

async function gracefulShutdown(signal) {
  logger.info(`🛑 Received ${signal}, shutting down gracefully`);
  
  // Stop accepting new requests
  server.close(() => {
    logger.info('✅ HTTP server closed');
    
    // Cleanup security monitor
    try {
      const securityMonitor = require('./src/middleware/security-monitoring');
      if (securityMonitor && securityMonitor.shutdown) {
        securityMonitor.shutdown();
        logger.info('✅ Security monitor cleaned up');
      }
    } catch (error) {
      logger.warn('⚠️ Security monitor cleanup failed:', error.message);
    }
    
    // Close database connections
    try {
      const { dbConnection } = require('./src/database/db-connection');
      if (dbConnection && dbConnection.end) {
        dbConnection.end();
        logger.info('✅ Database connections closed');
      }
    } catch (error) {
      logger.warn('⚠️ Database cleanup failed:', error.message);
    }

    // Close Redis connection
    try {
      const redisConnection = require('./src/database/redis-connection');
      if (redisConnection && redisConnection.disconnect) {
        redisConnection.disconnect().then(() => {
          logger.info('✅ Redis connection closed');
          process.exit(0);
        }).catch(error => {
          logger.warn('⚠️ Redis cleanup failed:', error.message);
          process.exit(0);
        });
        return;
      }
    } catch (error) {
      logger.warn('⚠️ Redis cleanup failed:', error.message);
    }
    
    process.exit(0);
  });

  // Force shutdown after 30 seconds
  setTimeout(() => {
    logger.error('❌ Forced shutdown after timeout');
    process.exit(1);
  }, 30000);
}

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('🚨 Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

module.exports = app;