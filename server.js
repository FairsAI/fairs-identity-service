/**
 * Fairs Identity Service Server
 * 
 * Main entry point for the identity service application
 */

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { logger } = require('./src/utils/logger');
const config = require('./src/config');

// Import routes
const identityRoutes = require('./src/routes/identity-api');
const enhancedSchemaRoutes = require('./src/routes/enhanced-schema-api');
// const privacyRoutes = require('./src/routes/privacy');
const userRightsRoutes = require('./src/routes/user-rights-api');
const dataTransparencyRoutes = require('./src/routes/data-transparency-api');
const { initializeRoutes: initializeRecognitionRoutes } = require('./src/routes/recognition-routes');

// Create Express application
const app = express();

// Security middleware
app.use(helmet());

// CORS configuration
app.use(cors({
  origin: config.security?.corsOrigins || ['http://localhost:3000'],
  credentials: true
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

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

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'fairs-identity-service',
    version: '1.0.0'
  });
});

// API routes
app.use('/api', identityRoutes);

// Enhanced Schema routes for multiple addresses and payment methods
app.use('/api', enhancedSchemaRoutes);

// Privacy routes for CCPA/PIPEDA compliance
// app.use("/api/privacy", privacyRoutes););

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
    path: req.originalUrl
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  logger.error({
    message: 'Unhandled error',
    error: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method
  });

  res.status(error.status || 500).json({
    success: false,
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message
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
    environment: process.env.NODE_ENV || 'development'
  });
  
  console.log(`🚀 Fairs Identity Service running on http://${HOST}:${PORT}`);
  console.log(`📊 Health check available at http://${HOST}:${PORT}/health`);
  
  // Initialize all services after server starts
  await initializeServices();
});

// ===========================================
// GRACEFUL SHUTDOWN HANDLING
// ===========================================

function gracefulShutdown(signal) {
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
      if (redisConnection) {
        await redisConnection.disconnect();
        logger.info('✅ Redis connection closed');
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