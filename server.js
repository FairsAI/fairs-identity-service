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
 * Database Connection Verification
 * Ensures we're connected to the correct database and schema for Enhanced Schema
 */
async function verifyDatabaseConnection() {
  try {
    const { dbConnection } = require('./src/database/db-connection');
    
    const result = await dbConnection.query(`
      SELECT 
        current_database() as database_name,
        current_schema() as schema_name,
        current_user as user_name
    `);
    
    console.log('🔍 Database Connection Verification:', result[0]);
    
    // MUST return:
    // database_name: 'fairs_commerce'
    // schema_name: 'identity_service' 
    
    if (result[0].database_name !== 'fairs_commerce') {
      throw new Error(`❌ Wrong database! Connected to: ${result[0].database_name}, expected: fairs_commerce`);
    }
    
    if (result[0].schema_name !== 'identity_service') {
      console.log(`⚠️ Schema notice: Currently in '${result[0].schema_name}' schema, Enhanced Schema tables are in 'identity_service' schema`);
    }
    
    console.log('✅ Database verification passed - Connected to fairs_commerce database');
    
    // Verify Enhanced Schema tables exist
    const tableCheck = await dbConnection.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'identity_service' 
      AND table_name IN ('user_payment_methods', 'user_addresses')
      ORDER BY table_name
    `);
    
    console.log('🎯 Enhanced Schema tables found:', tableCheck.map(r => r.table_name));
    
    if (tableCheck.length !== 2) {
      console.log('⚠️ Warning: Not all Enhanced Schema tables found. Expected: user_addresses, user_payment_methods');
    }
    
  } catch (error) {
    console.error('❌ Database verification failed:', error.message);
    if (process.env.NODE_ENV !== 'development') {
      throw error; // Fail startup in production if database verification fails
    }
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
  
  // Verify database connection after server starts
  await verifyDatabaseConnection();
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