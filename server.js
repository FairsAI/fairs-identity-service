/**
 * Fairs Identity Service Server
 * 
 * Main entry point for the identity service application
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { logger } = require('./src/utils/logger');
const config = require('./src/config');

// Import routes
const identityRoutes = require('./src/routes/identity-api');

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

// Start server
const PORT = process.env.IDENTITY_SERVICE_PORT || process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, HOST, () => {
  logger.info({
    message: 'Server started successfully',
    port: PORT,
    host: HOST,
    environment: process.env.NODE_ENV || 'development'
  });
  
  console.log(`🚀 Fairs Identity Service running on http://${HOST}:${PORT}`);
  console.log(`📊 Health check available at http://${HOST}:${PORT}/health`);
});

module.exports = app; 