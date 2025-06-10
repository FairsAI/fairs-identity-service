/**
 * Database Connection Module
 * 
 * Provides database connection and query interface for the identity service
 */

const { Pool } = require('pg');
const config = require('../config');
const { logger } = require('../utils/logger');

class DatabaseConnection {
  constructor() {
    this.pool = null;
    this.isConnected = false;
  }

  /**
   * Initialize database connection
   */
  async initialize() {
    try {
      // For test environment with mocks, don't create real connection
      if (config.env === 'test' && config.database?.useMocks) {
        logger.info('Using mock database connection for testing');
        this.isConnected = true;
        return;
      }

      this.pool = new Pool({
        host: config.database.host,
        port: config.database.port,
        database: config.database.name,
        user: config.database.user,
        password: config.database.password,
        ssl: config.database.ssl,
        max: config.database.poolSize,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
        schema: config.database.schema || 'identity_service',
      });

      // Test the connection and set schema
      const client = await this.pool.connect();
      
      // Set search path to use the specific schema
      if (config.database.schema) {
        await client.query(`SET search_path TO ${config.database.schema}, public`);
      }
      
      await client.query('SELECT NOW()');
      client.release();

      this.isConnected = true;
      logger.info('Database connection established successfully', {
        host: config.database.host,
        database: config.database.name,
        poolSize: config.database.poolSize
      });

    } catch (error) {
      logger.error('Failed to initialize database connection', {
        error: error.message,
        host: config.database.host,
        database: config.database.name
      });
      
      // For development, we'll continue without database for now
      if (config.env === 'development') {
        logger.warn('Continuing without database connection in development mode');
        this.isConnected = false;
        return;
      }
      
      throw error;
    }
  }

  /**
   * Execute a query
   * @param {string} text - SQL query text
   * @param {Array} params - Query parameters
   * @returns {Promise<Array>} Query results
   */
  async query(text, params = []) {
    // Mock response for test environment
    if (config.env === 'test' && config.database?.useMocks) {
      logger.debug('Mock database query executed', { query: text.substring(0, 50) + '...' });
      return [{ id: 1, created_at: new Date(), fingerprint_hash: 'mock-hash' }];
    }

    // For development without database, return mock data
    if (config.env === 'development' && !this.isConnected) {
      logger.debug('Mock database query executed (no connection)', { query: text.substring(0, 50) + '...' });
      return [{ id: 1, created_at: new Date(), fingerprint_hash: 'mock-hash-dev' }];
    }

    if (!this.pool) {
      throw new Error('Database connection not initialized');
    }

    try {
      const start = Date.now();
      const result = await this.pool.query(text, params);
      const duration = Date.now() - start;

      logger.debug('Database query executed', {
        duration: `${duration}ms`,
        rows: result.rowCount,
        query: text.substring(0, 100) + (text.length > 100 ? '...' : '')
      });

      return result.rows;
    } catch (error) {
      logger.error('Database query failed', {
        error: error.message,
        query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
        params: params.length
      });
      throw error;
    }
  }

  /**
   * Get a client from the pool for transactions
   * @returns {Promise<Object>} Database client
   */
  async getClient() {
    if (!this.pool) {
      throw new Error('Database connection not initialized');
    }
    return await this.pool.connect();
  }

  /**
   * Close the database connection
   */
  async close() {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
      this.isConnected = false;
      logger.info('Database connection closed');
    }
  }

  /**
   * Check if database is connected
   * @returns {boolean} Connection status
   */
  isHealthy() {
    return this.isConnected;
  }
}

// Create singleton instance
const dbConnection = new DatabaseConnection();

// Initialize connection when module is loaded
dbConnection.initialize().catch(error => {
  logger.error('Failed to initialize database on module load', error);
});

module.exports = { dbConnection }; 