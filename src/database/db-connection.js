/**
 * Database Connection Module
 * 
 * Provides database connection and query interface for the identity service
 * SINGLE CONNECTION TO fairs_commerce DATABASE ONLY
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
   * Initialize database connection - EXPLICIT fairs_commerce connection
   */
  async initialize() {
    try {
      // For test environment with mocks, don't create real connection
      if (config.env === 'test' && config.database?.useMocks) {
        logger.info('Using mock database connection for testing');
        this.isConnected = true;
        return;
      }

      // EXPLICIT DATABASE CONFIGURATION - NO AMBIGUITY
      const dbConfig = {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5432', 10),
        database: 'fairs_commerce',              // HARDCODED - Enhanced Schema database
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD,
        ssl: process.env.DB_SSL === 'true',
        max: parseInt(process.env.DB_POOL_SIZE || '20', 10),
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
        statement_timeout: 10000,
        query_timeout: 10000,
        application_name: 'fairs_identity_service'
      };

      logger.info('🎯 ENHANCED SCHEMA: Connecting to fairs_commerce database', {
        host: dbConfig.host,
        database: dbConfig.database,
        port: dbConfig.port
      });

      this.pool = new Pool(dbConfig);

      // Simple connection test
      const client = await this.pool.connect();
      const testResult = await client.query('SELECT 1 as connection_test');
      client.release();

      this.isConnected = true;
      logger.info('🚀 ENHANCED SCHEMA: Database connection established successfully', {
        testResult: testResult.rows[0],
        connected: this.isConnected
      });

    } catch (error) {
      logger.error('❌ ENHANCED SCHEMA: Failed to initialize database connection', {
        error: error.message
      });
      
      // Continue without throwing - handle per request
      this.isConnected = false;
      logger.warn('⚠️ Service will continue - database connection will retry per request');
      
      // In development, retry connection after a delay
      if (config.env === 'development') {
        setTimeout(() => {
          logger.info('🔄 Retrying database connection...');
          this.initialize().catch(err => {
            logger.error('Database retry failed:', err.message);
          });
        }, 5000);
      }
    }
  }

  /**
   * Execute a query - ENHANCED SCHEMA ONLY
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

    // For development without database, try to reconnect before falling back to mock data
    if (config.env === 'development' && !this.isConnected) {
      logger.debug('Attempting to reconnect to database before query execution');
      try {
        await this.initialize();
        // If connection successful, proceed with the query
        if (this.isConnected && this.pool) {
          return this.query(text, params); // Retry the query with real connection
        }
      } catch (error) {
        logger.warn('Failed to reconnect, using mock data:', error.message);
      }
      
      logger.debug('Mock database query executed (no connection)', { query: text.substring(0, 50) + '...' });
      // Return mock user data that matches the expected schema
      if (text.includes('identity_service.users')) {
        return [{
          id: 1,
          email: 'bill@bill.com',
          first_name: 'Bill',
          last_name: 'User',
          phone: '8888888888',
          created_at: new Date(),
          updated_at: new Date()
        }];
      }
      return [{ id: 1, created_at: new Date(), fingerprint_hash: 'mock-hash-dev' }];
    }

    if (!this.pool) {
      throw new Error('Database connection not initialized');
    }

    try {
      const start = Date.now();
      
      // Get client - no schema path needed since we use explicit schema references
      const client = await this.pool.connect();
      
      const result = await client.query(text, params);
      client.release();
      
      const duration = Date.now() - start;

      logger.debug('🎯 ENHANCED SCHEMA: Database query executed', {
        duration: `${duration}ms`,
        rows: result.rowCount,
        query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
        params: params,
        fullQuery: text
      });

      return result.rows;
    } catch (error) {
      logger.error('❌ ENHANCED SCHEMA: Database query failed', {
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
    const client = await this.pool.connect();
    return client;
  }

  /**
   * Close the database connection
   */
  async close() {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
      this.isConnected = false;
      logger.info('🔌 ENHANCED SCHEMA: Database connection closed');
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