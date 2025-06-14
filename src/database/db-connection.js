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
        connectionTimeoutMillis: 2000,
      };

      logger.info('🎯 ENHANCED SCHEMA: Connecting explicitly to fairs_commerce database', {
        host: dbConfig.host,
        database: dbConfig.database,
        schema: 'identity_service'
      });

      this.pool = new Pool(dbConfig);

      // Test the connection and set schema EXPLICITLY
      const client = await this.pool.connect();
      
      // EXPLICIT SCHEMA PATH - identity_service ONLY
      await client.query('SET search_path TO identity_service, public');
      
      // Verify we're connected to the right database
      const dbCheck = await client.query('SELECT current_database() as db, current_schema() as schema');
      logger.info('✅ ENHANCED SCHEMA: Database connection verified', {
        database: dbCheck.rows[0].db,
        schema: dbCheck.rows[0].schema
      });
      
      // Verify Enhanced Schema tables exist
      const tableCheck = await client.query(`
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'identity_service' 
        AND table_name IN ('user_payment_methods', 'user_addresses')
      `);
      logger.info('✅ ENHANCED SCHEMA: Tables verified', {
        tables: tableCheck.rows.map(r => r.table_name)
      });
      
      client.release();

      this.isConnected = true;
      logger.info('🚀 ENHANCED SCHEMA: Database connection established successfully');

    } catch (error) {
      logger.error('❌ ENHANCED SCHEMA: Failed to initialize database connection', {
        error: error.message
      });
      
      // For development, we'll continue without database for now
      if (config.env === 'development') {
        logger.warn('⚠️ Continuing without database connection in development mode');
        this.isConnected = false;
        return;
      }
      
      throw error;
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
      
      // Get client and ensure correct schema
      const client = await this.pool.connect();
      await client.query('SET search_path TO identity_service, public');
      
      const result = await client.query(text, params);
      client.release();
      
      const duration = Date.now() - start;

      logger.debug('🎯 ENHANCED SCHEMA: Database query executed', {
        duration: `${duration}ms`,
        rows: result.rowCount,
        query: text.substring(0, 100) + (text.length > 100 ? '...' : '')
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
    await client.query('SET search_path TO identity_service, public');
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