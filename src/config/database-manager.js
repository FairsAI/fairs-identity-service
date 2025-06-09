/**
 * Multi-Database Connection Manager
 * Phase 3: Application Integration for Database Separation
 * 
 * Manages connections to separated databases:
 * - fairs_checkout: Checkout-specific tables
 * - fairs_ai: AI/analytics tables  
 * - sdkpayments: Shared infrastructure
 */

const { Pool } = require('pg');

class DatabaseManager {
  constructor() {
    this.connections = new Map();
    this.healthChecks = new Map();
    this.initializeConnections();
  }

  initializeConnections() {
    // Checkout Database Connection
    this.connections.set('checkout', new Pool({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432'),
      database: 'fairs_checkout',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'postgres',
      ssl: process.env.DB_SSL === 'true',
      max: 10, // Maximum connections in pool
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    }));

    // AI Database Connection
    this.connections.set('ai', new Pool({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432'),
      database: 'fairs_ai',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'postgres',
      ssl: process.env.DB_SSL === 'true',
      max: 8, // Smaller pool for AI queries
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    }));

    // Shared Database Connection
    this.connections.set('shared', new Pool({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432'),
      database: 'sdkpayments',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'postgres',
      ssl: process.env.DB_SSL === 'true',
      max: 15, // Larger pool for shared services
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    }));

    // Set up connection monitoring
    this.setupHealthChecks();
  }

  getConnection(type) {
    if (!this.connections.has(type)) {
      throw new Error(`Unknown database type: ${type}. Valid types: checkout, ai, shared`);
    }
    
    return this.connections.get(type);
  }

  async query(type, text, params = []) {
    const connection = this.getConnection(type);
    try {
      const start = Date.now();
      const result = await connection.query(text, params);
      const duration = Date.now() - start;
      
      // Log slow queries (>1000ms)
      if (duration > 1000) {
        console.warn(`Slow query detected on ${type} database:`, {
          query: text.substring(0, 100),
          duration,
          params: params.length
        });
      }
      
      return result.rows;
    } catch (error) {
      console.error(`Database query error on ${type}:`, {
        error: error.message,
        query: text.substring(0, 100),
        params: params.length
      });
      throw error;
    }
  }

  async getConnectionStats() {
    const stats = {};
    
    for (const [type, pool] of this.connections) {
      stats[type] = {
        totalCount: pool.totalCount,
        idleCount: pool.idleCount,
        waitingCount: pool.waitingCount,
        database: this.getDatabaseName(type)
      };
    }
    
    return stats;
  }

  getDatabaseName(type) {
    switch (type) {
      case 'checkout': return 'fairs_checkout';
      case 'ai': return 'fairs_ai';
      case 'shared': return 'sdkpayments';
      default: return 'unknown';
    }
  }

  setupHealthChecks() {
    // Health check every 30 seconds
    const interval = setInterval(async () => {
      await this.performHealthChecks();
    }, 30000);

    // Cleanup on process exit
    process.on('SIGINT', () => {
      clearInterval(interval);
      this.closeAllConnections();
    });
  }

  async performHealthChecks() {
    for (const [type, pool] of this.connections) {
      try {
        const start = Date.now();
        await pool.query('SELECT 1');
        const duration = Date.now() - start;
        
        this.healthChecks.set(type, {
          status: 'healthy',
          lastCheck: new Date(),
          responseTime: duration
        });
      } catch (error) {
        console.error(`Health check failed for ${type} database:`, error.message);
        this.healthChecks.set(type, {
          status: 'unhealthy',
          lastCheck: new Date(),
          error: error.message
        });
      }
    }
  }

  getHealthStatus() {
    const health = {};
    for (const [type, status] of this.healthChecks) {
      health[type] = status;
    }
    return health;
  }

  async closeAllConnections() {
    console.log('Closing database connections...');
    for (const [type, pool] of this.connections) {
      try {
        await pool.end();
        console.log(`Closed ${type} database connection`);
      } catch (error) {
        console.error(`Error closing ${type} connection:`, error.message);
      }
    }
  }

  // Emergency fallback to single database
  async enableEmergencyMode() {
    console.warn('EMERGENCY MODE: Falling back to shared database for all connections');
    
    const emergencyPool = new Pool({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432'),
      database: 'sdkpayments',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'postgres',
      ssl: process.env.DB_SSL === 'true',
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });

    // Replace all connections with emergency pool
    this.connections.set('checkout', emergencyPool);
    this.connections.set('ai', emergencyPool);
    this.connections.set('shared', emergencyPool);

    return emergencyPool;
  }

  // Cross-database transaction support (future enhancement)
  async executeTransaction(operations) {
    // For Phase 3, we'll implement simple sequential operations
    // Future enhancement: implement distributed transactions
    const results = [];
    
    for (const operation of operations) {
      try {
        const result = await this.query(operation.database, operation.query, operation.params);
        results.push({ success: true, result });
      } catch (error) {
        results.push({ success: false, error: error.message });
        // For now, continue with other operations
        // Future: implement rollback logic
      }
    }
    
    return results;
  }
}

// Singleton instance
let instance = null;

function getDatabaseManager() {
  if (!instance) {
    instance = new DatabaseManager();
  }
  return instance;
}

module.exports = {
  DatabaseManager,
  getDatabaseManager
}; 