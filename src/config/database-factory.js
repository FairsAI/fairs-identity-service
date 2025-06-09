/**
 * Database Factory for Phase 3 Database Separation
 * Production-ready multi-database connection manager
 */

const { Pool } = require('pg');

class DatabaseFactory {
  constructor() {
    this.connections = new Map();
    this.healthChecks = new Map();
    this.monitoring = {
      slowQueryThreshold: parseInt(process.env.DB_SLOW_QUERY_THRESHOLD || '1000'),
      enableMonitoring: process.env.ENABLE_DB_MONITORING === 'true'
    };
    this.init();
  }

  init() {
    const configs = {
      checkout: {
        host: process.env.CHECKOUT_DB_HOST || process.env.DB_HOST || 'localhost',
        database: process.env.CHECKOUT_DB_NAME || 'fairs_checkout',
        user: process.env.CHECKOUT_DB_USER || process.env.DB_USER || 'postgres',
        password: process.env.CHECKOUT_DB_PASSWORD || process.env.DB_PASSWORD || 'postgres',
        port: parseInt(process.env.DB_PORT || '5432'),
        max: parseInt(process.env.DB_POOL_MAX_CHECKOUT || '20'),
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
      },
      
      ai: {
        host: process.env.AI_DB_HOST || process.env.DB_HOST || 'localhost',
        database: process.env.AI_DB_NAME || 'fairs_ai',
        user: process.env.AI_DB_USER || process.env.DB_USER || 'postgres',
        password: process.env.AI_DB_PASSWORD || process.env.DB_PASSWORD || 'postgres',
        port: parseInt(process.env.DB_PORT || '5432'),
        max: parseInt(process.env.DB_POOL_MAX_AI || '10'),
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
      },
      
      shared: {
        host: process.env.SHARED_DB_HOST || process.env.DB_HOST || 'localhost',
        database: process.env.SHARED_DB_NAME || 'sdkpayments',
        user: process.env.SHARED_DB_USER || process.env.DB_USER || 'postgres',
        password: process.env.SHARED_DB_PASSWORD || process.env.DB_PASSWORD || 'postgres',
        port: parseInt(process.env.DB_PORT || '5432'),
        max: parseInt(process.env.DB_POOL_MAX_SHARED || '15'),
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
      }
    };

    console.log('🔧 Initializing database connections...');
    
    for (const [name, config] of Object.entries(configs)) {
      try {
        const pool = new Pool(config);
        
        // Add error handling
        pool.on('error', (err) => {
          console.error(`Database pool error (${name}):`, err);
          this.handlePoolError(name, err);
        });

        pool.on('connect', () => {
          if (this.monitoring.enableMonitoring) {
            console.log(`✅ New client connected to ${name} database`);
          }
        });

        pool.on('remove', () => {
          if (this.monitoring.enableMonitoring) {
            console.log(`🔌 Client removed from ${name} database pool`);
          }
        });

        this.connections.set(name, pool);
        this.healthChecks.set(name, this.createHealthCheck(pool, name));
        
        console.log(`✅ ${name} database pool initialized (max: ${config.max})`);
      } catch (error) {
        console.error(`❌ Failed to initialize ${name} database:`, error);
        throw error;
      }
    }

    // Start health monitoring
    this.startHealthMonitoring();
    
    // Graceful shutdown
    this.setupGracefulShutdown();
    
    console.log('🎉 Database factory initialization complete!');
  }

  getConnection(type) {
    const connection = this.connections.get(type);
    if (!connection) {
      throw new Error(`Unknown database type: ${type}. Available: ${Array.from(this.connections.keys()).join(', ')}`);
    }
    return connection;
  }

  async query(type, sql, params = []) {
    const startTime = Date.now();
    const pool = this.getConnection(type);
    
    try {
      const result = await pool.query(sql, params);
      const duration = Date.now() - startTime;
      
      // Monitor slow queries
      if (this.monitoring.enableMonitoring && duration > this.monitoring.slowQueryThreshold) {
        console.warn(`🐌 Slow query detected on ${type} database:`, {
          duration: `${duration}ms`,
          query: sql.substring(0, 100) + (sql.length > 100 ? '...' : ''),
          paramCount: params.length
        });
      }
      
      return result;
    } catch (error) {
      console.error(`❌ Database query error on ${type}:`, {
        error: error.message,
        query: sql.substring(0, 100) + (sql.length > 100 ? '...' : ''),
        paramCount: params.length
      });
      throw error;
    }
  }

  createHealthCheck(pool, name) {
    return async () => {
      try {
        const startTime = Date.now();
        const client = await pool.connect();
        const result = await client.query('SELECT NOW() as timestamp, version() as version');
        client.release();
        const responseTime = Date.now() - startTime;
        
        return {
          status: 'healthy',
          name,
          responseTime,
          timestamp: new Date().toISOString(),
          version: result.rows[0].version.split(' ')[0], // Extract PostgreSQL version
          poolInfo: {
            totalCount: pool.totalCount,
            idleCount: pool.idleCount,
            waitingCount: pool.waitingCount
          }
        };
      } catch (error) {
        return {
          status: 'unhealthy',
          name,
          error: error.message,
          timestamp: new Date().toISOString()
        };
      }
    };
  }

  async checkAllHealth() {
    const results = {};
    const promises = [];
    
    for (const [name, healthCheck] of this.healthChecks) {
      promises.push(
        healthCheck().then(result => {
          results[name] = result;
        }).catch(error => {
          results[name] = {
            status: 'error',
            name,
            error: error.message,
            timestamp: new Date().toISOString()
          };
        })
      );
    }
    
    await Promise.all(promises);
    return results;
  }

  getConnectionStats() {
    const stats = {};
    for (const [name, pool] of this.connections) {
      stats[name] = {
        database: this.getDatabaseName(name),
        totalCount: pool.totalCount,
        idleCount: pool.idleCount,
        waitingCount: pool.waitingCount,
        maxConnections: pool.options.max
      };
    }
    return stats;
  }

  getDatabaseName(type) {
    const pool = this.connections.get(type);
    return pool?.options?.database || 'unknown';
  }

  startHealthMonitoring() {
    if (!this.monitoring.enableMonitoring) return;
    
    // Health check every 60 seconds
    this.healthInterval = setInterval(async () => {
      try {
        const health = await this.checkAllHealth();
        const unhealthyDbs = Object.values(health).filter(h => h.status !== 'healthy');
        
        if (unhealthyDbs.length > 0) {
          console.warn('⚠️  Unhealthy databases detected:', 
            unhealthyDbs.map(db => `${db.name}: ${db.error || db.status}`).join(', ')
          );
        }
      } catch (error) {
        console.error('❌ Health monitoring error:', error);
      }
    }, 60000);
  }

  handlePoolError(name, error) {
    console.error(`🚨 Critical pool error for ${name}:`, error);
    
    // In production, you might want to:
    // - Send alerts
    // - Attempt reconnection
    // - Failover to backup database
  }

  setupGracefulShutdown() {
    const shutdown = async (signal) => {
      console.log(`\n🛑 Received ${signal}, closing database connections...`);
      
      if (this.healthInterval) {
        clearInterval(this.healthInterval);
      }
      
      await this.closeAll();
      process.exit(0);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
  }

  async closeAll() {
    console.log('🔒 Closing all database connections...');
    const closePromises = [];
    
    for (const [name, pool] of this.connections) {
      closePromises.push(
        pool.end().then(() => {
          console.log(`✅ Closed ${name} database connection`);
        }).catch((error) => {
          console.error(`❌ Error closing ${name} connection:`, error);
        })
      );
    }
    
    await Promise.all(closePromises);
    this.connections.clear();
    this.healthChecks.clear();
    console.log('🎉 All database connections closed');
  }

  // Emergency fallback mode
  async enableEmergencyMode() {
    console.warn('🚨 EMERGENCY MODE: Falling back to shared database for all connections');
    
    try {
      const emergencyConfig = {
        host: process.env.DB_HOST || 'localhost',
        database: 'sdkpayments',
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || 'postgres',
        port: parseInt(process.env.DB_PORT || '5432'),
        max: 30, // Larger pool for emergency mode
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
      };

      const emergencyPool = new Pool(emergencyConfig);
      
      // Test emergency connection
      await emergencyPool.query('SELECT 1');
      
      // Replace all connections with emergency pool
      for (const type of ['checkout', 'ai', 'shared']) {
        this.connections.set(type, emergencyPool);
      }
      
      console.log('✅ Emergency mode activated - all connections use shared database');
      return true;
    } catch (error) {
      console.error('❌ Failed to enable emergency mode:', error);
      throw error;
    }
  }
}

// Singleton instance
const databaseFactory = new DatabaseFactory();

module.exports = databaseFactory; 