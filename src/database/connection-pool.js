/**
 * IDENTITY SERVICE - Database Connection Pool
 * 
 * ✅ MICROSERVICES COMPLIANT: Service-specific database management
 * ✅ OPTIMIZED: Connection pooling with health monitoring
 * ✅ SECURE: Parameterized queries and injection prevention
 * 
 * Manages database connections specifically for the Identity Service
 */

const { Pool } = require('pg');
const { createQueryLogData } = require('@fairs/shared-utils').database;

/**
 * Identity Service Database Pool Configuration
 */
const poolConfig = {
  host: process.env.IDENTITY_DB_HOST || 'localhost',
  port: process.env.IDENTITY_DB_PORT || 5432,
  database: process.env.IDENTITY_DB_NAME || 'fairs_identity',
  user: process.env.IDENTITY_DB_USER || 'identity_user',
  password: process.env.IDENTITY_DB_PASSWORD || 'identity_pass',
  
  // Connection pool settings
  min: parseInt(process.env.IDENTITY_DB_POOL_MIN || '2'),
  max: parseInt(process.env.IDENTITY_DB_POOL_MAX || '10'),
  idleTimeoutMillis: parseInt(process.env.IDENTITY_DB_IDLE_TIMEOUT || '30000'),
  connectionTimeoutMillis: parseInt(process.env.IDENTITY_DB_CONNECTION_TIMEOUT || '5000'),
  
  // Performance settings
  statement_timeout: parseInt(process.env.IDENTITY_DB_STATEMENT_TIMEOUT || '30000'),
  query_timeout: parseInt(process.env.IDENTITY_DB_QUERY_TIMEOUT || '15000'),
  
  // SSL settings
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : false
};

/**
 * Create database pool instance
 */
const pool = new Pool(poolConfig);

/**
 * Query cache for improved performance
 * TTL-based cache for frequently accessed data
 */
const queryCache = new Map();
const CACHE_TTL = parseInt(process.env.IDENTITY_CACHE_TTL || '300000'); // 5 minutes
const MAX_CACHE_SIZE = parseInt(process.env.IDENTITY_MAX_CACHE_SIZE || '1000');

/**
 * Performance monitoring
 */
const performanceMetrics = {
  totalQueries: 0,
  slowQueries: 0,
  cacheHits: 0,
  cacheMisses: 0,
  errorCount: 0,
  averageQueryTime: 0
};

/**
 * ✅ OPTIMIZED: Execute query with connection pooling and caching
 * 
 * @param {string} query - SQL query string
 * @param {Array} params - Query parameters
 * @param {Object} options - Query options
 * @returns {Promise} - Query result
 */
async function query(queryText, params = [], options = {}) {
  const startTime = Date.now();
  const { 
    useCache = false,
    cacheKey = null,
    timeout = poolConfig.query_timeout,
    operation = 'query',
    tableName = 'unknown'
  } = options;
  
  performanceMetrics.totalQueries++;
  
  try {
    // Check cache first if enabled
    if (useCache && cacheKey) {
      const cached = getCachedResult(cacheKey);
      if (cached) {
        performanceMetrics.cacheHits++;
        return cached;
      }
      performanceMetrics.cacheMisses++;
    }
    
    // Execute query with timeout
    const client = await pool.connect();
    let result;
    
    try {
      // Set statement timeout for this query
      if (timeout !== poolConfig.query_timeout) {
        await client.query(`SET statement_timeout = ${timeout}`);
      }
      
      result = await client.query(queryText, params);
      
    } finally {
      client.release();
    }
    
    const duration = Date.now() - startTime;
    
    // Update performance metrics
    performanceMetrics.averageQueryTime = 
      (performanceMetrics.averageQueryTime * (performanceMetrics.totalQueries - 1) + duration) / 
      performanceMetrics.totalQueries;
    
    if (duration > 1000) {
      performanceMetrics.slowQueries++;
      console.warn('Slow query detected:', createQueryLogData(queryText, params, startTime, { operation, tableName }));
    }
    
    // Cache result if requested and successful
    if (useCache && cacheKey && result.rows) {
      setCachedResult(cacheKey, result);
    }
    
    return result;
    
  } catch (error) {
    performanceMetrics.errorCount++;
    
    const duration = Date.now() - startTime;
    console.error('Database query error:', {
      error: error.message,
      query: queryText.substring(0, 200),
      params: params?.length || 0,
      duration,
      operation,
      tableName
    });
    
    throw error;
  }
}

/**
 * ✅ SPECIALIZED: Identity-specific query methods
 */

/**
 * Find user by ID with caching
 */
async function findUserById(userId) {
  const cacheKey = `user:${userId}`;
  
  return query(
    'SELECT id, email, phone_number, created_at, updated_at, status FROM users WHERE id = $1',
    [userId],
    { 
      useCache: true, 
      cacheKey, 
      operation: 'SELECT',
      tableName: 'users'
    }
  );
}

/**
 * Find user by email with caching
 */
async function findUserByEmail(email) {
  const cacheKey = `user:email:${email}`;
  
  return query(
    'SELECT id, email, phone_number, created_at, updated_at, status FROM users WHERE email = $1',
    [email],
    { 
      useCache: true, 
      cacheKey, 
      operation: 'SELECT',
      tableName: 'users'
    }
  );
}

/**
 * Find user by phone with caching
 */
async function findUserByPhone(phoneNumber) {
  const cacheKey = `user:phone:${phoneNumber}`;
  
  return query(
    'SELECT id, email, phone_number, created_at, updated_at, status FROM users WHERE phone_number = $1',
    [phoneNumber],
    { 
      useCache: true, 
      cacheKey, 
      operation: 'SELECT',
      tableName: 'users'
    }
  );
}

/**
 * Create new user
 */
async function createUser(userData) {
  const { email, phoneNumber, hashedPassword } = userData;
  
  const result = await query(
    `INSERT INTO users (email, phone_number, password_hash, created_at, updated_at) 
     VALUES ($1, $2, $3, NOW(), NOW()) 
     RETURNING id, email, phone_number, created_at, updated_at, status`,
    [email, phoneNumber, hashedPassword],
    { 
      operation: 'INSERT',
      tableName: 'users'
    }
  );
  
  // Invalidate related cache entries
  if (result.rows.length > 0) {
    const user = result.rows[0];
    invalidateUserCache(user.id, user.email, user.phone_number);
  }
  
  return result;
}

/**
 * Update user data
 */
async function updateUser(userId, updateData) {
  const { email, phoneNumber, status } = updateData;
  const updates = [];
  const params = [];
  let paramIndex = 1;
  
  if (email !== undefined) {
    updates.push(`email = $${paramIndex++}`);
    params.push(email);
  }
  
  if (phoneNumber !== undefined) {
    updates.push(`phone_number = $${paramIndex++}`);
    params.push(phoneNumber);
  }
  
  if (status !== undefined) {
    updates.push(`status = $${paramIndex++}`);
    params.push(status);
  }
  
  updates.push('updated_at = NOW()');
  params.push(userId);
  
  const result = await query(
    `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex} 
     RETURNING id, email, phone_number, created_at, updated_at, status`,
    params,
    { 
      operation: 'UPDATE',
      tableName: 'users'
    }
  );
  
  // Invalidate cache
  if (result.rows.length > 0) {
    const user = result.rows[0];
    invalidateUserCache(user.id, user.email, user.phone_number);
  }
  
  return result;
}

/**
 * ✅ CACHE MANAGEMENT
 */

/**
 * Get cached result if valid
 */
function getCachedResult(key) {
  const cached = queryCache.get(key);
  if (!cached) return null;
  
  if (Date.now() - cached.timestamp > CACHE_TTL) {
    queryCache.delete(key);
    return null;
  }
  
  return cached.data;
}

/**
 * Set cached result with TTL
 */
function setCachedResult(key, data) {
  // Prevent cache from growing too large
  if (queryCache.size >= MAX_CACHE_SIZE) {
    // Remove oldest entries (simple LRU)
    const firstKey = queryCache.keys().next().value;
    queryCache.delete(firstKey);
  }
  
  queryCache.set(key, {
    data,
    timestamp: Date.now()
  });
}

/**
 * Invalidate user-related cache entries
 */
function invalidateUserCache(userId, email, phoneNumber) {
  const keysToDelete = [
    `user:${userId}`,
    `user:email:${email}`,
    `user:phone:${phoneNumber}`
  ];
  
  for (const key of keysToDelete) {
    queryCache.delete(key);
  }
}

/**
 * Clear all cache entries
 */
function clearCache() {
  queryCache.clear();
}

/**
 * ✅ HEALTH MONITORING
 */

/**
 * Check database connection health
 */
async function healthCheck() {
  try {
    const result = await query('SELECT 1 as health_check', [], { timeout: 5000 });
    return {
      healthy: true,
      response_time: result.duration || 0,
      pool_total: pool.totalCount,
      pool_idle: pool.idleCount,
      pool_waiting: pool.waitingCount
    };
  } catch (error) {
    return {
      healthy: false,
      error: error.message,
      pool_total: pool.totalCount,
      pool_idle: pool.idleCount,
      pool_waiting: pool.waitingCount
    };
  }
}

/**
 * Get performance metrics
 */
function getPerformanceMetrics() {
  return {
    ...performanceMetrics,
    cacheSize: queryCache.size,
    poolStats: {
      total: pool.totalCount,
      idle: pool.idleCount,
      waiting: pool.waitingCount
    }
  };
}

/**
 * ✅ GRACEFUL SHUTDOWN
 */

/**
 * Close all database connections
 */
async function close() {
  try {
    clearCache();
    await pool.end();
    console.log('✅ Identity service database connections closed');
  } catch (error) {
    console.error('❌ Error closing identity service database connections:', error);
    throw error;
  }
}

// Handle process termination
process.on('SIGTERM', close);
process.on('SIGINT', close);

module.exports = {
  // Core query method
  query,
  
  // Identity-specific methods
  findUserById,
  findUserByEmail,
  findUserByPhone,
  createUser,
  updateUser,
  
  // Cache management
  clearCache,
  invalidateUserCache,
  
  // Health and monitoring
  healthCheck,
  getPerformanceMetrics,
  close,
  
  // Direct pool access for advanced use cases
  pool
}; 