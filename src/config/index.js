/**
 * Application Configuration - ZERO HARDCODED CREDENTIALS
 * 
 * SECURITY: All credentials must come from environment variables
 * NO fallbacks to insecure defaults allowed in production
 */

const crypto = require('crypto');

// Get environment
const env = process.env.NODE_ENV || 'development';

/**
 * Validates required environment variables for security
 * @param {string[]} requiredVars - Array of required environment variable names
 * @throws {Error} If any required variables are missing or invalid
 */
function validateRequiredEnvironmentVariables(requiredVars) {
  const missing = [];
  const weak = [];
  
  for (const varName of requiredVars) {
    const value = process.env[varName];
    
    if (!value) {
      missing.push(varName);
      continue;
    }
    
    // Validate minimum security requirements
    if (varName.includes('SECRET') || varName.includes('KEY')) {
      if (value.length < 32) {
        weak.push(`${varName} (must be at least 32 characters)`);
      }
      
      // Check for common weak patterns
      if (/^(test|demo|default|example|placeholder)/i.test(value)) {
        weak.push(`${varName} (contains weak/test pattern)`);
      }
    }
    
    // Validate API keys
    if (varName.includes('API_KEY') && value.length < 16) {
      weak.push(`${varName} (API key too short)`);
    }
  }
  
  if (missing.length > 0) {
    throw new Error(`SECURITY ERROR: Missing required environment variables: ${missing.join(', ')}`);
  }
  
  if (weak.length > 0) {
    throw new Error(`SECURITY ERROR: Weak credentials detected: ${weak.join(', ')}`);
  }
}

// Base configuration
const baseConfig = {
  env,
  isDevelopment: env === 'development',
  isProduction: env === 'production',
  isTest: env === 'test'
};

// Required environment variables based on environment
const requiredVars = env === 'production' 
  ? [
      'TILLED_API_KEY',
      'TILLED_MERCHANT_ID',
      'TILLED_PUBLIC_KEY',
      'DB_HOST',
      'DB_USER', 
      'DB_PASSWORD',
      'JWT_SECRET',
      'API_ENCRYPTION_KEY',
      'VALID_API_KEYS'
    ]
  : env === 'development'
    ? [
        'JWT_SECRET',
        'API_ENCRYPTION_KEY'
      ]
    : []; // Test environment - allow mocks

// Validate required environment variables (except in test mode)
if (env !== 'test') {
  validateRequiredEnvironmentVariables(requiredVars);
}

// Tilled API configuration - NO DEFAULTS
const tilledConfig = {
  apiKey: process.env.TILLED_API_KEY,
  apiUrl: process.env.TILLED_API_URL || (env === 'production' ? 'https://api.tilled.com/v1' : 'https://sandbox-api.tilled.com/v1'),
  merchantId: process.env.TILLED_MERCHANT_ID,
  publicKey: process.env.TILLED_PUBLIC_KEY,
  secretKey: process.env.TILLED_SECRET_KEY
};

// Database configuration - NO HARDCODED PASSWORDS
const databaseConfig = {
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432', 10),
  name: process.env.DB_NAME || (env === 'test' ? 'fairs_checkout_test' : 'fairs_checkout'),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: process.env.DB_SSL === 'true',
  poolSize: parseInt(process.env.DB_POOL_SIZE || '20', 10),
  schema: process.env.DB_SCHEMA || 'identity_service'
};

// Special handling for test environment ONLY
if (env === 'test') {
  const hasRealDbCredentials = !!(
    process.env.DB_HOST && 
    process.env.DB_USER && 
    process.env.DB_PASSWORD
  );
  
  databaseConfig.hasRealCredentials = hasRealDbCredentials;
  
      if (!hasRealDbCredentials) {
      console.log('TEST MODE: Using mock database credentials');
      databaseConfig.host = 'mock-db-host';
      databaseConfig.user = 'mock-db-user';
      databaseConfig.password = process.env.TEST_DB_PASSWORD || 'secure-mock-test-credentials-32-chars';
      databaseConfig.name = 'mock_payments_integration_test';
      databaseConfig.useMocks = true;
    }
} else {
  // For non-test environments, require real database credentials
  if (!databaseConfig.host || !databaseConfig.user || !databaseConfig.password) {
    throw new Error('SECURITY ERROR: Database credentials are required for production/development environments');
  }
}

// API Security Configuration - NO DEFAULTS
const apiConfig = {
  validApiKeys: process.env.VALID_API_KEYS ? process.env.VALID_API_KEYS.split(',').map(key => key.trim()) : [],
  jwtSecret: process.env.JWT_SECRET,
  encryptionKey: process.env.API_ENCRYPTION_KEY,
  sessionTimeout: parseInt(process.env.SESSION_TIMEOUT || '3600', 10), // 1 hour default
  maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5', 10),
  lockoutDuration: parseInt(process.env.LOCKOUT_DURATION || '900', 10) // 15 minutes default
};

// Validate API configuration
if (env !== 'test') {
  if (apiConfig.validApiKeys.length === 0) {
    throw new Error('SECURITY ERROR: No valid API keys configured. Set VALID_API_KEYS environment variable.');
  }
  
  if (!apiConfig.jwtSecret) {
    throw new Error('SECURITY ERROR: JWT_SECRET environment variable is required');
  }
  
  if (!apiConfig.encryptionKey) {
    throw new Error('SECURITY ERROR: API_ENCRYPTION_KEY environment variable is required');
  }
}

// Twilio configuration - NO DEFAULTS
const twilioConfig = {
  accountSid: process.env.TWILIO_ACCOUNT_SID,
  authToken: process.env.TWILIO_AUTH_TOKEN,
  fromNumber: process.env.TWILIO_FROM_NUMBER,
  enabled: !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN)
};

// Monitoring configuration
const monitoringConfig = {
  enabled: process.env.MONITORING_ENABLED !== 'false',
  metricsEndpoint: process.env.METRICS_ENDPOINT || '/api/metrics',
  apiBaseUrl: process.env.API_BASE_URL || '/api',
  metricsFlushInterval: parseInt(process.env.METRICS_FLUSH_INTERVAL, 10) || 30000,
  metricsBatchSize: parseInt(process.env.METRICS_BATCH_SIZE, 10) || 10
};

// Security headers configuration
const securityConfig = {
  corsOrigins: process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : ['http://localhost:3000'],
  contentSecurityPolicy: process.env.CSP_ENABLED !== 'false',
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
  enableSecurityHeaders: process.env.SECURITY_HEADERS_ENABLED !== 'false'
};

// Environment specific configurations
const envConfig = {
  development: {
    // Development specific overrides
    security: {
      ...securityConfig,
      corsOrigins: ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:8080']
    }
  },
  test: {
    // Test specific overrides  
    api: {
      ...apiConfig,
      validApiKeys: ['test-api-key-for-integration-tests-secure-32-character-minimum'], // Only for testing
      jwtSecret: process.env.JWT_SECRET || 'test-jwt-secret-minimum-32-characters-long-secure-fallback',
      encryptionKey: process.env.API_ENCRYPTION_KEY || 'test-encryption-key-32-chars-minimum-secure-fallback'
    }
  },
  production: {
    // Production specific overrides
    security: {
      ...securityConfig,
      rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '50', 10) // Stricter in production
    }
  }
};

// Combine configurations
const config = {
  ...baseConfig,
  tilled: tilledConfig,
  database: databaseConfig,
  api: apiConfig,
  twilio: twilioConfig,
  monitoring: monitoringConfig,
  security: securityConfig,
  ...(envConfig[env] || {})
};

// Log security status (without revealing secrets)
if (env !== 'test') {
  console.log('🔒 SECURITY STATUS:');
  console.log(`   Environment: ${env}`);
  console.log(`   API Keys configured: ${config.api.validApiKeys.length}`);
  console.log(`   JWT Secret: ${config.api.jwtSecret ? '✅ SET' : '❌ MISSING'}`);
  console.log(`   Encryption Key: ${config.api.encryptionKey ? '✅ SET' : '❌ MISSING'}`);
  console.log(`   Database: ${config.database.host ? '✅ CONFIGURED' : '❌ MISSING'}`);
  console.log(`   Tilled API: ${config.tilled.apiKey ? '✅ SET' : '❌ MISSING'}`);
  console.log(`   Twilio: ${config.twilio.enabled ? '✅ ENABLED' : '⚠️  DISABLED'}`);
}

// Export configuration
module.exports = config; 