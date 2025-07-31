/**
 * Development Environment Configuration
 * 
 * Configuration values for development environment.
 * DO NOT include sensitive values directly in this file.
 * Use environment variables for sensitive information.
 */

module.exports = {
  // General configuration
  environment: 'development',
  apiBasePath: '/api',
  port: 3000,
  
  // Database configuration
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'fairs_dev',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD,
    ssl: false,
    max: 10, // Maximum number of clients in pool
    idleTimeoutMillis: 30000 // Time a client can be idle before being removed
  },
  
  // Tilled integration configuration
  tilled: {
    apiBaseUrl: 'https://sandbox-api.tilled.com',
    apiVersion: 'v1',
    merchantId: process.env.TILLED_MERCHANT_ID,
    accountId: process.env.TILLED_ACCOUNT_ID,
    secretKey: process.env.TILLED_SECRET_KEY,
    webhookSecret: process.env.TILLED_WEBHOOK_SECRET,
    sandbox: true,
    timeoutMs: 10000,
    retryConfig: {
      maxRetries: 3,
      baseDelayMs: 500
    },
    circuitBreakerConfig: {
      errorThresholdPercentage: 50,
      resetTimeout: 30000,
      timeout: 5000
    }
  },
  
  // Twilio integration configuration
  twilio: {
    accountSid: process.env.TWILIO_ACCOUNT_SID,
    authToken: process.env.TWILIO_AUTH_TOKEN,
    verifySid: process.env.TWILIO_VERIFY_SID,
    messagingServiceSid: process.env.TWILIO_MESSAGING_SERVICE_SID,
    fromNumber: process.env.TWILIO_FROM_NUMBER,
    sandbox: true,
    timeoutMs: 10000,
    retryConfig: {
      maxRetries: 3,
      baseDelayMs: 500
    },
    circuitBreakerConfig: {
      errorThresholdPercentage: 50,
      resetTimeout: 30000,
      timeout: 5000
    },
    verificationExpiration: {
      phone: 10, // minutes
      email: 15 // minutes
    },
    maxVerificationAttempts: 5
  },
  
  // Logging configuration
  logging: {
    level: process.env.LOG_LEVEL || 'debug',
    format: 'json',
    destination: 'console',
    redactFields: [
      'password',
      'jwtToken',
      'secret',
      'token',
      'accessToken',
      'refreshToken',
      'privateKey',
      'authorization',
      'cardNumber',
      'cvv'
    ]
  },
  
  // Monitoring configuration
  monitoring: {
    health: {
      enabled: true,
      path: '/health',
      intervalMs: 60000 // Check health every minute
    },
    metrics: {
      enabled: true,
      path: '/metrics'
    },
    statusPage: {
      enabled: false
    }
  },
  
  // Memory cache configuration
  cache: {
    enabled: true,
    ttl: 300, // Default TTL in seconds
    maxSize: 1000, // Maximum items in cache
    compressionEnabled: false
  },
  
  // Rate limiting configuration
  rateLimit: {
    enabled: true,
    windowMs: 60000, // 1 minute
    max: 100, // Max requests per windowMs
    standardHeaders: true,
    legacyHeaders: false
  },
  
  // CORS configuration
  cors: {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400 // 24 hours
  },
  
  // Security configuration
  security: {
    helmet: {
      contentSecurityPolicy: false, // Disable for development
      xssFilter: true
    },
    jwtToken: {
      enabled: false, // Disable for development
      headerName: 'Authorization'
    }
  }
}; 