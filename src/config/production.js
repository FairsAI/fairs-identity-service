/**
 * Production Environment Configuration
 * 
 * Configuration values for production environment.
 * DO NOT include sensitive values directly in this file.
 * Use environment variables for sensitive information.
 */

module.exports = {
  // General configuration
  environment: 'production',
  apiBasePath: '/api',
  port: process.env.PORT || 3000,
  
  // Database configuration
  database: {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    ssl: {
      rejectUnauthorized: true,
      ca: process.env.DB_SSL_CA
    },
    max: 20, // Maximum number of clients in pool
    idleTimeoutMillis: 30000 // Time a client can be idle before being removed
  },
  
  // Tilled integration configuration
  tilled: {
    apiBaseUrl: 'https://api.tilled.com',
    apiVersion: 'v1',
    merchantId: process.env.TILLED_MERCHANT_ID,
    accountId: process.env.TILLED_ACCOUNT_ID,
    secretKey: process.env.TILLED_SECRET_KEY,
    webhookSecret: process.env.TILLED_WEBHOOK_SECRET,
    sandbox: false,
    timeoutMs: 5000,
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
    sandbox: false,
    timeoutMs: 5000,
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
    level: process.env.LOG_LEVEL || 'info',
    format: 'json',
    destination: 'fluentd',
    fluentd: {
      host: process.env.FLUENTD_HOST || 'localhost',
      port: process.env.FLUENTD_PORT || 24224,
      timeout: 3.0,
      tag: 'fairs'
    },
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
      intervalMs: 30000 // Check health every 30 seconds
    },
    metrics: {
      enabled: true,
      path: '/metrics'
    },
    statusPage: {
      enabled: true,
      jwtToken: process.env.STATUS_PAGE_JWT_SECRET,
      pageId: process.env.STATUS_PAGE_ID,
      componentMapping: {
        'tilled': process.env.STATUS_PAGE_TILLED_COMPONENT_ID,
        'twilio': process.env.STATUS_PAGE_TWILIO_COMPONENT_ID
      }
    },
    datadog: {
      enabled: true,
      jwtToken: process.env.DATADOG_JWT_SECRET,
      appKey: process.env.DATADOG_APP_KEY,
      tags: ['env:production', 'service:fairs-checkout']
    },
    alerting: {
      pagerDuty: {
        enabled: true,
        jwtToken: process.env.PAGERDUTY_JWT_SECRET,
        serviceId: process.env.PAGERDUTY_SERVICE_ID
      }
    }
  },
  
  // Memory cache configuration
  cache: {
    enabled: true,
    ttl: 300, // Default TTL in seconds
    maxSize: 10000, // Maximum items in cache
    compressionEnabled: true
  },
  
  // Rate limiting configuration
  rateLimit: {
    enabled: true,
    windowMs: 60000, // 1 minute
    max: 60, // Max requests per windowMs
    standardHeaders: true,
    legacyHeaders: false
  },
  
  // CORS configuration
  cors: {
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400 // 24 hours
  },
  
  // Security configuration
  security: {
    helmet: {
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
          connectSrc: ["'self'", 'https://api.tilled.com', 'https://api.twilio.com']
        }
      },
      xssFilter: true,
      hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
      }
    },
    jwtToken: {
      enabled: true,
      headerName: 'Authorization',
      keys: process.env.JWT_SECRETS ? process.env.JWT_SECRETS.split(',') : []
    }
  },
  
  // Queue configuration for webhook processing
  queue: {
    concurrency: 5,
    retryAttempts: 5,
    retryDelay: 30000, // 30 seconds
    stallInterval: 10000, // 10 seconds
    redis: {
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT || 6379,
      password: process.env.REDIS_PASSWORD,
      tls: process.env.REDIS_TLS === 'true'
    }
  }
}; 