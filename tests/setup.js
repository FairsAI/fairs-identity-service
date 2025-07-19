// Test setup file
// Configure test environment

// Set test environment
process.env.NODE_ENV = 'test';

// Mock Phase 1 environment variables
process.env.ENABLE_AUTO_RECOGNITION = 'true';
process.env.HIGH_CONFIDENCE_THRESHOLD = '80';
process.env.MEDIUM_CONFIDENCE_THRESHOLD = '50';
process.env.DEVICE_TRUST_THRESHOLD = '70';
process.env.AWS_REGION = 'us-east-1';
process.env.AWS_ACCESS_KEY_ID = 'test-access-key';
process.env.AWS_SECRET_ACCESS_KEY = 'test-secret-key';
process.env.AWS_SES_FROM_EMAIL = 'test@example.com';
process.env.COMMERCE_PLATFORM_URL = 'http://test-commerce-platform:3000';
process.env.REDIS_HOST = 'localhost';
process.env.REDIS_PORT = '6379';

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
};

// Add custom matchers if needed
expect.extend({
  toBeWithinRange(received, floor, ceiling) {
    const pass = received >= floor && received <= ceiling;
    if (pass) {
      return {
        message: () => `expected ${received} not to be within range ${floor} - ${ceiling}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be within range ${floor} - ${ceiling}`,
        pass: false,
      };
    }
  },
});

// Global test timeout
jest.setTimeout(10000);