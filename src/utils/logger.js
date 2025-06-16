/**
 * Simple logger utility
 */

// Create a simple logger with standard log levels
const logger = {
  debug: (message, ...args) => {
    if (process.env.NODE_ENV !== 'production') {
      if (typeof message === 'object') {
        console.debug('[DEBUG]', JSON.stringify(message, null, 2), ...args);
      } else {
        console.debug(`[DEBUG] ${message}`, ...args);
      }
    }
  },
  info: (message, ...args) => {
    if (typeof message === 'object') {
      console.info('[INFO]', JSON.stringify(message, null, 2), ...args);
    } else {
      console.info(`[INFO] ${message}`, ...args);
    }
  },
  warn: (message, ...args) => {
    if (typeof message === 'object') {
      console.warn('[WARN]', JSON.stringify(message, null, 2), ...args);
    } else {
      console.warn(`[WARN] ${message}`, ...args);
    }
  },
  error: (message, ...args) => {
    if (typeof message === 'object') {
      console.error('[ERROR]', JSON.stringify(message, null, 2), ...args);
    } else {
      console.error(`[ERROR] ${message}`, ...args);
    }
  }
};

module.exports = { logger }; 