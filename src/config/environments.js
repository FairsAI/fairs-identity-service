/**
 * Environment Configuration Manager
 * 
 * Handles environment detection and configuration loading.
 */

const path = require('path');
const { logger } = require('../monitoring/integration-logger');

// Valid environments
const ENVIRONMENTS = ['development', 'test', 'staging', 'production'];

/**
 * Get the current environment
 * @returns {string} Environment name
 * @throws {Error} If environment is invalid
 */
function getEnvironment() {
  const env = process.env.NODE_ENV || 'development';
  
  if (!ENVIRONMENTS.includes(env)) {
    throw new Error(`Invalid environment: ${env}. Must be one of: ${ENVIRONMENTS.join(', ')}`);
  }
  
  return env;
}

/**
 * Load configuration for the current environment
 * @returns {Object} Environment configuration
 */
function loadConfig() {
  const environment = getEnvironment();
  
  try {
    // Load environment-specific configuration
    const configPath = path.resolve(__dirname, `./${environment}.js`);
    const config = require(configPath);
    
    // Validate basic configuration structure
    if (!config) {
      throw new Error(`Empty configuration for environment: ${environment}`);
    }
    
    logger.info({
      message: `Loaded configuration for environment: ${environment}`,
      environment
    });
    
    return config;
  } catch (error) {
    logger.error({
      message: `Failed to load configuration for environment: ${environment}`,
      environment,
      error: error.message,
      stack: error.stack
    });
    
    throw new Error(`Failed to load configuration for environment: ${environment}. ${error.message}`);
  }
}

/**
 * Check if current environment is production
 * @returns {boolean} True if production
 */
function isProduction() {
  return getEnvironment() === 'production';
}

/**
 * Check if current environment is development
 * @returns {boolean} True if development
 */
function isDevelopment() {
  return getEnvironment() === 'development';
}

/**
 * Check if current environment is test
 * @returns {boolean} True if test
 */
function isTest() {
  return getEnvironment() === 'test';
}

/**
 * Check if current environment is staging
 * @returns {boolean} True if staging
 */
function isStaging() {
  return getEnvironment() === 'staging';
}

/**
 * Get a specific configuration section
 * @param {string} section Section name
 * @returns {Object} Configuration section
 */
function getConfigSection(section) {
  const config = loadConfig();
  
  if (!config[section]) {
    logger.warn({
      message: `Configuration section not found: ${section}`,
      environment: getEnvironment()
    });
    return {};
  }
  
  return config[section];
}

/**
 * Validate required environment variables
 * @param {Array<string>} requiredVars List of required environment variables
 * @returns {boolean} True if all variables exist
 * @throws {Error} If any required variable is missing
 */
function validateEnvVars(requiredVars) {
  const missing = [];
  
  for (const varName of requiredVars) {
    if (!process.env[varName]) {
      missing.push(varName);
    }
  }
  
  if (missing.length > 0) {
    const errorMessage = `Missing required environment variables: ${missing.join(', ')}`;
    logger.error({
      message: errorMessage,
      environment: getEnvironment(),
      missingVars: missing
    });
    
    throw new Error(errorMessage);
  }
  
  return true;
}

// Create config object with environment-specific values
const config = loadConfig();

module.exports = {
  getEnvironment,
  loadConfig,
  isProduction,
  isDevelopment,
  isTest,
  isStaging,
  getConfigSection,
  validateEnvVars,
  ENVIRONMENTS,
  config
}; 