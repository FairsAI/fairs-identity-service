const Redis = require('redis');
const winston = require('winston');

class RedisConnection {
  constructor() {
    this.client = null;
    this.isConnected = false;
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console()
      ]
    });
  }

  async initialize() {
    try {
      // Configure Redis client
      const redisConfig = {
        host: process.env.REDIS_HOST || 'redis',
        port: parseInt(process.env.REDIS_PORT || '6379'),
        retryDelayOnFailover: 100,
        enableReadyCheck: false,
        maxRetriesPerRequest: null
      };

      // Add password if configured
      if (process.env.REDIS_PASSWORD) {
        redisConfig.password = process.env.REDIS_PASSWORD;
      }

      this.logger.info('Initializing Redis connection', {
        host: redisConfig.host,
        port: redisConfig.port
      });

      this.client = Redis.createClient({
        socket: {
          host: redisConfig.host,
          port: redisConfig.port
        },
        password: redisConfig.password
      });

      // Set up event handlers
      this.client.on('connect', () => {
        this.logger.info('Redis client connected');
      });

      this.client.on('ready', () => {
        this.logger.info('Redis client ready');
        this.isConnected = true;
      });

      this.client.on('error', (error) => {
        this.logger.error('Redis client error', { error: error.message });
        this.isConnected = false;
      });

      this.client.on('end', () => {
        this.logger.info('Redis client disconnected');
        this.isConnected = false;
      });

      // Connect to Redis
      await this.client.connect();

      // Test connection
      await this.client.ping();
      this.logger.info('Redis connection established successfully');

      return this.client;
    } catch (error) {
      this.logger.error('Failed to initialize Redis connection', {
        error: error.message
      });
      throw error;
    }
  }

  getClient() {
    if (!this.isConnected || !this.client) {
      throw new Error('Redis client not connected');
    }
    return this.client;
  }

  async disconnect() {
    if (this.client) {
      await this.client.quit();
      this.isConnected = false;
      this.logger.info('Redis connection closed');
    }
  }

  // Convenience methods
  async get(key) {
    const client = this.getClient();
    return await client.get(key);
  }

  async set(key, value, ttl = null) {
    const client = this.getClient();
    if (ttl) {
      return await client.setEx(key, ttl, value);
    }
    return await client.set(key, value);
  }

  async setex(key, ttl, value) {
    const client = this.getClient();
    return await client.setEx(key, ttl, value);
  }

  async del(key) {
    const client = this.getClient();
    return await client.del(key);
  }

  async keys(pattern) {
    const client = this.getClient();
    return await client.keys(pattern);
  }

  async ttl(key) {
    const client = this.getClient();
    return await client.ttl(key);
  }

  async sadd(key, ...members) {
    const client = this.getClient();
    return await client.sAdd(key, members);
  }

  async srem(key, ...members) {
    const client = this.getClient();
    return await client.sRem(key, members);
  }

  async smembers(key) {
    const client = this.getClient();
    return await client.sMembers(key);
  }
}

// Export singleton instance
const redisConnection = new RedisConnection();
module.exports = redisConnection;