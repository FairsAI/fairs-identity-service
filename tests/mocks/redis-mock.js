// Mock Redis client for testing
class MockRedisClient {
  constructor() {
    this.data = new Map();
    this.expires = new Map();
  }

  async get(key) {
    // Check if key has expired
    if (this.expires.has(key) && Date.now() > this.expires.get(key)) {
      this.data.delete(key);
      this.expires.delete(key);
      return null;
    }
    return this.data.get(key) || null;
  }

  async set(key, value) {
    this.data.set(key, value);
    return 'OK';
  }

  async setex(key, seconds, value) {
    this.data.set(key, value);
    this.expires.set(key, Date.now() + (seconds * 1000));
    return 'OK';
  }

  async del(key) {
    const existed = this.data.has(key);
    this.data.delete(key);
    this.expires.delete(key);
    return existed ? 1 : 0;
  }

  async keys(pattern) {
    // Simple pattern matching for test purposes
    const allKeys = Array.from(this.data.keys());
    if (pattern === '*') {
      return allKeys;
    }
    
    // Convert pattern to regex (basic implementation)
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    return allKeys.filter(key => regex.test(key));
  }

  async ttl(key) {
    if (!this.expires.has(key)) {
      return -1; // No expiry
    }
    
    const expiryTime = this.expires.get(key);
    const remaining = Math.max(0, Math.ceil((expiryTime - Date.now()) / 1000));
    return remaining;
  }

  async sadd(key, ...members) {
    let existing = this.data.get(key);
    if (!existing) {
      existing = new Set();
      this.data.set(key, existing);
    }
    
    let added = 0;
    members.forEach(member => {
      if (!existing.has(member)) {
        existing.add(member);
        added++;
      }
    });
    
    return added;
  }

  async srem(key, ...members) {
    const existing = this.data.get(key);
    if (!existing) return 0;
    
    let removed = 0;
    members.forEach(member => {
      if (existing.has(member)) {
        existing.delete(member);
        removed++;
      }
    });
    
    return removed;
  }

  async smembers(key) {
    const existing = this.data.get(key);
    return existing ? Array.from(existing) : [];
  }

  // Test helpers
  clear() {
    this.data.clear();
    this.expires.clear();
  }

  size() {
    return this.data.size;
  }
}

module.exports = MockRedisClient;