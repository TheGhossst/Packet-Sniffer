const Redis = require('redis');

class CacheManager {
    constructor(options = {}) {
        this.client = Redis.createClient({
            url: process.env.REDIS_URL || 'redis://localhost:6379',
            database: options.database || 1,
            ...options
        });
        this.defaultTTL = options.defaultTTL || 3600; // 1 hour default
    }

    async init() {
        await this.client.connect();
    }

    async get(key) {
        try {
            const value = await this.client.get(key);
            return value ? JSON.parse(value) : null;
        } catch (error) {
            console.error('Cache get error:', error);
            return null;
        }
    }

    async set(key, value, ttl = this.defaultTTL) {
        try {
            await this.client.set(
                key,
                JSON.stringify(value),
                'EX',
                ttl
            );
            return true;
        } catch (error) {
            console.error('Cache set error:', error);
            return false;
        }
    }

    async cleanup() {
        await this.client.quit();
    }
}

module.exports = CacheManager; 