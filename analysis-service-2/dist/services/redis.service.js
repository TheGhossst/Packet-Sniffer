"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.redisService = void 0;
const redis_1 = require("redis");
class RedisService {
    constructor() {
        this.isConnected = false;
    }
    async connect() {
        try {
            this.client = (0, redis_1.createClient)({
                url: 'redis://localhost:6379'
            });
            await this.client.connect();
            this.client.on('error', (err) => {
                console.error('Redis error:', err);
                this.isConnected = false;
            });
            this.client.on('connect', () => {
                console.info('Redis connected successfully');
                this.isConnected = true;
            });
            this.isConnected = true;
            return true;
        }
        catch (error) {
            console.warn('Redis not available:', error);
            this.isConnected = false;
            return false;
        }
    }
    async subscribe(channel, callback) {
        if (!this.isConnected) {
            console.warn('Redis not available - subscription not possible');
            return false;
        }
        try {
            await this.client.subscribe(channel, callback);
            console.info(`Subscribed to channel: ${channel}`);
            return true;
        }
        catch (error) {
            console.error(`Failed to subscribe to ${channel}:`, error);
            return false;
        }
    }
}
exports.redisService = new RedisService();
//# sourceMappingURL=redis.service.js.map