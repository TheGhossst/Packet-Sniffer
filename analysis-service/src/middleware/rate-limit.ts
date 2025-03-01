import { createClient } from 'redis';
import { logger } from '../utils/logger';

export class RateLimiter {
    private redis;
    private readonly windowMs: number;
    private readonly maxRequests: number;

    constructor() {
        this.redis = createClient({
            url: process.env.REDIS_URL,
            database: parseInt(process.env.RATE_LIMIT_DB || '3')
        });
        
        // Connect to Redis when service initializes
        this.redis.connect().catch(err => {
            logger.error('Redis connection error:', {
                error: err instanceof Error ? { message: err.message, stack: err.stack } : String(err)
            });
        });

        // Handle Redis errors
        this.redis.on('error', err => {
            logger.error('Redis error:', {
                error: err instanceof Error ? { message: err.message, stack: err.stack } : String(err)
            });
        });

        this.windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000');
        this.maxRequests = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '10000');
    }

    async checkLimit(key: string): Promise<boolean> {
        try {
            const current = await this.redis.incr(key);
            if (current === 1) {
                await this.redis.expire(key, this.windowMs / 1000);
            }
            return current <= this.maxRequests;
        } catch (error) {
            logger.error('Rate limit check error:', {
                error: error instanceof Error ? { message: error.message, stack: error.stack } : String(error),
                key,
                windowMs: this.windowMs,
                maxRequests: this.maxRequests
            });
            return true; // Allow request on error to prevent blocking legitimate traffic
        }
    }
}

export const rateLimiter = new RateLimiter(); 