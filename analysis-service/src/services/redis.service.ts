import { createClient, RedisClientType } from 'redis';
import { logger } from '../utils/logger';

class RedisService {
  private client!: RedisClientType;
  private isConnected = false;
  
  async connect() {
    try {
      this.client = createClient({
        url: process.env.REDIS_URL
      });

      const connectPromise = this.client.connect();
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Redis connection timeout')), 5000);
      });

      await Promise.race([connectPromise, timeoutPromise]);

      this.client.on('error', (err) => {
        logger.error('Redis error:', err);
        this.isConnected = false;
      });

      this.client.on('connect', () => {
        logger.info('Redis connected successfully');
        this.isConnected = true;
      });

      this.isConnected = true;
    } catch (error) {
      logger.warn('Redis not available - some features will be disabled:', error);
      this.isConnected = false;
    }
  }

  async subscribe(channel: string, callback: (message: string) => Promise<void>) {
    if (!this.isConnected) {
      logger.warn('Redis not available - subscription not possible');
      return;
    }

    try {
      await this.client.subscribe(channel, callback);
      logger.info(`Subscribed to channel: ${channel}`);
    } catch (error) {
      logger.error(`Failed to subscribe to ${channel}:`, error);
    }
  }
}

export const redisService = new RedisService(); 