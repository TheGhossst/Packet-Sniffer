import { createClient, RedisClientType } from 'redis';

class RedisService {
  private client!: RedisClientType;
  private isConnected = false;

  async connect() {
    try {
      this.client = createClient({
        url: 'redis://localhost:6379'
      });

      await this.client.connect();

      this.client.on('error', (err: Error) => {
        console.error('Redis error:', err);
        this.isConnected = false;
      });

      this.client.on('connect', () => {
        console.info('Redis connected successfully');
        this.isConnected = true;
      });

      this.isConnected = true;
      return true;
    } catch (error) {
      console.warn('Redis not available:', error);
      this.isConnected = false;
      return false;
    }
  }

  async subscribe(channel: string, callback: (message: string) => Promise<void>) {
    if (!this.isConnected) {
      console.warn('Redis not available - subscription not possible');
      return false;
    }

    try {
      await this.client.subscribe(channel, callback);
      console.info(`Subscribed to channel: ${channel}`);
      return true;
    } catch (error) {
      console.error(`Failed to subscribe to ${channel}:`, error);
      return false;
    }
  }
}

export const redisService = new RedisService();