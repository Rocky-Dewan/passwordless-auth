import Redis from 'ioredis';
import { config } from '../config';
import { logger } from '../utils/logger';

class RedisService {
  private client: Redis;

  constructor() {
    this.client = new Redis({
      host:          config.redis.host,
      port:          config.redis.port,
      password:      config.redis.password || undefined,
      lazyConnect:   true,
      retryStrategy: (times) => (times > 5 ? null : Math.min(times * 200, 2000)),
      enableReadyCheck: true,
    });
    this.client.on('error', (err) => logger.error('Redis error', { msg: err.message }));
    this.client.on('ready', () => logger.info('Redis ready'));
  }

  async connect(): Promise<void> { await this.client.connect(); }
  getClient(): Redis { return this.client; }

  async set(key: string, value: string, ttl?: number): Promise<void> {
    if (ttl) await this.client.setex(key, ttl, value);
    else     await this.client.set(key, value);
  }

  async get(key: string): Promise<string | null> { return this.client.get(key); }
  async del(key: string): Promise<void>          { await this.client.del(key); }
  async exists(key: string): Promise<boolean>    { return (await this.client.exists(key)) === 1; }
  async incr(key: string): Promise<number>       { return this.client.incr(key); }
  async expire(key: string, sec: number): Promise<void> { await this.client.expire(key, sec); }
  async ttl(key: string): Promise<number>        { return this.client.ttl(key); }
}

export const redisService = new RedisService();
