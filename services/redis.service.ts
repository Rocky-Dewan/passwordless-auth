
import { injectable } from 'tsyringe';
import Redis from 'ioredis';
import { Logger } from '../src/utils/logger';

/**
 * @injectable
 * Service for managing connections and operations with Redis.
 * Centralizes caching logic for tokens and sessions.
 */
@injectable()
export class RedisService {
    private readonly logger = new Logger(RedisService.name);
    public readonly redis: Redis;
    private isConnected: boolean = false;

    // public get client(): Redis {
    //     return this.redis;
    // }

    constructor() {
        const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

        this.redis = new Redis(REDIS_URL, {
            maxRetriesPerRequest: null,
            enableReadyCheck: false,
            // Advanced connection options for production
            connectTimeout: 10000,
            keepAlive: 60000,
            retryStrategy: (times) => {
                const delay = Math.min(times * 50, 2000);
                this.logger.warn(`Redis connection retry attempt ${times}. Delaying ${delay}ms.`);
                return delay;
            }
        });

        this.redis.on('connect', () => {
            this.isConnected = true;
            this.logger.info('Redis client connected successfully.');
        });

        this.redis.on('error', (error) => {
            this.isConnected = false;
            this.logger.error('Redis error occurred.', { error: error.message });
        });

        this.redis.on('end', () => {
            this.isConnected = false;
            this.logger.warn('Redis connection closed.');
        });
    }

    /**
     * Sets a key-value pair in Redis with an optional expiration time.
     * @param key - The key to set.
     * @param value - The value to store (stringified JSON).
     * @param ttlSeconds - Time-to-live in seconds.
     */
    public async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
        if (!this.isConnected) {
            this.logger.warn('Attempted to set key while Redis is disconnected.', { key });
            // In a production scenario, this might fall back to a temporary store or throw.
            return;
        }
        try {
            if (ttlSeconds) {
                await this.redis.set(key, value, 'EX', ttlSeconds);
            } else {
                await this.redis.set(key, value);
            }
        } catch (error) {
            this.logger.error(`Failed to set key ${key}.`, { error });
            throw error;
        }
    }

    /**
     * Gets the value associated with a key.
     * @param key - The key to retrieve.
     * @returns The stored value as a string, or null if not found.
     */
    public async get(key: string): Promise<string | null> {
        if (!this.isConnected) {
            this.logger.warn('Attempted to get key while Redis is disconnected.', { key });
            return null;
        }
        try {
            return await this.redis.get(key);
        } catch (error) {
            this.logger.error(`Failed to get key ${key}.`, { error });
            throw error;
        }
    }

    /**
     * Deletes a key from Redis.
     * @param key - The key to delete.
     * @returns The number of keys removed (1 or 0).
     */
    public async del(key: string): Promise<number> {
        if (!this.isConnected) {
            this.logger.warn('Attempted to delete key while Redis is disconnected.', { key });
            return 0;
        }
        try {
            return await this.redis.del(key);
        } catch (error) {
            this.logger.error(`Failed to delete key ${key}.`, { error });
            throw error;
        }
    }

    /**
     * Increments the number stored at key by one.
     * @param key - The key to increment.
     * @returns The value of key after the increment.
     */
    public async incr(key: string): Promise<number> {
        if (!this.isConnected) {
            this.logger.warn('Attempted to increment key while Redis is disconnected.', { key });
            return 0;
        }
        try {
            return await this.redis.incr(key);
        } catch (error) {
            this.logger.error(`Failed to increment key ${key}.`, { error });
            throw error;
        }
    }

    /**
     * Sets the expiration time (TTL) for a key.
     * @param key - The key to set TTL for.
     * @param ttlSeconds - Time-to-live in seconds.
     * @returns 1 if the timeout was set, 0 otherwise.
     */
    public async expire(key: string, ttlSeconds: number): Promise<number> {
        if (!this.isConnected) {
            this.logger.warn('Attempted to set expiration while Redis is disconnected.', { key });
            return 0;
        }
        try {
            return await this.redis.expire(key, ttlSeconds);
        } catch (error) {
            this.logger.error(`Failed to set expiration for key ${key}.`, { error });
            throw error;
        }
    }

    /**
     * Retrieves all keys matching a pattern. Use with caution in production.
     * @param pattern - The glob-style pattern (e.g., 'auth:session:*').
     * @returns An array of matching keys.
     */
    public async keys(pattern: string): Promise<string[]> {
        if (!this.isConnected) {
            this.logger.warn('Attempted to use KEYS command while Redis is disconnected.', { pattern });
            return [];
        }
        try {
            // Using SCAN in a loop is preferred for production to avoid blocking the server,
            // but for simplicity and sandboxing, we use KEYS here.
            return await this.redis.keys(pattern);
        } catch (error) {
            this.logger.error(`Failed to execute KEYS command with pattern ${pattern}.`, { error });
            throw error;
        }
    }

    /**
     * Closes the Redis connection.
     */
    public async close(): Promise<void> {
        if (this.isConnected) {
            await this.redis.quit();
        }
    }

    /**
     * Checks the connection status.
     */
    public isRedisConnected(): boolean {
        return this.isConnected;
    }
}
}
