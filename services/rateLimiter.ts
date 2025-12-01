
import { injectable, inject } from 'tsyringe';
import { RedisService } from './redis.service';
import { Logger } from '../src/utils/logger';

// --- Configuration Constants: All times in seconds ---

// 1. Global IP Rate Limit (Prevent general flooding)
const GLOBAL_LIMIT_WINDOW = 60; // 1 minute
const GLOBAL_LIMIT_MAX = 100; // 100 requests per minute per IP

// 2. Login Request Limit (Prevent email enumeration/flooding)
const LOGIN_REQUEST_WINDOW = 3600; // 1 hour
const LOGIN_REQUEST_MAX_PER_EMAIL = 5; // 5 login link requests per email per hour

// 3. Verification Attempt Limit (Prevent token brute force)
const VERIFICATION_ATTEMPT_WINDOW = 600; // 10 minutes
const VERIFICATION_ATTEMPT_MAX_PER_TOKEN = 5; // 5 attempts per token

// 4. Failed Login Attempt Limit (Account Lockout Trigger)
const FAILED_LOGIN_ATTEMPT_WINDOW = 86400; // 24 hours
const FAILED_LOGIN_ATTEMPT_MAX = 10; // 10 failed attempts before a temporary account lock (handled by AuthService)

// 5. Account Creation Limit (Prevent signup spam)
const SIGNUP_LIMIT_WINDOW = 3600; // 1 hour
const SIGNUP_LIMIT_MAX_PER_IP = 5; // 5 signups per IP per hour

// --- Type Definitions ---
export interface RateLimitConfig {
    window: number; // in seconds
    max: number; // max requests
    prefix: string; // Redis key prefix
}

/**
 * @injectable
 * Advanced Rate Limiting Service.
 * Uses a combination of fixed window and sliding window techniques (via Redis EXPIRE/INCR).
 */
@injectable()
export class RateLimiterService {
    private readonly logger = new Logger(RateLimiterService.name);
    private readonly configs: Record<string, RateLimitConfig>;

    constructor(@inject(RedisService) private redisService: RedisService) {
        this.configs = {
            global: { window: GLOBAL_LIMIT_WINDOW, max: GLOBAL_LIMIT_MAX, prefix: 'rl:global:ip:' },
            loginRequest: { window: LOGIN_REQUEST_WINDOW, max: LOGIN_REQUEST_MAX_PER_EMAIL, prefix: 'rl:login:email:' },
            verificationAttempt: { window: VERIFICATION_ATTEMPT_WINDOW, max: VERIFICATION_ATTEMPT_MAX_PER_TOKEN, prefix: 'rl:verify:token:' },
            failedLogin: { window: FAILED_LOGIN_ATTEMPT_WINDOW, max: FAILED_LOGIN_ATTEMPT_MAX, prefix: 'rl:failed:email:' },
            signup: { window: SIGNUP_LIMIT_WINDOW, max: SIGNUP_LIMIT_MAX_PER_IP, prefix: 'rl:signup:ip:' },
        };
        this.logger.info('RateLimiterService initialized with multi-layer limits.');
    }

    // --- Core Rate Limiting Logic (Fixed Window) ---

    /**
     * Checks if a specific key has exceeded its rate limit based on a configuration.
     * Implements a secure fixed-window counter.
     * @param key - The unique identifier (IP, email, token ID).
     * @param configName - The name of the rate limit configuration.
     * @returns True if the limit is exceeded, false otherwise.
     */
    private async checkLimit(key: string, configName: keyof typeof this.configs): Promise<boolean> {
        const config = this.configs[configName];
        if (!config) {
            this.logger.error(`Unknown rate limit configuration: ${configName}`);
            return false;
        }

        const redisKey = config.prefix + key;
        const currentCount = await this.redisService.incr(redisKey);

        if (currentCount === 1) {
            // First hit, set the expiration window
            await this.redisService.expire(redisKey, config.window);
        }

        if (currentCount > config.max) {
            this.logger.warn(`Rate limit exceeded for ${configName} on key: ${key}. Count: ${currentCount}/${config.max}`);
            return true;
        }

        return false;
    }
}