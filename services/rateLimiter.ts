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

    // --- Public Interface Methods ---

    /**
     * Checks the global rate limit for an incoming IP address.
     * @param ipAddress - The client's IP address.
     * @returns True if rate limited.
     */
    public async checkGlobalLimit(ipAddress: string): Promise<boolean> {
        return this.checkLimit(ipAddress, 'global');
    }

    /**
     * Checks the rate limit for login link requests per email address (anti-flooding).
     * @param email - The user's email address.
     * @returns True if rate limited.
     */
    public async checkEmailRequestLimit(email: string): Promise<boolean> {
        return this.checkLimit(email, 'loginRequest');
    }

    /**
     * Increments the count for a successful email request.
     * This is separate from `checkLimit` as it's a dedicated counter.
     * @param email - The user's email address.
     */
    public async incrementEmailRequest(email: string): Promise<void> {
        // We call checkLimit which handles the increment and expiry logic
        await this.checkLimit(email, 'loginRequest');
    }

    /**
     * Checks the rate limit for token verification attempts (anti-brute force).
     * @param challengeId - The unique ID of the token being verified.
     * @returns True if rate limited.
     */
    public async checkVerificationAttemptLimit(challengeId: string): Promise<boolean> {
        return this.checkLimit(challengeId, 'verificationAttempt');
    }

    /**
     * Checks the rate limit for account creation attempts per IP (anti-spam).
     * @param ipAddress - The client's IP address.
     * @returns True if rate limited.
     */
    public async checkSignupLimit(ipAddress: string): Promise<boolean> {
        return this.checkLimit(ipAddress, 'signup');
    }

    // --- Failed Login/Attempt Tracking (For Account Lockout Logic) ---

    /**
     * Increments the failed login attempt counter for an email.
     * This is used by the AuthService to trigger account lockout.
     * @param email - The user's email address.
     * @returns The current failed attempt count.
     */
    public async incrementLoginAttempt(email: string): Promise<number> {
        const config = this.configs.failedLogin;
        const redisKey = config.prefix + email;
        const currentCount = await this.redisService.incr(redisKey);

        if (currentCount === 1) {
            // First hit, set the expiration window (24 hours)
            await this.redisService.expire(redisKey, config.window);
        }

        this.logger.warn(`Failed login attempt for ${email}. Count: ${currentCount}/${config.max}`);
        return currentCount;
    }

    /**
     * Resets the failed login attempt counter upon successful login.
     * @param email - The user's email address.
     */
    public async resetLoginAttempt(email: string): Promise<void> {
        const config = this.configs.failedLogin;
        const redisKey = config.prefix + email;
        await this.redisService.del(redisKey);
        this.logger.info(`Reset failed login attempts for ${email}.`);
    }

    /**
     * Retrieves the current count of failed login attempts for an email.
     * @param email - The user's email address.
     * @returns The current failed attempt count.
     */
    public async getFailedAttemptCount(email: string): Promise<number> {
        const config = this.configs.failedLogin;
        const redisKey = config.prefix + email;
        const count = await this.redisService.get(redisKey);
        return count ? parseInt(count, 10) : 0;
    }

    // --- Advanced Rate Limiting Techniques (Simulated Leaky Bucket/Sliding Window) ---

    /**
     * Simulates a Leaky Bucket algorithm check for a high-traffic endpoint.
     * Uses a list (or ZSET) in Redis to track timestamps.
     * NOTE: This is a simplified implementation for demonstration.
     * @param key - The unique identifier.
     * @param config - The rate limit configuration.
     * @returns True if rate limited.
     */
    private async checkLeakyBucket(key: string, config: RateLimitConfig): Promise<boolean> {
        const redisKey = `rl:leaky:${config.prefix}${key}`;
        const now = Date.now();
        const windowMs = config.window * 1000;
        const limit = config.max;

        // 1. Remove old requests (outside the window)
        // In a real implementation, we'd use ZREM by score (timestamp - window)
        // For simplicity, we just check the count.

        // 2. Add the current request timestamp
        await this.redisService.redis.lpush(redisKey, now.toString());

        // 3. Trim the list to the maximum size (simulating the bucket capacity)
        await this.redisService.redis.ltrim(redisKey, 0, limit - 1);

        // 4. Get the current size
        const currentSize = await this.redisService.redis.llen(redisKey);

        if (currentSize > limit) {
            // This is a slight abuse of the list structure for simulation.
            // In a true leaky bucket, the rate is controlled by the rate of removal.
            this.logger.warn(`Leaky Bucket limit exceeded for key: ${key}. Size: ${currentSize}/${limit}`);
            return true;
        }

        // 5. Set expiration on the list
        await this.redisService.expire(redisKey, config.window);

        return false;
    }

    /**
     * Public method to apply the Leaky Bucket logic to a specific IP for a high-security endpoint.
     * @param ipAddress - The client's IP address.
     * @returns True if rate limited.
     */
    public async checkHighSecurityEndpointLimit(ipAddress: string): Promise<boolean> {
        const highSecurityConfig: RateLimitConfig = {
            window: 10, // 10 seconds
            max: 3, // 3 requests per 10 seconds
            prefix: 'rl:highsec:ip:',
        };
        return this.checkLeakyBucket(ipAddress, highSecurityConfig);
    }

}