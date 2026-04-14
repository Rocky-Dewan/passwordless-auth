import { redisService } from './redis.service';
import { logger } from '../src/utils/logger';

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetIn: number;
}

class RateLimiterService {
  async check(
    key: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<RateLimitResult> {
    try {
      const count = await redisService.incr(key);
      if (count === 1) {
        await redisService.expire(key, windowSeconds);
      }
      const ttl = await redisService.ttl(key);
      const remaining = Math.max(0, maxRequests - count);
      return {
        allowed: count <= maxRequests,
        remaining,
        resetIn: ttl,
      };
    } catch (err) {
      logger.error('Rate limiter error, allowing request', { err });
      return { allowed: true, remaining: 1, resetIn: 0 };
    }
  }

  // IP-based: 10 auth requests per 15 minutes
  async checkIp(ip: string): Promise<RateLimitResult> {
    return this.check(`rl:ip:${ip}`, 10, 900);
  }

  // Email-based: 3 auth requests per 5 minutes per email
  async checkEmail(email: string): Promise<RateLimitResult> {
    const normalizedEmail = email.toLowerCase().trim();
    return this.check(`rl:email:${normalizedEmail}`, 3, 300);
  }

  // OTP verification: 5 attempts per OTP session
  async checkOtpAttempt(sessionId: string): Promise<RateLimitResult> {
    return this.check(`rl:otp:${sessionId}`, 5, 120);
  }
}

export const rateLimiterService = new RateLimiterService();
