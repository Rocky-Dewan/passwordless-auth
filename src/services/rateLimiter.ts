import { redisService } from './redis.service';
import { logger } from '../utils/logger';

interface RateLimitResult { allowed: boolean; remaining: number; resetIn: number; }

async function check(key: string, max: number, windowSec: number): Promise<RateLimitResult> {
  try {
    const count = await redisService.incr(key);
    if (count === 1) await redisService.expire(key, windowSec);
    const ttl = await redisService.ttl(key);
    return { allowed: count <= max, remaining: Math.max(0, max - count), resetIn: ttl };
  } catch (err) {
    logger.error('Rate limiter error — allowing request', { err });
    return { allowed: true, remaining: 1, resetIn: 0 };
  }
}

export const rateLimiterService = {
  checkIp:       (ip: string)      => check(`rl:ip:${ip}`,       10,  900),
  checkEmail:    (email: string)   => check(`rl:em:${email}`,     3,   300),
  checkOtpAttempt: (sid: string)   => check(`rl:otp:${sid}`,      5,   120),
};
