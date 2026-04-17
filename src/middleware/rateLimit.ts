import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';

function tooManyRequestsResponse(_req: Request, res: Response): void {
  res.status(429).json({ error: 'Too many requests. Please wait before trying again.' });
}

// Global limiter: 100 req/15min per IP
export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  handler: tooManyRequestsResponse,
});

// Auth endpoint limiter: 10 req/15min per IP
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: tooManyRequestsResponse,
});

// OTP verification: 10 attempts per 5 minutes per IP
export const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: tooManyRequestsResponse,
});
