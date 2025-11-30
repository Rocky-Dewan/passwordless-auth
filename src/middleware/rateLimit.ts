
import { Request, Response, NextFunction } from 'express';
import { injectable, inject } from 'tsyringe';
import { StatusCodes } from 'http-status-codes';
import { RateLimiterService } from '../../services/rateLimiter';
import { Logger } from '../utils/logger';
import { AuthError } from '../../services/auth.service';
import { AuditRepository, AuditAction } from '../models/audit.model';

// --- Configuration Constants ---
const GLOBAL_LIMIT_WINDOW_SECONDS = 60;
const GLOBAL_LIMIT_MAX_REQUESTS = 100;
const LOGIN_LIMIT_WINDOW_SECONDS = 60 * 5; // 5 minutes
const LOGIN_LIMIT_MAX_ATTEMPTS = 5;

/**
 * @injectable
 * Middleware class for rate limiting.
 */
@injectable()
export class RateLimitMiddleware {
    private readonly logger = new Logger(RateLimitMiddleware.name);

    constructor(
        @inject(RateLimiterService) private rateLimiterService: RateLimiterService,
        @inject(AuditRepository) private auditRepository: AuditRepository
    ) {
        this.logger.info('RateLimitMiddleware initialized.');
    }

    /**
     * Generic handler for rate limiting logic.
     * @param keyPrefix - The prefix for the Redis key (e.g., 'global', 'login').
     * @param windowSeconds - The time window in seconds.
     * @param maxRequests - The maximum number of requests allowed.
     * @param isLoginAttempt - Flag to indicate if this is a login attempt (for specific logging).
     */
    private createLimiter(keyPrefix: string, windowSeconds: number, maxRequests: number, isLoginAttempt: boolean = false) {
        return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
            const ip = req.ip || 'unknown';
            const key = `${keyPrefix}:${ip}`;

            try {
                const { isRateLimited, remaining, resetTime } = await this.rateLimiterService.checkLimit(
                    key,
                    windowSeconds,
                    maxRequests
                );

                res.setHeader('X-RateLimit-Limit', maxRequests);
                res.setHeader('X-RateLimit-Remaining', remaining);
                res.setHeader('X-RateLimit-Reset', resetTime);

                if (isRateLimited) {
                    this.logger.warn(`Rate limit exceeded for key: ${key}. IP: ${ip}`);

                    // Audit log the rate limit violation
                    await this.auditRepository.log(
                        AuditAction.RATE_LIMIT_EXCEEDED,
                        {
                            ipAddress: ip,
                            userAgent: req.get('User-Agent'),
                            key: key,
                            limit: maxRequests,
                            window: windowSeconds,
                            path: req.path,
                        },
                        RateLimitMiddleware.name
                    );

                    const retryAfter = Math.ceil((resetTime * 1000 - Date.now()) / 1000);
                    res.setHeader('Retry-After', retryAfter);

                    const error = new AuthError(
                        `Too many requests. Please try again in ${retryAfter} seconds.`,
                        'RATE_LIMIT_EXCEEDED'
                    );
                    error.statusCode = StatusCodes.TOO_MANY_REQUESTS;
                    return next(error);
                }

                // If it's a login attempt, check for account-specific limits as well
                if (isLoginAttempt) {
                    // This is handled by the AuthService.initiateLogin, but a pre-check here is good.
                    // We skip the account-specific check here to avoid reading the database on every request,
                    // letting the AuthService handle the more granular logic.
                }

                next();
            } catch (error) {
                this.logger.error('Error in rate limiting middleware.', { error });
                // Fail open: if Redis is down, allow the request to proceed to prevent a denial of service
                // on the rate limiter itself. Log a high-severity alert.
                this.auditRepository.log(
                    AuditAction.SECURITY_ALERT_HIGH,
                    {
                        ipAddress: ip,
                        reason: 'Rate Limiter Service Failure (Fail Open)',
                        error: (error as Error).message,
                    },
                    RateLimitMiddleware.name
                );
                next();
            }
        };
    }
}

