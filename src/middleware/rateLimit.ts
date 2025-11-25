
import { Request, Response, NextFunction } from 'express';
import { injectable, inject } from 'tsyringe';
import { HttpStatusCode } from 'http-status-codes';
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
}
