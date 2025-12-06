import { Request } from 'express';
import { injectable, inject } from 'tsyringe';
import { CryptoService, DeviceMetadata } from './crypto';
import { EmailService } from './email/sender';
import { RateLimiterService } from './rateLimiter';
import { UserRepository } from '../src/models/user.model';
import { AuditRepository, AuditAction } from '../src/models/audit.model';
import { User, UserStatus } from '../src/models/user.model';
import { Logger } from '../src/utils/logger';
import { RedisService } from './redis.service'; // Assuming a Redis service for token/session storage

// --- Configuration Constants ---
const LOGIN_TOKEN_EXPIRY_MINUTES = 5; // Short-lived token for security
const SESSION_EXPIRY_DAYS = 7; // Long-lived session for user convenience
const MAX_LOGIN_ATTEMPTS = 5; // Max failed attempts before account lockout
const ACCOUNT_LOCKOUT_HOURS = 1; // Duration of account lockout

// --- Type Definitions for Clarity ---
export type LoginRequest = {
    email: string;
    ipAddress: string;
    userAgent: string;
};

export type VerificationRequest = {
    token: string;
    challengeId: string;
    ipAddress: string;
    userAgent: string;
};

export type SessionPayload = {
    userId: string;
    sessionId: string;
    issuedAt: number;
    expiresAt: number;
    fingerprintHash: string;
};

// --- Error Definitions ---
export class AuthError extends Error {
    constructor(message: string, public code: string = 'AUTH_ERROR', public details?: any) {
        super(message);
        this.name = 'AuthError';
    }
}

/**
 * @injectable
 * Centralized service for all authentication-related business logic.
 * Implements the security policies defined in the threat model.
 */
@injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);

    constructor(
        @inject(CryptoService) private cryptoService: CryptoService,
        @inject(EmailService) private emailService: EmailService,
        @inject(RateLimiterService) private rateLimiterService: RateLimiterService,
        @inject(UserRepository) private userRepository: UserRepository,
        @inject(AuditRepository) private auditRepository: AuditRepository,
        @inject(RedisService) private redisService: RedisService // For token and session storage
    ) {
        this.logger.info('AuthService initialized with all dependencies.');
    }

    // --- 1. Login Initiation (Magic Link/OTP Request) ---

    /**
     * Handles the initial login request by email.
     * Performs extensive security checks before generating and sending a token.
     * @param req - The Express Request object containing user and device data.
     * @param email - The user's email address.
     */
    public async initiateLogin(req: Request, email: string): Promise<void> {
        const normalizedEmail = email.toLowerCase().trim();
        const metadata = this.cryptoService.extractDeviceMetadata(req);
        const { ipAddress } = metadata;

        this.logger.info(`Login initiation for email: ${normalizedEmail} from IP: ${ipAddress}`);

        // --- Security Check 1: Global IP Rate Limit ---
        const ipLimitReached = await this.rateLimiterService.checkGlobalLimit(ipAddress);
        if (ipLimitReached) {
            this.auditRepository.log(AuditAction.RATE_LIMIT_EXCEEDED, { email: normalizedEmail, ipAddress });
            throw new AuthError('Too many requests from this IP address.', 'IP_RATE_LIMITED');
        }

        let user: User | null;
        try {
            user = await this.userRepository.findByEncryptedEmail(normalizedEmail);
        } catch (error) {
            this.logger.error('Database error during user lookup.', { error });
            throw new AuthError('Internal server error.', 'DB_ERROR');
        }

    }

}
