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

        // --- Security Check 2: User Existence and Account Status ---
        if (!user) {
            // Log the attempt for security, but return a generic success message to prevent enumeration
            this.logger.warn(`Attempted login for non-existent email: ${normalizedEmail}`);
            await this.rateLimiterService.incrementLoginAttempt(normalizedEmail); // Still rate limit non-existent users
            await this.auditRepository.log(AuditAction.LOGIN_ATTEMPT_FAILED, { email: normalizedEmail, reason: 'Non-existent user', ipAddress });
            // Fail silently to prevent user enumeration
            return;
        }

        // --- Security Check 3: Account Lockout Check ---
        if (user.status === UserStatus.LOCKED) {
            const lockedUntil = new Date(user.lockedUntil!);
            if (lockedUntil > new Date()) {
                this.auditRepository.log(AuditAction.LOGIN_ATTEMPT_BLOCKED, { userId: user.id, reason: 'Account locked', ipAddress });
                throw new AuthError('Account is temporarily locked. Please try again later.', 'ACCOUNT_LOCKED');
            } else {
                // Automatically unlock the account after the lockout period
                user.status = UserStatus.ACTIVE;
                user.failedLoginAttempts = 0;
                user.lockedUntil = null;
                await this.userRepository.save(user);
                this.auditRepository.log(AuditAction.ACCOUNT_UNLOCKED, { userId: user.id, reason: 'Lockout period expired' });
            }
        }

        // --- Security Check 4: Account-Specific Rate Limit (Email Flooding Prevention) ---
        const emailLimitReached = await this.rateLimiterService.checkEmailRequestLimit(normalizedEmail);
        if (emailLimitReached) {
            this.auditRepository.log(AuditAction.RATE_LIMIT_EXCEEDED, { userId: user.id, reason: 'Email request limit', ipAddress });
            throw new AuthError('Too many login requests for this account. Please wait a few minutes.', 'EMAIL_RATE_LIMITED');
        }

            // --- 2. Token Generation and Storage ---

        const token = this.cryptoService.generateAuthToken();
        const challengeId = this.cryptoService.generateChallengeId();
        const expiresAt = new Date(Date.now() + LOGIN_TOKEN_EXPIRY_MINUTES * 60 * 1000);
        const fingerprintHash = this.cryptoService.createDeviceFingerprintHash(metadata);

        const authToken = {
            token,
            challengeId,
            userId: user.id,
            expiresAt: expiresAt.getTime(),
            fingerprintHash,
            isUsed: false,
            attemptCount: 0,
        };

            // Store the token in Redis for fast access and short-term persistence
        const tokenKey = `auth:token:${challengeId}`;
        await this.redisService.set(tokenKey, JSON.stringify(authToken), LOGIN_TOKEN_EXPIRY_MINUTES * 60);

        this.logger.info(`Generated token for user ${user.id} with challenge ID: ${challengeId}`);

        // --- 3. Email Dispatch and Audit Log ---

        const loginLink = this.generateLoginLink(token, challengeId);
        const emailSent = await this.emailService.sendLoginLink(normalizedEmail, loginLink, LOGIN_TOKEN_EXPIRY_MINUTES);

        if (emailSent) {
            await this.rateLimiterService.incrementEmailRequest(normalizedEmail);
            this.auditRepository.log(AuditAction.LOGIN_LINK_SENT, { userId: user.id, challengeId, ipAddress });
        } else {
            // Handle email failure gracefully (e.g., alert ops, but don't fail the user request)
            this.logger.error(`Failed to send login link to ${normalizedEmail}`);
            this.auditRepository.log(AuditAction.EMAIL_SEND_FAILED, { userId: user.id, challengeId });
        }
    }
    /**
     * Generates the secure, stateful login link.
     * @param token - The authentication token.
     * @param challengeId - The unique challenge ID.
     * @returns The full login URL.
     */
    private generateLoginLink(token: string, challengeId: string): string {
        const baseUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
        return `${baseUrl}/auth/verify?token=${token}&challengeId=${challengeId}`;
    }

    // --- 2. Token Verification and Session Creation ---

    /**
     * Validates the login token and creates a secure, device-bound session.
     * @param req - The Express Request object.
     * @param token - The token from the URL.
     * @param challengeId - The challenge ID from the URL.
     * @returns A secure session token string.
     */
    public async verifyTokenAndCreateSession(req: Request, token: string, challengeId: string): Promise<string> {
        const metadata = this.cryptoService.extractDeviceMetadata(req);
        const { ipAddress } = metadata;

        this.logger.info(`Verification attempt for challenge ID: ${challengeId} from IP: ${ipAddress}`);

        // --- Security Check 1: Global IP Rate Limit ---
        const ipLimitReached = await this.rateLimiterService.checkGlobalLimit(ipAddress);
        if (ipLimitReached) {
            this.auditRepository.log(AuditAction.RATE_LIMIT_EXCEEDED, { challengeId, ipAddress });
            throw new AuthError('Too many verification requests from this IP address.', 'IP_RATE_LIMITED');
        }

        const tokenKey = `auth:token:${challengeId}`;
        const tokenDataRaw = await this.redisService.get(tokenKey);

        if (!tokenDataRaw) {
            // Log the failed attempt, but don't reveal if the token existed or expired
            this.auditRepository.log(AuditAction.LOGIN_ATTEMPT_FAILED, { challengeId, reason: 'Token not found/expired', ipAddress });
            throw new AuthError('Invalid or expired login link.', 'INVALID_TOKEN');
        }

        const tokenData = JSON.parse(tokenDataRaw);
       // --- Security Check 2: Token Attempt Limit ---
        if (tokenData.attemptCount >= MAX_LOGIN_ATTEMPTS) {
            await this.redisService.del(tokenKey); // Invalidate the token
            this.auditRepository.log(AuditAction.LOGIN_ATTEMPT_BLOCKED, { userId: tokenData.userId, challengeId, reason: 'Max attempts reached', ipAddress });
            throw new AuthError('Maximum verification attempts reached. Please request a new login link.', 'MAX_ATTEMPTS_REACHED');
        }

        // --- Security Check 3: Token Expiration and Usage ---
        if (Date.now() > tokenData.expiresAt || tokenData.isUsed) {
            await this.redisService.del(tokenKey);
            const reason = tokenData.isUsed ? 'Token already used (Replay attack attempt)' : 'Token expired';
            this.auditRepository.log(AuditAction.LOGIN_ATTEMPT_FAILED, { userId: tokenData.userId, challengeId, reason, ipAddress });
            throw new AuthError('Invalid or expired login link.', 'INVALID_TOKEN');
        }
}
