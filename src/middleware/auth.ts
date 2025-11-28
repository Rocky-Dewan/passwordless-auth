import { Request, Response, NextFunction } from 'express';
import { injectable, inject } from 'tsyringe';
import { HttpStatusCode } from 'http-status-codes';
import { AuthService, AuthError } from '../../services/auth.service';
import { Logger } from '../utils/logger';
import { RedisService } from '../../services/redis.service';

// --- Type Extensions for Express Request ---
declare module 'express' {
    interface Request {
        userId?: string;
        sessionId?: string;
        sessionToken?: string;
        sessionPayload?: any; // Detailed payload from the session token
    }
}

// --- Configuration Constants ---
const SESSION_COOKIE_NAME = 'session_token';
const SESSION_ROTATION_INTERVAL_MS = 1000 * 60 * 15; // 15 minutes for session rotation check

/**
 * @injectable
 * Middleware class for authentication and session management.
 */
@injectable()
export class AuthMiddleware {
    private readonly logger = new Logger(AuthMiddleware.name);

    constructor(
        @inject(AuthService) private authService: AuthService,
        @inject(RedisService) private redisService: RedisService // Used for session metadata checks
    ) {
        this.logger.info('AuthMiddleware initialized.');
    }

    /**
     * Express middleware function to check if the user is authenticated.
     * @param req - Express Request object.
     * @param res - Express Response object.
     * @param next - Express NextFunction.
     */
    public isAuthenticated = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const sessionToken = req.cookies[SESSION_COOKIE_NAME] || req.headers['authorization']?.split(' ')[1];

        if (!sessionToken) {
            return this.handleAuthFailure(req, res, next, 'MISSING_SESSION_TOKEN');
        }

        try {
            // 1. Validate the token and retrieve the payload
            // const payload = await this.authService.validateSessionToken(sessionToken);

            // // 2. Perform advanced session checks (e.g., is session revoked?)
            // const isRevoked = await this.authService.isSessionRevoked(payload.sessionId);
            const payload = await this.authService.validateSession(req, sessionToken);
            if (isRevoked) {
                return this.handleAuthFailure(req, res, next, 'SESSION_REVOKED');
            }

            // 3. Inject user context into the request object
            req.userId = payload.userId;
            req.sessionId = payload.sessionId;
            req.sessionToken = sessionToken;
            req.sessionPayload = payload;

            // 4. Perform session rotation check
            await this.checkAndRotateSession(req, res, payload);

            // 5. Perform device fingerprint check (if implemented)
            // const isDeviceMatch = this.checkDeviceFingerprint(req, payload);
            // if (!isDeviceMatch) {
            //     return this.handleAuthFailure(req, res, next, 'DEVICE_FINGERPRINT_MISMATCH');
            // }

            next();
        } catch (error) {
            if (error instanceof AuthError) {
                // Log and handle specific AuthErrors (e.g., token expired, invalid signature)
                return this.handleAuthFailure(req, res, next, error.code, error.message);
            }
            // Handle unexpected errors during validation
            this.logger.error('Unexpected error during authentication middleware.', { error });
            return this.handleAuthFailure(req, res, next, 'UNEXPECTED_AUTH_ERROR');
        }
    };
}
