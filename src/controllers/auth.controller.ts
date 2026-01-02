import { Request, Response, NextFunction, Router } from 'express';
import { injectable, inject } from 'tsyringe';
import { StatusCodes } from 'http-status-codes';
import { AuthService, AuthError } from '../../services/auth.service';
import { Logger } from '../utils/logger';
import { RateLimiterService } from '../../services/rateLimiter';
import { AuthMiddleware } from '../middleware/auth';
import { CsrfMiddleware } from '../middleware/csrf';

// --- Configuration Constants ---
const SESSION_COOKIE_NAME = 'session_token';
const CSRF_COOKIE_NAME = 'csrf_secret';
const FRONTEND_LOGIN_REDIRECT = process.env.FRONTEND_LOGIN_REDIRECT || '/dashboard';

// --- Type Definitions ---
interface LoginRequestBody {
    email: string;
    isRecovery?: boolean;
}

interface VerifyRequestBody {
    token: string;
    challengeId: string;
    recoveryCode?: string;
}


@injectable()
export class AuthController {
    private readonly logger = new Logger(AuthController.name);
    public router: Router;

    constructor(
        @inject(AuthService) private authService: AuthService,
        @inject(RateLimiterService) private rateLimiterService: RateLimiterService,
        @inject(AuthMiddleware) private authMiddleware: AuthMiddleware,
        @inject(CsrfMiddleware) private csrfMiddleware: CsrfMiddleware
    ) {
        this.router = Router();
        this.initializeRoutes();
        this.logger.info('AuthController initialized.');
    }

    // --- 1. Route Initialization ---

    private initializeRoutes(): void {
        this.router.post('/login', this.validateLoginRequest, this.handleLogin);
        this.router.get('/verify', this.validateVerificationRequest, this.handleVerification);
        this.router.post('/logout', this.authMiddleware.isAuthenticated, this.csrfMiddleware.protect, this.handleLogout);
        this.router.post('/recovery/start', this.validateLoginRequest, this.handleRecoveryStart);
        this.router.post('/recovery/verify', this.validateRecoveryVerification, this.handleRecoveryVerification);
        this.router.get('/status', this.authMiddleware.isAuthenticated, this.handleStatus);
        this.router.post('/register', this.validateLoginRequest, this.handleRegistration);

        // Advanced security endpoints (for future features)
        this.router.post('/session/revoke-all', this.authMiddleware.isAuthenticated, this.csrfMiddleware.protect, this.handleRevokeAllSessions);
        this.router.post('/session/rotate', this.authMiddleware.isAuthenticated, this.csrfMiddleware.protect, this.handleSessionRotation);
    }

    // --- 2. Input Validation Middleware ---

    /**
     * Middleware to validate the login request body (email format).
     */
    private validateLoginRequest = (req: Request, res: Response, next: NextFunction): Response<any, Record<string, any>> | void => {
        const { email } = req.body as LoginRequestBody;

        if (!email || typeof email !== 'string' || email.trim().length === 0) {
            return res.status(StatusCodes.BAD_REQUEST).json({
                status: 'error',
                message: 'Email is required.',
                code: 'VALIDATION_ERROR',
            });
        }

        // Basic email format check (more robust validation is done in the service)
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(StatusCodes.BAD_REQUEST).json({
                status: 'error',
                message: 'Invalid email format.',
                code: 'VALIDATION_ERROR',
            });
        }

        // Additional sanity checks
        if (email.length > 255) {
            return res.status(StatusCodes.BAD_REQUEST).json({
                status: 'error',
                message: 'Email is too long.',
                code: 'VALIDATION_ERROR',
            });
        }

        next();
    };

    /**
     * Middleware to validate the token verification request query parameters.
     */
    private validateVerificationRequest = (req: Request, res: Response, next: NextFunction): Response<any, Record<string, any>> | void => {
        const { token, challengeId } = req.query as { token: string; challengeId: string };

        if (!token || !challengeId) {
            return res.status(StatusCodes.BAD_REQUEST).json({
                status: 'error',
                message: 'Missing token or challenge ID.',
                code: 'VALIDATION_ERROR',
            });
        }

        // Token and challenge ID length/format validation (assuming base64url format)
        if (token.length < 32 || challengeId.length < 16) {
            return res.status(StatusCodes.BAD_REQUEST).json({
                status: 'error',
                message: 'Token or challenge ID format is invalid.',
                code: 'VALIDATION_ERROR',
            });
        }

        next();
    };

    /**
     * Middleware to validate recovery code verification request body.
     */
    private validateRecoveryVerification = (req: Request, res: Response, next: NextFunction): Response<any, Record<string, any>> | void => {
        const { email, recoveryCode } = req.body as { email: string; recoveryCode: string };

        if (!email || !recoveryCode) {
            return res.status(StatusCodes.BAD_REQUEST).json({
                status: 'error',
                message: 'Email and recovery code are required.',
                code: 'VALIDATION_ERROR',
            });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(StatusCodes.BAD_REQUEST).json({
                status: 'error',
                message: 'Invalid email format.',
                code: 'VALIDATION_ERROR',
            });
        }

        // Recovery code format validation (e.g., XXXX-XXXX-XXXX-XXXX)
        if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(recoveryCode.toUpperCase())) {
            return res.status(StatusCodes.BAD_REQUEST).json({
                status: 'error',
                message: 'Invalid recovery code format.',
                code: 'VALIDATION_ERROR',
            });
        }

        next();
    };
// --- 3. Handler Functions ---

    /**
     * Handles the initial login/magic link request.
     */
    private handleLogin = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const { email } = req.body as LoginRequestBody;

        try {
            // The service handles all security checks (rate limiting, account status)
            await this.authService.initiateLogin(req, email);

            // Respond with a generic success message to prevent email enumeration
            res.status(StatusCodes.OK).json({
                status: 'success',
                message: 'If an account exists for this email, a login link has been sent.',
            });
        } catch (error) {
            // Pass the error to the error handler middleware
            next(error);
        }
    };


}

