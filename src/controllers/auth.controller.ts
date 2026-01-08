
import { Request, Response, NextFunction, Router } from 'express';
import { injectable, inject } from 'tsyringe';
import { HttpStatusCode } from 'http-status-codes';
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

/**
 * @injectable
 * Controller responsible for processing all authentication-related HTTP requests.
 */
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
    private validateLoginRequest = (req: Request, res: Response, next: NextFunction): void => {
        const { email } = req.body as LoginRequestBody;

        if (!email || typeof email !== 'string' || email.trim().length === 0) {
            return res.status(HttpStatusCode.BAD_REQUEST).json({
                status: 'error',
                message: 'Email is required.',
                code: 'VALIDATION_ERROR',
            });
        }

        // Basic email format check (more robust validation is done in the service)
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(HttpStatusCode.BAD_REQUEST).json({
                status: 'error',
                message: 'Invalid email format.',
                code: 'VALIDATION_ERROR',
            });
        }

        // Additional sanity checks
        if (email.length > 255) {
            return res.status(HttpStatusCode.BAD_REQUEST).json({
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
    private validateVerificationRequest = (req: Request, res: Response, next: NextFunction): void => {
        const { token, challengeId } = req.query as { token: string; challengeId: string };

        if (!token || !challengeId) {
            return res.status(HttpStatusCode.BAD_REQUEST).json({
                status: 'error',
                message: 'Missing token or challenge ID.',
                code: 'VALIDATION_ERROR',
            });
        }

        // Token and challenge ID length/format validation (assuming base64url format)
        if (token.length < 32 || challengeId.length < 16) {
            return res.status(HttpStatusCode.BAD_REQUEST).json({
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
    private validateRecoveryVerification = (req: Request, res: Response, next: NextFunction): void => {
        const { email, recoveryCode } = req.body as { email: string; recoveryCode: string };

        if (!email || !recoveryCode) {
            return res.status(HttpStatusCode.BAD_REQUEST).json({
                status: 'error',
                message: 'Email and recovery code are required.',
                code: 'VALIDATION_ERROR',
            });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(HttpStatusCode.BAD_REQUEST).json({
                status: 'error',
                message: 'Invalid email format.',
                code: 'VALIDATION_ERROR',
            });
        }

        // Recovery code format validation (e.g., XXXX-XXXX-XXXX-XXXX)
        if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(recoveryCode.toUpperCase())) {
            return res.status(HttpStatusCode.BAD_REQUEST).json({
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
            res.status(HttpStatusCode.OK).json({
                status: 'success',
                message: 'If an account exists for this email, a login link has been sent.',
            });
        } catch (error) {
            // Pass the error to the error handler middleware
            next(error);
        }
    };

    /**
     * Handles the token verification request from the magic link.
     */
    private handleVerification = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const { token, challengeId } = req.query as { token: string; challengeId: string };

        try {
            // The service validates the token, challenge, expiration, and device fingerprint
            const sessionToken = await this.authService.verifyTokenAndCreateSession(req, token, challengeId);

            // Set the session token in a secure HttpOnly cookie
            res.cookie(SESSION_COOKIE_NAME, sessionToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production', // Use secure in production
                sameSite: 'strict', // CSRF protection
                maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
                path: '/',
            });

            // Set the CSRF secret cookie (not HttpOnly) for the client to read and submit in headers
            const csrfSecret = this.csrfMiddleware.generateSecret();
            const csrfToken = this.csrfMiddleware.generateToken(csrfSecret);

            res.cookie(CSRF_COOKIE_NAME, csrfSecret, {
                httpOnly: true, // Should be HttpOnly for the secret!
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 1000 * 60 * 60 * 24 * 7,
                path: '/',
            });

            // Redirect the user to the frontend dashboard or a success page
            res.redirect(FRONTEND_LOGIN_REDIRECT);

            // NOTE: We don't send the CSRF token in a cookie, but rather let the client
            // read the secret from the HttpOnly cookie and generate the token, or
            // send the token in the response body/header of the redirect target.
            // For a robust implementation, the secret should be in the HttpOnly cookie,
            // and the token should be in a separate, non-HttpOnly cookie or a response header.
            // We will use the HttpOnly secret/token pattern for maximum security.
            // The CSRF middleware will handle the token generation/validation.

        } catch (error) {
            // Pass the error to the error handler middleware
            next(error);
        }
    };
    /**
     * Handles user logout and session revoca tion.
     */
    private handleLogout = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            // The session token is available via req.sessionToken from AuthMiddleware
            // @ts-ignore
            const sessionToken = req.sessionToken as string;
            // @ts-ignore
            const sessionId = req.sessionId as string;

            if (sessionToken && sessionId) {
                await this.authService.revokeSession(sessionId, sessionToken);
            }

            // Clear the cookies on the client side
            res.clearCookie(SESSION_COOKIE_NAME, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                path: '/',
            });
            res.clearCookie(CSRF_COOKIE_NAME, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                path: '/',
            });

            res.status(HttpStatusCode.OK).json({
                status: 'success',
                message: 'Successfully logged out.',
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Handles the request to start the account recovery process (sends recovery codes).
     */
    private handleRecoveryStart = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        // NOTE: This endpoint should be highly restricted and likely require a separate MFA/CAPTCHA.
        // For now, we reuse the login validation.
        const { email } = req.body as LoginRequestBody;

        try {
            // In a real system, this would send a link to generate new recovery codes,
            // or an OTP to confirm the recovery attempt.
            // For this example, we assume the user already has codes and is attempting to use them.

            res.status(HttpStatusCode.OK).json({
                status: 'success',
                message: 'If an account exists, please proceed with your recovery code verification.',
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Handles the verification of a recovery code.
     */
    private handleRecoveryVerification = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const { email, recoveryCode } = req.body as { email: string; recoveryCode: string };

        try {
            const sessionToken = await this.authService.verifyRecoveryCode(email, recoveryCode, req);

            // Set secure cookies (same logic as handleVerification)
            res.cookie(SESSION_COOKIE_NAME, sessionToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 1000 * 60 * 60 * 24 * 7,
                path: '/',
            });

            const csrfSecret = this.csrfMiddleware.generateSecret();
            res.cookie(CSRF_COOKIE_NAME, csrfSecret, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 1000 * 60 * 60 * 24 * 7,
                path: '/',
            });

            res.status(HttpStatusCode.OK).json({
                status: 'success',
                message: 'Account recovered successfully.',
                redirect: FRONTEND_LOGIN_REDIRECT,
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Handles the registration of a new user.
     */
    private handleRegistration = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const { email } = req.body as LoginRequestBody;

        try {
            // Check for IP-based signup rate limit
            const isRateLimited = await this.rateLimiterService.checkSignupLimit(req.ip || 'unknown');
            if (isRateLimited) {
                throw new AuthError('Too many registration attempts from this IP.', 'SIGNUP_RATE_LIMITED');
            }

            // The service handles user creation and checks for existence
            const user = await this.authService.registerUser(email);

            // Immediately initiate the login process to send the verification link
            await this.authService.initiateLogin(req, email);

            res.status(HttpStatusCode.CREATED).json({
                status: 'success',
                message: `Account created for ${user.decryptedEmail}. A verification link has been sent to your email.`,
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Handles the request to check the current authentication status.
     */
    private handleStatus = (req: Request, res: Response): void => {
        // This is protected by authMiddleware, so if it reaches here, the user is authenticated.
        // @ts-ignore
        const userId = req.userId;
        // @ts-ignore
        const sessionId = req.sessionId;

        res.status(HttpStatusCode.OK).json({
            status: 'authenticated',
            userId: userId,
            sessionId: sessionId,
            message: 'User is currently authenticated.',
        });
    };



}