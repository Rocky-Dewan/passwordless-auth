import { Request, Response, NextFunction } from 'express';
import { injectable, inject } from 'tsyringe';
import { StatusCodes } from 'http-status-codes';
import { CryptoService } from '../../services/crypto';
import { Logger } from '../utils/logger';
import { AuthError } from '../../services/auth.service';

// --- Configuration Constants ---
const CSRF_SECRET_COOKIE_NAME = 'csrf_secret'; // HttpOnly cookie containing the secret
const CSRF_TOKEN_HEADER_NAME = 'x-csrf-token'; // Header containing the client-submitted token
const CSRF_TOKEN_BODY_FIELD = '_csrf'; // Body field for form submissions

/**
 * @injectable
 * Middleware class for CSRF protection.
 */
@injectable()
export class CsrfMiddleware {
    private readonly logger = new Logger(CsrfMiddleware.name);

    constructor(
        @inject(CryptoService) private cryptoService: CryptoService
    ) {
        this.logger.info('CsrfMiddleware initialized.');
    }

    /**
     * Generates a cryptographically secure random secret.
     * @returns A base64url-encoded secret string.
     */
    public generateSecret(): string {
        // Generate a 32-byte secret
        return this.cryptoService.generateRandomBase64Url(32);
    }

    /**
     * Generates a CSRF token from the secret. The token is a hash of the secret.
     * This is the "Double Submit" part: the secret is in the cookie, the hash is in the header/body.
     * @param secret - The CSRF secret stored in the HttpOnly cookie.
     * @returns The SHA-256 hash of the secret, used as the token.
     */
    public generateToken(secret: string): string {
        // Use a fast, non-reversible hash (SHA-256) of the secret
        return this.cryptoService.generateSha256(secret);
    }

    /**
     * Middleware to protect state-changing requests (POST, PUT, DELETE, PATCH).
     * @param req - Express Request object.
     * @param res - Express Response object.
     * @param next - Express NextFunction.
     */
    public protect = (req: Request, res: Response, next: NextFunction): void => {
        // 1. Skip safe methods (GET, HEAD, OPTIONS, TRACE)
        if (['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(req.method)) {
            return next();
        }

        const secret = req.cookies[CSRF_SECRET_COOKIE_NAME];
        const token = req.header(CSRF_TOKEN_HEADER_NAME) || req.body[CSRF_TOKEN_BODY_FIELD];

        // 2. Check for presence of both secret and token
        if (!secret || !token) {
            this.logger.warn(`CSRF protection failed: Missing secret or token. Method: ${req.method}, Path: ${req.path}`);
            return this.handleCsrfFailure(req, next, 'MISSING_CSRF_CREDENTIALS');
        }

        // 3. Validate the token
        const expectedToken = this.generateToken(secret);

        if (token !== expectedToken) {
            this.logger.warn(`CSRF protection failed: Token mismatch. Method: ${req.method}, Path: ${req.path}`);
            return this.handleCsrfFailure(req, next, 'CSRF_TOKEN_MISMATCH');
        }

        // 4. Success
        next();
    };
}

