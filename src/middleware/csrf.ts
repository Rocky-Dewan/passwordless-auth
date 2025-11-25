
import { Request, Response, NextFunction } from 'express';
import { injectable, inject } from 'tsyringe';
import { HttpStatusCode } from 'http-status-codes';
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
