// File: passwordless-auth/src/app.ts
// Purpose: Main Express application setup, including middleware, routing, and error handling.

import 'dotenv/config';
import express, { Application, Request, Response, NextFunction } from 'express';
import 'reflect-metadata';
import { container } from 'tsyringe';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import { initializeDatabaseAndDI } from './utils/database';
import { Logger } from './utils/logger';
import { AuthRoutes } from './routes/auth.routes';
import { StatusCodes } from 'http-status-codes';
import { RateLimitMiddleware } from './middleware/rateLimit';
import { CsrfMiddleware } from './middleware/csrf';
import { AuthMiddleware } from './middleware/auth';
import { AuthError } from '../services/auth.service';

const logger = new Logger('App');

// --- 1. Custom Error Handler Middleware ---

interface CustomError extends Error {
    statusCode?: number;
    code?: string;
    details?: any;
}

const errorHandler = (err: CustomError, req: Request, res: Response, next: NextFunction) => {
    // Log the error for internal monitoring
    logger.error(`Unhandled Error: ${err.message}`, {
        stack: err.stack,
        path: req.path,
        method: req.method,
        ip: req.ip,
        statusCode: err.statusCode || StatusCodes.INTERNAL_SERVER_ERROR,
        errorCode: err.code || 'SERVER_ERROR',
    });

    // Check if it's a known AuthError or a general operational error
    const statusCode = err instanceof AuthError
        ? StatusCodes.UNAUTHORIZED // For AuthErrors like invalid token, etc.
        : err.statusCode || StatusCodes.INTERNAL_SERVER_ERROR;

    const message = statusCode === StatusCodes.INTERNAL_SERVER_ERROR && process.env.NODE_ENV === 'production'
        ? 'An unexpected error occurred.'
        : err.message;

    res.status(statusCode).json({
        status: 'error',
        message: message,
        code: err.code || 'SERVER_ERROR',
        // Only include stack trace in non-production environments
        ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
    });
};

// --- 2. Application Setup Class ---

export class App {
    public app: Application;

    constructor() {
        this.app = express();
        this.initialize();
    }

    private async initialize(): Promise<void> {
        // Must initialize DB and DI first
        await initializeDatabaseAndDI();

        this.configureSecurityMiddleware();
        this.configureStandardMiddleware();
        this.configureRoutes();
        this.configureErrorHandler();
    }

    /**
     * Configures all security-critical middleware (Helmet, CORS, Rate Limiting, CSRF).
     */
    private configureSecurityMiddleware(): void {
        logger.info('Configuring security middleware...');

        // A. Helmet: Sets various HTTP headers for security (Clickjacking, XSS, etc.)
        this.app.use(helmet({
            // Strict Transport Security (HSTS) - Enforces HTTPS
            hsts: {
                maxAge: 31536000, // 1 year
                includeSubDomains: true,
                preload: true,
            },
            // Content Security Policy (CSP) - Crucial for preventing XSS
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"], // Adjust this based on frontend needs
                    styleSrc: ["'self'", 'https:', "'unsafe-inline'"],
                    imgSrc: ["'self'", 'data:'],
                    connectSrc: ["'self'"],
                    fontSrc: ["'self'", 'https:', 'data:'],
                    objectSrc: ["'none'"], // Prevents embedding flash/plugins
                    mediaSrc: ["'self'"],
                    frameAncestors: ["'none'"], // Prevents Clickjacking via iframes
                },
            },
            // Referrer Policy
            referrerPolicy: { policy: 'same-origin' },
            // X-Frame-Options is covered by frameAncestors in CSP
            frameguard: false,
        }));

        // B. CORS: Configure for production environment
        const allowedOrigins = process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : ['http://localhost:3000'];
        this.app.use(cors({
            origin: (origin, callback) => {
                // Allow requests with no origin (like mobile apps or curl requests)
                if (!origin) return callback(null, true);
                if (allowedOrigins.includes(origin)) {
                    return callback(null, true);
                }
                logger.warn(`CORS blocked request from origin: ${origin}`);
                return callback(new Error('Not allowed by CORS'), false);
            },
            credentials: true, // Allow cookies to be sent
        }));

        // C. Global Rate Limiting: Apply to all requests
        const rateLimitMiddleware = container.resolve(RateLimitMiddleware);
        this.app.use(rateLimitMiddleware.globalLimiter);

        // D. CSRF Protection: Apply to all state-changing methods (POST, PUT, DELETE)
        const csrfMiddleware = container.resolve(CsrfMiddleware);
        this.app.use(csrfMiddleware.protect);
    }

    /**
     * Configures standard Express middleware.
     */
    private configureStandardMiddleware(): void {
        logger.info('Configuring standard middleware...');
        this.app.use(express.json()); // Body parser for JSON
        this.app.use(express.urlencoded({ extended: true })); // Body parser for URL-encoded data
        this.app.use(cookieParser(process.env.COOKIE_SECRET || 'a-very-long-secret-for-signed-cookies')); // Cookie parser with secret for signed cookies
    }

    /**
     * Configures all application routes.
     */
    private configureRoutes(): void {
        logger.info('Configuring application routes...');

        // Basic health check route (unprotected)
        this.app.get('/health', (req: Request, res: Response) => {
            res.status(StatusCodes.OK).json({ status: 'ok', uptime: process.uptime() });
        });

        // Auth Routes (login, verify, logout)
        const authRoutes = container.resolve(AuthRoutes);
        this.app.use('/auth', authRoutes.router);

        // Example Protected Route
        const authMiddleware = container.resolve(AuthMiddleware);
        this.app.get('/protected', authMiddleware.isAuthenticated, (req: Request, res: Response) => {
            // @ts-ignore
            res.status(StatusCodes.OK).json({ message: 'Access granted to protected resource.', userId: req.userId });
        });

        // 404 Not Found Handler
        this.app.use((req: Request, res: Response) => {
            res.status(StatusCodes.NOT_FOUND).json({
                status: 'error',
                message: `Cannot ${req.method} ${req.path}`,
                code: 'NOT_FOUND',
            });
        });
    }

    /**
     * Configures the final error handling middleware.
     */
    private configureErrorHandler(): void {
        this.app.use(errorHandler);
    }

    /**
     * Starts the Express server.
     * @param port - The port to listen on.
     */
    public start(port: number): void {
        this.app.listen(port, () => {
            logger.info(`Server is running on port ${port}`);
        });
    }

