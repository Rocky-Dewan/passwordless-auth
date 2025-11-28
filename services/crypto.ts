import crypto from 'crypto';
import * as argon2 from 'argon2';
import { v4 as uuidv4 } from 'uuid';
import { Request } from 'express';
import { injectable } from 'tsyringe';
import { Logger } from '../src/utils/logger';

// --- Configuration Constants ---
const hash = crypto.createHash('sha256').update(buffer).digest('hex');
const OTP_LENGTH = 6;
const TOKEN_LENGTH_BYTES = 32;
const CHALLENGE_LENGTH_BYTES = 16;
const SESSION_TOKEN_LENGTH_BYTES = 64;
const PEPPER = process.env.CRYPTO_PEPPER || 'a-very-strong-global-pepper-for-extra-security-layer-change-me-in-prod';
const HASH_SECRET = process.env.HASH_SECRET || 'another-secret-key-for-hmac-operations-must-be-long-and-random';
const DEVICE_FINGERPRINT_SALT = process.env.DEVICE_FINGERPRINT_SALT || 'device-fingerprint-salt-for-integrity-check';

// Argon2 Configuration for sensitive data hashing (e.g., recovery codes, internal secrets)
const ARGON2_CONFIG: argon2.Options = {
    type: argon2.argon2id,
    memoryCost: 2 ** 16, // 64MB
    timeCost: 4,
    parallelism: 1,
    //saltLength: 16,
    hashLength: 32,
};

// --- Type Definitions for Clarity ---
export type AuthToken = {
    token: string;
    challengeId: string;
    expiresAt: Date;
    metadataHash: string; // Hash of the device fingerprint
};

export type DeviceMetadata = {
    ipAddress: string;
    userAgent: string;
    acceptLanguage: string;
    secChUa?: string; // Client Hints
    secChUaMobile?: string;
    secChUaPlatform?: string;
};

// --- Error Definitions ---
export class CryptoError extends Error {
    constructor(message: string, public code: string = 'CRYPTO_ERROR') {
        super(message);
        this.name = 'CryptoError';
    }
}

/**
 * @injectable
 * Comprehensive service for all cryptographic and security-related operations.
 * This class ensures all security primitives are centralized and correctly configured.
 */
@injectable()
export class CryptoService {
    private readonly logger = new Logger(CryptoService.name);

    constructor() {
        this.logger.info('CryptoService initialized. Argon2 configuration loaded.');
    }

    // --- 1. Core Randomness and Token Generation ---

    /**
     * Generates a cryptographically secure random string of specified byte length.
     * @param bytes - The number of bytes of randomness to generate.
     * @returns A base64 URL-safe encoded string.
     */
    private generateRandomString(bytes: number): string {
        try {
            return crypto.randomBytes(bytes).toString('base64url');
        } catch (error) {
            this.logger.error('Failed to generate random bytes.', { error });
            throw new CryptoError('Secure randomness generation failed.', 'RANDOM_FAIL');
        }
    }

    /**
     * Generates a high-entropy, single-use authentication token (Magic Link/OTP).
     * @returns A secure token string.
     */
    public generateAuthToken(): string {
        return this.generateRandomString(TOKEN_LENGTH_BYTES);
    }

    /**
     * Generates a short, numeric One-Time Password (OTP) for email or SMS.
     * @returns A 6-digit numeric string.
     */
    public generateNumericOTP(): string {
        try {
            const min = 10 ** (OTP_LENGTH - 1); // e.g., 100000
            const max = 10 ** OTP_LENGTH - 1;   // e.g., 999999
            const range = max - min + 1;
            // Generate random number within the range [0, range-1] and add min
            const randomBytes = crypto.randomBytes(4);
            const randomNumber = randomBytes.readUInt32LE(0) % range;
            return String(randomNumber + min);
        } catch (error) {
            this.logger.error('Failed to generate numeric OTP.', { error });
            throw new CryptoError('OTP generation failed.', 'OTP_FAIL');
        }
    }

    /**
     * Generates a unique, non-guessable challenge ID for stateful token tracking.
     * @returns A secure challenge ID string.
     */
    public generateChallengeId(): string {
        return this.generateRandomString(CHALLENGE_LENGTH_BYTES);
    }

    /**
     * Generates a long-lived, high-entropy session token.
     * @returns A secure session token string.
     */
    public generateSessionToken(): string {
        return this.generateRandomString(SESSION_TOKEN_LENGTH_BYTES);
    }

    /**
     * Generates a UUID V4 for general unique identifier needs.
     * @returns A UUID V4 string.
     */
    public generateUUID(): string {
        return uuidv4();
    }

    // --- 2. Hashing and Verification (Argon2 for sensitive data) ---

    /**
     * Hashes a secret string (e.g., recovery code, internal API key) using Argon2id.
     * A global pepper is applied to mitigate rainbow table attacks even if the database is compromised.
     * @param secret - The string to hash.
     * @returns The Argon2id hash string.
     */
    public async hashSecret(secret: string): Promise<string> {
        if (!secret) {
            throw new CryptoError('Cannot hash an empty secret.', 'EMPTY_SECRET');
        }
        const pepperedSecret = secret + PEPPER;
        try {
            return await argon2.hash(pepperedSecret, ARGON2_CONFIG);
        } catch (error) {
            this.logger.error('Argon2 hashing failed.', { error });
            throw new CryptoError('Argon2 hashing failed.', 'HASH_FAIL');
        }
    }

    /**
     * Verifies a secret against a stored Argon2id hash.
     * @param hash - The stored hash.
     * @param secret - The secret to verify.
     * @returns True if the secret matches the hash, false otherwise.
     */
    public async verifySecret(hash: string, secret: string): Promise<boolean> {
        if (!hash || !secret) {
            return false;
        }
        const pepperedSecret = secret + PEPPER;
        try {
            return await argon2.verify(hash, pepperedSecret);
        } catch (error) {
            this.logger.warn('Argon2 verification failed (possible tampering or invalid hash format).', { error });
            return false;
        }
    }
}
