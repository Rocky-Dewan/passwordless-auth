
import { Entity, PrimaryColumn, Column, CreateDateColumn, UpdateDateColumn, Repository, DataSource } from 'typeorm';
import { injectable, inject } from 'tsyringe';
import { CryptoService } from '../../services/crypto';
import { Logger } from '../utils/logger';

// --- Enums and Constants ---
export enum UserStatus {
    ACTIVE = 'ACTIVE',
    PENDING_VERIFICATION = 'PENDING_VERIFICATION',
    LOCKED = 'LOCKED',
    SUSPENDED = 'SUSPENDED',
    DEACTIVATED = 'DEACTIVATED',
}

// --- TypeORM Entity: User ---

@Entity('users')
export class User {
    @PrimaryColumn('uuid')
    id!: string;

    /**
     * The user's email, stored in an encrypted format for data-at-rest security.
     * The actual email is decrypted only when needed for sending links or displaying to the user.
     * This column is indexed for fast lookups.
     */
    @Column({ type: 'varchar', length: 512, unique: true, nullable: false })
    email!: string; // Encrypted email

    /**
     * A hash of the normalized email (lowercase, trimmed) for fast, unencrypted lookups.
     * This allows us to query the database without decrypting every row.
     */
    @Column({ type: 'varchar', length: 64, unique: true, nullable: false })
    emailHash!: string; // SHA-256 hash of the normalized email

    @Column({ type: 'enum', enum: UserStatus, default: UserStatus.PENDING_VERIFICATION })
    status!: UserStatus;

    @Column({ type: 'int', default: 0 })
    failedLoginAttempts!: number;

    @Column({ type: 'timestamp', nullable: true })
    lockedUntil!: Date | null;

    @Column({ type: 'timestamp', nullable: true })
    lastLogin!: Date | null;

    @Column('text', { array: true, default: [] })
    recoveryCodeHashes!: string[]; // Argon2 hashes of one-time recovery codes

    @Column({ type: 'jsonb', default: () => "'[]'" })
    activeSessions!: { sessionId: string; device: string; lastUsed: Date }[];

    @Column({ type: 'varchar', length: 255, nullable: true })
    preferredLanguage!: string | null;

    @Column({ type: 'varchar', length: 255, nullable: true })
    timeZone!: string | null;

    @Column({ type: 'boolean', default: false })
    isMfaEnabled!: boolean; // Placeholder for future MFA implementation

    @Column({ type: 'jsonb', default: () => "'{}'" })
    mfaDevices!: object; // Stores FIDO2/WebAuthn credentials or TOTP secrets

    @CreateDateColumn({ type: 'timestamp' })
    createdAt!: Date;

    @UpdateDateColumn({ type: 'timestamp' })
    updatedAt!: Date;

    // --- Virtual Property for Decrypted Email (Non-persisted) ---
    private _decryptedEmail: string | undefined;

    public get decryptedEmail(): string {
        if (this._decryptedEmail) {
            return this._decryptedEmail;
        }
        // In a real TypeORM setup, this would use a subscriber or getter/setter,
        // but for a simple entity, we'll rely on the repository to hydrate this.
        return 'DECRYPTED_EMAIL_NOT_LOADED';
    }

    public set decryptedEmail(email: string) {
        this._decryptedEmail = email;
    }
}
