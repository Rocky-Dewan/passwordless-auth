
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


// --- TypeORM Repository: UserRepository ---

/**
 * @injectable
 * Custom repository for User operations, handling encryption/decryption and security logic.
 */
@injectable()
export class UserRepository {
    private readonly repository: Repository<User>;
    private readonly logger = new Logger(UserRepository.name);

    constructor(
        @inject('DataSource') private dataSource: DataSource,
        @inject(CryptoService) private cryptoService: CryptoService
    ) {
        this.repository = this.dataSource.getRepository(User);
        this.logger.info('UserRepository initialized.');
    }

    /**
     * Helper to normalize an email address for hashing.
     * @param email - The raw email string.
     * @returns The normalized email.
     */
    private normalizeEmail(email: string): string {
        return email.toLowerCase().trim();
    }

    /**
     * Helper to create the secure hash of the normalized email.
     * @param normalizedEmail - The normalized email string.
     * @returns The SHA-256 hash.
     */
    private hashEmail(normalizedEmail: string): string {
        // Use a non-reversible hash for the lookup index
        return this.cryptoService.generateSha256(normalizedEmail);
    }

    /**
     * Hydrates the User entity with the decrypted email and email hash before saving.
     * @param user - The User entity to be saved.
     */
    private prepareUserForSave(user: User): User {
        if (user.decryptedEmail && user.decryptedEmail !== 'DECRYPTED_EMAIL_NOT_LOADED') {
            const normalizedEmail = this.normalizeEmail(user.decryptedEmail);
            user.email = this.cryptoService.encryptData(normalizedEmail);
            user.emailHash = this.hashEmail(normalizedEmail);
        } else if (user.email) {
            // If the decrypted email is not set, ensure the hash is present
            try {
                const decrypted = this.cryptoService.decryptData(user.email);
                user.emailHash = this.hashEmail(this.normalizeEmail(decrypted));
            } catch (e) {
                this.logger.error('Failed to decrypt email during save preparation.', { error: e });
                // If decryption fails, we can't reliably set the hash.
                // In a production system, this would trigger an alert.
            }
        }
        return user;
    }

    /**
     * Hydrates the User entity with the decrypted email after loading.
     * @param user - The User entity loaded from the database.
     * @returns The User entity with the decrypted email property set.
     */
    private hydrateUserWithDecryptedEmail(user: User): User {
        try {
            const decryptedEmail = this.cryptoService.decryptData(user.email);
            user.decryptedEmail = decryptedEmail;
        } catch (error) {
            this.logger.error(`Failed to decrypt email for user ID: ${user.id}. Data corruption possible.`, { error });
            user.decryptedEmail = 'DECRYPTION_FAILED';
        }
        return user;
    }
    
