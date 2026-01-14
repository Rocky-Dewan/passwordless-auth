import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, Repository, DataSource } from 'typeorm';
import { injectable, inject } from 'tsyringe';
import { Logger } from '../utils/logger';
import { CryptoService } from '../../../services/crypto';

// --- Enums and Constants ---
export enum AuditAction {
    // Authentication Actions
    USER_REGISTERED = 'USER_REGISTERED',
    LOGIN_LINK_SENT = 'LOGIN_LINK_SENT',
    LOGIN_SUCCESS = 'LOGIN_SUCCESS',
    LOGIN_ATTEMPT_FAILED = 'LOGIN_ATTEMPT_FAILED',
    LOGOUT = 'LOGOUT',
    SESSION_REVOKED = 'SESSION_REVOKED',
    SESSION_EXPIRED = 'SESSION_EXPIRED',
    SESSION_ROTATED = 'SESSION_ROTATED',
    ALL_SESSIONS_REVOKED = 'ALL_SESSIONS_REVOKED',
    RECOVERY_ATTEMPT_FAILED = 'RECOVERY_ATTEMPT_FAILED',
    RECOVERY_CODES_GENERATED = 'RECOVERY_CODES_GENERATED',

    // Security Alerts & Violations
    SECURITY_ALERT_HIGH = 'SECURITY_ALERT_HIGH', // e.g., Device fingerprint mismatch, token replay
    SECURITY_ALERT_MEDIUM = 'SECURITY_ALERT_MEDIUM',
    RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
    ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
    ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED',
    LOGIN_ATTEMPT_BLOCKED = 'LOGIN_ATTEMPT_BLOCKED', // Blocked due to lockout or rate limit

    // Account Management Actions
    EMAIL_CHANGE_REQUEST = 'EMAIL_CHANGE_REQUEST',
    EMAIL_CHANGE_SUCCESS = 'EMAIL_CHANGE_SUCCESS',
    PROFILE_UPDATE = 'PROFILE_UPDATE',
    MFA_ENABLED = 'MFA_ENABLED',
    MFA_DISABLED = 'MFA_DISABLED',
    DEACTIVATION_REQUEST = 'DEACTIVATION_REQUEST',
    ACCOUNT_DEACTIVATED = 'ACCOUNT_DEACTIVATED',

    // System/Admin Actions
    ADMIN_LOGIN = 'ADMIN_LOGIN',
    ADMIN_USER_SUSPENDED = 'ADMIN_USER_SUSPENDED',
    ADMIN_USER_UNSUSPENDED = 'ADMIN_USER_UNSUSPENDED',
    SYSTEM_CONFIG_CHANGE = 'SYSTEM_CONFIG_CHANGE',
    DATABASE_MIGRATION = 'DATABASE_MIGRATION',
    EMAIL_SEND_FAILED = 'EMAIL_SEND_FAILED',
}

// --- TypeORM Entity: Audit ---

@Entity('audit_logs')
export class Audit {
    @PrimaryGeneratedColumn('uuid')
    id!: string;

    @Column({ type: 'enum', enum: AuditAction, nullable: false })
    action!: AuditAction;

    @Column({ type: 'uuid', nullable: true })
    userId!: string | null; // The user who performed the action (if applicable)

    @Column({ type: 'varchar', length: 255, nullable: true })
    targetId!: string | null; // The ID of the resource affected (e.g., session ID, challenge ID)

    @Column({ type: 'varchar', length: 50, nullable: true })
    ipAddress!: string | null;

    @Column({ type: 'jsonb', nullable: false })
    details!: object; // JSON object containing all relevant context (e.g., user-agent, reason, old/new values)

    @CreateDateColumn({ type: 'timestamp' })
    timestamp!: Date;

    @Column({ type: 'boolean', default: false })
    isSecurityEvent!: boolean; // Flag for easier filtering of critical events

    @Column({ type: 'varchar', length: 100, nullable: true })
    serviceContext!: string | null; // e.g., 'AuthService', 'RateLimiterMiddleware'
}
// --- TypeORM Repository: AuditRepository ---

/**
 * @injectable
 * Custom repository for Audit Log operations.
 * Provides a simplified interface for logging and ensures data integrity.
 */
@injectable()
export class AuditRepository {
    private readonly repository: Repository<Audit>;
    private readonly logger = new Logger(AuditRepository.name);
    private readonly securityEvents = [
        AuditAction.SECURITY_ALERT_HIGH,
        AuditAction.SECURITY_ALERT_MEDIUM,
        AuditAction.RATE_LIMIT_EXCEEDED,
        AuditAction.ACCOUNT_LOCKED,
        AuditAction.LOGIN_ATTEMPT_BLOCKED,
        AuditAction.ALL_SESSIONS_REVOKED,
        AuditAction.RECOVERY_ATTEMPT_FAILED,
        AuditAction.LOGIN_ATTEMPT_FAILED,
    ];

    constructor(
        @inject('DataSource') private dataSource: DataSource,
        @inject(CryptoService) private cryptoService: CryptoService
    ) {
        this.repository = this.dataSource.getRepository(Audit);
        this.logger.info('AuditRepository initialized.');
    }

    /**
     * Logs a new audit event.
     * @param action - The type of action performed.
     * @param details - A detailed object containing context for the event.
     * @param context - The service/module logging the event.
     */
    public async log(action: AuditAction, details: any, context?: string): Promise<Audit> {
        const auditLog = new Audit();
        auditLog.id = this.cryptoService.generateUUID();
        auditLog.action = action;
        auditLog.userId = details.userId || null;
        auditLog.targetId = details.challengeId || details.sessionId || details.targetId || null;
        auditLog.ipAddress = details.ipAddress || null;
        auditLog.serviceContext = context || 'Unknown';

        // Clean up the details object for storage
        const cleanedDetails = { ...details };
        delete cleanedDetails.userId;
        delete cleanedDetails.challengeId;
        delete cleanedDetails.sessionId;
        delete cleanedDetails.targetId;
        delete cleanedDetails.ipAddress;

        auditLog.details = cleanedDetails;
        auditLog.isSecurityEvent = this.securityEvents.includes(action);

        try {
            const savedLog = await this.repository.save(auditLog);
            this.logger.debug(`Audit Logged: ${action}`, { userId: auditLog.userId, ip: auditLog.ipAddress });
            return savedLog;
        } catch (error) {
            this.logger.error(`Failed to save audit log for action: ${action}`, { error, details });
            // IMPORTANT: In a real system, a failure to log should trigger an immediate alert
            // and potentially fail the transaction to ensure non-repudiation.
            throw new Error(`Critical: Failed to save audit log for ${action}`);
        }
    }
