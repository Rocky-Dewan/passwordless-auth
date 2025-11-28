import { injectable, inject } from 'tsyringe';
import { Logger } from '../../src/utils/logger';
import { AuditRepository, AuditAction } from '../../src/models/audit.model';

// --- Configuration Constants ---
const SENDER_EMAIL = process.env.EMAIL_SENDER || 'no-reply@secureauth.com';
const APP_NAME = process.env.APP_NAME || 'SecureAuth';
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

// --- Type Definitions ---
export enum EmailType {
    LOGIN_LINK = 'LOGIN_LINK',
    NEW_DEVICE_LOGIN = 'NEW_DEVICE_LOGIN',
    ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
    SESSION_REVOKED = 'SESSION_REVOKED',
    RECOVERY_CODES = 'RECOVERY_CODES',
    EMAIL_CHANGE_CONFIRM = 'EMAIL_CHANGE_CONFIRM',
}

interface EmailPayload {
    to: string;
    type: EmailType;
    subject: string;
    templateData: {
        appName: string;
        link?: string;
        device?: string;
        ipAddress?: string;
        location?: string;
        timestamp?: string;
        recoveryCodes?: string[];
        [key: string]: any;
    };
}

/**
 * @injectable
 * Service for sending secure, templated emails.
 */
@injectable()
export class EmailService {
    private readonly logger = new Logger(EmailService.name);

    constructor(
        @inject(AuditRepository) private auditRepository: AuditRepository
    ) {
        this.logger.info('EmailService initialized.');
    }

    /**
     * Sends an email using a simulated or actual provider (e.g., SendGrid, Mailgun).
     * @param payload - The email payload containing recipient, type, subject, and template data.
     */
    public async sendEmail(payload: EmailPayload): Promise<void> {
        // 1. Validate Payload
        if (!payload.to || !payload.type || !payload.subject) {
            this.logger.error('Attempted to send email with missing required fields.', { payload });
            throw new Error('Invalid email payload.');
        }

        // 2. Generate HTML Content from Template
        const htmlContent = this.generateHtmlContent(payload.type, payload.templateData);

        // 3. Simulate or Call Email Provider API
        try {
            this.logger.info(`Simulating sending email to: ${payload.to}`);
            this.logger.debug(`Subject: ${payload.subject}`);
            this.logger.debug(`Content Preview: ${htmlContent.substring(0, 100)}...`);

            // 4. Audit Log Success
            await this.auditRepository.log(
                AuditAction.LOGIN_LINK_SENT,
                {
                    ipAddress: payload.templateData?.ipAddress,
                    recipient: payload.to,
                    emailType: payload.type,
                    subject: payload.subject,
                },
                EmailService.name
            );

        } catch (error) {
            this.logger.error(
                `Failed to send email of type ${payload.type} to ${payload.to}.`,
                { error }
            );

            await this.auditRepository.log(
                AuditAction.EMAIL_SEND_FAILED,
                {
                    ipAddress: payload.templateData?.ipAddress,
                    recipient: payload.to,
                    emailType: payload.type,
                    error: (error as Error).message,
                },
                EmailService.name
            );

            throw new Error('Email sending failed.');
        }
    }

    
    public async sendNewDeviceNotification(email: string): Promise<void> {
        return this.sendEmail({
            to: email,
            type: EmailType.NEW_DEVICE_LOGIN,
            subject: 'New Device Detected',
            templateData: {
                message: 'A new device was used to access your account.',
                ipAddress: undefined,
                appName: APP_NAME
            }
        });
    }
    
    public async sendRecoveryCodeGenerationNotification(email: string): Promise<void> {
        return this.sendEmail({
            to: email,
            type: EmailType.RECOVERY_CODES,
            subject: 'Recovery Code Created',
            templateData: {
                message: 'A password recovery code has been generated for your account.',
                ipAddress: undefined,
                appName: APP_NAME
            }
        });
    }
    
    public async sendAccountLockedNotification(email: string): Promise<void> {
        return this.sendEmail({
            to: email,
            type: EmailType.ACCOUNT_LOCKED,
            subject: 'Your Account Has Been Locked',
            templateData: {
                message: 'Your account is temporarily locked due to suspicious activity.',
                ipAddress: undefined,
                appName: APP_NAME
            }
        });
    }
    
    public async sendSecurityAlert(email: string, message: string): Promise<void> {
        return this.sendEmail({
            to: email,
            type: EmailType.SESSION_REVOKED, // or another appropriate EmailType
            subject: 'Security Alert',
            templateData: {
                message,
                ipAddress: undefined,
                appName: APP_NAME
            }
        });
}
