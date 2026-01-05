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
            // --- SIMULATION START ---
            this.logger.info(`Simulating sending email to: ${payload.to}`);
            this.logger.debug(`Subject: ${payload.subject}`);
            this.logger.debug(`Content Preview: ${htmlContent.substring(0, 100)}...`);
            // await actualEmailProvider.send({ from: SENDER_EMAIL, to: payload.to, subject: payload.subject, html: htmlContent });
            // --- SIMULATION END ---

            // 4. Audit Log Success
            await this.auditRepository.log(
                AuditAction.LOGIN_LINK_SENT, // Reusing for all successful sends for simplicity
                {
                    ipAddress: payload.templateData.ipAddress,
                    recipient: payload.to,
                    emailType: payload.type,
                    subject: payload.subject,
                },
                EmailService.name
            );

        } catch (error) {
            this.logger.error(`Failed to send email of type ${payload.type} to ${payload.to}.`, { error });

            // 5. Audit Log Failure
            await this.auditRepository.log(
                AuditAction.EMAIL_SEND_FAILED,
                {
                    ipAddress: payload.templateData.ipAddress,
                    recipient: payload.to,
                    emailType: payload.type,
                    error: (error as Error).message,
                },
                EmailService.name
            );
            throw new Error('Email sending failed.');
        }
    }

    /**
     * Generates the HTML content for the email based on the type and data.
     * This is where robust, secure email templates would be managed.
     * @param type - The type of email to generate.
     * @param data - The data to inject into the template.
     * @returns The generated HTML string.
     */
    private generateHtmlContent(type: EmailType, data: EmailPayload['templateData']): string {
        const header = `<div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #ddd; padding: 20px;">
            <h1 style="color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px;">${data.appName}</h1>`;
        const footer = `<p style="font-size: 12px; color: #999; margin-top: 20px;">
            This is an automated security notification. If you did not request this, please ignore this email.
            Do not reply to this email. For support, visit our help center.
        </p></div>`;

        let body = '';

        switch (type) {
            case EmailType.LOGIN_LINK:
                body = `
                    <p>Hello,</p>
                    <p>You recently requested to log in to your ${data.appName} account.</p>
                    <p style="margin: 20px 0; text-align: center;">
                        <a href="${data.link}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                            Log in to ${data.appName}
                        </a>
                    </p>
                    <p>This link will expire in 10 minutes and can only be used once.</p>
                    <hr style="border: 0; border-top: 1px solid #eee;">
                    <p style="font-size: 14px; color: #555;">
                        <strong>Security Details:</strong><br>
                        Time: ${data.timestamp}<br>
                        IP Address: ${data.ipAddress}<br>
                        Approximate Location: ${data.location || 'Unknown'}<br>
                        Device/Browser: ${data.device || 'Unknown'}
                    </p>
                    <p>If you did not request this, please ignore this email. Your account remains secure.</p>
                `;
                break;

            case EmailType.NEW_DEVICE_LOGIN:
                body = `
                    <h2 style="color: #dc3545;">Security Alert: New Device Login</h2>
                    <p>Your ${data.appName} account was just accessed from a new device.</p>
                    <p style="font-size: 14px; color: #555;">
                        <strong>Login Details:</strong><br>
                        Time: ${data.timestamp}<br>
                        IP Address: ${data.ipAddress}<br>
                        Approximate Location: ${data.location || 'Unknown'}<br>
                        Device/Browser: ${data.device || 'Unknown'}
                    </p>
                    <p>If this was you, you can safely ignore this email.</p>
                    <p><strong>If this was NOT you, please <a href="${BASE_URL}/security-review" style="color: #007bff;">review your account security immediately</a>.</strong></p>
                `;
                break;

            case EmailType.ACCOUNT_LOCKED:
                body = `
                    <h2 style="color: #dc3545;">Account Locked Due to Too Many Failed Attempts</h2>
                    <p>Your ${data.appName} account has been temporarily locked due to too many failed login attempts.</p>
                    <p>This is a security measure to protect your account from brute-force attacks.</p>
                    <p>Your account will be automatically unlocked in <strong>${data.lockoutDurationMinutes} minutes</strong>.</p>
                    <p>If you believe your account is under attack, please contact support immediately.</p>
                `;
                break;

            case EmailType.SESSION_REVOKED:
                body = `
                    <h2 style="color: #ffc107;">Session Revoked Notification</h2>
                    <p>A session for your ${data.appName} account has been revoked.</p>
                    <p>This could be because you manually logged out, logged in from a new device, or an administrator revoked the session.</p>
                    <p>If you are currently logged in on the device described below, you will need to log in again.</p>
                    <p style="font-size: 14px; color: #555;">
                        <strong>Revoked Session Details:</strong><br>
                        Time: ${data.timestamp}<br>
                        IP Address: ${data.ipAddress}<br>
                        Device/Browser: ${data.device || 'Unknown'}
                    </p>
                `;
                break;

            case EmailType.RECOVERY_CODES:
                body = `
                    <h2 style="color: #28a745;">Your Account Recovery Codes</h2>
                    <p>These are your new one-time recovery codes for your ${data.appName} account. <strong>Please store them in a secure place.</strong></p>
                    <p style="color: #dc3545; font-weight: bold;">These codes will replace any previous recovery codes you had.</p>
                    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center;">
                        ${(data.recoveryCodes || []).map(code => `<p style="font-size: 18px; font-family: monospace; margin: 5px 0;"><strong>${code}</strong></p>`).join('')}
                    </div>
                    <p>Each code can be used only once to regain access to your account if you lose your device.</p>
                `;
                break;

            case EmailType.EMAIL_CHANGE_CONFIRM:
                body = `
                    <p>Hello,</p>
                    <p>You recently requested to change the email address associated with your ${data.appName} account to <strong>${data.newEmail}</strong>.</p>
                    <p style="margin: 20px 0; text-align: center;">
                        <a href="${data.link}" style="background-color: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                            Confirm New Email Address
                        </a>
                    </p>
                    <p>If you did not request this change, please ignore this email, and your email address will remain <strong>${data.oldEmail}</strong>.</p>
                `;
                break;

            default:
                this.logger.error(`Unknown email type: ${type}`);
                body = `<p>An unexpected notification was sent. Please contact support.</p>`;
        }

        return `${header}${body}${footer}`;
    }

    /**
     * Public method to specifically send a login link email.
     * @param to - Recipient email address.
     * @param loginLink - The full magic login link URL.
     * @param ipAddress - The IP address of the user initiating the login.
     * @param device - User-Agent string or parsed device info.
     * @param location - Approximate geographical location.
     */
    public async sendLoginLink(to: string, loginLink: string, ipAddress: string, device: string, location: string): Promise<void> {
        const timestamp = new Date().toUTCString();
        await this.sendEmail({
            to,
            type: EmailType.LOGIN_LINK,
            subject: `Your Secure Login Link for ${APP_NAME}`,
            templateData: {
                appName: APP_NAME,
                link: loginLink,
                ipAddress,
                device,
                location,
                timestamp,
            },
        });
    }
}