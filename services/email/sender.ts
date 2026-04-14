import nodemailer, { Transporter } from 'nodemailer';
import { config } from '../../src/config';
import { logger } from '../../src/utils/logger';

interface MailOptions {
  to: string;
  subject: string;
  html: string;
  text: string;
}

class EmailService {
  private transporter: Transporter | null = null;

  async getTransporter(): Promise<Transporter> {
    if (this.transporter) return this.transporter;

    if (!config.email.user || !config.email.pass) {
      // Auto Ethereal account for development when no SMTP configured
      const testAccount = await nodemailer.createTestAccount();
      logger.info('Ethereal test account created (dev only)', {
        user: testAccount.user,
        preview: 'https://ethereal.email',
        note: 'Set EMAIL_USER and EMAIL_PASS in .env to use Brevo for real delivery',
      });
      this.transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: { user: testAccount.user, pass: testAccount.pass },
      });
    } else {
      // Brevo (smtp-relay.brevo.com:587) or any configured SMTP
      this.transporter = nodemailer.createTransport({
        host: config.email.host,
        port: config.email.port,
        secure: config.email.secure,
        auth: {
          user: config.email.user,
          pass: config.email.pass,
        },
        tls: { rejectUnauthorized: false },
      });
    }

    return this.transporter;
  }

  async send(options: MailOptions): Promise<void> {
    const transport = await this.getTransporter();
    const info = await transport.sendMail({
      from: `"SecureAuth" <${config.email.from}>`,
      to: options.to,
      subject: options.subject,
      html: options.html,
      text: options.text,
    });

    if (config.env !== 'production') {
      const previewUrl = nodemailer.getTestMessageUrl(info);
      if (previewUrl) {
        logger.info('Email preview (Ethereal)', { url: previewUrl, to: options.to });
      } else {
        logger.info('Email sent via Brevo', { to: options.to, subject: options.subject });
      }
    }
  }

  async sendMagicLink(
    to: string,
    magicLink: string,
    otp: string,
    expirySeconds: number
  ): Promise<void> {
    const mins = Math.floor(expirySeconds / 60);
    const secs = expirySeconds % 60;
    const expiryLabel = mins > 0
      ? `${mins} minute${mins > 1 ? 's' : ''} ${secs > 0 ? `${secs} seconds` : ''}`
      : `${secs} seconds`;

    // Format OTP with dash: 1234-5678
    const otpFormatted = otp.slice(0, 4) + '-' + otp.slice(4);

    const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Your Sign-In Code</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');
    body { margin:0; padding:0; background:#f1f5f9; font-family:'Inter',Arial,sans-serif; }
    .wrap { max-width:520px; margin:40px auto; padding:0 16px; }
    .card { background:#fff; border-radius:20px; overflow:hidden; box-shadow:0 8px 32px rgba(102,126,234,0.15); }
    .top-bar { height:5px; background:linear-gradient(90deg,#667eea,#764ba2,#f093fb); }
    .header { padding:36px 36px 24px; text-align:center; background:linear-gradient(135deg,rgba(102,126,234,0.06),rgba(118,75,162,0.04)); border-bottom:1px solid #e2e8f0; }
    .logo-badge { display:inline-flex; align-items:center; justify-content:center; width:56px; height:56px; background:linear-gradient(135deg,#667eea,#764ba2); border-radius:14px; margin-bottom:16px; }
    .header h1 { font-size:22px; font-weight:800; color:#1a1a2e; margin:0 0 6px; }
    .header p { font-size:14px; color:#6b7280; margin:0; line-height:1.5; }
    .body { padding:32px 36px; }
    .body p { color:#374151; font-size:14px; line-height:1.7; margin:0 0 20px; }
    .expiry-badge { display:inline-flex; align-items:center; gap:6px; background:#fffbeb; border:1px solid #fbbf24; border-radius:8px; padding:8px 14px; color:#92400e; font-size:13px; font-weight:600; margin-bottom:24px; }
    .btn-wrap { text-align:center; margin:24px 0; }
    .btn { display:inline-block; background:linear-gradient(135deg,#667eea,#764ba2); color:#fff !important; text-decoration:none; padding:14px 36px; border-radius:12px; font-weight:700; font-size:15px; letter-spacing:0.01em; box-shadow:0 4px 15px rgba(102,126,234,0.4); }
    .divider { display:flex; align-items:center; gap:12px; color:#cbd5e1; font-size:12px; margin:24px 0; }
    .divider::before, .divider::after { content:''; flex:1; height:1px; background:#e5e7eb; }
    .otp-box { background:linear-gradient(135deg,rgba(102,126,234,0.05),rgba(118,75,162,0.03)); border:2px dashed rgba(102,126,234,0.3); border-radius:14px; padding:24px; text-align:center; }
    .otp-label { font-size:11px; color:#9ca3af; text-transform:uppercase; letter-spacing:1.5px; font-weight:600; margin-bottom:10px; }
    .otp-code { font-size:40px; font-weight:800; letter-spacing:10px; color:#1a1a2e; font-family:'Courier New',monospace; }
    .footer { padding:0 36px 32px; }
    .footer p { color:#9ca3af; font-size:12px; line-height:1.6; margin:0 0 6px; }
    .security-note { background:#f0fdf4; border:1px solid #86efac; border-radius:8px; padding:10px 14px; color:#166534; font-size:12px; font-weight:500; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="top-bar"></div>
      <div class="header">
        <div class="logo-badge">
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
        </div>
        <h1>Your Sign-In Link</h1>
        <p>Someone (hopefully you) requested to sign in to SecureAuth</p>
      </div>
      <div class="body">
        <p>Click the button below to sign in instantly, or use the 8-digit code on the login page.</p>

        <div>
          <span class="expiry-badge">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            Expires in ${expiryLabel}
          </span>
        </div>

        <div class="btn-wrap">
          <a href="${magicLink}" class="btn">Sign In Now</a>
        </div>

        <div class="divider">or enter the code manually</div>

        <div class="otp-box">
          <div class="otp-label">One-Time Code</div>
          <div class="otp-code">${otpFormatted}</div>
        </div>
      </div>
      <div class="footer">
        <div class="security-note" style="margin-bottom:14px;">
          This link can only be used once and expires in ${expiryLabel}. Do not share it.
        </div>
        <p>If you did not request this, you can safely ignore this email.</p>
        <p>Your account will not be affected unless you click the link or enter the code.</p>
      </div>
    </div>
  </div>
</body>
</html>`;

    const text = `Your SecureAuth Sign-In\n\nMagic Link: ${magicLink}\n\nOne-Time Code: ${otpFormatted}\n\nExpires in: ${expiryLabel}\n\nThis link is single-use. Do not share it. Ignore this email if you did not request it.`;

    await this.send({
      to,
      subject: `Your sign-in code: ${otpFormatted}`,
      html,
      text,
    });
  }

  async sendNewDeviceAlert(to: string, ip: string, userAgent: string): Promise<void> {
    const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { margin:0; padding:20px; background:#f1f5f9; font-family:Inter,Arial,sans-serif; }
    .card { max-width:500px; margin:0 auto; background:#fff; border-radius:16px; overflow:hidden; box-shadow:0 4px 16px rgba(0,0,0,0.08); }
    .top-bar { height:4px; background:linear-gradient(90deg,#ef4444,#f97316); }
    .body { padding:28px; }
    .alert-box { background:#fef2f2; border:1px solid #fca5a5; border-radius:10px; padding:14px 16px; color:#991b1b; font-size:14px; font-weight:600; margin-bottom:20px; }
    p { color:#374151; font-size:14px; line-height:1.6; margin:0 0 10px; }
    code { background:#f4f4f5; padding:2px 7px; border-radius:5px; font-size:13px; color:#1a1a2e; }
  </style>
</head>
<body>
  <div class="card">
    <div class="top-bar"></div>
    <div class="body">
      <div class="alert-box">New device sign-in detected</div>
      <p>Your account was accessed from a new device or IP address.</p>
      <p><strong>IP Address:</strong> <code>${ip}</code></p>
      <p><strong>Device:</strong> <code>${userAgent.substring(0, 100)}</code></p>
      <p>If this was you, no action is needed. If it was not you, contact support immediately.</p>
    </div>
  </div>
</body>
</html>`;

    await this.send({
      to,
      subject: 'New device sign-in detected',
      html,
      text: `New device sign-in detected.\nIP: ${ip}\nDevice: ${userAgent}\nIf this was not you, contact support.`,
    });
  }
}

export const emailService = new EmailService();
