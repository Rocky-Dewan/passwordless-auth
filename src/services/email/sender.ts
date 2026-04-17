import nodemailer, { Transporter, SentMessageInfo } from 'nodemailer';
import { config } from '../../config';
import { logger } from '../../utils/logger';

interface MailOptions { to: string; subject: string; html: string; text: string; }

class EmailService {
  private transporter: Transporter | null = null;

  private async getTransporter(): Promise<Transporter> {
    if (this.transporter) return this.transporter;

    if (config.email.user && config.email.pass) {
      // Real SMTP — Brevo or any provider
      this.transporter = nodemailer.createTransport({
        host:   config.email.host,
        port:   config.email.port,
        secure: config.email.secure,
        auth:   { user: config.email.user, pass: config.email.pass },
        tls:    { rejectUnauthorized: false },
        connectionTimeout: 10_000,
        greetingTimeout:   10_000,
      });
      logger.info('Email transport configured', { host: config.email.host, user: config.email.user });
    } else {
      // Dev fallback — Ethereal fake SMTP (no config needed)
      const acct = await nodemailer.createTestAccount();
      this.transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email', port: 587, secure: false,
        auth: { user: acct.user, pass: acct.pass },
      });
      logger.info('DEV: Ethereal test account created', {
        user: acct.user, pass: acct.pass, preview: 'https://ethereal.email',
      });
    }
    return this.transporter;
  }

  private async send(opts: MailOptions): Promise<void> {
    const t    = await this.getTransporter();
    const info: SentMessageInfo = await t.sendMail({
      from:    `"SecureAuth" <${config.email.from}>`,
      to:      opts.to,
      subject: opts.subject,
      html:    opts.html,
      text:    opts.text,
    });

    const preview = nodemailer.getTestMessageUrl(info);
    if (preview) {
      logger.info('DEV email preview', { url: preview, to: opts.to });
    } else {
      logger.info('Email sent', { to: opts.to, messageId: info.messageId });
    }
  }

  async sendMagicLink(to: string, magicLink: string, otp: string, expirySec: number): Promise<void> {
    const otpFmt  = `${otp.slice(0,4)}-${otp.slice(4)}`;
    const mins    = Math.floor(expirySec / 60);
    const secs    = expirySec % 60;
    const expLabel = mins > 0 ? `${mins}m ${secs > 0 ? secs+'s' : ''}`.trim() : `${secs}s`;

    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign In</title>
<style>
 @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');
 *{box-sizing:border-box;margin:0;padding:0}
 body{font-family:'Inter',Arial,sans-serif;background:#f1f5f9;padding:40px 16px}
 .wrap{max-width:520px;margin:0 auto}
 .card{background:#fff;border-radius:20px;overflow:hidden;box-shadow:0 8px 40px rgba(102,126,234,.15)}
 .bar{height:5px;background:linear-gradient(90deg,#667eea,#764ba2,#f093fb)}
 .hdr{padding:32px 36px 24px;text-align:center;background:linear-gradient(135deg,rgba(102,126,234,.07),rgba(118,75,162,.05));border-bottom:1px solid #e8eaf6}
 .logo{display:inline-flex;align-items:center;justify-content:center;width:54px;height:54px;background:linear-gradient(135deg,#667eea,#764ba2);border-radius:14px;margin-bottom:14px}
 h1{font-size:21px;font-weight:800;color:#1a1a2e;margin-bottom:5px}
 .sub{font-size:13px;color:#6b7280}
 .body{padding:28px 36px}
 p{font-size:14px;color:#374151;line-height:1.7;margin-bottom:16px}
 .badge{display:inline-flex;align-items:center;gap:6px;background:#fffbeb;border:1px solid #fbbf24;border-radius:8px;padding:7px 13px;color:#92400e;font-size:13px;font-weight:600;margin-bottom:22px}
 .btn-wrap{text-align:center;margin:22px 0}
 .btn{display:inline-block;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff!important;text-decoration:none;padding:14px 38px;border-radius:12px;font-weight:700;font-size:15px;box-shadow:0 4px 14px rgba(102,126,234,.4)}
 .div{display:flex;align-items:center;gap:10px;color:#d1d5db;font-size:12px;margin:20px 0}
 .div::before,.div::after{content:'';flex:1;height:1px;background:#e5e7eb}
 .otp{background:linear-gradient(135deg,rgba(102,126,234,.06),rgba(118,75,162,.04));border:2px dashed rgba(102,126,234,.25);border-radius:14px;padding:22px;text-align:center}
 .otp-lbl{font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:1.5px;font-weight:600;margin-bottom:8px}
 .otp-code{font-size:38px;font-weight:800;letter-spacing:8px;color:#1a1a2e;font-family:'Courier New',monospace}
 .footer{padding:0 36px 28px;border-top:1px solid #f1f5f9;margin-top:8px}
 .note{background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:10px 14px;color:#166534;font-size:12px;font-weight:500;margin:18px 0 14px}
 .fine{font-size:12px;color:#9ca3af;line-height:1.6}
</style></head><body>
<div class="wrap"><div class="card">
 <div class="bar"></div>
 <div class="hdr">
  <div class="logo">
   <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
  </div>
  <h1>Sign in to SecureAuth</h1>
  <p class="sub">Requested from ${to}</p>
 </div>
 <div class="body">
  <p>Click the button to sign in instantly, or enter the 8-digit code manually.</p>
  <span class="badge">
   <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
   Expires in ${expLabel}
  </span>
  <div class="btn-wrap"><a href="${magicLink}" class="btn">Sign In Now</a></div>
  <div class="div">or enter code manually</div>
  <div class="otp">
   <div class="otp-lbl">One-Time Code</div>
   <div class="otp-code">${otpFmt}</div>
  </div>
 </div>
 <div class="footer">
  <div class="note">Single use only. Do not share this link or code with anyone.</div>
  <p class="fine">If you didn't request this sign-in, ignore this email. Your account is safe.</p>
 </div>
</div></div></body></html>`;

    const text = `SecureAuth Sign-In\n\nLink: ${magicLink}\nCode: ${otpFmt}\nExpires: ${expLabel}\n\nDo not share this. Ignore if you didn't request it.`;
    await this.send({ to, subject: `Your sign-in code: ${otpFmt}`, html, text });
  }

  async sendNewDeviceAlert(to: string, ip: string, ua: string): Promise<void> {
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{font-family:sans-serif;padding:30px;background:#f1f5f9}.card{max-width:480px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.08)}.bar{height:4px;background:linear-gradient(90deg,#ef4444,#f97316)}.body{padding:28px}.alert{background:#fef2f2;border:1px solid #fca5a5;border-radius:10px;padding:14px;color:#991b1b;font-size:14px;font-weight:600;margin-bottom:18px}p{color:#374151;font-size:14px;line-height:1.6;margin-bottom:10px}code{background:#f4f4f5;padding:2px 7px;border-radius:5px;font-size:13px}</style></head><body>
<div class="card"><div class="bar"></div><div class="body">
<div class="alert">New device sign-in detected</div>
<p>A sign-in to your SecureAuth account was completed from an unrecognised device.</p>
<p><strong>IP:</strong> <code>${ip}</code></p>
<p><strong>Device:</strong> <code>${ua.substring(0,120)}</code></p>
<p>If this was you, no action needed. If not, contact support immediately.</p>
</div></div></body></html>`;
    await this.send({ to, subject: 'New device sign-in — SecureAuth', html, text: `New device sign-in.\nIP: ${ip}\nDevice: ${ua}` });
  }
}

export const emailService = new EmailService();
