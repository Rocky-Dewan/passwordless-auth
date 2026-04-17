import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { authService } from '../services/auth.service';
import { rateLimiterService } from '../services/rateLimiter';
import { config } from '../config';
import { logger } from '../utils/logger';

function getIp(req: Request): string {
  return (
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    '0.0.0.0'
  );
}

function getCtx(req: Request) {
  return {
    ip: getIp(req),
    userAgent: (req.headers['user-agent'] || 'unknown').substring(0, 512),
  };
}

function isValidEmail(email: string): boolean {
  // RFC 5322 simplified - accepts any valid email including gmail, yahoo, custom
  return /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(email.trim());
}

function setCookieSession(res: Response, token: string): void {
  res.cookie('session_token', token, {
    httpOnly: true,
    secure: config.env === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  });
}

// GET /auth/csrf-token
// Always issue/refresh a signed CSRF token in a cookie and return it in JSON
export function getCsrfToken(req: Request, res: Response): void {
  // csrfMiddleware stores the signed token in res.locals.csrfSigned.
  // req.cookies has the *incoming* cookies; a freshly generated token is only
  // in res.locals until the browser receives the Set-Cookie header.
  const signed = (res.locals.csrfSigned as string | undefined) || req.cookies?.csrf_token || '';
  res.status(200).json({ csrfToken: signed });
}

// POST /auth/request
export async function requestAuth(req: Request, res: Response): Promise<void> {
  const raw = req.body?.email;
  const email = typeof raw === 'string' ? raw.trim().toLowerCase() : '';

  if (!email || !isValidEmail(email)) {
    res.status(400).json({ error: 'Please enter a valid email address.' });
    return;
  }

  const ctx = getCtx(req);

  const ipLimit = await rateLimiterService.checkIp(ctx.ip);
  if (!ipLimit.allowed) {
    res.status(429).json({ error: 'Too many requests from your IP. Please wait.', resetIn: ipLimit.resetIn });
    return;
  }

  const emailLimit = await rateLimiterService.checkEmail(email);
  if (!emailLimit.allowed) {
    res.status(429).json({ error: 'Too many login attempts for this email. Wait a few minutes.', resetIn: emailLimit.resetIn });
    return;
  }

  try {
    const sessionId = uuidv4();
    await authService.initiateAuthWithSessionId(email, sessionId, ctx);

    res.status(200).json({
      sessionId,
      message: 'Login email sent. Check your inbox.',
      expiresIn: config.auth.otpExpirySeconds,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    logger.warn('Auth request failed', { email, err: message });
    res.status(400).json({ error: message });
  }
}

// POST /auth/verify-otp
export async function verifyOtp(req: Request, res: Response): Promise<void> {
  const { sessionId, otp } = req.body as { sessionId?: string; otp?: string };

  if (!sessionId || typeof sessionId !== 'string' || sessionId.length > 64) {
    res.status(400).json({ error: 'Session ID is required.' });
    return;
  }
  if (!otp || !/^\d{8}$/.test(otp)) {
    res.status(400).json({ error: 'An 8-digit numeric code is required.' });
    return;
  }

  const ctx = getCtx(req);

  const otpLimit = await rateLimiterService.checkOtpAttempt(sessionId);
  if (!otpLimit.allowed) {
    res.status(429).json({ error: 'Too many attempts. Request a new login link.' });
    return;
  }

  try {
    const token = await authService.verifyOtp(sessionId, otp, ctx);
    setCookieSession(res, token);
    res.status(200).json({ success: true, message: 'Authenticated.' });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Verification failed.';
    res.status(401).json({ error: message });
  }
}

// GET /auth/verify-link  (magic link click from email)
export async function verifyMagicLink(req: Request, res: Response): Promise<void> {
  const { token, sid } = req.query as { token?: string; sid?: string };

  if (!token || typeof token !== 'string' || !sid || typeof sid !== 'string') {
    res.status(400).send(errorPage('Invalid or missing link parameters.'));
    return;
  }

  const ctx = getCtx(req);

  try {
    const sessionToken = await authService.verifyMagicLink(token, sid, ctx);
    setCookieSession(res, sessionToken);
    res.redirect('/dashboard');
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Link verification failed.';
    res.status(401).send(errorPage(message));
  }
}

// POST /auth/logout
export async function logout(req: Request, res: Response): Promise<void> {
  const ctx = getCtx(req);
  const user = req.user;

  if (user) {
    try {
      await authService.revokeSession(user.jti, ctx, user.sub);
    } catch (err) {
      logger.warn('Session revocation error', { err });
    }
  }

  res.clearCookie('session_token', { path: '/' });
  res.clearCookie('csrf_token', { path: '/' });
  res.status(200).json({ message: 'Logged out.' });
}

// GET /auth/me
export function getMe(req: Request, res: Response): void {
  if (!req.user) { res.status(401).json({ error: 'Not authenticated.' }); return; }
  res.status(200).json({ user: { id: req.user.sub, email: req.user.email } });
}

function errorPage(message: string): string {
  return `<!DOCTYPE html><html><head><title>Error</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:linear-gradient(135deg,#667eea,#764ba2)}
.box{background:#fff;padding:40px;border-radius:16px;text-align:center;max-width:400px;box-shadow:0 20px 60px rgba(0,0,0,.2)}
h1{color:#ef4444;font-size:20px;margin-bottom:12px}p{color:#6b7280;margin-bottom:20px}
a{display:inline-block;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;padding:10px 24px;border-radius:8px;text-decoration:none;font-weight:600}</style>
</head><body><div class="box"><h1>Authentication Failed</h1><p>${message}</p><a href="/">Request a new link</a></div></body></html>`;
}
