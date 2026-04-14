import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { authService } from '../../services/auth.service';
import { rateLimiterService } from '../../services/rateLimiter';
import { config } from '../config';
import { logger } from '../utils/logger';

function getIp(req: Request): string {
  return (
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.socket.remoteAddress ||
    'unknown'
  );
}

function getCtx(req: Request) {
  return { ip: getIp(req), userAgent: req.headers['user-agent'] || 'unknown' };
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function setCookieSession(res: Response, token: string): void {
  res.cookie('session_token', token, {
    httpOnly: true,
    secure: config.env === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  });
}

// POST /auth/request
export async function requestAuth(req: Request, res: Response): Promise<void> {
  const { email } = req.body;

  if (!email || typeof email !== 'string' || !isValidEmail(email)) {
    res.status(400).json({ error: 'A valid email address is required.' });
    return;
  }

  const ctx = getCtx(req);

  const emailLimit = await rateLimiterService.checkEmail(email);
  if (!emailLimit.allowed) {
    res.status(429).json({
      error: 'Too many login requests for this email. Wait a few minutes.',
      resetIn: emailLimit.resetIn,
    });
    return;
  }

  try {
    const sessionId = uuidv4();
    await authService.initiateAuthWithSessionId(email, sessionId, ctx);

    res.status(200).json({
      sessionId,
      message: 'Check your inbox for the magic link and 8-digit code.',
      expiresIn: config.auth.otpExpirySeconds,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    logger.warn('Auth initiation failed', { email, err: message });
    res.status(400).json({ error: message });
  }
}

// POST /auth/verify-otp
export async function verifyOtp(req: Request, res: Response): Promise<void> {
  const { sessionId, otp } = req.body;

  if (!sessionId || typeof sessionId !== 'string') {
    res.status(400).json({ error: 'Session ID is required.' });
    return;
  }
  if (!otp || typeof otp !== 'string' || !/^\d{8}$/.test(otp)) {
    res.status(400).json({ error: 'A valid 8-digit OTP is required.' });
    return;
  }

  const ctx = getCtx(req);
  const otpLimit = await rateLimiterService.checkOtpAttempt(sessionId);
  if (!otpLimit.allowed) {
    res.status(429).json({ error: 'Too many OTP attempts. Request a new code.' });
    return;
  }

  try {
    const token = await authService.verifyOtp(sessionId, otp, ctx);
    setCookieSession(res, token);
    res.status(200).json({ message: 'Login successful.', token });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Verification failed.';
    res.status(401).json({ error: message });
  }
}

// GET /auth/verify-link
export async function verifyMagicLink(req: Request, res: Response): Promise<void> {
  const { token, sid } = req.query;

  if (!token || typeof token !== 'string' || !sid || typeof sid !== 'string') {
    res.status(400).send(renderErrorPage('Invalid or missing link parameters.'));
    return;
  }

  const ctx = getCtx(req);

  try {
    const sessionToken = await authService.verifyMagicLink(token, sid, ctx);
    setCookieSession(res, sessionToken);
    res.redirect('/dashboard');
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Link verification failed.';
    res.status(401).send(renderErrorPage(message));
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
      logger.warn('Session revocation error on logout', { err });
    }
  }

  res.clearCookie('session_token');
  res.clearCookie('csrf_token');
  res.status(200).json({ message: 'Logged out successfully.' });
}

// GET /auth/me
export async function getMe(req: Request, res: Response): Promise<void> {
  res.status(200).json({ user: { id: req.user?.sub, email: req.user?.email } });
}

// GET /auth/csrf-token
export async function getCsrfToken(req: Request, res: Response): Promise<void> {
  const token = req.cookies?.csrf_token || '';
  res.status(200).json({ csrfToken: token });
}

function renderErrorPage(message: string): string {
  return `<!DOCTYPE html>
<html>
<head>
  <title>Authentication Error</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f4f4f5}
    .box{background:#fff;padding:40px;border-radius:12px;text-align:center;max-width:400px;box-shadow:0 2px 12px rgba(0,0,0,.1)}
    h1{color:#dc2626;font-size:20px}p{color:#52525b}a{color:#18181b;font-weight:600}
  </style>
</head>
<body>
  <div class="box">
    <h1>Authentication Failed</h1>
    <p>${message}</p>
    <p><a href="/">Request a new link</a></p>
  </div>
</body>
</html>`;
}
