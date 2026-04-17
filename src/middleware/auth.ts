import { Request, Response, NextFunction } from 'express';
import { authService, SessionPayload } from '../services/auth.service';

declare global {
  namespace Express {
    interface Request {
      user?: SessionPayload;
    }
  }
}

function getIp(req: Request): string {
  return (
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    '0.0.0.0'
  );
}

export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token =
    req.cookies?.session_token ||
    (req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.slice(7)
      : undefined);

  if (!token) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }

  const ctx = {
    ip: getIp(req),
    userAgent: (req.headers['user-agent'] || 'unknown').substring(0, 512),
  };

  try {
    req.user = await authService.validateSession(token, ctx);
    next();
  } catch (err: unknown) {
    res.clearCookie('session_token', { path: '/' });
    const message = err instanceof Error ? err.message : 'Invalid session.';
    res.status(401).json({ error: message });
  }
}
