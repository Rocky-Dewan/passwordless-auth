import { Request, Response, NextFunction } from 'express';
import { authService, SessionPayload } from '../../services/auth.service';

declare global {
  namespace Express {
    interface Request {
      user?: SessionPayload;
    }
  }
}

export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token = req.cookies?.session_token || req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }

  try {
    const payload = await authService.validateSession(token);
    req.user = payload;
    next();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Authentication failed.';
    res.status(401).json({ error: message });
  }
}
