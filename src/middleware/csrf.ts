import { Request, Response, NextFunction } from 'express';
import { config } from '../config';
import crypto from 'crypto';

const CSRF_COOKIE = 'csrf_token';
const CSRF_HEADER = 'x-csrf-token';
const SEP = '|';

function generateToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

function signToken(token: string): string {
  const sig = crypto.createHmac('sha256', config.csrf.secret).update(token).digest('hex');
  return `${token}${SEP}${sig}`;
}

function verifyToken(signed: string): string | null {
  const idx = signed.lastIndexOf(SEP);
  if (idx === -1) return null;
  const token = signed.substring(0, idx);
  const sig = signed.substring(idx + 1);
  if (!token || !sig) return null;
  const expected = crypto.createHmac('sha256', config.csrf.secret).update(token).digest('hex');
  if (sig.length !== expected.length) return null;
  const bufA = Buffer.from(sig, 'hex');
  const bufB = Buffer.from(expected, 'hex');
  try {
    if (!crypto.timingSafeEqual(bufA, bufB)) return null;
  } catch {
    return null;
  }
  return token;
}

export function csrfMiddleware(req: Request, res: Response, next: NextFunction): void {
  if (req.method === 'GET') {
    if (!req.cookies?.[CSRF_COOKIE]) {
      const token = generateToken();
      const signed = signToken(token);
      res.cookie(CSRF_COOKIE, signed, {
        httpOnly: false,
        sameSite: 'strict',
        secure: config.env === 'production',
        maxAge: 60 * 60 * 1000,
      });
    }
    next();
    return;
  }

  const cookieSigned = req.cookies?.[CSRF_COOKIE];
  const headerSigned = req.headers[CSRF_HEADER] as string | undefined;

  if (!cookieSigned || !headerSigned) {
    res.status(403).json({ error: 'CSRF token missing.' });
    return;
  }

  const cookieToken = verifyToken(cookieSigned);
  const headerToken = verifyToken(headerSigned);

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    res.status(403).json({ error: 'CSRF token invalid.' });
    return;
  }

  next();
}
