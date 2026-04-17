import { Request, Response, NextFunction } from 'express';
import { config } from '../config';
import crypto from 'crypto';

const CSRF_COOKIE = 'csrf_token';
const CSRF_HEADER = 'x-csrf-token';

// Generate a signed token: hex_random|hmac_sig
function generateSigned(): string {
  const token = crypto.randomBytes(32).toString('hex');
  const sig = crypto
    .createHmac('sha256', config.csrf.secret)
    .update(token)
    .digest('hex');
  return `${token}|${sig}`;
}

function isValidSigned(signed: string): boolean {
  const bar = signed.lastIndexOf('|');
  if (bar === -1) return false;
  const token = signed.substring(0, bar);
  const sig   = signed.substring(bar + 1);
  if (!token || sig.length !== 64) return false;
  const expected = crypto
    .createHmac('sha256', config.csrf.secret)
    .update(token)
    .digest('hex');
  // constant-time compare
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false;
  }
}

function setCsrfCookie(res: Response, signed: string): void {
  res.cookie(CSRF_COOKIE, signed, {
    httpOnly: false,       // must be readable by JS to send as header
    sameSite: 'lax',       // lax so it works on redirect-back from magic link
    secure: config.env === 'production',
    maxAge: 4 * 60 * 60 * 1000, // 4 hours
    path: '/',
  });
}

export function csrfMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Always ensure cookie exists on GET requests
  if (req.method === 'GET') {
    const existing = req.cookies?.[CSRF_COOKIE];
    if (!existing || !isValidSigned(existing)) {
      const newSigned = generateSigned();
      setCsrfCookie(res, newSigned);
      res.locals.csrfSigned = newSigned;   // <-- make it available to the handler
    } else {
      res.locals.csrfSigned = existing;    // <-- already-valid cookie
    }
    return next();
  }

  // For mutating methods, validate Double Submit
  const cookieSigned  = req.cookies?.[CSRF_COOKIE] as string | undefined;
  const headerSigned  = req.headers[CSRF_HEADER]   as string | undefined;

  if (!cookieSigned || !headerSigned) {
    res.status(403).json({ error: 'CSRF token missing.' });
    return;
  }

  if (!isValidSigned(cookieSigned) || !isValidSigned(headerSigned)) {
    res.status(403).json({ error: 'CSRF token tampered.' });
    return;
  }

  // Extract the bare token from each and compare
  const cookieToken = cookieSigned.substring(0, cookieSigned.lastIndexOf('|'));
  const headerToken = headerSigned.substring(0, headerSigned.lastIndexOf('|'));

  if (cookieToken !== headerToken) {
    res.status(403).json({ error: 'CSRF token mismatch.' });
    return;
  }

  next();
}
