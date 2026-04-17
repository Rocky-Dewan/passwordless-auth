import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

// 1. Attach unique request ID for tracing
export function requestId(req: Request, res: Response, next: NextFunction): void {
  const id = crypto.randomBytes(12).toString('hex');
  req.headers['x-request-id'] = id;
  res.setHeader('X-Request-Id', id);
  next();
}

// 2. Honeypot endpoint — any bot hitting /api/admin, /wp-admin, etc. gets logged
const honeypotPaths = [
  '/api/admin', '/admin', '/wp-admin', '/wp-login.php',
  '/.env', '/config', '/phpmyadmin', '/shell', '/backup',
];
export function honeypot(req: Request, res: Response, next: NextFunction): void {
  if (honeypotPaths.some(p => req.path.toLowerCase().startsWith(p))) {
    // Log and drop — don't reveal anything
    res.status(404).end();
    return;
  }
  next();
}

// 3. Block requests with suspicious headers often sent by scanners
export function blockScanners(req: Request, res: Response, next: NextFunction): void {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const scannerPatterns = ['sqlmap', 'nikto', 'nessus', 'masscan', 'zgrab', 'burpsuite', 'dirbuster', 'gobuster'];
  if (scannerPatterns.some(p => ua.includes(p))) {
    res.status(403).end();
    return;
  }
  next();
}

// 4. Remove headers that leak server info
export function scrubHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  next();
}
