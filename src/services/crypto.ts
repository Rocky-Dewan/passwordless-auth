import crypto from 'crypto';

export function generateOTP(): string {
  // Cryptographically random 8-digit number, uniform distribution
  const buf = crypto.randomBytes(4);
  const num = buf.readUInt32BE(0) % 100_000_000;
  return num.toString().padStart(8, '0');
}

export function generateToken(bytes = 40): string {
  return crypto.randomBytes(bytes).toString('hex');
}

export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function timingSafeStringEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
