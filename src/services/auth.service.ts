import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { AppDataSource } from '../utils/database';
import { User } from '../models/user.model';
import { AuditLog, AuditAction } from '../models/audit.model';
import { redisService } from './redis.service';
import { emailService } from './email/sender';
import { generateOTP, generateToken, hashToken } from './crypto';
import { config } from '../config';
import { logger } from '../utils/logger';

export interface AuthRequestContext {
  ip: string;
  userAgent: string;
}

export interface SessionPayload {
  sub: string;
  jti: string;
  email: string;
  fprint: string;   // request fingerprint bound to session
  iat?: number;
  exp?: number;
}

// Key prefixes in Redis
const K = {
  OTP:     (sid: string) => `auth:otp:${sid}`,
  LINK:    (h: string)   => `auth:link:${h}`,
  SESSION: (jti: string) => `auth:sess:${jti}`,
  FAIL:    (uid: string) => `auth:fail:${uid}`,
  BLOCK:   (uid: string) => `auth:block:${uid}`,
};

// Compute a lightweight session fingerprint from IP + UA
function fingerprint(ctx: AuthRequestContext): string {
  return crypto
    .createHash('sha256')
    .update(`${ctx.ip}::${ctx.userAgent}::${config.jwt.secret}`)
    .digest('hex')
    .slice(0, 32);
}

class AuthService {
  private get userRepo()  { return AppDataSource.getRepository(User); }
  private get auditRepo() { return AppDataSource.getRepository(AuditLog); }

  private async audit(
    action: AuditAction,
    success: boolean,
    ctx: AuthRequestContext,
    userId?: string | null,
    metadata?: Record<string, unknown>
  ): Promise<void> {
    try {
      await this.auditRepo.save(
        this.auditRepo.create({ userId: userId ?? null, action, success, ip: ctx.ip, userAgent: ctx.userAgent, metadata: metadata ?? null })
      );
    } catch (err) {
      logger.error('Audit log failed', { err });
    }
  }

  async findOrCreateUser(email: string): Promise<User> {
    let user = await this.userRepo.findOne({ where: { email } });
    if (!user) {
      user = this.userRepo.create({ email, isActive: true, isVerified: false });
      await this.userRepo.save(user);
      logger.info('New user registered', { email });
    }
    return user;
  }

  async initiateAuthWithSessionId(
    email: string,
    sessionId: string,
    ctx: AuthRequestContext
  ): Promise<void> {
    const user = await this.findOrCreateUser(email);

    if (!user.isActive) {
      await this.audit('AUTH_REQUEST', false, ctx, user.id, { reason: 'inactive' });
      throw new Error('Account is inactive. Contact support.');
    }

    // Check Redis-level lockout (faster than DB)
    const blocked = await redisService.get(K.BLOCK(user.id));
    if (blocked) {
      await this.audit('AUTH_REQUEST', false, ctx, user.id, { reason: 'rate_blocked' });
      throw new Error('Too many failed attempts. Account locked for 15 minutes.');
    }

    if (user.isLocked) {
      await this.audit('AUTH_REQUEST', false, ctx, user.id, { reason: 'db_locked' });
      throw new Error('Account temporarily locked. Try again later.');
    }

    const otp        = generateOTP();
    const linkToken  = generateToken(40);
    const expiry     = config.auth.otpExpirySeconds;

    await redisService.set(
      K.OTP(sessionId),
      JSON.stringify({ hashedOtp: hashToken(otp), userId: user.id, email: user.email }),
      expiry
    );
    await redisService.set(
      K.LINK(hashToken(linkToken)),
      JSON.stringify({ sessionId, userId: user.id, email: user.email }),
      expiry
    );

    const magicLink = `${config.baseUrl}/auth/verify-link?token=${linkToken}&sid=${sessionId}`;

    await emailService.sendMagicLink(user.email, magicLink, otp, expiry);
    await this.audit('AUTH_REQUEST', true, ctx, user.id, { sessionId });
    logger.info('Auth initiated', { userId: user.id });
  }

  async verifyOtp(sessionId: string, otp: string, ctx: AuthRequestContext): Promise<string> {
    const raw = await redisService.get(K.OTP(sessionId));
    if (!raw) {
      await this.audit('AUTH_OTP_FAILED', false, ctx, null, { reason: 'expired', sessionId });
      throw new Error('Code expired or already used. Request a new login link.');
    }

    const { hashedOtp, userId, email } = JSON.parse(raw) as {
      hashedOtp: string; userId: string; email: string;
    };

    if (hashToken(otp) !== hashedOtp) {
      await this.recordFailure(userId, ctx);
      await this.audit('AUTH_OTP_FAILED', false, ctx, userId, { reason: 'wrong_otp' });
      throw new Error('Incorrect code. Please check your email and try again.');
    }

    await redisService.del(K.OTP(sessionId));
    const token = await this.createSession(userId, email, ctx);
    await this.audit('AUTH_OTP_VERIFIED', true, ctx, userId);
    await this.postLogin(userId, email, ctx);
    return token;
  }

  async verifyMagicLink(linkToken: string, sessionId: string, ctx: AuthRequestContext): Promise<string> {
    const key = K.LINK(hashToken(linkToken));
    const raw = await redisService.get(key);
    if (!raw) {
      await this.audit('AUTH_LINK_EXPIRED', false, ctx, null, { reason: 'expired' });
      throw new Error('Link expired or already used. Please request a new one.');
    }

    const { sessionId: storedSid, userId, email } = JSON.parse(raw) as {
      sessionId: string; userId: string; email: string;
    };

    if (storedSid !== sessionId) {
      await this.audit('AUTH_LINK_EXPIRED', false, ctx, userId, { reason: 'sid_mismatch' });
      throw new Error('Invalid link parameters.');
    }

    // Consume both link and OTP atomically
    await redisService.del(key);
    await redisService.del(K.OTP(sessionId));

    const token = await this.createSession(userId, email, ctx);
    await this.audit('AUTH_LINK_USED', true, ctx, userId);
    await this.postLogin(userId, email, ctx);
    return token;
  }

  private async createSession(userId: string, email: string, ctx: AuthRequestContext): Promise<string> {
    const jti    = uuidv4();
    const fprint = fingerprint(ctx);
    const payload: SessionPayload = { sub: userId, jti, email, fprint };

    const token = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiry,
      algorithm: 'HS512',   // stronger than default HS256
    } as jwt.SignOptions);

    // Store in Redis with 7-day TTL
    await redisService.set(
      K.SESSION(jti),
      JSON.stringify({ userId, fprint, createdAt: Date.now() }),
      60 * 60 * 24 * 7
    );

    await this.audit('SESSION_CREATED', true, ctx, userId, { jti });
    return token;
  }

  async validateSession(token: string, ctx?: AuthRequestContext): Promise<SessionPayload> {
    let payload: SessionPayload;
    try {
      payload = jwt.verify(token, config.jwt.secret, {
        algorithms: ['HS512'],
      }) as SessionPayload;
    } catch {
      throw new Error('Invalid or expired session.');
    }

    const stored = await redisService.get(K.SESSION(payload.jti));
    if (!stored) throw new Error('Session revoked or expired.');

    // Fingerprint check — detects token theft across different IP/UA
    if (ctx) {
      const expectedFprint = fingerprint(ctx);
      const { fprint: storedFprint } = JSON.parse(stored) as { fprint: string };
      if (storedFprint !== expectedFprint) {
        // Revoke immediately
        await redisService.del(K.SESSION(payload.jti));
        await this.audit('SUSPICIOUS_LOGIN', false, ctx, payload.sub, { reason: 'fingerprint_mismatch' });
        throw new Error('Session invalid. Please log in again.');
      }
    }

    return payload;
  }

  async revokeSession(jti: string, ctx: AuthRequestContext, userId: string): Promise<void> {
    await redisService.del(K.SESSION(jti));
    await this.audit('SESSION_REVOKED', true, ctx, userId, { jti });
  }

  private async recordFailure(userId: string, ctx: AuthRequestContext): Promise<void> {
    const failKey = K.FAIL(userId);
    const count = await redisService.incr(failKey);
    if (count === 1) await redisService.expire(failKey, 900); // 15 min window

    if (count >= config.auth.maxLoginAttempts) {
      // Lock in Redis for 15 minutes
      await redisService.set(K.BLOCK(userId), '1', config.auth.lockoutDurationMinutes * 60);
      await redisService.del(failKey);
      await this.audit('ACCOUNT_LOCKED', false, ctx, userId, { attempts: count });

      // Also persist to DB
      const user = await this.userRepo.findOne({ where: { id: userId } });
      if (user) {
        user.lockedUntil = new Date(Date.now() + config.auth.lockoutDurationMinutes * 60 * 1000);
        user.failedLoginAttempts = count;
        await this.userRepo.save(user);
      }
    }
  }

  private async postLogin(userId: string, email: string, ctx: AuthRequestContext): Promise<void> {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) return;

    const isNewDevice = user.lastLoginIp !== ctx.ip || user.lastLoginUserAgent !== ctx.userAgent;

    if (isNewDevice && user.lastLoginAt) {
      await this.audit('SUSPICIOUS_LOGIN', true, ctx, userId, { prevIp: user.lastLoginIp, newIp: ctx.ip });
      emailService.sendNewDeviceAlert(email, ctx.ip, ctx.userAgent).catch(() => {});
    }

    user.lastLoginAt          = new Date();
    user.lastLoginIp          = ctx.ip;
    user.lastLoginUserAgent   = ctx.userAgent;
    user.isVerified           = true;
    user.failedLoginAttempts  = 0;
    user.lockedUntil          = null;
    await this.userRepo.save(user);
  }
}

export const authService = new AuthService();
