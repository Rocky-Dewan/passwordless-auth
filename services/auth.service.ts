import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { AppDataSource } from '../src/utils/database';
import { User } from '../src/models/user.model';
import { AuditLog, AuditAction } from '../src/models/audit.model';
import { redisService } from './redis.service';
import { emailService } from './email/sender';
import { generateOTP, generateToken, hashToken } from './crypto';
import { config } from '../src/config';
import { logger } from '../src/utils/logger';

export interface AuthRequestContext {
  ip: string;
  userAgent: string;
}

export interface SessionPayload {
  sub: string;
  jti: string;
  email: string;
  iat?: number;
  exp?: number;
}

const OTP_PREFIX = 'auth:otp:';
const LINK_PREFIX = 'auth:link:';
const SESSION_PREFIX = 'auth:session:';

class AuthService {
  private get userRepo() {
    return AppDataSource.getRepository(User);
  }

  private get auditRepo() {
    return AppDataSource.getRepository(AuditLog);
  }

  private async audit(
    action: AuditAction,
    success: boolean,
    ctx: AuthRequestContext,
    userId?: string | null,
    metadata?: Record<string, unknown>
  ): Promise<void> {
    try {
      const log = this.auditRepo.create({
        userId: userId || null,
        action,
        success,
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: metadata || null,
      });
      await this.auditRepo.save(log);
    } catch (err) {
      logger.error('Audit log failed', { err });
    }
  }

  async findOrCreateUser(email: string): Promise<User> {
    const normalized = email.toLowerCase().trim();
    let user = await this.userRepo.findOne({ where: { email: normalized } });
    if (!user) {
      user = this.userRepo.create({
        email: normalized,
        isActive: true,
        isVerified: false,
      });
      await this.userRepo.save(user);
      logger.info('New user created', { email: normalized });
    }
    return user;
  }

  async initiateAuth(email: string, ctx: AuthRequestContext): Promise<void> {
    const sessionId = uuidv4();
    await this.initiateAuthWithSessionId(email, sessionId, ctx);
  }

  async initiateAuthWithSessionId(
    email: string,
    sessionId: string,
    ctx: AuthRequestContext
  ): Promise<void> {
    const user = await this.findOrCreateUser(email);

    if (!user.isActive) {
      await this.audit('AUTH_REQUEST', false, ctx, user.id, { reason: 'account_inactive' });
      throw new Error('Account is inactive.');
    }

    if (user.isLocked) {
      await this.audit('AUTH_REQUEST', false, ctx, user.id, { reason: 'account_locked' });
      throw new Error(
        `Account is temporarily locked. Try again in ${config.auth.lockoutDurationMinutes} minutes.`
      );
    }

    const otp = generateOTP();
    const linkToken = generateToken(32);
    const hashedOtp = hashToken(otp);
    const hashedLinkToken = hashToken(linkToken);
    const expiry = config.auth.otpExpirySeconds;

    const otpKey = `${OTP_PREFIX}${sessionId}`;
    const linkKey = `${LINK_PREFIX}${hashedLinkToken}`;

    await redisService.set(
      otpKey,
      JSON.stringify({ hashedOtp, userId: user.id, email: user.email }),
      expiry
    );
    await redisService.set(
      linkKey,
      JSON.stringify({ sessionId, userId: user.id, email: user.email }),
      expiry
    );

    const magicLink = `${config.baseUrl}/auth/verify-link?token=${linkToken}&sid=${sessionId}`;

    await emailService.sendMagicLink(user.email, magicLink, otp, expiry);
    await this.audit('AUTH_REQUEST', true, ctx, user.id, { sessionId });

    logger.info('Auth initiated', { userId: user.id, sessionId });
  }

  async verifyOtp(
    sessionId: string,
    otp: string,
    ctx: AuthRequestContext
  ): Promise<string> {
    const otpKey = `${OTP_PREFIX}${sessionId}`;
    const raw = await redisService.get(otpKey);

    if (!raw) {
      await this.audit('AUTH_OTP_FAILED', false, ctx, null, {
        reason: 'expired_or_invalid',
        sessionId,
      });
      throw new Error('OTP expired or invalid. Please request a new login link.');
    }

    const { hashedOtp, userId, email } = JSON.parse(raw) as {
      hashedOtp: string;
      userId: string;
      email: string;
    };

    const hashedInput = hashToken(otp);

    if (hashedInput !== hashedOtp) {
      await this.audit('AUTH_OTP_FAILED', false, ctx, userId, {
        reason: 'wrong_otp',
        sessionId,
      });
      throw new Error('Incorrect OTP. Please check the code in your email.');
    }

    await redisService.del(otpKey);

    const token = await this.createSession(userId, email, ctx);
    await this.audit('AUTH_OTP_VERIFIED', true, ctx, userId, { sessionId });
    await this.handlePostLogin(userId, email, ctx);

    return token;
  }

  async verifyMagicLink(
    linkToken: string,
    sessionId: string,
    ctx: AuthRequestContext
  ): Promise<string> {
    const hashedLinkToken = hashToken(linkToken);
    const linkKey = `${LINK_PREFIX}${hashedLinkToken}`;
    const raw = await redisService.get(linkKey);

    if (!raw) {
      await this.audit('AUTH_LINK_EXPIRED', false, ctx, null, {
        reason: 'expired_or_invalid',
      });
      throw new Error('Magic link expired or already used. Please request a new one.');
    }

    const {
      sessionId: storedSid,
      userId,
      email,
    } = JSON.parse(raw) as {
      sessionId: string;
      userId: string;
      email: string;
    };

    if (storedSid !== sessionId) {
      await this.audit('AUTH_LINK_EXPIRED', false, ctx, userId, {
        reason: 'session_mismatch',
      });
      throw new Error('Invalid magic link.');
    }

    await redisService.del(linkKey);
    await redisService.del(`${OTP_PREFIX}${sessionId}`);

    const token = await this.createSession(userId, email, ctx);
    await this.audit('AUTH_LINK_USED', true, ctx, userId);
    await this.handlePostLogin(userId, email, ctx);

    return token;
  }

  private async createSession(
    userId: string,
    email: string,
    ctx: AuthRequestContext
  ): Promise<string> {
    const jti = uuidv4();
    const payload: SessionPayload = { sub: userId, jti, email };

    const token = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiry,
    } as jwt.SignOptions);

    const sessionKey = `${SESSION_PREFIX}${jti}`;
    await redisService.set(sessionKey, userId, 60 * 60 * 24 * 7);

    await this.audit('SESSION_CREATED', true, ctx, userId, { jti });
    logger.info('Session created', { userId, jti });

    return token;
  }

  async validateSession(token: string): Promise<SessionPayload> {
    let payload: SessionPayload;

    try {
      payload = jwt.verify(token, config.jwt.secret) as SessionPayload;
    } catch {
      throw new Error('Invalid or expired session token.');
    }

    const sessionKey = `${SESSION_PREFIX}${payload.jti}`;
    const exists = await redisService.exists(sessionKey);

    if (!exists) {
      throw new Error('Session has been revoked.');
    }

    return payload;
  }

  async revokeSession(
    jti: string,
    ctx: AuthRequestContext,
    userId: string
  ): Promise<void> {
    const sessionKey = `${SESSION_PREFIX}${jti}`;
    await redisService.del(sessionKey);
    await this.audit('SESSION_REVOKED', true, ctx, userId, { jti });
    logger.info('Session revoked', { userId, jti });
  }

  private async handlePostLogin(
    userId: string,
    email: string,
    ctx: AuthRequestContext
  ): Promise<void> {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) return;

    const isNewDevice =
      user.lastLoginIp !== ctx.ip || user.lastLoginUserAgent !== ctx.userAgent;

    if (isNewDevice && user.lastLoginAt) {
      await this.audit('SUSPICIOUS_LOGIN', true, ctx, userId, {
        previousIp: user.lastLoginIp,
        newIp: ctx.ip,
      });
      await emailService.sendNewDeviceAlert(email, ctx.ip, ctx.userAgent).catch(() => {});
    }

    user.lastLoginAt = new Date();
    user.lastLoginIp = ctx.ip;
    user.lastLoginUserAgent = ctx.userAgent;
    user.isVerified = true;
    user.failedLoginAttempts = 0;
    user.lockedUntil = null;

    await this.userRepo.save(user);
  }
}

export const authService = new AuthService();
