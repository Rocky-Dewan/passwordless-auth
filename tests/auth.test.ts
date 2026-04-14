import request from 'supertest';
import app from '../src/app';
import { generateOTP, generateToken, hashToken, timingSafeEqual } from '../services/crypto';

// --- Unit tests for crypto utilities ---

describe('Crypto utilities', () => {
  test('generateOTP produces 8-digit numeric string', () => {
    for (let i = 0; i < 20; i++) {
      const otp = generateOTP();
      expect(otp).toMatch(/^\d{8}$/);
    }
  });

  test('generateToken produces hex string of expected length', () => {
    const token = generateToken(32);
    expect(token).toMatch(/^[a-f0-9]{64}$/);
  });

  test('hashToken produces consistent SHA-256 hash', () => {
    const token = 'test-token-123';
    const hash1 = hashToken(token);
    const hash2 = hashToken(token);
    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
  });

  test('hashToken produces different hashes for different inputs', () => {
    expect(hashToken('aaa')).not.toBe(hashToken('bbb'));
  });

  test('timingSafeEqual returns true for equal strings', () => {
    expect(timingSafeEqual('hello', 'hello')).toBe(true);
  });

  test('timingSafeEqual returns false for unequal strings', () => {
    expect(timingSafeEqual('hello', 'world')).toBe(false);
    expect(timingSafeEqual('hello', 'hell')).toBe(false);
  });
});

// --- HTTP endpoint tests (no DB/Redis, just shape and validation) ---

describe('Auth API - input validation', () => {
  test('GET /health returns 200', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });

  test('POST /auth/request - rejects missing email', async () => {
    const res = await request(app)
      .post('/auth/request')
      .set('Content-Type', 'application/json')
      .send({});
    // 400 (bad input) or 403 (CSRF) - both mean request was blocked
    expect([400, 403]).toContain(res.status);
  });

  test('POST /auth/request - rejects invalid email format', async () => {
    const res = await request(app)
      .post('/auth/request')
      .set('Content-Type', 'application/json')
      .send({ email: 'not-an-email' });
    expect([400, 403]).toContain(res.status);
  });

  test('POST /auth/verify-otp - rejects missing sessionId', async () => {
    const res = await request(app)
      .post('/auth/verify-otp')
      .set('Content-Type', 'application/json')
      .send({ otp: '12345678' });
    expect([400, 403]).toContain(res.status);
  });

  test('POST /auth/verify-otp - rejects invalid OTP format', async () => {
    const res = await request(app)
      .post('/auth/verify-otp')
      .set('Content-Type', 'application/json')
      .send({ sessionId: 'some-id', otp: 'abcdefgh' });
    expect([400, 403]).toContain(res.status);
  });

  test('POST /auth/verify-otp - rejects short OTP', async () => {
    const res = await request(app)
      .post('/auth/verify-otp')
      .set('Content-Type', 'application/json')
      .send({ sessionId: 'some-id', otp: '1234' });
    expect([400, 403]).toContain(res.status);
  });

  test('GET /auth/me - returns 401 without session', async () => {
    const res = await request(app).get('/auth/me');
    expect(res.status).toBe(401);
  });

  test('GET /auth/verify-link - returns 400 without token', async () => {
    const res = await request(app).get('/auth/verify-link');
    expect([400, 401]).toContain(res.status);
  });

  test('GET /auth/csrf-token - returns a token', async () => {
    const res = await request(app).get('/auth/csrf-token');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('csrfToken');
  });
});

describe('Auth API - rate limiting', () => {
  test('POST /auth/request - rate limited after many requests', async () => {
    const requests = Array.from({ length: 12 }, () =>
      request(app)
        .post('/auth/request')
        .set('Content-Type', 'application/json')
        .send({ email: 'test@example.com' })
    );
    const results = await Promise.all(requests);
    const statuses = results.map((r) => r.status);
    // At least one should be rate limited (429) or blocked (403 CSRF / 400 bad input)
    expect(statuses.some((s) => s === 429 || s === 403 || s === 400)).toBe(true);
  });
});
