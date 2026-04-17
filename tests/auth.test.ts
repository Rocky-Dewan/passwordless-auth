import request from 'supertest';
import app from '../src/app';
import { generateOTP, generateToken, hashToken, timingSafeStringEqual } from '../src/services/crypto';

describe('Crypto utilities', () => {
  test('generateOTP produces 8-digit numeric string', () => {
    for (let i = 0; i < 30; i++) {
      const otp = generateOTP();
      expect(otp).toMatch(/^\d{8}$/);
      expect(otp.length).toBe(8);
    }
  });

  test('generateOTP values are statistically distributed', () => {
    const set = new Set(Array.from({ length: 50 }, () => generateOTP()));
    expect(set.size).toBeGreaterThan(40); // should not repeat
  });

  test('generateToken produces hex string', () => {
    const t = generateToken(32);
    expect(t).toMatch(/^[a-f0-9]{64}$/);
  });

  test('hashToken is deterministic', () => {
    expect(hashToken('abc')).toBe(hashToken('abc'));
    expect(hashToken('abc').length).toBe(64);
  });

  test('hashToken differs for different inputs', () => {
    expect(hashToken('aaa')).not.toBe(hashToken('bbb'));
  });

  test('timingSafeStringEqual works correctly', () => {
    expect(timingSafeStringEqual('hello', 'hello')).toBe(true);
    expect(timingSafeStringEqual('hello', 'world')).toBe(false);
    expect(timingSafeStringEqual('a', 'ab')).toBe(false);
  });
});

describe('HTTP endpoints — validation & shape', () => {
  test('GET /health returns 200', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });

  test('GET /auth/csrf-token returns a token', async () => {
    const res = await request(app).get('/auth/csrf-token');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('csrfToken');
    expect(typeof res.body.csrfToken).toBe('string');
    expect(res.body.csrfToken.length).toBeGreaterThan(10);
  });

  test('POST /auth/request without CSRF returns 403', async () => {
    const res = await request(app)
      .post('/auth/request')
      .set('Content-Type', 'application/json')
      .send({ email: 'test@example.com' });
    expect(res.status).toBe(403);
  });

  test('POST /auth/request with invalid email returns 400 or 403', async () => {
    const csrf = await request(app).get('/auth/csrf-token');
    const cookie = csrf.headers['set-cookie'];
    const token = csrf.body.csrfToken;

    const res = await request(app)
      .post('/auth/request')
      .set('Cookie', cookie)
      .set('x-csrf-token', token)
      .set('Content-Type', 'application/json')
      .send({ email: 'not-valid' });
    expect([400, 403]).toContain(res.status);
  });

  test('POST /auth/verify-otp without CSRF returns 403', async () => {
    const res = await request(app)
      .post('/auth/verify-otp')
      .send({ sessionId: 'abc', otp: '12345678' });
    expect(res.status).toBe(403);
  });

  test('POST /auth/verify-otp with invalid OTP format returns 400', async () => {
    const csrf = await request(app).get('/auth/csrf-token');
    const cookie = csrf.headers['set-cookie'];
    const token = csrf.body.csrfToken;

    const res = await request(app)
      .post('/auth/verify-otp')
      .set('Cookie', cookie)
      .set('x-csrf-token', token)
      .send({ sessionId: 'abc', otp: 'abcdefgh' });
    expect(res.status).toBe(400);
  });

  test('GET /auth/me without session returns 401', async () => {
    const res = await request(app).get('/auth/me');
    expect(res.status).toBe(401);
  });

  test('GET /auth/verify-link without params returns 400', async () => {
    const res = await request(app).get('/auth/verify-link');
    expect([400, 401]).toContain(res.status);
  });
});

describe('Security headers', () => {
  test('Response includes X-Content-Type-Options', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  test('X-Powered-By is removed', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  test('X-Request-Id is present', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-request-id']).toBeTruthy();
  });
});
