import dotenv from 'dotenv';
dotenv.config();

function optional(key: string, fallback: string): string {
  return process.env[key] || fallback;
}

export const config = {
  env: optional('NODE_ENV', 'development'),
  port: parseInt(optional('PORT', '3000'), 10),
  baseUrl: optional('BASE_URL', 'http://localhost:3000'),

  db: {
    host: optional('DB_HOST', 'localhost'),
    port: parseInt(optional('DB_PORT', '5432'), 10),
    user: optional('DB_USER', 'auth_user'),
    password: optional('DB_PASSWORD', 'auth_password'),
    name: optional('DB_NAME', 'passwordless_auth_db'),
  },

  redis: {
    host: optional('REDIS_HOST', 'localhost'),
    port: parseInt(optional('REDIS_PORT', '6379'), 10),
    password: optional('REDIS_PASSWORD', ''),
  },

  jwt: {
    secret: optional('JWT_SECRET', 'dev_secret_change_in_production_min_64_chars_xxxxxxxxxxx'),
    expiry: optional('JWT_EXPIRY', '7d'),
  },

  csrf: {
    secret: optional('CSRF_SECRET', 'dev_csrf_secret_change_in_production_xxxxxxxxxxx'),
  },

  email: {
    host: optional('EMAIL_HOST', 'smtp-relay.brevo.com'),
    port: parseInt(optional('EMAIL_PORT', '587'), 10),
    secure: optional('EMAIL_SECURE', 'false') === 'true',
    user: optional('EMAIL_USER', ''),
    pass: optional('EMAIL_PASS', ''),
    from: optional('EMAIL_FROM', 'noreply@yourapp.com'),
  },

  auth: {
    otpExpirySeconds: parseInt(optional('OTP_EXPIRY_SECONDS', '250'), 10),
    magicLinkExpirySeconds: parseInt(optional('MAGIC_LINK_EXPIRY_SECONDS', '250'), 10),
    maxLoginAttempts: parseInt(optional('MAX_LOGIN_ATTEMPTS', '5'), 10),
    lockoutDurationMinutes: parseInt(optional('LOCKOUT_DURATION_MINUTES', '15'), 10),
  },
} as const;
