import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import path from 'path';
import { globalLimiter } from './middleware/rateLimit';
import { csrfMiddleware } from './middleware/csrf';
import { requestId, honeypot, blockScanners, scrubHeaders } from './middleware/security';
import authRoutes from './routes/auth.routes';
import { logger } from './utils/logger';
import { config } from './config';

const app = express();

// Trust proxy (needed for correct IP behind nginx/docker)
app.set('trust proxy', 1);

// --- Security headers via Helmet ---
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
      styleSrc:    ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'fonts.gstatic.com'],
      fontSrc:     ["'self'", 'fonts.gstatic.com'],
      imgSrc:      ["'self'", 'data:'],
      connectSrc:  ["'self'"],
      frameSrc:    ["'none'"],
      objectSrc:   ["'none'"],
      baseUri:     ["'self'"],
      formAction:  ["'self'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
}));

// --- Custom security middleware ---
app.use(scrubHeaders);
app.use(requestId);
app.use(blockScanners);
app.use(honeypot);

// --- CORS ---
app.use(cors({
  origin: config.env === 'production' ? config.baseUrl : true,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token', 'x-request-id'],
}));

// --- Body parsing (strict size limits to prevent DoS) ---
app.use(compression());
app.use(express.json({ limit: '8kb' }));
app.use(express.urlencoded({ extended: false, limit: '8kb' }));
app.use(cookieParser());

// --- Global rate limiter ---
app.use(globalLimiter);

// --- CSRF protection (runs before all routes) ---
app.use(csrfMiddleware);

// --- Static files ---
app.use(express.static(path.join(__dirname, '..', 'public'), {
  maxAge: config.env === 'production' ? '1d' : 0,
  etag: true,
}));

// --- Auth routes ---
app.use('/auth', authRoutes);

// --- Dashboard (cookie check, serve HTML) ---
app.get('/dashboard', (req, res) => {
  if (!req.cookies?.session_token) return res.redirect('/');
  res.sendFile(path.join(__dirname, '..', 'public', 'dashboard.html'));
});

// --- Root ---
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// --- Health ---
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok', env: config.env, ts: Date.now() });
});

// --- 404 ---
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// --- Global error handler ---
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error('Unhandled error', { err: err.message });
  res.status(500).json({ error: 'Internal server error.' });
});

export default app;
