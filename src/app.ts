import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import path from 'path';
import { globalLimiter } from './middleware/rateLimit';
import { csrfMiddleware } from './middleware/csrf';
import authRoutes from './routes/auth.routes';
import { logger } from './utils/logger';
import { config } from './config';

const app = express();

// Security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

// CORS
app.use(
  cors({
    origin: config.env === 'production' ? config.baseUrl : true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
  })
);

app.use(compression());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Trust proxy for rate limiting and IP detection
app.set('trust proxy', 1);

// Global rate limiter
app.use(globalLimiter);

// CSRF protection on all routes
app.use(csrfMiddleware);

// Static files
app.use(express.static(path.join(__dirname, '..', 'public')));

// Routes
app.use('/auth', authRoutes);

// Dashboard (protected - just a simple HTML page, guarded by cookie check)
app.get('/dashboard', (req, res) => {
  const token = req.cookies?.session_token;
  if (!token) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, '..', 'public', 'dashboard.html'));
});

// Root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Health check
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok', env: config.env });
});

// 404
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// Global error handler
app.use(
  (
    err: Error,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction
  ) => {
    logger.error('Unhandled error', { err: err.message, stack: err.stack });
    res.status(500).json({ error: 'Internal server error.' });
  }
);

export default app;
