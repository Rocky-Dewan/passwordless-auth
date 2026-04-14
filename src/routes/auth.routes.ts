import { Router } from 'express';
import {
  requestAuth,
  requestAuthWithSession,
  verifyOtp,
  verifyMagicLink,
  logout,
  getMe,
  getCsrfToken,
} from '../controllers/auth.controller';
import { requireAuth } from '../middleware/auth';
import { authLimiter, otpLimiter } from '../middleware/rateLimit';

const router = Router();

// Public routes
router.get('/csrf-token', getCsrfToken);
router.post('/request', authLimiter, requestAuthWithSession);
router.post('/verify-otp', otpLimiter, verifyOtp);
router.get('/verify-link', verifyMagicLink);

// Protected routes
router.post('/logout', requireAuth, logout);
router.get('/me', requireAuth, getMe);

export default router;
