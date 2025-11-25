
import { Request, Response, NextFunction } from 'express';
import { injectable, inject } from 'tsyringe';
import { HttpStatusCode } from 'http-status-codes';
import { AuthService, AuthError } from '../../services/auth.service';
import { Logger } from '../utils/logger';
import { RedisService } from '../../services/redis.service';

// --- Type Extensions for Express Request ---
declare module 'express' {
    interface Request {
        userId?: string;
        sessionId?: string;
        sessionToken?: string;
        sessionPayload?: any; // Detailed payload from the session token
    }
}


// --- Configuration Constants ---
const SESSION_COOKIE_NAME = 'session_token';
const SESSION_ROTATION_INTERVAL_MS = 1000 * 60 * 15; // 15 minutes for session rotation check
