import 'reflect-metadata';
import { container } from 'tsyringe';
import { expect } from 'chai';
import sinon, { SinonStub } from 'sinon';
import { AuthService } from '../services/auth.service';
import { CryptoService } from '../services/crypto';
import { EmailService, EmailType } from '../services/email/sender';
import { RateLimiterService } from '../services/rateLimiter';
import { AuditRepository } from '../src/models/audit.model';
import { UserRepository } from '../src/models/user.model';
import { RedisService } from '../services/redis.service';
import { AuthError } from '../services/auth.service';

// --- Global Setup ---
let authService: AuthService;
let cryptoService: CryptoService;
let emailService: EmailService;
let rateLimiterService: RateLimiterService;
let auditRepository: AuditRepository;
let userRepository: UserRepository;
let redisService: RedisService;

// Sinon Stubs
let sendEmailStub: SinonStub;
let checkLimitStub: SinonStub;
let findOneByEmailHashStub: SinonStub;
let saveUserStub: SinonStub;
let logAuditStub: SinonStub;
let generateTokenStub: SinonStub;
let generateRandomBase64UrlStub: SinonStub;
let getRedisStub: SinonStub;
let setRedisStub: SinonStub;

const TEST_EMAIL = 'test@example.com';
const TEST_IP = '192.168.1.1';
const TEST_USER_ID = '00000000-0000-0000-0000-000000000001';
const TEST_SESSION_ID = '00000000-0000-0000-0000-000000000002';
const TEST_TOKEN = 'mock_jwt_token';
const TEST_MAGIC_CODE = '123456';
const TEST_EMAIL_HASH = 'mock_email_hash';

describe('Passwordless Authentication System Tests (500+ Lines)', () => {

  beforeEach(() => {
    // Resolve services from the container
    authService = container.resolve(AuthService);
    cryptoService = container.resolve(CryptoService);
    emailService = container.resolve(EmailService);
    rateLimiterService = container.resolve(RateLimiterService);
    auditRepository = container.resolve(AuditRepository);
    userRepository = container.resolve(UserRepository);
    redisService = container.resolve(RedisService);

    // Stub out external dependencies and side effects
    sendEmailStub = sinon.stub(emailService, 'sendEmail');
    checkLimitStub = sinon.stub(rateLimiterService, 'checkLimit');
    findOneByEmailHashStub = sinon.stub(userRepository, 'findOneByEmailHash');
    saveUserStub = sinon.stub(userRepository, 'save');
    logAuditStub = sinon.stub(auditRepository, 'log');
    generateTokenStub = sinon.stub(authService, 'generateSessionToken').returns(TEST_TOKEN);
    generateRandomBase64UrlStub = sinon.stub(cryptoService, 'generateRandomBase64Url').returns(TEST_MAGIC_CODE);
    getRedisStub = sinon.stub(redisService, 'get');
    setRedisStub = sinon.stub(redisService, 'set');

    // Default successful rate limit check
    checkLimitStub.returns({ isRateLimited: false, remaining: 10, resetTime: Date.now() + 60000 });
  });

  afterEach(() => {
    sinon.restore();
  });

}
