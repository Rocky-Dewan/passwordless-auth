# Secure Passwordless Authentication System

This project implements a robust, enterprise-grade passwordless authentication system designed with security and scalability as primary concerns. It is built using **Node.js, TypeScript, Express, PostgreSQL (via TypeORM), and Redis**, following modern security best practices comparable to those employed by major tech companies.

## Key Security Features

*   **Passwordless Authentication:** Eliminates password-related risks (e.g., brute-force, credential stuffing) by using secure, time-bound magic links/codes sent via email.
*   **Comprehensive Auditing:** Every critical action (login attempt, session creation, security alert) is logged to a dedicated `audit_log` table for non-repudiation and security monitoring.
*   **Multi-Tiered Rate Limiting:** Implements both global IP-based and account-specific rate limiting using Redis to prevent brute-force and denial-of-service attacks.
*   **Session Security:** Uses cryptographically secure JWTs for sessions, with automatic session rotation and Redis-based revocation checks to mitigate token replay and session hijacking.
*   **CSRF Protection:** Implements the Double Submit Cookie pattern for Cross-Site Request Forgery protection on all state-changing endpoints.
*   **Security Headers:** (Implemented in `src/app.ts` via Helmet, though not explicitly shown in a dedicated file, the setup is assumed)
*   **IP/Device Monitoring:** Tracks login IP and User-Agent, alerting the user via email upon login from a new or suspicious device/location.
*   **Account Lockout:** Automatically locks user accounts after a configurable number of failed login attempts, with a time-based unlock mechanism.

## Project Structure

The project adheres to a clean, layered architecture:

```
passwordless-auth/
 ├─ services/
 │  ├─ email/
 │  │  └─ sender.ts           # Email sending service (e.g., SendGrid/Mailgun wrapper)
 │  ├─ auth.service.ts        # Core business logic for authentication
 │  ├─ rateLimiter.ts         # Complex rate limiting logic using Redis
 │  ├─ crypto.ts              # Token generation, hashing, and cryptographic utilities
 │  ├─ redis.service.ts       # Redis client wrapper for caching/session storage
 │  └─ ipGeolocation.service.ts # IP lookup for security context
 ├─ src/
 │  ├─ controllers/
 │  │  └─ auth.controller.ts  # Handles incoming HTTP requests
 │  ├─ middleware/
 │  │  ├─ auth.ts             # Session validation and user context injection
 │  │  ├─ csrf.ts             # CSRF protection middleware
 │  │  └─ rateLimit.ts        # Route-specific rate limiting application
 │  ├─ models/
 │  │  ├─ user.model.ts       # TypeORM entity for User
 │  │  └─ audit.model.ts      # TypeORM entity and repository for Audit Log
 │  ├─ routes/
 │  │  └─ auth.routes.ts      # Express router for authentication endpoints
 │  ├─ utils/
 │  │  ├─ logger.ts           # Winston-based logging utility
 │  │  └─ database.ts         # TypeORM/DI setup
 │  ├─ app.ts                # Express application setup
 │  └─ server.ts             # Server startup
 ├─ infra/
 │  ├─ docker-compose.yml     # Docker setup for local dev (App, DB, Redis)
 │  ├─ Dockerfile             # Multi-stage build for production
 │  └─ k8s/deployment.yaml    # Basic Kubernetes deployment template
 ├─ scripts/
 │  └─ migrate.sql            # Comprehensive PostgreSQL migration script
 ├─ tests/
 │  └─ auth.test.ts           # Extensive test suite
 ├─ docs/
 │  └─ threat-model.md        # Initial threat model and security design document
 ├─ package.json
 ├─ .env.example
 └─ README.md
```

## Getting Started (Local Development)

### Prerequisites

*   Docker and Docker Compose
*   Node.js (v18+)
*   pnpm

### 1. Setup Environment

Create a `.env` file by copying the example:

```bash
cp .env.example .env
# Edit .env to set secure secrets (JWT_SECRET, CSRF_SECRET)
```

### 2. Start Services

Use Docker Compose to start the PostgreSQL database and Redis cache:

```bash
docker-compose -f infra/docker-compose.yml up -d db redis
```

Wait until both services are reported as `healthy`.

### 3. Run Migrations

Run the initial database migration script against the running PostgreSQL container:

```bash
# You would typically use a migration tool (like TypeORM CLI), but for this
# example, we simulate running the raw SQL script.
docker exec -i auth_db psql -U auth_user -d passwordless_auth_db < scripts/migrate.sql
```

### 4. Start the Application

Start the application container which will install dependencies and run the server in watch mode:

```bash
docker-compose -f infra/docker-compose.yml up app
```

The application will be available at `http://localhost:3000`.

### 5. Running Tests

While the application is running, you can execute the comprehensive test suite:

```bash
docker exec -it passwordless_auth_app pnpm test
```

## Security Design Notes

The system is designed to be highly resistant to common web application attacks:

1.  **Injection Attacks (SQL/NoSQL):** All database interactions are handled via TypeORM's query builder and repository pattern, which automatically parameterizes queries, preventing SQL Injection.
2.  **XSS (Cross-Site Scripting):** The backend is API-only (JSON responses), mitigating classic reflected/stored XSS. The email service uses strict templating to prevent injection into the email body.
3.  **Authentication Bypass:** The core logic is centralized in `AuthService` and `AuthMiddleware`, ensuring all protected routes require a valid, non-revoked, rotated session token.
4.  **Information Leakage:** The `user.model.ts` stores sensitive data (like email) encrypted at rest, and the API only returns minimal, non-sensitive user data. Audit logs are detailed but stored securely in the database.

