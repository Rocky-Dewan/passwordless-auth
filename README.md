# Passwordless Auth

A production-quality passwordless authentication system using magic links + OTP, built with Node.js, TypeScript, PostgreSQL, and Redis.

---

<div align="center">
  <a href="https://passwordless-authenticate.vercel.app/"><strong>Explore Passwordless Authentication Live »</strong></a>
</div>

---

## How It Works

1. User enters any email (Gmail, Yahoo, Outlook, custom — all accepted)
2. Server generates a random 8-digit OTP + magic link token, stores both (hashed) in Redis with a 250 s TTL
3. Brevo sends a styled email containing both a **magic link button** and the **OTP**
4. A top progress bar counts down 250 seconds; a ring countdown is shown inside the OTP step
5. User clicks the link **OR** types the OTP — whichever comes first
6. Token/OTP is consumed (deleted) immediately on first use
7. A JWT session cookie is issued and the user lands on the dashboard

---

## Quick Start (step by step)

### 1 — Prerequisites

| Tool | Install |
|---|---|
| Node.js >= 18 | https://nodejs.org |
| Docker Desktop | https://www.docker.com/products/docker-desktop/ |
| Git Bash (Windows) | included with Git for Windows |

---

### 2 — Install dependencies

```bash
cd passwordless-auth
npm install
```

---

### 3 — Set up Brevo (free email, 300 emails/day)

1. Go to **https://www.brevo.com** and create a FREE account
2. Verify your email address
3. After logging in: click the **gear icon** (top-right) → **SMTP & API** → **SMTP** tab
4. You will see your **Login** email — use this as EMAIL_USER
5. Click **"Generate a new SMTP key"** → copy it as EMAIL_PASS
6. EMAIL_FROM must be the same email you signed up with

> **No Brevo yet?** Without credentials the app automatically falls back to **Ethereal** (fake inbox). Emails are never delivered but the server logs print a preview URL like `DEV email preview { url: 'https://ethereal.email/message/...' }`. Perfect for local dev.

---

### 4 — Configure .env

Open the `.env` file. Fill in your Brevo details:

```
EMAIL_USER=your_brevo_login@example.com
EMAIL_PASS=xsmtpsib-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
EMAIL_FROM=your_brevo_login@example.com
```

Everything else is already correct for local development.

---

### 5 — Start Docker (PostgreSQL + Redis)

Open **Docker Desktop** first, then:

```bash
docker-compose -f infra/docker-compose.yml up -d db redis
```

Wait ~5 seconds. Verify both are healthy:

```bash
docker ps
# auth_db and auth_redis should show "(healthy)"
```

---

### 6 — Run the database migration

```bash
npx ts-node scripts/migrate.ts
# Should print: Connected to database -> Migration completed successfully
```

> If you see "database does not exist" — the DB container hasn't finished initialising yet. Wait 10 s and retry.

---

### 7 — Start the dev server

```bash
npm run dev
```

Open http://localhost:3000 in your browser.

---

### 8 — Run tests

```bash
npm test
# All 17 tests should pass
```

---

## Redis — what it does and how it connects

Redis stores OTP tokens, magic link tokens, session allow-list entries, and rate-limit counters. All have short TTLs.

The Docker container runs with **no password** on port 6379. The .env already has:

```
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=        # empty = no password required
```

If Redis is not running the server logs "Redis error" and retries. The app still starts but login will fail.

---

## PostgreSQL — what it does

Stores users and audit logs. The Docker container auto-creates the database and runs scripts/migrate.sql on first boot.

---

## Common Errors and Fixes

| Error | Fix |
|---|---|
| database "passwordless-auth-db" does not exist | Wrong DB_NAME in .env — must be passwordless_auth_db (underscores, not hyphens) |
| Failed to start server (Redis error) | Run docker-compose -f infra/docker-compose.yml up -d redis |
| "Security token missing" in browser | CSRF bug — fixed in this version |
| Send login link button does nothing | CSRF bug — fixed in this version |
| Email not arriving | Add Brevo SMTP key to .env. Without it, copy preview URL from server logs. |
| Migration failed immediately | DB container not healthy yet — wait 10 s then retry |

---

## Environment Variables Reference

| Variable | Description | Default |
|---|---|---|
| NODE_ENV | development or production | development |
| PORT | HTTP port | 3000 |
| BASE_URL | Public URL (for magic links) | http://localhost:3000 |
| DB_HOST | Postgres host | localhost |
| DB_PORT | Postgres port | 5432 |
| DB_USER | Postgres user | auth_user |
| DB_PASSWORD | Postgres password | auth_password |
| DB_NAME | Postgres database name | passwordless_auth_db |
| REDIS_HOST | Redis host | localhost |
| REDIS_PORT | Redis port | 6379 |
| REDIS_PASSWORD | Redis password (empty = none) | (empty) |
| JWT_SECRET | Secret for JWT signing — change in prod | (dev value) |
| CSRF_SECRET | Secret for CSRF token signing — change in prod | (dev value) |
| EMAIL_HOST | SMTP host | smtp-relay.brevo.com |
| EMAIL_PORT | SMTP port | 587 |
| EMAIL_SECURE | TLS on connect (true/false) | false |
| EMAIL_USER | Your Brevo login email | (must set) |
| EMAIL_PASS | SMTP key from Brevo | (must set) |
| EMAIL_FROM | Sender address shown in emails | (must set) |
| OTP_EXPIRY_SECONDS | How long OTP is valid | 250 |
| MAGIC_LINK_EXPIRY_SECONDS | How long magic link is valid | 250 |
| MAX_LOGIN_ATTEMPTS | Max failed attempts before lockout | 5 |
| LOCKOUT_DURATION_MINUTES | How long account is locked | 15 |
