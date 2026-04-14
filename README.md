# SecureAuth — Passwordless Authentication

A production-grade passwordless login system. Users enter any email (Gmail, Yahoo, custom domain, etc.) and receive a 250-second magic link plus an 8-digit OTP. Either method completes login. No passwords stored.

## Setup with Brevo (Free Email — 300/day)

1. Sign up at https://www.brevo.com using your mail
2. Go to **Settings → SMTP & API → SMTP** tab
3. Find your SMTP login and either use the master password or generate an SMTP key
4. Fill in your `.env`:

```env
EMAIL_HOST=smtp-relay.brevo.com
EMAIL_PORT=587
EMAIL_SECURE=false
EMAIL_USER=
EMAIL_PASS=
EMAIL_FROM=noreply@yourapp.com
```

## Quick Start

```bash
# 1. Extract and install
unzip passwordless-auth.zip && cd passwordless-auth
cp .env.example .env
# Edit .env — add your Brevo SMTP password
npm install

# 2. Start Postgres + Redis
docker-compose -f infra/docker-compose.yml up -d db redis

# 3. Run migrations
npx ts-node scripts/migrate.ts

# 4. Start server
npm run dev
# App at http://localhost:3000
```

## How It Works

1. User enters any email (Gmail, Yahoo, Outlook, custom — all accepted)
2. Server generates random 8-digit OTP + magic link token, stores both hashed in Redis with 250s TTL
3. Brevo sends a styled email with both the magic link button and the OTP
4. A top progress bar counts down the 250 seconds, a ring countdown shows inside the OTP step
5. User clicks link OR types OTP — whichever comes first
6. Token/OTP is consumed (deleted) immediately on first use
7. JWT session cookie is issued, user lands on dashboard

## Security

- OTP and link tokens are SHA-256 hashed before Redis storage — raw values never stored
- Both are one-time use (deleted immediately on verification)
- CSRF Double Submit Cookie pattern on all POST endpoints
- Per-IP (10/15min) and per-email (3/5min) rate limiting
- New device alert email sent on login from unrecognised IP/device
- Helmet security headers
- Full audit log in PostgreSQL

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `BASE_URL` | Public URL for magic links | `http://localhost:3000` |
| `EMAIL_HOST` | SMTP host | `smtp-relay.brevo.com` |
| `EMAIL_USER` | Brevo login email | — |
| `EMAIL_PASS` | Brevo SMTP key | — |
| `EMAIL_FROM` | From address | same as EMAIL_USER |
| `OTP_EXPIRY_SECONDS` | TTL for OTP and link | `250` |
| `JWT_SECRET` | Session signing secret (64+ chars) | dev default |
| `CSRF_SECRET` | CSRF HMAC secret | dev default |

## Running Tests

```bash
npm test
```
