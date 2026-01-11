-- --- 1. Schema Setup ---
CREATE SCHEMA IF NOT EXISTS auth;
SET search_path TO auth, public;

-- --- 2. User Table (Core Entity) ---
CREATE TABLE IF NOT EXISTS auth.user (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Email is encrypted at the application layer, so we store the hash for lookups
    email_hash VARCHAR(64) UNIQUE NOT NULL,
    -- Encrypted email for display/recovery purposes (stored securely)
    encrypted_email TEXT NOT NULL,
    -- User metadata
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    -- Security Fields
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_locked BOOLEAN NOT NULL DEFAULT FALSE,
    lockout_until TIMESTAMP WITH TIME ZONE,
    failed_login_attempts SMALLINT NOT NULL DEFAULT 0,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip INET,
    -- Recovery Codes (Hashed and salted)
    recovery_codes_hash TEXT,
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for fast lookups by email hash
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_email_hash ON auth.user (email_hash);

-- --- 3. Audit Log Table (Non-repudiation) ---
CREATE TABLE IF NOT EXISTS auth.audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES auth.user(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL, -- e.g., 'LOGIN_SUCCESS', 'LOGIN_FAILED', 'SESSION_REVOKED'
    -- Detailed context in JSONB format
    context JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Source information
    ip_address INET,
    user_agent TEXT,
    service_name VARCHAR(100) NOT NULL, -- The service that logged the event (e.g., 'AuthService')
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_audit_log_user_id_created_at ON auth.audit_log (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON auth.audit_log (action);


CREATE TABLE IF NOT EXISTS auth.session (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES auth.user(id) ON DELETE CASCADE,
    device_info JSONB,
    ip_address INET,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_session_user_id ON auth.session (user_id);


CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';


CREATE OR REPLACE TRIGGER update_user_updated_at
BEFORE UPDATE ON auth.user
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE VIEW auth.user_public_view AS
SELECT
    id,
    first_name,
    last_name,
    is_active,
    is_locked,
    lockout_until,
    failed_login_attempts,
    last_login_at,
    last_login_ip,
    created_at,
    updated_at
FROM auth.user;

