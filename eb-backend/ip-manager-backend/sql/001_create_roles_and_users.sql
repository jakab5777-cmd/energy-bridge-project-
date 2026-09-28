-- Migration: UserRoles + Registered_Users
-- Run against the existing shared PostgreSQL DB (same one used by IP Manager)

CREATE TABLE IF NOT EXISTS user_roles (
    role_id     SERIAL PRIMARY KEY,
    name        VARCHAR(100) NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS registered_users (
    user_id         SERIAL PRIMARY KEY,
    username        VARCHAR(100) NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,          -- bcrypt hash, always set
    password_plain  TEXT,                   -- WARNING: plaintext, see README. Nullable so it can be cleared.
    role_id         INTEGER NOT NULL REFERENCES user_roles(role_id) ON DELETE RESTRICT,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_registered_users_role_id ON registered_users(role_id);

-- Seed a couple of default roles (adjust as needed)
INSERT INTO user_roles (name) VALUES ('Admin') ON CONFLICT (name) DO NOTHING;
INSERT INTO user_roles (name) VALUES ('Technician') ON CONFLICT (name) DO NOTHING;
INSERT INTO user_roles (name) VALUES ('Viewer') ON CONFLICT (name) DO NOTHING;