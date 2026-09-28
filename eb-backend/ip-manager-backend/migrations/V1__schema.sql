-- ============================================================
-- EB IP Manager — PostgreSQL Schema
-- Migrated from Google Apps Script V14 (sheet-based) to real tables
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- for gen_random_uuid()

-- ── Real IP subnets (was: one sheet per subnet, e.g. "5.100.240") ──
CREATE TABLE IF NOT EXISTS real_ips (
  id          BIGSERIAL PRIMARY KEY,
  subnet      TEXT NOT NULL,
  real_ip     TEXT NOT NULL,
  client_id   TEXT,
  client_name TEXT,
  fake_ip     TEXT,
  vlan_id     TEXT,
  dsp         TEXT,
  block_id    TEXT,
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_real_ips_subnet ON real_ips(subnet);
CREATE INDEX IF NOT EXISTS idx_real_ips_client ON real_ips(client_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_real_ips_ip ON real_ips(real_ip);

-- ── Internal/Fake IP subnets (was: Int_XXX sheets, 256 rows each) ──
-- Sparse design: only rows for IPs actually assigned to a client are stored.
CREATE TABLE IF NOT EXISTS internal_ips (
  id            BIGSERIAL PRIMARY KEY,
  subnet        TEXT NOT NULL,
  internal_ip   TEXT NOT NULL,
  client_id     TEXT,
  client_name   TEXT,
  block_id      TEXT,
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_internal_ips_subnet ON internal_ips(subnet);
CREATE INDEX IF NOT EXISTS idx_internal_ips_client ON internal_ips(client_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_internal_ips_ip ON internal_ips(internal_ip);

-- Tracks which internal subnets exist (was: sheet existing = subnet existing)
CREATE TABLE IF NOT EXISTS internal_subnets (
  subnet TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── WAN Solutions ──
CREATE TABLE IF NOT EXISTS wan_solutions (
  id           BIGSERIAL PRIMARY KEY,
  client_id    TEXT,
  branch_code  TEXT,
  branch_name  TEXT,
  vlan_id      TEXT,
  dsp          TEXT,
  updown       TEXT,
  vlan_subnet  TEXT,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wan_client ON wan_solutions(client_id);

-- ── Tunnels ──
CREATE TABLE IF NOT EXISTS ip_tunnels (
  id                 BIGSERIAL PRIMARY KEY,
  client_id          TEXT,
  client_name        TEXT,
  tunnel_local_ip    TEXT,
  tunnel_remote_ip   TEXT,
  tunnel_interface   TEXT,
  description        TEXT,
  created_at         TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_tunnels_client ON ip_tunnels(client_id);

-- ── VPN entries (password encrypted, never plaintext) ──
CREATE TABLE IF NOT EXISTS vpn_entries (
  id                     BIGSERIAL PRIMARY KEY,
  client_id              TEXT,
  client_name            TEXT,
  vpn_type               TEXT,
  vpn_ip                 TEXT,
  vpn_username           TEXT,
  vpn_password_encrypted TEXT,
  description            TEXT,
  created_at             TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_vpn_client ON vpn_entries(client_id);

-- ── DSP Providers ──
CREATE TABLE IF NOT EXISTS dsp_providers (
  id       SERIAL PRIMARY KEY,
  dsp_name TEXT UNIQUE NOT NULL
);
INSERT INTO dsp_providers (dsp_name) VALUES
  ('TRISAT'),('PESCO'),('GDS'),('CONNECT/MADA'),('CABLE ONE'),
  ('CEDARCOM'),('DSL'),('FIBER OGERO'),('DIRECTLY CONNECTED')
ON CONFLICT (dsp_name) DO NOTHING;

-- ── VLAN Tracking ──
CREATE TABLE IF NOT EXISTS vlan_tracking (
  id                BIGSERIAL PRIMARY KEY,
  vlan_id           TEXT NOT NULL,
  status            TEXT,
  assignment_type   TEXT,
  zone              TEXT,
  service_category  TEXT,
  client_id         TEXT,
  client_name       TEXT,
  real_ip           TEXT,
  fake_ip           TEXT,
  bng_card          TEXT,
  primary_path      TEXT,
  backup_path       TEXT,
  other_path        TEXT,
  source            TEXT,
  cdn               TEXT,
  notes             TEXT,
  locked            BOOLEAN DEFAULT false,
  dsp               TEXT,
  group_id          TEXT,
  last_modified     TIMESTAMPTZ DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vlan_id ON vlan_tracking(vlan_id);
CREATE INDEX IF NOT EXISTS idx_vlan_client  ON vlan_tracking(client_id);
CREATE INDEX IF NOT EXISTS idx_vlan_group   ON vlan_tracking(group_id);

-- ── VLAN Meta (was: VLAN_Meta sheet, cdnList key/value) ──
CREATE TABLE IF NOT EXISTS vlan_meta (
  key   TEXT PRIMARY KEY,
  value JSONB
);

-- ── Credentials (password encrypted, never plaintext) ──
CREATE TABLE IF NOT EXISTS credentials (
  id                  BIGSERIAL PRIMARY KEY,
  subnet              TEXT,
  gateway             TEXT,
  vlan                TEXT,
  category            TEXT,
  net_desc            TEXT,
  ip_address          TEXT,
  node_type           TEXT,
  device_desc         TEXT,
  username            TEXT,
  password_encrypted  TEXT,
  login_url           TEXT,
  additional          TEXT,
  created_at          TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cred_ip       ON credentials(ip_address);
CREATE INDEX IF NOT EXISTS idx_cred_category ON credentials(category);

-- ── Credentials meta (node types + categories dropdown lists) ──
CREATE TABLE IF NOT EXISTS cred_meta (
  key   TEXT PRIMARY KEY,
  value JSONB
);
INSERT INTO cred_meta (key, value) VALUES
  ('nodeTypes', '["vCenter","ESXI","Proxmox","Switch","Router","Firewall","ILO","iDRAC","Windows Server","Linux Server","NAS","Storage","Other"]'),
  ('categories', '["Server","Network","Storage","Security","Other"]')
ON CONFLICT (key) DO NOTHING;

-- ── Users & Permissions ──
CREATE TABLE IF NOT EXISTS ip_manager_users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT DEFAULT 'viewer',
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ip_manager_permissions (
  user_id   UUID REFERENCES ip_manager_users(id) ON DELETE CASCADE,
  perm_key  TEXT NOT NULL,
  granted   BOOLEAN DEFAULT false,
  PRIMARY KEY (user_id, perm_key)
);
CREATE INDEX IF NOT EXISTS idx_perms_user ON ip_manager_permissions(user_id);
