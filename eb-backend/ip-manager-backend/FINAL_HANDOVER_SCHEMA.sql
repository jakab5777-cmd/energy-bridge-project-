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
INSERT INTO user_roles (name) VALUES ('Viewer') ON CONFLICT (name) DO NOTHING;-- Migration: permissions + role_permissions
-- ADDITIVE ONLY. Does not touch ip_manager_users, ip_manager_permissions,
-- user_roles, or registered_users. Existing login/permission system keeps
-- working exactly as before until a separate, deliberate code change later
-- switches auth.js to read from these tables instead of ROLE_DEFAULTS.

CREATE TABLE IF NOT EXISTS permissions (
    permission_id SERIAL PRIMARY KEY,
    module VARCHAR(100) NOT NULL,
    permission_name VARCHAR(150) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_permission_id SERIAL PRIMARY KEY,
    role VARCHAR(50) NOT NULL,
    permission_id INTEGER NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
    UNIQUE(role, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role);

-- Seed: all 39 existing PERM_KEYS, mapped to a module, 1:1 with current system
INSERT INTO permissions (module, permission_name, description) VALUES
  ('real_ip',     'assignReal',        'Assign a real IP'),
  ('real_ip',     'editReal',          'Edit a real IP entry'),
  ('real_ip',     'deleteReal',        'Delete a real IP entry'),
  ('fake_ip',     'assignFake',        'Assign a fake/internal IP'),
  ('fake_ip',     'editFake',          'Edit a fake/internal IP entry'),
  ('fake_ip',     'deleteFake',        'Delete a fake/internal IP entry'),
  ('fake_ip',     'addFakeSubnet',     'Add a fake IP subnet'),
  ('fake_ip',     'deleteFakeSubnet',  'Delete a fake IP subnet'),
  ('wan',         'addWan',            'Add a WAN solution'),
  ('wan',         'editWan',           'Edit a WAN solution'),
  ('wan',         'deleteWan',         'Delete a WAN solution'),
  ('tunnel',      'addTunnel',         'Add an IP tunnel'),
  ('tunnel',      'editTunnel',        'Edit an IP tunnel'),
  ('tunnel',      'deleteTunnel',      'Delete an IP tunnel'),
  ('vpn',         'addVpn',            'Add a VPN entry'),
  ('vpn',         'editVpn',           'Edit a VPN entry'),
  ('vpn',         'deleteVpn',         'Delete a VPN entry'),
  ('dsp',         'addDsp',            'Add a DSP provider'),
  ('dsp',         'editDsp',           'Edit a DSP provider'),
  ('dsp',         'deleteDsp',         'Delete a DSP provider'),
  ('vlan',        'addVlan',           'Add a VLAN entry'),
  ('vlan',        'editVlan',          'Edit a VLAN entry'),
  ('vlan',        'deleteVlan',        'Delete a VLAN entry'),
  ('users',       'manageUsers',       'Full user management (create/edit/delete/permissions)'),
  ('system',      'exportExcel',       'Export data to Excel'),
  ('credentials', 'addCredentials',    'Add a credential entry'),
  ('credentials', 'editCredentials',   'Edit a credential entry'),
  ('credentials', 'deleteCredentials', 'Delete a credential entry'),
  ('visibility',  'seeDashboard',      'View Dashboard section'),
  ('visibility',  'seeRealIP',         'View Real IP section'),
  ('visibility',  'seeFakeIP',         'View Fake/Internal IP section'),
  ('visibility',  'seeWan',            'View WAN section'),
  ('visibility',  'seeVlan',           'View VLAN section'),
  ('visibility',  'seeTunnels',        'View Tunnels section'),
  ('visibility',  'seeVpn',            'View VPN section'),
  ('visibility',  'seeSearch',         'View Client Search section'),
  ('visibility',  'seeDsp',            'View DSP section'),
  ('visibility',  'seeCredentials',    'View Credentials section'),
  ('visibility',  'seeUsers',          'View Users section')
ON CONFLICT (permission_name) DO NOTHING;

-- Seed role_permissions: admin = every permission
INSERT INTO role_permissions (role, permission_id)
SELECT 'admin', permission_id FROM permissions
ON CONFLICT (role, permission_id) DO NOTHING;

-- Seed role_permissions: editor = everything except manageUsers and all delete* keys
INSERT INTO role_permissions (role, permission_id)
SELECT 'editor', permission_id FROM permissions
WHERE permission_name NOT IN (
  'manageUsers', 'deleteReal', 'deleteFake', 'deleteWan',
  'deleteTunnel', 'deleteVpn', 'deleteDsp', 'deleteVlan', 'deleteCredentials'
)
ON CONFLICT (role, permission_id) DO NOTHING;

-- Seed role_permissions: viewer = only see* keys
INSERT INTO role_permissions (role, permission_id)
SELECT 'viewer', permission_id FROM permissions
WHERE permission_name LIKE 'see%'
ON CONFLICT (role, permission_id) DO NOTHING;
-- Migration: clients + normalized IP management schema
-- ADDITIVE ONLY. Existing tables (wan_solutions, ip_tunnels, real_ips,
-- credentials, dsp_providers, vlan_tracking, etc.) are NOT touched, dropped,
-- or modified. New tables use a _v2 suffix where a name collision with an
-- existing table would otherwise occur, so nothing live is at risk.
-- Data migration from old tables into these new ones is a separate,
-- deliberate step — not part of this migration.

CREATE TABLE IF NOT EXISTS clients (
    client_id SERIAL PRIMARY KEY,
    client_name VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS dsp_providers_v2 (
    dsp_id SERIAL PRIMARY KEY,
    dsp_name VARCHAR(255),
    code_name VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS vlans_v2 (
    vlan_id INTEGER PRIMARY KEY,
    status VARCHAR(50),
    type VARCHAR(50),
    service VARCHAR(100),
    zone VARCHAR(100),
    client_id INTEGER REFERENCES clients(client_id),
    real_ip VARCHAR(50),
    fake_ip VARCHAR(50),
    dsp_id INTEGER REFERENCES dsp_providers_v2(dsp_id)
);

CREATE TABLE IF NOT EXISTS real_ip_subnets (
    real_ip_id SERIAL PRIMARY KEY,
    real_ip_block VARCHAR(100),
    client_id INTEGER REFERENCES clients(client_id),
    fake_ip VARCHAR(100),
    vlan_id INTEGER REFERENCES vlans_v2(vlan_id),
    dsp_id INTEGER REFERENCES dsp_providers_v2(dsp_id),
    wan VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS internal_ip_subnets (
    internal_ip_id SERIAL PRIMARY KEY,
    internal_ip_block VARCHAR(100),
    client_id INTEGER REFERENCES clients(client_id),
    other_ips TEXT
);

CREATE TABLE IF NOT EXISTS wan_solutions_v2 (
    wan_id SERIAL PRIMARY KEY,
    client_id INTEGER REFERENCES clients(client_id),
    head_office VARCHAR(100),
    branch_code VARCHAR(100),
    branch_name VARCHAR(255),
    vlan_id INTEGER REFERENCES vlans_v2(vlan_id),
    dsp_id INTEGER REFERENCES dsp_providers_v2(dsp_id),
    upload_download VARCHAR(100),
    subnet_ho_to_branch VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS ip_tunnels_v2 (
    tunnel_id SERIAL PRIMARY KEY,
    client_id INTEGER REFERENCES clients(client_id),
    local_ip VARCHAR(100),
    remote_ip VARCHAR(100),
    interface VARCHAR(100),
    description TEXT
);

CREATE TABLE IF NOT EXISTS vpns (
    vpn_id SERIAL PRIMARY KEY,
    client_id INTEGER REFERENCES clients(client_id),
    vpn_type VARCHAR(100),
    vpn_ip VARCHAR(100),
    username VARCHAR(255),
    password VARCHAR(255),
    description TEXT
);

CREATE TABLE IF NOT EXISTS credentials_v2 (
    credential_id SERIAL PRIMARY KEY,
    subnet VARCHAR(100),
    gateway VARCHAR(100),
    vlan_id INTEGER REFERENCES vlans_v2(vlan_id),
    net_desc TEXT,
    ip_address VARCHAR(100),
    node_type VARCHAR(100),
    device_desc TEXT,
    username VARCHAR(255),
    password VARCHAR(255),
    login_url TEXT,
    additional TEXT
);
CREATE TABLE IF NOT EXISTS change_logs (
    log_id SERIAL PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    record_id INTEGER NOT NULL,
    action VARCHAR(10) NOT NULL,
    changed_by INTEGER REFERENCES registered_users(user_id),
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    old_data JSONB,
    new_data JSONB
);

CREATE INDEX idx_logs_table_record ON change_logs(table_name, record_id);
CREATE INDEX idx_logs_user ON change_logs(changed_by);
CREATE TABLE IF NOT EXISTS hardware_assets (
    asset_id SERIAL PRIMARY KEY,
    device_name VARCHAR(100) NOT NULL,
    serial_number VARCHAR(100) UNIQUE,
    model VARCHAR(100),
    firmware_version VARCHAR(50),
    status VARCHAR(50) DEFAULT 'In Storage',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS isp_staff (
    staff_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES registered_users(user_id) ON DELETE CASCADE,
    department VARCHAR(100),
    position VARCHAR(100),
    access_level VARCHAR(50) DEFAULT 'Technician'
);
