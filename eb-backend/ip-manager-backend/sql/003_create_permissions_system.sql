-- Migration: permissions + role_permissions
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
