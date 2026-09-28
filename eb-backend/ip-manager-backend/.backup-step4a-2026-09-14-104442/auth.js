const jwt = require('jsonwebtoken');
const pool = require('../db');

const PERM_KEYS = [
  'addClient', 'editClient', 'deleteClient',
  'assignReal', 'editReal', 'deleteReal',
  'assignFake', 'editFake', 'deleteFake', 'addFakeSubnet', 'deleteFakeSubnet',
  'addWan', 'editWan', 'deleteWan',
  'addTunnel', 'editTunnel', 'deleteTunnel',
  'addVpn', 'editVpn', 'deleteVpn',
  'addDsp', 'editDsp', 'deleteDsp',
  'addVlan', 'editVlan', 'deleteVlan',
  'manageUsers', 'exportExcel',
  'addCredentials', 'editCredentials', 'deleteCredentials',
  'seeDashboard', 'seeRealIP', 'seeFakeIP', 'seeWan',
  'seeVlan', 'seeTunnels', 'seeVpn', 'seeSearch', 'seeDsp', 'seeCredentials', 'seeUsers',
  'addRealIpSubnet', 'editRealIpSubnet', 'deleteRealIpSubnet',
  'addInternalIpSubnet', 'editInternalIpSubnet', 'deleteInternalIpSubnet',
  'addVlanV2', 'editVlanV2', 'deleteVlanV2',
  'addWanV2', 'editWanV2', 'deleteWanV2',
  'addTunnelV2', 'editTunnelV2', 'deleteTunnelV2',
  'addVpnV2', 'editVpnV2', 'deleteVpnV2',
  'addDspV2', 'editDspV2', 'deleteDspV2',
  'addCredentialV2', 'editCredentialV2', 'deleteCredentialV2',
  'addHardwareAsset', 'editHardwareAsset', 'deleteHardwareAsset',
  'addStaff', 'editStaff', 'deleteStaff',
  'addHardwareAsset', 'editHardwareAsset', 'deleteHardwareAsset',
  'addStaff', 'editStaff', 'deleteStaff'
];

const ROLE_DEFAULTS = {
  admin: Object.fromEntries(PERM_KEYS.map(k => [k, true])),
  editor: Object.fromEntries(PERM_KEYS.map(k => [
    k, !['manageUsers', 'deleteClient', 'deleteReal', 'deleteFake', 'deleteWan', 'deleteTunnel', 'deleteVpn', 'deleteDsp', 'deleteVlan', 'deleteCredentials',
         'deleteRealIpSubnet', 'deleteInternalIpSubnet', 'deleteVlanV2', 'deleteWanV2', 'deleteTunnelV2', 'deleteVpnV2', 'deleteDspV2', 'deleteCredentialV2'].includes(k)
  ])),
  viewer: Object.fromEntries(PERM_KEYS.map(k => [k, k.startsWith('see')])),
};

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ ok: false, error: 'Missing token' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.auth = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, error: 'Invalid or expired token' });
  }
}

function requirePermission(permKey) {
  return (req, res, next) => {
    if (!req.auth) return res.status(401).json({ ok: false, error: 'Not authenticated' });
    if (!req.auth.perms || !req.auth.perms[permKey]) {
      return res.status(403).json({ ok: false, error: `Missing permission: ${permKey}` });
    }
    next();
  };
}

async function getRoleDefaultsFromDb(role) {
  const { rows } = await pool.query(
    `SELECT p.permission_name FROM role_permissions rp
     JOIN permissions p ON p.permission_id = rp.permission_id
     WHERE rp.role = $1`, [role]
  );
  const granted = new Set(rows.map(r => r.permission_name));
  const perms = {};
  PERM_KEYS.forEach(key => { perms[key] = granted.has(key); });
  return perms;
}

async function getPermsForUser(userId) {
  const { rows } = await pool.query(
    'SELECT perm_key, granted FROM ip_manager_permissions WHERE user_id = $1',
    [userId]
  );
  const perms = {};
  rows.forEach(r => { perms[r.perm_key] = r.granted; });
  return perms;
}

module.exports = { requireAuth, requirePermission, getPermsForUser, getRoleDefaultsFromDb, PERM_KEYS, ROLE_DEFAULTS };
