// src/middleware/auth.js — replaced by server step 4a (2026-09-14, SECURITY_AUDIT.md)
//
// What changed from the previous version, and why:
//
//  1. PERMISSIONS ARE READ FROM THE DATABASE ON EVERY REQUEST (10 s cache), not
//     from the token. The token used to carry a snapshot of the user's
//     permissions for 30 days: revoking a right, or deleting the user, changed
//     nothing until that token expired. Now a deleted user is refused within
//     10 s and a permission change applies within 10 s.
//  2. THE ADMIN ROLE PASSES EVERY PERMISSION CHECK, as the frontend engine
//     already assumed. Admin rows in ip_manager_permissions only covered
//     PERM_KEYS, so an admin could be refused a right nobody had seeded.
//  3. A permission must be exactly `true` — an unknown, NULL or missing key is
//     a refusal (deny by default).
//  4. req.access = { userId, username, role, admin, perms, scope } is the one
//     place later layers (the client scope filter, step 4b) read from.
//
// Exports are unchanged plus loadAccess / invalidateAccess, so every existing
// `require('../middleware/auth')` keeps working.
const jwt = require('jsonwebtoken');
const pool = require('../db');

const PERM_KEYS = [...new Set([
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
  // names the routes check that the old list never seeded
  'seeClients', 'seeDevices', 'seeLte', 'addLteDevice', 'editLteDevice', 'deleteLteDevice',
  'seeTicketing', 'createTicket', 'addTicket', 'editTicket', 'deleteTicket', 'assignTicket',
  // permissions v2 (server/permissions-v2.sql)
  'exportRealIP', 'exportFakeIP', 'exportWan', 'exportVlan', 'exportTunnels', 'exportVpn',
  'exportDsp', 'exportLte', 'exportDevices', 'exportClients', 'exportTickets', 'exportInventory',
  'addDevice', 'editDevice', 'deleteDevice', 'revealCredentialPassword', 'moderateComments',
  'seeSupportLog', 'addSupportCase', 'editSupportCase', 'deleteSupportCase', 'exportSupportLog',
  'importSupportLog', 'seeVisitReports', 'addVisitReport', 'editAnyVisitReport',
  'deleteVisitReport', 'exportVisitReports', 'seeRecycleBin', 'restoreArchive', 'purgeArchive',
  'assignClientScope',
])];

const DESTRUCTIVE = new Set(['manageUsers', 'deleteClient', 'deleteReal', 'deleteFake', 'deleteWan',
  'deleteTunnel', 'deleteVpn', 'deleteDsp', 'deleteVlan', 'deleteCredentials', 'deleteRealIpSubnet',
  'deleteInternalIpSubnet', 'deleteVlanV2', 'deleteWanV2', 'deleteTunnelV2', 'deleteVpnV2',
  'deleteDspV2', 'deleteCredentialV2', 'purgeArchive', 'assignClientScope', 'revealCredentialPassword']);

const ROLE_DEFAULTS = {
  admin: Object.fromEntries(PERM_KEYS.map(k => [k, true])),
  editor: Object.fromEntries(PERM_KEYS.map(k => [k, !DESTRUCTIVE.has(k)])),
  viewer: Object.fromEntries(PERM_KEYS.map(k => [k, k.startsWith('see')])),
};

async function getPermsForUser(userId) {
  const { rows } = await pool.query(
    'SELECT perm_key, granted FROM ip_manager_permissions WHERE user_id = $1',
    [userId]
  );
  const perms = {};
  rows.forEach(r => { perms[r.perm_key] = r.granted === true; });
  return perms;
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

/* ── ACCESS, FRESH FROM THE DATABASE ─────────────────────────────────────── */
const ACCESS_TTL_MS = 10000;
/* 12 h, plus slack for clock skew between issue and check. */
const MAX_TOKEN_LIFETIME_S = 12 * 3600 + 600;
const cache = new Map();

function invalidateAccess(userId) {
  if (userId === undefined || userId === null) cache.clear();
  else cache.delete(String(userId));
}

async function loadAccess(userId) {
  const key = String(userId);
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < ACCESS_TTL_MS) return hit.access;

  const u = await pool.query('SELECT * FROM ip_manager_users WHERE id = $1', [userId]);
  if (!u.rows.length) { cache.delete(key); return null; }
  const row = u.rows[0];
  const admin = String(row.role || '').toLowerCase() === 'admin';
  const perms = await getPermsForUser(row.id);

  /* The client scope (step 4b enforces it). null = sees every client. An
     'assigned' user with nothing assigned gets an EMPTY set — sees nothing —
     which is the safe reading of "only these", not "all". */
  let scope = null;
  if (!admin && row.scope_mode === 'assigned') {
    const s = await pool.query(
      'SELECT upper(trim(client_id)) AS c FROM user_client_scope WHERE user_id = $1', [row.id]);
    const heads = s.rows.map(r => r.c);
    const b = heads.length
      ? await pool.query(
          "SELECT upper(trim(id)) AS c FROM clients WHERE upper(trim(coalesce(parent_client_id,''))) = ANY($1)",
          [heads])
      : { rows: [] };
    scope = new Set([...heads, ...b.rows.map(r => r.c)]);
  }

  const access = { userId: row.id, username: row.username, role: row.role, admin, perms, scope };
  cache.set(key, { at: Date.now(), access });
  return access;
}

async function requireAuth(req, res, next) {
  /* Several mounts apply requireAuth twice (their own + the blanket one on
     /api/ip-manager). Once per request is enough. */
  if (req.access) return next();

  let decoded;
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ ok: false, error: 'Missing token' });
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ ok: false, error: 'Invalid or expired token', code: 'SESSION_EXPIRED' });
  }

  /* ── A TOKEN ISSUED TO LIVE LONGER THAN 12 HOURS IS REFUSED (step 5) ─────
     Step 4 made new sign-ins last 12 h, but every token issued before it
     still carried a 30-day expiry and kept working for up to a month. This
     refuses them once — everyone signs in again, one time — without rotating
     the signing secret. The frontend turns this 401 into the sign-in page. */
  if (decoded && decoded.iat && decoded.exp && decoded.exp - decoded.iat > MAX_TOKEN_LIFETIME_S) {
    return res.status(401).json({ ok: false, error: 'Your sign-in has expired — please sign in again', code: 'SESSION_EXPIRED' });
  }

  let access;
  try {
    access = await loadAccess(decoded.userId);
  } catch (err) {
    /* Fail CLOSED. If the database cannot say who this is, the answer is not
       "whoever the token claims". */
    console.error('requireAuth: access lookup failed:', err.message);
    return res.status(503).json({ ok: false, error: 'Access check unavailable — try again' });
  }
  if (!access) {
    return res.status(401).json({ ok: false, error: 'This account no longer exists — sign in again' });
  }

  req.access = access;
  req.auth = {
    ...decoded,
    userId: access.userId,
    username: access.username,
    role: access.role,
    perms: access.admin ? { ...access.perms, ...ROLE_DEFAULTS.admin } : access.perms,
  };

  /* A scoped user's request goes through the client-scope layer (src/scope.js):
     their answers are filtered and their writes checked. If the layer cannot
     run, the request is refused — never served unfiltered. */
  if (access.scope) {
    try {
      if (await scopeLayer().guard(req, res, access.scope)) return;
    } catch (err) {
      console.error('requireAuth: scope check failed:', err.message);
      return res.status(503).json({ ok: false, error: 'Access check unavailable — try again' });
    }
  }
  next();
}

let _scope = null;
function scopeLayer() {
  if (!_scope) _scope = require('../scope');
  return _scope;
}

function hasPermission(req, permKey) {
  if (req.access && req.access.admin) return true;
  return !!(req.auth && req.auth.perms && req.auth.perms[permKey] === true);
}

function requirePermission(permKey) {
  return (req, res, next) => {
    if (!req.auth) return res.status(401).json({ ok: false, error: 'Not authenticated' });
    if (!hasPermission(req, permKey)) {
      return res.status(403).json({ ok: false, error: `Missing permission: ${permKey}` });
    }
    next();
  };
}

module.exports = {
  requireAuth, requirePermission, hasPermission, getPermsForUser, getRoleDefaultsFromDb,
  loadAccess, invalidateAccess, PERM_KEYS, ROLE_DEFAULTS,
};
