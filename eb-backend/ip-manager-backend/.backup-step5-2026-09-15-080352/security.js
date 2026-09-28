// src/security.js — added by server step 4a (2026-09-14, SECURITY_AUDIT.md)
//
// Mounted once in server.js, directly after express.json(), so everything in
// here runs BEFORE the routes it protects or replaces:
//
//   1. Sign-in throttle         POST /api/ip-manager/auth/login
//   2. Private notepad          GET/POST /api/ip-manager/support-notes
//                               (was: anyone read everyone's notes, and could
//                               overwrite anyone's by sending their username)
//   3. Platform permission      PUT/POST/DELETE /api/platform/users/:id/permissions
//      writes need manageUsers  and /api/platform/roles/:id/permissions
//                               (were: any signed-in user could rewrite them)
//   4. Role defaults            PUT /api/platform/permissions/role/:role
//   5. Client scope storage     GET/PUT /api/ip-manager/users/:id/scope
//                               Stored and editable now; FILTERING is step 4b,
//                               and the answer says so (enforced:false).
const express = require('express');
const pool = require('./db');
const { requireAuth, requirePermission, hasPermission, invalidateAccess } = require('./middleware/auth');

const router = express.Router();

/* True when the filter (src/scope.js) is installed next to this file. The
   Permissions page shows "not enforced yet" whenever this is false. */
const SCOPE_ENFORCED = (() => {
  try { require.resolve('./scope'); return true; } catch (e) { return false; }
})();

/* ── 1. SIGN-IN THROTTLE ──────────────────────────────────────────────────
   Per USERNAME, not per IP: behind nginx every request arrives from
   127.0.0.1, so a per-IP limit would lock the whole company out at once.
   Five free failures in 15 minutes, then one attempt per 30 seconds for that
   username — about 120 guesses an hour instead of thousands, and a real user
   who fat-fingered their password waits half a minute, never an hour. */
const FAILS = new Map();
const WINDOW_MS = 15 * 60 * 1000, FREE_TRIES = 5, DELAY_MS = 30 * 1000;

router.use('/api/ip-manager/auth/login', (req, res, next) => {
  if (req.method !== 'POST') return next();
  const user = String((req.body && req.body.username) || '').toLowerCase().trim();
  if (!user) return next();
  const now = Date.now();
  const f = FAILS.get(user);
  if (f && now - f.first > WINDOW_MS) FAILS.delete(user);
  const g = FAILS.get(user);
  if (g && g.count >= FREE_TRIES && now - g.last < DELAY_MS) {
    res.set('Retry-After', String(Math.ceil((DELAY_MS - (now - g.last)) / 1000)));
    return res.status(429).json({ ok: false, error: 'Too many failed sign-ins for this account — wait 30 seconds and try again.' });
  }
  const json = res.json.bind(res);
  res.json = (body) => {
    if (res.statusCode === 401) {
      if (FAILS.size > 10000) FAILS.clear();
      const h = FAILS.get(user) || { count: 0, first: Date.now(), last: 0 };
      h.count += 1; h.last = Date.now();
      FAILS.set(user, h);
    } else if (res.statusCode < 400) {
      FAILS.delete(user);
    }
    return json(body);
  };
  next();
});

/* ── 2. THE NOTEPAD IS PRIVATE ───────────────────────────────────────────── */
router.get('/api/ip-manager/support-notes', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT username, body, updated_at FROM support_notes WHERE username = $1', [req.auth.username]);
    res.json({ ok: true, data: r.rows });
  } catch (err) {
    console.error('support-notes GET:', err.message);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

router.post('/api/ip-manager/support-notes', requireAuth, async (req, res) => {
  try {
    const body = String((req.body && req.body.body) || '');
    if (body.length > 100000) return res.status(413).json({ ok: false, error: 'Note is too long' });
    await pool.query(
      `INSERT INTO support_notes (username, body, updated_at) VALUES ($1,$2,now())
       ON CONFLICT (username) DO UPDATE SET body = EXCLUDED.body, updated_at = now()`,
      [req.auth.username, body]);          // the TOKEN's username — never the body's
    res.json({ ok: true });
  } catch (err) {
    console.error('support-notes POST:', err.message);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

/* ── 3. PLATFORM PERMISSION WRITES NEED manageUsers ───────────────────────── */
const writesNeedManageUsers = (req, res, next) =>
  req.method === 'GET' ? next() : requirePermission('manageUsers')(req, res, next);
router.use('/api/platform/users/:id/permissions', requireAuth, writesNeedManageUsers);
router.use('/api/platform/roles/:id/permissions', requireAuth, writesNeedManageUsers);
/* The ticketing platform's own user and role routes carry
   "TODO: plug in existing auth middleware" — any signed-in account could
   create a staff login, rename one, reset its password or delete it. */
router.use('/api/platform/users', requireAuth, writesNeedManageUsers);
router.use('/api/platform/roles', requireAuth, writesNeedManageUsers);

/* ── 4. ROLE DEFAULTS ─────────────────────────────────────────────────────
   Insert what is missing, THEN remove what is no longer wanted — two
   idempotent statements, so an interruption between them can only leave a
   role with MORE of the rights it was being given, never fewer than it had. */
router.put('/api/platform/permissions/role/:role', requireAuth, requirePermission('manageUsers'), async (req, res) => {
  try {
    const role = String(req.params.role || '').trim();
    const names = Array.isArray(req.body && req.body.permissions)
      ? [...new Set(req.body.permissions.map(String))] : null;
    if (!role) return res.status(400).json({ ok: false, error: 'role required' });
    if (!names) return res.status(400).json({ ok: false, error: 'permissions[] required' });
    await pool.query(
      `INSERT INTO role_permissions (role, permission_id)
       SELECT $1, p.permission_id FROM permissions p
       WHERE p.permission_name = ANY($2)
         AND NOT EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role = $1 AND rp.permission_id = p.permission_id)`,
      [role, names]);
    await pool.query(
      `DELETE FROM role_permissions rp WHERE rp.role = $1
         AND rp.permission_id NOT IN (SELECT permission_id FROM permissions WHERE permission_name = ANY($2))`,
      [role, names]);
    const { rows } = await pool.query('SELECT count(*)::int AS n FROM role_permissions WHERE role = $1', [role]);
    res.json({ ok: true, data: { role, permissions: rows[0].n } });
  } catch (err) {
    console.error('role defaults PUT:', err.message);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

/* ── 5. CLIENT SCOPE ──────────────────────────────────────────────────────
   Who may read a scope: the user themself, or anyone with manageUsers /
   assignClientScope. Who may change it: only the latter. Unknown user →
   404, whatever the reason (a malformed id included), so ids cannot be
   probed. */
const mayManageScope = (req) => hasPermission(req, 'manageUsers') || hasPermission(req, 'assignClientScope');

router.get('/api/ip-manager/users/:id/scope', requireAuth, async (req, res) => {
  const id = req.params.id;
  if (String(id) !== String(req.auth.userId) && !mayManageScope(req)) {
    return res.status(403).json({ ok: false, error: 'Missing permission: assignClientScope' });
  }
  try {
    const u = await pool.query('SELECT role, scope_mode FROM ip_manager_users WHERE id = $1', [id]);
    if (!u.rows.length) return res.status(404).json({ ok: false, error: 'User not found' });
    const c = await pool.query('SELECT client_id FROM user_client_scope WHERE user_id = $1 ORDER BY client_id', [id]);
    res.json({ ok: true, data: {
      mode: u.rows[0].scope_mode === 'assigned' ? 'assigned' : 'all',
      clients: c.rows.map(r => r.client_id),
      admin: String(u.rows[0].role || '').toLowerCase() === 'admin',
      enforced: SCOPE_ENFORCED,
    } });
  } catch (err) {
    if (err.code === '22P02') return res.status(404).json({ ok: false, error: 'User not found' });
    console.error('scope GET:', err.message);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

router.put('/api/ip-manager/users/:id/scope', requireAuth, async (req, res) => {
  if (!mayManageScope(req)) return res.status(403).json({ ok: false, error: 'Missing permission: assignClientScope' });
  const id = req.params.id;
  const mode = req.body && req.body.mode === 'assigned' ? 'assigned' : (req.body && req.body.mode === 'all' ? 'all' : null);
  if (!mode) return res.status(400).json({ ok: false, error: "mode must be 'all' or 'assigned'" });
  const wanted = Array.isArray(req.body.clients)
    ? [...new Set(req.body.clients.map(c => String(c || '').trim().toUpperCase()).filter(Boolean))] : [];
  if (wanted.length > 1000) return res.status(400).json({ ok: false, error: 'Too many clients' });
  try {
    const u = await pool.query('SELECT id FROM ip_manager_users WHERE id = $1', [id]);
    if (!u.rows.length) return res.status(404).json({ ok: false, error: 'User not found' });

    if (mode === 'assigned' && wanted.length) {
      const { rows } = await pool.query(
        "SELECT upper(trim(id)) AS id, upper(trim(coalesce(parent_client_id,''))) AS parent FROM clients WHERE upper(trim(id)) = ANY($1)",
        [wanted]);
      const known = new Map(rows.map(r => [r.id, r.parent]));
      const unknown = wanted.filter(w => !known.has(w));
      if (unknown.length) return res.status(400).json({ ok: false, error: 'Not in the Clients table: ' + unknown.slice(0, 5).join(', ') });
      const branches = wanted.filter(w => known.get(w));
      if (branches.length) {
        return res.status(400).json({ ok: false, error: `${branches[0]} is a branch of ${known.get(branches[0])} — assign the head office; its branches come with it` });
      }
    }

    await pool.query('UPDATE ip_manager_users SET scope_mode = $1 WHERE id = $2', [mode, id]);
    await pool.query('DELETE FROM user_client_scope WHERE user_id = $1', [id]);
    if (mode === 'assigned' && wanted.length) {
      await pool.query(
        'INSERT INTO user_client_scope (user_id, client_id) SELECT $1, unnest($2::text[])', [id, wanted]);
    }
    invalidateAccess(id);
    res.json({ ok: true, data: { mode, clients: mode === 'assigned' ? wanted : [], enforced: SCOPE_ENFORCED } });
  } catch (err) {
    if (err.code === '22P02') return res.status(404).json({ ok: false, error: 'User not found' });
    console.error('scope PUT:', err.message);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

/* Changing a user's permissions or deleting them must take effect at once,
   not after the 10 s cache: drop the cached access after any write to
   /api/ip-manager/users. */
router.use('/api/ip-manager/users', (req, res, next) => {
  if (req.method !== 'GET') res.on('finish', () => invalidateAccess());
  next();
});

module.exports = router;
