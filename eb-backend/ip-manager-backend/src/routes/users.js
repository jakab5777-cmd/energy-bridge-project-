const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('../db');
const { requirePermission, getPermsForUser, getRoleDefaultsFromDb, PERM_KEYS, ROLE_DEFAULTS } = require('../middleware/auth');
const router = express.Router();

router.get('/', requirePermission('manageUsers'), async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, role, created_at FROM ip_manager_users ORDER BY username');
  const withPerms = await Promise.all(rows.map(async u => ({
    ...u,
    perms: await getPermsForUser(u.id)
  })));
  res.json({ ok: true, data: withPerms });
});

router.post('/', requirePermission('manageUsers'), async (req, res) => {
  const { username, password, role, perms } = req.body;
  if (!username || !password) return res.status(400).json({ ok: false, error: 'username and password required' });

  const hash = await bcrypt.hash(password, 12);
  const { rows } = await pool.query(
    'INSERT INTO ip_manager_users (username, password_hash, role) VALUES ($1,$2,$3) RETURNING id',
    [username.toLowerCase().trim(), hash, role || 'viewer']
  );
  const userId = rows[0].id;

  const finalPerms = perms || await getRoleDefaultsFromDb(role || 'viewer') || ROLE_DEFAULTS.viewer;
  for (const key of PERM_KEYS) {
    await pool.query(
      'INSERT INTO ip_manager_permissions (user_id, perm_key, granted) VALUES ($1,$2,$3)',
      [userId, key, finalPerms[key] || false]
    );
  }
  res.status(201).json({ ok: true, id: userId });
});

router.patch('/:id', requirePermission('manageUsers'), async (req, res) => {
  const { password, role, perms } = req.body;

  if (password) {
    const hash = await bcrypt.hash(password, 12);
    await pool.query('UPDATE ip_manager_users SET password_hash = $1 WHERE id = $2', [hash, req.params.id]);
  }
  if (role) {
    await pool.query('UPDATE ip_manager_users SET role = $1 WHERE id = $2', [role, req.params.id]);
  }
  if (perms) {
    for (const key of Object.keys(perms)) {
      await pool.query(
        `INSERT INTO ip_manager_permissions (user_id, perm_key, granted) VALUES ($1,$2,$3)
         ON CONFLICT (user_id, perm_key) DO UPDATE SET granted = $3`,
        [req.params.id, key, perms[key]]
      );
    }
  }
  res.json({ ok: true });
});

router.delete('/:id', requirePermission('manageUsers'), async (req, res) => {
  const { rows } = await pool.query('SELECT role FROM ip_manager_users WHERE id = $1', [req.params.id]);
  if (rows.length === 0) {
    return res.status(404).json({ ok: false, error: 'User not found' });
  }
  if (rows[0].role === 'admin') {
    return res.status(403).json({ ok: false, error: 'Cannot delete an admin account' });
  }
  if (req.params.id === req.auth.userId) {
    return res.status(403).json({ ok: false, error: 'Cannot delete your own account' });
  }
  await pool.query('DELETE FROM ip_manager_users WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

module.exports = router;
