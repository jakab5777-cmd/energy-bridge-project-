const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../db');
const { getPermsForUser, ROLE_DEFAULTS, PERM_KEYS } = require('../middleware/auth');

const router = express.Router();

// POST /api/ip-manager/auth/login
// Replaces the Apps Script login(username, password) function
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: 'Username and password required' });
  }

  const { rows } = await pool.query(
    'SELECT id, username, password_hash, role FROM ip_manager_users WHERE username = $1',
    [username.toLowerCase().trim()]
  );

  if (rows.length === 0) {
    return res.status(401).json({ ok: false, error: 'Invalid username or password' });
  }

  const user = rows[0];
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    return res.status(401).json({ ok: false, error: 'Invalid username or password' });
  }

  const perms = await getPermsForUser(user.id);

  const token = jwt.sign(
    { userId: user.id, username: user.username, role: user.role, perms },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );

  await pool.query(
    'INSERT INTO ip_manager_users (id) VALUES ($1) ON CONFLICT (id) DO NOTHING', [user.id]
  ).catch(() => {}); // no-op safeguard, ignore

  res.json({
    ok: true,
    token,
    user: { id: user.id, username: user.username, role: user.role },
    perms
  });
});

// One-time setup helper — creates the first admin user if none exist.
// Run this once, then remove or protect this route.
router.post('/bootstrap-admin', async (req, res) => {
  const { rows } = await pool.query('SELECT COUNT(*) FROM ip_manager_users');
  if (parseInt(rows[0].count, 10) > 0) {
    return res.status(403).json({ ok: false, error: 'Users already exist — bootstrap disabled' });
  }

  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: 'Username and password required' });
  }

  const hash = await bcrypt.hash(password, 12);
  const { rows: created } = await pool.query(
    'INSERT INTO ip_manager_users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
    [username.toLowerCase().trim(), hash, 'admin']
  );

  const userId = created[0].id;
  const perms = ROLE_DEFAULTS.admin;
  for (const key of PERM_KEYS) {
    await pool.query(
      'INSERT INTO ip_manager_permissions (user_id, perm_key, granted) VALUES ($1, $2, $3)',
      [userId, key, perms[key] || false]
    );
  }

  res.json({ ok: true, message: 'Admin user created', userId });
});

module.exports = router;
