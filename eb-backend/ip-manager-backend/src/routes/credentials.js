const express = require('express');
const pool = require('../db');
const { requirePermission } = require('../middleware/auth');
const { encrypt, decrypt } = require('../crypto');
const router = express.Router();

// GET /api/ip-manager/credentials — replaces getCredentials(payload)
router.get('/', requirePermission('seeCredentials'), async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM credentials ORDER BY id DESC');
  const data = rows.map(r => ({
    ...r,
    password: r.password_encrypted ? decrypt(r.password_encrypted) : null,
    password_encrypted: undefined
  }));

  const metaResult = await pool.query('SELECT key, value FROM cred_meta');
  const meta = {};
  metaResult.rows.forEach(r => { meta[r.key] = r.value; });

  res.json({ ok: true, data, nodeTypes: meta.nodeTypes || [], categories: meta.categories || [] });
});

// POST /api/ip-manager/credentials — replaces addCredential(payload)
router.post('/', requirePermission('addCredentials'), async (req, res) => {
  const b = req.body;
  const { rows } = await pool.query(
    `INSERT INTO credentials (subnet, gateway, vlan, category, net_desc, ip_address, node_type, device_desc, username, password_encrypted, login_url, additional)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
    [b.subnet, b.gateway, b.vlan, b.category, b.net_desc, b.ip_address, b.node_type,
     b.device_desc, b.username, encrypt(b.password), b.login_url, b.additional]
  );
  res.status(201).json({ ok: true, id: rows[0].id });
});

// PATCH /api/ip-manager/credentials/:id — replaces editCredential(payload)
router.patch('/:id', requirePermission('editCredentials'), async (req, res) => {
  const b = req.body;
  await pool.query(
    `UPDATE credentials SET subnet=$1, gateway=$2, vlan=$3, category=$4, net_desc=$5,
     ip_address=$6, node_type=$7, device_desc=$8, username=$9, password_encrypted=$10,
     login_url=$11, additional=$12 WHERE id=$13`,
    [b.subnet, b.gateway, b.vlan, b.category, b.net_desc, b.ip_address, b.node_type,
     b.device_desc, b.username, encrypt(b.password), b.login_url, b.additional, req.params.id]
  );
  res.json({ ok: true });
});

// DELETE /api/ip-manager/credentials/:id
router.delete('/:id', requirePermission('deleteCredentials'), async (req, res) => {
  await pool.query('DELETE FROM credentials WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

// PUT /api/ip-manager/credentials/meta — replaces saveCredMeta(payload)
router.put('/meta', requirePermission('addCredentials'), async (req, res) => {
  const { nodeTypes, categories } = req.body;
  if (nodeTypes) {
    await pool.query(
      `INSERT INTO cred_meta (key, value) VALUES ('nodeTypes', $1)
       ON CONFLICT (key) DO UPDATE SET value = $1`, [JSON.stringify(nodeTypes)]
    );
  }
  if (categories) {
    await pool.query(
      `INSERT INTO cred_meta (key, value) VALUES ('categories', $1)
       ON CONFLICT (key) DO UPDATE SET value = $1`, [JSON.stringify(categories)]
    );
  }
  res.json({ ok: true });
});

module.exports = router;
