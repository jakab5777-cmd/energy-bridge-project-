const express = require('express');
const pool = require('../db');
const { requirePermission } = require('../middleware/auth');
const { encrypt, decrypt } = require('../crypto');
const router = express.Router();

// GET /api/ip-manager/vpn — passwords decrypted only here, at the API boundary
router.get('/', requirePermission('seeVpn'), async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM vpn_entries ORDER BY id DESC');
  const data = rows.map(r => ({
    ...r,
    vpn_password: r.vpn_password_encrypted ? decrypt(r.vpn_password_encrypted) : null,
    vpn_password_encrypted: undefined
  }));
  res.json({ ok: true, data });
});

// POST /api/ip-manager/vpn — replaces addVpn(auth, payload)
router.post('/', requirePermission('addVpn'), async (req, res) => {
  const { client_id, client_name, vpn_type, vpn_ip, vpn_username, vpn_password, description } = req.body;
  const { rows } = await pool.query(
    `INSERT INTO vpn_entries (client_id, client_name, vpn_type, vpn_ip, vpn_username, vpn_password_encrypted, description)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
    [client_id, client_name, vpn_type, vpn_ip, vpn_username, encrypt(vpn_password), description]
  );
  res.status(201).json({ ok: true, id: rows[0].id });
});

// PATCH /api/ip-manager/vpn/:id — replaces editVpn(auth, payload)
router.patch('/:id', requirePermission('editVpn'), async (req, res) => {
  const { client_id, client_name, vpn_type, vpn_ip, vpn_username, vpn_password, description } = req.body;
  await pool.query(
    `UPDATE vpn_entries SET client_id=$1, client_name=$2, vpn_type=$3, vpn_ip=$4,
     vpn_username=$5, vpn_password_encrypted=$6, description=$7 WHERE id=$8`,
    [client_id, client_name, vpn_type, vpn_ip, vpn_username, encrypt(vpn_password), description, req.params.id]
  );
  res.json({ ok: true });
});

// DELETE /api/ip-manager/vpn/:id — replaces deleteVpn(auth, payload)
router.delete('/:id', requirePermission('deleteVpn'), async (req, res) => {
  await pool.query('DELETE FROM vpn_entries WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

module.exports = router;
