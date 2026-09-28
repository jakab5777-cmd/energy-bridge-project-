const express = require('express');
const pool = require('../db');
const { requirePermission } = require('../middleware/auth');
const router = express.Router();

const VLAN_COLUMNS = [
  'vlan_id','status','assignment_type','zone','service_category','client_id',
  'client_name','real_ip','fake_ip','bng_card','primary_path','backup_path',
  'other_path','source','cdn','notes','locked','dsp','group_id'
];

// GET /api/ip-manager/vlans
router.get('/', requirePermission('seeVlan'), async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM vlan_tracking ORDER BY vlan_id');
  res.json({ ok: true, data: rows });
});

// POST /api/ip-manager/vlans — replaces addVlan(auth, payload)
router.post('/', requirePermission('addVlan'), async (req, res) => {
  const values = VLAN_COLUMNS.map(c => req.body[c] ?? null);
  const placeholders = VLAN_COLUMNS.map((_, i) => `$${i + 1}`).join(', ');
  const { rows } = await pool.query(
    `INSERT INTO vlan_tracking (${VLAN_COLUMNS.join(', ')}, last_modified)
     VALUES (${placeholders}, NOW()) RETURNING *`,
    values
  );
  res.status(201).json({ ok: true, data: rows[0] });
});

// PATCH /api/ip-manager/vlans/:id — replaces editVlan(auth, payload)
router.patch('/:id', requirePermission('editVlan'), async (req, res) => {
  const values = VLAN_COLUMNS.map(c => req.body[c] ?? null);
  const setClause = VLAN_COLUMNS.map((c, i) => `${c} = $${i + 1}`).join(', ');
  const { rows } = await pool.query(
    `UPDATE vlan_tracking SET ${setClause}, last_modified = NOW() WHERE id = $${VLAN_COLUMNS.length + 1} RETURNING *`,
    [...values, req.params.id]
  );
  if (rows.length === 0) return res.status(404).json({ ok: false, error: 'Not found' });
  res.json({ ok: true, data: rows[0] });
});

// DELETE /api/ip-manager/vlans/:id — replaces deleteVlan(auth, payload)
router.delete('/:id', requirePermission('deleteVlan'), async (req, res) => {
  await pool.query('DELETE FROM vlan_tracking WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

// POST /api/ip-manager/vlans/batch-add — replaces batchAddVlan(auth, payload)
router.post('/batch-add', requirePermission('addVlan'), async (req, res) => {
  const { rows: inputRows } = req.body;
  if (!Array.isArray(inputRows)) return res.status(400).json({ ok: false, error: 'rows[] required' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const row of inputRows) {
      const values = VLAN_COLUMNS.map(c => row[c] ?? null);
      const placeholders = VLAN_COLUMNS.map((_, i) => `$${i + 1}`).join(', ');
      await client.query(
        `INSERT INTO vlan_tracking (${VLAN_COLUMNS.join(', ')}, last_modified) VALUES (${placeholders}, NOW())`,
        values
      );
    }
    await client.query('COMMIT');
    res.json({ ok: true, added: inputRows.length });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ ok: false, error: err.message });
  } finally {
    client.release();
  }
});

// PATCH /api/ip-manager/vlans/batch-edit — replaces batchEditVlan(auth, payload)
router.patch('/batch-edit', requirePermission('editVlan'), async (req, res) => {
  const { ids, changes } = req.body; // changes: { status: 'active', ... } applied to all ids
  if (!Array.isArray(ids) || !changes) return res.status(400).json({ ok: false, error: 'ids[] and changes required' });

  const setKeys = Object.keys(changes).filter(k => VLAN_COLUMNS.includes(k));
  const setClause = setKeys.map((k, i) => `${k} = $${i + 1}`).join(', ');
  const values = setKeys.map(k => changes[k]);

  await pool.query(
    `UPDATE vlan_tracking SET ${setClause}, last_modified = NOW() WHERE id = ANY($${setKeys.length + 1})`,
    [...values, ids]
  );
  res.json({ ok: true, updated: ids.length });
});

// POST /api/ip-manager/vlans/batch-delete — replaces batchDeleteVlan(auth, payload)
router.post('/batch-delete', requirePermission('deleteVlan'), async (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids)) return res.status(400).json({ ok: false, error: 'ids[] required' });
  await pool.query('DELETE FROM vlan_tracking WHERE id = ANY($1)', [ids]);
  res.json({ ok: true, deleted: ids.length });
});

// PUT /api/ip-manager/vlans/meta — replaces saveVlanMeta(payload) — cdnList only (V14)
router.put('/meta', requirePermission('editVlan'), async (req, res) => {
  const { cdnList } = req.body;
  if (cdnList) {
    await pool.query(
      `INSERT INTO vlan_meta (key, value) VALUES ('cdnList', $1)
       ON CONFLICT (key) DO UPDATE SET value = $1`, [JSON.stringify(cdnList)]
    );
  }
  res.json({ ok: true });
});

// GET /api/ip-manager/vlans/meta
router.get('/meta', requirePermission('seeVlan'), async (req, res) => {
  const { rows } = await pool.query("SELECT value FROM vlan_meta WHERE key = 'cdnList'");
  res.json({ ok: true, cdnList: rows[0]?.value || [] });
});

module.exports = router;
