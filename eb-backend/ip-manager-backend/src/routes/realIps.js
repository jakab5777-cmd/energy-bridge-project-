const express = require('express');
const pool = require('../db');
const { requirePermission } = require('../middleware/auth');
const router = express.Router();

// GET /api/ip-manager/real-ips?subnet=5.100.240
router.get('/', requirePermission('seeRealIP'), async (req, res) => {
  const { subnet } = req.query;
  const query = subnet
    ? { text: 'SELECT * FROM real_ips WHERE subnet = $1 ORDER BY real_ip', values: [subnet] }
    : { text: 'SELECT * FROM real_ips ORDER BY subnet, real_ip' };
  const { rows } = await pool.query(query);
  res.json({ ok: true, data: rows });
});

// PATCH /api/ip-manager/real-ips/batch
// Replaces saveRows(payload) — payload: { subnet, rows: [{real_ip, client_id, client_name, fake_ip, vlan_id, dsp, block_id}] }
router.patch('/batch', requirePermission('assignReal'), async (req, res) => {
  const { subnet, rows } = req.body;
  if (!subnet || !Array.isArray(rows)) {
    return res.status(400).json({ ok: false, error: 'subnet and rows[] required' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const row of rows) {
      await client.query(
        `INSERT INTO real_ips (subnet, real_ip, client_id, client_name, fake_ip, vlan_id, dsp, block_id, notes, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, NOW())
         ON CONFLICT (real_ip) DO UPDATE SET
           client_id = EXCLUDED.client_id, client_name = EXCLUDED.client_name,
           fake_ip = EXCLUDED.fake_ip, vlan_id = EXCLUDED.vlan_id,
           dsp = EXCLUDED.dsp, block_id = EXCLUDED.block_id, notes = CASE WHEN $10::boolean THEN EXCLUDED.notes ELSE real_ips.notes END, updated_at = NOW()`,
        [subnet, row.real_ip, row.client_id || null, row.client_name || null,
         row.fake_ip || null, row.vlan_id || null, row.dsp || null, row.block_id || null, (row.notes == null ? null : (String(row.notes).trim() || null)), Object.prototype.hasOwnProperty.call(row, "notes")]
      );
    }
    await client.query('COMMIT');
    res.json({ ok: true, updated: rows.length });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ ok: false, error: err.message });
  } finally {
    client.release();
  }
});

// PATCH /api/ip-manager/real-ips/clear
// Replaces clearRows(payload) — clears assignment fields but keeps the IP row
router.patch('/clear', requirePermission('editReal'), async (req, res) => {
  const { real_ips } = req.body; // array of IP strings to clear
  if (!Array.isArray(real_ips)) return res.status(400).json({ ok: false, error: 'real_ips[] required' });

  await pool.query(
    `UPDATE real_ips SET client_id = NULL, client_name = NULL, fake_ip = NULL,
     vlan_id = NULL, dsp = NULL, block_id = NULL, notes = NULL, updated_at = NOW()
     WHERE real_ip = ANY($1)`,
    [real_ips]
  );
  res.json({ ok: true, cleared: real_ips.length });
});

/* EB_PURGE_ROUTE — removing a subnet must remove its ADDRESS ROWS too.
 * /clear only empties the assignment and keeps the row, so GET /all
 * regrouped the leftovers and the subnet came back on the next refresh.
 * Refuses (409) while anything is still assigned. */
router.delete('/', requirePermission('deleteRealIpSubnet'), async (req, res) => {
  const { subnet } = req.query;
  if (!subnet) return res.status(400).json({ ok: false, error: 'subnet required' });
  try {
    const busy = await pool.query('SELECT count(*)::int n FROM real_ips WHERE subnet=$1 AND client_id IS NOT NULL', [subnet]);
    if (busy.rows[0].n > 0) {
      return res.status(409).json({ ok: false, error: busy.rows[0].n + ' address(es) in ' + subnet + ' are still assigned' });
    }
    const r = await pool.query('DELETE FROM real_ips WHERE subnet=$1 RETURNING real_ip', [subnet]);
    res.json({ ok: true, deleted: r.rowCount });
  } catch (err) {
    console.error('DELETE real_ips:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

module.exports = router;
