const express = require('express');
const pool = require('../db');
const { requirePermission } = require('../middleware/auth');
const router = express.Router();

// GET /api/ip-manager/internal-ips?subnet=5.100.240
router.get('/', requirePermission('seeFakeIP'), async (req, res) => {
  const { subnet } = req.query;
  const query = subnet
    ? { text: 'SELECT * FROM internal_ips WHERE subnet = $1 ORDER BY internal_ip', values: [subnet] }
    : { text: 'SELECT * FROM internal_ips ORDER BY subnet, internal_ip' };
  const { rows } = await pool.query(query);
  res.json({ ok: true, data: rows });
});

// GET /api/ip-manager/internal-ips/subnets — list of existing internal subnets
router.get('/subnets', requirePermission('seeFakeIP'), async (req, res) => {
  const { rows } = await pool.query('SELECT subnet FROM internal_subnets ORDER BY subnet');
  res.json({ ok: true, data: rows.map(r => r.subnet) });
});

// PUT /api/ip-manager/internal-ips/subnets
// Replaces saveInternalSubnets(payload) — payload: { subnets: ['5.100.240', '10.50.1'] }
router.put('/subnets', requirePermission('addFakeSubnet'), async (req, res) => {
  const { subnets } = req.body;
  if (!Array.isArray(subnets)) return res.status(400).json({ ok: false, error: 'subnets[] required' });

  for (const subnet of subnets) {
    await pool.query(
      'INSERT INTO internal_subnets (subnet) VALUES ($1) ON CONFLICT (subnet) DO NOTHING',
      [subnet]
    );
  }
  res.json({ ok: true, added: subnets.length });
});

// PATCH /api/ip-manager/internal-ips/batch
// Replaces saveInternalRows(payload) — sparse: only inserts rows with a client_id set
router.patch('/batch', requirePermission('assignFake'), async (req, res) => {
  const { subnet, rows } = req.body;
  if (!subnet || !Array.isArray(rows)) {
    return res.status(400).json({ ok: false, error: 'subnet and rows[] required' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let inserted = 0;
    let cleared = 0;
    for (const row of rows) {
      // Sparse design: skip rows with no client assigned — don't store empty placeholders
      /* EB_CLEAR_PATCH: sparse table - a null client means DELETE the row, not skip it */
      if (!row.client_id) { const _d = await client.query("DELETE FROM internal_ips WHERE internal_ip = $1 AND subnet = $2 AND ($3::text IS NULL OR client_id = $3)", [row.internal_ip, subnet, row.prev_client_id || null]); cleared += _d.rowCount; continue; }
      await client.query(
        `INSERT INTO internal_ips (subnet, internal_ip, client_id, client_name, block_id, updated_at)
         VALUES ($1,$2,$3,$4,$5, NOW())
         ON CONFLICT (subnet, internal_ip, client_id) DO UPDATE SET
           client_id = EXCLUDED.client_id, client_name = EXCLUDED.client_name,
           block_id = EXCLUDED.block_id, updated_at = NOW()`,
        [subnet, row.internal_ip, row.client_id, row.client_name || null, row.block_id || null]
      );
      inserted++;
    }
    await client.query('COMMIT');
    res.json({ ok: true, updated: inserted, cleared });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ ok: false, error: err.message });
  } finally {
    client.release();
  }
});

/* EB_PURGE_ROUTE — removing a subnet must remove its ADDRESS ROWS too.
 * /clear only empties the assignment and keeps the row, so GET /all
 * regrouped the leftovers and the subnet came back on the next refresh.
 * Refuses (409) while anything is still assigned. */
router.delete('/', requirePermission('deleteFakeSubnet'), async (req, res) => {
  const { subnet } = req.query;
  if (!subnet) return res.status(400).json({ ok: false, error: 'subnet required' });
  try {
    const busy = await pool.query('SELECT count(*)::int n FROM internal_ips WHERE subnet=$1 AND client_id IS NOT NULL', [subnet]);
    if (busy.rows[0].n > 0) {
      return res.status(409).json({ ok: false, error: busy.rows[0].n + ' address(es) in ' + subnet + ' are still assigned' });
    }
    const r = await pool.query('DELETE FROM internal_ips WHERE subnet=$1 RETURNING internal_ip', [subnet]);
    res.json({ ok: true, deleted: r.rowCount });
  } catch (err) {
    console.error('DELETE internal_ips:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

module.exports = router;
