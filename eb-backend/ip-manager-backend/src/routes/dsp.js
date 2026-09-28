const express = require('express');
const pool = require('../db');
const { requirePermission } = require('../middleware/auth');
const router = express.Router();

// GET /api/ip-manager/dsp
router.get('/', requirePermission('seeDsp'), async (req, res) => {
  const { rows } = await pool.query('SELECT dsp_name FROM dsp_providers ORDER BY dsp_name');
  res.json({ ok: true, data: rows.map(r => r.dsp_name) });
});

// PUT /api/ip-manager/dsp — replaces saveDSP(payload), full list replace
router.put('/', requirePermission('addDsp'), async (req, res) => {
  const { list } = req.body;
  if (!Array.isArray(list)) return res.status(400).json({ ok: false, error: 'list[] required' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM dsp_providers');
    for (const name of list) {
      await client.query('INSERT INTO dsp_providers (dsp_name) VALUES ($1) ON CONFLICT DO NOTHING', [name]);
    }
    await client.query('COMMIT');
    res.json({ ok: true, count: list.length });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ ok: false, error: err.message });
  } finally {
    client.release();
  }
});

module.exports = router;
