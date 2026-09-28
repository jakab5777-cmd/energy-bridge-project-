const pool = require('../db');
const { requirePermission } = require('../middleware/auth');

const logAction = async (table, recordId, action, userId, oldData = null, newData = null) => {
  try {
    await pool.query(
      'INSERT INTO change_logs (table_name, record_id, action, changed_by, old_data, new_data) VALUES ($1, $2, $3, $4, $5, $6)',
      [table, recordId, action, userId || null, oldData, newData]
    );
  } catch (err) {
    console.error("Audit log failed:", err.message);
  }
};

const buildCrudRouter = ({ table, columns, permPrefix, primaryKey = 'id' }) => {
  const express = require('express');
  const router = express.Router();
  const cols = columns.join(', ');
  const placeholders = columns.map((_, i) => `$${i + 1}`).join(', ');

  router.get('/', async (req, res) => {
    try {
      const { rows } = await pool.query(`SELECT * FROM ${table} ORDER BY ${primaryKey} DESC`);
      res.json({ ok: true, data: rows });
    } catch (err) {
      console.error(`GET ${table} error:`, err.message);
      res.status(500).json({ ok: false, error: 'Internal server error' });
    }
  });

  router.post('/', requirePermission(`add${permPrefix}`), async (req, res) => {
    try {
      const values = columns.map(c => req.body[c] ?? null);
      const { rows } = await pool.query(
        `INSERT INTO ${table} (${cols}) VALUES (${placeholders}) RETURNING *`,
        values
      );
      await logAction(table, rows[0][primaryKey], 'INSERT', req.auth?.userId, null, rows[0]);
      res.status(201).json({ ok: true, data: rows[0] });
    } catch (err) {
      console.error(`POST ${table} error:`, err.message);
      res.status(500).json({ ok: false, error: 'Internal server error' });
    }
  });

  router.patch('/:id', requirePermission(`edit${permPrefix}`), async (req, res) => {
    try {
      // Only update columns actually present in the request body, never the primary key itself
      const updatable = columns.filter(c => c !== primaryKey && req.body[c] !== undefined);
      if (updatable.length === 0) {
        return res.status(400).json({ ok: false, error: 'No updatable fields provided', received_keys: Object.keys(req.body || {}), table_columns: columns });
      }
      const setClause = updatable.map((c, i) => `${c} = $${i + 1}`).join(', ');
      const values = updatable.map(c => req.body[c]);
      const { rows } = await pool.query(
        `UPDATE ${table} SET ${setClause} WHERE ${primaryKey} = $${updatable.length + 1} RETURNING *`,
        [...values, req.params.id]
      );
      if (rows.length === 0) return res.status(404).json({ ok: false, error: 'Not found' });
      await logAction(table, req.params.id, 'UPDATE', req.auth?.userId, null, rows[0]);
      res.json({ ok: true, data: rows[0] });
    } catch (err) {
      console.error(`PATCH ${table} error:`, err.message);
      res.status(500).json({ ok: false, error: 'Internal server error' });
    }
  });

  router.delete('/:id', requirePermission(`delete${permPrefix}`), async (req, res) => {
    try {
      await logAction(table, req.params.id, 'DELETE', req.auth?.userId);
      await pool.query(`DELETE FROM ${table} WHERE ${primaryKey} = $1`, [req.params.id]);
      res.json({ ok: true });
    } catch (err) {
      console.error(`DELETE ${table} error:`, err.message);
      res.status(500).json({ ok: false, error: 'Internal server error' });
    }
  });

  router.post('/batch-delete', requirePermission(`delete${permPrefix}`), async (req, res) => {
    try {
      const { ids } = req.body;
      if (!Array.isArray(ids)) return res.status(400).json({ ok: false, error: 'ids[] required' });
      for (const id of ids) await logAction(table, id, 'DELETE', req.auth?.userId);
      await pool.query(`DELETE FROM ${table} WHERE ${primaryKey} = ANY($1)`, [ids]);
      res.json({ ok: true, deleted: ids.length });
    } catch (err) {
      console.error(`batch-delete ${table} error:`, err.message);
      res.status(500).json({ ok: false, error: 'Internal server error' });
    }
  });

  return router;
};

module.exports = buildCrudRouter;
