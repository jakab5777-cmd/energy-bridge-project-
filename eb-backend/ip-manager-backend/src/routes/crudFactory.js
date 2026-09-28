// src/routes/crudFactory.js — replaced by server step 4a (2026-09-14, SECURITY_AUDIT.md)
//
// THE READ PERMISSION WAS NEVER CHECKED. Every mount in server.js passes
// `seePerm: 'seeCredentials'`, `'seeVpn'`, … and the old factory's signature
// was ({ table, columns, permPrefix, primaryKey }) — seePerm was silently
// dropped, and GET / had no guard at all. Any signed-in account could read
// credentials_v2 (usernames AND passwords of the network devices), vpns
// (with passwords) and every register, by asking the API directly.
//
// Now:
//  - GET / requires seePerm when the mount declares one. The client and DSP
//    directories stay readable to every signed-in user: every section's
//    pickers read them, and who sees WHICH clients is the scope's job (4b).
//  - Private tables (support_tasks) only ever show, edit and delete the
//    caller's own rows, and a new row is always the caller's — whatever the
//    body says.
//  - DELETE reports 404 when nothing was deleted, instead of "ok".
const pool = require('../db');
const { requirePermission } = require('../middleware/auth');

const READ_OPEN = new Set(['clients', 'dsp_providers_v2']);
const OWNER_COLUMN = { support_tasks: 'username' };

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

const pass = (req, res, next) => next();

const buildCrudRouter = ({ table, columns, permPrefix, primaryKey = 'id', seePerm }) => {
  const express = require('express');
  const router = express.Router();
  const owner = OWNER_COLUMN[table] || null;
  const viewGuard = seePerm && !READ_OPEN.has(table) ? requirePermission(seePerm) : pass;
  const me = (req) => (req.auth && req.auth.username) || '';

  router.get('/', viewGuard, async (req, res) => {
    try {
      const { rows } = owner
        ? await pool.query(`SELECT * FROM ${table} WHERE ${owner} = $1 ORDER BY ${primaryKey} DESC`, [me(req)])
        : await pool.query(`SELECT * FROM ${table} ORDER BY ${primaryKey} DESC`);
      res.json({ ok: true, data: rows });
    } catch (err) {
      console.error(`GET ${table} error:`, err.message);
      res.status(500).json({ ok: false, error: 'Internal server error' });
    }
  });

  router.post('/', requirePermission(`add${permPrefix}`), async (req, res) => {
    try {
      const body = { ...(req.body || {}) };
      if (owner) body[owner] = me(req);
      const cols = columns.join(', ');
      const placeholders = columns.map((_, i) => `$${i + 1}`).join(', ');
      const values = columns.map(c => body[c] ?? null);
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
      // Only columns present in the body; never the primary key, never the owner.
      const updatable = columns.filter(c => c !== primaryKey && c !== owner && req.body[c] !== undefined);
      if (updatable.length === 0) {
        return res.status(400).json({ ok: false, error: 'No updatable fields provided', received_keys: Object.keys(req.body || {}), table_columns: columns });
      }
      const setClause = updatable.map((c, i) => `${c} = $${i + 1}`).join(', ');
      const values = updatable.map(c => req.body[c]);
      let where = `${primaryKey} = $${updatable.length + 1}`;
      const params = [...values, req.params.id];
      if (owner) { where += ` AND ${owner} = $${params.length + 1}`; params.push(me(req)); }
      const { rows } = await pool.query(`UPDATE ${table} SET ${setClause} WHERE ${where} RETURNING *`, params);
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
      const params = [req.params.id];
      let where = `${primaryKey} = $1`;
      if (owner) { where += ` AND ${owner} = $2`; params.push(me(req)); }
      const { rows } = await pool.query(`DELETE FROM ${table} WHERE ${where} RETURNING *`, params);
      if (rows.length === 0) return res.status(404).json({ ok: false, error: 'Not found' });
      await logAction(table, req.params.id, 'DELETE', req.auth?.userId, rows[0], null);
      res.json({ ok: true });
    } catch (err) {
      console.error(`DELETE ${table} error:`, err.message);
      res.status(500).json({ ok: false, error: 'Internal server error' });
    }
  });

  router.post('/batch-delete', requirePermission(`delete${permPrefix}`), async (req, res) => {
    try {
      const { ids } = req.body || {};
      if (!Array.isArray(ids)) return res.status(400).json({ ok: false, error: 'ids[] required' });
      const params = [ids];
      let where = `${primaryKey} = ANY($1)`;
      if (owner) { where += ` AND ${owner} = $2`; params.push(me(req)); }
      const { rows } = await pool.query(`DELETE FROM ${table} WHERE ${where} RETURNING ${primaryKey}`, params);
      for (const r of rows) await logAction(table, r[primaryKey], 'DELETE', req.auth?.userId);
      res.json({ ok: true, deleted: rows.length });
    } catch (err) {
      console.error(`batch-delete ${table} error:`, err.message);
      res.status(500).json({ ok: false, error: 'Internal server error' });
    }
  });

  return router;
};

module.exports = buildCrudRouter;
