// controllers/inventory.controller.js
// One small CRUD factory drives Brand / Supplier / Types / Stock so every
// handler shares the tickets.controller conventions: pool from ../src/db,
// try/catch, { ok:true, data } / { ok:false, error }.
const pool = require('../src/db');

// Resolve the acting user from the token (never the body). See FOR_THE_DEV.md.
function actorFrom(req) {
  const u = req.auth || {};
  return u.username || u.name || u.email || (u.userId != null ? String(u.userId) : null);
}

/**
 * @param {string} table   SQL table name
 * @param {string[]} cols  columns the client may set (create + update)
 * @param {object} opts    { scopeCol?: 'system', authorCol?: 'created_by' }
 */
function makeCrud(table, cols, opts = {}) {
  const { scopeCol, authorCol } = opts;

  const list = async (req, res) => {
    try {
      // Optional ?system= (or whatever scopeCol is) filter.
      if (scopeCol && req.query[scopeCol]) {
        const { rows } = await pool.query(
          `SELECT * FROM ${table} WHERE ${scopeCol} = $1 ORDER BY id DESC`,
          [req.query[scopeCol]]
        );
        return res.json({ ok: true, data: rows });
      }
      const { rows } = await pool.query(`SELECT * FROM ${table} ORDER BY id DESC`);
      return res.json({ ok: true, data: rows });
    } catch (err) {
      console.error(`${table} list error:`, err);
      return res.status(500).json({ ok: false, error: 'Internal server error' });
    }
  };

  const getOne = async (req, res) => {
    try {
      const { rows } = await pool.query(`SELECT * FROM ${table} WHERE id = $1`, [req.params.id]);
      if (!rows.length) return res.status(404).json({ ok: false, error: 'Not found.' });
      return res.json({ ok: true, data: rows[0] });
    } catch (err) {
      console.error(`${table} getOne error:`, err);
      return res.status(500).json({ ok: false, error: 'Internal server error' });
    }
  };

  const create = async (req, res) => {
    try {
      const colNames = [];
      const values = [];
      cols.forEach((c) => {
        if (req.body[c] !== undefined) { colNames.push(c); values.push(req.body[c]); }
      });
      if (scopeCol) { colNames.push(scopeCol); values.push(req.body[scopeCol] || 'main'); }
      if (authorCol) { colNames.push(authorCol); values.push(actorFrom(req)); }
      if (!colNames.length) return res.status(422).json({ ok: false, error: 'No fields provided' });

      const placeholders = colNames.map((_, i) => `$${i + 1}`).join(', ');
      const { rows } = await pool.query(
        `INSERT INTO ${table} (${colNames.join(', ')}) VALUES (${placeholders}) RETURNING *`,
        values
      );
      return res.status(201).json({ ok: true, data: rows[0] });
    } catch (err) {
      console.error(`${table} create error:`, err);
      return res.status(500).json({ ok: false, error: 'Internal server error' });
    }
  };

  const update = async (req, res) => {
    try {
      const settable = scopeCol ? [...cols, scopeCol] : cols;
      const updates = settable.filter((c) => req.body[c] !== undefined);
      if (!updates.length) return res.status(422).json({ ok: false, error: 'No updatable fields provided' });
      const setClause = updates.map((c, i) => `${c} = $${i + 1}`).join(', ');
      const values = updates.map((c) => req.body[c]);
      const { rows } = await pool.query(
        `UPDATE ${table} SET ${setClause} WHERE id = $${updates.length + 1} RETURNING *`,
        [...values, req.params.id]
      );
      if (!rows.length) return res.status(404).json({ ok: false, error: 'Not found.' });
      return res.json({ ok: true, data: rows[0] });
    } catch (err) {
      console.error(`${table} update error:`, err);
      return res.status(500).json({ ok: false, error: 'Internal server error' });
    }
  };

  const remove = async (req, res) => {
    try {
      const { rows } = await pool.query(`DELETE FROM ${table} WHERE id = $1 RETURNING id`, [req.params.id]);
      if (!rows.length) return res.status(404).json({ ok: false, error: 'Not found.' });
      return res.json({ ok: true });
    } catch (err) {
      console.error(`${table} remove error:`, err);
      return res.status(500).json({ ok: false, error: 'Internal server error' });
    }
  };

  return { list, getOne, create, update, remove };
}

module.exports = {
  brand:    makeCrud('brands',    ['brand', 'status']),
  supplier: makeCrud('suppliers', ['supplier', 'mobile', 'email', 'status']),
  type:     makeCrud('types',     ['type']),
  stock:    makeCrud('stock',
    ['connections', 'link_name', 'type', 'brand', 'sn', 'supplier', 'price', 'antenna_size', 'purchase_date', 'status'],
    { scopeCol: 'system', authorCol: 'created_by' }),
};
