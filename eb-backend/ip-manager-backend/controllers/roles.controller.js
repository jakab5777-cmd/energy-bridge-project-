const pool = require('../src/db');

async function createRole(req, res) {
    try {
        const { name, system } = req.body;
        if (!name || !name.trim()) {
            return res.status(400).json({ error: 'name is required' });
        }
        const result = await pool.query(
            `INSERT INTO user_roles (name, system) VALUES ($1, $2) RETURNING role_id, name, system, created_at`,
            [name.trim(), system || 'tech_dashboard']
        );
        return res.status(201).json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ error: 'A role with that name already exists' });
        }
        console.error('createRole error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

async function getRoles(req, res) {
    try {
        const result = await pool.query(
            `SELECT role_id, name, system, created_at FROM user_roles ORDER BY role_id ASC`
        );
        return res.json(result.rows);
    } catch (err) {
        console.error('getRoles error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

async function getRoleById(req, res) {
    try {
        const { id } = req.params;
        const result = await pool.query(
            `SELECT role_id, name, system, created_at FROM user_roles WHERE role_id = $1`,
            [id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Role not found' });
        }
        return res.json(result.rows[0]);
    } catch (err) {
        console.error('getRoleById error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

async function updateRole(req, res) {
    try {
        const { id } = req.params;
        const { name, system } = req.body;
        if (!name || !name.trim()) {
            return res.status(400).json({ error: 'name is required' });
        }
        const result = await pool.query(
            `UPDATE user_roles SET name = $1, system = COALESCE($2, system) WHERE role_id = $3
             RETURNING role_id, name, system, created_at`,
            [name.trim(), system || null, id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Role not found' });
        }
        return res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ error: 'A role with that name already exists' });
        }
        console.error('updateRole error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

async function deleteRole(req, res) {
    try {
        const { id } = req.params;
        const inUse = await pool.query(
            `SELECT 1 FROM registered_users WHERE role_id = $1 LIMIT 1`,
            [id]
        );
        if (inUse.rows.length > 0) {
            return res.status(409).json({ error: 'Cannot delete a role that is still assigned to users' });
        }
        const result = await pool.query(
            `DELETE FROM user_roles WHERE role_id = $1 RETURNING role_id`,
            [id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Role not found' });
        }
        return res.status(204).send();
    } catch (err) {
        console.error('deleteRole error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

module.exports = { createRole, getRoles, getRoleById, updateRole, deleteRole };
