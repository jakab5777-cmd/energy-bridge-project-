const bcrypt = require('bcrypt');
const pool = require('../src/db');

const SALT_ROUNDS = 12;
const SAFE_FIELDS = `user_id, username, role_id, is_active, created_at, updated_at`;

async function createUser(req, res) {
    try {
        const { username, password, role_id } = req.body;
        if (!username || !username.trim()) {
            return res.status(400).json({ error: 'username is required' });
        }
        if (!password || password.length < 6) {
            return res.status(400).json({ error: 'password is required (min 6 characters)' });
        }
        if (!role_id) {
            return res.status(400).json({ error: 'role_id is required' });
        }

        const roleCheck = await pool.query(`SELECT 1 FROM user_roles WHERE role_id = $1`, [role_id]);
        if (roleCheck.rows.length === 0) {
            return res.status(400).json({ error: 'role_id does not exist' });
        }

        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        const result = await pool.query(
            `INSERT INTO registered_users (username, password_hash, role_id, is_active)
             VALUES ($1, $2, $3, TRUE)
             RETURNING ${SAFE_FIELDS}`,
            [username.trim(), passwordHash, role_id]
        );

        return res.status(201).json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ error: 'A user with that username already exists' });
        }
        console.error('createUser error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

async function getUsers(req, res) {
    try {
        const result = await pool.query(`SELECT ${SAFE_FIELDS} FROM registered_users ORDER BY user_id ASC`);
        return res.json(result.rows);
    } catch (err) {
        console.error('getUsers error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

async function getUserById(req, res) {
    try {
        const { id } = req.params;
        const result = await pool.query(`SELECT ${SAFE_FIELDS} FROM registered_users WHERE user_id = $1`, [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        return res.json(result.rows[0]);
    } catch (err) {
        console.error('getUserById error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

async function updateUser(req, res) {
    try {
        const { id } = req.params;
        const { username, role_id, is_active, password } = req.body;

        const existing = await pool.query(`SELECT user_id FROM registered_users WHERE user_id = $1`, [id]);
        if (existing.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (role_id) {
            const roleCheck = await pool.query(`SELECT 1 FROM user_roles WHERE role_id = $1`, [role_id]);
            if (roleCheck.rows.length === 0) {
                return res.status(400).json({ error: 'role_id does not exist' });
            }
        }

        const fields = [];
        const values = [];
        let i = 1;

        if (username) { fields.push(`username = $${i++}`); values.push(username.trim()); }
        if (role_id) { fields.push(`role_id = $${i++}`); values.push(role_id); }
        if (typeof is_active === 'boolean') { fields.push(`is_active = $${i++}`); values.push(is_active); }

        if (password) {
            if (password.length < 6) {
                return res.status(400).json({ error: 'password must be at least 6 characters' });
            }
            const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
            fields.push(`password_hash = $${i++}`); values.push(passwordHash);
            /* password_plain was dropped - never stored */
        }

        if (fields.length === 0) {
            return res.status(400).json({ error: 'No updatable fields provided' });
        }

        fields.push(`updated_at = NOW()`);
        values.push(id);

        const result = await pool.query(
            `UPDATE registered_users SET ${fields.join(', ')}
             WHERE user_id = $${i}
             RETURNING ${SAFE_FIELDS}`,
            values
        );

        return res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ error: 'A user with that username already exists' });
        }
        console.error('updateUser error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

async function deleteUser(req, res) {
    try {
        const { id } = req.params;
        const result = await pool.query(`DELETE FROM registered_users WHERE user_id = $1 RETURNING user_id`, [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        return res.status(204).send();
    } catch (err) {
        console.error('deleteUser error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

module.exports = { createUser, getUsers, getUserById, updateUser, deleteUser };