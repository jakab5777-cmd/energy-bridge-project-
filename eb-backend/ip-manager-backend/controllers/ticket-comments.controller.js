// controllers/ticket-comments.controller.js
// Same style as tickets.controller.js: pool from ../src/db, try/catch on every
// handler, { ok:true, data } / { ok:false, error } envelope.
//
// ── SECURITY (2026-09-14 audit) ──────────────────────────────────────────────
// Two broken-access-control bugs are fixed in this file:
//
//   1. OBJECT-LEVEL AUTHORISATION. PUT / DELETE ran `WHERE id = $1` with no
//      check on who wrote the comment, so anyone holding editTicket could
//      rewrite — and anyone holding deleteTicket could erase — ANY user's
//      comment on ANY ticket, including someone else's account of what they
//      did. A route-level permission answers "may this user touch comments at
//      all"; it never answered "is this THEIR comment". Now: the author may
//      edit or delete their own comment; anyone else needs moderateComments
//      (or the admin role). The WHERE clause carries the author, so the check
//      and the write cannot be separated by a race.
//
//   2. UNSCOPED READ. GET / with no ?ticket_id returned every comment in the
//      system to anyone with seeTicketing — a bulk export of every internal
//      conversation. A ticket id is now required unless the caller may
//      moderate.
//
// The comment body is stored as-is and must be rendered as TEXT by the client
// (React escapes by default; never dangerouslySetInnerHTML a comment).
const pool = require('../src/db');

// Resolve the comment author from the authenticated token — NEVER from the body.
// requireAuth attaches the decoded token to req.auth (payload: { userId,
// username, role, perms }).
function authorFrom(req) {
  const u = req.auth || {};
  return u.username || u.name || u.email || (u.userId != null ? String(u.userId) : null);
}

// Moderators may act on other people's comments. The admin ROLE always may;
// otherwise it is an explicit permission, never a default.
function canModerate(req) {
  const u = req.auth || {};
  if (String(u.role || '').toLowerCase() === 'admin') return true;
  const perms = u.perms || {};
  return perms.moderateComments === true;
}

// Bounded, because an unbounded body is a storage and rendering DoS.
const MAX_COMMENT = 5000;

// GET /  — one ticket's log via ?ticket_id=T00010 (required unless moderator)
async function getComments(req, res) {
  try {
    const { ticket_id } = req.query;
    if (!ticket_id) {
      if (!canModerate(req)) {
        return res.status(400).json({ ok: false, error: 'ticket_id is required' });
      }
      const { rows } = await pool.query(
        `SELECT * FROM ticket_comments ORDER BY created_at DESC LIMIT 500`
      );
      return res.json({ ok: true, data: rows });
    }
    const { rows } = await pool.query(
      `SELECT * FROM ticket_comments WHERE ticket_id = $1 ORDER BY created_at ASC`,
      [ticket_id]
    );
    return res.json({ ok: true, data: rows });
  } catch (err) {
    console.error('getComments error:', err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
}

// POST /  — { ticket_id, comment }. author + created_at are server-set.
async function createComment(req, res) {
  try {
    const { ticket_id, comment } = req.body;
    const missing = ['ticket_id', 'comment'].filter(f => !req.body[f] || String(req.body[f]).trim() === '');
    if (missing.length) {
      return res.status(422).json({ ok: false, error: 'Validation failed', fields: { required: missing } });
    }
    if (String(comment).length > MAX_COMMENT) {
      return res.status(422).json({ ok: false, error: `Comment is longer than ${MAX_COMMENT} characters.` });
    }
    const author = authorFrom(req);
    if (!author) return res.status(401).json({ ok: false, error: 'No authenticated author.' });

    // ticket_id must reference an existing ticket (tickets PK is reference_id).
    const t = await pool.query(`SELECT 1 FROM tickets WHERE reference_id = $1 LIMIT 1`, [ticket_id]);
    if (!t.rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found.' });

    const { rows } = await pool.query(
      `INSERT INTO ticket_comments (ticket_id, author, comment)
       VALUES ($1, $2, $3) RETURNING *`,
      [ticket_id, author, comment]
    );
    return res.status(201).json({ ok: true, data: rows[0] });
  } catch (err) {
    console.error('createComment error:', err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
}

// PUT /:id  — only `comment` is editable; ticket_id/author/created_at are fixed.
// Only the author may edit, unless the caller may moderate.
async function updateComment(req, res) {
  try {
    const { comment } = req.body;
    if (!comment || String(comment).trim() === '') {
      return res.status(422).json({ ok: false, error: 'Validation failed', fields: { required: ['comment'] } });
    }
    if (String(comment).length > MAX_COMMENT) {
      return res.status(422).json({ ok: false, error: `Comment is longer than ${MAX_COMMENT} characters.` });
    }
    const { rows } = canModerate(req)
      ? await pool.query(
          `UPDATE ticket_comments SET comment = $1 WHERE id = $2 RETURNING *`,
          [comment, req.params.id])
      : await pool.query(
          `UPDATE ticket_comments SET comment = $1 WHERE id = $2 AND author = $3 RETURNING *`,
          [comment, req.params.id, authorFrom(req)]);
    if (!rows.length) {
      /* Same answer for "does not exist" and "not yours": telling them apart
         would let a caller probe which comment ids exist. */
      return res.status(404).json({ ok: false, error: 'Comment not found, or not yours to edit.' });
    }
    return res.json({ ok: true, data: rows[0] });
  } catch (err) {
    console.error('updateComment error:', err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
}

// DELETE /:id — only the author, unless the caller may moderate.
async function deleteComment(req, res) {
  try {
    const { rows } = canModerate(req)
      ? await pool.query(
          `DELETE FROM ticket_comments WHERE id = $1 RETURNING id`,
          [req.params.id])
      : await pool.query(
          `DELETE FROM ticket_comments WHERE id = $1 AND author = $2 RETURNING id`,
          [req.params.id, authorFrom(req)]);
    if (!rows.length) {
      return res.status(404).json({ ok: false, error: 'Comment not found, or not yours to delete.' });
    }
    return res.json({ ok: true });
  } catch (err) {
    console.error('deleteComment error:', err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
}

module.exports = { getComments, createComment, updateComment, deleteComment };
