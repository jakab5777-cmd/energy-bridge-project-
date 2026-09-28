// routes/ticket-comments.routes.js
// Same shape as tickets.routes.js.
const express = require('express');
const router = express.Router();
const { requireAuth, requirePermission } = require('../src/middleware/auth');
const {
  getComments,
  createComment,
  updateComment,
  deleteComment,
} = require('../controllers/ticket-comments.controller');

// Everything below requires a valid token.
router.use(requireAuth);

// Reads use seeTicketing; writes reuse editTicket / deleteTicket. No new perms
// needed. (Swap to a dedicated 'commentTicket' perm here if you prefer.)
router.get('/',        requirePermission('seeTicketing'), getComments);   // ?ticket_id=T00010 optional
router.post('/',       requirePermission('editTicket'),   createComment);
router.put('/:id',     requirePermission('editTicket'),   updateComment);
router.delete('/:id',  requirePermission('deleteTicket'), deleteComment);

module.exports = router;

// In server.js, mount it next to the tickets router:
//   const ticketCommentsRouter = require('./routes/ticket-comments.routes');
//   app.use('/api/ip-manager/ticket-comments', ticketCommentsRouter);
