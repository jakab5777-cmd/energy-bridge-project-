const express = require('express');
const router = express.Router();
const { requireAuth, requirePermission } = require('../src/middleware/auth');
const {
  createTicket, getTickets, getTicketByRef, updateTicket,
  updateTicketStatus, deleteTicket, assignUser, assignRole,
} = require('../controllers/tickets.controller');

router.use(requireAuth);

router.post('/',                          requirePermission('createTicket'), createTicket);
router.get('/',                           requirePermission('seeTicketing'), getTickets);
router.get('/:reference_id',              requirePermission('seeTicketing'), getTicketByRef);
router.put('/:reference_id',              requirePermission('editTicket'),   updateTicket);
router.patch('/:reference_id/status',     requirePermission('editTicket'),   updateTicketStatus);
router.delete('/:reference_id',           requirePermission('deleteTicket'), deleteTicket);
router.post('/:reference_id/assign-user', requirePermission('assignTicket'), assignUser);
router.post('/:reference_id/assign-role', requirePermission('assignTicket'), assignRole);

module.exports = router;
