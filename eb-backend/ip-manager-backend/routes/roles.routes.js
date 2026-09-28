const express = require('express');
const router = express.Router();
const {
    createRole,
    getRoles,
    getRoleById,
    updateRole,
    deleteRole,
} = require('../controllers/roles.controller');

// TODO: plug in existing auth middleware, e.g. router.use(requireAuth);

router.post('/', createRole);
router.get('/', getRoles);
router.get('/:id', getRoleById);
router.put('/:id', updateRole);
router.delete('/:id', deleteRole);

module.exports = router;