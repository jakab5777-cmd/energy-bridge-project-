const express = require('express');
const router = express.Router();
const { getPermissions, getRolePermissions } = require('../controllers/permissions.controller');
const { requireAuth } = require('../src/middleware/auth');

router.use(requireAuth);
router.get('/', getPermissions);
router.get('/role/:role', getRolePermissions);

module.exports = router;
