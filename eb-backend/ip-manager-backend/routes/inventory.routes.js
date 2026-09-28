// routes/inventory.routes.js
// One router per resource, same shape as tickets.routes.js. All behind auth;
// reads use seeInventory, writes use manage<Resource>.
const express = require('express');
const { requireAuth, requirePermission } = require('../src/middleware/auth');
const inv = require('../controllers/inventory.controller');

function resourceRouter(handlers, seePerm, managePerm) {
  const r = express.Router();
  r.use(requireAuth);
  r.get('/',       requirePermission(seePerm),    handlers.list);
  r.get('/:id',    requirePermission(seePerm),    handlers.getOne);
  r.post('/',      requirePermission(managePerm), handlers.create);
  r.put('/:id',    requirePermission(managePerm), handlers.update);
  r.delete('/:id', requirePermission(managePerm), handlers.remove);
  return r;
}

module.exports = {
  brands:    resourceRouter(inv.brand,    'seeInventory', 'manageBrand'),
  suppliers: resourceRouter(inv.supplier, 'seeInventory', 'manageSupplier'),
  types:     resourceRouter(inv.type,     'seeInventory', 'manageType'),
  stock:     resourceRouter(inv.stock,    'seeInventory', 'manageStock'),
};

// In server.js, mount the four next to the other routers:
//   const inventory = require('./routes/inventory.routes');
//   app.use('/api/ip-manager/brands',    inventory.brands);
//   app.use('/api/ip-manager/suppliers', inventory.suppliers);
//   app.use('/api/ip-manager/types',     inventory.types);
//   app.use('/api/ip-manager/stock',     inventory.stock);
