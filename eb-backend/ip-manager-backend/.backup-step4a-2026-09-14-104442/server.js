require('dotenv').config();
const express = require("express");
const db = require("./db");
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('../swagger.json');
const { requireAuth } = require('./middleware/auth');
const buildCrudRouter = require('./routes/crudFactory');
const platformRolesRoutes = require('../routes/roles.routes');
const platformUsersRoutes = require('../routes/users.routes');

const app = express();
app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
  next();
});
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.use('/api/ip-manager/real-ip-subnets', requireAuth, buildCrudRouter({
  table: 'real_ip_subnets',
  columns: ['real_ip_block', 'client_id', 'fake_ip', 'vlan_id', 'dsp_id', 'wan', 'is_real', 'is_managed', 'reserved_sections', 'reserved_client_id'],
  permPrefix: 'RealIpSubnet',
  seePerm: 'seeRealIP'
}));

app.use('/api/ip-manager/internal-ip-subnets', requireAuth, buildCrudRouter({
  table: 'internal_ip_subnets',
  columns: ['internal_ip_block', 'client_id', 'other_ips', 'is_real', 'is_managed', 'reserved_sections', 'reserved_client_id'],
  permPrefix: 'InternalIpSubnet',
  seePerm: 'seeFakeIP'
}));

app.use('/api/ip-manager/l2-domains', requireAuth, buildCrudRouter({
  table: 'l2_domains',
  columns: ['name','kind','client_id','description'],
  permPrefix: 'Vlan',
  seePerm: 'seeVlan'
}));

app.use('/api/ip-manager/devices', requireAuth, buildCrudRouter({
  table: 'devices',
  columns: ['hostname','role','site','client_id','stock_item_id','mgmt_ip','l2_domain','status','note'],
  permPrefix: 'Client',
  seePerm: 'seeDashboard'
}));

app.use('/api/ip-manager/vlans-v2', requireAuth, buildCrudRouter({
  table: 'vlans_v2',
  columns: ['id', 'status', 'type', 'service', 'zone', 'client_id', 'client_name', 'real_ip', 'fake_ip', 'local_ip', 'remote_ip', 'overlay_local_ip', 'overlay_remote_ip', 'dsp_id', 'l2_domain', 'bng_card', 'cdn', 'source', 'primary_path', 'backup_path', 'other_path', 'notes'],
  permPrefix: 'Vlan',
  seePerm: 'seeVlan',
  primaryKey: 'id'
}));

app.use('/api/ip-manager/wan-v2', requireAuth, buildCrudRouter({
  table: 'wan_solutions_v2',
  columns: ['client_id', 'head_office', 'branch_code', 'branch_name', 'vlan_id', 'dsp_id', 'upload_download', 'subnet_ho_to_branch'],
  permPrefix: 'Wan',
  seePerm: 'seeWan'
}));

app.use('/api/ip-manager/tunnels-v2', requireAuth, buildCrudRouter({
  table: 'ip_tunnels_v2',
  columns: ['client_id', 'local_ip', 'remote_ip', 'overlay_local_ip', 'overlay_remote_ip', 'interface', 'description', 'underlay_local_ip', 'underlay_remote_ip'],
  permPrefix: 'Tunnel',
  seePerm: 'seeTunnels'
}));

app.use('/api/ip-manager/vpns', requireAuth, buildCrudRouter({
  table: 'vpns',
  columns: ['client_id', 'vpn_type', 'vpn_ip', 'username', 'password', 'description'],
  permPrefix: 'Vpn',
  seePerm: 'seeVpn'
}));

app.use('/api/ip-manager/dsp-v2', requireAuth, buildCrudRouter({
  table: 'dsp_providers_v2',
  columns: ['dsp_name', 'code_name'],
  permPrefix: 'Dsp',
  seePerm: 'seeDsp'
}));

app.use('/api/ip-manager/credentials-v2', requireAuth, buildCrudRouter({
  table: 'credentials_v2',
  columns: ['subnet', 'gateway', 'vlan_id', 'net_desc', 'ip_address', 'node_type', 'device_desc', 'username', 'password', 'login_url', 'additional'],
  permPrefix: 'Credentials',
  seePerm: 'seeCredentials'
}));
app.use('/api/ip-manager/hardware-assets', requireAuth, buildCrudRouter({
  table: 'hardware_assets',
  columns: ['device_name', 'serial_number', 'model', 'firmware_version', 'status'],
  permPrefix: 'HardwareAsset',
  primaryKey: 'asset_id'
}));

app.use('/api/ip-manager/staff', requireAuth, buildCrudRouter({
  table: 'isp_staff',
  columns: ['user_id', 'department', 'position', 'access_level', 'username'],
  permPrefix: 'Staff',
  primaryKey: 'staff_id'
}));

app.get('/api/ip-manager/health', (req, res) => res.json({ ok: true, service: 'ip-manager-backend' }));

// ── Public routes (no auth required) ──
app.use('/api/ip-manager/auth', require('./routes/auth'));

// ── Everything below requires a valid JWT ──
app.use('/api/ip-manager/events', function (req, res, next) {
  if (req.headers.authorization === undefined && req.query.token)
    req.headers.authorization = 'Bearer ' + req.query.token;
  next();
});
app.use('/api/ip-manager', requireAuth);
app.use('/api/ip-manager', require('./sse-hook'));

app.use('/api/ip-manager/all', require('./routes/all'));
app.use('/api/ip-manager/real-ips', require('./routes/realIps'));
app.use('/api/ip-manager/internal-ips', require('./routes/internalIps'));
app.use('/api/ip-manager/vpn', require('./routes/vpn'));
app.use('/api/ip-manager/credentials', require('./routes/credentials'));
app.use('/api/ip-manager/vlans', require('./routes/vlans'));
app.use('/api/ip-manager/users', require('./routes/users'));
app.use('/api/ip-manager/events', require('./routes/events').router);
app.use('/api/ip-manager/archive', require('./routes/archive'));
app.use('/api/ip-manager/dsp', require('./routes/dsp'));
app.use('/api/ip-manager/dsp', require('./routes/dsp'));
app.use('/api/platform/roles', requireAuth, platformRolesRoutes);
app.use('/api/ip-manager/tickets', require('../routes/tickets.routes'));
app.use('/api/ip-manager/lte-devices', requireAuth, buildCrudRouter({ table: 'lte_devices', columns: ['client_id','device_vendor','device_model','device_serial','imei','carrier','iccid','phone_number','apn','status','install_location','installed_at','notes','stock_item_id'], permPrefix: 'LteDevice' }));
app.use('/api/platform/permissions', require('../routes/permissions.routes'));
app.use('/api/platform/users', requireAuth, platformUsersRoutes);

// WAN and Tunnels use the generic CRUD factory (simple add/edit/delete pattern)
app.use('/api/ip-manager/wan', buildCrudRouter({
  table: 'wan_solutions',
  columns: ['client_id', 'branch_code', 'branch_name', 'vlan_id', 'dsp', 'updown', 'vlan_subnet'],
  permPrefix: 'Wan',
  seePerm: 'seeWan'
}));
app.use('/api/ip-manager/clients', buildCrudRouter({
  table: 'clients',
  columns: ['id', 'client_name', 'address', 'service', 'dsp', 'client_type', 'parent_client_id', 'branches'],
  permPrefix: 'Client',
  seePerm: 'seeDashboard',
  primaryKey: 'id'
}));
app.use('/api/ip-manager/tunnels', buildCrudRouter({
  table: 'ip_tunnels',
  columns: ['client_id', 'client_name', 'tunnel_local_ip', 'tunnel_remote_ip', 'tunnel_interface', 'description'],
  permPrefix: 'Tunnel',
  seePerm: 'seeTunnels'
}));

app.get('/api/ip-manager/health', (req, res) => res.json({ ok: true, service: 'ip-manager-backend' }));

const PORT = process.env.PORT || 4000;

// --- INJECTED ROLE & USER PERMISSION ROUTES ---
app.get("/api/platform/roles/:role_id/permissions", async (req, res) => { try { const result = await db.query("SELECT p.* FROM permissions p JOIN role_permissions rp ON p.permission_id = rp.permission_id WHERE rp.role_id = $1", [req.params.role_id]); res.json({ ok: true, data: result.rows || [] }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.post("/api/platform/roles/:role_id/permissions", async (req, res) => { try { await db.query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", [req.params.role_id, req.body.permission_id]); res.json({ ok: true, message: "Added" }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.put("/api/platform/roles/:role_id/permissions", async (req, res) => { try { const { role_id } = req.params; const { permission_ids } = req.body; if (!Array.isArray(permission_ids)) return res.status(400).json({ok:false, error:"Array required"}); await db.query("BEGIN"); await db.query("DELETE FROM role_permissions WHERE role_id = $1", [role_id]); for (const pid of permission_ids) { await db.query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)", [role_id, pid]); } await db.query("COMMIT"); res.json({ ok: true, message: "Updated" }); } catch (err) { await db.query("ROLLBACK"); res.status(500).json({ ok: false, error: err.message }); } });
app.delete("/api/platform/roles/:role_id/permissions/:permission_id", async (req, res) => { try { await db.query("DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2", [req.params.role_id, req.params.permission_id]); res.json({ ok: true, message: "Removed" }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });

app.get("/api/platform/users/:user_id/permissions", async (req, res) => { try { const result = await db.query("SELECT p.* FROM permissions p JOIN user_permissions up ON p.permission_id = up.permission_id WHERE up.user_id = $1", [req.params.user_id]); res.json({ ok: true, data: result.rows || [] }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.post("/api/platform/users/:user_id/permissions", async (req, res) => { try { await db.query("INSERT INTO user_permissions (user_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", [req.params.user_id, req.body.permission_id]); res.json({ ok: true, message: "Added" }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.put("/api/platform/users/:user_id/permissions", async (req, res) => { try { const { user_id } = req.params; const { permission_ids } = req.body; if (!Array.isArray(permission_ids)) return res.status(400).json({ok:false, error:"Array required"}); await db.query("BEGIN"); await db.query("DELETE FROM user_permissions WHERE user_id = $1", [user_id]); for (const pid of permission_ids) { await db.query("INSERT INTO user_permissions (user_id, permission_id) VALUES ($1, $2)", [user_id, pid]); } await db.query("COMMIT"); res.json({ ok: true, message: "Updated" }); } catch (err) { await db.query("ROLLBACK"); res.status(500).json({ ok: false, error: err.message }); } });
app.delete("/api/platform/users/:user_id/permissions/:permission_id", async (req, res) => { try { await db.query("DELETE FROM user_permissions WHERE user_id = $1 AND permission_id = $2", [req.params.user_id, req.params.permission_id]); res.json({ ok: true, message: "Removed" }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });


// --- EnergyBridge: Ticket Comments + Inventory APIs ---
const ticketCommentsRouter = require('../routes/ticket-comments.routes');
app.use('/api/ip-manager/ticket-comments', ticketCommentsRouter);
const inventory = require('../routes/inventory.routes');
app.use('/api/ip-manager/brands',    inventory.brands);
app.use('/api/ip-manager/suppliers', inventory.suppliers);
app.use('/api/ip-manager/types',     inventory.types);
app.use('/api/ip-manager/stock',     inventory.stock);
// --- end EnergyBridge ---


// ---- Support Log -------------------------------------------------------
// The tech-support workspace. permPrefix reuses the seeded ticketing
// permissions rather than inventing a parallel set nobody has been granted.
// No FK on client_id: every client_id -> clients FK was dropped 2026-07-29
// because the app treats client codes as free text and auto-creates them.
app.use('/api/ip-manager/support-log', requireAuth, buildCrudRouter({
  table: 'support_log',
  columns: ['log_date','opened_at','closed_at','client_id','client_name',
            'dsp','problem','solution','agent','solved'],
  permPrefix: 'Ticket'
}));

// The private notepad is an upsert keyed on username, so the crud factory
// cannot serve it.
app.post('/api/ip-manager/support-notes', requireAuth, async (req, res) => {
  try {
    const { username, body } = req.body || {};
    if (!username) return res.status(400).json({ ok:false, error:'username required' });
    await db.query(
      `INSERT INTO support_notes (username, body, updated_at) VALUES ($1,$2,now())
       ON CONFLICT (username) DO UPDATE SET body = EXCLUDED.body, updated_at = now()`,
      [username, body || '']);
    res.json({ ok:true });
  } catch (err) {
    console.error('support-notes POST:', err);
    res.status(500).json({ ok:false, error:'Internal server error' });
  }
});

app.get('/api/ip-manager/support-notes', requireAuth, async (req, res) => {
  try {
    const r = await db.query('SELECT username, body, updated_at FROM support_notes');
    res.json({ ok:true, data: r.rows });
  } catch (err) {
    console.error('support-notes GET:', err);
    res.status(500).json({ ok:false, error:'Internal server error' });
  }
});


app.use('/api/ip-manager/support-tasks', requireAuth, buildCrudRouter({
  table: 'support_tasks',
  columns: ['username','text','due_date','done'],
  permPrefix: 'Ticket'
}));


app.use("/api/ip-manager/visit-reports", requireAuth, buildCrudRouter({
  table: "visit_reports",
  columns: ["visit_no","visit_date","client_id","company_name","contact_person",
            "phone","email","address","city_region","technician","employee_id",
            "arrived_at","departed_at","visit_type","work_done","equipment",
            "status","follow_up","tech_signed_name","client_signed_name"],
  permPrefix: "Ticket"
}));

app.listen(PORT, '127.0.0.1', () => {
  console.log(`IP Manager backend running on 127.0.0.1:${PORT}`);
});
