const express = require('express');
const pool = require('../db');
const { requirePermission } = require('../middleware/auth');
const router = express.Router();

// GET /api/ip-manager/all
// Matches the exact shape the HTML frontend expects from the old Apps Script getAll() action:
// { subnets: {subnetName: [rows]}, internalSubnets: {subnetName: [rows]}, wan: [], tunnels: [],
//   vpn: [], vlans: [], vlanCdnList: [], dspList: [] }
router.get('/', requirePermission('seeDashboard'), async (req, res) => {
  try {
    const [realRes, internalRes, wanRes, tunnelsRes, vpnRes, vlansRes, cdnRes, dspRes] = await Promise.all([
      pool.query('SELECT * FROM real_ips ORDER BY subnet, real_ip'),
      pool.query('SELECT * FROM internal_ips ORDER BY subnet, internal_ip'),
      pool.query('SELECT * FROM wan_solutions_v2 ORDER BY id DESC'),
      pool.query('SELECT * FROM ip_tunnels_v2 ORDER BY id DESC'),
      pool.query('SELECT * FROM vpn_entries ORDER BY id DESC'),
      pool.query('SELECT * FROM vlan_tracking ORDER BY vlan_id'),
      pool.query("SELECT value FROM vlan_meta WHERE key = 'cdnList'"),
      pool.query('SELECT dsp_name FROM dsp_providers ORDER BY dsp_name'),
    ]);

    // Group real_ips and internal_ips by subnet, matching the old sheet-per-subnet shape
    const subnets = {};
    for (const row of realRes.rows) {
      if (!subnets[row.subnet]) subnets[row.subnet] = [];
      subnets[row.subnet].push(row);
    }

    const internalSubnets = {};
    for (const row of internalRes.rows) {
      if (!internalSubnets[row.subnet]) internalSubnets[row.subnet] = [];
      internalSubnets[row.subnet].push(row);
    }

    // VPN passwords are intentionally omitted here (use GET /vpn directly, which decrypts)
    const vpnSafe = vpnRes.rows.map(({ vpn_password_encrypted, ...rest }) => rest);

    res.json({
      ok: true,
      data: {
        subnets,
        internalSubnets,
        wan: wanRes.rows,
        tunnels: tunnelsRes.rows,
        vpn: vpnSafe,
        vlans: vlansRes.rows,
        vlanCdnList: cdnRes.rows[0]?.value || [],
        dspList: dspRes.rows.map(r => r.dsp_name),
      }
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

module.exports = router;
