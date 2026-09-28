// src/scope.js — the client scope, ENFORCED (server step 4, 2026-09-14, SECURITY_AUDIT.md)
//
// Runs inside requireAuth, and only for a user whose scope_mode is 'assigned'
// (admins and 'all' users never reach it). Two halves:
//
// EGRESS — every JSON answer is reshaped before it leaves:
//   · records that belong to another client are DROPPED (clients, WAN,
//     tunnels, VPN, tickets, support cases, visit reports, LTE, …);
//   · rows of the RESOURCE REGISTERS — addresses, subnets, VLAN tags, devices,
//     L2 domains — are REDACTED instead: the row stays, marked "RESTRICTED",
//     with the client, names and notes removed. A scoped engineer must still
//     see that 5.100.240.6 or VLAN 1203 is TAKEN, or they would assign it a
//     second time;
//   · a single record of another client answers 404, not 403, so ids cannot
//     be probed.
//
// INGRESS — before any write:
//   · every client code the body names must be in scope;
//   · the record being changed or deleted must be in scope (404 otherwise);
//   · an address held by another client cannot be re-assigned or cleared;
//   · subnet management and the recycle bin are refused outright.
//
// "In scope" = the user's head offices plus those offices' branches, computed
// in middleware/auth.js loadAccess().
const pool = require('./db');

const API = '/api/ip-manager';
const KEYS = ['client_id', 'reserved_client_id', 'branch_code'];
const CLIENT_KEYS = ['id', 'parent_client_id'];
const REDACT_BASES = new Set(['real-ips', 'internal-ips', 'real-ip-subnets', 'internal-ip-subnets',
  'vlans', 'vlans-v2', 'devices', 'l2-domains']);
const KEEP_ON_REDACT = new Set(['id', 'row_id', 'subnet', 'real_ip', 'internal_ip', 'real_ip_block',
  'internal_ip_block', 'fake_ip', 'vlan_id', 'block_id', 'status', 'zone', 'l2_domain', 'mgmt_ip',
  'is_real', 'is_managed', 'kind', 'type', 'locked', 'created_at', 'updated_at', 'last_modified']);

/* Tables behind "/<base>/:id" and "/<base>/batch-delete", for the target check. */
const TABLES = {
  'real-ip-subnets': 'real_ip_subnets', 'internal-ip-subnets': 'internal_ip_subnets',
  'l2-domains': 'l2_domains', devices: 'devices', 'vlans-v2': 'vlans_v2', 'wan-v2': 'wan_solutions_v2',
  'tunnels-v2': 'ip_tunnels_v2', vpns: 'vpns', 'lte-devices': 'lte_devices', 'support-log': 'support_log',
  'visit-reports': 'visit_reports', wan: 'wan_solutions', tunnels: 'ip_tunnels', vlans: 'vlan_tracking',
  vpn: 'vpn_entries', clients: 'clients',
};

const up = (v) => String(v === null || v === undefined ? '' : v).trim().toUpperCase();
const isPlain = (o) => !!o && typeof o === 'object' && !Array.isArray(o);

/* 'in' — some client field names an in-scope client; 'out' — client fields are
   filled and none is in scope; 'none' — the row names no client at all. */
function verdict(row, scope, keys) {
  let seen = false;
  for (const k of keys) {
    if (!(k in row)) continue;
    const v = up(row[k]);
    if (!v) continue;
    seen = true;
    if (scope.has(v)) return 'in';
  }
  return seen ? 'out' : 'none';
}

function redact(row) {
  const out = { _restricted: true };
  for (const k of Object.keys(row)) if (KEEP_ON_REDACT.has(k)) out[k] = row[k];
  if ('client_id' in row) out.client_id = 'RESTRICTED';
  if ('client_name' in row) out.client_name = 'Another client';
  return out;
}

function shape(x, scope, keys, mode, depth = 0) {
  if (depth > 6) return x;
  if (Array.isArray(x)) {
    const out = [];
    for (const el of x) {
      if (!isPlain(el)) { out.push(el); continue; }
      if (verdict(el, scope, keys) === 'out') { if (mode === 'redact') out.push(redact(el)); continue; }
      out.push(shape(el, scope, keys, mode, depth + 1));
    }
    return out;
  }
  if (isPlain(x)) {
    const o = {};
    for (const k of Object.keys(x)) o[k] = shape(x[k], scope, keys, mode, depth + 1);
    return o;
  }
  return x;
}

function segments(req) {
  const path = String(req.originalUrl || req.url || '').split('?')[0];
  if (!path.startsWith(API + '/')) return null;
  return path.slice(API.length + 1).split('/').filter(Boolean).map((s) => {
    try { return decodeURIComponent(s); } catch (e) { return s; }
  });
}

function attachEgress(res, scope, base) {
  const keys = base === 'clients' ? CLIENT_KEYS : KEYS;
  const mode = REDACT_BASES.has(base) ? 'redact' : 'drop';
  const json = res.json.bind(res);
  res.json = (body) => {
    try {
      if (res.statusCode >= 400) return json(body);
      if (Array.isArray(body)) return json(shape(body, scope, keys, mode));
      if (!isPlain(body)) return json(body);
      const data = body.data;
      if (base === 'all' && isPlain(data)) {
        const d = { ...data };
        ['subnets', 'internalSubnets', 'vlans'].forEach((k) => { if (k in d) d[k] = shape(d[k], scope, KEYS, 'redact'); });
        ['wan', 'tunnels', 'vpn'].forEach((k) => { if (k in d) d[k] = shape(d[k], scope, KEYS, 'drop'); });
        return json({ ...body, data: d });
      }
      if (isPlain(data) && verdict(data, scope, keys) === 'out') {
        res.status(404);
        return json({ ok: false, error: 'Not found' });
      }
      return json(shape(body, scope, keys, mode));
    } catch (e) {
      console.error('[scope] egress failed:', e.message);
      res.status(500);
      return json({ ok: false, error: 'Internal server error' });
    }
  };
}

function refuse(res, code, error) {
  res.status(code).json({ ok: false, error });
  return true;
}

async function rows(sql, params) {
  return (await pool.query(sql, params)).rows;
}

/* Returns true when it has already answered (a refusal); false to continue. */
async function guard(req, res, scope) {
  const segs = segments(req);
  if (!segs) return false;
  const base = segs[0] || '';
  const sub = segs[1];
  const m = String(req.method || 'GET').toUpperCase();
  const b = isPlain(req.body) ? req.body : {};

  attachEgress(res, scope, base);

  if (base === 'archive') {
    /* A snapshot is taken before every delete and reveals nothing; the list of
       what was deleted, company-wide, is another matter. */
    if (m === 'POST' && !sub) return false;
    return refuse(res, 403, 'The recycle bin is not available to users with a client scope');
  }

  if (base === 'ticket-comments' && m === 'GET') {
    const tid = req.query && req.query.ticket_id;
    if (!tid) return refuse(res, 403, 'ticket_id is required');
    const t = await rows('SELECT client_id FROM tickets WHERE reference_id = $1', [String(tid)]);
    if (t.some((r) => verdict(r, scope, ['client_id']) === 'out')) return refuse(res, 404, 'Not found');
    return false;
  }

  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return false;

  /* 1. Every client code the body names. */
  const named = [];
  const collect = (o) => {
    if (!isPlain(o)) return;
    KEYS.forEach((k) => { if (o[k] !== undefined && o[k] !== null && o[k] !== '') named.push(o[k]); });
    if (o.prev_client_id) named.push(o.prev_client_id);
  };
  collect(b);
  if (Array.isArray(b.rows)) b.rows.forEach(collect);
  collect(b.changes);
  if (base === 'clients' && b.parent_client_id) named.push(b.parent_client_id);
  const outside = named.map(up).filter((v) => v && !scope.has(v));
  if (outside.length) return refuse(res, 403, `${outside[0]} is outside your client scope`);

  /* 2. Infrastructure that no scoped user manages. */
  if ((base === 'real-ips' || base === 'internal-ips') && (m === 'DELETE' || sub === 'subnets')) {
    return refuse(res, 403, 'Subnet management is not available to users with a client scope');
  }
  if ((base === 'real-ip-subnets' || base === 'internal-ip-subnets') && m === 'POST') {
    return refuse(res, 403, 'Subnet management is not available to users with a client scope');
  }
  if (base === 'clients' && m === 'POST' && !scope.has(up(b.parent_client_id))) {
    return refuse(res, 403, 'With a client scope you can add branches to your own head offices, not new head offices');
  }

  /* 3. Addresses already held by another client. */
  if (base === 'real-ips' && (sub === 'batch' || sub === 'clear')) {
    const ips = (sub === 'batch' ? (Array.isArray(b.rows) ? b.rows : []).map((r) => r && r.real_ip) : (b.real_ips || []))
      .filter(Boolean).map(String);
    if (ips.length) {
      const held = await rows('SELECT real_ip, client_id FROM real_ips WHERE real_ip = ANY($1::text[])', [ips]);
      const taken = held.find((r) => up(r.client_id) && !scope.has(up(r.client_id)));
      if (taken) return refuse(res, 403, `${taken.real_ip} belongs to another client`);
    }
    return false;
  }
  if (base === 'internal-ips' && sub === 'batch') {
    /* A row with no client CLEARS the address — for every client holding it
       unless prev_client_id narrows it. A scoped user must name whose. */
    for (const r of (Array.isArray(b.rows) ? b.rows : [])) {
      if (r && !r.client_id && !scope.has(up(r.prev_client_id))) {
        return refuse(res, 403, 'Clearing an internal address needs the client it belongs to (in your scope)');
      }
    }
    return false;
  }

  /* 4. The record being changed or deleted. */
  if (base === 'tickets' && sub) {
    const t = await rows('SELECT client_id FROM tickets WHERE reference_id = $1', [sub]);
    if (t.some((r) => verdict(r, scope, ['client_id']) === 'out')) return refuse(res, 404, 'Not found');
    return false;
  }
  if (base === 'ticket-comments') {
    const t = m === 'POST'
      ? await rows('SELECT client_id FROM tickets WHERE reference_id = $1', [String(b.ticket_id || '')])
      : (sub ? await rows(
          'SELECT t.client_id FROM ticket_comments c JOIN tickets t ON t.reference_id = c.ticket_id WHERE c.id::text = $1', [sub]) : []);
    if (t.some((r) => verdict(r, scope, ['client_id']) === 'out')) return refuse(res, 404, 'Not found');
    return false;
  }
  const table = TABLES[base];
  if (table) {
    let ids = [];
    if (sub === 'batch-delete' || sub === 'batch-edit') ids = Array.isArray(b.ids) ? b.ids : [];
    else if (sub && (m === 'PATCH' || m === 'PUT' || m === 'DELETE')) ids = [sub];
    if (ids.length) {
      const keys = base === 'clients' ? CLIENT_KEYS : KEYS;
      const found = await rows(`SELECT * FROM ${table} WHERE id::text = ANY($1::text[])`, [ids.map(String)]);
      if (found.some((r) => verdict(r, scope, keys) === 'out')) return refuse(res, 404, 'Not found');
    }
  }
  return false;
}

module.exports = { guard, shape, verdict, redact };
