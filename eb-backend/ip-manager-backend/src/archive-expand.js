/* ═══════════════════════════════════════════════════════════════════════════
   ADD THE MISSING RESOURCES TO THE ARCHIVE REGISTRY
   ═══════════════════════════════════════════════════════════════════════════
       node /home/abed/apps/isp-monitoring/ip-manager-backend/src/archive-expand.js

   WHY. An audit of every delete path in the app found that only 10 resources
   were archived before deletion. Twelve more were permanent:

       user  role  credential  stock  brand  supplier  type
       ticket  ticket_comment  support_log  visit_report

   The frontend now calls the archive for all of them. Until this script runs,
   the server answers 400 "unknown resource: stock" and the frontend treats
   that as "this server cannot archive that" and deletes anyway — exactly as it
   behaved before. So the two halves can be deployed in either order; running
   this is what actually turns the copies on.

   IT GUESSES NOTHING IT CANNOT CHECK. Each candidate below names a table, an
   id column and a label column. Every one of them is verified against
   information_schema BEFORE it is written, and anything that does not match
   the real schema is SKIPPED and reported rather than installed. A wrong guess
   therefore costs a line of output, not a broken delete — which matters,
   because a registry entry pointing at a table that does not exist makes the
   snapshot throw and the delete refuse.

   IT IS A FILE, NOT A ONE-LINER, AND THAT IS THE POINT. `node -e "... !x ..."`
   inside double quotes in an interactive bash is HISTORY EXPANSION: the command
   is rewritten before node ever sees it, which once produced a baffling
   "ReferenceError: a is not defined". Run from a file, the shell never reads
   the contents, so the `!==` on line ~132 is safe. Keep it that way — do not
   turn this back into a `node -e`.

   IT VERIFIES BEFORE IT KEEPS ANYTHING: the edited file is re-parsed and put
   back if it does not parse, so pm2 can never see a broken file.
   ═══════════════════════════════════════════════════════════════════════════ */

const fs = require('fs');
const path = require('path');

const APP = '/home/abed/apps/isp-monitoring/ip-manager-backend';
const NEEDLE = 'const ARCHIVE = {';

function fail(m) { console.error('FAILED: ' + m); process.exit(1); }

/* ── The candidates ────────────────────────────────────────────────────────
   `label` is the column shown in the Recycle Bin. `id` is the column the
   frontend deletes BY — for tickets that is reference_id, not the serial id,
   because DELETE /tickets/:reference_id is the route. Getting that wrong means
   the snapshot finds no row and the delete is refused, so it is checked. */
const CANDIDATES = [
  { key: 'user',           table: 'ip_manager_users', id: 'id',           label: 'username' },
  { key: 'role',           table: 'roles',            id: 'role_id',      label: 'role_name' },
  { key: 'credential',     table: 'credentials',      id: 'id',           label: 'ip_address' },
  { key: 'stock',          table: 'stock',            id: 'id',           label: 'sn' },
  { key: 'brand',          table: 'brands',           id: 'id',           label: 'brand' },
  { key: 'supplier',       table: 'suppliers',        id: 'id',           label: 'supplier' },
  { key: 'type',           table: 'types',            id: 'id',           label: 'type' },
  { key: 'ticket',         table: 'tickets',          id: 'reference_id', label: 'reference_id' },
  { key: 'ticket_comment', table: 'ticket_comments',  id: 'id',           label: 'comment' },
  { key: 'support_log',    table: 'support_log',      id: 'id',           label: 'id' },
  { key: 'visit_report',   table: 'visit_reports',    id: 'id',           label: 'id' },
];

/* Fallbacks tried when the first choice is absent. Schemas drift; a table
   named support_logs instead of support_log should not silently mean "this
   record is never recoverable". */
const TABLE_ALIASES = {
  support_log:  ['support_log', 'support_logs', 'support_cases'],
  visit_report: ['visit_reports', 'visit_report'],
  role:         ['user_roles', 'roles', 'platform_roles'],
  credential:   ['credentials', 'credentials_v2'],
};
const LABEL_ALIASES = {
  role:        ['role_name', 'name', 'title'],
  credential:  ['ip_address', 'subnet', 'node_type'],
  stock:       ['sn', 'link_name', 'system'],
  support_log: ['title', 'subject', 'client_id', 'id'],
  visit_report:['client_id', 'visit_date', 'id'],
};
const ID_ALIASES = {
  role: ['role_id', 'id'],
};

(async () => {
  let pool;
  try { pool = require(path.join(APP, 'src/db')); }
  catch (e) { fail('could not load src/db: ' + e.message); }

  /* Everything the schema really has, in one query. */
  const { rows } = await pool.query(
    "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public'");
  const cols = new Map();
  for (const r of rows) {
    if (cols.has(r.table_name) === false) cols.set(r.table_name, new Set());
    cols.get(r.table_name).add(r.column_name);
  }

  const pick = (list, has) => {
    for (const c of list) { if (has(c)) return c; }
    return null;
  };

  const resolved = [], skipped = [];
  for (const c of CANDIDATES) {
    const table = pick(TABLE_ALIASES[c.key] || [c.table], t => cols.has(t));
    if (table === null) { skipped.push(c.key + ' (no table ' + c.table + ')'); continue; }
    const have = cols.get(table);

    const idCol = pick(ID_ALIASES[c.key] || [c.id, 'id'], x => have.has(x));
    if (idCol === null) { skipped.push(c.key + ' (' + table + ' has no ' + c.id + ')'); continue; }

    /* A label is cosmetic — the Recycle Bin shows it — so a missing one falls
       back to the id rather than skipping an otherwise good entry. */
    const labelCol = pick((LABEL_ALIASES[c.key] || [c.label]).concat([idCol]), x => have.has(x));

    resolved.push({ key: c.key, table, idCol, labelCol });
  }

  console.log('resolved against the live schema:');
  for (const r of resolved) console.log('  + ' + r.key.padEnd(15) + r.table + ' (' + r.idCol + ', label ' + r.labelCol + ')');
  for (const s of skipped)  console.log('  - skipped ' + s);
  if (resolved.length === 0) fail('nothing resolved; the schema does not match any candidate');

  /* ── Find the file that holds the registry ──────────────────────────────
     It may be routes/archive.js or server.js depending on how the archive was
     installed, so look for the file that actually contains it. */
  const found = [];
  (function walk(dir, depth) {
    if (depth > 3) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (e.name !== 'node_modules') walk(p, depth + 1); continue; }
      if (e.name.endsWith('.js') === false) continue;
      if (p === __filename) continue;                 /* this file quotes the needle */
      let src = '';
      try { src = fs.readFileSync(p, 'utf8'); } catch (e2) { continue; }
      if (src.includes('const NEEDLE')) continue;
      if (src.includes(NEEDLE)) found.push(p);
    }
  })(path.join(APP, 'src'), 0);

  if (found.length === 0) fail('no file defines ' + NEEDLE + ' — is the archive installed?');
  if (found.length > 1)  fail('more than one file defines it: ' + found.join(', '));

  const target = found[0];
  const before = fs.readFileSync(target, 'utf8');

  const additions = resolved
    .filter(r => before.includes('\n  ' + r.key + ':') === false
              && before.includes('\n  ' + r.key + ' ') === false)
    .map(r => '  ' + r.key + ': { table: ' + JSON.stringify(r.table)
            + ', idCol: ' + JSON.stringify(r.idCol)
            + ', label: r => String(r.' + r.labelCol + ' ?? r.' + r.idCol + ') },');

  if (additions.length === 0) {
    console.log('nothing to add — every resolved resource is already in the registry');
    process.exit(0);
  }

  const at = before.indexOf(NEEDLE);
  const after = before.slice(0, at + NEEDLE.length)
    + '\n  /* Added by archive-expand.js — these deletes used to be permanent. */\n'
    + additions.join('\n') + '\n'
    + before.slice(at + NEEDLE.length);

  /* Re-parse before keeping it. pm2 must never be handed a broken file. */
  const tmp = target + '.archive-expand.tmp';
  fs.writeFileSync(tmp, after, 'utf8');
  try {
    new (require('vm').Script)(after, { filename: target });
  } catch (e) {
    fs.unlinkSync(tmp);
    fail('the edited file does not parse, nothing was changed: ' + e.message);
  }

  fs.copyFileSync(target, target + '.bak-' + Date.now());
  fs.renameSync(tmp, target);

  console.log('');
  console.log('added ' + additions.length + ' resource(s) to ' + target);
  console.log('a .bak- copy of the original is beside it');
  console.log('');
  console.log('now:  pm2 restart ip-manager-backend');
  console.log('then: pm2 logs ip-manager-backend --lines 20 --nostream | grep -i archive');
  console.log('expect: [archive] registry checked: N resources, all tables present');
  process.exit(0);
})().catch(e => fail(e.message));
