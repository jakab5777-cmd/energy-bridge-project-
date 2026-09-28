/* ═══════════════════════════════════════════════════════════════════════════
   REMOVE THE PLAINTEXT PASSWORD COLUMN  —  install as src/password-plain-fix.js
   ═══════════════════════════════════════════════════════════════════════════
       node /home/abed/apps/isp-monitoring/ip-manager-backend/src/password-plain-fix.js
       node .../password-plain-fix.js --apply          NULLs the values
       node .../password-plain-fix.js --apply --drop   NULLs, then drops the column

   THE PROBLEM. A column holding passwords in clear text. Whoever reads that
   table has the passwords: a backup file, a `select *` in a support session, a
   screenshot of a query result, a leaked dump. The bcrypt hash beside it is
   doing nothing while the plaintext sits in the next column, and because
   people reuse passwords the damage is not limited to this system.

   Login does NOT use it — src/routes/auth.js compares against password_hash
   with bcrypt — so nulling it cannot lock anybody out.

   TWO STEPS, DELIBERATELY SEPARATE:

     --apply         sets every value to NULL. This removes the exposure NOW,
                     and is reversible in the sense that nothing breaks: no
                     code path needs the value to log anyone in.
     --apply --drop  removes the column as well. Only offered when NOTHING in
                     src/ mentions it — because if the backend still WRITES it,
                     dropping the column turns user creation into a 500, and if
                     it still READS it, some screen breaks. Either way I want
                     to see the code first, not find out from your users.

   Run it with no flags first. It changes nothing and tells you exactly what
   is there.

   IT FINDS THE COLUMN ITSELF. `registered_users.password_plain` is where it
   was reported, but the same mistake tends to appear more than once and under
   more than one name, so this sweeps every table in the schema for any column
   that looks like it stores a password in the clear.

   A file, not a `node -e`: `!` inside double quotes in an interactive bash is
   history expansion.
   ═══════════════════════════════════════════════════════════════════════════ */

const fs = require('fs');
const path = require('path');

const APP = '/home/abed/apps/isp-monitoring/ip-manager-backend';
const APPLY = process.argv.includes('--apply');
const DROP = process.argv.includes('--drop');

/* Names that mean "the password, readable". `password_hash`, `password_digest`
   and `password_encrypted` are deliberately NOT here — those are the ones
   doing their job. */
const SUSPECT = /^(password_plain|plain_password|password_text|password_clear|clear_password|plaintext_password|pwd_plain|user_password|password)$/i;
const SAFE = /^(password_hash|password_digest|password_encrypted|hashed_password|vpn_password_encrypted)$/i;

function fail(m) { console.error('FAILED: ' + m); process.exit(1); }
const ident = (s) => {
  if (/^[a-z_][a-z0-9_]*$/.test(String(s)) === false) throw new Error('bad identifier: ' + s);
  return '"' + s + '"';
};

(async () => {
  let pool;
  try { pool = require(path.join(APP, 'src/db')); }
  catch (e) { fail('could not load src/db: ' + e.message); }

  /* ── 1. Which columns store a readable password? ───────────────────────── */
  const { rows } = await pool.query(
    "SELECT table_name, column_name, data_type FROM information_schema.columns " +
    "WHERE table_schema = 'public' ORDER BY table_name, column_name");

  const hits = rows.filter(r => SUSPECT.test(r.column_name) && SAFE.test(r.column_name) === false);

  if (hits.length === 0) {
    console.log('Nothing found — no table in this schema has a plaintext password column.');
    console.log('(Checked ' + rows.length + ' columns. password_hash and friends are ignored on purpose.)');
    process.exit(0);
  }

  console.log('Found ' + hits.length + ' plaintext password column(s):\n');

  /* ── 2. How exposed is it, and does any code touch it? ─────────────────── */
  const report = [];
  for (const h of hits) {
    let filled = 0, total = 0;
    try {
      const q = await pool.query(
        'SELECT count(*) FILTER (WHERE ' + ident(h.column_name) + ' IS NOT NULL) AS filled, ' +
        'count(*) AS total FROM ' + ident(h.table_name));
      filled = Number(q.rows[0].filled);
      total = Number(q.rows[0].total);
    } catch (e) {
      console.log('  could not count ' + h.table_name + '.' + h.column_name + ': ' + e.message);
    }

    /* Every mention in the backend source. A write means dropping the column
       breaks a route; a read means some screen breaks. Either is worth seeing
       before, not after. */
    const refs = [];
    (function walk(dir, depth) {
      if (depth > 4) return;
      let entries = [];
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
      for (const e of entries) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) { if (e.name !== 'node_modules') walk(p, depth + 1); continue; }
        if (/\.(js|sql|ts)$/.test(e.name) === false) continue;
        if (p === __filename) continue;          /* this file names the column */
        let src = '';
        try { src = fs.readFileSync(p, 'utf8'); } catch (e2) { continue; }
        src.split('\n').forEach((line, i) => {
          if (line.includes(h.column_name)) refs.push(p + ':' + (i + 1) + '  ' + line.trim().slice(0, 100));
        });
      }
    })(path.join(APP, 'src'), 0);

    report.push({ h, filled, total, refs });

    console.log('  ' + h.table_name + '.' + h.column_name + '  (' + h.data_type + ')');
    console.log('    ' + filled + ' of ' + total + ' rows hold a readable password');
    console.log('    ' + refs.length + ' reference(s) in src/');
    refs.slice(0, 8).forEach(r => console.log('      ' + r));
    if (refs.length > 8) console.log('      ... and ' + (refs.length - 8) + ' more');
    console.log('');
  }

  if (APPLY !== true) {
    console.log('DRY RUN — nothing changed.');
    console.log('');
    console.log('  node src/password-plain-fix.js --apply          NULL every value (removes the exposure)');
    console.log('  node src/password-plain-fix.js --apply --drop   NULL, then drop the column entirely');
    console.log('');
    console.log('--drop is refused for any column that src/ still references. If one is');
    console.log('listed above with references, send me those lines and I will patch the');
    console.log('route first — dropping a column a route still writes turns it into a 500.');
    process.exit(0);
  }

  /* ── 3. NULL the values. Safe in every case: login uses password_hash. ─── */
  for (const r of report) {
    const t = ident(r.h.table_name), c = ident(r.h.column_name);
    const res = await pool.query('UPDATE ' + t + ' SET ' + c + ' = NULL WHERE ' + c + ' IS NOT NULL');
    console.log('cleared ' + res.rowCount + ' value(s) from ' + r.h.table_name + '.' + r.h.column_name);
  }

  if (DROP !== true) {
    console.log('');
    console.log('Values cleared. The columns still exist — re-run with --drop to remove them,');
    console.log('but note that anything still WRITING them will simply refill them on the next');
    console.log('password change. Check the reference list above.');
    process.exit(0);
  }

  /* ── 4. Drop, but only where nothing in the code names it. ─────────────── */
  let dropped = 0, refused = 0;
  for (const r of report) {
    if (r.refs.length > 0) {
      console.log('REFUSED to drop ' + r.h.table_name + '.' + r.h.column_name
        + ' — ' + r.refs.length + ' reference(s) in src/ (see the list above).');
      refused++;
      continue;
    }
    await pool.query('ALTER TABLE ' + ident(r.h.table_name)
      + ' DROP COLUMN IF EXISTS ' + ident(r.h.column_name));
    console.log('dropped ' + r.h.table_name + '.' + r.h.column_name);
    dropped++;
  }

  console.log('');
  console.log(dropped + ' dropped, ' + refused + ' refused.');
  if (refused > 0) {
    console.log('The refused ones are now EMPTY but still present. Send me their reference');
    console.log('lines and the route gets patched, then re-run with --drop.');
  }
  console.log('');
  console.log('Verify — this must return nothing:');
  console.log("  select table_name, column_name from information_schema.columns");
  console.log("   where table_schema='public' and column_name ~* 'plain|clear|_text'");
  console.log("     and column_name !~* 'hash|digest|encrypted';");
  process.exit(0);
})().catch(e => fail(e.message));
