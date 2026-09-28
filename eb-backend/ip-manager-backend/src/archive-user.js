const fs = require('fs');
const path = require('path');
const APP = '/home/abed/apps/isp-monitoring/ip-manager-backend';
const NEEDLE = 'const ARCHIVE = {';
function fail(m) { console.error('FAILED: ' + m); process.exit(1); }
const candidates = [];
(function walk(dir, depth) {
  if (depth > 3) return;
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name.charAt(0) === '.') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, depth + 1);
    else if (e.name.endsWith('.js')) {
      let txt = '';
      try { txt = fs.readFileSync(full, 'utf8'); } catch (err) { continue; }
      if (txt.indexOf(NEEDLE) >= 0) candidates.push(full);
    }
  }
})(path.join(APP, 'src'), 0);
if (candidates.length === 0) fail('no file under src/ contains the registry');
if (candidates.length > 1) fail('more than one file defines it: ' + candidates.join(', '));
const FILE = candidates[0];
let src = fs.readFileSync(FILE, 'utf8');
const original = src;
if (src.indexOf("table: 'users'") >= 0) { console.log('Already present.'); process.exit(0); }
src = src.replace(NEEDLE, NEEDLE + "\n  user: { table: 'users', idCol: 'id', label: function (r) { return r.username; } },");
fs.writeFileSync(FILE, src, 'utf8');
try { require('child_process').execFileSync(process.execPath, ['--check', FILE], { stdio: 'pipe' }); }
catch (e) { fs.writeFileSync(FILE, original, 'utf8'); fail('edited file does not parse - reverted'); }
fs.writeFileSync(FILE + '.before-user', original, 'utf8');
console.log('Added to ' + FILE);
