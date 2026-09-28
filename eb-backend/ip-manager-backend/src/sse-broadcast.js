const fs = require('fs');
const APP = '/home/abed/apps/isp-monitoring/ip-manager-backend';
const SERVER = APP + '/src/server.js';
const HOOK = APP + '/src/sse-hook.js';
function fail(m) { console.error('FAILED: ' + m); process.exit(1); }
const HOOK_SRC = [
  "let broadcast = function () {};",
  "try { broadcast = require('./routes/events').broadcast || broadcast; } catch (e) {}",
  "function resourceOf(path) {",
  "  const m = String(path || '').match(/^\\/?([a-z0-9-]+)/i);",
  "  if (m === null) return '';",
  "  return m[1].toLowerCase().replace(/s$/, '');",
  "}",
  "module.exports = function sseHook(req, res, next) {",
  "  if (req.method === 'GET' || req.method === 'OPTIONS') return next();",
  "  res.on('finish', function () {",
  "    try {",
  "      if (res.statusCode >= 400) return;",
  "      const resource = resourceOf(req.path);",
  "      if (resource === '' || resource === 'auth' || resource === 'event') return;",
  "      broadcast(resource, {",
  "        action: req.method === 'DELETE' ? 'delete' : 'save',",
  "        by: (req.user && (req.user.username || req.user.name)) || null",
  "      });",
  "    } catch (e) {}",
  "  });",
  "  next();",
  "};",
  ""
].join('\n');
fs.writeFileSync(HOOK, HOOK_SRC, 'utf8');
let hook;
try { hook = require(HOOK); } catch (e) { fail('sse-hook.js does not load: ' + e.message); }
if ((typeof hook === 'function') === false) fail('sse-hook.js does not export a function');
if ((hook.length === 3) === false) fail('sse-hook.js is not a 3-argument middleware');
let src = fs.readFileSync(SERVER, 'utf8');
const original = src;
if (src.indexOf("require('./sse-hook')") >= 0) { console.log('Already wired.'); process.exit(0); }
const AUTH = "app.use('/api/ip-manager', requireAuth);";
if (src.indexOf(AUTH) < 0) fail('requireAuth line not found in server.js');
src = src.replace(AUTH, AUTH + "\napp.use('/api/ip-manager', require('./sse-hook'));");
fs.writeFileSync(SERVER, src, 'utf8');
try { require('child_process').execFileSync(process.execPath, ['--check', SERVER], { stdio: 'pipe' }); }
catch (e) { fs.writeFileSync(SERVER, original, 'utf8'); fail('edited server.js does not parse - reverted'); }
fs.writeFileSync(SERVER + '.before-broadcast', original, 'utf8');
console.log('Wired. Backup: ' + SERVER + '.before-broadcast');
