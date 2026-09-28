const fs = require('fs');
const APP = '/home/abed/apps/isp-monitoring/ip-manager-backend';
const SERVER = APP + '/src/server.js';
const EVENTS = APP + '/src/routes/events.js';
function fail(m) { console.error('FAILED: ' + m); process.exit(1); }
if (fs.existsSync(EVENTS) === false) fail('src/routes/events.js is missing');
let mod;
try { mod = require(EVENTS); } catch (e) { fail('events.js does not load: ' + e.message); }
if ((typeof mod.router === 'function') === false) fail('events.js does not export a router');
let src = fs.readFileSync(SERVER, 'utf8');
const original = src;
if (src.indexOf("require('./routes/events')") >= 0) { console.log('Already mounted.'); process.exit(0); }
const SHIM = "app.use('/api/ip-manager/events', function (req, res, next) {\n"
  + "  if (req.headers.authorization === undefined && req.query.token)\n"
  + "    req.headers.authorization = 'Bearer ' + req.query.token;\n"
  + "  next();\n});\n";
const AUTH = "app.use('/api/ip-manager', requireAuth);";
if (src.indexOf(AUTH) < 0) fail('requireAuth line not found');
src = src.replace(AUTH, SHIM + AUTH);
const AFTER = "app.use('/api/ip-manager/users', require('./routes/users'));";
if (src.indexOf(AFTER) < 0) fail('users mount not found');
src = src.replace(AFTER, AFTER + "\napp.use('/api/ip-manager/events', require('./routes/events').router);");
fs.writeFileSync(SERVER, src, 'utf8');
try { require('child_process').execFileSync(process.execPath, ['--check', SERVER], { stdio: 'pipe' }); }
catch (e) { fs.writeFileSync(SERVER, original, 'utf8'); fail('edited server.js does not parse - reverted'); }
fs.writeFileSync(SERVER + '.before-sse', original, 'utf8');
console.log('Mounted. Backup: ' + SERVER + '.before-sse');
