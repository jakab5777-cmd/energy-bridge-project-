const express = require('express');
const router = express.Router();
const clients = new Set();
router.get('/', (req, res) => {
  res.set({'Content-Type':'text/event-stream','Cache-Control':'no-cache, no-transform',Connection:'keep-alive','X-Accel-Buffering':'no'});
  if (res.flushHeaders) res.flushHeaders();
  res.write('retry: 5000\n');
  res.write('event: hello\ndata: {"ok":true}\n\n');
  const entry = { res: res };
  clients.add(entry);
  const beat = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) {} }, 25000);
  req.on('close', () => { clearInterval(beat); clients.delete(entry); });
});
router.get('/status', (req, res) => res.json({ ok: true, listeners: clients.size }));
function broadcast(resource, meta) {
  if (resource === undefined || clients.size === 0) return;
  const payload = JSON.stringify(Object.assign({ resource: resource, at: Date.now() }, meta || {}));
  const frame = 'event: changed\ndata: ' + payload + '\n\n';
  for (const c of clients) { try { c.res.write(frame); } catch (e) { clients.delete(c); } }
}
console.log('[events] live-update stream mounted');
module.exports = { router: router, broadcast: broadcast };
