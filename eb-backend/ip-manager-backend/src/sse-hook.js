let broadcast = function () {};
try { broadcast = require('./routes/events').broadcast || broadcast; } catch (e) {}
function resourceOf(path) {
  const m = String(path || '').match(/^\/?([a-z0-9-]+)/i);
  if (m === null) return '';
  return m[1].toLowerCase().replace(/s$/, '');
}
module.exports = function sseHook(req, res, next) {
  if (req.method === 'GET' || req.method === 'OPTIONS') return next();
  res.on('finish', function () {
    try {
      if (res.statusCode >= 400) return;
      const resource = resourceOf(req.path);
      if (resource === '' || resource === 'auth' || resource === 'event') return;
      broadcast(resource, {
        action: req.method === 'DELETE' ? 'delete' : 'save',
        by: (req.user && (req.user.username || req.user.name)) || null
      });
    } catch (e) {}
  });
  next();
};
