const fs = require('fs');
const path = require('path');
const { BUILD, requireAdmin, getJsonBody, getConfig, setConfig, globalPausedKey, logAudit } = require('../_admin');

module.exports = async function handler(req, res) {
  const admin = await requireAdmin(req, res, 'ulises');
  if (!admin) return;

  const body = req.method === 'POST' ? await getJsonBody(req) : req.query;
  const action = String(body.action || 'status').trim();
  const role = admin.payload.role;
  const redis = admin.redis;

  if (action === 'status') {
    const config = await getConfig(redis);
    const paused = !!(await redis.get(globalPausedKey()));
    return res.status(200).json({ ok: true, paused, config, build: BUILD });
  }

  if (role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden', build: BUILD });

  if (action === 'pause') {
    await redis.set(globalPausedKey(), JSON.stringify({ paused: true, by: role, at: Math.floor(Date.now()/1000), message: String(body.message || '') }));
    await logAudit(redis, { type: 'pause_launcher', role, ip: admin.session.ip, success: true, reason: String(body.message || '') });
    return res.status(200).json({ ok: true, paused: true, build: BUILD });
  }
  if (action === 'unpause') {
    await redis.del(globalPausedKey());
    await logAudit(redis, { type: 'unpause_launcher', role, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, paused: false, build: BUILD });
  }
  if (action === 'set_min_version') {
    const value = String(body.value || '').trim();
    const config = await setConfig(redis, { forceMinVersion: value });
    try { fs.writeFileSync(path.join(process.cwd(), '1234', 'version.txt'), value); } catch {}
    await logAudit(redis, { type: 'set_min_version', role, ip: admin.session.ip, value, success: true });
    return res.status(200).json({ ok: true, forceMinVersion: config.forceMinVersion, build: BUILD });
  }
  if (action === 'set_maintenance') {
    const message = String(body.message || '');
    const config = await setConfig(redis, { maintenanceMessage: message });
    await logAudit(redis, { type: 'set_maintenance_message', role, ip: admin.session.ip, value: message, success: true });
    return res.status(200).json({ ok: true, maintenanceMessage: config.maintenanceMessage, build: BUILD });
  }

  return res.status(400).json({ ok: false, error: 'unknown_action', build: BUILD });
};