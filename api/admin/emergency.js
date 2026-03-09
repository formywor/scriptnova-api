const { BUILD, requireAdmin, getJsonBody, globalDisableAllKey, globalPausedKey, getAllSessions, sessionKey, activeSetKey, logAudit, setConfig } = require('../_admin');

module.exports = async function handler(req, res) {
  const admin = await requireAdmin(req, res, 'owner');
  if (!admin) return;

  const body = await getJsonBody(req);
  const action = String(body.action || '').trim();
  const redis = admin.redis;
  const role = admin.payload.role;

  if (action === 'disable_all_keys') {
    await redis.set(globalDisableAllKey(), JSON.stringify({ by: role, at: Math.floor(Date.now()/1000), reason: String(body.reason || '') }));
  } else if (action === 'enable_all_keys') {
    await redis.del(globalDisableAllKey());
  } else if (action === 'pause_all_launches') {
    await redis.set(globalPausedKey(), JSON.stringify({ by: role, at: Math.floor(Date.now()/1000), message: String(body.reason || '') }));
  } else if (action === 'clear_launch_nonces') {
    const keys = await redis.keys('sn:launchnonce:*');
    for (const key of keys || []) await redis.del(key);
  } else if (action === 'wipe_active_sessions' || action === 'end_all_sessions_now') {
    const sessions = await getAllSessions(redis);
    for (const s of sessions) {
      await redis.del(sessionKey(s.license, s.sessionId));
      await redis.srem(activeSetKey(s.license), s.sessionId);
    }
  } else if (action === 'enter_maintenance_mode') {
    await setConfig(redis, { maintenanceMessage: String(body.message || 'Maintenance mode enabled') });
  } else if (action === 'set_emergency_banner') {
    await setConfig(redis, { emergencyBanner: String(body.message || '') });
  } else {
    return res.status(400).json({ ok: false, error: 'unknown_action', build: BUILD });
  }

  await logAudit(redis, { type: 'emergency_' + action, role, ip: admin.session.ip, success: true, reason: String(body.reason || body.message || '') });
  return res.status(200).json({ ok: true, action, build: BUILD });
};