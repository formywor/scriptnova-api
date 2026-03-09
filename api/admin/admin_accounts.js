const { BUILD, requireAdmin, getJsonBody, adminSessionKey, adminDisabledKey, parseRedisJson, logAudit } = require('../_admin');

module.exports = async function handler(req, res) {
  const admin = await requireAdmin(req, res, 'owner');
  if (!admin) return;

  const body = req.method === 'POST' ? await getJsonBody(req) : req.query;
  const action = String(body.action || 'list').trim();
  const redis = admin.redis;
  const role = admin.payload.role;

  if (action === 'list') {
    const keys = await redis.keys('sn:admin:session:*');
    const sessions = [];
    for (const key of keys || []) {
      const obj = parseRedisJson(await redis.get(key));
      if (obj) sessions.push(obj);
    }
    const roles = ['owner', 'ulises', 'other'];
    const disabled = {};
    for (const r of roles) disabled[r] = !!(await redis.get(adminDisabledKey(r)));
    return res.status(200).json({ ok: true, roles, sessions, disabled, build: BUILD });
  }

  if (action === 'revoke') {
    const tid = String(body.tid || '').trim();
    await redis.del(adminSessionKey(tid));
    await logAudit(redis, { type: 'revoke_admin_session', role, target: { tid }, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === 'force_logout_all') {
    const keys = await redis.keys('sn:admin:session:*');
    for (const key of keys || []) await redis.del(key);
    await logAudit(redis, { type: 'force_logout_all_admins', role, count: (keys || []).length, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, count: (keys || []).length, build: BUILD });
  }

  if (action === 'disable_role') {
    const targetRole = String(body.role || '').trim();
    await redis.set(adminDisabledKey(targetRole), JSON.stringify({ by: role, at: Math.floor(Date.now()/1000) }));
    await logAudit(redis, { type: 'disable_admin_role', role, target: { targetRole }, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === 'enable_role') {
    const targetRole = String(body.role || '').trim();
    await redis.del(adminDisabledKey(targetRole));
    await logAudit(redis, { type: 'enable_admin_role', role, target: { targetRole }, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, build: BUILD });
  }

  return res.status(400).json({ ok: false, error: 'unknown_action', build: BUILD });
};