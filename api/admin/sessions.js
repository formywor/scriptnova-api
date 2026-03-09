const { BUILD, requireAdmin, getJsonBody, getAllSessions, sessionKey, activeSetKey, logAudit, incrementCounter, dateKey } = require('../_admin');

module.exports = async function handler(req, res) {
  const admin = await requireAdmin(req, res, 'other');
  if (!admin) return;

  const body = req.method === 'POST' ? await getJsonBody(req) : req.query;
  const action = String(body.action || 'list').trim();
  const role = admin.payload.role;
  const redis = admin.redis;
  const now = Math.floor(Date.now()/1000);

  if (action === 'list') {
    const q = String(body.q || '').toLowerCase().trim();
    const sessions = (await getAllSessions(redis)).filter((s) => s.exp > now).filter((s) => {
      if (!q) return true;
      return [s.license, s.plan, s.cid, s.hw, s.sessionId, s.hwidRaw, s.ip].join(' ').toLowerCase().includes(q);
    });
    return res.status(200).json({ ok: true, sessions, build: BUILD });
  }

  if (role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden', build: BUILD });

  if (action === 'end_one') {
    const lic = String(body.license || '');
    const sid = String(body.sessionId || '');
    if (!lic || !sid) return res.status(400).json({ ok: false, error: 'missing_target', build: BUILD });
    await redis.del(sessionKey(lic, sid));
    await redis.srem(activeSetKey(lic), sid);
    await incrementCounter(redis, dateKey('sn:metric:end'));
    await logAudit(redis, { type: 'end_session', role, target: { lic, sid }, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === 'end_all') {
    const sessions = await getAllSessions(redis);
    for (const s of sessions) {
      await redis.del(sessionKey(s.license, s.sessionId));
      await redis.srem(activeSetKey(s.license), s.sessionId);
    }
    await incrementCounter(redis, dateKey('sn:metric:end'), sessions.length || 1);
    await logAudit(redis, { type: 'end_all_sessions', role, count: sessions.length, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, count: sessions.length, build: BUILD });
  }

  if (action === 'disconnect_hwid') {
    const hw = String(body.hw || '').trim();
    if (!hw) return res.status(400).json({ ok: false, error: 'missing_hw', build: BUILD });
    const sessions = await getAllSessions(redis);
    let count = 0;
    for (const s of sessions) {
      if (String(s.hw || '') === hw) {
        await redis.del(sessionKey(s.license, s.sessionId));
        await redis.srem(activeSetKey(s.license), s.sessionId);
        count++;
      }
    }
    await incrementCounter(redis, dateKey('sn:metric:end'), count || 1);
    await logAudit(redis, { type: 'disconnect_hwid', role, hw, count, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, count, build: BUILD });
  }

  return res.status(400).json({ ok: false, error: 'unknown_action', build: BUILD });
};