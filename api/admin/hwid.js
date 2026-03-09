const {
  BUILD, requireAdmin, getJsonBody, bannedHwidKey, suspiciousHwidKey,
  logAudit, parseRedisJson, getAllSessions, hwidSetKey
} = require('../_admin');

module.exports = async function handler(req, res) {
  const admin = await requireAdmin(req, res, 'ulises');
  if (!admin) return;

  const body = req.method === 'POST' ? await getJsonBody(req) : req.query;
  const action = String(body.action || 'search').trim();
  const role = admin.payload.role;
  const redis = admin.redis;

  if (action === 'search') {
    const q = String(body.q || '').trim().toLowerCase();
    if (!q) return res.status(400).json({ ok: false, error: 'missing_query', build: BUILD });

    const sessions = await getAllSessions(redis);
    const matched = sessions.filter((s) => [s.hw, s.license, s.hwidRaw, s.cid].join(' ').toLowerCase().includes(q));
    const byHwid = {};

    for (const s of matched) {
      byHwid[s.hw] = byHwid[s.hw] || { hw: s.hw, hwidRaw: s.hwidRaw, licenses: new Set(), sessions: [], lastSeen: 0, active: false };
      byHwid[s.hw].licenses.add(s.license);
      byHwid[s.hw].sessions.push(s);
      byHwid[s.hw].lastSeen = Math.max(byHwid[s.hw].lastSeen, s.seen || 0);
      byHwid[s.hw].active = byHwid[s.hw].active || (s.exp > Math.floor(Date.now()/1000));
    }

    const items = [];
    for (const hw of Object.keys(byHwid)) {
      const ban = parseRedisJson(await redis.get(bannedHwidKey(hw)));
      const suspicious = parseRedisJson(await redis.get(suspiciousHwidKey(hw)));
      items.push({
        hw,
        deviceFingerprintDetails: byHwid[hw].hwidRaw,
        licenses: Array.from(byHwid[hw].licenses),
        licenseCount: byHwid[hw].licenses.size,
        sessions: byHwid[hw].sessions,
        lastSeen: byHwid[hw].lastSeen,
        currentActiveStatus: byHwid[hw].active,
        ban,
        suspicious
      });
    }

    return res.status(200).json({ ok: true, items, build: BUILD });
  }

  if (role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden', build: BUILD });

  if (action === 'ban') {
    const hw = String(body.hw || '').trim();
    const reason = String(body.reason || '').trim();
    const record = { reason, by: role, at: Math.floor(Date.now()/1000) };
    await redis.set(bannedHwidKey(hw), JSON.stringify(record));
    await logAudit(redis, { type: 'ban_hwid', role, target: { hw }, reason, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, build: BUILD });
  }
  if (action === 'unban') {
    const hw = String(body.hw || '').trim();
    await redis.del(bannedHwidKey(hw));
    await logAudit(redis, { type: 'unban_hwid', role, target: { hw }, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, build: BUILD });
  }
  if (action === 'mark_suspicious') {
    const hw = String(body.hw || '').trim();
    const reason = String(body.reason || '').trim();
    await redis.set(suspiciousHwidKey(hw), JSON.stringify({ reason, by: role, at: Math.floor(Date.now()/1000) }));
    await logAudit(redis, { type: 'mark_suspicious_hwid', role, target: { hw }, reason, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, build: BUILD });
  }
  if (action === 'reset_key_bindings') {
    const license = String(body.license || '').trim();
    await redis.del(hwidSetKey(license));
    await logAudit(redis, { type: 'reset_hwid_bindings_for_key', role, target: { license }, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, build: BUILD });
  }

  return res.status(400).json({ ok: false, error: 'unknown_action', build: BUILD });
};