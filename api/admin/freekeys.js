const { BUILD, requireAdmin, getJsonBody, freeKeyRedisKey, parseRedisJson, logAudit } = require('../_admin');

function makeFreeKey() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = '';
  for (let i = 0; i < 6; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
  return 'FREE-' + out;
}

module.exports = async function handler(req, res) {
  const admin = await requireAdmin(req, res, 'ulises');
  if (!admin) return;

  const body = req.method === 'POST' ? await getJsonBody(req) : req.query;
  const action = String(body.action || 'list').trim();
  const role = admin.payload.role;
  const redis = admin.redis;

  if (action === 'list') {
    const keys = await redis.keys('sn:freekey:*');
    const items = [];
    for (const key of keys || []) {
      const raw = parseRedisJson(await redis.get(key)) || {};
      items.push({ key: String(key).split(':').slice(2).join(':'), exp: parseInt(raw.exp, 10) || 0, issuedAt: parseInt(raw.issuedAt, 10) || 0 });
    }
    items.sort((a,b) => b.exp - a.exp);
    return res.status(200).json({ ok: true, items, build: BUILD });
  }

  if (role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden', build: BUILD });

  if (action === 'add') {
    const key = String(body.key || makeFreeKey()).trim();
    const ttl = parseInt(body.ttlSeconds, 10) || 900;
    const now = Math.floor(Date.now()/1000);
    await redis.set(freeKeyRedisKey(key), JSON.stringify({ exp: now + ttl, issuedAt: now, manual: true }), { ex: ttl });
    await logAudit(redis, { type: 'add_free_key', role, target: { key }, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, key, ttlSeconds: ttl, build: BUILD });
  }

  if (action === 'remove') {
    const key = String(body.key || '').trim();
    await redis.del(freeKeyRedisKey(key));
    await logAudit(redis, { type: 'remove_free_key', role, target: { key }, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === 'expire_all') {
    const keys = await redis.keys('sn:freekey:*');
    for (const key of keys || []) await redis.del(key);
    await logAudit(redis, { type: 'expire_all_free_keys', role, count: (keys || []).length, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, count: (keys || []).length, build: BUILD });
  }

  return res.status(400).json({ ok: false, error: 'unknown_action', build: BUILD });
};