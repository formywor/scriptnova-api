const {
  BUILD, requireAdmin, getJsonBody, getLicenseMeta, customKeyKey, disabledKeyKey,
  logAudit, getCustomKey, hwidSetKey
} = require('../_admin');

module.exports = async function handler(req, res) {
  const admin = await requireAdmin(req, res, 'ulises');
  if (!admin) return;

  const body = req.method === 'POST' ? await getJsonBody(req) : req.query;
  const action = String(body.action || 'search').trim();
  const role = admin.payload.role;
  const redis = admin.redis;

  if (action === 'search') {
    const license = String(body.license || '').trim();
    if (!license) return res.status(400).json({ ok: false, error: 'missing_license', build: BUILD });
    const meta = await getLicenseMeta(redis, license);
    const custom = await getCustomKey(redis, license);
    const disabled = !!(await redis.get(disabledKeyKey(license)));
    const hwids = await redis.smembers(hwidSetKey(license));
    return res.status(200).json({ ok: true, license, meta, custom, disabled, hwids: hwids || [], build: BUILD });
  }

  if (role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden', build: BUILD });

  if (action === 'create_custom' || action === 'update') {
    const license = String(body.license || '').trim();
    if (!license) return res.status(400).json({ ok: false, error: 'missing_license', build: BUILD });
    const obj = {
      enabled: true,
      plan: String(body.plan || 'basic').trim(),
      ttlSeconds: parseInt(body.ttlSeconds, 10) || 3600,
      sessionLimit: parseInt(body.sessionLimit, 10) || 1,
      deviceLimit: parseInt(body.deviceLimit, 10) || 1,
      exp: parseInt(body.exp, 10) || 0,
      notes: String(body.notes || ''),
      createdAt: Math.floor(Date.now()/1000)
    };
    await redis.set(customKeyKey(license), JSON.stringify(obj));
    await logAudit(redis, { type: action, role, target: { license }, value: obj, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, license, record: obj, build: BUILD });
  }

  if (action === 'delete_custom') {
    const license = String(body.license || '').trim();
    await redis.del(customKeyKey(license));
    await logAudit(redis, { type: 'delete_custom_key', role, target: { license }, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === 'disable') {
    const license = String(body.license || '').trim();
    await redis.set(disabledKeyKey(license), JSON.stringify({ by: role, at: Math.floor(Date.now()/1000), reason: String(body.reason || '') }));
    await logAudit(redis, { type: 'disable_key', role, target: { license }, ip: admin.session.ip, success: true, reason: String(body.reason || '') });
    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === 'enable') {
    const license = String(body.license || '').trim();
    await redis.del(disabledKeyKey(license));
    await logAudit(redis, { type: 'enable_key', role, target: { license }, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, build: BUILD });
  }

  if (action === 'reset_bindings') {
    const license = String(body.license || '').trim();
    await redis.del(hwidSetKey(license));
    await logAudit(redis, { type: 'reset_key_bindings', role, target: { license }, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, build: BUILD });
  }

  return res.status(400).json({ ok: false, error: 'unknown_action', build: BUILD });
};