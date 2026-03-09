const { BUILD, requireAdmin, getJsonBody, getConfig, setConfig, logAudit } = require('../_admin');

module.exports = async function handler(req, res) {
  const admin = await requireAdmin(req, res, 'ulises');
  if (!admin) return;

  const body = req.method === 'POST' ? await getJsonBody(req) : req.query;
  const action = String(body.action || 'get').trim();
  const role = admin.payload.role;
  const redis = admin.redis;

  if (action === 'get') {
    const config = await getConfig(redis);
    return res.status(200).json({ ok: true, config, build: BUILD });
  }

  if (role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden', build: BUILD });

  if (action === 'update') {
    const patch = body.patch && typeof body.patch === 'object' ? body.patch : {};
    const config = await setConfig(redis, patch);
    await logAudit(redis, { type: 'update_system_config', role, value: patch, ip: admin.session.ip, success: true });
    return res.status(200).json({ ok: true, config, build: BUILD });
  }

  return res.status(400).json({ ok: false, error: 'unknown_action', build: BUILD });
};