const { BUILD, requireAdmin, adminSessionKey, logAudit } = require('../_admin');

module.exports = async function handler(req, res) {
  const admin = await requireAdmin(req, res, 'other');
  if (!admin) return;

  await admin.redis.del(adminSessionKey(admin.payload.tid));
  await logAudit(admin.redis, { type: 'admin_logout', role: admin.payload.role, ip: admin.session.ip, success: true });

  return res.status(200).json({ ok: true, build: BUILD });
};