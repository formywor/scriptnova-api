const { BUILD, requireAdmin } = require('../_admin');

module.exports = async function handler(req, res) {
  const admin = await requireAdmin(req, res, 'other');
  if (!admin) return;

  return res.status(200).json({
    ok: true,
    role: admin.payload.role,
    exp: admin.payload.exp,
    session: admin.session,
    build: BUILD
  });
};