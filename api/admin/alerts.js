const { BUILD, requireAdmin, getAllSessions } = require('../_admin');

module.exports = async function handler(req, res) {
  const admin = await requireAdmin(req, res, 'other');
  if (!admin) return;

  const redis = admin.redis;
  const sessions = await getAllSessions(redis);
  const now = Math.floor(Date.now()/1000);
  const byLicense = {};
  const byHw = {};

  for (const s of sessions) {
    byLicense[s.license] = byLicense[s.license] || new Set();
    byLicense[s.license].add(s.hw);
    byHw[s.hw] = byHw[s.hw] || [];
    byHw[s.hw].push(s);
  }

  const alerts = [];

  for (const lic of Object.keys(byLicense)) {
    if (byLicense[lic].size >= 3) alerts.push({ type: 'many_devices_on_one_key', license: lic, count: byLicense[lic].size });
  }

  for (const hw of Object.keys(byHw)) {
    const items = byHw[hw];
    const recent = items.filter((s) => (now - (s.seen || 0)) < 120);
    if (recent.length >= 3) alerts.push({ type: 'repeated_launches_from_one_hwid', hw, count: recent.length });
    const churn = items.filter((s) => (s.exp - (s.createdAt || s.seen || now)) < 180);
    if (churn.length >= 2) alerts.push({ type: 'suspicious_rapid_session_churn', hw, count: churn.length });
  }

  const bannedTry = parseInt(await redis.get('sn:metric:banned_hwid_hits') || 0, 10) || 0;
  if (bannedTry) alerts.push({ type: 'banned_device_trying_again', count: bannedTry });

  const adminFails = parseInt(await redis.get('sn:metric:admin_login_fail') || 0, 10) || 0;
  if (adminFails) alerts.push({ type: 'admin_login_failures', count: adminFails });

  return res.status(200).json({ ok: true, alerts, build: BUILD });
};