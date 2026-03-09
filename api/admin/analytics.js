const { BUILD, requireAdmin, dateKey } = require('../_admin');

module.exports = async function handler(req, res) {
  const admin = await requireAdmin(req, res, 'ulises');
  if (!admin) return;

  const redis = admin.redis;
  const errors = ['rate_limited','license_disabled','all_keys_disabled','launcher_paused','hwid_banned','bad_client_id','bad_hwid','too_many_sessions','session_not_found','session_corrupt','session_expired','bad_launch_sig','nonce_used'];
  const topErrorTypes = [];
  for (const err of errors) {
    topErrorTypes.push({ type: err, count: parseInt(await redis.get(dateKey('sn:metric:error:' + err)) || 0, 10) || 0 });
  }
  topErrorTypes.sort((a,b) => b.count - a.count);

  return res.status(200).json({
    ok: true,
    totals: {
      visitors: parseInt(await redis.get('sn:counter:trusted') || 0, 10) || 0,
      trustedVisitors: parseInt(await redis.get('sn:counter:trusted') || 0, 10) || 0,
      downloads: parseInt(await redis.get('sn:counter:downloads') || 0, 10) || 0
    },
    today: {
      keyChecks: parseInt(await redis.get(dateKey('sn:metric:check')) || 0, 10) || 0,
      verifyAttempts: parseInt(await redis.get(dateKey('sn:metric:verify')) || 0, 10) || 0,
      launchAttempts: parseInt(await redis.get(dateKey('sn:metric:launch')) || 0, 10) || 0,
      launchFailures: parseInt(await redis.get(dateKey('sn:metric:launch_fail')) || 0, 10) || 0,
      freeKeysGenerated: parseInt(await redis.get(dateKey('sn:metric:freekey')) || 0, 10) || 0,
      sessionsEnded: parseInt(await redis.get(dateKey('sn:metric:end')) || 0, 10) || 0,
      adminLoginFailures: parseInt(await redis.get(dateKey('sn:metric:admin_login_fail')) || 0, 10) || 0
    },
    topErrorTypes,
    build: BUILD
  });
};