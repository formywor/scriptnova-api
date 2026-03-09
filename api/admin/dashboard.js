const fs = require('fs');
const path = require('path');
const {
  BUILD, requireAdmin, getConfig, getAllSessions, globalPausedKey, globalDisableAllKey,
  dateKey
} = require('../_admin');

module.exports = async function handler(req, res) {
  const admin = await requireAdmin(req, res, 'other');
  if (!admin) return;

  const redis = admin.redis;
  const config = await getConfig(redis);
  const sessions = await getAllSessions(redis);
  const activeNow = Math.floor(Date.now()/1000);
  const liveSessions = sessions.filter((s) => s.exp > activeNow);
  const freeKeyKeys = await redis.keys('sn:freekey:*');
  const customKeys = await redis.keys('sn:customkey:*');
  const disabledKeys = await redis.keys('sn:disabled:*');
  const bannedHwids = await redis.keys('sn:banned:hwid:*');
  const paused = !!(await redis.get(globalPausedKey()));
  const disableAll = !!(await redis.get(globalDisableAllKey()));

  const versionPath = path.join(process.cwd(), '1234', 'version.txt');
  let launcherVersion = config.forceMinVersion;
  try { launcherVersion = String(fs.readFileSync(versionPath, 'utf8') || '').trim() || config.forceMinVersion; } catch {}

  const visits = parseInt(await redis.get('sn:counter:trusted') || 0, 10) || 0;
  const trusted = visits;
  const downloads = parseInt(await redis.get('sn:counter:downloads') || 0, 10) || 0;

  return res.status(200).json({
    ok: true,
    role: admin.payload.role,
    dashboard: {
      apiOnline: true,
      publicSiteOnline: true,
      redisOnline: true,
      launcherVersionStatus: launcherVersion,
      forceMinVersion: config.forceMinVersion,
      activeSessionsCount: liveSessions.length,
      freeKeysCount: freeKeyKeys.length,
      customKeysCount: customKeys.length,
      disabledKeysCount: disabledKeys.length,
      bannedHwidsCount: bannedHwids.length,
      pausedState: paused ? 'paused' : 'unpaused',
      disableAllKeys: disableAll,
      maintenanceMessage: config.maintenanceMessage || '',
      emergencyBanner: config.emergencyBanner || '',
      totals: { visitors: visits, trustedVisitors: trusted, downloads },
      daily: {
        keyChecksToday: parseInt(await redis.get(dateKey('sn:metric:check')) || 0, 10) || 0,
        verifyAttemptsToday: parseInt(await redis.get(dateKey('sn:metric:verify')) || 0, 10) || 0,
        launchAttemptsToday: parseInt(await redis.get(dateKey('sn:metric:launch')) || 0, 10) || 0,
        launchFailuresToday: parseInt(await redis.get(dateKey('sn:metric:launch_fail')) || 0, 10) || 0,
        freeKeysGeneratedToday: parseInt(await redis.get(dateKey('sn:metric:freekey')) || 0, 10) || 0,
        sessionsEndedToday: parseInt(await redis.get(dateKey('sn:metric:end')) || 0, 10) || 0,
        adminLoginFailuresToday: parseInt(await redis.get(dateKey('sn:metric:admin_login_fail')) || 0, 10) || 0
      }
    },
    build: BUILD
  });
};