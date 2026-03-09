const crypto = require('crypto');
const { getRedis } = require('./_redis');
const { rateLimit } = require('./_rate');
const {
  BUILD, getJsonBody, getLicenseMeta, incrementCounter, dateKey, trackError,
  hwidHash, isHwidBanned, globalPausedKey, sessionKey, activeSetKey, hwidSetKey,
  signToken
} = require('./_admin');

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}
function isSafeClientId(s) { return !!s && s.length >= 16 && s.length <= 80 && /^[A-Za-z0-9\-_.]+$/.test(s); }
function isSafeHwidRaw(s) { s = String(s || '').trim(); return !!s && s.length >= 8 && s.length <= 240 && !(/[\r\n\t\0]/.test(s)); }
function makeSessionId() { return crypto.randomBytes(18).toString('hex'); }

async function cleanupActive(redis, lic, now) {
  const setKey = activeSetKey(lic);
  const sids = await redis.smembers(setKey);
  if (!sids || !sids.length) return;
  for (const sid of sids) {
    const raw = await redis.get(sessionKey(lic, sid));
    if (!raw) { await redis.srem(setKey, sid); continue; }
    try {
      const obj = typeof raw === 'object' ? raw : JSON.parse(String(raw));
      if ((parseInt(obj.exp, 10) || 0) <= now) {
        await redis.del(sessionKey(lic, sid));
        await redis.srem(setKey, sid);
      }
    } catch {
      await redis.del(sessionKey(lic, sid));
      await redis.srem(setKey, sid);
    }
  }
}

async function enforceHwidBind(redis, lic, hwHash, maxDevices, plan) {
  const members = await redis.smembers(hwidSetKey(lic));
  const set = new Set((members || []).map(String));
  if (plan === 'free' && set.size > 1) return { ok: false, error: 'free_key_locked' };
  if (set.size === 0) { await redis.sadd(hwidSetKey(lic), hwHash); return { ok: true, boundNow: true, allowedCount: 1 }; }
  if (set.has(hwHash)) return { ok: true, boundNow: false, allowedCount: set.size };
  if (set.size >= maxDevices) return { ok: false, error: 'hwid_mismatch' };
  await redis.sadd(hwidSetKey(lic), hwHash);
  return { ok: true, boundNow: true, allowedCount: set.size + 1 };
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();

  const rl = await rateLimit(req, 'verify', 12, 60);
  if (!rl.ok) {
    res.setHeader('Retry-After', String(rl.retryAfter));
    return res.status(429).json({ ok: false, error: 'rate_limited', retryAfter: rl.retryAfter, build: BUILD });
  }

  const secret = String(process.env.SECRET_SALT || '');
  if (!secret || secret.length < 16) return res.status(500).json({ ok: false, error: 'server_misconfigured_secret', build: BUILD });

  let lic = '', clientId = '', hwidRaw = '';
  if (req.method === 'GET') {
    lic = String(req.query.license || '').trim();
    clientId = String(req.query.clientId || req.query.cid || '').trim();
    hwidRaw = String(req.query.hwid || '').trim();
  } else {
    const body = await getJsonBody(req);
    lic = String(body.license || '').trim();
    clientId = String(body.clientId || '').trim();
    hwidRaw = String(body.hwid || '').trim();
  }

  if (!isSafeClientId(clientId)) return res.status(400).json({ ok: false, error: 'bad_client_id', build: BUILD });
  if (!isSafeHwidRaw(hwidRaw)) return res.status(400).json({ ok: false, error: 'bad_hwid', build: BUILD });

  let redis;
  try { redis = getRedis(); }
  catch { return res.status(500).json({ ok: false, error: 'redis_not_configured', build: BUILD }); }

  await incrementCounter(redis, dateKey('sn:metric:verify'));

  const paused = await redis.get(globalPausedKey());
  if (paused) {
    await trackError(redis, 'launcher_paused');
    return res.status(403).json({ ok: false, error: 'launcher_paused', build: BUILD });
  }

  const meta = await getLicenseMeta(redis, lic);
  if (!meta.ok) {
    await trackError(redis, meta.error || 'not_found');
    return res.status(200).json({ ok: false, plan: 'none', error: meta.error, build: BUILD });
  }

  const hw = hwidHash(hwidRaw, secret);
  const banned = await isHwidBanned(redis, hw);
  if (banned) {
    await redis.incr('sn:metric:banned_hwid_hits');
    await trackError(redis, 'hwid_banned');
    return res.status(403).json({ ok: false, error: 'hwid_banned', reason: banned.reason || '', build: BUILD });
  }

  const bind = await enforceHwidBind(redis, lic, hw, meta.deviceLimit, meta.plan);
  if (!bind.ok) {
    await trackError(redis, bind.error);
    return res.status(403).json({ ok: false, error: bind.error, build: BUILD });
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = now + meta.ttlSeconds;

  await cleanupActive(redis, lic, now);

  const activeCount = await redis.scard(activeSetKey(lic));
  if ((activeCount || 0) >= meta.sessionLimit) {
    await trackError(redis, 'too_many_sessions');
    return res.status(429).json({
      ok: false,
      plan: meta.plan,
      error: 'too_many_sessions',
      active: activeCount || 0,
      limit: meta.sessionLimit,
      build: BUILD
    });
  }

  const sid = makeSessionId();
  const record = JSON.stringify({
    exp,
    cid: clientId,
    hw,
    seen: now,
    createdAt: now,
    ip: String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || ''),
    hwidRaw,
    userAgent: String(req.headers['user-agent'] || '')
  });

  await redis.set(sessionKey(lic, sid), record, { ex: meta.ttlSeconds + 180 });
  await redis.sadd(activeSetKey(lic), sid);
  await redis.expire(activeSetKey(lic), meta.ttlSeconds + 300);

  const token = signToken({ lic, plan: meta.plan, exp, sid, cid: clientId, hw }, secret);

  return res.status(200).json({
    ok: true,
    plan: meta.plan,
    token,
    exp,
    sessionId: sid,
    ttlSeconds: meta.ttlSeconds,
    hwBound: bind.boundNow === true,
    hwSlotsUsed: bind.allowedCount,
    maxDevices: meta.deviceLimit,
    limit: meta.sessionLimit,
    build: BUILD
  });
};