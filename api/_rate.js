const { getRedis } = require("./_redis");

function getIp(req) {
  const xf =
    req.headers["x-forwarded-for"] ||
    req.headers["x-real-ip"] ||
    req.headers["cf-connecting-ip"] ||
    "";

  if (xf) return String(xf).split(",")[0].trim();

  return String(
    (req.socket && req.socket.remoteAddress) ||
    (req.connection && req.connection.remoteAddress) ||
    req.ip ||
    "unknown"
  ).trim();
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function keyFor(bucket, req) {
  return "sn:rl:" + String(bucket || "default") + ":" + getIp(req);
}

async function rateLimit(req, bucket, limit, windowSec) {
  limit = parseInt(limit, 10);
  windowSec = parseInt(windowSec, 10);

  if (!Number.isFinite(limit) || limit <= 0) limit = 60;
  if (!Number.isFinite(windowSec) || windowSec <= 0) windowSec = 60;

  let redis;
  try {
    redis = getRedis();
  } catch {
    return {
      ok: true,
      remaining: limit - 1,
      retryAfter: 0,
      resetAt: nowSec() + windowSec,
      degraded: true
    };
  }

  const key = keyFor(bucket, req);

  try {
    const current = await redis.incr(key);

    if (current === 1) {
      await redis.expire(key, windowSec);
    }

    let ttl = 0;
    try {
      ttl = await redis.ttl(key);
      ttl = parseInt(ttl, 10);
      if (!Number.isFinite(ttl) || ttl < 0) ttl = windowSec;
    } catch {
      ttl = windowSec;
    }

    return {
      ok: current <= limit,
      remaining: Math.max(0, limit - current),
      retryAfter: current > limit ? ttl : 0,
      resetAt: nowSec() + ttl
    };
  } catch {
    return {
      ok: true,
      remaining: limit - 1,
      retryAfter: 0,
      resetAt: nowSec() + windowSec,
      degraded: true
    };
  }
}

module.exports = { rateLimit };