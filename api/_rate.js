const { getRedis } = require("./_redis");

function getIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) return String(xf).split(",")[0].trim();
  return String(req.socket?.remoteAddress || "unknown").trim();
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

/**
 * Fixed-window rate limit:
 * - route: string label (e.g. "verify")
 * - limit: max hits per windowSec
 * - windowSec: window duration
 */
async function rateLimit(req, route, limit, windowSec) {
  let redis;
  try {
    redis = getRedis();
  } catch {
    // If Redis is missing, fail-open to avoid breaking prod.
    return { ok: true, remaining: limit, retryAfter: 0 };
  }

  const ip = getIp(req);
  const t = nowSec();
  const bucket = Math.floor(t / windowSec);
  const key = `sn:rl:${route}:${ip}:${bucket}`;

  const n = await redis.incr(key);
  if (n === 1) {
    await redis.expire(key, windowSec + 2);
  }

  if (n > limit) {
    const reset = (bucket + 1) * windowSec;
    const retryAfter = Math.max(1, reset - t);
    return { ok: false, remaining: 0, retryAfter };
  }

  return { ok: true, remaining: Math.max(0, limit - n), retryAfter: 0 };
}

module.exports = { rateLimit };