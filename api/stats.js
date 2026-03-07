const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-stats-2026-03-07a";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "https://scriptnovaa.com");
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

async function getCount(redis, key, fallback = 0) {
  const raw = await redis.get(key);
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") return res.status(405).json({ ok: false, error: "method_not_allowed", build: BUILD });

  const rl = await rateLimit(req, "stats", 240, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({ ok: false, error: "rate_limited", retryAfter: rl.retryAfter, build: BUILD });
  }

  let redis;
  try {
    redis = getRedis();
  } catch {
    return res.status(500).json({ ok: false, error: "redis_not_configured", build: BUILD });
  }

  const trusted = await getCount(redis, "sn:counter:trusted", 2400000);
  const downloads = await getCount(redis, "sn:counter:downloads", 482315);

  return res.status(200).json({
    ok: true,
    trusted,
    visitors: trusted,
    downloads,
    build: BUILD
  });
};