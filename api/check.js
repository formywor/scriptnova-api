const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-hard-2026-03-05e";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function getLicenseList() {
  return (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function freeKeyRedisKey(freeKey) {
  return "sn:freekey:" + String(freeKey);
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") return res.status(405).json({ ok: false, error: "method_not_allowed", build: BUILD });

  const rl = await rateLimit(req, "check", 120, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({ ok: false, error: "rate_limited", retryAfter: rl.retryAfter, build: BUILD });
  }

  const lic = String(req.query.license || "").trim();
  if (!lic) return res.status(200).json({ ok: false, plan: "none", build: BUILD });

  // FREE keys: stored in Redis only
  if (lic.indexOf("FREE-") === 0) {
    let redis;
    try { redis = getRedis(); }
    catch { return res.status(500).json({ ok: false, error: "redis_not_configured", build: BUILD }); }

    const raw = await redis.get(freeKeyRedisKey(lic));
    if (!raw) return res.status(200).json({ ok: false, plan: "none", build: BUILD });

    return res.status(200).json({ ok: true, plan: "free", ttlSeconds: 900, build: BUILD });
  }

  // BASIC/PRO keys: env LICENSES list
  const list = getLicenseList();
  if (!list.includes(lic)) return res.status(200).json({ ok: false, plan: "none", build: BUILD });

  const plan = lic.indexOf("PRO-") === 0 ? "pro" : "basic";
  const ttlSeconds = plan === "pro" ? (118 * 60 * 60) : (32 * 60);
  return res.status(200).json({ ok: true, plan, ttlSeconds, build: BUILD });
};