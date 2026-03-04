const { getRedis } = require("./_redis");

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  const lic = String(req.query.license || "").trim();
  const sid = String(req.query.sid || "").trim();

  if (!lic || !sid) {
    return res.status(400).json({ ok: false, error: "missing_license_or_sid" });
  }

  let redis;
  try {
    redis = getRedis();
  } catch (e) {
    return res.status(500).json({ ok: false, error: "redis_not_configured" });
  }

  const sessionKey = "sn:sessions:" + lic;

  // Safe environment hints (NO secrets)
  const envHint = {
    has_KV_REST_API_URL: !!process.env.KV_REST_API_URL,
    has_KV_REST_API_TOKEN: !!process.env.KV_REST_API_TOKEN,
    has_UPSTASH_REDIS_REST_URL: !!process.env.UPSTASH_REDIS_REST_URL,
    has_UPSTASH_REDIS_REST_TOKEN: !!process.env.UPSTASH_REDIS_REST_TOKEN
  };

  const raw = await redis.hget(sessionKey, sid);
  const exists = !!raw;

  const fieldCount = await redis.hlen(sessionKey).catch(() => null);

  return res.status(200).json({
    ok: true,
    sessionKey,
    sid,
    exists,
    fieldCount,
    envHint
  });
};