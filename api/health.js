const { getRedis } = require("./_redis");

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") {
    return res.status(405).json({ ok: false, error: "method_not_allowed" });
  }

  const out = {
    ok: true,
    service: "scriptnova-api",
    redis: false,
    secret: false,
    timestamp: new Date().toISOString()
  };

  try {
    const secret = String(process.env.SECRET_SALT || "");
    out.secret = secret.length >= 16;
  } catch {
    out.secret = false;
  }

  try {
    const redis = getRedis();
    await redis.set("sn:healthcheck", "1", { ex: 60 });
    const v = await redis.get("sn:healthcheck");
    out.redis = String(v) === "1";
  } catch {
    out.redis = false;
  }

  if (!out.secret || !out.redis) {
    return res.status(500).json({
      ok: false,
      error: "server_misconfigured",
      ...out
    });
  }

  return res.status(200).json(out);
};
