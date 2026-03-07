const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-download-2026-03-07a";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "https://scriptnovaa.com");
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

async function getJsonBody(req) {
  try {
    if (req.body) {
      if (typeof req.body === "string") return JSON.parse(req.body);
      if (Buffer.isBuffer(req.body)) return JSON.parse(req.body.toString("utf8"));
      if (typeof req.body === "object") return req.body;
    }
  } catch {}

  try {
    const raw = await new Promise((resolve) => {
      let data = "";
      req.on("data", (c) => (data += c));
      req.on("end", () => resolve(data));
      req.on("error", () => resolve(""));
    });
    if (!raw) return {};
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "method_not_allowed", build: BUILD });

  const rl = await rateLimit(req, "download", 120, 60);
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

  const body = await getJsonBody(req);
  const page = String(body.page || "download").slice(0, 32);
  const fileType = String(body.fileType || "unknown").slice(0, 16);

  const downloads = await redis.incr("sn:counter:downloads");
  await redis.incr("sn:downloads:type:" + fileType);
  await redis.incr("sn:downloads:page:" + page);

  const trusted = Number(await redis.get("sn:counter:trusted")) || 2400000;

  return res.status(200).json({
    ok: true,
    trusted,
    visitors: trusted,
    downloads: Number(downloads) || 0,
    page,
    fileType,
    build: BUILD
  });
};