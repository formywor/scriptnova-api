const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-visit-2026-03-07a";

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

function getIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) return String(xf).split(",")[0].trim();
  return String(req.socket?.remoteAddress || "unknown").trim();
}

function visitorHash(req) {
  const ip = getIp(req);
  const ua = String(req.headers["user-agent"] || "");
  return crypto.createHash("sha256").update(ip + "|" + ua).digest("hex");
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "method_not_allowed", build: BUILD });

  const rl = await rateLimit(req, "visit", 120, 60);
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
  const page = String(body.page || "index").slice(0, 32);

  const visitorKey = "sn:visitor:" + visitorHash(req);
  const trustedKey = "sn:counter:trusted";
  const pageViewsKey = "sn:pageviews:" + page;

  const alreadySeen = await redis.get(visitorKey);

  if (!alreadySeen) {
    await redis.set(visitorKey, "1", { ex: 60 * 60 * 24 * 365 });
    await redis.incr(trustedKey);
  }

  await redis.incr(pageViewsKey);

  const trusted = Number(await redis.get(trustedKey)) || 2400000;
  const downloads = Number(await redis.get("sn:counter:downloads")) || 482315;

  return res.status(200).json({
    ok: true,
    trusted,
    visitors: trusted,
    downloads,
    unique: !alreadySeen,
    page,
    build: BUILD
  });
};