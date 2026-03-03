const crypto = require("crypto");
const { getRedis } = require("./_redis");

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function b64urlEncodeUtf8(str) {
  return Buffer.from(String(str), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signToken(payloadObj, secret) {
  const payloadJson = JSON.stringify(payloadObj);
  const payloadB64 = b64urlEncodeUtf8(payloadJson);
  const sig = crypto.createHmac("sha256", secret).update(payloadB64).digest();
  const sigB64 = sig
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return payloadB64 + "." + sigB64;
}

function getLicenseList() {
  return (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function readLicense(req) {
  if (req.method === "GET") return String(req.query.license || "").trim();
  const b = req.body;
  if (!b) return "";
  if (typeof b === "string") {
    try { return String(JSON.parse(b).license || "").trim(); } catch { return ""; }
  }
  return String(b.license || "").trim();
}

function planForLicense(lic) {
  return lic.indexOf("PRO-") === 0 ? "pro" : "basic";
}
function limitForPlan(plan) {
  return plan === "pro" ? 4 : 2;
}
function ttlForPlan(plan) {
  return plan === "pro" ? (118 * 60 * 60) : (32 * 60);
}
function makeSessionId() {
  return crypto.randomBytes(18).toString("hex");
}

async function cleanupExpired(redis, key, nowSec) {
  const map = await redis.hgetall(key);
  if (!map) return;

  const entries = Object.entries(map);
  for (let i = 0; i < entries.length; i++) {
    const sid = entries[i][0];
    const exp = parseInt(entries[i][1], 10) || 0;
    if (exp <= nowSec) await redis.hdel(key, sid);
  }
}

async function countActive(redis, key, nowSec) {
  const map = await redis.hgetall(key);
  if (!map) return 0;

  const entries = Object.entries(map);
  let c = 0;
  for (let i = 0; i < entries.length; i++) {
    const exp = parseInt(entries[i][1], 10) || 0;
    if (exp > nowSec) c++;
  }
  return c;
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  const secret = String(process.env.SECRET_SALT || "");
  if (!secret || secret.length < 16) {
    return res.status(500).json({ ok: false, error: "server_misconfigured_secret" });
  }

  const lic = readLicense(req);
  const list = getLicenseList();
  if (!lic || !list.includes(lic)) {
    return res.status(200).json({ ok: false, plan: "none" });
  }

  let redis;
  try {
    redis = getRedis();
  } catch (e) {
    return res.status(500).json({ ok: false, error: "redis_not_configured" });
  }

  const plan = planForLicense(lic);
  const limit = limitForPlan(plan);
  const ttl = ttlForPlan(plan);

  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttl;

  const sessionKey = "sn:sessions:" + lic;

  await cleanupExpired(redis, sessionKey, now);

  const active = await countActive(redis, sessionKey, now);
  if (active >= limit) {
    return res.status(429).json({
      ok: false,
      plan,
      error: "too_many_sessions",
      active,
      limit
    });
  }

  const sid = makeSessionId();
  await redis.hset(sessionKey, { [sid]: String(exp) });
  await redis.expire(sessionKey, ttl + 120);

  const token = signToken({ lic: lic, plan: plan, exp: exp, sid: sid }, secret);

  return res.status(200).json({
    ok: true,
    plan,
    token,
    exp,
    sessionId: sid,
    ttlSeconds: ttl
  });
};