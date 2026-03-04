const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const PREFIX = "sn2"; // versioned key prefix to avoid old-format collisions

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
  const sigB64 = sig.toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return payloadB64 + "." + sigB64;
}

function getLicenseList() {
  return (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

// Robust body parsing for Vercel
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

function isSafeClientId(s) {
  if (!s) return false;
  if (s.length < 16 || s.length > 80) return false;
  return /^[A-Za-z0-9\-_.]+$/.test(s);
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

function parseSessionValue(raw) {
  const expNum = parseInt(raw, 10) || 0;
  if (expNum) return { exp: expNum, cid: "", seen: 0 };
  try {
    const obj = JSON.parse(String(raw));
    return {
      exp: parseInt(obj.exp, 10) || 0,
      cid: String(obj.cid || ""),
      seen: parseInt(obj.seen, 10) || 0
    };
  } catch {
    return { exp: 0, cid: "", seen: 0 };
  }
}

async function cleanupExpired(redis, key, nowSec) {
  const map = await redis.hgetall(key);
  if (!map) return;
  for (const [sid, raw] of Object.entries(map)) {
    const s = parseSessionValue(raw);
    if ((s.exp || 0) <= nowSec) await redis.hdel(key, sid);
  }
}

async function countActive(redis, key, nowSec) {
  const map = await redis.hgetall(key);
  if (!map) return 0;
  let c = 0;
  for (const raw of Object.values(map)) {
    const s = parseSessionValue(raw);
    if ((s.exp || 0) > nowSec) c++;
  }
  return c;
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  const rl = await rateLimit(req, "verify", 12, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({ ok: false, error: "rate_limited", retryAfter: rl.retryAfter });
  }

  const secret = String(process.env.SECRET_SALT || "");
  if (!secret || secret.length < 16) {
    return res.status(500).json({ ok: false, error: "server_misconfigured_secret" });
  }

  // GET for debugging, POST for HTA
  let lic = "";
  let clientId = "";

  if (req.method === "GET") {
    lic = String(req.query.license || "").trim();
    clientId = String(req.query.clientId || req.query.cid || "").trim();
  } else {
    const body = await getJsonBody(req);
    lic = String(body.license || "").trim();
    clientId = String(body.clientId || "").trim();
  }

  const list = getLicenseList();
  if (!lic || !list.includes(lic)) return res.status(200).json({ ok: false, plan: "none" });
  if (!isSafeClientId(clientId)) return res.status(400).json({ ok: false, error: "bad_client_id" });

  let redis;
  try { redis = getRedis(); }
  catch { return res.status(500).json({ ok: false, error: "redis_not_configured" }); }

  const plan = planForLicense(lic);
  const limit = limitForPlan(plan);
  const ttl = ttlForPlan(plan);

  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttl;

  const sessionKey = `${PREFIX}:sessions:${lic}`;

  await cleanupExpired(redis, sessionKey, now);

  const active = await countActive(redis, sessionKey, now);
  if (active >= limit) {
    return res.status(429).json({ ok: false, plan, error: "too_many_sessions", active, limit });
  }

  const sid = makeSessionId();
  const record = JSON.stringify({ exp: exp, cid: clientId, seen: now });

  // IMPORTANT: explicit (key, field, value)
  await redis.hset(sessionKey, sid, record);
  await redis.expire(sessionKey, ttl + 180);

  const token = signToken({ lic, plan, exp, sid, cid: clientId }, secret);

  return res.status(200).json({ ok: true, plan, token, exp, sessionId: sid, ttlSeconds: ttl });
};