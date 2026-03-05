const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-hard-2026-03-05d";

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

// HTA sends raw hwid string; server hashes it.
function isSafeHwidRaw(s) {
  s = String(s || "").trim();
  if (!s) return false;
  if (s.length < 8 || s.length > 240) return false;
  if (/[\r\n\t\0]/.test(s)) return false;
  return true;
}

function hwidHash(raw, secret) {
  return crypto.createHash("sha256").update(String(secret) + "|" + String(raw)).digest("hex");
}

function planForLicense(lic) { return lic.indexOf("PRO-") === 0 ? "pro" : "basic"; }
function limitForPlan(plan) { return plan === "pro" ? 4 : 2; }
function ttlForPlan(plan) { return plan === "pro" ? (118 * 60 * 60) : (32 * 60); }

function makeSessionId() { return crypto.randomBytes(18).toString("hex"); }
function sessionKey(lic, sid) { return "sn:session:" + lic + ":" + sid; }
function activeSetKey(lic) { return "sn:active:" + lic; }
function hwidSetKey(lic) { return "sn:hwids:" + lic; }

async function cleanupActive(redis, lic, now) {
  const setKey = activeSetKey(lic);
  const sids = await redis.smembers(setKey);
  if (!sids || !sids.length) return;

  for (const sid of sids) {
    const sk = sessionKey(lic, sid);
    const raw = await redis.get(sk);
    if (!raw) {
      await redis.srem(setKey, sid);
      continue;
    }
    try {
      const obj = JSON.parse(String(raw));
      const exp = parseInt(obj.exp, 10) || 0;
      if (exp <= now) {
        await redis.del(sk);
        await redis.srem(setKey, sid);
      }
    } catch {
      await redis.del(sk);
      await redis.srem(setKey, sid);
    }
  }
}

// HWID binding: allow up to 2 devices per license.
async function enforceHwidBind(redis, lic, hwHash) {
  const key = hwidSetKey(lic);
  const members = await redis.smembers(key);
  const set = new Set((members || []).map(String));

  if (set.size === 0) {
    await redis.sadd(key, hwHash);
    return { ok: true, boundNow: true, allowedCount: 1 };
  }

  if (set.has(hwHash)) {
    return { ok: true, boundNow: false, allowedCount: set.size };
  }

  if (set.size >= 2) {
    return { ok: false, error: "hwid_mismatch" };
  }

  await redis.sadd(key, hwHash);
  return { ok: true, boundNow: true, allowedCount: set.size + 1 };
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  const rl = await rateLimit(req, "verify", 12, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({ ok: false, error: "rate_limited", retryAfter: rl.retryAfter, build: BUILD });
  }

  const secret = String(process.env.SECRET_SALT || "");
  if (!secret || secret.length < 16) {
    return res.status(500).json({ ok: false, error: "server_misconfigured_secret", build: BUILD });
  }

  let lic = "";
  let clientId = "";
  let hwidRaw = "";

  if (req.method === "GET") {
    lic = String(req.query.license || "").trim();
    clientId = String(req.query.clientId || req.query.cid || "").trim();
    hwidRaw = String(req.query.hwid || "").trim();
  } else {
    const body = await getJsonBody(req);
    lic = String(body.license || "").trim();
    clientId = String(body.clientId || "").trim();
    hwidRaw = String(body.hwid || "").trim();
  }

  const list = getLicenseList();
  if (!lic || !list.includes(lic)) return res.status(200).json({ ok: false, plan: "none", build: BUILD });
  if (!isSafeClientId(clientId)) return res.status(400).json({ ok: false, error: "bad_client_id", build: BUILD });
  if (!isSafeHwidRaw(hwidRaw)) return res.status(400).json({ ok: false, error: "bad_hwid", build: BUILD });

  let redis;
  try { redis = getRedis(); }
  catch { return res.status(500).json({ ok: false, error: "redis_not_configured", build: BUILD }); }

  const hw = hwidHash(hwidRaw, secret);

  // Enforce HWID binding for the license
  const bind = await enforceHwidBind(redis, lic, hw);
  if (!bind.ok) {
    return res.status(403).json({ ok: false, error: bind.error, build: BUILD });
  }

  const plan = planForLicense(lic);
  const limit = limitForPlan(plan);
  const ttl = ttlForPlan(plan);

  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttl;

  await cleanupActive(redis, lic, now);

  const setKey = activeSetKey(lic);
  const activeCount = await redis.scard(setKey);

  if ((activeCount || 0) >= limit) {
    return res.status(429).json({
      ok: false,
      plan,
      error: "too_many_sessions",
      active: activeCount || 0,
      limit,
      build: BUILD
    });
  }

  const sid = makeSessionId();
  const sk = sessionKey(lic, sid);

  // Store session with cid + hw
  const record = JSON.stringify({ exp: exp, cid: clientId, hw: hw, seen: now });

  await redis.set(sk, record, { ex: ttl + 180 });
  await redis.sadd(setKey, sid);
  await redis.expire(setKey, ttl + 300);

  // Token includes hw so later endpoints can enforce without resending hwid
  const token = signToken({ lic, plan, exp, sid, cid: clientId, hw: hw }, secret);

  return res.status(200).json({
    ok: true,
    plan,
    token,
    exp,
    sessionId: sid,
    ttlSeconds: ttl,
    hwBound: bind.boundNow === true,
    hwSlotsUsed: bind.allowedCount,
    build: BUILD
  });
};