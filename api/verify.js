const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-hard-2026-03-20-balance-c";

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

function b64urlFromBuffer(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signToken(payloadObj, secret) {
  const payloadJson = JSON.stringify(payloadObj);
  const payloadB64 = b64urlEncodeUtf8(payloadJson);
  const sig = crypto.createHmac("sha256", secret).update(payloadB64).digest();
  const sigB64 = b64urlFromBuffer(sig);
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
  s = String(s || "").trim();
  if (!s) return false;
  if (s.length < 16 || s.length > 80) return false;
  return /^[A-Za-z0-9\-_.]+$/.test(s);
}

function isSafeHwidRaw(s) {
  s = String(s || "").trim();
  if (!s) return false;
  if (s.length < 8 || s.length > 240) return false;
  if (/[\r\n\t\0]/.test(s)) return false;
  return true;
}

function hwidHash(raw, secret) {
  return crypto
    .createHash("sha256")
    .update(String(secret) + "|" + String(raw))
    .digest("hex");
}

function planForLicense(lic) {
  lic = String(lic || "").trim().toUpperCase();

  if (lic.indexOf("FREE-") === 0) return "free";
  if (lic.indexOf("BLACKEXP-") === 0 || lic.indexOf("BLACK_EXPRESS-") === 0) return "black_express";
  if (lic.indexOf("EXPRESS-") === 0) return "express";
  if (lic.indexOf("ELITE-") === 0) return "elite";
  if (lic.indexOf("PRO-") === 0) return "pro";
  if (lic.indexOf("BASIC-") === 0) return "basic";

  return "basic";
}

function limitForPlan(plan) {
  if (plan === "free") return 1;
  if (plan === "basic") return 3;
  if (plan === "pro") return 10;
  if (plan === "elite") return 10;
  if (plan === "express") return 725;
  if (plan === "black_express") return 1500;
  return 3;
}

function ttlForPlan(plan) {
  if (plan === "free") return 15 * 60;
  if (plan === "basic") return 6 * 60 * 60;
  if (plan === "pro") return 48 * 60 * 60;
  if (plan === "elite") return 168 * 60 * 60;
  if (plan === "express") return 720 * 60 * 60;
  if (plan === "black_express") return 1800 * 60 * 60;
  return 6 * 60 * 60;
}

function maxDevicesForPlan(plan) {
  if (plan === "free") return 1;
  if (plan === "basic") return 2;
  if (plan === "pro") return 10;
  if (plan === "elite") return 6;
  if (plan === "express") return 2;
  if (plan === "black_express") return 12;
  return 2;
}

function makeSessionId() {
  return crypto.randomBytes(18).toString("hex");
}

function safeJsonParse(v, fallback) {
  try {
    if (v == null) return fallback;
    if (typeof v === "object") return v;
    return JSON.parse(String(v));
  } catch {
    return fallback;
  }
}

function toInt(v, dflt) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : dflt;
}

function sessionKey(lic, sid) {
  return "sn:session:" + lic + ":" + sid;
}

function activeSetKey(lic) {
  return "sn:active:" + lic;
}

function hwidSetKey(lic) {
  return "sn:hwids:" + lic;
}

function freeKeyRedisKey(freeKey) {
  return "sn:freekey:" + String(freeKey);
}

function customKeyRedisKey(license) {
  return "sn:custom:" + String(license);
}

function disabledKeyRedisKey(license) {
  return "sn:disabled:" + String(license);
}

function bannedHwidKey(hwHash) {
  return "sn:banned:hwid:" + String(hwHash);
}

function globalKey(name) {
  return "sn:global:" + String(name);
}

function metricsKey(day) {
  return "sn:metrics:" + String(day);
}

function todayKeyDate() {
  const d = new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  return `${y}${m}${dd}`;
}

async function metricIncr(redis, field, by) {
  try {
    const key = metricsKey(todayKeyDate());
    await redis.hincrby(key, field, by || 1);
    await redis.expire(key, 60 * 60 * 24 * 10);
  } catch {}
}

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

async function enforceHwidBind(redis, lic, hwHash, maxDevices, plan) {
  const key = hwidSetKey(lic);
  const members = await redis.smembers(key);
  const set = new Set((members || []).map(String));

  if (plan === "free" && set.size > 1) {
    return { ok: false, error: "free_key_locked" };
  }

  if (set.size === 0) {
    await redis.sadd(key, hwHash);
    return { ok: true, boundNow: true, allowedCount: 1 };
  }

  if (set.has(hwHash)) {
    return { ok: true, boundNow: false, allowedCount: set.size };
  }

  if (set.size >= maxDevices) {
    return { ok: false, error: "hwid_mismatch" };
  }

  await redis.sadd(key, hwHash);
  return { ok: true, boundNow: true, allowedCount: set.size + 1 };
}

async function resolveLicense(redis, lic) {
  if (!lic) return { ok: false, error: "invalid_key" };

  const disabled = await redis.get(disabledKeyRedisKey(lic));
  if (disabled) {
    return { ok: false, error: "key_disabled" };
  }

  const disableAll = await redis.get(globalKey("disable_all"));
  if (disableAll) {
    return { ok: false, error: "all_keys_disabled" };
  }

  const customRaw = await redis.get(customKeyRedisKey(lic));
  if (customRaw) {
    const obj = safeJsonParse(customRaw, null);
    if (!obj || typeof obj !== "object") {
      return { ok: false, error: "custom_key_invalid" };
    }

    const now = Math.floor(Date.now() / 1000);
    const plan = String(obj.plan || planForLicense(lic)).trim().toLowerCase();
    const configuredTtl = Math.max(1, toInt(obj.ttlSeconds, ttlForPlan(plan)));
    const limit = Math.max(1, toInt(obj.sessionLimit, limitForPlan(plan)));
    const maxDevices = Math.max(1, toInt(obj.maxDevices, maxDevicesForPlan(plan)));
    const exp = toInt(obj.exp, 0);

    if (exp > 0 && exp <= now) {
      return { ok: false, error: "key_expired" };
    }

    let ttl = configuredTtl;
    if (exp > 0) {
      ttl = Math.max(1, Math.min(configuredTtl, exp - now));
    }

    return {
      ok: true,
      source: "custom",
      kind: "custom",
      plan,
      tier: String(obj.tier || ""),
      ttl,
      configuredTtlSeconds: configuredTtl,
      limit,
      maxDevices,
      keyExp: exp
    };
  }

  if (String(lic).toUpperCase().indexOf("FREE-") === 0) {
    return { ok: false, error: "invalid_key" };
  }

  const allowedKeys = ["PRO-Z", "PRO-SNOVAPROKEY", "PRO-SENG1", "PRO-MH1", "PRO-LUKASISCOOL", "PRO-MH2", "PRO-SHAYGAY", "PRO-KOFS"];
  if (!lic || !allowedKeys.includes(lic.toUpperCase())) {
    return { ok: false, error: "invalid_key" };
  }

  const plan = planForLicense(lic);

  return {
    ok: true,
    source: "env",
    kind: "env",
    plan,
    tier: "",
    ttl: ttlForPlan(plan),
    configuredTtlSeconds: ttlForPlan(plan),
    limit: limitForPlan(plan),
    maxDevices: maxDevicesForPlan(plan),
    keyExp: 0
  };
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  const rl = await rateLimit(req, "verify", 12, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({
      ok: false,
      error: "rate_limited",
      retryAfter: rl.retryAfter,
      build: BUILD
    });
  }

  const secret = String(process.env.SECRET_SALT || "");
  if (!secret || secret.length < 16) {
    return res.status(500).json({
      ok: false,
      error: "server_misconfigured_secret",
      build: BUILD
    });
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

  if (!isSafeClientId(clientId)) {
    return res.status(400).json({ ok: false, error: "bad_client_id", build: BUILD });
  }

  if (!isSafeHwidRaw(hwidRaw)) {
    return res.status(400).json({ ok: false, error: "bad_hwid", build: BUILD });
  }

  let redis;
  try {
    redis = getRedis();
  } catch {
    return res.status(500).json({ ok: false, error: "redis_not_configured", build: BUILD });
  }

  await metricIncr(redis, "verifyAttempts", 1);

  const globalPaused = await redis.get(globalKey("paused"));
  if (globalPaused) {
    const reason = String((await redis.get(globalKey("paused_reason"))) || "");
    return res.status(503).json({
      ok: false,
      error: "launcher_paused",
      reason,
      build: BUILD
    });
  }

  const maintenanceMode = await redis.get(globalKey("maintenance_mode"));
  if (maintenanceMode) {
    const message = String((await redis.get(globalKey("maintenance_message"))) || "");
    return res.status(503).json({
      ok: false,
      error: "maintenance_mode",
      message,
      build: BUILD
    });
  }

  const licenseInfo = await resolveLicense(redis, lic);
  if (!licenseInfo.ok) {
    return res.status(licenseInfo.error === "invalid_key" ? 200 : 403).json({
      ok: false,
      plan: "none",
      error: licenseInfo.error,
      build: BUILD
    });
  }

  const plan = licenseInfo.plan;
  const tier = licenseInfo.tier || "";
  const maxDevices = licenseInfo.maxDevices;
  const limit = licenseInfo.limit;
  const ttl = Math.max(1, toInt(licenseInfo.ttl, 1));

  const hw = hwidHash(hwidRaw, secret);

  const banned = await redis.get(bannedHwidKey(hw));
  if (banned) {
    return res.status(403).json({
      ok: false,
      error: "hwid_banned",
      build: BUILD
    });
  }

  const bind = await enforceHwidBind(redis, lic, hw, maxDevices, plan);
  if (!bind.ok) {
    return res.status(403).json({ ok: false, error: bind.error, build: BUILD });
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttl;

  await cleanupActive(redis, lic, now);

  const setKey = activeSetKey(lic);
  const activeCount = await redis.scard(setKey);

  if ((activeCount || 0) >= limit) {
    return res.status(429).json({
      ok: false,
      plan,
      tier,
      error: "too_many_sessions",
      active: activeCount || 0,
      limit,
      build: BUILD
    });
  }

  const sid = makeSessionId();
  const sk = sessionKey(lic, sid);

  const record = JSON.stringify({
    exp,
    cid: clientId,
    hw,
    seen: now,
    createdAt: now,
    ip: "",
    hwidRawPreview: String(hwidRaw).slice(0, 80),
    plan,
    tier,
    source: licenseInfo.source || "",
    keyExp: toInt(licenseInfo.keyExp, 0)
  });

  await redis.set(sk, record, { ex: ttl + 180 });
  await redis.sadd(setKey, sid);
  await redis.expire(setKey, ttl + 300);

  const token = signToken(
    { lic, plan, tier, exp, sid, cid: clientId, hw },
    secret
  );

  return res.status(200).json({
    ok: true,
    plan,
    tier,
    token,
    exp,
    sessionId: sid,
    ttlSeconds: ttl,
    configuredTtlSeconds: toInt(licenseInfo.configuredTtlSeconds, ttl),
    hwBound: bind.boundNow === true,
    hwSlotsUsed: bind.allowedCount,
    maxDevices,
    limit,
    source: licenseInfo.source,
    kind: licenseInfo.kind || "",
    keyExp: toInt(licenseInfo.keyExp, 0),
    build: BUILD
  });
};