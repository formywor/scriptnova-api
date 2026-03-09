const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-hard-2026-03-09-admin3";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function b64urlEncodeUtf8(str) {
  return Buffer.from(String(str), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function b64urlDecodeUtf8(s) {
  s = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64").toString("utf8");
}

function b64urlFromBuffer(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function verifySignedToken(token, secret) {
  token = String(token || "").trim();
  const dot = token.lastIndexOf(".");
  if (dot <= 0) return null;

  const payloadB64 = token.slice(0, dot);
  const sigB64 = token.slice(dot + 1);

  const expectedSig = b64urlFromBuffer(
    crypto.createHmac("sha256", secret).update(payloadB64).digest()
  );

  const a = Buffer.from(sigB64);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length) return null;
  if (!crypto.timingSafeEqual(a, b)) return null;

  try {
    const payloadJson = b64urlDecodeUtf8(payloadB64);
    const obj = JSON.parse(payloadJson);
    return obj && typeof obj === "object" ? obj : null;
  } catch {
    return null;
  }
}

function isSafeClientId(s) {
  s = String(s || "").trim();
  if (!s) return false;
  if (s.length < 16 || s.length > 80) return false;
  return /^[A-Za-z0-9\-_.]+$/.test(s);
}

function sessionKey(lic, sid) {
  return "sn:session:" + String(lic) + ":" + String(sid);
}

function launchNonceKey(lic, sid, nonce) {
  return "sn:launchnonce:" + String(lic) + ":" + String(sid) + ":" + String(nonce);
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

function auditListKey() {
  return "sn:admin:audit";
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

async function pushAudit(redis, entry) {
  try {
    await redis.lpush(auditListKey(), JSON.stringify({
      id: crypto.randomBytes(10).toString("hex"),
      ts: Math.floor(Date.now() / 1000),
      ...entry
    }));
    await redis.ltrim(auditListKey(), 0, 799);
  } catch {}
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

function randHex(n) {
  return crypto.randomBytes(n).toString("hex");
}

function signLaunchChallenge(parts, secret) {
  const joined = parts.map((x) => String(x || "")).join("|");
  return b64urlFromBuffer(
    crypto.createHmac("sha256", secret).update(joined).digest()
  );
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  if (req.method !== "GET") {
    return res.status(405).json({
      ok: false,
      error: "method_not_allowed",
      build: BUILD
    });
  }

  const rl = await rateLimit(req, "ui", 30, 60);
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

  const token = String(req.query.token || "").trim();
  const cid = String(req.query.cid || req.query.clientId || "").trim();

  if (!token) {
    return res.status(400).json({
      ok: false,
      error: "missing_token",
      build: BUILD
    });
  }

  if (!isSafeClientId(cid)) {
    return res.status(400).json({
      ok: false,
      error: "bad_client_id",
      build: BUILD
    });
  }

  let redis;
  try {
    redis = getRedis();
  } catch {
    return res.status(500).json({
      ok: false,
      error: "redis_not_configured",
      build: BUILD
    });
  }

  const paused = await redis.get(globalKey("paused"));
  if (paused) {
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

  const payload = verifySignedToken(token, secret);
  if (!payload) {
    return res.status(401).json({
      ok: false,
      error: "bad_token",
      build: BUILD
    });
  }

  const lic = String(payload.lic || "").trim();
  const plan = String(payload.plan || "").trim().toLowerCase();
  const exp = toInt(payload.exp, 0);
  const sid = String(payload.sid || "").trim();
  const tokenCid = String(payload.cid || "").trim();
  const tokenHw = String(payload.hw || "").trim();

  if (!lic || !plan || !exp || !sid || !tokenCid || !tokenHw) {
    return res.status(401).json({
      ok: false,
      error: "bad_token_payload",
      build: BUILD
    });
  }

  if (tokenCid !== cid) {
    return res.status(403).json({
      ok: false,
      error: "bad_client_id",
      build: BUILD
    });
  }

  const now = Math.floor(Date.now() / 1000);
  if (exp <= now) {
    return res.status(401).json({
      ok: false,
      error: "session_expired",
      build: BUILD
    });
  }

  const keyDisabled = await redis.get(disabledKeyRedisKey(lic));
  if (keyDisabled) {
    return res.status(403).json({
      ok: false,
      error: "key_disabled",
      build: BUILD
    });
  }

  const disableAll = await redis.get(globalKey("disable_all"));
  if (disableAll) {
    return res.status(403).json({
      ok: false,
      error: "all_keys_disabled",
      build: BUILD
    });
  }

  const banned = await redis.get(bannedHwidKey(tokenHw));
  if (banned) {
    return res.status(403).json({
      ok: false,
      error: "hwid_banned",
      build: BUILD
    });
  }

  const sk = sessionKey(lic, sid);
  const raw = await redis.get(sk);
  if (!raw) {
    return res.status(404).json({
      ok: false,
      error: "session_not_found",
      build: BUILD
    });
  }

  const sess = safeJsonParse(raw, null);
  if (!sess || typeof sess !== "object") {
    await redis.del(sk);
    return res.status(500).json({
      ok: false,
      error: "session_corrupt",
      build: BUILD
    });
  }

  const sessExp = toInt(sess.exp, 0);
  const sessCid = String(sess.cid || "").trim();
  const sessHw = String(sess.hw || "").trim();

  if (!sessExp || !sessCid || !sessHw) {
    await redis.del(sk);
    return res.status(500).json({
      ok: false,
      error: "session_corrupt",
      build: BUILD
    });
  }

  if (sessExp <= now) {
    await redis.del(sk);
    return res.status(401).json({
      ok: false,
      error: "session_expired",
      build: BUILD
    });
  }

  if (sessCid !== cid) {
    return res.status(403).json({
      ok: false,
      error: "bad_client_id",
      build: BUILD
    });
  }

  if (sessHw !== tokenHw) {
    return res.status(403).json({
      ok: false,
      error: "hwid_mismatch",
      build: BUILD
    });
  }

  const launchNonce = randHex(16);
  const launchExp = now + 20;
  const launchProfileId = plan + "_default_1";

  const launchSig = signLaunchChallenge(
    [lic, sid, cid, tokenHw, launchNonce, launchExp, launchProfileId],
    secret
  );

  const nonceRow = JSON.stringify({
    lic,
    sid,
    cid,
    hw: tokenHw,
    exp: launchExp,
    profileId: launchProfileId,
    createdAt: now
  });

  await redis.set(
    launchNonceKey(lic, sid, launchNonce),
    nonceRow,
    { ex: 25 }
  );

  await metricIncr(redis, "uiChallenges", 1);

  await pushAudit(redis, {
    type: "launch",
    actor: "system",
    role: "system",
    action: "ui_challenge_issued",
    target: lic + ":" + sid,
    success: true,
    details: {
      license: lic,
      sessionId: sid,
      clientId: cid,
      profileId: launchProfileId
    }
  });

  return res.status(200).json({
    ok: true,
    launchProfileId,
    launchNonce,
    launchExp,
    launchSig,
    ui: {
      plan,
      maintenance: false
    },
    build: BUILD
  });
};