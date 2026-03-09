const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-hard-2026-03-09-admin4c";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
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

function signLaunchChallenge(parts, secret) {
  const joined = parts.map((x) => String(x || "")).join("|");
  return b64urlFromBuffer(
    crypto.createHmac("sha256", secret).update(joined).digest()
  );
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

function isSafeStartUrl(s) {
  s = String(s || "").trim();
  if (!s) return false;
  if (s.length > 2048) return false;
  if (/["'\r\n]/.test(s)) return false;
  const l = s.toLowerCase();
  return l.startsWith("http://") || l.startsWith("https://");
}

function toInt(v, dflt) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : dflt;
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

function alertsListKey() {
  return "sn:admin:alerts";
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

async function pushAlert(redis, entry) {
  try {
    await redis.lpush(alertsListKey(), JSON.stringify({
      id: crypto.randomBytes(10).toString("hex"),
      ts: Math.floor(Date.now() / 1000),
      ...entry
    }));
    await redis.ltrim(alertsListKey(), 0, 299);
  } catch {}
}

function getFlagsForPlan(plan) {
  const base = [
    "--no-first-run",
    "--disable-default-apps",
    "--disable-component-update",
    "--disable-background-networking",
    "--disable-sync",
    "--metrics-recording-only",
    "--disable-renderer-backgrounding",
    "--disable-backgrounding-occluded-windows",
    "--disable-features=OptimizationGuideModelDownloading,Translate,MediaRouter,AutofillServerCommunication",
    "--disable-extensions",
    '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    "--dns-over-https-templates=https://cloudflare-dns.com/dns-query"
  ];

  if (plan === "pro") {
    return base.concat([
      "--force-dark-mode",
      "--enable-gpu-rasterization"
    ]);
  }

  if (plan === "free") {
    return base;
  }

  return base.concat([
    "--force-dark-mode"
  ]);
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  if (req.method !== "POST") {
    return res.status(405).json({
      ok: false,
      error: "method_not_allowed",
      build: BUILD
    });
  }

  const rl = await rateLimit(req, "launch", 20, 60);
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

  const body = await getJsonBody(req);

  const token = String(body.token || "").trim();
  const clientId = String(body.clientId || "").trim();
  const startUrl = String(body.startUrl || "").trim();
  const launchNonce = String(body.launchNonce || "").trim();
  const launchExp = toInt(body.launchExp, 0);
  const launchSig = String(body.launchSig || "").trim();
  const launchProfileId = String(body.launchProfileId || "").trim();

  if (!token) {
    return res.status(400).json({ ok: false, error: "missing_token", build: BUILD });
  }
  if (!isSafeClientId(clientId)) {
    return res.status(400).json({ ok: false, error: "bad_client_id", build: BUILD });
  }
  if (!isSafeStartUrl(startUrl)) {
    return res.status(400).json({ ok: false, error: "unsafe_url", build: BUILD });
  }
  if (!launchNonce || !launchExp || !launchSig || !launchProfileId) {
    return res.status(400).json({ ok: false, error: "missing_launch_fields", build: BUILD });
  }

  let redis;
  try {
    redis = getRedis();
  } catch {
    return res.status(500).json({ ok: false, error: "redis_not_configured", build: BUILD });
  }

  await metricIncr(redis, "launchAttempts", 1);

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
    await metricIncr(redis, "launchFailures", 1);
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
    await metricIncr(redis, "launchFailures", 1);
    return res.status(401).json({
      ok: false,
      error: "bad_token_payload",
      build: BUILD
    });
  }

  if (tokenCid !== clientId) {
    await metricIncr(redis, "launchFailures", 1);
    return res.status(403).json({
      ok: false,
      error: "bad_client_id",
      build: BUILD
    });
  }

  const now = Math.floor(Date.now() / 1000);
  if (exp <= now) {
    await metricIncr(redis, "launchFailures", 1);
    return res.status(401).json({
      ok: false,
      error: "session_expired",
      build: BUILD
    });
  }

  const keyDisabled = await redis.get(disabledKeyRedisKey(lic));
  if (keyDisabled) {
    await metricIncr(redis, "launchFailures", 1);
    return res.status(403).json({
      ok: false,
      error: "key_disabled",
      build: BUILD
    });
  }

  const disableAll = await redis.get(globalKey("disable_all"));
  if (disableAll) {
    await metricIncr(redis, "launchFailures", 1);
    return res.status(403).json({
      ok: false,
      error: "all_keys_disabled",
      build: BUILD
    });
  }

  const banned = await redis.get(bannedHwidKey(tokenHw));
  if (banned) {
    await metricIncr(redis, "launchFailures", 1);
    await pushAlert(redis, {
      type: "banned_device_try",
      hwidHash: tokenHw,
      license: lic,
      level: "high"
    });
    return res.status(403).json({
      ok: false,
      error: "hwid_banned",
      build: BUILD
    });
  }

  const sk = sessionKey(lic, sid);
  const sessRaw = await redis.get(sk);
  if (!sessRaw) {
    await metricIncr(redis, "launchFailures", 1);
    return res.status(404).json({
      ok: false,
      error: "session_not_found",
      build: BUILD
    });
  }

  const sess = safeJsonParse(sessRaw, null);
  if (!sess || typeof sess !== "object") {
    await redis.del(sk);
    await metricIncr(redis, "launchFailures", 1);
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
    await metricIncr(redis, "launchFailures", 1);
    return res.status(500).json({
      ok: false,
      error: "session_corrupt",
      build: BUILD
    });
  }

  if (sessExp <= now) {
    await redis.del(sk);
    await metricIncr(redis, "launchFailures", 1);
    return res.status(401).json({
      ok: false,
      error: "session_expired",
      build: BUILD
    });
  }

  if (sessCid !== clientId) {
    await metricIncr(redis, "launchFailures", 1);
    return res.status(403).json({
      ok: false,
      error: "bad_client_id",
      build: BUILD
    });
  }

  if (sessHw !== tokenHw) {
    await metricIncr(redis, "launchFailures", 1);
    return res.status(403).json({
      ok: false,
      error: "hwid_mismatch",
      build: BUILD
    });
  }

  const expectedSig = signLaunchChallenge(
    [lic, sid, clientId, tokenHw, launchNonce, launchExp, launchProfileId],
    secret
  );

  const a = Buffer.from(launchSig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    await metricIncr(redis, "launchFailures", 1);
    return res.status(403).json({
      ok: false,
      error: "bad_launch_sig",
      build: BUILD
    });
  }

  if (launchExp <= now) {
    await metricIncr(redis, "launchFailures", 1);
    return res.status(403).json({
      ok: false,
      error: "launch_expired",
      build: BUILD
    });
  }

  const nk = launchNonceKey(lic, sid, launchNonce);
  const nonceRaw = await redis.get(nk);
  if (!nonceRaw) {
    await metricIncr(redis, "launchFailures", 1);
    return res.status(403).json({
      ok: false,
      error: "launch_nonce_invalid",
      build: BUILD
    });
  }

  const nonceRow = safeJsonParse(nonceRaw, null);
  if (!nonceRow || typeof nonceRow !== "object") {
    await redis.del(nk);
    await metricIncr(redis, "launchFailures", 1);
    return res.status(403).json({
      ok: false,
      error: "launch_nonce_invalid",
      build: BUILD
    });
  }

  if (
    String(nonceRow.lic || "") !== lic ||
    String(nonceRow.sid || "") !== sid ||
    String(nonceRow.cid || "") !== clientId ||
    String(nonceRow.hw || "") !== tokenHw ||
    String(nonceRow.profileId || "") !== launchProfileId
  ) {
    await redis.del(nk);
    await metricIncr(redis, "launchFailures", 1);
    return res.status(403).json({
      ok: false,
      error: "launch_nonce_mismatch",
      build: BUILD
    });
  }

  if (toInt(nonceRow.exp, 0) <= now) {
    await redis.del(nk);
    await metricIncr(redis, "launchFailures", 1);
    return res.status(403).json({
      ok: false,
      error: "launch_expired",
      build: BUILD
    });
  }

  await redis.del(nk);

  const updatedSession = {
    ...sess,
    seen: now,
    lastLaunchAt: now,
    lastStartUrl: startUrl
  };

  const remainingTtl = Math.max(60, sessExp - now + 180);
  await redis.set(sk, JSON.stringify(updatedSession), { ex: remainingTtl });

  const flags = getFlagsForPlan(plan);
  const bundleExp = now + 20;

  await pushAudit(redis, {
    type: "launch",
    actor: "system",
    role: "system",
    action: "launch_bundle_issued",
    target: lic + ":" + sid,
    success: true,
    details: {
      license: lic,
      sessionId: sid,
      clientId,
      plan,
      startUrl
    }
  });

  return res.status(200).json({
    ok: true,
    bundle: {
      url: startUrl,
      flags,
      exp: bundleExp
    },
    build: BUILD
  });
};