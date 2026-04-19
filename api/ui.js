const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-hard-2026-03-10-public2";
const EVENT_KEEP = 400;

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
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

function eventsListKey() {
  return "sn:public:events";
}

function pollVotesKey(pollId) {
  return "sn:public:poll:" + String(pollId) + ":votes";
}

function pollVoteByClientKey(pollId, clientId) {
  return "sn:public:pollvote:" + String(pollId) + ":cid:" + String(clientId);
}

function pollVoteByHwidKey(pollId, hwid) {
  return "sn:public:pollvote:" + String(pollId) + ":hw:" + String(hwid);
}

async function metricIncr(redis, field, by) {
  try {
    const key = metricsKey(todayKeyDate());
    await redis.hincrby(key, field, by || 1);
    await redis.expire(key, 60 * 60 * 24 * 10);
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

function cleanStr(v, maxLen) {
  v = String(v == null ? "" : v).trim();
  if (!maxLen) return v;
  return v.length > maxLen ? v.slice(0, maxLen) : v;
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

async function handlePublicSubmit(req, res, redis) {
  const rl = await rateLimit(req, "ui_submit", 120, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({ ok: false, error: "rate_limited", retryAfter: rl.retryAfter, build: BUILD });
  }

  const paused = await redis.get(globalKey("paused"));
  if (paused) {
    return res.status(503).json({ ok: false, error: "launcher_paused", build: BUILD });
  }

  const body = await getJsonBody(req);
  const kind = cleanStr(body.kind, 64).toLowerCase();
  const clientId = cleanStr(body.clientId, 128);
  const hwid = cleanStr(body.hwid, 128);
  const version = cleanStr(body.version, 64);
  const data = safeJsonParse(body.data, {});

  if (!kind) return res.status(400).json({ ok: false, error: "missing_kind", build: BUILD });

  const row = {
    id: `${Math.floor(Date.now() / 1000)}_${Math.random().toString(16).slice(2, 10)}`,
    ts: Math.floor(Date.now() / 1000),
    kind,
    clientId,
    hwid,
    version,
    data: typeof data === "object" && data ? data : {}
  };

  try {
    await redis.lpush(eventsListKey(), JSON.stringify(row));
    await redis.ltrim(eventsListKey(), 0, EVENT_KEEP - 1);
  } catch {}

  await metricIncr(redis, "publicEvents", 1);

  if (kind === "dismiss_banner") {
    await metricIncr(redis, "bannerDismissals", 1);
  }

  if (kind === "cleanup_run") {
    await metricIncr(redis, "cleanupRuns", 1);
  }

  if (kind === "poll_vote") {
    const pollId = cleanStr(data.pollId, 128);
    const value = cleanStr(data.value, 200);
    if (pollId && value) {
      let duplicate = false;
      try {
        if (clientId) {
          const k = pollVoteByClientKey(pollId, clientId);
          const had = await redis.get(k);
          if (had) duplicate = true;
          else await redis.set(k, value, { ex: 60 * 60 * 24 * 90 });
        }
      } catch {}
      try {
        if (!duplicate && hwid) {
          const k = pollVoteByHwidKey(pollId, hwid);
          const had = await redis.get(k);
          if (had) duplicate = true;
          else await redis.set(k, value, { ex: 60 * 60 * 24 * 90 });
        }
      } catch {}

      if (!duplicate) {
        try {
          await redis.hincrby(pollVotesKey(pollId), value, 1);
          await redis.expire(pollVotesKey(pollId), 60 * 60 * 24 * 180);
        } catch {}
        await metricIncr(redis, "pollVotes", 1);
      }

      return res.status(200).json({ ok: true, duplicate, build: BUILD });
    }
  }

  return res.status(200).json({ ok: true, build: BUILD });
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

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

  if (req.method === "POST") {
    return handlePublicSubmit(req, res, redis);
  }

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