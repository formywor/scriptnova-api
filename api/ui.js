const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-hard-2026-03-05a";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function b64urlToBuffer(s) {
  s = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

function b64urlFromBuffer(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function safeJsonParse(str) {
  try { return JSON.parse(str); } catch { return null; }
}

function parseRedisJson(raw) {
  if (raw == null) return null;
  if (typeof raw === "object") return raw;
  if (typeof raw === "string") return safeJsonParse(raw);
  return safeJsonParse(String(raw));
}

function isSafeClientId(s) {
  if (!s) return false;
  if (s.length < 16 || s.length > 80) return false;
  return /^[A-Za-z0-9\-_.]+$/.test(s);
}

function verifyToken(token, secret) {
  if (!token || token.indexOf(".") === -1) return { ok: false, error: "bad_token" };
  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, error: "bad_token" };

  const payloadB64 = parts[0];
  const sigB64 = parts[1];

  const expected = crypto.createHmac("sha256", secret).update(payloadB64).digest();
  const expectedB64 = b64urlFromBuffer(expected);

  const a = Buffer.from(expectedB64);
  const b = Buffer.from(sigB64);
  if (a.length !== b.length) return { ok: false, error: "bad_sig" };
  if (!crypto.timingSafeEqual(a, b)) return { ok: false, error: "bad_sig" };

  const payloadJson = b64urlToBuffer(payloadB64).toString("utf8");
  const payload = safeJsonParse(payloadJson);
  if (!payload || !payload.lic || !payload.plan || !payload.exp || !payload.sid || !payload.cid) {
    return { ok: false, error: "bad_payload" };
  }

  const now = Math.floor(Date.now() / 1000);
  if (now > (payload.exp + 15)) return { ok: false, error: "expired" };

  return { ok: true, payload };
}

function getLicenseList() {
  return (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function sessionKey(lic, sid) { return "sn:session:" + lic + ":" + sid; }

function randomNonceB64url(bytes = 16) {
  return b64urlFromBuffer(crypto.randomBytes(bytes));
}

function makeLaunchSig(secret, sid, cid, nonce, exp, profileId) {
  const msg = `sid=${sid}&cid=${cid}&nonce=${nonce}&exp=${exp}&profile=${profileId}`;
  return b64urlFromBuffer(crypto.createHmac("sha256", secret).update(msg).digest());
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  const rl = await rateLimit(req, "ui", 240, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({ ok: false, error: "rate_limited", retryAfter: rl.retryAfter, build: BUILD });
  }

  const secret = String(process.env.SECRET_SALT || "");
  if (!secret || secret.length < 16) {
    return res.status(500).json({ ok: false, error: "server_misconfigured_secret", build: BUILD });
  }

  const token = String(req.query.token || "").trim();
  const cid = String(req.query.cid || "").trim();
  if (!isSafeClientId(cid)) return res.status(400).json({ ok: false, error: "bad_client_id", build: BUILD });

  const vt = verifyToken(token, secret);
  if (!vt.ok) return res.status(403).json({ ok: false, error: vt.error, build: BUILD });

  const { lic, plan, sid } = vt.payload;
  if (cid !== vt.payload.cid) return res.status(403).json({ ok: false, error: "client_mismatch", build: BUILD });

  const list = getLicenseList();
  if (!list.includes(lic)) return res.status(200).json({ ok: false, plan: "none", build: BUILD });

  let redis;
  try { redis = getRedis(); }
  catch { return res.status(500).json({ ok: false, error: "redis_not_configured", build: BUILD }); }

  const sk = sessionKey(lic, sid);
  const raw = await redis.get(sk);
  if (!raw) return res.status(403).json({ ok: false, error: "session_not_found", build: BUILD });

  const s = parseRedisJson(raw);
  if (!s) return res.status(403).json({ ok: false, error: "session_corrupt", build: BUILD });

  const now = Math.floor(Date.now() / 1000);
  const expStored = parseInt(s.exp, 10) || 0;
  if (expStored <= now) {
    await redis.del(sk);
    return res.status(403).json({ ok: false, error: "session_expired", build: BUILD });
  }
  if (String(s.cid || "") !== cid) return res.status(403).json({ ok: false, error: "client_mismatch", build: BUILD });

  // touch session
  s.seen = now;
  await redis.set(sk, JSON.stringify(s), { ex: Math.max(60, expStored - now + 180) });

  // ✅ NEW: launch challenge (NO FLAGS HERE)
  const launchProfileId = (plan === "pro") ? "pro_default_1" : "basic_default_1";
  const launchNonce = randomNonceB64url(16);
  const launchExp = now + 20; // short window
  const launchSig = makeLaunchSig(secret, sid, cid, launchNonce, launchExp, launchProfileId);

  return res.status(200).json({
    ok: true,
    plan,
    exp: expStored,
    sessionId: sid,

    // launch challenge
    launchProfileId,
    launchNonce,
    launchExp,
    launchSig,

    // small UI config only
    ui: { showProModeToggle: plan === "pro", showMediaModeToggle: true, showThemePicker: true },
    build: BUILD
  });
};