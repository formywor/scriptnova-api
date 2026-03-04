const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const PREFIX = "sn2";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function b64urlToBuffer(s) {
  s = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

function safeJsonParse(str) {
  try { return JSON.parse(str); } catch { return null; }
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

function verifyToken(token, secret) {
  if (!token || token.indexOf(".") === -1) return { ok: false, error: "bad_token" };
  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, error: "bad_token" };

  const payloadB64 = parts[0];
  const sigB64 = parts[1];

  const expected = crypto.createHmac("sha256", secret).update(payloadB64).digest();
  const expectedB64 = expected.toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

  const a = Buffer.from(expectedB64);
  const b = Buffer.from(sigB64);
  if (a.length !== b.length) return { ok: false, error: "bad_sig" };
  if (!crypto.timingSafeEqual(a, b)) return { ok: false, error: "bad_sig" };

  const payloadJson = b64urlToBuffer(payloadB64).toString("utf8");
  const payload = safeJsonParse(payloadJson);
  if (!payload || !payload.lic || !payload.sid || !payload.exp || !payload.cid) {
    return { ok: false, error: "bad_payload" };
  }

  const now = Math.floor(Date.now() / 1000);
  if (now > (payload.exp + 15)) return { ok: false, error: "expired" };

  return { ok: true, payload };
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

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "method_not_allowed" });

  const rl = await rateLimit(req, "ping", 300, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({ ok: false, error: "rate_limited", retryAfter: rl.retryAfter });
  }

  const secret = String(process.env.SECRET_SALT || "");
  if (!secret || secret.length < 16) {
    return res.status(500).json({ ok: false, error: "server_misconfigured_secret" });
  }

  const body = await getJsonBody(req);
  const token = String(body.token || "");
  const cid = String(body.clientId || "").trim();
  if (!isSafeClientId(cid)) return res.status(400).json({ ok: false, error: "bad_client_id" });

  const vt = verifyToken(token, secret);
  if (!vt.ok) return res.status(403).json({ ok: false, error: vt.error });

  const { lic, sid, cid: tokenCid } = vt.payload;
  if (cid !== tokenCid) return res.status(403).json({ ok: false, error: "client_mismatch" });

  let redis;
  try { redis = getRedis(); }
  catch { return res.status(500).json({ ok: false, error: "redis_not_configured" }); }

  const sessionKey = `${PREFIX}:sessions:${lic}`;
  const storedRaw = await redis.hget(sessionKey, sid);
  if (!storedRaw) return res.status(403).json({ ok: false, error: "session_not_found" });

  const now = Math.floor(Date.now() / 1000);
  const s = parseSessionValue(storedRaw);

  if ((s.exp || 0) <= now) {
    await redis.hdel(sessionKey, sid);
    return res.status(403).json({ ok: false, error: "session_expired" });
  }

  if (s.cid && s.cid !== cid) return res.status(403).json({ ok: false, error: "client_mismatch" });

  await redis.hset(sessionKey, sid, JSON.stringify({ exp: s.exp, cid: cid, seen: now }));
  return res.status(200).json({ ok: true, seen: now });
};