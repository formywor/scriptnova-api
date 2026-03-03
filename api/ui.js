import crypto from "crypto";
import { getRedis } from "./_redis.js";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function b64urlToBuffer(s) {
  s = (s || "").toString().replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

function safeJsonParse(str) {
  try { return JSON.parse(str); } catch { return null; }
}

function getToken(req) {
  return (req.query.token || "").toString().trim();
}

function verifyToken(token, secret) {
  if (!token || token.indexOf(".") === -1) return { ok: false, error: "bad_token" };

  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, error: "bad_token" };

  const payloadB64 = parts[0];
  const sigB64 = parts[1];

  const expected = crypto.createHmac("sha256", secret).update(payloadB64).digest();
  const expectedB64 = expected
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  const a = Buffer.from(expectedB64);
  const b = Buffer.from(sigB64);
  if (a.length !== b.length) return { ok: false, error: "bad_sig" };
  if (!crypto.timingSafeEqual(a, b)) return { ok: false, error: "bad_sig" };

  const payloadJson = b64urlToBuffer(payloadB64).toString("utf8");
  const payload = safeJsonParse(payloadJson);
  if (!payload || !payload.lic || !payload.exp || !payload.sid || !payload.plan) {
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

export default async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  const secret = (process.env.SECRET_SALT || "").toString();
  if (!secret || secret.length < 16) {
    return res.status(500).json({ ok: false, error: "server_misconfigured_secret" });
  }

  const token = getToken(req);
  const vt = verifyToken(token, secret);
  if (!vt.ok) return res.status(403).json({ ok: false, error: vt.error });

  const { lic, plan, exp, sid } = vt.payload;

  const list = getLicenseList();
  if (!list.includes(lic)) return res.status(403).json({ ok: false, error: "license_revoked" });

  let redis;
  try {
    redis = getRedis();
  } catch {
    return res.status(500).json({ ok: false, error: "redis_not_configured" });
  }

  const sessionKey = `sn:sessions:${lic}`;
  const storedExp = await redis.hget(sessionKey, sid);
  if (!storedExp) return res.status(403).json({ ok: false, error: "session_not_found" });

  const now = Math.floor(Date.now() / 1000);
  const storedExpNum = parseInt(storedExp, 10) || 0;
  if (storedExpNum <= now) {
    await redis.hdel(sessionKey, sid);
    return res.status(403).json({ ok: false, error: "session_expired" });
  }

  const ui = {
    showProModeToggle: plan === "pro",
    showMediaModeToggle: true,
    showThemePicker: true
  };

  const config = {
    chromeFlags: plan === "pro"
      ? [
          "--no-first-run",
          "--force-dark-mode",
          "--disable-renderer-backgrounding",
          "--dns-over-https-templates=https://chrome.cloudflare-dns.com/dns-query",
          "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]
      : [
          "--no-first-run",
          "--force-dark-mode"
        ]
  };

  return res.status(200).json({
    ok: true,
    plan,
    exp,
    sessionId: sid,
    ui,
    config
  });
}