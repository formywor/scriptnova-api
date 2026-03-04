const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

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

function safeJsonParse(str) {
  try { return JSON.parse(str); } catch { return null; }
}

function getToken(req) {
  return String(req.query.token || "").trim();
}

function getClientId(req) {
  return String(req.query.cid || "").trim();
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
  if (!payload || !payload.lic || !payload.plan || !payload.exp || !payload.sid || !payload.cid) {
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

function normalizeFlagServer(flag) {
  // Only allow what you explicitly support
  const ALLOW = {
    "--no-first-run": true,
    "--force-dark-mode": true,
    "--disable-renderer-backgrounding": true,
    "--dns-over-https-templates": true,
    "--user-agent": true
  };

  let f = String(flag || "").trim();
  if (!f) return "";
  if (/[\r\n\t\0]/.test(f)) return "";
  if (f.indexOf("--") !== 0) return "";
  if (f.indexOf("\"") !== -1) return ""; // server will quote values itself

  const eq = f.indexOf("=");
  const name = eq === -1 ? f : f.substring(0, eq);
  if (!ALLOW[name]) return "";

  if (eq === -1) return name;

  let val = f.substring(eq + 1).trim();
  if (!val) return "";

  if (val.indexOf(" ") !== -1) val = "\"" + val + "\"";
  return name + "=" + val;
}

function getLicenseList() {
  return (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  const rl = await rateLimit(req, "ui", 120, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({ ok: false, error: "rate_limited", retryAfter: rl.retryAfter });
  }

  const secret = String(process.env.SECRET_SALT || "");
  if (!secret || secret.length < 16) {
    return res.status(500).json({ ok: false, error: "server_misconfigured_secret" });
  }

  const token = getToken(req);
  const cid = getClientId(req);
  if (!isSafeClientId(cid)) return res.status(400).json({ ok: false, error: "bad_client_id" });

  const vt = verifyToken(token, secret);
  if (!vt.ok) return res.status(403).json({ ok: false, error: vt.error });

  const { lic, plan, sid, exp, cid: tokenCid } = vt.payload;
  if (cid !== tokenCid) return res.status(403).json({ ok: false, error: "client_mismatch" });

  const list = getLicenseList();
  if (!list.includes(lic)) return res.status(403).json({ ok: false, error: "license_revoked" });

  let redis;
  try {
    redis = getRedis();
  } catch {
    return res.status(500).json({ ok: false, error: "redis_not_configured" });
  }

  const sessionKey = "sn:sessions:" + lic;
  const storedRaw = await redis.hget(sessionKey, sid);
  if (!storedRaw) return res.status(403).json({ ok: false, error: "session_not_found" });

  const now = Math.floor(Date.now() / 1000);
  const s = parseSessionValue(storedRaw);

  if (s.exp <= now) {
    await redis.hdel(sessionKey, sid);
    return res.status(403).json({ ok: false, error: "session_expired" });
  }

  if (s.cid && s.cid !== cid) return res.status(403).json({ ok: false, error: "client_mismatch" });

  // Heartbeat enforcement (tune in env)
  const HEARTBEAT_MAX_GAP = parseInt(process.env.HEARTBEAT_MAX_GAP_SEC || "210", 10);
  if (s.seen && (now - s.seen) > HEARTBEAT_MAX_GAP) {
    await redis.hdel(sessionKey, sid);
    return res.status(403).json({ ok: false, error: "heartbeat_lost" });
  }

  // Update last seen (also acts as heartbeat)
  await redis.hset(sessionKey, { [sid]: JSON.stringify({ exp: s.exp, cid: cid, seen: now }) });

  const ui = {
    showProModeToggle: plan === "pro",
    showMediaModeToggle: true,
    showThemePicker: true
  };

  const proUA = "Mozilla/5.0 (X11; CrOS aarch64 15699.85.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.110 Safari/537.36";

  const rawFlags = plan === "pro"
    ? [
        "--no-first-run",
        "--force-dark-mode",
        "--disable-renderer-backgrounding",
        "--dns-over-https-templates=https://chrome.cloudflare-dns.com/dns-query",
        "--user-agent=" + proUA
      ]
    : [
        "--no-first-run",
        "--force-dark-mode"
      ];

  const chromeFlags = rawFlags.map(normalizeFlagServer).filter(Boolean);

  return res.status(200).json({
    ok: true,
    plan,
    exp,
    sessionId: sid,
    ui,
    config: { chromeFlags }
  });
};