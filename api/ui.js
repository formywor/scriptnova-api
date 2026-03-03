const crypto = require("crypto");

// --- helpers ---
function b64urlToBuffer(s) {
  s = (s || "").toString().replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

function safeJsonParse(str) {
  try { return JSON.parse(str); } catch { return null; }
}

function verifyToken(token, secret) {
  if (!token || token.indexOf(".") === -1) return { ok: false, error: "bad_token" };

  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, error: "bad_token" };

  const payloadB64 = parts[0];
  const sigB64 = parts[1];

  // recompute signature
  const expected = crypto.createHmac("sha256", secret).update(payloadB64).digest();
  const expectedB64 = expected
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  // constant-time compare
  const a = Buffer.from(expectedB64);
  const b = Buffer.from(sigB64);
  if (a.length !== b.length) return { ok: false, error: "bad_sig" };
  if (!crypto.timingSafeEqual(a, b)) return { ok: false, error: "bad_sig" };

  // decode payload
  const payloadJson = b64urlToBuffer(payloadB64).toString("utf8");
  const payload = safeJsonParse(payloadJson);
  if (!payload || !payload.lic || !payload.exp) return { ok: false, error: "bad_payload" };

  const now = Math.floor(Date.now() / 1000);
  // small clock-skew allowance (60s)
  if (now > (payload.exp + 60)) return { ok: false, error: "expired" };

  return { ok: true, payload };
}

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function getLicenseList() {
  return (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function getTokenFromReq(req) {
  // Accept token from:
  // 1) Authorization: Bearer <token>
  // 2) body.token
  // 3) query.token (for testing)
  const auth = (req.headers.authorization || "").toString();
  if (auth.toLowerCase().indexOf("bearer ") === 0) return auth.slice(7).trim();

  if (req.method === "GET") return (req.query.token || "").toString();
  return ((req.body && req.body.token) || "").toString();
}

module.exports = function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  const secret = (process.env.SECRET_SALT || "").toString();
  if (!secret || secret.length < 16) {
    return res.status(500).json({ ok: false, error: "server_misconfigured" });
  }

  const token = getTokenFromReq(req);
  const vt = verifyToken(token, secret);
  if (!vt.ok) return res.status(403).json({ ok: false, error: vt.error });

  const { lic, plan } = vt.payload;

  // server-side enforcement: token license must still be in LICENSES
  const list = getLicenseList();
  if (!list.includes(lic)) return res.status(403).json({ ok: false, error: "license_revoked" });

  // --- server controlled UI ---
  const ui = {
    showProModeToggle: plan === "pro",
    showMediaModeToggle: true,
    showToolsKillApps: true,
    showToolsRamOptimize: true,
    showToolsClearCache: true,
    showEdgeDrmButton: true,
    showThemePicker: true
  };

  // --- server controlled defaults + flags ---
  // Keep these safe. (Client will also filter.)
  const config = {
    defaults: {
      t_kill: plan === "pro",
      t_temp: false,
      t_incog: false,
      t_kiosk: false,
      t_gpu: true,
      t_ext: false,
      t_proxy: true,
      t_fps: false,
      t_mute: false
    },
    chromeFlags: plan === "pro"
      ? ["--no-first-run", "--force-dark-mode", "--disable-renderer-backgrounding"]
      : ["--no-first-run", "--force-dark-mode"]
  };

  return res.status(200).json({ ok: true, plan, ui, config });
};