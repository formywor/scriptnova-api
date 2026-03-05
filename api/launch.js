const crypto = require("crypto");
const { getRedis } = require("./_redis");
const { rateLimit } = require("./_rate");

const BUILD = "sn-hard-2026-03-05f";

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

function b64urlFromBuffer(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function safeJsonParse(str) { try { return JSON.parse(str); } catch { return null; } }
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

function isSafeHttpUrl(u) {
  u = String(u || "").trim();
  if (!u) return false;
  if (u.includes('"') || u.includes("'")) return false;
  if (u.includes("\r") || u.includes("\n")) return false;
  const low = u.toLowerCase();
  return low.startsWith("http://") || low.startsWith("https://");
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
  } catch { return {}; }
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
  if (!payload || !payload.lic || !payload.plan || !payload.exp || !payload.sid || !payload.cid || !payload.hw) {
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

function isFreeKey(lic) {
  return String(lic || "").indexOf("FREE-") === 0;
}

function freeKeyRedisKey(lic) {
  return "sn:freekey:" + String(lic);
}

function sessionKey(lic, sid) { return "sn:session:" + lic + ":" + sid; }
function nonceUsedKey(lic, sid, nonce) { return `sn:launchnonce:${lic}:${sid}:${nonce}`; }

function makeLaunchSig(secret, sid, cid, nonce, exp, profileId) {
  const msg = `sid=${sid}&cid=${cid}&nonce=${nonce}&exp=${exp}&profile=${profileId}`;
  return b64urlFromBuffer(crypto.createHmac("sha256", secret).update(msg).digest());
}

function normalizeFlagServer(flag) {
  const ALLOW = {
    "--no-first-run": true,
    "--force-dark-mode": true,
    "--disable-renderer-backgrounding": true,
    "--dns-over-https-templates": true,
    "--user-agent": true,
    "--disable-extensions": true,
    "--disable-default-apps": true,
    "--disable-component-update": true
  };

  let f = String(flag || "").trim();
  if (!f) return "";
  if (/[\r\n\t\0]/.test(f)) return "";
  if (!f.startsWith("--")) return "";
  if (f.includes('"')) return "";

  const eq = f.indexOf("=");
  const name = eq === -1 ? f : f.substring(0, eq);
  if (!ALLOW[name]) return "";

  if (eq === -1) return name;

  const val = f.substring(eq + 1).trim();
  if (!val) return "";

  return `${name}=${val}`;
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "method_not_allowed", build: BUILD });

  const rl = await rateLimit(req, "launch", 240, 60);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfter));
    return res.status(429).json({ ok: false, error: "rate_limited", retryAfter: rl.retryAfter, build: BUILD });
  }

  const secret = String(process.env.SECRET_SALT || "");
  if (!secret || secret.length < 16) {
    return res.status(500).json({ ok: false, error: "server_misconfigured_secret", build: BUILD });
  }

  const body = await getJsonBody(req);

  const token = String(body.token || "").trim();
  const clientId = String(body.clientId || "").trim();
  const startUrl = String(body.startUrl || "").trim();

  const launchNonce = String(body.launchNonce || "").trim();
  const launchExp = parseInt(body.launchExp, 10) || 0;
  const launchSig = String(body.launchSig || "").trim();
  const launchProfileId = String(body.launchProfileId || "").trim();

  if (!isSafeClientId(clientId)) return res.status(400).json({ ok: false, error: "bad_client_id", build: BUILD });
  if (!isSafeHttpUrl(startUrl)) return res.status(400).json({ ok: false, error: "unsafe_url", build: BUILD });
  if (!launchNonce || launchNonce.length < 16) return res.status(400).json({ ok: false, error: "bad_nonce", build: BUILD });
  if (!launchExp) return res.status(400).json({ ok: false, error: "bad_launch_exp", build: BUILD });
  if (!launchSig) return res.status(400).json({ ok: false, error: "bad_launch_sig", build: BUILD });
  if (!launchProfileId) return res.status(400).json({ ok: false, error: "bad_profile", build: BUILD });

  const now = Math.floor(Date.now() / 1000);
  if (now > launchExp) return res.status(403).json({ ok: false, error: "launch_expired", build: BUILD });
  if (launchExp > (now + 60)) return res.status(403).json({ ok: false, error: "launch_exp_too_far", build: BUILD });

  const vt = verifyToken(token, secret);
  if (!vt.ok) return res.status(403).json({ ok: false, error: vt.error, build: BUILD });

  const { lic, plan, sid, hw } = vt.payload;
  if (clientId !== vt.payload.cid) return res.status(403).json({ ok: false, error: "client_mismatch", build: BUILD });

  let redis;
  try { redis = getRedis(); }
  catch { return res.status(500).json({ ok: false, error: "redis_not_configured", build: BUILD }); }

  // ✅ License validation:
  if (isFreeKey(lic)) {
    const freeRaw = await redis.get(freeKeyRedisKey(lic));
    if (!freeRaw) return res.status(200).json({ ok: false, plan: "none", build: BUILD });
  } else {
    const list = getLicenseList();
    if (!list.includes(lic)) return res.status(200).json({ ok: false, plan: "none", build: BUILD });
  }

  const sk = sessionKey(lic, sid);
  const raw = await redis.get(sk);
  if (!raw) return res.status(403).json({ ok: false, error: "session_not_found", build: BUILD });

  const s = parseRedisJson(raw);
  if (!s) return res.status(403).json({ ok: false, error: "session_corrupt", build: BUILD });

  const expStored = parseInt(s.exp, 10) || 0;
  if (expStored <= now) {
    await redis.del(sk);
    return res.status(403).json({ ok: false, error: "session_expired", build: BUILD });
  }

  if (String(s.cid || "") !== clientId) return res.status(403).json({ ok: false, error: "client_mismatch", build: BUILD });
  if (String(s.hw || "") !== String(hw)) return res.status(403).json({ ok: false, error: "hwid_mismatch", build: BUILD });

  const expectedSig = makeLaunchSig(secret, sid, clientId, launchNonce, launchExp, launchProfileId);
  if (expectedSig.length !== launchSig.length) return res.status(403).json({ ok: false, error: "bad_launch_sig", build: BUILD });
  if (!crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(launchSig))) {
    return res.status(403).json({ ok: false, error: "bad_launch_sig", build: BUILD });
  }

  const nk = nonceUsedKey(lic, sid, launchNonce);
  const already = await redis.get(nk);
  if (already) return res.status(403).json({ ok: false, error: "nonce_used", build: BUILD });
  await redis.set(nk, "1", { ex: 30 });

  // Flags: PRO gets full; BASIC/FREE gets minimal
  const proUA =
    "Mozilla/5.0 (X11; CrOS aarch64 15699.85.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.110 Safari/537.36";

  const rawFlags = plan === "pro"
    ? [
        "--no-first-run",
        "--force-dark-mode",
        "--disable-renderer-backgrounding",
        "--disable-extensions",
        "--disable-default-apps",
        "--disable-component-update",
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
    bundle: {
      exp: now + 20,
      url: startUrl,
      flags: chromeFlags
    },
    build: BUILD
  });
};