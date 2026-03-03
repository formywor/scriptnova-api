const crypto = require("crypto");

// --- helpers ---
function b64urlEncode(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signToken(payloadObj, secret) {
  const payloadJson = JSON.stringify(payloadObj);
  const payloadB64 = b64urlEncode(payloadJson);

  const sig = crypto.createHmac("sha256", secret).update(payloadB64).digest();
  const sigB64 = b64urlEncode(sig);

  return payloadB64 + "." + sigB64;
}

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function parseLicense(req) {
  if (req.method === "GET") return (req.query.license || "").toString();
  return ((req.body && req.body.license) || "").toString();
}

function getLicenseList() {
  return (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

module.exports = function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  const secret = (process.env.SECRET_SALT || "").toString();
  if (!secret || secret.length < 16) {
    return res.status(500).json({ ok: false, error: "server_misconfigured" });
  }

  const license = parseLicense(req);
  const list = getLicenseList();

  const ok = list.includes(license);
  if (!ok) return res.status(200).json({ ok: false, plan: "none" });

  const plan = license.startsWith("PRO-") ? "pro" : "basic";

  // token expires in 10 minutes
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 10 * 60;

  const token = signToken({ lic: license, plan, exp }, secret);

  return res.status(200).json({ ok: true, plan, token, exp });
};