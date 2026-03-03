const crypto = require("crypto");

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function b64urlEncodeUtf8(str) {
  return Buffer.from(String(str), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signToken(payloadObj, secret) {
  const payloadJson = JSON.stringify(payloadObj);
  const payloadB64 = b64urlEncodeUtf8(payloadJson);
  const sig = crypto.createHmac("sha256", secret).update(payloadB64).digest();
  const sigB64 = sig
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return payloadB64 + "." + sigB64;
}

function getLicenseList() {
  return (process.env.LICENSES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

// robust parsing for GET or POST (body can be object or string)
function getLicense(req) {
  if (req.method === "GET") return (req.query.license || "").toString();
  const b = req.body;
  if (!b) return "";
  if (typeof b === "string") {
    try { return (JSON.parse(b).license || "").toString(); } catch { return ""; }
  }
  return (b.license || "").toString();
}

module.exports = function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();

  const secret = (process.env.SECRET_SALT || "").toString();
  if (!secret || secret.length < 16) {
    return res.status(500).json({ ok: false, error: "server_misconfigured_secret" });
  }

  const license = getLicense(req);
  const list = getLicenseList();
  const ok = list.includes(license);

  if (!ok) return res.status(200).json({ ok: false, plan: "none" });

  const plan = license.startsWith("PRO-") ? "pro" : "basic";
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 10 * 60;

  const token = signToken({ lic: license, plan, exp }, secret);
  return res.status(200).json({ ok: true, plan, token, exp });
};