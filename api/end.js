import crypto from "crypto";
import { kv } from "@vercel/kv";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
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

function getJsonBody(req) {
  try {
    if (!req.body) return {};
    if (typeof req.body === "string") return JSON.parse(req.body);
    return req.body;
  } catch {
    return {};
  }
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
  if (!payload || !payload.lic || !payload.sid) return { ok: false, error: "bad_payload" };

  return { ok: true, payload };
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "method_not_allowed" });

  const secret = (process.env.SECRET_SALT || "").toString();
  if (!secret || secret.length < 16) {
    return res.status(500).json({ ok: false, error: "server_misconfigured_secret" });
  }

  const body = getJsonBody(req);
  const token = (body.token || "").toString();

  const vt = verifyToken(token, secret);
  if (!vt.ok) return res.status(403).json({ ok: false, error: vt.error });

  const { lic, sid } = vt.payload;
  const sessionKey = `sn:sessions:${lic}`;

  await kv.hdel(sessionKey, sid);

  return res.status(200).json({ ok: true });
}